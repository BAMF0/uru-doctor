"""Splitting ``apt.log`` into resolver sections, and collapsing the duplicates.

``apt.log`` is not one log. The upgrader opens the file once and redirects apt's
stdout and stderr into it around each cache operation
(``DistUpgradeCache.withResolverLog``), writing a ``Log time:`` header each
time. So the file is a concatenation of unrelated resolver runs, and treating it
as a single stream conflates a clean early ``openCache()`` with the failing
``distUpgrade()`` that matters.

Three properties of the real files drive this module.

**One problem is logged four times.** Within a resolve, apt runs two passes and
logs both (``Starting pkgProblemResolver`` then ``Starting 2
pkgProblemResolver``). The upgrader then performs the whole calculation twice,
once to show the user what would happen and once for real. A single conflict
therefore appears four times with identical content. In the local logs,
``broken count: 11`` appears exactly four times for one underlying problem.
Without collapsing, every count this tool reports is inflated fourfold.

**Sections are not well-formed.** ``Entering ResolveByKeep`` occurs with no
preceding ``Starting``. ``Log time:`` headers arrive in runs of three with
nothing between them. A file can end mid-resolve: bug 2169028's ``apt.log``
stops on the ``Done`` of its only resolve, and its ``main.log`` stops earlier
still. Every one of those is normal input, not corruption, and none may raise.

**The last section is usually the interesting one**, but not always -- a resolve
that ended cleanly tells you nothing even if it came last. So sections are
scored by what they contain rather than by position, and
:func:`primary_section` picks the one that actually failed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import blake2b
from typing import TYPE_CHECKING

from uru_doctor.apt.grammar import Verb
from uru_doctor.apt.lexer import LexStats, Token, lex

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


@dataclass(slots=True)
class Section:
    """One contiguous run of apt output between ``Log time:`` headers.

    A section may contain zero, one or several resolver passes. Mutable while
    being accumulated, then treated as read-only.
    """

    index: int
    """Position in the file, counting from zero."""

    first_line: int
    """1-based line number of the ``Log time:`` header, or of the first token."""

    timestamp: str = ""
    """Raw text of the ``Log time:`` header. Not parsed into a datetime: it is
    local time with no zone and is only ever used to correlate with
    ``main.log``, which is also local."""

    tokens: list[Token] = field(default_factory=list)

    broken_counts: list[int] = field(default_factory=list)
    """Every ``broken count: N`` seen, one per pass."""

    passes: int = 0
    """Number of ``Starting`` lines."""

    resolve_by_keep: bool = False
    completed: bool = False
    """Whether a ``Done`` was seen. False means the log stops inside this
    section."""

    @property
    def broken_count(self) -> int | None:
        """The worst broken count reported in this section.

        The maximum rather than the last, because the second pass reports the
        count it started with, and a resolve that improved from eleven broken to
        two is still a resolve that had eleven problems.
        """
        return max(self.broken_counts) if self.broken_counts else None

    @property
    def has_conflict(self) -> bool:
        """Whether anything in this section describes a real problem."""
        return bool(self.broken_count) or any(
            token.verb in _CONFLICT_VERBS for token in self.tokens
        )

    @property
    def resolver_tokens(self) -> list[Token]:
        return [token for token in self.tokens if token.is_resolver]

    def count(self, *verbs: Verb) -> int:
        wanted = set(verbs)
        return sum(1 for token in self.tokens if token.verb in wanted)

    def content_hash(self) -> bytes:
        """Digest of the section's semantic content, for collapsing duplicates.

        Covers the verb, both package references and the constraint of every
        token, but deliberately **not** line numbers, indentation or timestamps.
        Two logs of the same resolve differ in all three of those and in nothing
        else, which is exactly the case this has to recognise.
        """
        digest = blake2b(digest_size=16)
        for token in self.tokens:
            if token.verb is Verb.LOG_TIME:
                continue
            digest.update(token.verb.value.encode())
            digest.update(b"\x00")
            digest.update(token.subject.encode())
            digest.update(b"\x00")
            digest.update(token.object.encode())
            digest.update(b"\x00")
            digest.update(token.constraint.encode())
            digest.update(b"\x01")
        return digest.digest()

    def score(self) -> tuple[int, int, int, int]:
        """Rank for :func:`primary_section`, highest wins.

        ``(broken count, conflict tokens, decisions, not-completed)``.
        Deliberately not position in the file: the last section is frequently a
        clean ``openCache()`` performed while unwinding from the failure, and
        picking it would report "no problem" on a bug that plainly has one.
        A section that never reached ``Done`` ranks above an equivalent one that
        did, because a resolve the log was truncated inside is more likely to be
        where things went wrong.
        """
        return (
            self.broken_count or 0,
            self.count(*_CONFLICT_VERBS),
            self.count(*_DECISION_VERBS),
            0 if self.completed else 1,
        )


#: Verbs that mean "something is actually wrong here".
_CONFLICT_VERBS: frozenset[Verb] = frozenset(
    {Verb.BROKEN, Verb.CANT_BE_SATISFIED, Verb.DEPS_NOT_SATISFIED, Verb.PACKAGE_DEP}
)

#: Verbs recording a remedy apt chose.
_DECISION_VERBS: frozenset[Verb] = frozenset(
    {
        Verb.HOLDING_BACK,
        Verb.REMOVING_RATHER,
        Verb.FIXING_VIA_REMOVE,
        Verb.FIXING_VIA_KEEP,
        Verb.ADDED_TO_REMOVE_LIST,
        Verb.DELAYED_REMOVING,
        Verb.KEEPING_PACKAGE,
        Verb.TRY_INSTALLING_BEFORE,
    }
)


def split_sections(tokens: Iterable[Token]) -> list[Section]:
    """Group tokens into sections on ``Log time:`` boundaries.

    Tokens appearing before any header still get a section, because a log that
    has been excerpted into a bug description -- which happens constantly --
    starts mid-stream with no header at all.
    """
    sections: list[Section] = []
    current: Section | None = None

    for token in tokens:
        if token.verb is Verb.LOG_TIME:
            current = Section(
                index=len(sections), first_line=token.line_no, timestamp=token.timestamp
            )
            sections.append(current)
            continue

        if current is None:
            current = Section(index=len(sections), first_line=token.line_no)
            sections.append(current)

        current.tokens.append(token)

        if token.verb is Verb.STARTING:
            current.passes += 1
            if token.broken_count is not None:
                current.broken_counts.append(token.broken_count)
        elif token.verb is Verb.ENTERING_RESOLVE_BY_KEEP:
            current.resolve_by_keep = True
        elif token.verb is Verb.DONE:
            current.completed = True

    return sections


def drop_empty(sections: Sequence[Section]) -> list[Section]:
    """Remove sections with no tokens.

    ``Log time:`` headers arrive in runs -- three consecutive ones open every
    real log -- because the upgrader opens the cache several times before
    anything interesting happens. The empty sections between them are noise.
    """
    return [section for section in sections if section.tokens]


def collapse_duplicates(sections: Sequence[Section]) -> list[Section]:
    """Keep one section per distinct content hash, preserving order.

    This is the fourfold-inflation fix. The first occurrence is kept so that
    reported line numbers point at the earliest copy, which is the one a reader
    scrolling the file will find.
    """
    seen: set[bytes] = set()
    kept: list[Section] = []
    for section in sections:
        digest = section.content_hash()
        if digest in seen:
            continue
        seen.add(digest)
        kept.append(section)
    return kept


def primary_section(sections: Sequence[Section]) -> Section | None:
    """The section most likely to contain the failure.

    Chosen by :meth:`Section.score`, with ties broken toward the later section
    since a repeated problem is usually reported last in its final form.
    """
    if not sections:
        return None
    return max(sections, key=lambda s: (*s.score(), s.index))


@dataclass(slots=True)
class SectionedLog:
    """The result of reading one ``apt.log``."""

    sections: list[Section]
    stats: LexStats
    collapsed: int = 0
    """How many duplicate sections were removed.

    Reported rather than hidden: a log where this is three for every real
    section is behaving exactly as expected, and a log where it is zero when
    several resolves ran is a hint that the content hash is not matching
    something it should.
    """

    truncated: bool = False
    """Whether a resolve was started and never finished.

    Evidence about the capture, not about the upgrade: the honest reading is
    "the log stops here", never "the upgrade failed here".

    Specifically a section with at least one ``Starting`` and no ``Done``. The
    weaker test -- last section lacks ``Done`` -- gives false positives on
    perfectly complete logs, because the final section of a successful run is
    frequently a bare ``Entering ResolveByKeep`` followed by ``MarkKeep``
    traffic, with no ``Starting`` and so no ``Done`` to expect.
    """

    @property
    def primary(self) -> Section | None:
        return primary_section(self.sections)

    @property
    def total_broken(self) -> int:
        return max((s.broken_count or 0 for s in self.sections), default=0)

    @property
    def any_conflict(self) -> bool:
        return any(s.has_conflict for s in self.sections)


def read_sections(
    lines: Iterable[str], *, dedupe: bool = True, stats: LexStats | None = None
) -> SectionedLog:
    """Lex and section a log in one pass.

    ``dedupe`` is exposed because ``uru-doctor show --raw`` wants to display
    what the file actually says, duplicates and all, while every analytical
    path wants them gone.
    """
    collected = stats if stats is not None else LexStats()
    tokens = list(lex(lines, collected))
    sections = drop_empty(split_sections(tokens))

    before = len(sections)
    if dedupe:
        sections = collapse_duplicates(sections)

    # Renumber so indices stay contiguous after dropping and collapsing, and so
    # a section index in a report refers to something a reader can count to.
    for position, section in enumerate(sections):
        section.index = position

    truncated = any(s.passes > 0 and not s.completed for s in sections)
    return SectionedLog(
        sections=sections,
        stats=collected,
        collapsed=before - len(sections),
        truncated=truncated,
    )


def read_sections_text(text: str, *, dedupe: bool = True) -> SectionedLog:
    """Convenience wrapper for a log already in memory."""
    return read_sections(text.splitlines(), dedupe=dedupe)
