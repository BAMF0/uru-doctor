# SPDX-License-Identifier: GPL-2.0-or-later
"""Turning ``apt.log`` lines into tokens, depth and all.

The scan is one pass, and it does three things per line that the rest of the
subsystem depends on.

**Measures indentation.** This is not cosmetic. apt indents its
``pkgDepCache`` output by recursion depth, and in real logs that reaches 28
columns -- roughly fourteen levels of dependency expansion. Depth is what
separates a top-level conflict from a consequence discovered deep inside a
subtree, and :mod:`uru_doctor.apt.roots` uses it to prefer shallow roots when
ranking. Discard it and the log flattens into an unordered pile of assertions.

**Extracts state expressions before matching.** Each ``< ... @... >`` blob is
parsed out by :mod:`uru_doctor.apt.state` first, leaving a short skeleton of
fixed prose and package references for the grammar to match. Verb recognition
therefore survives a change to the state format, which is a format apt
explicitly reserves the right to change and demonstrably has.

**Counts what it cannot parse.** Unmatched lines become
:attr:`~uru_doctor.apt.grammar.Verb.UNKNOWN` tokens and are tallied by shape.
That tally is the feedback loop: the first draft of the grammar was built from
six real logs and was still missing four verbs, which this mechanism found
rather than hid.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from uru_doctor.apt.grammar import PATTERNS, VERB_STREAM, Dialect, Verb, dep_type
from uru_doctor.apt.state import STATE_RE, PackageState, StateVocabulary, parse_states
from uru_doctor.intern import mask_line
from uru_doctor.models import AptStream, DepType

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

#: Lines longer than this are almost certainly not resolver output -- a
#: ``history.log`` stanza spliced into the wrong file, or a binary blob. Parsing
#: them wastes time and risks pathological regex behaviour, so they are counted
#: as unknown and skipped.
MAX_LINE_LENGTH = 8192


@dataclass(frozen=True, slots=True)
class Token:
    """One recognised ``apt.log`` line.

    A slotted dataclass, not a Pydantic model: a single large log yields tens of
    thousands of these and they are consumed immediately into packed arrays, so
    construction cost dominates and validation would buy nothing.
    """

    verb: Verb
    stream: AptStream
    depth: int
    """Indentation in columns. The resolver's recursion depth."""

    line_no: int
    """1-based, for provenance in reports."""

    subject: str = ""
    """The primary package reference, as written."""

    object: str = ""
    """The second package reference, where the verb has one."""

    third: str = ""
    """A third reference, used only by ``Upgrading: A due to B Depends on C``."""

    dep: DepType = DepType.UNKNOWN
    constraint: str = ""
    """The unsatisfied version constraint, e.g. ``"= 2.86.3-4"`` or ``"< 3.13"``.

    Stored without the surrounding parentheses. The *operator* survives version
    normalisation during deduplication while the version does not, because
    ``(< 46.0.1~)`` and ``(< 46.0.7~)`` are one bug reported twice.
    """

    states: tuple[PackageState, ...] = ()
    """State expressions found on the line, left to right.

    Usually zero or one. ``Upgrading: A <state> due to B Depends on C <state>``
    carries two, which is why this is a tuple rather than an optional single.
    """

    score_src: int | None = None
    score_dst: int | None = None
    """apt's ``Considering`` scores. Negative values occur and are meaningful."""

    broken_count: int | None = None
    pass_no: int | None = None
    """Resolver pass, from ``Starting 2`` or ``Investigating (N)``."""

    from_user: bool | None = None
    """``FU=1`` on a ``Mark*`` line: the change was explicitly requested rather
    than inferred, which makes the package a more credible root."""

    timestamp: str = ""
    """Raw text of a ``Log time:`` header."""

    @property
    def state(self) -> PackageState | None:
        """The first state expression, which is the subject's on most verbs."""
        return self.states[0] if self.states else None

    @property
    def is_resolver(self) -> bool:
        return self.stream is AptStream.RESOLVER


@dataclass(slots=True)
class LexStats:
    """What a scan saw, for diagnostics and the unclassified report."""

    lines: int = 0
    matched: int = 0
    blank: int = 0
    oversized: int = 0
    by_verb: dict[Verb, int] = field(default_factory=dict)
    unknown_shapes: dict[str, int] = field(default_factory=dict)
    """Masked templates of unmatched lines, by frequency.

    Masked rather than raw so that ten thousand variations of one unrecognised
    shape appear as a single entry with a count -- which is what makes the gap
    legible instead of drowning the report.
    """

    vocabulary: StateVocabulary = field(default_factory=StateVocabulary)

    @property
    def unmatched(self) -> int:
        return self.lines - self.matched - self.blank - self.oversized

    @property
    def coverage(self) -> float:
        """Share of non-blank lines the grammar recognised."""
        considered = self.lines - self.blank
        return self.matched / considered if considered else 1.0

    def note_verb(self, verb: Verb) -> None:
        self.by_verb[verb] = self.by_verb.get(verb, 0) + 1

    def note_unknown(self, line: str) -> None:
        shape, _ = mask_line(line)
        self.unknown_shapes[shape] = self.unknown_shapes.get(shape, 0) + 1

    def top_unknown(self, limit: int = 20) -> list[tuple[str, int]]:
        return sorted(self.unknown_shapes.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]


def measure_depth(line: str) -> int:
    """Count leading indentation in columns, expanding tabs to eight.

    apt uses spaces, but a log that has been through a terminal, a mail client
    and a bug tracker may not have survived intact, and treating a tab as one
    column would collapse two distinct recursion levels into one.
    """
    depth = 0
    for char in line:
        if char == " ":
            depth += 1
        elif char == "\t":
            depth += 8 - (depth % 8)
        else:
            break
    return depth


def _skeleton(line: str) -> str:
    """Strip state expressions and normalise whitespace for matching."""
    return " ".join(STATE_RE.sub(" ", line).split())


def lex_line(line: str, line_no: int, stats: LexStats | None = None) -> Token:
    """Tokenise one line.

    Always returns a token; an unrecognised line becomes
    :attr:`~uru_doctor.apt.grammar.Verb.UNKNOWN` with its depth and line number
    intact, so that the caller can still report where the gap was.
    """
    depth = measure_depth(line)
    stripped = line.rstrip("\n").rstrip()

    if stats is not None:
        stats.lines += 1

    if not stripped.strip():
        if stats is not None:
            stats.blank += 1
        return Token(verb=Verb.UNKNOWN, stream=AptStream.UNKNOWN, depth=depth, line_no=line_no)

    if len(stripped) > MAX_LINE_LENGTH:
        if stats is not None:
            stats.oversized += 1
        return Token(verb=Verb.UNKNOWN, stream=AptStream.UNKNOWN, depth=depth, line_no=line_no)

    vocabulary = stats.vocabulary if stats is not None else None
    states = tuple(parse_states(stripped, vocabulary))
    skeleton = _skeleton(stripped)

    for verb, pattern in PATTERNS:
        match = pattern.match(skeleton)
        if match is None:
            continue
        groups = match.groupdict()
        if stats is not None:
            stats.matched += 1
            stats.note_verb(verb)
        return Token(
            verb=verb,
            stream=VERB_STREAM.get(verb, AptStream.UNKNOWN),
            depth=depth,
            line_no=line_no,
            subject=groups.get("subject") or "",
            object=groups.get("object") or "",
            third=groups.get("third") or "",
            dep=dep_type(groups.get("dep")),
            constraint=(groups.get("constraint") or "").strip(),
            states=states,
            score_src=_as_int(groups.get("score_src")),
            score_dst=_as_int(groups.get("score_dst")),
            broken_count=_as_int(groups.get("broken")),
            pass_no=_as_int(groups.get("pass")),
            from_user=_as_bool(groups.get("fu")),
            timestamp=(groups.get("timestamp") or "").strip(),
        )

    if stats is not None:
        stats.note_unknown(stripped)
    return Token(
        verb=Verb.UNKNOWN,
        stream=AptStream.UNKNOWN,
        depth=depth,
        line_no=line_no,
        states=states,
    )


def _as_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:  # pragma: no cover - patterns only capture digits
        return None


def _as_bool(value: str | None) -> bool | None:
    if value is None or value == "":
        return None
    return value == "1"


def lex(lines: Iterable[str], stats: LexStats | None = None) -> Iterator[Token]:
    """Tokenise a whole log, skipping blanks.

    A generator, because ``apt.log`` reaches hundreds of thousands of lines and
    there is no reason to materialise every token when the consumer builds
    packed arrays incrementally.
    """
    for line_no, line in enumerate(lines, start=1):
        token = lex_line(line, line_no, stats)
        if token.verb is Verb.UNKNOWN and not line.strip():
            continue
        yield token


def lex_text(text: str, stats: LexStats | None = None) -> Iterator[Token]:
    """Tokenise from a single string."""
    return lex(text.splitlines(), stats)


def dialect_of(tokens: Iterable[Token]) -> Dialect:
    """Guess the dialect from token content alone.

    A fallback for when ``main.log`` is absent and the ``apt version`` line is
    therefore unavailable. It is only a hint: the mode-prefix letter ``p``
    (as in ``@un pumN Ib``) was seen only in apt 2.8 output, so its presence
    suggests apt 2, but its absence implies nothing either way.
    """
    for token in tokens:
        for state in token.states:
            raw = state.raw
            if raw.startswith("@") and " p" in raw:
                return Dialect.APT2
    return Dialect.UNKNOWN
