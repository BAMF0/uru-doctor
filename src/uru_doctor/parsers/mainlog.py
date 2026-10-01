"""Parsing ``main.log``, the upgrader's own narrative of the run.

Three things in this file are less obvious than they look.

**Records are not lines.** The upgrader logs multi-line values -- a deb822
source stanza, a PGP key block, a Python traceback -- as a single record whose
continuation lines carry no timestamp. Treating each physical line as a record
produces hundreds of junk events and loses the association between a traceback
and the error that raised it. So a record begins at a timestamp and absorbs
everything up to the next one.

**``W:`` is not a cause.** When apt fails, the upgrader stringifies the whole
apt error stack into one message, and that stack mixes warnings with errors::

    ERROR Dist-upgrade failed: 'W:Skipping acquire of configured file
    'main/binary-i386/Packages' as repository 'https://dl.google.com/linux/
    chrome-stable/deb stable InRelease' doesn't support architecture 'i386',
    E:Error, pkgProblemResolver::Resolve generated breaks, this may be caused
    by held packages.'

That is LP#2150319. The warning names Google Chrome and is cosmetically
alarming; the error says the resolver failed. The bug was reported, triaged and
discussed as a Chrome problem, and the actual cause -- a held
``libfile-libmagic-perl`` -- went unnoticed. So warnings and errors are split
apart here and only ``E:`` is ever allowed to be causal.

**The ``Foreign`` list is the upgrader's own third-party verdict.** It is
computed by walking installed packages and asking whether any origin is
Ubuntu's, which is a far better signal than anything we could reconstruct from
version strings. The *before* list is the one to use: after the sources are
rewritten, archive packages have no resolute candidate yet and show up as
foreign too (the "after" list in one of our fixtures contains ``coreutils``).
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from itertools import pairwise
from typing import Final

from uru_doctor.intern import Interner
from uru_doctor.models import (
    ABSENT,
    Event,
    Level,
    LogSource,
    Phase,
    PkgId,
    StrId,
)
from uru_doctor.phases import PhaseTracker

__all__ = [
    "AptMessage",
    "MainLog",
    "MainLogRecord",
    "iter_records",
    "parse_main_log",
    "resolve_third_party",
    "split_apt_messages",
]

#: ``2026-04-25 10:49:56,344 ERROR message``
_RECORD_RE: Final = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}),(?P<ms>\d{3})\s+"
    r"(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)\s"
    r"(?P<message>.*)$"
)

_LEVELS: Final[dict[str, Level]] = {
    "DEBUG": Level.DEBUG,
    "INFO": Level.INFO,
    "WARNING": Level.WARNING,
    "ERROR": Level.ERROR,
    # The upgrader's only CRITICAL calls are fatal aborts. We have no separate
    # level for them and ERROR is the honest mapping.
    "CRITICAL": Level.ERROR,
}

#: Package-list markers. The value is the :class:`PackageDelta` field name.
#:
#: ``Upgradable, but held- back`` is spelled exactly that way in
#: ``DistUpgradeCache.py`` -- the stray space is the upgrader's typo, and
#: matching it loosely is how you silently lose the held-back list.
_LIST_MARKERS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (re.compile(r"^Keep at same version:\s*(?P<pkgs>.*)$"), "kept"),
    (re.compile(r"^Upgradable, but held-\s*back:\s*(?P<pkgs>.*)$"), "held_back"),
    (re.compile(r"^Upgrade:\s*(?P<pkgs>.*)$"), "upgraded"),
    (re.compile(r"^Install:\s*(?P<pkgs>.*)$"), "installed"),
    (re.compile(r"^Remove:\s*(?P<pkgs>.*)$"), "removed"),
    (re.compile(r"^Obsolete:\s*(?P<pkgs>.*)$"), "obsolete"),
    (re.compile(r"^MetaPkgs:\s*(?P<pkgs>.*)$"), "meta"),
)

_FOREIGN_RE: Final = re.compile(
    r"^Foreign \((?P<when>before|after) rewriting sources\):\s*(?P<pkgs>.*)$"
)

#: ``Install: pkg (1.2-3)`` -- some lists annotate versions in parentheses.
_PKG_TOKEN_RE: Final = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9+._-]*(?::\w+)?)")

# -- run metadata ------------------------------------------------------------

_META_RE: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("apt_version", re.compile(r"^apt version: '(?P<v>[^']*)'")),
    ("python_version", re.compile(r"^python version: '(?P<v>[^']+?)(?: \(|')")),
    ("upgrader_version", re.compile(r"^release-upgrader version '(?P<v>[^']*)' started")),
    ("view", re.compile(r"^Using '(?P<v>[^']*)' view")),
    ("kernel", re.compile(r"^uname information: 'Linux \S+ (?P<v>\S+)")),
    ("locale", re.compile(r"^locale: '(?P<v>[^']*)'")),
    ("from_release", re.compile(r"^Upgrading from (?P<v>\w+) to \w+")),
    ("to_release", re.compile(r"^Upgrading from \w+ to (?P<v>\w+)")),
)

_CACHE_SIZE_RE: Final = re.compile(r"^/openCache\(\), new cache size (?P<n>\d+)")


@dataclass(frozen=True, slots=True)
class MainLogRecord:
    """One logical log record, with continuation lines folded in."""

    line_no: int
    """1-based line number of the record's first physical line."""

    t_ms: int
    """Milliseconds since the first record of the log."""

    level: Level
    message: str
    """The first line of the message, which is the part worth matching on."""

    continuation: tuple[str, ...] = ()
    """Subsequent physical lines, verbatim and unparsed."""

    stamp: datetime | None = None
    """Absolute local wall clock, when the record's timestamp parsed.

    Needed to tell which run a log belongs to. ``/var/log/dist-upgrade`` is
    archived wholesale at startup, so one ``YYYYMMDD-HHMM`` directory can hold
    a ``main.log`` from today beside an ``apt.log`` from six months ago.
    Offsets cannot detect that; absolute times can.
    """

    @property
    def full(self) -> str:
        """The record reassembled, for traceback and stanza extraction."""
        if not self.continuation:
            return self.message
        return "\n".join((self.message, *self.continuation))


@dataclass(frozen=True, slots=True)
class AptMessage:
    """One ``W:`` or ``E:`` component of an apt error stack."""

    text: str
    is_error: bool

    @property
    def is_warning(self) -> bool:
        return not self.is_error


def _to_stamp(date: str, time: str, ms: str) -> datetime | None:
    """Parse a record timestamp into a local, naive datetime.

    Naive on purpose: the upgrader logs local time with no zone, and so do
    ``apt.log``, ``apt-term.log`` and ``history.log``. Correlating them only
    requires that they share a clock, which they do.
    """
    try:
        hour, minute, second = (int(part) for part in time.split(":"))
        return datetime(
            int(date[0:4]),
            int(date[5:7]),
            int(date[8:10]),
            hour,
            minute,
            second,
            int(ms) * 1000,
        )
    except ValueError:
        return None


def _to_ms(date: str, time: str, ms: str) -> int:
    """Wall-clock to milliseconds, without constructing a datetime.

    The absolute value is meaningless; only differences are used, and the run
    is bounded by the upgrader's own timeout, so no date arithmetic is needed
    beyond the day-of-month to survive a run crossing midnight.
    """
    day = int(date[8:10])
    hh, mm, ss = (int(part) for part in time.split(":"))
    return ((day * 24 + hh) * 3600 + mm * 60 + ss) * 1000 + int(ms)


def iter_records(lines: Sequence[str]) -> Iterator[MainLogRecord]:
    """Fold physical lines into logical records.

    Leading lines without a timestamp are dropped: they can only be the tail of
    a record from a previous, truncated log.
    """
    origin: int | None = None
    pending: re.Match[str] | None = None
    pending_no = 0
    pending_ms = 0
    continuation: list[str] = []

    def build() -> MainLogRecord:
        assert pending is not None
        return MainLogRecord(
            line_no=pending_no,
            t_ms=pending_ms,
            level=_LEVELS.get(pending["level"], Level.UNKNOWN),
            message=pending["message"],
            continuation=tuple(continuation),
            stamp=_to_stamp(pending["date"], pending["time"], pending["ms"]),
        )

    for index, line in enumerate(lines, start=1):
        match = _RECORD_RE.match(line)
        if match is None:
            if pending is not None:
                continuation.append(line)
            continue

        if pending is not None:
            yield build()

        absolute = _to_ms(match["date"], match["time"], match["ms"])
        if origin is None:
            origin = absolute
        pending, pending_no = match, index
        pending_ms = max(0, absolute - origin)
        continuation = []

    if pending is not None:
        yield build()


def split_apt_messages(blob: str) -> tuple[AptMessage, ...]:
    """Split a stringified apt error stack into its components.

    apt joins its message stack with ``", "`` and prefixes each with ``W:`` or
    ``E:``. Splitting on the comma alone would shred messages that contain
    commas -- and they routinely do ("this may be caused by held packages") --
    so the split is anchored on a following prefix instead.

    The prefix must be at a true boundary, either the start of the blob or
    directly after ``", "``. ``E:`` also occurs inside quoted repository URLs
    and filenames, and splitting there would corrupt both halves.
    """
    text = blob.strip().strip("'\"")
    if not text:
        return ()

    boundaries = [m.start() for m in re.finditer(r"(?:^|(?<=, ))[WE]:", text)]
    if not boundaries:
        # No prefixes at all: a bare message, which apt treats as an error.
        return (AptMessage(text, is_error=True),)

    # Anything before the first prefix is a preamble and belongs to nothing.
    pieces: list[AptMessage] = []
    bounded = [*boundaries, len(text) + 2]
    for start, stop in pairwise(bounded):
        chunk = text[start : min(stop, len(text))]
        chunk = chunk.rstrip().removesuffix(",").rstrip()
        if len(chunk) > 2:
            pieces.append(AptMessage(chunk[2:].strip(), is_error=chunk[0] == "E"))
    return tuple(pieces)


@dataclass(slots=True)
class MainLog:
    """Everything ``main.log`` tells us about a run."""

    events: list[Event] = field(default_factory=list)
    spans: dict[Phase, tuple[int, int]] = field(default_factory=dict)
    """Phase to ``(t_start_ms, t_end_ms)``."""

    terminal_phase: Phase = Phase.UNKNOWN
    meta: dict[str, StrId] = field(default_factory=dict)
    packages: dict[str, tuple[PkgId, ...]] = field(default_factory=dict)
    foreign: tuple[PkgId, ...] = ()
    """The upgrader's own third-party verdict, from the *before* list."""

    foreign_after: tuple[PkgId, ...] = ()
    errors: list[tuple[int, str]] = field(default_factory=list)
    """``(line_no, message)`` for every ``ERROR``/``CRITICAL`` record."""

    apt_errors: list[AptMessage] = field(default_factory=list)
    """``E:`` components only -- the causal half of apt's message stacks."""

    apt_warnings: list[AptMessage] = field(default_factory=list)
    """``W:`` components, kept for the report but never used for diagnosis."""

    cache_sizes: list[int] = field(default_factory=list)
    aborted: bool = False
    duration_ms: int = 0
    record_count: int = 0

    started_at: datetime | None = None
    """Absolute local time of the first record."""

    ended_at: datetime | None = None
    """Absolute local time of the last record."""

    @property
    def reached_commit(self) -> bool:
        """Whether dpkg ran, which decides if the system was modified."""
        return self.terminal_phase >= Phase.COMMIT

    @property
    def held_back(self) -> tuple[PkgId, ...]:
        return self.packages.get("held_back", ())


def _packages(blob: str, interner: Interner) -> tuple[PkgId, ...]:
    """Intern a whitespace-separated package list.

    Order is preserved rather than sorted: ``Obsolete:`` and ``Foreign:`` are
    already sorted by the upgrader, and for the rest the log order is the only
    ordering information we have.
    """
    out: list[PkgId] = []
    for token in blob.split():
        match = _PKG_TOKEN_RE.match(token)
        if match is not None:
            out.append(interner.package(match["name"]))
    return tuple(out)


def parse_main_log(lines: Sequence[str], interner: Interner) -> MainLog:
    """Parse ``main.log`` into a :class:`MainLog`.

    Every record becomes an :class:`Event` so that similarity scoring has the
    full narrative to work with; the structured fields are extracted alongside.
    """
    log = MainLog()
    tracker = PhaseTracker()
    starts: dict[Phase, int] = {}
    last_ms = 0

    for record in iter_records(lines):
        log.record_count += 1
        last_ms = record.t_ms
        if record.stamp is not None:
            if log.started_at is None:
                log.started_at = record.stamp
            log.ended_at = record.stamp
        message = record.message
        phase = tracker.feed(message, record.line_no)

        if phase is not Phase.UNKNOWN and phase not in starts:
            starts[phase] = record.t_ms
        for seen in starts:
            if seen <= phase:
                log.spans[seen] = (starts[seen], record.t_ms)

        template_id, args = interner.template(message)
        log.events.append(
            Event(
                template_id=template_id,
                args=args,
                level=record.level,
                source=LogSource.MAIN,
                t_ms=record.t_ms,
                line_no=record.line_no,
                phase=phase,
            )
        )

        _extract(log, record, message, interner)

    log.terminal_phase = tracker.current
    log.duration_ms = last_ms
    return log


def _extract(log: MainLog, record: MainLogRecord, message: str, interner: Interner) -> None:
    """Pull structured facts out of one record."""
    for key, pattern in _META_RE:
        if key not in log.meta and (match := pattern.match(message)):
            log.meta[key] = interner.string(match["v"])

    for pattern, field_name in _LIST_MARKERS:
        if match := pattern.match(message):
            log.packages[field_name] = _packages(match["pkgs"], interner)
            return

    if match := _FOREIGN_RE.match(message):
        packages = _packages(match["pkgs"], interner)
        if match["when"] == "before":
            log.foreign = packages
        else:
            log.foreign_after = packages
        return

    if match := _CACHE_SIZE_RE.match(message):
        log.cache_sizes.append(int(match["n"]))
        return

    if message.startswith("abort called"):
        log.aborted = True
        return

    if record.level.is_problem:
        _extract_apt_stack(log, record, message)


#: Messages that wrap an apt error stack. The captured group is the stack.
_APT_STACK_RE: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"^Dist-upgrade failed:\s*(?P<stack>.*)$", re.DOTALL),
    re.compile(r"^Can't mark '[^']*' for upgrade \((?P<stack>.*)\)$", re.DOTALL),
    re.compile(r"^failed to mark '[^']*' for install \((?P<stack>.*)\)$", re.DOTALL),
    re.compile(r"^openCache\(\) failed:\s*(?P<stack>.*)$", re.DOTALL),
    re.compile(r"^(?:IOError|SystemError)[^:]*:\s*(?P<stack>.*)$", re.DOTALL),
)


def _extract_apt_stack(log: MainLog, record: MainLogRecord, message: str) -> None:
    """Record an error, splitting any embedded apt stack into W: and E:."""
    if record.level.is_error:
        log.errors.append((record.line_no, message))

    for pattern in _APT_STACK_RE:
        if match := pattern.match(record.full):
            for piece in split_apt_messages(match["stack"]):
                target = log.apt_errors if piece.is_error else log.apt_warnings
                target.append(piece)
            return


def meta_or_absent(log: MainLog, key: str) -> StrId:
    """Look up run metadata, returning :data:`ABSENT` when not logged."""
    return log.meta.get(key, ABSENT)


def resolve_third_party(log: MainLog, interner: Interner) -> tuple[PkgId, ...]:
    """Expand the ``Foreign`` list to the architectures apt actually names.

    The two logs spell packages differently. ``main.log`` uses python-apt's
    ``pkg.name``, which omits ``:arch`` for the native architecture, so the
    surface PPA appears as ``libwacom9-surface``. The apt resolver trace writes
    ``libwacom9-surface:amd64``. Those intern to different ids, so passing the
    ``Foreign`` list straight to the graph marks nothing third-party and the
    ``Conflicts`` reorientation quietly does nothing -- which is how LP#2150245
    ends up blaming the Ubuntu package it broke.

    **Call this after the apt log has been parsed.** Resolution can only find
    architectures that have already been interned, and the ``:amd64`` forms
    come from the apt log. Calling it first returns the bare ids unchanged and
    is silently useless.
    """
    out: list[PkgId] = []
    seen: set[PkgId] = set()
    for pkg_id in log.foreign:
        name = interner.package_label(pkg_id)
        matches = interner.packages_named(name) or (pkg_id,)
        for match in matches:
            if match not in seen:
                seen.add(match)
                out.append(match)
    return tuple(out)
