# SPDX-License-Identifier: GPL-2.0-or-later
"""Turning a directory of logs into one or more :class:`UpgradeRun` records.

This module owns the *order* in which parsers run, and that order is not
arbitrary.

**The apt log must be parsed before the third-party set is resolved.** apt names
packages with their architecture (``libwacom9-surface:amd64``); ``main.log``'s
``Foreign`` list uses python-apt's ``pkg.name``, which omits ``:arch`` for the
native architecture. The two intern to different ids, so resolving the
``Foreign`` list before the apt log has been interned silently matches nothing
and the ``Conflicts`` blame reorientation quietly does nothing -- which is how
LP#2150245 ends up blaming the Ubuntu package its PPA broke. Getting this wrong
produces no error, just a worse diagnosis, which is why the sequencing lives
here rather than being left to callers.

**One directory can hold several attempts.** ``/var/log/dist-upgrade`` keeps the
most recent attempt at the top level and archives earlier ones into
``YYYYMMDD-HHMM/`` subdirectories. All are ingested, because repeated attempts
are themselves triage signal, and the most recent is marked primary.

**Absence is evidence, but only in one direction.** No ``apt-term.log`` and no
``history.log`` means dpkg never ran. Their presence means nothing: apport
attaches on existence rather than content, a successful run's first
``apt-term.log`` block is empty, and ``history.log`` records the full planned
package set even for a commit whose dpkg run did nothing. So
:attr:`UpgradeRun.dpkg_wrote` is set from the parsed block contents, and left
``None`` when no log settles it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Final

from uru_doctor.apt.graph import build_graph
from uru_doctor.apt.lexer import LexStats
from uru_doctor.apt.livelock import detect_oscillations
from uru_doctor.apt.sections import read_sections
from uru_doctor.distroinfo import series_table
from uru_doctor.intern import Interner
from uru_doctor.models import (
    Arch,
    ConflictGraph,
    Event,
    Frontend,
    LogSource,
    NodeBits,
    PackageCounts,
    PackageDelta,
    Phase,
    PhaseOutcome,
    PhaseSpan,
    PkgId,
    ProblemType,
    UpgradeRun,
    pack_u32,
)
from uru_doctor.parsers.apportmeta import ApportMeta
from uru_doctor.parsers.aptterm import TermLog, parse_apt_term
from uru_doctor.parsers.history import HistoryLog, parse_history
from uru_doctor.parsers.mainlog import MainLog, parse_main_log, resolve_third_party
from uru_doctor.parsers.sanitize import read_log

__all__ = [
    "ATTEMPT_DIR_RE",
    "COHERENCE_SLACK_S",
    "LOG_FILENAMES",
    "IngestResult",
    "LogSet",
    "check_coherence",
    "discover",
    "ingest_directory",
    "ingest_logs",
    "is_terminal_error",
    "terminal_errors",
]

#: Archived attempt directories, e.g. ``20260623-1109``.
ATTEMPT_DIR_RE: Final = re.compile(r"^(?P<stamp>\d{8}-\d{4})$")

#: On-disk filenames, which differ from the apport attachment keys.
LOG_FILENAMES: Final[dict[str, LogSource]] = {
    "apt.log": LogSource.APT,
    "apt-term.log": LogSource.APT_TERM,
    "history.log": LogSource.HISTORY,
    "main.log": LogSource.MAIN,
    "term.log": LogSource.TERM,
    "xorg_fixup.log": LogSource.XORG_FIXUP,
    "screenlog.0": LogSource.SCREENLOG,
}

#: Broken-state bits. A node carrying any of them is a broken package; the rest
#: of the graph is context the resolver happened to mention.
_BROKEN_BITS: Final = (
    NodeBits.INST_BROKEN,
    NodeBits.NOW_BROKEN,
    NodeBits.INST_POLICY_BROKEN,
    NodeBits.NOW_POLICY_BROKEN,
)

#: ``ERROR`` records the upgrader logs and then carries on past.
#:
#: Treating any ``ERROR`` as terminal marked bug 2169028's deliberately
#: truncated log as complete evidence, on the strength of one line saying an
#: optional module is absent. A run has concluded when it aborts, when apt
#: reports an error stack, or when it reaches the end -- not merely because
#: something was logged at ``ERROR`` level.
_BENIGN_ERRORS: Final[tuple[str, ...]] = (
    "failed to import AptClone",
    "failed to import apport python module",
    "_checkDep:",
    "has no priority set",
    "can not find failed maintainer script",
    "Can not open terminal log",
    "No snap store connectivity",
    "Failed fetching size of snap",
    "error reading from self.master_fd",
    "error setting default icon",
    "lspci failed",
    "os.path.realpath failed",
)

_FRONTENDS: Final[dict[str, Frontend]] = {
    "DistUpgradeViewGtk3": Frontend.GTK3,
    "DistUpgradeViewKDE": Frontend.KDE,
    "DistUpgradeViewText": Frontend.TEXT,
    "DistUpgradeViewNonInteractive": Frontend.NON_INTERACTIVE,
}

#: Caps per log, applied to the *tail* -- a truncated upgrade log is
#: interesting at the end, because that is where it stopped.
#:
#: ``screenlog.0`` is the reason this exists: it mirrors the entire terminal
#: session and reaches 4.6 MB on an ordinary desktop upgrade, almost all of it
#: progress redraws already covered by ``apt-term.log``.
_SIZE_CAPS: Final[dict[LogSource, int]] = {
    LogSource.SCREENLOG: 512_000,
    LogSource.TERM: 2_000_000,
    LogSource.APT_TERM: 4_000_000,
    LogSource.APT: 16_000_000,
}


#: ``Log time: 2026-06-23 11:09:40.123456`` at the head of an apt.log section.
_APT_LOG_TIME_RE: Final = re.compile(
    r"^Log time:\s*(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)

#: How far a log's internal timestamp may sit outside the ``main.log`` window
#: before it is judged to belong to a different run.
#:
#: Fifteen minutes. The comparison is against the *whole* window, from
#: ``main.log``'s first record to its last, and every log of a genuine run
#: starts inside that window -- so the slack only has to absorb clock jitter
#: between processes and the case where ``main.log`` is a re-exec stub spanning
#: a third of a second.
#:
#: The mismatches this has to catch are not marginal: the development machine's
#: archive directories pair a ``main.log`` with logs 29 days and 5 months older.
COHERENCE_SLACK_S: Final[float] = 900.0


def _log_timestamp(log_set: LogSet, source: LogSource) -> datetime | None:
    """The first wall-clock time a log states about itself, if any."""
    if source is LogSource.APT:
        for line in log_set.lines(source):
            if match := _APT_LOG_TIME_RE.match(line):
                return _parse_local(match["date"], match["time"])
        return None
    if source is LogSource.APT_TERM:
        parsed = parse_apt_term(log_set.lines(source))
        for block in parsed.blocks:
            if block.start is not None:
                return block.start
        return None
    if source is LogSource.HISTORY:
        for transaction in parse_history(log_set.lines(source)).transactions:
            if transaction.start is not None:
                return transaction.start
        return None
    return None


def _parse_local(date: str, time: str) -> datetime | None:
    try:
        return datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def check_coherence(log_set: LogSet, main: MainLog) -> dict[LogSource, datetime]:
    """Find logs whose own timestamps place them in a different run.

    ``/var/log/dist-upgrade`` is archived *wholesale* when an upgrade starts:
    whatever is sitting there gets moved into a ``YYYYMMDD-HHMM`` directory
    named for the moment of archiving, not for when those logs were written. So
    one directory routinely holds logs from unrelated runs. The fixture
    directory on the development machine has a ``main.log`` from 23 June beside
    an ``apt.log``, ``apt-term.log`` and ``history.log`` from 16 January.

    Taken at face value that directory reports an upgrade with 134 broken
    packages and no recorded release pair -- 134 packages that broke half a
    year earlier, attributed to a run that did nothing but re-exec into screen.

    Every one of these logs states its own time, so the mismatch is detectable
    rather than something to be lived with. Returns the offending sources and
    the timestamp that condemned them.
    """
    if main.started_at is None:
        # Nothing to correlate against. Keeping the logs is the lesser error:
        # being unable to prove they belong is not proof that they do not.
        return {}

    if LogSource.MAIN in log_set.truncated:
        # Only the tail of main.log was kept, so its apparent start is late in
        # the run and every other log would look impossibly early. Refusing to
        # judge is correct here; there is no cap on main.log precisely so this
        # does not normally arise.
        return {}

    window_start = main.started_at
    window_end = main.ended_at or main.started_at
    stale: dict[LogSource, datetime] = {}

    for source in (LogSource.APT, LogSource.APT_TERM, LogSource.HISTORY):
        if not log_set.has(source):
            continue
        stamp = _log_timestamp(log_set, source)
        if stamp is None:
            continue
        before = (window_start - stamp).total_seconds()
        after = (stamp - window_end).total_seconds()
        if max(before, after) > COHERENCE_SLACK_S:
            stale[source] = stamp
    return stale


@dataclass(slots=True)
class LogSet:
    """The raw text of one attempt's logs, already sanitised and redacted."""

    source_dir: str = ""
    attempt: int = 0
    texts: dict[LogSource, str] = field(default_factory=dict)
    truncated: set[LogSource] = field(default_factory=set)
    """Logs whose tail was kept because the file exceeded its cap."""

    stale: dict[LogSource, datetime] = field(default_factory=dict)
    """Logs excluded for belonging to a different run. See
    :func:`check_coherence`."""

    @property
    def present(self) -> tuple[LogSource, ...]:
        return tuple(sorted(self.texts, key=lambda s: s.value))

    def lines(self, source: LogSource) -> list[str]:
        return self.texts.get(source, "").splitlines()

    def has(self, source: LogSource) -> bool:
        return source in self.texts

    def without(self, sources: Iterable[LogSource]) -> LogSet:
        """A copy with the given logs dropped, recording why."""
        dropped = set(sources)
        if not dropped:
            return self
        return LogSet(
            source_dir=self.source_dir,
            attempt=self.attempt,
            texts={k: v for k, v in self.texts.items() if k not in dropped},
            truncated={s for s in self.truncated if s not in dropped},
            stale=dict(self.stale),
        )


@dataclass(slots=True)
class IngestResult:
    """Everything one directory produced."""

    runs: list[UpgradeRun] = field(default_factory=list)
    lex_stats: dict[int, LexStats] = field(default_factory=dict)
    """Per-attempt lexer coverage, for the ``--strict`` health check."""

    skipped: list[str] = field(default_factory=list)

    @property
    def primary(self) -> UpgradeRun | None:
        for run in self.runs:
            if run.is_primary:
                return run
        return self.runs[0] if self.runs else None


def discover(root: Path) -> Iterator[tuple[int, Path]]:
    """Yield ``(attempt, directory)``, most recent first.

    Attempt 0 is the top-level directory. Archived directories are numbered in
    reverse chronological order, which is the order a triager cares about.
    """
    if not root.is_dir():
        return
    archived = sorted(
        (child for child in root.iterdir() if child.is_dir() and ATTEMPT_DIR_RE.match(child.name)),
        key=lambda p: p.name,
        reverse=True,
    )
    if any(root.joinpath(name).is_file() for name in LOG_FILENAMES):
        yield (0, root)
    yield from enumerate(archived, start=1)


def read_log_set(directory: Path, attempt: int = 0, *, redact: bool = True) -> LogSet:
    """Read and clean every recognised log in one directory.

    ``redact`` defaults to on, and did not used to. The Launchpad path has
    always redacted -- it is the default in :func:`read_log` -- so a bug fetched
    from the web had its hostname and home directory removed while the same
    logs read from ``/var/log/dist-upgrade`` kept them, with no comment saying
    why and with ``IngestConfig.redact`` claiming otherwise.

    That mattered because the record is persisted and the Markdown report
    quotes log lines verbatim for pasting into a public bug. ``uname
    information:`` carries the hostname and is an ordinary event, so whether it
    reached the page depended only on whether a finding happened to match that
    line. Redaction is idempotent, so the safe default costs nothing on logs
    that have already been through it.
    """
    log_set = LogSet(source_dir=str(directory), attempt=attempt)
    for name, source in LOG_FILENAMES.items():
        path = directory / name
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        cap = _SIZE_CAPS.get(source)
        if cap is not None and len(data) > cap:
            log_set.truncated.add(source)
        text = read_log(data, redacted=redact, max_bytes=cap)
        # An existing but empty log is itself evidence, so the key is recorded
        # even when the text is blank.
        log_set.texts[source] = text
    return log_set


def is_terminal_error(message: str) -> bool:
    """Whether an ``ERROR`` record means the run stopped.

    Conservative in the safe direction: an unrecognised error counts as
    terminal, because missing a real failure is worse than over-reporting one
    the run survived.
    """
    return not any(benign in message for benign in _BENIGN_ERRORS)


def terminal_errors(main: MainLog) -> list[tuple[int, str]]:
    """``main.log`` errors that actually ended the run."""
    return [(line, msg) for line, msg in main.errors if is_terminal_error(msg)]


def _series_from_main(
    main: MainLog, interner: Interner, meta: ApportMeta | None
) -> tuple[str, str]:
    """Resolve the release pair, falling back to the apport metadata.

    ``main.log``'s ``Upgrading from X to Y`` is authoritative and names both
    codenames directly. When no ``main.log`` was attached -- common, because
    reporters often attach only the apt log -- the source release is still
    recoverable from apport's ``DistroRelease: Ubuntu 24.04`` via
    ``/usr/share/distro-info/ubuntu.csv``.

    The *target* is deliberately left blank in that case rather than guessed.
    A 24.04 system can be upgrading to 24.10 or to 26.04, the log does not say
    which, and a title that asserts the wrong target is worse than one that
    admits to not knowing.
    """

    def get(key: str) -> str:
        value = main.meta.get(key)
        return interner.text(value) if value is not None else ""

    from_series, to_series = get("from_release"), get("to_release")
    if from_series or meta is None or not meta.distro_release:
        return (from_series, to_series)

    entry = series_table().by_version(meta.distro_release)
    return (entry.series if entry else "", to_series)


def _phase_spans(main: MainLog, *, failed: bool) -> tuple[PhaseSpan, ...]:
    """Build phase spans, marking only the final phase as failed.

    Earlier phases completed by definition -- the run got past them -- so
    attributing the failure to anything but the terminal phase would be
    inventing detail the log does not support.
    """
    spans: list[PhaseSpan] = []
    ordered = sorted(main.spans.items(), key=lambda item: item[0])
    for index, (phase, (start, end)) in enumerate(ordered):
        last = index == len(ordered) - 1
        outcome = PhaseOutcome.OK
        if last:
            outcome = PhaseOutcome.FAILED if failed else PhaseOutcome.UNKNOWN
        spans.append(PhaseSpan(phase=phase, t_start_ms=start, t_end_ms=end, outcome=outcome))
    return tuple(spans)


def _arch_of(meta: ApportMeta | None, main: MainLog, interner: Interner) -> Arch:
    if meta is not None and meta.architecture:
        try:
            return Arch(meta.architecture)
        except ValueError:
            pass
    kernel = main.meta.get("kernel")
    if kernel is not None and "x86_64" in interner.text(kernel):
        return Arch.AMD64
    return Arch.UNKNOWN


def _delta(main: MainLog, graphs: Sequence[ConflictGraph]) -> tuple[PackageDelta, PackageCounts]:
    """Pack the package sets, taking broken packages from the apt graph.

    ``main.log``'s lists are the upgrader's plan; the broken set only exists in
    the resolver trace, so the two sources are combined here rather than
    pretending either is complete on its own.

    Only nodes actually carrying a broken bit are counted. The graph holds
    every package the resolver mentioned -- blamers, dependencies and
    candidates alike -- so treating all of its nodes as broken reported 964
    broken packages for a bug whose resolver trace says 148.
    """

    def ids(key: str) -> list[PkgId]:
        return sorted(set(main.packages.get(key, ())))

    broken: set[PkgId] = set()
    for graph in graphs:
        nodes = graph.nodes
        for index, pkg_id in enumerate(nodes.ids):
            if any(nodes.has(index, bit) for bit in _BROKEN_BITS):
                broken.add(pkg_id)

    fields = {
        "upgraded": ids("upgraded"),
        "installed": ids("installed"),
        "removed": ids("removed"),
        "held_back": ids("held_back"),
        "obsolete": ids("obsolete"),
        "broken": sorted(broken),
    }
    delta = PackageDelta(**{key: pack_u32(value) for key, value in fields.items()})
    counts = PackageCounts(**{key: len(value) for key, value in fields.items()})
    return (delta, counts)


def ingest_logs(
    log_set: LogSet,
    interner: Interner,
    *,
    meta: ApportMeta | None = None,
    bug_id: int | None = None,
    is_primary: bool = True,
    stats: LexStats | None = None,
) -> UpgradeRun:
    """Reduce one attempt's logs to an :class:`UpgradeRun`.

    The parse order is fixed and load-bearing:

    1. ``main.log``, which establishes the run's time window.
    2. A coherence check, dropping logs that belong to a different run -- see
       :func:`check_coherence`.
    3. ``apt.log``, which interns every architecture-qualified package name.
    4. ``main.log``'s ``Foreign`` list resolved against those names, which only
       works once step 3 has run.

    Steps 3 and 4 cannot be swapped. Resolving first matches nothing, the
    ``Conflicts`` blame reorientation does nothing, and the only symptom is a
    worse diagnosis on one class of bug.
    """
    # 1. main.log: phases, versions, the Foreign list, and the time window.
    main = parse_main_log(log_set.lines(LogSource.MAIN), interner)

    # 2. Reject logs left behind by an earlier, unrelated run.
    stale = check_coherence(log_set, main)
    if stale:
        log_set = log_set.without(stale)
        log_set.stale = stale

    # 3. apt.log -- this is what interns ``name:arch``.
    graphs: list[ConflictGraph] = []
    apt_truncated = False
    apt_broken_count = 0
    oscillations: tuple[tuple[int, int, int, int], ...] = ()
    if log_set.has(LogSource.APT):
        sectioned = read_sections(log_set.lines(LogSource.APT), stats=stats)
        apt_truncated = sectioned.truncated
        if sectioned.primary is not None:
            graphs.append(build_graph(sectioned.primary, interner))
            apt_broken_count = sectioned.primary.broken_count or 0
            # Only livelocks apt was still stuck in when it gave up. One it
            # escaped is a detour it recovered from, not the reason the
            # upgrade failed, and the livelock rule outranks blast radius --
            # so letting a recovered oscillation through would let it displace
            # a genuine hundred-package cascade.
            oscillations = tuple(
                (o.pkg_id, o.reversals, o.blocked_by, o.forced_by)
                for o in detect_oscillations(sectioned.primary, interner)
                if o.is_terminal
            )

    # 4. Only now can the third-party set be resolved.
    third_party = resolve_third_party(main, interner)

    # The locale must come from main.log, which is why this runs after it:
    # dpkg's output is translated, and parsing an Italian apt-term.log as
    # English yields zero counts and no failures.
    locale = interner.text(main.meta["locale"]) if "locale" in main.meta else None

    term: TermLog | None = None
    if log_set.has(LogSource.APT_TERM):
        term = parse_apt_term(log_set.lines(LogSource.APT_TERM), locale=locale)

    history: HistoryLog | None = None
    if log_set.has(LogSource.HISTORY):
        history = parse_history(log_set.lines(LogSource.HISTORY))

    dpkg_wrote = _dpkg_wrote(log_set, term, meta, main)
    fatal = terminal_errors(main)
    failed = bool(fatal) or main.aborted or bool(term and term.roots)
    evidence_complete = _evidence_complete(main, apt_truncated, term)

    from_series, to_series = _series_from_main(main, interner, meta)
    delta, counts = _delta(main, graphs)

    return UpgradeRun(
        bug_id=bug_id,
        attempt=log_set.attempt,
        is_primary=is_primary,
        source_dir=log_set.source_dir,
        from_series=from_series,
        to_series=to_series,
        arch=_arch_of(meta, main, interner),
        problem_type=meta.problem_type if meta else ProblemType.UNKNOWN,
        apt_version=interner.text(main.meta["apt_version"]) if "apt_version" in main.meta else "",
        upgrader_version=(
            interner.text(main.meta["upgrader_version"]) if "upgrader_version" in main.meta else ""
        ),
        python_version=(
            interner.text(main.meta["python_version"]) if "python_version" in main.meta else ""
        ),
        kernel=interner.text(main.meta["kernel"]) if "kernel" in main.meta else "",
        locale=locale or "",
        frontend=_FRONTENDS.get(
            interner.text(main.meta["view"]) if "view" in main.meta else "", Frontend.UNKNOWN
        ),
        started_at=main.started_at or _started_at(history, term),
        phases=_phase_spans(main, failed=failed),
        terminal_phase=main.terminal_phase,
        evidence_complete=evidence_complete,
        dpkg_wrote=dpkg_wrote,
        logs_present=log_set.present,
        events=tuple(main.events),
        pkgs=delta,
        counts=counts,
        graphs=tuple(graphs),
        apt_error_entries=tuple(interner.string(e.text) for e in main.apt_errors),
        apt_warning_entries=tuple(interner.string(w.text) for w in main.apt_warnings),
        tags=meta.tags if meta else (),
        third_party=third_party,
        apt_broken_count=apt_broken_count,
        oscillations=oscillations,
    )


def _dpkg_wrote(
    log_set: LogSet,
    term: TermLog | None,
    meta: ApportMeta | None,
    main: MainLog,
) -> bool | None:
    """Decide whether dpkg wrote packages, or admit to not knowing.

    Ordered by how directly each source answers the question.
    """
    # A parsed apt-term.log is decisive in both directions.
    if term is not None:
        return term.dpkg_ran
    # The description can report the file as having existed and been empty.
    if meta is not None and meta.dpkg_produced_no_output:
        return False

    # Absence of both dpkg logs only means dpkg never ran if the rest of the
    # evidence agrees, and ``main.log`` is the arbiter. A run that reached
    # COMMIT wrote packages whether or not the reporter attached the dpkg
    # logs, and attaching only apt.log and main.log is common.
    #
    # Taking absence as proof marked LP#2169251 -- an upgrade that completed,
    # installed 2881 packages and reached POST_INSTALL_SCRIPTS -- as never
    # having run dpkg, which stopped the ranking from recognising it as a
    # post-upgrade failure at all.
    if not log_set.has(LogSource.APT_TERM) and not log_set.has(LogSource.HISTORY):
        if main.terminal_phase >= Phase.COMMIT:
            return True
        if main.record_count:
            return False
        return None
    return None


def _evidence_complete(main: MainLog, apt_truncated: bool, term: TermLog | None) -> bool:
    """Whether the logs tell a finished story.

    A log that stops mid-run is the one case where this tool must refuse to
    name a cause. Bug 2169028's ``main.log`` ends at
    ``Quirks.PreDistUpgradeCache`` with no error and no abort; the honest
    output is "no failure recorded", with the resolver roots offered as
    findings that have no confirmed terminal cause.
    """
    if apt_truncated or (term is not None and term.truncated):
        return False
    if term is not None and term.roots:
        # dpkg reported a failure it could not recover from. That is a definite
        # conclusion on its own, whatever main.log does or does not say -- and
        # bugs filed against a failing package routinely carry apt-term.log
        # without a main.log at all.
        return True
    if main.record_count == 0:
        # No main.log at all. An apt log on its own can still be analysed, but
        # we cannot claim to know how the run ended.
        return False
    if main.terminal_phase is Phase.SCREEN_REEXEC:
        # The run moved into screen and continued in a different log. Nothing
        # went wrong; this log simply is not the whole story.
        return False
    # A conclusion means: an explicit abort, an apt error stack, a terminal
    # error, or having run to the end.
    return (
        main.aborted
        or bool(main.apt_errors)
        or bool(terminal_errors(main))
        or main.terminal_phase >= Phase.POST_CLEANUP
    )


def _started_at(history: HistoryLog | None, term: TermLog | None) -> datetime | None:
    """Wall-clock start, which only the dpkg-side logs record.

    ``main.log`` has timestamps but ingest stores its events as offsets, so the
    absolute start is taken from whichever log states one.
    """
    if history is not None:
        for transaction in history.transactions:
            if transaction.start is not None:
                return transaction.start
    if term is not None:
        for block in term.blocks:
            if block.start is not None:
                return block.start
    return None


def ingest_directory(
    root: Path,
    interner: Interner,
    *,
    meta: ApportMeta | None = None,
    bug_id: int | None = None,
    redact: bool = True,
) -> IngestResult:
    """Ingest every attempt in a ``dist-upgrade`` directory."""
    result = IngestResult()
    for attempt, directory in discover(root):
        log_set = read_log_set(directory, attempt, redact=redact)
        if not log_set.texts:
            result.skipped.append(f"{directory} (no recognised logs)")
            continue
        stats = LexStats()
        run = ingest_logs(
            log_set,
            interner,
            meta=meta if attempt == 0 else None,
            bug_id=bug_id,
            is_primary=attempt == 0,
            stats=stats,
        )
        result.runs.append(run)
        result.lex_stats[attempt] = stats
    if result.runs and not any(run.is_primary for run in result.runs):
        # Only archived attempts were found. The newest of them is primary.
        result.runs[0] = result.runs[0].model_copy(update={"is_primary": True})
    return result


def ingest_attachments(
    attachments: dict[LogSource, str],
    interner: Interner,
    *,
    meta: ApportMeta | None = None,
    bug_id: int | None = None,
) -> UpgradeRun:
    """Ingest logs that came from Launchpad attachments rather than a directory.

    A bug carries one attempt's worth of logs, so there is no attempt
    numbering to do.
    """
    log_set = LogSet(source_dir=f"lp:{bug_id}" if bug_id else "lp:", texts=dict(attachments))
    return ingest_logs(log_set, interner, meta=meta, bug_id=bug_id, is_primary=True)


def unpack_events(run: UpgradeRun) -> tuple[Event, ...]:
    """Events in log order, for the report."""
    return tuple(sorted(run.events, key=lambda e: (e.t_ms, e.line_no)))
