# SPDX-License-Identifier: GPL-2.0-or-later
"""Parsing ``apt-term.log``, dpkg's own terminal output.

The authority on whether anything was written to the system, and the only place
a maintainer-script failure is explained.

**Block framing decides whether dpkg ran.** The file is a sequence of
``Log started:``/``Log ended:`` blocks, one per ``cache.commit()``. A block can
be completely empty, and that is not a parser artefact: a successful run in our
fixtures opens with ``Log started: 11:13:22`` / ``Log ended: 11:13:23`` and
nothing in between, because the upgrader commits once before re-planning. So
"this file exists" and even "``history.log`` lists 969 packages" do not mean
dpkg did work -- a non-empty block does. ``history.log`` records what apt
*planned* at commit time and lists the full package set either way.

**Proximity is not causation.** A failing maintainer script writes whatever it
likes to the terminal, and the lines nearest the error are routinely innocent.
The reference case in our fixtures is ``python3`` failing to configure: the
twenty lines above the error are ``SyntaxWarning`` notices about files in
``hplip``, which had nothing to do with it, while the actual cause is a single
line naming a different package entirely::

    SyntaxError: Non-UTF-8 code starting with '\\xc2' on line 3 ...
    error running python rtupdate hook llvm-21-tools
    dpkg: error processing package python3 (--configure):
     old python3 package postinst maintainer script subprocess failed with exit status 4

This is the same shape of trap as the ``W:``/``E:`` confusion in ``main.log``.
Blame is therefore decided by the *reason line* that dpkg prints immediately
after naming the package, never by what happens to be nearby.

**The log may not be in English.** dpkg's output is fully translated: an
Italian ``apt-term.log`` says ``Configurazione di`` for ``Setting up`` and
``dpkg: attenzione:`` for ``dpkg: warning:``. Matching English alone returns
zero counts and misses every failure, so :func:`parse_apt_term` takes a locale
and consults the same ``dpkg`` message catalogue dpkg itself used. See
:mod:`uru_doctor.i18n`.

**The reason line separates roots from victims.** ``dependency problems -
leaving unconfigured`` means this package is collateral damage; a maintainer
script exit status or a file conflict means it is a cause. In the reference
cascade one package is a root and thirty-four are victims, and the
``Errors were encountered while processing:`` summary lists all thirty-five
without distinguishing them.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final

from uru_doctor.i18n import dpkg_verb_patterns

__all__ = [
    "DpkgFailure",
    "FailureKind",
    "TermBlock",
    "TermLog",
    "parse_apt_term",
]

_LOG_START_RE: Final = re.compile(
    r"^Log started:\s*(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)
_LOG_END_RE: Final = re.compile(
    r"^Log ended:\s*(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)

#: ``dpkg: error processing package foo:amd64 (--configure):``
#: and the archive form ``dpkg: error processing archive /path/foo.deb (--unpack):``
_DPKG_ERROR_RE: Final = re.compile(
    r"^dpkg: error processing (?:package\s+(?P<package>[^\s(]+)"
    r"|archive\s+(?P<archive>\S+))\s*\((?P<action>--\w[\w-]*)\)\s*:"
)

#: ``dpkg: dependency problems prevent configuration of foo:``
_DPKG_DEPS_RE: Final = re.compile(
    r"^dpkg: dependency problems prevent (?P<what>configuration|processing triggers) "
    r"(?:of|for)\s+(?P<package>[^\s:]+(?::\w+)?)\s*:"
)

#: ``Errors were encountered while processing:`` then one indented name per line.
_SUMMARY_RE: Final = re.compile(r"^Errors were encountered while processing:\s*$")

#: ``E: Sub-process /usr/bin/dpkg returned an error code (1)``
_SUBPROCESS_RE: Final = re.compile(
    r"^E: Sub-process (?P<program>\S+) returned an error code \((?P<code>\d+)\)"
)

#: Lines that name the real culprit of a byte-compile or hook failure.
#:
#: ``error running python rtupdate hook llvm-21-tools`` is the only line in the
#: reference cascade that names the package actually at fault; the dpkg error
#: above it names ``python3``, whose postinst merely ran the hook.
_HOOK_FAILURE_RE: Final = re.compile(r"^error running (?P<kind>\S+(?: \S+)?) hook (?P<package>\S+)")

#: Reason lines that mean "this package is a victim, not a cause".
_VICTIM_REASONS: Final[tuple[str, ...]] = (
    "dependency problems - leaving unconfigured",
    "dependency problems - leaving triggers unprocessed",
)

#: Noise that must never be treated as a cause.
#:
#: Python emits these in bulk while byte-compiling unrelated packages during a
#: ``python3`` postinst. Twenty of them sit directly above the real error in
#: the reference fixture.
_NOISE_RE: Final = re.compile(
    r"(?:SyntaxWarning|DeprecationWarning|UserWarning|FutureWarning"
    r"|ResourceWarning|PendingDeprecationWarning):"
)


class FailureKind(str):
    """How a package failed, which decides whether it is blamed.

    A plain ``str`` subclass rather than an enum: the set is open, because the
    reason line is free text written by dpkg and by maintainer scripts, and an
    unrecognised reason must still be reportable verbatim.
    """

    __slots__ = ()

    #: Collateral damage: it depended on something that failed.
    DEPENDENCY = "dependency"
    #: A maintainer script exited non-zero. A cause.
    MAINTAINER_SCRIPT = "maintainer-script"
    #: Two packages ship the same path. A cause, and often a third-party one.
    FILE_CONFLICT = "file-conflict"
    #: Unpacking failed -- truncated download, full disk, corrupt archive.
    UNPACK = "unpack"
    #: Recognised as a failure but not as a known shape.
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class DpkgFailure:
    """One package dpkg could not process."""

    package: str
    """``name`` or ``name:arch`` as dpkg wrote it. Empty for archive errors."""

    action: str = ""
    """``--configure``, ``--unpack``, ``--remove``."""

    reason: str = ""
    """dpkg's indented explanation, verbatim."""

    kind: str = FailureKind.OTHER
    archive: str = ""
    """Set instead of ``package`` for ``error processing archive`` lines."""

    conflicting_package: str = ""
    """For a file conflict, the package that already owns the path."""

    conflicting_path: str = ""
    blamed_package: str = ""
    """A package named by a hook-failure line as the true culprit.

    Distinct from :attr:`package`: in the reference cascade ``package`` is
    ``python3`` and this is ``llvm-21-tools``.
    """

    exit_status: int = 0
    line_no: int = 0

    @property
    def is_victim(self) -> bool:
        """Whether this failure is explained by another package's failure."""
        return self.kind == FailureKind.DEPENDENCY

    @property
    def culprit(self) -> str:
        """The package to blame: the hook's package if named, else this one."""
        return self.blamed_package or self.package


@dataclass(frozen=True, slots=True)
class TermBlock:
    """One ``Log started``/``Log ended`` block."""

    start: datetime | None = None
    end: datetime | None = None
    line_no: int = 0
    line_count: int = 0
    """Content lines, excluding the framing and blank lines."""

    failures: tuple[DpkgFailure, ...] = ()
    summary: tuple[str, ...] = ()
    """``Errors were encountered while processing:`` -- roots and victims mixed."""

    subprocess_code: int = 0
    configured: int = 0
    unpacked: int = 0
    removed: int = 0

    @property
    def is_empty(self) -> bool:
        """Whether dpkg did nothing in this block.

        The discriminator for "were packages written". A successful run's first
        block is empty because the upgrader commits once before re-planning.
        """
        return self.line_count == 0

    @property
    def duration_s(self) -> float:
        if self.start is None or self.end is None:
            return 0.0
        return (self.end - self.start).total_seconds()

    @property
    def truncated(self) -> bool:
        """Whether the block never closed, i.e. the log stops mid-run."""
        return self.start is not None and self.end is None

    @property
    def roots(self) -> tuple[DpkgFailure, ...]:
        """Failures that are causes rather than consequences."""
        return tuple(f for f in self.failures if not f.is_victim)

    @property
    def victims(self) -> tuple[DpkgFailure, ...]:
        return tuple(f for f in self.failures if f.is_victim)


@dataclass(slots=True)
class TermLog:
    """Every block in one ``apt-term.log``."""

    blocks: list[TermBlock] = field(default_factory=list)

    @property
    def substantive(self) -> list[TermBlock]:
        return [b for b in self.blocks if not b.is_empty]

    @property
    def dpkg_ran(self) -> bool:
        """Whether dpkg actually wrote to the system.

        The reliable form of the question. Neither the file's existence nor
        ``history.log``'s package lists answer it.
        """
        return bool(self.substantive)

    @property
    def failures(self) -> tuple[DpkgFailure, ...]:
        return tuple(f for block in self.blocks for f in block.failures)

    @property
    def roots(self) -> tuple[DpkgFailure, ...]:
        """Causal failures across the whole log, in order."""
        return tuple(f for f in self.failures if not f.is_victim)

    @property
    def truncated(self) -> bool:
        return any(b.truncated for b in self.blocks)


#: ``trying to overwrite '/usr/bin/foo', which is also in package bar 1.0``
_OVERWRITE_RE: Final = re.compile(
    r"trying to overwrite ['\"](?P<path>[^'\"]+)['\"], which is also in package "
    r"(?P<package>\S+)(?:\s+(?P<version>\S+))?"
)

#: ``... subprocess ... returned error exit status 4``, and dpkg's older
#: ``subprocess failed with exit status N`` phrasing.
_EXIT_STATUS_RE: Final = re.compile(
    r"(?:returned error exit status|failed with exit status|exited with status)\s+(?P<code>\d+)"
)


def _classify(reason: str) -> str:
    """Map dpkg's reason line to a :class:`FailureKind`."""
    lowered = reason.strip().lower()
    for victim in _VICTIM_REASONS:
        if lowered.startswith(victim):
            return FailureKind.DEPENDENCY
    if "trying to overwrite" in lowered:
        return FailureKind.FILE_CONFLICT
    if "maintainer script" in lowered or ("installed" in lowered and "script" in lowered):
        return FailureKind.MAINTAINER_SCRIPT
    if _EXIT_STATUS_RE.search(reason):
        return FailureKind.MAINTAINER_SCRIPT
    if "cannot access archive" in lowered or "unable to" in lowered:
        return FailureKind.UNPACK
    if "corrupted" in lowered or "unexpected end of file" in lowered:
        return FailureKind.UNPACK
    return FailureKind.OTHER


def _parse_stamp(date: str, time: str) -> datetime | None:
    try:
        return datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _iter_blocks(lines: Sequence[str]) -> Iterator[tuple[int, list[str], str, str]]:
    """Yield ``(line_no, body, start_stamp, end_stamp)`` per block.

    Content before the first ``Log started:`` is yielded as an unframed block.
    A hand-attached excerpt often has no framing at all, and discarding it
    would lose the only evidence on the bug.
    """
    body: list[str] = []
    origin = 1
    start = end = ""
    opened = False

    def has_content() -> bool:
        return any(line.strip() for line in body)

    for index, line in enumerate(lines, start=1):
        if match := _LOG_START_RE.match(line):
            # Only emit what came before if it was a real block. Blocks are
            # separated by a blank line, and the file opens with one, so
            # treating any accumulated lines as a block invents two empty
            # blocks per file -- which would then be miscounted as the
            # genuine empty block that proves a no-op commit.
            if opened or has_content():
                yield (origin, body, start, end)
            body, start, end, origin, opened = [], "", "", index, True
            start = f"{match['date']} {match['time']}"
            continue
        if (match := _LOG_END_RE.match(line)) and opened:
            end = f"{match['date']} {match['time']}"
            yield (origin, body, start, end)
            body, start, end, opened = [], "", "", False
            continue
        body.append(line)

    if opened or has_content():
        yield (origin, body, start, end)


def parse_apt_term(lines: Sequence[str], *, locale: str | None = None) -> TermLog:
    """Parse ``apt-term.log`` into blocks and failures.

    ``locale`` comes from ``main.log``'s ``locale:`` line. Without it the
    parser assumes English, which silently produces zero counts and no
    failures on a translated log rather than reporting a problem.
    """
    verbs = dpkg_verb_patterns(locale)
    log = TermLog()
    for line_no, body, start, end in _iter_blocks(lines):
        log.blocks.append(_parse_block(line_no, body, start, end, verbs))
    return log


def _parse_block(
    line_no: int,
    body: list[str],
    start: str,
    end: str,
    verbs: dict[str, re.Pattern[str]] | None = None,
) -> TermBlock:
    failures: list[DpkgFailure] = []
    summary: list[str] = []
    in_summary = False
    pending_hook = ""
    subprocess_code = 0
    configured = unpacked = removed = 0
    content = 0

    index = 0
    while index < len(body):
        raw = body[index]
        line = raw.rstrip()
        stripped = line.strip()
        if stripped:
            content += 1

        if in_summary:
            # The summary is an indented list, terminated by any unindented line.
            if line.startswith((" ", "\t")) and stripped:
                summary.append(stripped)
                index += 1
                continue
            in_summary = False

        if _SUMMARY_RE.match(stripped):
            in_summary = True
            index += 1
            continue

        if verbs:
            # Matched anywhere in the line, not anchored: German and Japanese
            # put the package name before the verb.
            if (pattern := verbs.get("setting_up")) and pattern.search(stripped):
                configured += 1
            elif (pattern := verbs.get("unpacking")) and pattern.search(stripped):
                unpacked += 1
            elif (
                (pattern := verbs.get("removing"))
                and pattern.search(stripped)
                and "diversion" not in stripped
                and "deviazione" not in stripped
            ):
                removed += 1
        elif stripped.startswith("Setting up "):
            configured += 1
        elif stripped.startswith("Unpacking "):
            unpacked += 1
        elif stripped.startswith("Removing ") and "diversion" not in stripped:
            removed += 1

        # Remember a hook failure so the dpkg error below it can be blamed
        # correctly. Reset on the next dpkg error so it is never carried across
        # two unrelated failures.
        if hook := _HOOK_FAILURE_RE.match(stripped):
            pending_hook = hook["package"]

        if match := _SUBPROCESS_RE.match(stripped):
            subprocess_code = int(match["code"])

        if match := _DPKG_ERROR_RE.match(stripped):
            reason, consumed = _collect_reason(body, index + 1)
            failure = _build_failure(
                package=match["package"] or "",
                archive=match["archive"] or "",
                action=match["action"] or "",
                reason=reason,
                hook=pending_hook,
                line_no=line_no + index,
            )
            failures.append(failure)
            pending_hook = ""
            index += 1 + consumed
            continue

        index += 1

    return TermBlock(
        start=_parse_stamp(*start.split()) if start else None,
        end=_parse_stamp(*end.split()) if end else None,
        line_no=line_no,
        line_count=content,
        failures=tuple(failures),
        summary=tuple(summary),
        subprocess_code=subprocess_code,
        configured=configured,
        unpacked=unpacked,
        removed=removed,
    )


def _collect_reason(body: Sequence[str], start: int) -> tuple[str, int]:
    """Gather the indented reason lines following a dpkg error.

    Noise is dropped here rather than later: a ``SyntaxWarning`` indented under
    an error would otherwise become part of the reason and then part of the
    deduplication signature, splitting one fault into many.
    """
    collected: list[str] = []
    index = start
    while index < len(body):
        line = body[index].rstrip()
        if not line.startswith((" ", "\t")) or not line.strip():
            break
        if not _NOISE_RE.search(line):
            collected.append(line.strip())
        index += 1
    return (" ".join(collected), index - start)


def _build_failure(
    *,
    package: str,
    archive: str,
    action: str,
    reason: str,
    hook: str,
    line_no: int,
) -> DpkgFailure:
    kind = _classify(reason)
    conflicting = path = ""
    if overwrite := _OVERWRITE_RE.search(reason):
        conflicting = overwrite["package"]
        path = overwrite["path"]
        kind = FailureKind.FILE_CONFLICT

    status = 0
    if exit_match := _EXIT_STATUS_RE.search(reason):
        status = int(exit_match["code"])

    # A hook failure is only allowed to redirect blame when the package itself
    # failed by running that hook. Otherwise the two are unrelated and the
    # redirect would invent a culprit.
    blamed = hook if hook and kind == FailureKind.MAINTAINER_SCRIPT else ""

    return DpkgFailure(
        package=package,
        archive=archive,
        action=action,
        reason=reason,
        kind=kind,
        conflicting_package=conflicting,
        conflicting_path=path,
        blamed_package=blamed,
        exit_status=status,
        line_no=line_no,
    )
