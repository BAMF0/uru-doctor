"""Parsing ``history.log``, apt's record of what it actually did.

The authoritative answer to "were packages written to this system". ``main.log``
says what the upgrader *intended*; this file says what apt *committed*, with
old and new versions for every package. Field names are
``Start-Date``, ``End-Date``, ``Commandline``, ``Requested-By``, ``Install``,
``Upgrade``, ``Remove``, ``Purge``, ``Downgrade``, ``Reinstall``, ``Error`` and
``Comment``, taken from ``libapt-pkg``.

Two traps.

**A file can hold several transactions, including stale ones.** apt appends,
and ``/var/log/dist-upgrade/history.log`` survives from one upgrade to the next.
One of our bug fixtures reports ``UpgradeStatus: Upgraded to noble`` -- so its
``history.log`` contains that *earlier, successful* upgrade as well as the
failed attempt. Reading the file as a whole and concluding "packages were
installed" is therefore wrong, and it is wrong in the dangerous direction: it
turns a planning failure that touched nothing into an apparent half-upgraded
system. :meth:`HistoryLog.within` exists to select only the transactions that
overlap the run being analysed.

**Commas appear inside the parentheses.** ``Install:`` entries look like
``libfoo:amd64 (1.2-3, automatic)`` and ``Upgrade:`` entries like
``libfoo:amd64 (1.2-3, 1.2-4)``. Splitting the list on ``", "`` shreds every
entry in half. Entries are extracted by matching ``name (contents)`` instead,
which is safe because a Debian version cannot contain a parenthesis.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final

__all__ = [
    "HISTORY_LIST_FIELDS",
    "HistoryLog",
    "PackageChange",
    "Transaction",
    "parse_history",
    "parse_package_list",
]

#: ``Start-Date: 2026-06-23  11:13:22`` -- two spaces, which is apt's format.
_DATE_RE: Final = re.compile(
    r"^(?P<key>Start-Date|End-Date):\s*(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)

_FIELD_RE: Final = re.compile(r"^(?P<key>[A-Za-z][A-Za-z-]*):[ \t]*(?P<value>.*)$")

#: ``libfoo:amd64 (1.2-3, automatic)``. The name stops at whitespace or ``(``;
#: the body is everything up to the closing parenthesis.
_ENTRY_RE: Final = re.compile(r"(?P<name>[^\s(,][^\s(]*)\s+\((?P<body>[^)]*)\)")

#: Fields whose value is a package list.
HISTORY_LIST_FIELDS: Final[tuple[str, ...]] = (
    "Install",
    "Upgrade",
    "Remove",
    "Purge",
    "Downgrade",
    "Reinstall",
)


@dataclass(frozen=True, slots=True)
class PackageChange:
    """One package's change within a transaction."""

    name: str
    """``name:arch`` exactly as apt wrote it."""

    version: str = ""
    """The resulting version. For an upgrade, the new one."""

    previous: str = ""
    """The prior version, for upgrades and downgrades only."""

    automatic: bool = False
    """Whether apt marked it auto-installed, i.e. pulled in as a dependency."""

    @property
    def is_upgrade(self) -> bool:
        return bool(self.previous) and bool(self.version)


def parse_package_list(value: str) -> tuple[PackageChange, ...]:
    """Parse one ``Install:``/``Upgrade:``/... field value.

    The parenthesised body is comma-separated and position-dependent: a bare
    version, ``old, new`` for an upgrade, or a version plus the literal
    ``automatic``. Deciding by content rather than by which field we are in
    keeps this function usable for all of them.
    """
    out: list[PackageChange] = []
    for match in _ENTRY_RE.finditer(value):
        parts = [part.strip() for part in match["body"].split(",") if part.strip()]
        automatic = "automatic" in parts
        versions = [part for part in parts if part != "automatic"]
        previous = versions[0] if len(versions) > 1 else ""
        current = versions[-1] if versions else ""
        out.append(
            PackageChange(
                name=match["name"],
                version=current,
                previous=previous,
                automatic=automatic,
            )
        )
    return tuple(out)


@dataclass(frozen=True, slots=True)
class Transaction:
    """One ``Start-Date`` to ``End-Date`` block."""

    start: datetime | None = None
    end: datetime | None = None
    requested_by: str = ""
    commandline: str = ""
    error: str = ""
    comment: str = ""
    changes: dict[str, tuple[PackageChange, ...]] = field(default_factory=dict)
    line_no: int = 0

    @property
    def duration_s(self) -> float:
        if self.start is None or self.end is None:
            return 0.0
        return (self.end - self.start).total_seconds()

    @property
    def total_changes(self) -> int:
        return sum(len(v) for v in self.changes.values())

    @property
    def is_empty(self) -> bool:
        """Whether apt committed nothing.

        A real occurrence, not a theoretical one: a quirk calls
        ``cache.commit()`` during PostInitialUpdate to persist an auto-install
        mark, which produces a transaction that changes no packages. Counting
        it as evidence that dpkg ran is how a pre-commit failure gets
        misreported as a partial upgrade.
        """
        return self.total_changes == 0

    @property
    def failed(self) -> bool:
        return bool(self.error)

    def names(self, *fields: str) -> tuple[str, ...]:
        """Package names across the given change fields, in order."""
        wanted = fields or HISTORY_LIST_FIELDS
        return tuple(change.name for key in wanted for change in self.changes.get(key, ()))


def _parse_stamp(date: str, time: str) -> datetime | None:
    try:
        return datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


@dataclass(slots=True)
class HistoryLog:
    """Every transaction in one ``history.log``."""

    transactions: list[Transaction] = field(default_factory=list)

    @property
    def substantive(self) -> list[Transaction]:
        """Transactions that actually changed packages."""
        return [t for t in self.transactions if not t.is_empty]

    @property
    def collapsed(self) -> list[Transaction]:
        """Transactions with repeats of the same change set merged.

        One upgrade attempt can produce several identical transactions. The
        upgrader commits, reopens the cache, re-runs its planning quirks and
        commits again, and apt writes a full history entry each time from the
        *planned* state -- so a single run shows up twice with the same 969
        packages, the first lasting 0.68 seconds and the second fourteen
        minutes. Summing over the file would double-count every package.

        Repeats are identified by their change set, and the longest-running
        member of each group is kept, because that is the one during which dpkg
        did the work. This mirrors the duplicate-section collapsing in
        :mod:`uru_doctor.apt.sections`, where apt logs one resolve four times.
        """
        best: dict[tuple[tuple[str, tuple[str, ...]], ...], Transaction] = {}
        order: list[tuple[tuple[str, tuple[str, ...]], ...]] = []
        for transaction in self.transactions:
            key = tuple(
                (field_name, tuple(c.name for c in changes))
                for field_name, changes in sorted(transaction.changes.items())
            )
            if key not in best:
                best[key] = transaction
                order.append(key)
            elif transaction.duration_s > best[key].duration_s:
                best[key] = transaction
        return [best[key] for key in order]

    @property
    def wrote_packages(self) -> bool:
        """Whether any transaction in the file changed a package.

        Weaker than it looks, and not the question usually being asked. The
        file may be stale -- use :meth:`within` when the run window is known --
        and a transaction records what apt *planned* at commit time, so a
        commit whose dpkg run did nothing still appears here with a full
        package list. For "did dpkg actually write anything", the authority is
        whether ``apt-term.log`` has a non-empty block; see
        :mod:`uru_doctor.parsers.aptterm`.
        """
        return bool(self.substantive)

    def within(
        self, start: datetime | None, end: datetime | None, *, slack_s: float = 300.0
    ) -> list[Transaction]:
        """Transactions overlapping ``[start, end]``.

        ``slack_s`` tolerates clock differences between the upgrader's own
        timestamps and apt's. Five minutes is generous for skew while still
        excluding a previous release upgrade, which is the case that matters.

        With no window given, every transaction is returned: being unable to
        establish staleness is not a reason to discard the evidence, only a
        reason not to claim it belongs to this run.
        """
        if start is None and end is None:
            return list(self.transactions)

        out: list[Transaction] = []
        for transaction in self.transactions:
            stamp = transaction.start or transaction.end
            if stamp is None:
                continue
            if start is not None and (start - stamp).total_seconds() > slack_s:
                continue
            if end is not None and (stamp - end).total_seconds() > slack_s:
                continue
            out.append(transaction)
        return out

    @property
    def errors(self) -> list[Transaction]:
        return [t for t in self.transactions if t.failed]


def _stanzas(lines: Sequence[str]) -> Iterator[tuple[int, list[str]]]:
    """Yield ``(line_no, stanza_lines)``, split on blank lines."""
    current: list[str] = []
    origin = 0
    for index, line in enumerate(lines, start=1):
        if line.strip():
            if not current:
                origin = index
            current.append(line)
        elif current:
            yield (origin, current)
            current = []
    if current:
        yield (origin, current)


def parse_history(lines: Sequence[str]) -> HistoryLog:
    """Parse ``history.log`` into its transactions."""
    log = HistoryLog()

    for line_no, stanza in _stanzas(lines):
        start = end = None
        fields: dict[str, str] = {}

        for raw in stanza:
            if date_match := _DATE_RE.match(raw):
                stamp = _parse_stamp(date_match["date"], date_match["time"])
                if date_match["key"] == "Start-Date":
                    start = stamp
                else:
                    end = stamp
                continue
            if field_match := _FIELD_RE.match(raw):
                fields[field_match["key"]] = field_match["value"]

        # A stanza with no Start-Date is not a transaction. The file begins
        # with a blank line and can be concatenated from several sources.
        if start is None and end is None and not fields:
            continue

        changes = {
            key: parsed
            for key in HISTORY_LIST_FIELDS
            if (parsed := parse_package_list(fields.get(key, "")))
        }
        log.transactions.append(
            Transaction(
                start=start,
                end=end,
                requested_by=fields.get("Requested-By", ""),
                commandline=fields.get("Commandline", ""),
                error=fields.get("Error", ""),
                comment=fields.get("Comment", ""),
                changes=changes,
                line_no=line_no,
            )
        )
    return log
