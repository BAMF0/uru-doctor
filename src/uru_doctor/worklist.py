# SPDX-License-Identifier: GPL-2.0-or-later
"""What still needs a decision, and what has already had one.

A diagnosis is not a triage decision. The corpus commands answer "what broke"
and "has this been seen before"; this one answers "what have I not acted on",
which is a different question and was the one thing the tool could not say.

Three properties shape everything here.

**Done is read from Launchpad, never recorded locally.** A row leaves the
worklist because the bug's status changed or because Launchpad now calls it a
duplicate -- not because something here remembers you looking at it. A local
"acknowledged" flag would be a second opinion about a fact Launchpad already
owns, and the two would diverge the first time anyone used the web UI. The
cost of this choice is that the worklist is exactly as current as the last
refresh, so :class:`Worklist` carries its own age and says so.

**It proposes.** Every row names an action a human then takes, in Launchpad,
by hand. Nothing here is phrased as a conclusion: a third-party finding is a
*candidate* Invalid, because whether a bug is Invalid is a judgement belonging
to someone accountable for it.

**It is linear in narrow rows.** Classification reads
:class:`~uru_doctor.store.TriageRow` objects, which are projections of indexed
columns, and clusters built from two indexed BLOB columns. Nothing in this
module deserialises an ``UpgradeRun``: at 0.6ms per payload against 0.02ms per
projected row, a corpus of ten thousand is the difference between six seconds
and a fifth of a second.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from uru_doctor.dedup import Tier

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from uru_doctor.dedup import Cluster
    from uru_doctor.store import TriageRow


class Bucket(StrEnum):
    """What kind of attention a bug is waiting for.

    Ordered by how safe the proposed action is, which is also the order they
    are presented in: an identical root-cause subgraph is a mechanical
    duplicate marking, while "read this log" is an afternoon.
    """

    MARK_DUPLICATE = "mark-duplicate"
    DUPLICATE_CONFLICT = "duplicate-conflict"
    CANDIDATE_INVALID = "candidate-invalid"
    DIAGNOSED_UNRECORDED = "diagnosed-unrecorded"
    NEEDS_READ = "needs-read"
    STATUS_UNKNOWN = "status-unknown"
    DONE = "done"

    @property
    def actionable(self) -> bool:
        """Whether this bucket is a worklist entry rather than a tally."""
        return self is not Bucket.DONE


#: Open statuses that record no assessment of the bug.
#:
#: ``Incomplete`` belongs here rather than among the closed statuses because it
#: means the bug is waiting on its reporter -- and that is a claim the logs can
#: contradict. A bug marked Incomplete whose attached logs *do* support a
#: diagnosis was asked for information it had already supplied, which is worth
#: surfacing rather than filing as somebody else's problem.
UNRECORDED_STATUSES: frozenset[str] = frozenset({"New", "Incomplete"})


#: One line per bucket, explaining what the rows in it have in common.
#:
#: Kept beside the enum rather than in the renderer because the terminal view,
#: the Markdown view and ``--json`` must not be able to describe the same
#: bucket differently.
BUCKET_HELP: Mapping[Bucket, str] = {
    Bucket.MARK_DUPLICATE: (
        "Same root-cause subgraph as an earlier bug, which Launchpad has not linked. "
        "The strongest tier there is: safe to act on."
    ),
    Bucket.DUPLICATE_CONFLICT: (
        "Launchpad's master and this tool's disagree. One of them is wrong and "
        "the logs are the tiebreak."
    ),
    Bucket.CANDIDATE_INVALID: (
        "The primary cause is a package Ubuntu does not ship, and the bug is still open. "
        "Candidate Invalid -- the judgement is yours."
    ),
    Bucket.DIAGNOSED_UNRECORDED: (
        "Confidently diagnosed, but the status does not say so. "
        "Nothing is wrong; nobody has written it down."
    ),
    Bucket.NEEDS_READ: (
        "No rule matched, or the evidence was too thin to name a cause. "
        "Read the log, or ask the reporter for one."
    ),
    Bucket.STATUS_UNKNOWN: (
        "No Launchpad status recorded, so these cannot be classified at all. "
        "Run `uru-doctor refresh`."
    ),
    Bucket.DONE: "Resolved, or already a duplicate. Counted, not listed.",
}


@dataclass(frozen=True, slots=True)
class Item:
    """One bug, filed under one bucket, with the action it is waiting for."""

    row: TriageRow
    bucket: Bucket
    action: str
    """What a human would do next, phrased as a proposal."""

    master: str = ""
    """Label of the bug this one should be filed under, when there is one."""

    tier: str = ""
    """Which duplicate tier put it there, when a cluster was involved."""

    @property
    def label(self) -> str:
        return self.row.label


@dataclass(frozen=True, slots=True)
class Worklist:
    """A classified corpus, plus how much to trust the classification."""

    items: tuple[Item, ...]
    counts: Mapping[Bucket, int]
    done_by_status: Mapping[str, int]
    """Breakdown of the ``DONE`` tally, so a count is never unexplained."""

    newest_check: datetime | None = None
    oldest_check: datetime | None = None
    unchecked: int = 0
    """Bugs whose Launchpad state has never been read."""

    deep_unknown: tuple[int, ...] = field(default_factory=tuple)
    """Bug ids Launchpad calls duplicates without us knowing of what.

    These are what ``refresh --deep`` would resolve, and the reason it exists:
    a search can reveal *that* a bug is a duplicate for one request per fifty
    bugs, but only the bug resource names the master.
    """

    @property
    def actionable(self) -> int:
        return sum(n for bucket, n in self.counts.items() if bucket.actionable)

    def of(self, bucket: Bucket) -> tuple[Item, ...]:
        return tuple(item for item in self.items if item.bucket is bucket)

    def stale(self, *, now: datetime, after_days: int) -> bool:
        """Whether the recorded Launchpad state is too old to rely on.

        True also when nothing has ever been checked: a worklist with no idea
        what Launchpad thinks is the least trustworthy kind, and reporting it
        as fresh because there is no timestamp to contradict would be the one
        failure this whole mechanism exists to prevent.
        """
        if self.oldest_check is None:
            return True
        return (now - self.oldest_check).days >= after_days


def _parse(stamp: str) -> datetime | None:
    """Read a stored timestamp, always as an aware one.

    A naive value is read as UTC rather than rejected. Everything in this
    codebase writes ``datetime.now(UTC).isoformat()``, so a zoneless stamp can
    only come from an older record or a hand-edited store -- and the cost of
    being strict is a ``TypeError`` deep inside a staleness subtraction, which
    takes the whole command down rather than degrading one row.
    """
    if not stamp:
        return None
    try:
        parsed = datetime.fromisoformat(stamp)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _masters(clusters: Sequence[Cluster]) -> dict[str, tuple[str, str]]:
    """Run key to ``(master run key, tier)`` for every clustered member.

    The master is included as a member of its own cluster, which is what lets
    a conflict be detected on the master as well as on its duplicates.
    """
    index: dict[str, tuple[str, str]] = {}
    for cluster in clusters:
        for member in cluster.members:
            index[member] = (cluster.representative, cluster.tier)
    return index


def classify(
    rows: Iterable[TriageRow],
    clusters: Sequence[Cluster] = (),
) -> Worklist:
    """File every run under exactly one bucket.

    First match wins, and the order is not cosmetic:

    1. A bug whose status was never read cannot be classified at all, so it is
       separated before anything that depends on knowing the status. Guessing
       would silently file a closed bug as outstanding work.
    2. A disagreement about the master is reported even for a closed bug,
       because "Launchpad says this duplicates A, the logs say B" does not stop
       mattering once somebody has closed it.
    3. Resolved and already-duplicate bugs drop out next, so no later rule can
       propose work on a bug nobody needs to touch.
    4. Only then the actionable tiers, strongest first.

    A missing cluster is never read as disagreement. The corpus routinely
    fails to find a partner for a run -- that is the absence of evidence, not
    evidence of uniqueness -- so a conflict is raised only when both masters
    are known and differ.
    """
    masters = _masters(clusters)
    projected = list(rows)
    labels = {row.run_key: row.label for row in projected}
    diagnosed = {row.run_key: row.diagnosed for row in projected}

    items: list[Item] = []
    done_by_status: Counter[str] = Counter()
    checks: list[datetime] = []
    unchecked = 0
    deep_unknown: list[int] = []

    for row in projected:
        state = row.state
        when = _parse(state.checked_at) if state else None
        if when is not None:
            checks.append(when)
        if state is None or not state.status:
            unchecked += 1

        master_key, tier = masters.get(row.run_key, ("", Tier.NONE))
        is_master = bool(master_key) and master_key == row.run_key
        master_label = labels.get(master_key, master_key)

        # 1 -- unknown status: a precondition for every test below.
        if state is None or not state.status:
            items.append(
                Item(
                    row=row,
                    bucket=Bucket.STATUS_UNKNOWN,
                    action="refresh to learn this bug's status",
                )
            )
            continue

        lp_master = state.duplicate_of
        # Known to be a duplicate, master unknown. Recorded so the command can
        # say what a deep refresh would buy.
        if state.is_duplicate and lp_master is None and row.bug_id is not None:
            deep_unknown.append(row.bug_id)

        # 2 -- the two verdicts disagree about the master.
        if (
            lp_master is not None
            and master_key
            and not is_master
            and f"LP#{lp_master}" != master_label
        ):
            items.append(
                Item(
                    row=row,
                    bucket=Bucket.DUPLICATE_CONFLICT,
                    action=(
                        f"Launchpad files this under LP#{lp_master}; "
                        f"the logs put it under {master_label}"
                    ),
                    master=master_label,
                    tier=tier,
                )
            )
            continue

        # 3 -- nothing left to do.
        if row.closed or state.is_duplicate:
            reason = "already a duplicate" if state.is_duplicate else row.status
            done_by_status[reason] += 1
            items.append(Item(row=row, bucket=Bucket.DONE, action=""))
            continue

        # 4a -- a mechanical duplicate marking.
        if (
            tier == Tier.ROOT_GRAPH
            and not is_master
            and row.diagnosed
            and diagnosed.get(master_key, False)
        ):
            items.append(
                Item(
                    row=row,
                    bucket=Bucket.MARK_DUPLICATE,
                    action=f"mark as a duplicate of {master_label}",
                    master=master_label,
                    tier=tier,
                )
            )
            continue

        # 4b -- not Ubuntu's package, and still open. The *primary* cause only;
        # see TriageRow.candidate_invalid for the three bugs in this corpus
        # that the broader test gets wrong.
        if row.candidate_invalid:
            items.append(
                Item(
                    row=row,
                    bucket=Bucket.CANDIDATE_INVALID,
                    action="judge whether this is Invalid; the cause is not an Ubuntu package",
                )
            )
            continue

        # 4c -- understood, and unrecorded.
        if row.confident and row.diagnosed and row.status in UNRECORDED_STATUSES:
            action = (
                "set a status; the cause is already known"
                if row.status == "New"
                else "the attached logs do support a diagnosis -- Incomplete may be stale"
            )
            items.append(Item(row=row, bucket=Bucket.DIAGNOSED_UNRECORDED, action=action))
            continue

        # 4d -- the tool could not settle it, and nobody has assessed it either.
        #
        # Gated on the status for a reason. A bug sitting at Confirmed, Triaged
        # or In Progress has already had a human's judgement, and "I cannot
        # read this log" adds nothing to it -- in this corpus that gate is the
        # difference between fifteen rows and eight, and the seven it removes
        # are all old reports somebody triaged years ago.
        if not row.confident and row.status in UNRECORDED_STATUSES:
            why = (
                "no rule matched"
                if row.cause is None
                else (
                    "evidence incomplete"
                    if not row.evidence_complete
                    else "cause is not a diagnosis"
                )
            )
            action = (
                f"waiting on the reporter -- {why}"
                if row.status == "Incomplete"
                else f"read the log -- {why}"
            )
            items.append(Item(row=row, bucket=Bucket.NEEDS_READ, action=action))
            continue

        # Open, but somebody has already taken a view: Confirmed, Triaged or
        # In Progress. Counted under its status rather than proposed as work.
        done_by_status[row.status] += 1
        items.append(Item(row=row, bucket=Bucket.DONE, action=""))

    counts = Counter(item.bucket for item in items)
    return Worklist(
        items=tuple(items),
        counts={bucket: counts.get(bucket, 0) for bucket in Bucket},
        done_by_status=dict(done_by_status),
        newest_check=max(checks, default=None),
        oldest_check=min(checks, default=None),
        unchecked=unchecked,
        deep_unknown=tuple(sorted(deep_unknown)),
    )
