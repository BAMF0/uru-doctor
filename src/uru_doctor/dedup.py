# SPDX-License-Identifier: GPL-2.0-or-later
"""Deduplication on log evidence alone.

**Nothing in this module reads a bug title, description or comment.** That is
the central design decision, and it is not squeamishness -- it is because the
text is actively misleading on exactly the bugs that matter most. The thirteen
Launchpad-confirmed duplicates of LP#2150245 carry titles including
``Ubgrade does not work``, ``upgrade to 26.4`` and
``libwacom-surface - Upgrade from 24.04 LTS to 26.04 LTS fails``. No text
measure clusters that set, and any measure tuned until it did would be fitted
to noise. What those thirteen reports *do* share is a conflict graph: the same
PPA package conflicting with the same archive package, stranding the same
dependents. That is a fact about the logs, it is identical across all thirteen,
and it is what this module compares.

The same reasoning rules out Launchpad's own mechanism. apport computes a
``DuplicateSignature`` for ``ProblemType: Package`` reports and embeds
``package:name:version`` in it (``/usr/share/apport/general-hooks/ubuntu.py``),
so two reporters of one fault on different point releases get different
signatures and do not collapse. That is a large part of why these bugs
accumulate duplicates in the first place.

Three tiers, cheapest first, each a strict fallback for the one above:

0. **Root graph digest.** The canonical fingerprint of the root-cause subgraph
   -- participating package names, relationship types, constraint operators,
   versions normalised away. An exact hash match is a duplicate; no scoring,
   no threshold, no judgement.
1. **Cause tuple.** ``(cause, root package names, terminal phase)``. Coarser,
   and the only option for failures with no graph at all: a full disk, a dpkg
   maintainer-script failure, an upgrader traceback.
2. **IDF-weighted Jaccard over log templates.** Scored, and only for pairs that
   already share a tier-1 bucket. The templates are masked log lines, so this
   is still log evidence; the IDF weighting comes from the corpus, which is
   what stops the thousand ``Setting up <PKG>`` lines every upgrade shares from
   drowning the handful that distinguish one failure from another.

Only tier 2 produces a score, and only scores inside a configured band are
ambiguous enough to be worth a second opinion. Tiers 0 and 1 are decided by
equality.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from hashlib import blake2b
from typing import TYPE_CHECKING, Final

from uru_doctor.apt.graph import canonical_digest
from uru_doctor.models import (
    Cause,
    Finding,
    Phase,
    Signature,
    UpgradeRun,
    pack_u32,
    unpack_u32,
)

if TYPE_CHECKING:
    from uru_doctor.config import DedupConfig
    from uru_doctor.intern import Interner

__all__ = [
    "EXCLUDED_FROM_SIGNATURES",
    "Cluster",
    "DuplicateVerdict",
    "Tier",
    "build_signature",
    "cluster_runs",
    "jaccard",
    "score_pair",
]

#: Recorded so the exclusion is checkable rather than merely intended.
#:
#: Asserted by the test suite against :func:`build_signature`: no field listed
#: here may influence a signature. The first three are reporter prose; the
#: fourth is apport's version-sensitive signature, which fails to collapse the
#: very reports it is meant to.
EXCLUDED_FROM_SIGNATURES: Final[frozenset[str]] = frozenset(
    {
        "current_title",
        "tags",
        "preamble",
        "duplicate_signature",
    }
)


class Tier:
    """Which mechanism decided a pair. Named so reports can explain themselves."""

    __slots__ = ()

    ROOT_GRAPH = "root-graph"
    """Exact match on the canonical root-cause subgraph."""

    CAUSE_TUPLE = "cause-tuple"
    """Exact match on cause, roots and phase."""

    EVIDENCE = "evidence-similarity"
    """IDF-weighted Jaccard over log templates."""

    NONE = "none"


@dataclass(frozen=True, slots=True)
class DuplicateVerdict:
    """Why two runs were or were not judged duplicates."""

    duplicate: bool
    tier: str
    score: float = 1.0
    """1.0 for the exact tiers; the Jaccard score for tier 2."""

    ambiguous: bool = False
    """Score fell inside the configured band, so structure did not settle it."""

    shared_roots: tuple[str, ...] = ()
    reason: str = ""

    @property
    def needs_adjudication(self) -> bool:
        """Whether a second opinion would add anything.

        Only ever true for tier 2. An exact structural match is not a judgement
        call and must never be sent to a model for one.
        """
        return self.ambiguous and self.tier == Tier.EVIDENCE


def _root_nodes(run: UpgradeRun, findings: Sequence[Finding]) -> dict[int, list[int]]:
    """Graph index to the node indices of the primary finding's structure.

    **Only the primary finding contributes.** Fingerprinting every finding
    seemed harmless and was not: a resolver failure produces a dozen roots, and
    most of them reflect what the reporter happened to have installed rather
    than what broke. The two independently filed logs for LP#2150319 share
    their primary cause exactly and share almost none of their incidental
    roots -- one machine contributes ``libheif1`` and ``python3.12-tk``, the
    other ``pidgin-data`` and ``libsgutils2-1.48``. Including them made the two
    reports' tier-0 digests differ, which is precisely the accident that stops
    these bugs deduplicating on Launchpad today.

    So the digest covers the blamed root, its immediate victims, and nothing
    else.
    """
    primary = _primary(findings)
    if primary is None or primary.graph_index is None:
        return {}
    graph_index = primary.graph_index
    if graph_index >= len(run.graphs):
        return {}

    lookup = {pkg: node for node, pkg in enumerate(run.graphs[graph_index].nodes.ids)}
    nodes = {
        node
        for pkg_id in (*primary.root_pkgs, *primary.victim_pkgs)
        if (node := lookup.get(pkg_id)) is not None
    }
    return {graph_index: sorted(nodes)} if nodes else {}


def build_signature(
    run: UpgradeRun,
    findings: Sequence[Finding],
    interner: Interner,
    *,
    granularity: str = "operator",
) -> Signature:
    """Compute a run's signature from its logs.

    Reads :attr:`UpgradeRun.graphs`, the findings derived from them, and the
    run's own log events. It does not read
    :attr:`UpgradeRun.current_title`, :attr:`UpgradeRun.tags`, or any field of
    the bug report written by a human -- see
    :data:`EXCLUDED_FROM_SIGNATURES`.
    """
    return Signature(
        apport_dupe=None,
        root_graph=_root_graph_digest(run, findings, interner, granularity=granularity),
        cause_tuple=_cause_digest(run, findings, interner),
        evidence_set=_evidence_set(run),
    )


def _root_graph_digest(
    run: UpgradeRun,
    findings: Sequence[Finding],
    interner: Interner,
    *,
    granularity: str,
) -> bytes | None:
    """Digest the blamed subgraph, or ``None`` when there is no graph.

    Several graphs are combined by digesting each and hashing the sorted
    results, so the outcome does not depend on the order apt happened to log
    its resolver sections in.
    """
    buckets = _root_nodes(run, findings)
    if not buckets:
        return None

    parts: list[bytes] = []
    for graph_index, nodes in buckets.items():
        if not nodes:
            continue
        parts.append(
            canonical_digest(run.graphs[graph_index], interner, nodes, granularity=granularity)
        )
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]

    combined = blake2b(digest_size=16)
    for part in sorted(parts):
        combined.update(part)
    return combined.digest()


def _cause_digest(run: UpgradeRun, findings: Sequence[Finding], interner: Interner) -> bytes | None:
    """Digest ``(cause, root names, terminal phase)`` of the primary finding.

    The phase is included because the same package failing at ``CALCULATE`` and
    at ``COMMIT`` are different bugs: one is a planning problem that touched
    nothing, the other left a half-configured system.

    Only the primary finding contributes. Including every finding would make
    the key depend on how many incidental conflicts the reporter's particular
    machine happened to have, which is the accident this is meant to see past.
    """
    primary = _primary(findings)
    if primary is None:
        return None

    names = sorted(interner.package_label(p) for p in primary.root_pkgs)
    digest = blake2b(digest_size=16)
    digest.update(primary.cause.value.encode())
    digest.update(b"\x00")
    for name in names:
        digest.update(name.encode())
        digest.update(b"\x00")
    digest.update(b"\x01")
    digest.update(str(int(_phase_band(primary.phase or run.terminal_phase))).encode())
    return digest.digest()


def _phase_band(phase: Phase) -> int:
    """Collapse the phase to the distinction that matters for identity.

    Three bands: before anything was written, during dpkg, and after. The exact
    phase is too fine -- whether a resolver failure surfaced at
    ``PRE_DIST_UPGRADE`` or ``CALCULATE`` depends on which quirk ran first, not
    on what broke.
    """
    if phase < Phase.COMMIT:
        return 0
    if phase <= Phase.POST_UPGRADE:
        return 1
    return 2


def _evidence_set(run: UpgradeRun) -> bytes:
    """Packed sorted template ids for this run's log events.

    Sorted so comparison is a linear merge, and a set rather than a sequence
    because a line occurring twice says no more than a line occurring once.
    """
    return pack_u32(sorted({event.template_id for event in run.events}))


def _primary(findings: Sequence[Finding]) -> Finding | None:
    from uru_doctor.diagnose import CAVEAT_CAUSES

    for finding in findings:
        if finding.cause not in CAVEAT_CAUSES:
            return finding
    return findings[0] if findings else None


def jaccard(
    left: Iterable[int],
    right: Iterable[int],
    weights: dict[int, float] | None = None,
) -> float:
    """Weighted Jaccard similarity of two template-id sets.

    With ``weights`` omitted this is the plain ratio, which is only useful for
    testing: unweighted, two unrelated upgrade logs score around 0.8 purely on
    the boilerplate they share. The IDF weights are what make the measure mean
    anything.

    Two empty sets return 1.0, which is the conventional definition and is
    *not* safe to use directly for duplicate detection -- see the guard in
    :func:`score_pair`.
    """
    first = set(left)
    second = set(right)
    if not first and not second:
        return 1.0
    if not first or not second:
        return 0.0

    if weights is None:
        return len(first & second) / len(first | second)

    def total(items: set[int]) -> float:
        return sum(weights.get(item, 1.0) for item in items)

    union = total(first | second)
    if union <= 0.0:
        return 0.0
    return total(first & second) / union


def score_pair(
    left: UpgradeRun,
    right: UpgradeRun,
    left_findings: Sequence[Finding],
    right_findings: Sequence[Finding],
    interner: Interner,
    config: DedupConfig,
    *,
    weights: dict[int, float] | None = None,
) -> DuplicateVerdict:
    """Decide whether two runs report the same fault.

    Tiers are tried in order and each is a strict fallback: a tier-0 match is
    never second-guessed by a tier-2 score.
    """
    left_sig = build_signature(
        left, left_findings, interner, granularity=config.version_granularity
    )
    right_sig = build_signature(
        right, right_findings, interner, granularity=config.version_granularity
    )
    shared = _shared_roots(left_findings, right_findings, interner)

    # Tier 0 -- identical blamed subgraph.
    if left_sig.root_graph is not None and left_sig.root_graph == right_sig.root_graph:
        return DuplicateVerdict(
            duplicate=True,
            tier=Tier.ROOT_GRAPH,
            shared_roots=shared,
            reason="identical root-cause subgraph",
        )

    # Tier 1 -- same cause, same roots, same side of the commit boundary.
    same_cause = left_sig.cause_tuple is not None and left_sig.cause_tuple == right_sig.cause_tuple
    if same_cause:
        return DuplicateVerdict(
            duplicate=True,
            tier=Tier.CAUSE_TUPLE,
            shared_roots=shared,
            reason="same cause and root packages at the same stage",
        )

    # Tier 2 -- scored, and only when the roots already overlap. Without that
    # gate, similarity alone merges every noble-to-resolute failure, because
    # they genuinely do share most of their log.
    if len(shared) < config.min_shared_roots:
        return DuplicateVerdict(
            duplicate=False,
            tier=Tier.NONE,
            score=0.0,
            reason=(
                f"only {len(shared)} shared root package(s); "
                f"{config.min_shared_roots} required before scoring"
            ),
        )

    left_evidence = unpack_u32(left_sig.evidence_set)
    right_evidence = unpack_u32(right_sig.evidence_set)

    # Absence of evidence is not evidence of similarity. Jaccard of two empty
    # sets is 1.0, which is defensible arithmetic and catastrophic here: a bug
    # that attached only an apt.log has no log *events* at all -- those come
    # from main.log -- so two unrelated reports both scored a perfect match and
    # were declared duplicates.
    if not left_evidence or not right_evidence:
        return DuplicateVerdict(
            duplicate=False,
            tier=Tier.NONE,
            score=0.0,
            shared_roots=shared,
            reason=(
                "no comparable log events on at least one side; "
                "structural tiers did not match either"
            ),
        )

    score = jaccard(left_evidence, right_evidence, weights)
    if score >= config.ambiguous_high:
        return DuplicateVerdict(
            duplicate=True,
            tier=Tier.EVIDENCE,
            score=score,
            shared_roots=shared,
            reason="log evidence overlaps above the confident threshold",
        )
    if score < config.ambiguous_low:
        return DuplicateVerdict(
            duplicate=False,
            tier=Tier.EVIDENCE,
            score=score,
            shared_roots=shared,
            reason="log evidence overlaps too little",
        )
    return DuplicateVerdict(
        duplicate=False,
        tier=Tier.EVIDENCE,
        score=score,
        ambiguous=True,
        shared_roots=shared,
        reason="shared roots but inconclusive evidence overlap",
    )


def _shared_roots(
    left: Sequence[Finding], right: Sequence[Finding], interner: Interner
) -> tuple[str, ...]:
    def names(findings: Sequence[Finding]) -> set[str]:
        return {interner.package_label(pkg) for finding in findings for pkg in finding.root_pkgs}

    return tuple(sorted(names(left) & names(right)))


@dataclass(slots=True)
class Cluster:
    """A set of runs reporting the same fault."""

    key: bytes
    tier: str
    members: list[str] = field(default_factory=list)
    """Run keys, as stored."""

    representative: str = ""
    """The member to keep open; the rest are candidate duplicates of it."""

    shared_roots: tuple[str, ...] = ()

    @property
    def size(self) -> int:
        return len(self.members)

    @property
    def duplicates(self) -> list[str]:
        return [m for m in self.members if m != self.representative]


def cluster_runs(
    signatures: dict[str, Signature],
    *,
    config: DedupConfig,
    oldest_first: Sequence[str] = (),
) -> list[Cluster]:
    """Group runs by exact signature: tier 0 first, then tier 1 extends it.

    ``oldest_first`` orders representative selection. The earliest report is
    kept as the representative because that is what Launchpad convention treats
    as the master, and the later ones become its duplicates.

    Tier 1 **extends** tier-0 clusters rather than only forming new ones. An
    earlier version skipped any run already assigned, which quietly lost
    transitive duplicates: bugs 2151847 and 2150339 match at tier 0, and bug
    2169028 matches both at tier 1, but because the first two were already
    assigned, 2169028 came out a singleton. All three are the same
    ``libpeas-1.0-1`` transition and Launchpad has none of them linked.

    Tier 2 scoring is deliberately not done here. It is quadratic and only
    meaningful within a tier-1 bucket, so callers run it per bucket.
    """
    rank = {key: index for index, key in enumerate(oldest_first)}

    def representative(members: Iterable[str]) -> str:
        return min(members, key=lambda key: (rank.get(key, len(rank)), key))

    clusters: list[Cluster] = []
    owner: dict[str, Cluster] = {}

    for tier, column in (
        (Tier.ROOT_GRAPH, "root_graph"),
        (Tier.CAUSE_TUPLE, "cause_tuple"),
    ):
        buckets: dict[bytes, list[str]] = {}
        for run_key, signature in signatures.items():
            value = getattr(signature, column)
            if value is not None:
                buckets.setdefault(value, []).append(run_key)

        for digest, members in buckets.items():
            if len(members) < 2:
                continue

            existing = {id(owner[k]): owner[k] for k in members if k in owner}
            if len(existing) > 1:
                # A tier-1 bucket spanning two tier-0 clusters means the coarse
                # key has merged faults that the precise key told apart. The
                # precise key is the one to trust, so this bucket is dropped.
                continue

            target = next(iter(existing.values()), None)
            if target is None:
                target = Cluster(key=digest, tier=tier, members=[])
                clusters.append(target)

            for key in members:
                if key not in owner:
                    target.members.append(key)
                    owner[key] = target

            target.members.sort()
            target.representative = representative(target.members)

    # A cluster grown implausibly large means the fingerprint lost its
    # discriminating power, not that hundreds of people hit one bug.
    clusters = [c for c in clusters if 2 <= c.size <= config.max_cluster_size]
    clusters.sort(key=lambda c: (-c.size, c.tier, c.representative))
    return clusters


def summarise(clusters: Sequence[Cluster]) -> dict[str, int]:
    """Counts for the report and the health check."""
    return {
        "clusters": len(clusters),
        "duplicates": sum(len(c.duplicates) for c in clusters),
        "largest": max((c.size for c in clusters), default=0),
        "by_root_graph": sum(1 for c in clusters if c.tier == Tier.ROOT_GRAPH),
        "by_cause_tuple": sum(1 for c in clusters if c.tier == Tier.CAUSE_TUPLE),
    }


def unresolved_causes(signatures: dict[str, Signature]) -> set[str]:
    """Runs with no usable signature at all.

    Reported rather than hidden: a run that cannot be fingerprinted will never
    deduplicate, and silently dropping it from clustering would look like a
    bug with no duplicates.
    """
    return {
        key
        for key, signature in signatures.items()
        if signature.root_graph is None and signature.cause_tuple is None
    }


def cause_of(findings: Sequence[Finding]) -> Cause:
    primary = _primary(findings)
    return primary.cause if primary is not None else Cause.UNKNOWN
