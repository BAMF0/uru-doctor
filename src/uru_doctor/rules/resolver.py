"""Rules for apt resolver failures.

These are the common case -- a 24.04 to 26.04 upgrade that never starts --
and the work is already done by :mod:`uru_doctor.apt.roots`, which reduces a
few hundred ``Broken`` lines to a handful of roots. This module's job is to
turn those roots into findings and to rank them, not to re-derive them.

Ranking is where the judgement lives. A corpus of these bugs produces a dozen
roots per run, and presenting them unordered is barely better than presenting
the raw log. The order is: blast radius first, because a root that strands
forty packages is the bug and one that strands a single package is noise;
third-party pins promoted, because they are actionable and usually mean
Invalid; and anything apt itself declined with a narrow score margin flagged as
fragile, because those are the bugs that cannot be reproduced on a clean
install and therefore attract piles of inconsistent duplicates.
"""

from __future__ import annotations

from collections.abc import Sequence

from uru_doctor.apt.roots import Root
from uru_doctor.models import (
    BLAME_EDGES,
    Cause,
    Confidence,
    ConflictGraph,
    Decision,
    Finding,
    Severity,
)
from uru_doctor.rules.context import RuleContext
from uru_doctor.rules.registry import rule

__all__ = [
    "RESOLVER_CAUSES",
    "fragile_decision",
    "resolver_roots",
    "summarise_root",
    "third_party_blocker",
]

#: Causes produced by resolver analysis, as opposed to dpkg or the upgrader.
RESOLVER_CAUSES: frozenset[Cause] = frozenset(
    {
        Cause.HOLDBACK_BLOCKS_NEW_DEP,
        Cause.HELD_PACKAGE_BLOCKS_UPGRADE,
        Cause.EXACT_PIN_BROKEN_BY_UPGRADE,
        Cause.REMOVAL_CASCADE,
        Cause.T64_TRANSITION,
        Cause.UNSATISFIABLE_VIRTUAL,
        Cause.I386_ORPHAN,
        Cause.THIRD_PARTY_PIN,
        Cause.TRANSITIONAL_BREAKS,
    }
)

#: Causes whose severity should not be reduced by a small blast radius.
#:
#: A third-party pin blocking one package still means the upgrade is impossible
#: until the PPA is removed, and an i386 orphan is a packaging bug whether it
#: strands one package or thirty.
_ALWAYS_SIGNIFICANT: frozenset[Cause] = frozenset(
    {Cause.THIRD_PARTY_PIN, Cause.I386_ORPHAN, Cause.T64_TRANSITION}
)


def summarise_root(context: RuleContext, root: Root) -> str:
    """One line of plain English for a resolver root.

    Deliberately concrete: it names the package, what apt wanted to do, and how
    many packages were affected. A summary that says "dependency problem" tells
    a triager nothing they did not already know from the bug title.
    """
    name = context.label(root.pkg_id)
    victims = len(root.cascade)
    tail = f", blocking {victims} package{'s' if victims != 1 else ''}" if victims else ""

    if root.cause is Cause.THIRD_PARTY_PIN:
        return f"{name} comes from outside Ubuntu and cannot be upgraded{tail}"
    if root.cause is Cause.HOLDBACK_BLOCKS_NEW_DEP:
        dep = root.detail.get("dependency", "")
        extra = f" because it needs {dep}" if dep else ""
        return f"apt held {name} back{extra}{tail}"
    if root.cause is Cause.HELD_PACKAGE_BLOCKS_UPGRADE:
        return f"{name} is held at its current version{tail}"
    if root.cause is Cause.EXACT_PIN_BROKEN_BY_UPGRADE:
        constraint = root.constraint or "an exact version"
        return f"{name} requires {constraint}, which the upgrade does not provide{tail}"
    if root.cause is Cause.UNSATISFIABLE_VIRTUAL:
        return f"nothing in resolute provides {name}{tail}"
    if root.cause is Cause.I386_ORPHAN:
        return f"{name} is i386 and has no 26.04 counterpart{tail}"
    if root.cause is Cause.T64_TRANSITION:
        return f"{name} is caught in the 64-bit time_t transition{tail}"
    if root.cause is Cause.REMOVAL_CASCADE:
        return f"removing {name} would cascade{tail}"
    if root.cause is Cause.TRANSITIONAL_BREAKS:
        return f"{name} conflicts with its own replacement{tail}"
    return f"{name} could not be resolved{tail}"


def _cascade_pkgs(graph: ConflictGraph, cascade: Sequence[int]) -> tuple[int, ...]:
    """Convert a root's cascade from vertex indices to package ids.

    :attr:`~uru_doctor.apt.roots.Root.cascade` holds *vertex indices*, as its
    own docstring says, while :attr:`~uru_doctor.models.Finding.victim_pkgs`
    holds interned package ids. Assigning one straight to the other -- which
    this module did -- stores indices where ids are expected.

    It stayed invisible for a long time because both are small integers and,
    with one interner per run, a low vertex index resolves to *some* plausible
    package from the same log. It only surfaced when a corpus shared an
    interner and bug 2150245's victims came back as budgie packages belonging
    to a different report. Every victim list was wrong, and so was every
    signature computed from one.
    """
    ids = graph.nodes.ids
    return tuple(ids[index] for index in cascade if index < len(ids))


def _rank_key(root: Root) -> tuple[int, int, int, str]:
    """Sort key: most consequential first.

    Severity before blast radius, because a third-party pin with two victims
    still blocks the upgrade outright, while a transitional conflict with two
    victims is routine. Name last so the order is stable across runs.
    """
    return (
        -int(root.severity),
        -len(root.cascade),
        -int(root.confidence),
        (root.pkg_id and "") or "",
    )


def _findings_from_roots(
    context: RuleContext,
    roots: Sequence[Root],
    graph_index: int,
    *,
    rule_name: str,
) -> list[Finding]:
    out: list[Finding] = []
    for root in roots:
        severity = root.severity
        if root.cause in _ALWAYS_SIGNIFICANT and severity is not Severity.HIGH:
            severity = Severity.HIGH

        detail = dict(root.detail)
        if root.constraint:
            detail.setdefault("constraint", root.constraint)
        if root.dep in BLAME_EDGES:
            detail.setdefault("relationship", str(root.dep.value))
        if root.cycle_broken:
            detail["cycle_broken"] = "true"

        name = context.label(root.pkg_id)
        graph = context.run.graphs[graph_index]
        out.append(
            context.finding(
                rule=rule_name,
                cause=root.cause,
                summary=summarise_root(context, root),
                severity=severity,
                confidence=root.confidence,
                root_pkgs=(root.pkg_id,),
                victim_pkgs=_cascade_pkgs(graph, root.cascade),
                cascade_size=len(root.cascade),
                evidence=context.event_indices(name)[:8],
                graph_index=graph_index,
                remedy=root.remedy,
                score_margin=root.score_margin,
                fragile=root.fragile,
                detail=detail,
            )
        )
    return out


@rule(
    "resolver.roots",
    Cause.UNKNOWN,
    priority=100,
    phase_hint="CALCULATE",
    provenance=(
        "apt's three debug streams, enabled together by "
        "DistUpgradeCache.py:243-245; reduced to roots by uru_doctor.apt.roots"
    ),
    remedy="Resolve the named root package, not its victims",
    # Exempt from the completeness requirement: these findings describe state
    # apt recorded, not a claim about how the run ended. Bug 2169028's log is
    # truncated and its resolver trace is still the most useful thing on the
    # bug -- it is diagnose.py's job to say "no failure recorded" alongside.
    requires_complete_evidence=False,
)
def resolver_roots(context: RuleContext) -> Sequence[Finding]:
    """Convert every conflict graph's roots into ranked findings."""
    findings: list[Finding] = []
    for index, report in enumerate(context.root_reports):
        if not report.roots:
            continue
        ordered = sorted(report.roots, key=_rank_key)
        findings.extend(_findings_from_roots(context, ordered, index, rule_name="resolver.roots"))
    return findings


@rule(
    "resolver.fragile-decision",
    Cause.UNKNOWN,
    priority=200,
    severity=Severity.INFO,
    confidence=Confidence.STRONG,
    phase_hint="CALCULATE",
    provenance="apt 'Considering' score comparison in the resolver trace",
    remedy=("Reproduce with the reporter's exact package set; a clean install will not show this"),
    requires_complete_evidence=False,
)
def fragile_decision(context: RuleContext) -> Sequence[Finding]:
    """One advisory note when apt decided something by a hair.

    apt prints the scores it compared, and when the margin is a point or two
    the outcome depends on incidental system state. That is why LP#2150319 was
    irreproducible on a clean install and accumulated contradictory comments
    for weeks, so it is worth stating plainly.

    Three things this rule deliberately does *not* do, each of which an earlier
    version did:

    - **One finding, not one per root.** Bug 2169028 has a dozen roots with a
      narrow margin, and a finding for each buried the real ``python3`` cascade
      of thirty-nine underneath twelve findings of cascade one.
    - **It does not claim to be a holdback.** Fragility turns up on
      ``t64_transition`` and ``removal_cascade`` roots too, so naming the rule
      after one cause misrepresented the rest.
    - **It does not compete for the title.** Priority 200 puts it below every
      real cause, because "this was a close call" is advice on reproducing the
      bug rather than a description of it. The affected roots already carry
      :attr:`~uru_doctor.models.Finding.fragile`.
    """
    fragile: list[Root] = []
    for report in context.root_reports:
        fragile.extend(
            root for root in report.roots if root.fragile and root.score_margin is not None
        )
    if not fragile:
        return ()

    fragile.sort(key=lambda r: (r.score_margin or 0, -len(r.cascade)))
    narrowest = fragile[0]
    margin = narrowest.score_margin or 0
    names = context.labels(root.pkg_id for root in fragile)
    shown = ", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")

    return (
        context.finding(
            rule="resolver.fragile-decision",
            cause=narrowest.cause,
            summary=(
                f"apt decided {len(fragile)} of these by a margin of {margin} "
                f"point{'s' if margin != 1 else ''} or less ({shown}), so the "
                f"outcome depends on the reporter's exact package set"
            ),
            severity=Severity.INFO,
            confidence=Confidence.STRONG,
            root_pkgs=tuple(root.pkg_id for root in fragile),
            cascade_size=0,
            evidence=context.event_indices("Considering")[:6],
            score_margin=margin,
            fragile=True,
            detail={
                "fragile_packages": ", ".join(names),
                "narrowest_margin": str(margin),
                "advisory": "true",
            },
        ),
    )


@rule(
    "resolver.third-party-blocker",
    Cause.THIRD_PARTY_PIN,
    priority=100,
    severity=Severity.HIGH,
    confidence=Confidence.STRONG,
    phase_hint="CALCULATE",
    provenance=(
        "main.log 'Foreign (before rewriting sources)', which is the upgrader's "
        "own verdict on which installed packages are not from Ubuntu"
    ),
    remedy="Remove or downgrade the third-party packages, then retry",
    requires_complete_evidence=False,
)
def third_party_blocker(context: RuleContext) -> Sequence[Finding]:
    """Group third-party roots into one actionable finding.

    A PPA that blocks an upgrade usually blocks it several times over, and
    reporting each conflict separately buries the one thing a triager needs to
    know: the upgrade cannot succeed while that PPA is installed. LP#2150245
    was closed Invalid for exactly this reason and collected thirteen
    duplicates.

    Registered at the same priority as the ordinary roots so that blast radius
    decides between them. Promoting third-party findings unconditionally was
    wrong: a machine with a dozen PPAs -- the normal state of the machines that
    file these bugs -- always has *some* third-party package in a conflict
    somewhere. On LP#2150319 that put a four-victim ``imagemagick`` PPA root
    above the ``libfile-libmagic-perl`` deadlock upstream eventually fixed with
    a quirk. Being third-party makes a root actionable; it does not make it the
    cause.
    """
    foreign = set(context.run.third_party)
    if not foreign:
        return ()

    blockers: list[Root] = []
    graph_index: int | None = None
    for index, report in enumerate(context.root_reports):
        for root in report.roots:
            if root.pkg_id in foreign:
                blockers.append(root)
                if graph_index is None:
                    graph_index = index
    if not blockers:
        return ()

    blockers.sort(key=lambda r: -len(r.cascade))
    graph = context.run.graphs[graph_index] if graph_index is not None else None
    victims: list[int] = []
    seen: set[int] = set()
    for root in blockers:
        resolved = _cascade_pkgs(graph, root.cascade) if graph is not None else ()
        for victim in resolved:
            if victim not in seen:
                seen.add(victim)
                victims.append(victim)

    names = context.labels(root.pkg_id for root in blockers)
    shown = ", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")
    return (
        context.finding(
            rule="resolver.third-party-blocker",
            cause=Cause.THIRD_PARTY_PIN,
            summary=(
                f"packages from outside Ubuntu block the upgrade: {shown}"
                f" ({len(victims)} package{'s' if len(victims) != 1 else ''} affected)"
            ),
            severity=Severity.HIGH,
            confidence=Confidence.STRONG,
            root_pkgs=tuple(root.pkg_id for root in blockers),
            victim_pkgs=tuple(victims),
            cascade_size=len(victims),
            graph_index=graph_index,
            remedy=Decision.UNKNOWN,
            detail={
                "third_party_packages": ", ".join(names),
                "candidate_invalid": "true",
            },
        ),
    )


@rule(
    "resolver.livelock",
    Cause.RESOLVER_LIVELOCK,
    priority=50,
    severity=Severity.HIGH,
    confidence=Confidence.STRONG,
    phase_hint="CALCULATE",
    provenance=(
        "uru_doctor.apt.livelock: a package repeatedly held back and "
        "force-upgraded in the same trace"
    ),
    remedy=(
        "Install the blocking package explicitly to break the cycle, as "
        "DistUpgradeQuirks._fix_lintian_resolver_deadlock does"
    ),
    requires_complete_evidence=False,
)
def resolver_livelock(context: RuleContext) -> Sequence[Finding]:
    """apt never converged, so the failure it reported names nothing.

    The only resolver rule allowed to outrank blast radius, and it has to be.
    A livelocked package strands almost nothing -- LP#2150319's ``lintian`` has
    two victims -- so every ranking by consequence buries it beneath roots that
    explain five or thirty-nine packages. Those roots are real but incidental;
    the reason the upgrade failed is that the resolver was still arguing with
    itself when it ran out of iterations, and the error it then printed,
    ``Error, pkgProblemResolver::Resolve generated breaks``, names no package
    at all.

    The finding blames the package apt refused to install rather than the one
    it kept flip-flopping. For LP#2150319 that is ``libfile-libmagic-perl``,
    which is exactly what upstream's quirk marks for install -- a conclusion
    reached here from the log alone.
    """
    if not context.run.oscillations:
        return ()

    # The oscillation was detected on the primary section, which is graph 0.
    # Recording it matters: without a graph index the deduplicator cannot
    # fingerprint the primary finding's structure, and tier 0 silently falls
    # back to the per-machine incidental roots instead.
    graph_index = 0 if context.run.graphs else None

    # Group by the package apt refused to install, not by the package that
    # oscillated. Several packages livelocking at once are normally the same
    # fault seen from several angles: in LP#2151847 both ``gir1.2-peas-1.0``
    # and ``gedit`` are stuck on ``libpeas-1.0-1``, and in LP#2150339 so are
    # ``gedit`` and ``gir1.2-peas-1.0``. Reporting one finding per oscillating
    # package produced three findings for one libpeas transition and, worse,
    # ranked them by reversal count -- so whether the primary cause came out as
    # ``libpeas-1.0-1`` or ``budgie-core`` turned on the difference between 18
    # reversals and 17, which is noise.
    grouped: dict[int, list[tuple[int, int, int]]] = {}
    for pkg_id, reversals, blocked_by, forced_by in context.run.oscillations:
        grouped.setdefault(blocked_by or pkg_id, []).append((pkg_id, reversals, forced_by))

    out: list[Finding] = []
    ordered = sorted(
        grouped.items(),
        key=lambda item: (-len(item[1]), -max(r for _, r, _ in item[1]), item[0]),
    )

    for blocker, members in ordered:
        stuck_names = context.labels(pkg for pkg, _, _ in members)
        blocker_name = context.label(blocker)
        worst_reversals = max(reversals for _, reversals, _ in members)
        forcers = context.labels({f for _, _, f in members if f})

        shown = ", ".join(stuck_names[:2]) + (
            f" and {len(stuck_names) - 2} more" if len(stuck_names) > 2 else ""
        )
        if forcers:
            summary = (
                f"apt could not converge: {forcers[0]} requires a newer {shown}, "
                f"but that needs {blocker_name}, which apt refused to install "
                f"-- reversed {worst_reversals} times before giving up"
            )
        else:
            summary = (
                f"apt could not converge on {shown} because it refused to "
                f"install {blocker_name}, reversing {worst_reversals} times"
            )

        detail = {
            "oscillating_package": stuck_names[0],
            "oscillating_packages": ", ".join(stuck_names),
            "reversals": str(worst_reversals),
            "blocked_by": blocker_name,
        }
        if forcers:
            detail["forced_by"] = forcers[0]

        out.append(
            context.finding(
                rule="resolver.livelock",
                cause=Cause.RESOLVER_LIVELOCK,
                summary=summary,
                severity=Severity.HIGH,
                confidence=Confidence.STRONG,
                root_pkgs=(blocker,),
                victim_pkgs=tuple(pkg for pkg, _, _ in members),
                # Blast radius is not the point here and must not rank this
                # against ordinary roots; see the docstring.
                cascade_size=0,
                evidence=context.event_indices(blocker_name)[:6],
                graph_index=graph_index,
                detail=detail,
            )
        )
    return out
