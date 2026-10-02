# SPDX-License-Identifier: GPL-2.0-or-later
"""Running the rules and ranking what they produce.

Diagnosis is a pure function of an ingested record. That is deliberate: it
means a rule change can be re-run across a whole corpus in seconds without
touching a log file, and it means the output is reproducible from the stored
record alone.

**Ranking is the hard part, not matching.** A real bug fires several rules. A
disk-space failure during ``COMMIT`` also leaves broken packages; a third-party
PPA produces both a grouped blocker finding and four individual roots; a
truncated log produces a refusal alongside a dozen genuine conflicts. Picking
the wrong one for the title sends triage to the wrong place, so the order is
spelled out here rather than emerging from whichever rule happened to run last.

The policy, in order:

1. **Preconditions beat everything.** If dpkg was interrupted or the upgrader
   crashed, nothing else observed is trustworthy evidence about a cause.
2. **Environment beats packages.** Out of disk, not root, archive unreachable:
   these masquerade as dependency problems, and the dependency problem is the
   symptom.
3. **Then rule priority**, which encodes the remaining judgements.
4. **Then blast radius**, because a root stranding forty packages is the bug
   and one stranding a single package is noise.
5. **Then confidence, then rule name**, purely for a stable order -- an
   unstable ranking makes deduplication depend on dictionary iteration.

One rule is exempt from ranking entirely: the truncation refusal is forced to
the end so it reads as a caveat beside the findings rather than replacing them.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from uru_doctor.i18n import catalogue_for
from uru_doctor.intern import Interner
from uru_doctor.models import (
    Cause,
    Confidence,
    Finding,
    Phase,
    Severity,
    Signature,
    UpgradeRun,
)
from uru_doctor.parsers.apportmeta import ApportMeta
from uru_doctor.parsers.aptterm import TermLog
from uru_doctor.rules import upgrader as _upgrader_rules  # noqa: F401  (registers rules)
from uru_doctor.rules.context import RuleContext
from uru_doctor.rules.registry import RULES, Rule, all_rules, rules_for
from uru_doctor.rules.resolver import RESOLVER_CAUSES
from uru_doctor.rules.resolver import resolver_roots as _resolver_rules  # noqa: F401

__all__ = [
    "CAVEAT_CAUSES",
    "PRECONDITION_CAUSES",
    "DiagnosisResult",
    "diagnose",
    "rank_findings",
]

#: Causes that invalidate everything observed alongside them.
#:
#: Not merely "more important". If dpkg is mid-transaction the package states
#: the resolver saw are meaningless, so the dependency findings are not a
#: secondary cause -- they are an artefact.
PRECONDITION_CAUSES: frozenset[Cause] = frozenset(
    {
        Cause.DPKG_INTERRUPTED,
        Cause.UPGRADER_CRASH,
    }
)

#: Failures that make the rest of the trace unreliable rather than wrong.
#:
#: A livelocked resolver reports ``Error, pkgProblemResolver::Resolve generated
#: breaks``, which names no package. The roots visible alongside are real but
#: incidental -- apt would have resolved them had it converged -- so the
#: livelock has to outrank them even though it strands almost nothing. Ranking
#: inside a tier is by blast radius, which is exactly the comparison a livelock
#: must not be subjected to, so it gets a tier of its own.
_NON_CONVERGENCE_CAUSES: frozenset[Cause] = frozenset({Cause.RESOLVER_LIVELOCK})

#: Physical and configuration failures, which dependency problems mimic.
_ENVIRONMENT_CAUSES: frozenset[Cause] = frozenset(
    {
        Cause.NOT_ENOUGH_DISK_SPACE,
        Cause.FILESYSTEM_NOT_WRITABLE,
        Cause.CACHE_LOCK_FAILED,
        Cause.SSH_UPGRADE_BLOCKED,
        Cause.ESP_UNUSABLE,
        Cause.UNSUPPORTED_UPGRADE_PATH,
        Cause.PACKAGE_AUTH_FAILED,
        Cause.DOWNLOAD_FAILED,
        Cause.UPDATE_FAILED,
        Cause.MIRROR_UNKNOWN,
    }
)

#: Failures the upgrader itself declared, as opposed to ones inferred from the
#: conflict graph.
#:
#: Ranked below non-convergence and above the resolver roots, and both halves
#: of that are deliberate.
#:
#: Above the roots, because the upgrader saying "I could not install this"
#: is a statement about the ending, while a root is a statement about a
#: decision apt made on the way there. A metapackage broken by one
#: unsatisfiable dependency strands nothing, so ranking by blast radius buries
#: it beneath roots apt had already resolved -- which is exactly what happened
#: on LP#2168919, LP#2168863 and LP#2168909, three reports of one fault that
#: came back with three different wrong causes.
#:
#: Below non-convergence, because a livelocked resolver *explains* why the
#: metapackage could not be marked: apt never converged, so nothing it was
#: asked to do succeeded. The livelock is the cause and the failed mark is its
#: symptom. A root apt resolved and moved past explains nothing of the kind,
#: which is why that comparison goes the other way.
_UPGRADER_CONCLUSION_CAUSES: frozenset[Cause] = frozenset({Cause.META_PACKAGE_UNINSTALLABLE})

#: Causes that can only explain a failure *before* dpkg ran.
#:
#: If the upgrade reached the end and wrote its packages, the resolver did its
#: job. Held-back packages are then a historical note about what apt decided,
#: not the reason anything broke -- and they are present in every successful
#: upgrade, so they must not be allowed to answer "why did this break".
#:
#: The case that forced this: LP#2169251 upgraded 2881 packages, reached
#: ``POST_INSTALL_SCRIPTS``, and the reporter's complaint is that graphics
#: stopped working on reboot. The log's only error is
#: ``got error from PostInstallScript ./xorg_fix_proprietary.py`` -- a failure
#: of the Xorg proprietary-driver fixup, which is precisely the symptom. Ranked
#: on blast radius alone, a sixteen-package holdback from a successful resolve
#: displaced it.
#:
#: ``META_PACKAGE_UNINSTALLABLE`` joins them because ``_installMetaPkgs`` runs
#: long before dpkg does: if the upgrade went on to write packages, the
#: metapackage was marked successfully and any earlier complaint about it
#: belongs to a different attempt.
_PRE_COMMIT_ONLY_CAUSES: frozenset[Cause] = (
    RESOLVER_CAUSES | {Cause.RESOLVER_LIVELOCK} | _UPGRADER_CONCLUSION_CAUSES
)


def _upgrade_completed(run: UpgradeRun) -> bool:
    """Whether the upgrade ran to completion, whatever happened afterwards.

    Deliberately strict: dpkg must have written packages *and* the upgrader
    must have got past the post-upgrade stage. A run killed during ``COMMIT``
    has written packages too, and its resolver findings remain relevant.
    """
    return run.reached_dpkg and run.terminal_phase >= Phase.POST_UPGRADE


#: Findings that are commentary on the evidence, not candidate causes.
CAVEAT_CAUSES: frozenset[Cause] = frozenset({Cause.NO_FAILURE_RECORDED})

#: apt's terminal ``E:`` messages, and the root causes each one implicates.
#:
#: apt names a *mechanism* when it gives up, and that mechanism is checkable
#: evidence about which of a dozen roots actually stopped the upgrade. It was
#: being stored and ignored.
#:
#: The case that forced this: LP#2150245's largest root is
#: ``gir1.2-gio-2.0``, unsatisfiable, with ninety-eight victims -- genuinely
#: in the log, and genuinely not the failure. apt *resolved* it, by
#: ``Removing gir1.2-gdkpixbuf-2.0 rather than change gir1.2-gio-2.0``, and
#: moved on. What it then could not resolve it reported as ``Unable to correct
#: problems, you have held broken packages``, which implicates a hold -- the
#: ``libwacom9`` holdback that the surface PPA causes. Ranking on blast radius
#: alone put a resolved conflict above the unresolved one that mattered.
#: Keyed by :data:`uru_doctor.i18n.APT_MESSAGES` identifier rather than by
#: English text, because apt translates these. A Catalan log reports
#: ``E:Error, pkgProblemResolver::Resolve ha trencat coses, potser a causa de
#: paquets retinguts.`` and matching the English substring finds nothing, so
#: every non-English report silently lost its corroboration.
_APT_ERROR_AFFINITY: tuple[tuple[str, frozenset[Cause]], ...] = (
    (
        "held_broken",
        frozenset(
            {
                Cause.HOLDBACK_BLOCKS_NEW_DEP,
                Cause.HELD_PACKAGE_BLOCKS_UPGRADE,
                Cause.THIRD_PARTY_PIN,
                Cause.META_PACKAGE_UNINSTALLABLE,
            }
        ),
    ),
    (
        "resolver_breaks",
        frozenset(
            {
                Cause.RESOLVER_LIVELOCK,
                Cause.TRANSITIONAL_BREAKS,
                Cause.HOLDBACK_BLOCKS_NEW_DEP,
                Cause.THIRD_PARTY_PIN,
                Cause.META_PACKAGE_UNINSTALLABLE,
            }
        ),
    ),
    (
        "unmet_deps",
        frozenset({Cause.UNSATISFIABLE_VIRTUAL, Cause.EXACT_PIN_BROKEN_BY_UPGRADE}),
    ),
)


def corroborated_causes(run: UpgradeRun, interner: Interner) -> frozenset[Cause]:
    """Causes that apt's own terminal error implicates.

    Matched through :mod:`uru_doctor.i18n` against the run's locale, so a
    Catalan or Japanese log is recognised as readily as an English one. Empty
    when apt said nothing, in which case no finding is promoted and ranking
    falls back to blast radius alone.
    """
    messages = [interner.text(entry) for entry in run.apt_error_entries]
    if not messages:
        return frozenset()
    catalogue = catalogue_for(run.locale or None)
    implicated: set[Cause] = set()
    for key, causes in _APT_ERROR_AFFINITY:
        if any(catalogue.matches(key, message) for message in messages):
            implicated |= causes
    return frozenset(implicated)


#: Rules whose findings are advice about the bug rather than a description of
#: it. Kept visible but never allowed to take the title.
ADVISORY_RULES: frozenset[str] = frozenset({"resolver.fragile-decision"})

#: Most findings reported for one run.
#:
#: A resolver failure legitimately produces dozens of roots -- LP#2150245 has
#: thirty-seven -- and a list of thirty-nine findings is not a diagnosis, it is
#: the log again. The ranking puts the consequential ones first, so truncating
#: the tail costs nothing a triager would have read.
MAX_FINDINGS: int = 12


def _is_pre_commit_finding(finding: Finding) -> bool:
    """Whether a finding can only describe something that happened before dpkg.

    Tested structurally where possible, by whether the finding came from a
    conflict graph, rather than by enumerating causes. The cause list missed
    :attr:`Cause.UNKNOWN`, which ``apt.roots.classify`` returns for a root it
    cannot categorise: such a finding is produced by a resolver rule, carries a
    ``graph_index``, and is every bit as pre-commit as a classified one -- but
    being absent from ``RESOLVER_CAUSES`` it escaped the demotion below and
    became the headline on a successful upgrade.

    ``graph_index`` is set only by the rules in
    :mod:`uru_doctor.rules.resolver`, so it is an exact marker rather than a
    proxy. The cause set catches the rest: a livelock, and the upgrader's own
    metapackage complaint, both of which precede dpkg without coming from a
    graph.
    """
    return finding.graph_index is not None or finding.cause in _PRE_COMMIT_ONLY_CAUSES


def _tier(finding: Finding, *, completed: bool = False) -> int:
    """Which band a finding sits in. Lower is more authoritative.

    ``completed`` marks a run that upgraded successfully, which demotes every
    pre-commit finding: they describe decisions apt made on its way to a
    working system, so they cannot explain a failure that happened afterwards.
    """
    if finding.cause in CAVEAT_CAUSES:
        return 99
    if finding.rule in ADVISORY_RULES:
        return 50
    if completed and _is_pre_commit_finding(finding):
        return 40
    if finding.cause in PRECONDITION_CAUSES:
        return 0
    if finding.cause in _ENVIRONMENT_CAUSES:
        return 1
    if finding.cause in _NON_CONVERGENCE_CAUSES:
        return 2
    if finding.cause in _UPGRADER_CONCLUSION_CAUSES:
        return 3
    return 4


def _rank_key(
    finding: Finding,
    rule: Rule | None,
    corroborated: frozenset[Cause] = frozenset(),
    *,
    completed: bool = False,
) -> tuple[int, int, int, int, int, int, str]:
    """Sort key for one finding. Lower sorts first.

    Two orderings here are deliberate and were both arrived at by getting them
    wrong first.

    **Corroboration by apt's own error outranks blast radius.** A root that the
    mechanism apt named implicates is preferred over a bigger one it did not.
    Without this, LP#2150245 led with a ninety-eight-victim conflict that apt
    had already resolved by removal, instead of the hold that apt actually gave
    up on.

    **Blast radius outranks rule priority within a tier.** With priority
    dominating, whichever rule happened to carry a lower number swept the top
    of the list regardless of how little it explained -- a dozen single-victim
    advisory notes outranked a thirty-nine-package cascade. Priority decides
    which *kind* of failure wins across tiers; inside a tier, explaining more
    wins.
    """
    priority = rule.priority if rule is not None else 500
    return (
        _tier(finding, completed=completed),
        -int(finding.severity),
        0 if finding.cause in corroborated else 1,
        -finding.cascade_size,
        priority,
        -int(finding.confidence),
        finding.rule,
    )


def rank_findings(
    findings: Sequence[Finding],
    *,
    limit: int | None = MAX_FINDINGS,
    corroborated: frozenset[Cause] = frozenset(),
    completed: bool = False,
) -> tuple[Finding, ...]:
    """Order findings so the first one belongs in the title.

    Caveats survive truncation unconditionally: a refusal to name a cause must
    never be the thing that falls off the end of the list.
    """
    ordered = sorted(
        findings,
        key=lambda f: _rank_key(f, RULES.get(f.rule), corroborated, completed=completed),
    )
    if limit is None or len(ordered) <= limit:
        return tuple(ordered)

    kept = ordered[:limit]
    caveats = [f for f in ordered[limit:] if f.cause in CAVEAT_CAUSES]
    return tuple(kept + caveats)


@dataclass(slots=True)
class DiagnosisResult:
    """Findings plus the bookkeeping needed to explain them."""

    findings: tuple[Finding, ...] = ()
    fired: tuple[str, ...] = ()
    """Names of rules that produced at least one finding."""

    considered: int = 0
    """How many rules were eligible, for the health check."""

    skipped_incomplete: tuple[str, ...] = ()
    """Rules withheld because the evidence was truncated."""

    corroborated: frozenset[Cause] = frozenset()
    """Causes implicated by apt's own terminal error message."""

    upgrade_completed: bool = False
    """Whether the upgrade finished, so the failure is post-upgrade.

    A materially different kind of bug: the machine is upgraded and broken,
    rather than un-upgraded and intact.
    """

    notes: list[str] = field(default_factory=list)

    @property
    def primary(self) -> Finding | None:
        """The finding the title should describe."""
        for finding in self.findings:
            if finding.cause not in CAVEAT_CAUSES:
                return finding
        return self.findings[0] if self.findings else None

    @property
    def caveats(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.cause in CAVEAT_CAUSES)

    @property
    def resolver_findings(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.cause in RESOLVER_CAUSES)

    @property
    def is_candidate_invalid(self) -> bool:
        """Whether the *primary* cause is a third-party package.

        Reported as a candidate, never acted on. The judgement that a bug is
        Invalid belongs to a human; this tool's job is to group the evidence so
        that judgement takes a minute rather than an afternoon.

        Only the primary finding counts. Any machine with a few PPAs -- the
        normal state of a machine that files one of these bugs -- has *some*
        third-party package implicated somewhere, and testing every finding
        flagged LP#2150319 as a candidate on the strength of an ``imagemagick``
        PPA with four victims. That bug was not invalid; upstream fixed it with
        an SRU. A bug is a candidate only when the third-party package is what
        actually stopped the upgrade.
        """
        primary = self.primary
        if primary is None:
            return False
        return (
            primary.detail.get("candidate_invalid") == "true"
            or primary.cause is Cause.THIRD_PARTY_PIN
        )

    @property
    def third_party_findings(self) -> tuple[Finding, ...]:
        """Every third-party finding, primary or not.

        Distinct from :attr:`is_candidate_invalid` because the two answer
        different questions: this one is "what did the PPAs touch", worth
        reporting on any bug, while the other is "is this Ubuntu's problem".
        """
        return tuple(
            f
            for f in self.findings
            if f.cause is Cause.THIRD_PARTY_PIN or f.detail.get("candidate_invalid") == "true"
        )


def diagnose(
    run: UpgradeRun,
    interner: Interner,
    *,
    meta: ApportMeta | None = None,
    term: TermLog | None = None,
    enabled: Sequence[str] = (),
    disabled: Sequence[str] = (),
) -> DiagnosisResult:
    """Run every eligible rule over ``run`` and rank the results.

    ``enabled``, when non-empty, restricts the run to exactly those rule names;
    ``disabled`` removes names from whatever is left. Both exist for bisecting
    a surprising verdict -- turning one rule off and seeing what the ranking
    says instead is the quickest way to find out whether a finding is the cause
    or merely the loudest thing in the log. Unknown names are ignored rather
    than rejected, so a config written against a newer version still works.
    """
    context = RuleContext(run=run, interner=interner, meta=meta, term=term)

    collected: list[Finding] = []
    fired: list[str] = []
    eligible = list(rules_for(run))
    if enabled:
        allowed = set(enabled)
        eligible = [r for r in eligible if r.name in allowed]
    if disabled:
        refused = set(disabled)
        eligible = [r for r in eligible if r.name not in refused]

    for candidate in eligible:
        produced = candidate(context)
        if produced:
            fired.append(candidate.name)
            collected.extend(produced)

    withheld = tuple(
        candidate.name
        for candidate in all_rules()
        if candidate.requires_complete_evidence and not run.evidence_complete
    )

    corroborated = corroborated_causes(run, interner)
    ranked = rank_findings(
        _deduplicate(collected),
        corroborated=corroborated,
        completed=_upgrade_completed(run),
    )
    result = DiagnosisResult(
        findings=ranked,
        fired=tuple(fired),
        considered=len(eligible),
        skipped_incomplete=withheld,
        corroborated=corroborated,
        upgrade_completed=_upgrade_completed(run),
    )

    if not ranked:
        result.notes.append("no rule matched; the logs record no recognised failure")
    elif withheld:
        result.notes.append(f"{len(withheld)} rule(s) withheld because the evidence is incomplete")
    return result


def _deduplicate(findings: Sequence[Finding]) -> list[Finding]:
    """Collapse findings that say the same thing about the same packages.

    Two rules legitimately describe one fault: a fragile holdback is also a
    holdback root, and a third-party blocker is also a set of resolver roots.
    Keeping both is right -- they carry different advice -- but keeping two
    findings with the same rule, cause and root set is just noise, and it would
    double-count in the ranking.
    """
    seen: dict[tuple[str, Cause, tuple[int, ...]], Finding] = {}
    for finding in findings:
        key = (finding.rule, finding.cause, finding.root_pkgs)
        existing = seen.get(key)
        if existing is None or finding.cascade_size > existing.cascade_size:
            seen[key] = finding
    return list(seen.values())


def signature_for(run: UpgradeRun, result: DiagnosisResult) -> Signature:
    """Placeholder until :mod:`uru_doctor.dedup` lands.

    Returned empty rather than guessed at: a wrong signature silently merges
    unrelated bugs, which is worse than no deduplication at all.
    """
    del run, result
    return Signature()


def explain(rule_name: str) -> Rule | None:
    """Look up a rule for ``uru-doctor rules --explain``."""
    return RULES.get(rule_name)


def severity_of(result: DiagnosisResult) -> Severity:
    """The run's overall severity, from its primary finding."""
    primary = result.primary
    return primary.severity if primary is not None else Severity.INFO


def confidence_of(result: DiagnosisResult) -> Confidence:
    primary = result.primary
    return primary.confidence if primary is not None else Confidence.WEAK
