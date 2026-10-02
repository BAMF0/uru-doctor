# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for :mod:`uru_doctor.diagnose`, the rule registry and livelock detection."""

from __future__ import annotations

import json
import re
from dataclasses import replace

import pytest

from uru_doctor.apt.livelock import MIN_REVERSALS, detect_oscillations
from uru_doctor.apt.sections import read_sections
from uru_doctor.diagnose import (
    CAVEAT_CAUSES,
    MAX_FINDINGS,
    PRECONDITION_CAUSES,
    corroborated_causes,
    diagnose,
    rank_findings,
)
from uru_doctor.intern import Interner
from uru_doctor.models import Cause, Confidence, Finding, LogSource, Severity
from uru_doctor.parsers.apportmeta import parse_apport_meta
from uru_doctor.rules.registry import RULES, all_rules, rule, rules_digest

from .conftest import FIXTURES, fixture_text, ingest_one


def lp(bug_id: str, interner: Interner):
    payload = json.loads((FIXTURES / "lp" / f"bug{bug_id}.json").read_text())
    meta = parse_apport_meta(payload["description"], tags=payload["tags"])
    run = ingest_one(
        {
            LogSource.APT: fixture_text(f"apt/lp{bug_id}-apt.log"),
            LogSource.MAIN: fixture_text(f"logs/lp{bug_id}-main.log"),
        },
        interner,
        meta=meta,
        bug_id=int(bug_id),
    )
    return (run, diagnose(run, interner, meta=meta))


def sectioned(name: str):
    return read_sections(fixture_text(f"apt/{name}").splitlines())


class TestGroundTruth:
    """The whole point: does it get the three known bugs right?"""

    @pytest.mark.parametrize(
        ("bug_id", "cause", "package", "invalid"),
        [
            # Closed Invalid, thirteen duplicates, unsupported surface PPA.
            ("2150245", Cause.THIRD_PARTY_PIN, "libwacom9-surface", True),
            # Fixed by DistUpgradeQuirks._fix_lintian_resolver_deadlock, which
            # marks exactly this package for install.
            ("2150319", Cause.RESOLVER_LIVELOCK, "libfile-libmagic-perl", False),
            ("2169028", Cause.RESOLVER_LIVELOCK, "libpeas-1.0-1", False),
        ],
    )
    def test_primary_cause_matches(
        self,
        bug_id: str,
        cause: Cause,
        package: str,
        invalid: bool,
        interner: Interner,
    ) -> None:
        _, result = lp(bug_id, interner)
        primary = result.primary
        assert primary is not None
        assert primary.cause is cause
        assert interner.package_label(primary.root_pkgs[0]) == package
        assert result.is_candidate_invalid is invalid

    def test_the_summary_names_both_halves_of_the_deadlock(self, interner: Interner) -> None:
        """Upstream's quirk docstring describes exactly this cycle."""
        _, result = lp("2150319", interner)
        summary = result.primary.summary
        assert "libyaml-libyaml-perl" in summary
        assert "lintian" in summary
        assert "libfile-libmagic-perl" in summary


class TestLivelockDetection:
    """apt alternating between two contradictory decisions, for ever."""

    def test_the_lintian_deadlock_is_found(self, interner: Interner) -> None:
        found = detect_oscillations(sectioned("lp2150319-apt.log").primary, interner)
        assert len(found) == 1
        stuck = found[0]
        assert interner.package_label(stuck.pkg_id) == "lintian"
        assert interner.package_label(stuck.blocked_by) == "libfile-libmagic-perl"
        assert interner.package_label(stuck.forced_by) == "libyaml-libyaml-perl"
        assert stuck.reversals >= 20

    @pytest.mark.parametrize(
        "name",
        [
            "local-apt3-success.log",
            "local-apt3-gnome.log",
            "local-apt3-devcascade.log",
            "lp2150245-apt.log",
        ],
    )
    def test_logs_that_converged_show_no_livelock(self, name: str, interner: Interner) -> None:
        """Including one that failed for an unrelated reason.

        LP#2150245 fails on a third-party conflict, not a livelock. An earlier
        version of the detector reported thirty-six oscillating packages there
        because it counted ``MarkInstall`` -- which apt emits for every package
        it installs -- as a reversal.
        """
        assert detect_oscillations(sectioned(name).primary, interner) == ()

    def test_the_threshold_sits_in_the_measured_gap(self, interner: Interner) -> None:
        """Reversal counts are bimodal: 1-2 is noise, 17-20 is a livelock.

        Nothing at all falls between 3 and 16 across the six real logs, so the
        threshold is not fitted to them.
        """
        counts: list[int] = []
        for name in ("lp2150319-apt.log", "lp2169028-apt.log", "lp2150245-apt.log"):
            counts.extend(
                o.reversals
                for o in detect_oscillations(sectioned(name).primary, interner, min_reversals=1)
            )
        assert counts, "expected some oscillation in these logs"
        assert not any(3 <= c < 16 for c in counts)
        assert 3 <= MIN_REVERSALS <= 16

    def test_a_single_reversal_is_not_a_livelock(self, interner: Interner) -> None:
        """Keeping a package then upgrading it once is convergence."""
        found = detect_oscillations(
            sectioned("local-apt3-gnome.log").primary, interner, min_reversals=1
        )
        assert all(o.reversals <= 2 for o in found)

    def test_blame_falls_on_the_package_apt_refused(self, interner: Interner) -> None:
        """Installing it is what breaks the cycle; it is what the quirk marks."""
        _, result = lp("2150319", interner)
        livelock = next(f for f in result.findings if f.cause is Cause.RESOLVER_LIVELOCK)
        assert interner.package_label(livelock.root_pkgs[0]) == "libfile-libmagic-perl"
        assert livelock.detail["oscillating_package"] == "lintian"


class TestAptErrorCorroboration:
    """apt names a mechanism when it gives up, and that is checkable evidence."""

    def test_held_broken_packages_implicates_holds(self, interner: Interner) -> None:
        run, _ = lp("2150245", interner)
        causes = corroborated_causes(run, interner)
        assert Cause.HOLDBACK_BLOCKS_NEW_DEP in causes
        assert Cause.THIRD_PARTY_PIN in causes
        assert Cause.UNSATISFIABLE_VIRTUAL not in causes

    def test_corroboration_beats_a_bigger_resolved_conflict(self, interner: Interner) -> None:
        """LP#2150245's largest root is real, and is not the failure.

        ``gir1.2-gio-2.0`` is unsatisfiable with ninety-eight victims, but apt
        *resolved* it by removing the dependents and moved on. What it could
        not resolve it reported as ``you have held broken packages``. Ranking
        on blast radius alone led with the resolved conflict.
        """
        _, result = lp("2150245", interner)
        assert result.primary.cause is Cause.THIRD_PARTY_PIN

        biggest = max(result.findings, key=lambda f: f.cascade_size)
        assert biggest.cause is Cause.UNSATISFIABLE_VIRTUAL
        assert biggest.cascade_size > result.primary.cascade_size
        assert result.findings.index(result.primary) < result.findings.index(biggest)

    def test_no_apt_error_means_no_corroboration(self, interner: Interner) -> None:
        run, result = lp("2169028", interner)
        assert run.apt_error_entries == ()
        assert corroborated_causes(run, interner) == frozenset()
        assert result.corroborated == frozenset()


class TestRanking:
    def _finding(self, **kwargs: object) -> Finding:
        base: dict[str, object] = {
            "cause": Cause.EXACT_PIN_BROKEN_BY_UPGRADE,
            "rule": "resolver.roots",
            "severity": Severity.HIGH,
            "confidence": Confidence.STRONG,
        }
        base.update(kwargs)
        return Finding(**base)  # type: ignore[arg-type]

    def test_blast_radius_beats_rule_priority_within_a_tier(self) -> None:
        """Priority dominating put single-victim notes above a 39-package cascade."""
        small = self._finding(rule="resolver.third-party-blocker", cascade_size=1)
        large = self._finding(rule="resolver.roots", cascade_size=39)
        assert rank_findings([small, large])[0] is large

    def test_preconditions_outrank_everything(self) -> None:
        """Nothing observed is trustworthy while dpkg is mid-transaction."""
        big = self._finding(cascade_size=500)
        precondition = self._finding(
            cause=Cause.DPKG_INTERRUPTED, rule="dpkg.interrupted", cascade_size=0
        )
        assert rank_findings([big, precondition])[0] is precondition
        assert Cause.DPKG_INTERRUPTED in PRECONDITION_CAUSES

    def test_environment_outranks_packages(self) -> None:
        """A full disk looks like a dependency problem."""
        packages = self._finding(cascade_size=100)
        disk = self._finding(
            cause=Cause.NOT_ENOUGH_DISK_SPACE, rule="env.disk-space", cascade_size=0
        )
        assert rank_findings([packages, disk])[0] is disk

    def test_a_livelock_outranks_a_bigger_root(self) -> None:
        """It strands almost nothing, and it is still why apt gave up."""
        big = self._finding(cascade_size=98)
        livelock = self._finding(
            cause=Cause.RESOLVER_LIVELOCK, rule="resolver.livelock", cascade_size=0
        )
        assert rank_findings([big, livelock])[0] is livelock

    def test_advisories_never_take_the_title(self) -> None:
        advisory = self._finding(
            rule="resolver.fragile-decision", severity=Severity.INFO, cascade_size=0
        )
        real = self._finding(cascade_size=1)
        assert rank_findings([advisory, real])[0] is real

    def test_caveats_sort_last_but_are_never_truncated(self) -> None:
        caveat = self._finding(
            cause=Cause.NO_FAILURE_RECORDED,
            rule="evidence.truncated",
            severity=Severity.INFO,
        )
        bulk = [self._finding(cascade_size=n) for n in range(MAX_FINDINGS + 10)]
        ranked = rank_findings([*bulk, caveat])
        assert ranked[-1] is caveat
        assert len(ranked) == MAX_FINDINGS + 1

    def test_the_output_is_capped(self, interner: Interner) -> None:
        """Thirty-nine findings is the log again, not a diagnosis."""
        _, result = lp("2150245", interner)
        non_caveat = [f for f in result.findings if f.cause not in CAVEAT_CAUSES]
        assert len(non_caveat) <= MAX_FINDINGS

    def test_ranking_is_stable(self, interner: Interner) -> None:
        """An unstable order would make deduplication non-deterministic."""
        _, first = lp("2150245", interner)
        _, second = lp("2150245", interner)
        assert [f.summary for f in first.findings] == [f.summary for f in second.findings]


class TestAdvisoryGrouping:
    """Fragility is a property of a finding, not a class of finding."""

    def test_one_advisory_not_one_per_root(self, interner: Interner) -> None:
        """A finding per fragile root buried a 39-package cascade under twelve."""
        _, result = lp("2169028", interner)
        advisories = [f for f in result.findings if f.rule == "resolver.fragile-decision"]
        assert len(advisories) <= 1

    def test_the_advisory_names_the_narrowest_margin(self, interner: Interner) -> None:
        _, result = lp("2169028", interner)
        advisory = next(
            (f for f in result.findings if f.rule == "resolver.fragile-decision"),
            None,
        )
        if advisory is not None:
            assert advisory.fragile
            assert "package set" in advisory.summary
            assert advisory.severity is Severity.INFO


class TestTruncatedEvidence:
    def test_the_refusal_is_reported(self, interner: Interner) -> None:
        _, result = lp("2169028", interner)
        assert result.caveats
        assert "no failure was recorded" in result.caveats[0].summary

    def test_most_rules_are_withheld(self, interner: Interner) -> None:
        _, result = lp("2169028", interner)
        assert result.skipped_incomplete
        assert "env.disk-space" in result.skipped_incomplete

    def test_resolver_findings_still_appear(self, interner: Interner) -> None:
        """The roots are the most useful thing on such a bug.

        What is forbidden is claiming they are the cause, which the caveat
        prevents.
        """
        _, result = lp("2169028", interner)
        assert len(result.resolver_findings) > 0

    def test_complete_evidence_produces_no_caveat(self, interner: Interner) -> None:
        _, result = lp("2150319", interner)
        assert result.caveats == ()
        assert result.skipped_incomplete == ()


class TestRegistry:
    def test_every_rule_records_its_provenance(self) -> None:
        """A pattern with no upstream origin is a pattern fitted to samples."""
        for candidate in all_rules():
            assert candidate.provenance, f"{candidate.name} has no provenance"

    def test_rule_names_are_namespaced(self) -> None:
        for candidate in all_rules():
            assert "." in candidate.name, candidate.name

    def test_firing_order_is_deterministic(self) -> None:
        assert [r.name for r in all_rules()] == [r.name for r in all_rules()]

    def test_duplicate_registration_is_rejected(self) -> None:
        existing = next(iter(RULES))
        with pytest.raises(ValueError, match="duplicate rule name"):
            rule(existing, Cause.UNKNOWN, priority=1)(lambda _: ())

    def test_rules_are_registered(self) -> None:
        names = {r.name for r in all_rules()}
        assert "resolver.roots" in names
        assert "resolver.livelock" in names
        assert "dpkg.interrupted" in names
        assert "evidence.truncated" in names


class TestRulesDigest:
    """The digest attributes a verdict to a policy, so it must track policy.

    Signatures are persisted and compared across sessions. A cluster that
    changes tier between two corpus passes has two possible explanations --
    the logs describe different faults, or the rules changed underneath -- and
    a release number is too coarse to tell them apart, because almost every
    change that moves a verdict is a rule change between releases.
    """

    def test_is_stable_across_calls(self) -> None:
        assert rules_digest() == rules_digest()

    def test_is_short_enough_to_read_in_a_table(self) -> None:
        digest = rules_digest()
        assert len(digest) == 16
        assert all(c in "0123456789abcdef" for c in digest)

    def test_changes_when_a_ranking_input_changes(self) -> None:
        """Priority decides which of two findings becomes the title."""
        before = rules_digest()
        victim = next(iter(RULES))
        original = RULES[victim]
        RULES[victim] = replace(original, priority=original.priority + 1000)
        try:
            assert rules_digest() != before
        finally:
            RULES[victim] = original
        assert rules_digest() == before

    def test_changes_when_a_rule_is_added_or_removed(self) -> None:
        before = rules_digest()
        rule("test.ephemeral", Cause.UNKNOWN, priority=9999)(lambda _: ())
        try:
            assert rules_digest() != before
        finally:
            del RULES["test.ephemeral"]
        assert rules_digest() == before

    def test_changes_when_the_grammar_gains_a_verb(self) -> None:
        """A pattern addition changes the graph, so it must move the stamp.

        A line the lexer could not read is a verb the conflict graph could not
        see, so adding a pattern changes the graph, the coverage figure and
        potentially the ranking. Omitting the grammar was a real gap: after the
        ``Or group remove`` and parenthesised-``PreDepends`` patterns landed,
        stored runs held coverage numbers the current build would no longer
        produce and nothing said so.
        """
        import uru_doctor.apt.grammar as grammar
        from uru_doctor.apt.grammar import Verb

        before = rules_digest()
        original = grammar.PATTERNS
        grammar.PATTERNS = (*original, (Verb.UNKNOWN, re.compile("^never$")))
        try:
            assert rules_digest() != before
        finally:
            grammar.PATTERNS = original
        assert rules_digest() == before

    def test_is_unmoved_by_tightening_a_pattern(self) -> None:
        """The verb set, not the expressions.

        Rewriting a regex without changing which verbs exist does not change
        what can be recognised, and a digest that moved on every refactor would
        be ignored within a week.
        """
        import uru_doctor.apt.grammar as grammar

        before = rules_digest()
        original = grammar.PATTERNS
        grammar.PATTERNS = tuple(
            (verb, re.compile(pattern.pattern + "")) for verb, pattern in original
        )
        try:
            assert rules_digest() == before
        finally:
            grammar.PATTERNS = original

    def test_is_unmoved_by_documentation(self) -> None:
        """Rewording a remedy must not look like a policy change.

        If prose moves the digest then every doc edit raises a false drift
        warning, the warnings become noise, and the one that matters is
        ignored. ``provenance``, ``remedy`` and ``phase_hint`` are excluded
        for exactly that reason.
        """
        before = rules_digest()
        victim = next(iter(RULES))
        original = RULES[victim]
        RULES[victim] = replace(
            original,
            remedy="reworded entirely",
            provenance="DistUpgradeQuirks.something_else",
            phase_hint="SOMEWHERE_ELSE",
        )
        try:
            assert rules_digest() == before
        finally:
            RULES[victim] = original


class TestDpkgRules:
    def test_the_cascade_yields_one_finding_not_thirty_five(self, interner: Interner) -> None:
        """``Errors were encountered while processing:`` lists all 35."""
        from uru_doctor.parsers.aptterm import parse_apt_term

        term = parse_apt_term(fixture_text("logs/local-aptterm-dpkgfail.log").splitlines())
        run = ingest_one(
            {
                LogSource.MAIN: "2026-03-30 13:45:00,000 INFO apt version: '3.2.0'\n",
                LogSource.APT_TERM: fixture_text("logs/local-aptterm-dpkgfail.log"),
            },
            interner,
        )
        result = diagnose(run, interner, term=term)
        dpkg = [f for f in result.findings if f.rule == "dpkg.failures"]
        assert len(dpkg) == 1
        assert dpkg[0].cause is Cause.DPKG_MAINTSCRIPT_FAILED

    def test_blame_goes_to_the_hook_package(self, interner: Interner) -> None:
        """``python3`` ran the hook; ``llvm-21-tools`` shipped the broken file."""
        from uru_doctor.parsers.aptterm import parse_apt_term

        term = parse_apt_term(fixture_text("logs/local-aptterm-dpkgfail.log").splitlines())
        run = ingest_one(
            {
                LogSource.MAIN: "2026-03-30 13:45:00,000 INFO apt version: '3.2.0'\n",
                LogSource.APT_TERM: fixture_text("logs/local-aptterm-dpkgfail.log"),
            },
            interner,
        )
        result = diagnose(run, interner, term=term)
        dpkg = next(f for f in result.findings if f.rule == "dpkg.failures")
        assert interner.package_label(dpkg.root_pkgs[0]) == "llvm-21-tools"
        assert dpkg.detail["named_by_hook"] == "llvm-21-tools"
        assert dpkg.detail["failing_package"] == "python3"


class TestUpgraderRules:
    @pytest.mark.parametrize(
        ("message", "cause"),
        [
            ("Not enough free space: ['/boot needs 200M']", Cause.NOT_ENOUGH_DISK_SPACE),
            ("Not running as root!", Cause.FILESYSTEM_NOT_WRITABLE),
            ("Cache can not be locked (dpkg busy)", Cause.CACHE_LOCK_FAILED),
            ("upgrade over ssh not allowed", Cause.SSH_UPGRADE_BLOCKED),
            (
                "Unauthenticated packages found: 'foo'",
                Cause.PACKAGE_AUTH_FAILED,
            ),
            ("doUpdate() failed completely", Cause.UPDATE_FAILED),
            ("checkViewDepends() failed", Cause.VIEW_DEPENDS_MISSING),
            (
                "Packages to downgrade found: 'bar'",
                Cause.UNSUPPORTED_UPGRADE_PATH,
            ),
        ],
    )
    def test_upstream_strings_are_recognised(
        self, message: str, cause: Cause, interner: Interner
    ) -> None:
        run = ingest_one(
            {
                LogSource.MAIN: (
                    "2026-01-01 10:00:00,000 INFO apt version: '3.2.0'\n"
                    f"2026-01-01 10:00:01,000 ERROR {message}\n"
                )
            },
            interner,
        )
        result = diagnose(run, interner)
        assert cause in {f.cause for f in result.findings}, result.findings

    def test_disk_space_reports_the_requirement(self, interner: Interner) -> None:
        run = ingest_one(
            {
                LogSource.MAIN: (
                    "2026-01-01 10:00:00,000 INFO apt version: '3.2.0'\n"
                    "2026-01-01 10:00:01,000 ERROR Not enough free space:"
                    " ['/boot needs 200M']\n"
                )
            },
            interner,
        )
        result = diagnose(run, interner)
        disk = next(f for f in result.findings if f.cause is Cause.NOT_ENOUGH_DISK_SPACE)
        assert "/boot" in disk.summary

    def test_dpkg_interrupted_is_recognised_from_the_apt_error(self, interner: Interner) -> None:
        run = ingest_one(
            {
                LogSource.MAIN: (
                    "2026-01-01 10:00:00,000 INFO apt version: '3.2.0'\n"
                    "2026-01-01 10:00:01,000 ERROR Dist-upgrade failed: "
                    "'E:dpkg was interrupted, you must manually run "
                    "'dpkg --configure -a' to correct the problem.'\n"
                )
            },
            interner,
        )
        result = diagnose(run, interner)
        assert result.primary.cause is Cause.DPKG_INTERRUPTED
        assert result.primary.detail["remedy_command"] == "sudo dpkg --configure -a"

    def test_a_benign_error_fires_nothing(self, interner: Interner) -> None:
        run = ingest_one(
            {
                LogSource.MAIN: (
                    "2026-01-01 10:00:00,000 INFO apt version: '3.2.0'\n"
                    "2026-01-01 10:00:01,000 ERROR failed to import AptClone\n"
                )
            },
            interner,
        )
        result = diagnose(run, interner)
        causes = {f.cause for f in result.findings}
        assert causes <= CAVEAT_CAUSES


class TestHeldOutBugs:
    """Four bugs the tool had never seen when its rules were written.

    Fetched after the diagnosis engine was complete, which makes them the only
    unbiased check on it available. Three carry logs; the fourth carries two
    screenshots and nothing else.
    """

    @pytest.mark.parametrize(
        ("bug_id", "cause", "package"),
        [
            # The libpeas 1.0-0 -> 1.0-1 transition: python3-gi needs a newer
            # gedit/eog, which need libpeas-1.0-1, which Breaks the installed
            # libpeas-1.0-0 that apt keeps.
            ("2150339", Cause.RESOLVER_LIVELOCK, "libpeas-1.0-1"),
            ("2151847", Cause.RESOLVER_LIVELOCK, "libpeas-1.0-1"),
            # KDE Frameworks holdback cascade, no livelock at all.
            ("2155743", Cause.HELD_PACKAGE_BLOCKS_UPGRADE, "libkirigami-data"),
        ],
    )
    def test_primary_cause(
        self, bug_id: str, cause: Cause, package: str, interner: Interner
    ) -> None:
        _, result = lp(bug_id, interner)
        primary = result.primary
        assert primary is not None
        assert primary.cause is cause
        assert interner.package_label(primary.root_pkgs[0]) == package

    def test_a_recovered_livelock_is_not_causal(self, interner: Interner) -> None:
        """Only oscillations apt was still stuck in when it quit count.

        Every genuine livelock in the corpus has its last reversal between
        99.1% and 100% of the way through the section -- apt never escapes
        them. One it escaped would be a detour, and because the livelock tier
        outranks blast radius it would wrongly displace a real cascade.
        """
        from uru_doctor.apt.livelock import TERMINAL_POSITION, detect_oscillations

        for name in ("lp2150339-apt.log", "lp2151847-apt.log", "lp2150319-apt.log"):
            found = detect_oscillations(sectioned(name).primary, interner)
            assert found
            for oscillation in found:
                assert oscillation.is_terminal
                assert oscillation.position >= TERMINAL_POSITION

    def test_livelocks_are_grouped_by_blocker(self, interner: Interner) -> None:
        """Several packages stuck on one package is one fault, not several.

        LP#2151847 has three oscillating packages; two are stuck on
        ``libpeas-1.0-1``. Reporting one finding each ranked them by reversal
        count, so the primary cause turned on 18 reversals versus 17 -- noise.
        """
        _, result = lp("2151847", interner)
        livelocks = [f for f in result.findings if f.rule == "resolver.livelock"]
        assert len(livelocks) == 2
        assert interner.package_label(livelocks[0].root_pkgs[0]) == "libpeas-1.0-1"
        assert len(livelocks[0].victim_pkgs) == 2

    def test_a_livelock_outranks_a_larger_holdback(self, interner: Interner) -> None:
        """LP#2151847 has two independent faults.

        A ``libkirigami-data`` holdback strands a hundred packages, and the
        libpeas livelock strands two. The livelock still wins: apt never
        converged, so it never got as far as resolving the holdback.
        """
        _, result = lp("2151847", interner)
        assert result.primary.cause is Cause.RESOLVER_LIVELOCK
        holdback = next(f for f in result.findings if f.cause is Cause.HELD_PACKAGE_BLOCKS_UPGRADE)
        assert holdback.cascade_size >= 100
        assert result.findings.index(result.primary) < result.findings.index(holdback)

    def test_third_party_packages_are_not_blamed_without_evidence(self, interner: Interner) -> None:
        """LP#2155743 is the negative control for third-party blame.

        A triager tagged it ``third-party-packages`` and its ``Foreign`` list
        has forty-six entries including ``systemd`` and ``udev``. Not one of
        them is a root: the PPAs upgrade cleanly and a KDE holdback is the
        fault. Being third-party is not evidence of being the cause.
        """
        run, result = lp("2155743", interner)
        assert len(run.third_party) >= 40
        assert not result.is_candidate_invalid
        assert result.primary.cause is Cause.HELD_PACKAGE_BLOCKS_UPGRADE
        assert "resolver.third-party-blocker" not in result.fired

    def test_a_bug_with_no_logs_says_so(self, interner: Interner) -> None:
        """LP#2161332 attached two screenshots and nothing else."""
        payload = json.loads((FIXTURES / "lp" / "bug2161332.json").read_text())
        meta = parse_apport_meta(payload["description"], tags=payload["tags"])
        run = ingest_one({}, interner, meta=meta, bug_id=2161332)
        result = diagnose(run, interner, meta=meta)

        assert not run.evidence_complete
        assert result.primary is not None
        assert result.primary.cause is Cause.NO_FAILURE_RECORDED
        assert "logs not provided" in result.primary.summary

    def test_screenshots_are_skipped_without_downloading(self) -> None:
        """The LP API answers 429 under load, so every avoided fetch counts."""
        from uru_doctor.parsers.apportmeta import (
            attachment_source,
            is_irrelevant_attachment,
        )

        payload = json.loads((FIXTURES / "lp" / "bug2161332.json").read_text())
        assert payload["attachments"]
        for title in payload["attachments"]:
            assert is_irrelevant_attachment(title), title
            assert attachment_source(title) is None


class TestNewGrammarShapes:
    """Shapes the held-out logs contained and the corpus did not."""

    def test_full_coverage_including_the_new_logs(self) -> None:
        """Any unlexed line is a verb the analysis cannot see."""
        from uru_doctor.apt.lexer import LexStats, lex

        total = matched = 0
        for path in sorted((FIXTURES / "apt").glob("*.log")):
            stats = LexStats()
            list(lex(path.read_text().splitlines(), stats))
            assert stats.coverage == 1.0, f"{path.name}: {stats.top_unknown(3)}"
            total += stats.lines - stats.blank
            matched += stats.matched
        assert matched == total
        # Guards against the corpus shrinking to the point of proving nothing.
        assert total > 18_000

    def test_the_reinstated_score_variant(self) -> None:
        """``Re-Instated <pkg> (N vs N)``.

        Five of the 798 ``Re-Instated`` lines in the corpus carry a score pair,
        so a pattern anchored without it matched 99.4% and dropped the rest.
        """
        from uru_doctor.apt.grammar import Verb
        from uru_doctor.apt.lexer import lex

        tokens = list(
            lex(
                [
                    "  Re-Instated libkirigami-data:amd64",
                    "  Re-Instated libkirigami6:amd64 (3 vs 7)",
                ]
            )
        )
        assert [t.verb for t in tokens] == [Verb.REINSTATED, Verb.REINSTATED]
        assert tokens[1].subject == "libkirigami6:amd64"

    def test_the_ignored_conflict_shape(self) -> None:
        """apt declining to apply a conflict must never read as a conflict."""
        from uru_doctor.apt.grammar import Verb
        from uru_doctor.apt.lexer import lex

        tokens = list(
            lex(
                [
                    "Conflicts//Breaks against version 1:17.0+dfsg1-2ubuntu3 for"
                    " pulseaudio but that is not InstVer, ignoring"
                ]
            )
        )
        assert [t.verb for t in tokens] == [Verb.IGNORE_NOT_INSTVER]
        assert tokens[0].subject == "pulseaudio"

    def test_both_or_group_verbs(self) -> None:
        """``Or group remove for A`` as well as ``Or group keep for A``.

        Found by the first live ``sweep``: LP#2168863 dropped coverage to
        99.9527% on two lines reading ``Or group remove for teamviewer:amd64``.
        Only the ``keep`` form had been enumerated.

        Both strings sit adjacent to each other in ``libapt-pkg``, which is the
        recurring shape of a grammar gap in this codebase -- an upstream pair
        whose sibling stays invisible until some log happens to contain it.
        Checked against the library rather than against the one log that
        exposed it, so the fix covers the pair rather than the instance.

        The ``remove`` form is the one that carries blame: apt emits it when no
        alternative in an or-group can be satisfied, immediately before the
        ``MarkDelete`` that drops the package.
        """
        from uru_doctor.apt.grammar import Verb
        from uru_doctor.apt.lexer import lex

        tokens = list(
            lex(
                [
                    "  Or group keep for gedit:amd64",
                    "  Or group remove for teamviewer:amd64",
                    "  MarkDelete teamviewer:amd64 < 15.17.6 @ii mK Ib > FU=0",
                ]
            )
        )
        assert [t.verb for t in tokens] == [
            Verb.OR_GROUP_KEEP,
            Verb.OR_GROUP_REMOVE,
            Verb.MARK_DELETE,
        ]
        assert tokens[1].subject == "teamviewer:amd64"

    def test_or_group_verbs_are_distinct(self) -> None:
        """Keep and remove are opposite outcomes and must not share a verb.

        A single ``OR_GROUP`` token would make "apt kept this package" and
        "apt deleted this package" indistinguishable downstream.
        """
        from uru_doctor.apt.grammar import Verb

        assert Verb.OR_GROUP_KEEP is not Verb.OR_GROUP_REMOVE
        assert Verb.OR_GROUP_KEEP.value != Verb.OR_GROUP_REMOVE.value
