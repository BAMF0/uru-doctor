# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for :mod:`uru_doctor.dedup` and :mod:`uru_doctor.title`.

The headline test is :class:`TestTwoReportersOneBug`, which uses the only
genuine deduplication ground truth available: two independently filed
``apt.log`` files for LP#2150319, from different machines eight days apart.
"""

from __future__ import annotations

import json
from dataclasses import fields as dataclass_fields

import pytest

from uru_doctor.config import DedupConfig
from uru_doctor.dedup import (
    EXCLUDED_FROM_SIGNATURES,
    Signature,
    Tier,
    build_signature,
    cluster_runs,
    jaccard,
    score_pair,
    summarise,
    unresolved_causes,
)
from uru_doctor.diagnose import diagnose
from uru_doctor.intern import Interner
from uru_doctor.models import Cause, Finding, LogSource, Phase, Severity, UpgradeRun
from uru_doctor.parsers.apportmeta import parse_apport_meta
from uru_doctor.title import MAX_TITLE, propose_title, render_detail, title_for_cluster

from .conftest import FIXTURES, fixture_text, ingest_one


def ingest(
    interner: Interner,
    *,
    apt: str | None = None,
    main: str | None = None,
    bug_id: str | None = None,
):
    attachments: dict[LogSource, str] = {}
    if apt:
        attachments[LogSource.APT] = fixture_text(f"apt/{apt}")
    if main:
        attachments[LogSource.MAIN] = fixture_text(f"logs/{main}")
    meta = None
    if bug_id:
        payload = json.loads((FIXTURES / "lp" / f"bug{bug_id}.json").read_text())
        meta = parse_apport_meta(payload["description"], tags=payload["tags"])
    run = ingest_one(
        attachments, interner, meta=meta, bug_id=int(bug_id) if bug_id else None
    )
    return (run, diagnose(run, interner, meta=meta))


class TestNoTextIsUsed:
    """Signatures must never depend on what a human typed.

    The thirteen duplicates of LP#2150245 are titled ``Ubgrade does not work``,
    ``upgrade to 26.4`` and similar. Any text measure that clustered them would
    have been fitted to noise.
    """

    def test_the_title_does_not_affect_the_signature(self, interner: Interner) -> None:
        run, result = ingest(interner, apt="lp2150319-apt.log")
        baseline = build_signature(run, result.findings, interner)

        for title in ("Ubgrade does not work", "upgrade to 26.4", ""):
            renamed = run.model_copy(update={"current_title": title})
            assert build_signature(renamed, result.findings, interner) == baseline

    def test_tags_do_not_affect_the_signature(self, interner: Interner) -> None:
        run, result = ingest(interner, apt="lp2150319-apt.log")
        baseline = build_signature(run, result.findings, interner)
        tagged = run.model_copy(update={"tags": ("apport-bug", "noble", "regression")})
        assert build_signature(tagged, result.findings, interner) == baseline

    def test_apport_signature_is_not_consulted(self, interner: Interner) -> None:
        """apport embeds ``package:name:version``, so it fails to collapse.

        Two reporters of one fault on different point releases get different
        apport signatures, which is a large part of why these bugs accumulate
        duplicates in the first place.
        """
        run, result = ingest(interner, apt="lp2150319-apt.log")
        assert build_signature(run, result.findings, interner).apport_dupe is None

    def test_prior_triage_does_not_affect_the_signature(self, interner: Interner) -> None:
        """Launchpad's own verdicts are ground truth, never evidence.

        ``duplicate_of``, ``duplicate_count`` and ``bug_status`` are carried on
        the run because the bug's resolution is the best cheap check on whether
        this tool is right. Reading them back in as evidence would reproduce
        the triage mistakes already in the corpus -- and these bugs accumulate
        duplicates precisely because the existing grouping is wrong, so
        learning from it would be learning the error.
        """
        run, result = ingest(interner, apt="lp2150319-apt.log")
        baseline = build_signature(run, result.findings, interner)

        for update in (
            {"duplicate_of": 2150245},
            {"duplicate_count": 13},
            {"bug_status": "Invalid"},
            {"bug_status": "Fix Released", "duplicate_of": 99, "duplicate_count": 7},
        ):
            altered = run.model_copy(update=update)
            assert build_signature(altered, result.findings, interner) == baseline, update

    def test_the_exclusion_list_names_real_fields(self) -> None:
        """Guards the list itself against drifting out of date."""
        known = set(UpgradeRun.model_fields) | {"preamble", "duplicate_signature"}
        assert known >= EXCLUDED_FROM_SIGNATURES


class TestTwoReportersOneBug:
    """Genuine ground truth: two independent logs for one confirmed bug.

    ``lp2150319-apt.log`` and ``lp2150319-c19-apt.log`` were filed eight days
    apart from different machines, with different lengths, dates and installed
    software.
    """

    def test_they_are_judged_duplicates(self, interner: Interner) -> None:
        left, left_result = ingest(interner, apt="lp2150319-apt.log")
        right, right_result = ingest(interner, apt="lp2150319-c19-apt.log")

        verdict = score_pair(
            left,
            right,
            left_result.findings,
            right_result.findings,
            interner,
            DedupConfig(),
        )
        assert verdict.duplicate
        assert "libfile-libmagic-perl" in verdict.shared_roots

    def test_they_share_an_exact_root_graph_digest(self, interner: Interner) -> None:
        """Tier 0, the strongest form of match: identical blamed subgraph."""
        left, left_result = ingest(interner, apt="lp2150319-apt.log")
        right, right_result = ingest(interner, apt="lp2150319-c19-apt.log")

        left_sig = build_signature(left, left_result.findings, interner)
        right_sig = build_signature(right, right_result.findings, interner)
        assert left_sig.root_graph is not None
        assert left_sig.root_graph == right_sig.root_graph

    def test_incidental_roots_are_excluded(self, interner: Interner) -> None:
        """Only the primary finding's structure is fingerprinted.

        Including every finding broke this: each machine contributes roots
        reflecting its own installed software -- ``libheif1`` and
        ``python3.12-tk`` on one, ``pidgin-data`` and ``libsgutils2-1.48`` on
        the other -- and the digests differed.
        """
        left, left_result = ingest(interner, apt="lp2150319-apt.log")
        right, right_result = ingest(interner, apt="lp2150319-c19-apt.log")

        def roots(result: object) -> set[str]:
            return {
                interner.package_label(p)
                for f in result.findings  # type: ignore[attr-defined]
                for p in f.root_pkgs
            }

        shared = roots(left_result) & roots(right_result)
        either = roots(left_result) | roots(right_result)
        # The reports genuinely disagree about most roots, and still match.
        assert len(shared) < len(either)
        left_sig = build_signature(left, left_result.findings, interner)
        right_sig = build_signature(right, right_result.findings, interner)
        assert left_sig.root_graph == right_sig.root_graph

    def test_the_primary_finding_carries_a_graph_index(self, interner: Interner) -> None:
        """Without it tier 0 cannot see the primary finding at all.

        The livelock rule omitted it, so the digest silently fell back to the
        per-machine incidental roots.
        """
        _, result = ingest(interner, apt="lp2150319-apt.log")
        assert result.primary is not None
        assert result.primary.graph_index is not None


class TestDistinctBugsStayApart:
    @pytest.mark.parametrize(
        ("left_apt", "right_apt"),
        [
            ("lp2150319-apt.log", "lp2150245-apt.log"),
            ("lp2150319-apt.log", "local-apt3-devcascade.log"),
            ("lp2150245-apt.log", "local-apt3-devcascade.log"),
            ("lp2150245-apt.log", "lp2169028-apt.log"),
        ],
    )
    def test_unrelated_logs_are_not_duplicates(
        self, left_apt: str, right_apt: str, interner: Interner
    ) -> None:
        left, left_result = ingest(interner, apt=left_apt)
        right, right_result = ingest(interner, apt=right_apt)
        verdict = score_pair(
            left,
            right,
            left_result.findings,
            right_result.findings,
            interner,
            DedupConfig(),
        )
        assert not verdict.duplicate, verdict.reason

    def test_root_graph_digests_differ(self, interner: Interner) -> None:
        digests = set()
        for name in (
            "lp2150319-apt.log",
            "lp2150245-apt.log",
            "local-apt3-devcascade.log",
        ):
            run, result = ingest(interner, apt=name)
            signature = build_signature(run, result.findings, interner)
            digests.add(signature.root_graph)
        assert len(digests) == 3


class TestVersionNormalisation:
    """A constraint's operator is identity; its version usually is not."""

    def test_the_same_log_is_its_own_duplicate(self, interner: Interner) -> None:
        run, result = ingest(interner, apt="lp2150245-apt.log")
        signature = build_signature(run, result.findings, interner)
        again = build_signature(run, result.findings, interner)
        assert signature.root_graph == again.root_graph

    @pytest.mark.parametrize("granularity", ["operator", "upstream", "major", "exact"])
    def test_every_granularity_is_deterministic(self, granularity: str, interner: Interner) -> None:
        run, result = ingest(interner, apt="lp2150319-apt.log")
        first = build_signature(run, result.findings, interner, granularity=granularity)
        second = build_signature(run, result.findings, interner, granularity=granularity)
        assert first.root_graph == second.root_graph

    def test_the_default_drops_the_version(self) -> None:
        assert DedupConfig().version_granularity == "operator"


class TestPhaseBanding:
    """The same package failing before and during dpkg are different bugs."""

    def _finding(self, phase: Phase) -> Finding:
        return Finding(
            cause=Cause.DPKG_MAINTSCRIPT_FAILED,
            rule="dpkg.failures",
            root_pkgs=(1,),
            phase=phase,
            severity=Severity.HIGH,
        )

    def test_planning_and_commit_differ(self, interner: Interner) -> None:
        run = UpgradeRun()
        before = build_signature(run, [self._finding(Phase.CALCULATE)], interner)
        during = build_signature(run, [self._finding(Phase.COMMIT)], interner)
        assert before.cause_tuple != during.cause_tuple

    def test_adjacent_pre_commit_phases_are_the_same_band(self, interner: Interner) -> None:
        """Which quirk ran first is not a property of the bug."""
        run = UpgradeRun()
        a = build_signature(run, [self._finding(Phase.PRE_DIST_UPGRADE)], interner)
        b = build_signature(run, [self._finding(Phase.CALCULATE)], interner)
        assert a.cause_tuple == b.cause_tuple


class TestJaccard:
    def test_unweighted_ratio(self) -> None:
        assert jaccard([1, 2, 3], [2, 3, 4]) == pytest.approx(2 / 4)
        assert jaccard([1, 2], [1, 2]) == 1.0
        assert jaccard([], []) == 1.0
        assert jaccard([1], []) == 0.0

    def test_weights_suppress_boilerplate(self) -> None:
        """Common templates must not dominate.

        Unweighted, two unrelated upgrade logs score high purely on the
        thousand ``Setting up <PKG>`` lines they share.
        """
        shared_boilerplate = list(range(100))
        left = [*shared_boilerplate, 900]
        right = [*shared_boilerplate, 901]
        weights = {t: 0.01 for t in shared_boilerplate} | {900: 5.0, 901: 5.0}

        assert jaccard(left, right) > 0.95
        assert jaccard(left, right, weights) < 0.2


class TestScoringGate:
    def test_shared_roots_are_required_before_scoring(self, interner: Interner) -> None:
        """Without the gate, similarity merges every noble-to-resolute failure."""
        left, left_result = ingest(interner, apt="lp2150319-apt.log")
        right, right_result = ingest(interner, apt="local-apt3-devcascade.log")
        verdict = score_pair(
            left,
            right,
            left_result.findings,
            right_result.findings,
            interner,
            DedupConfig(min_shared_roots=99),
        )
        assert not verdict.duplicate
        assert verdict.tier == Tier.NONE
        assert "shared root" in verdict.reason

    def test_only_tier_two_can_be_ambiguous(self, interner: Interner) -> None:
        """An exact structural match is not a judgement call."""
        left, left_result = ingest(interner, apt="lp2150319-apt.log")
        right, right_result = ingest(interner, apt="lp2150319-c19-apt.log")
        verdict = score_pair(
            left,
            right,
            left_result.findings,
            right_result.findings,
            interner,
            DedupConfig(),
        )
        assert verdict.duplicate
        assert not verdict.needs_adjudication


class TestClustering:
    def _sig(self, root: bytes | None, cause: bytes | None) -> Signature:
        return Signature(root_graph=root, cause_tuple=cause)

    def test_tier_zero_wins_over_tier_one(self) -> None:
        signatures = {
            "a": self._sig(b"same-graph-xxxxx", b"cause-1xxxxxxxxx"),
            "b": self._sig(b"same-graph-xxxxx", b"cause-2xxxxxxxxx"),
        }
        clusters = cluster_runs(signatures, config=DedupConfig())
        assert len(clusters) == 1
        assert clusters[0].tier == Tier.ROOT_GRAPH

    def test_tier_one_catches_what_tier_zero_misses(self) -> None:
        signatures = {
            "a": self._sig(b"graph-axxxxxxxxx", b"same-causexxxxxx"),
            "b": self._sig(b"graph-bxxxxxxxxx", b"same-causexxxxxx"),
        }
        clusters = cluster_runs(signatures, config=DedupConfig())
        assert len(clusters) == 1
        assert clusters[0].tier == Tier.CAUSE_TUPLE

    def test_the_earliest_report_is_the_representative(self) -> None:
        signatures = {
            "late": self._sig(b"same-graph-xxxxx", None),
            "early": self._sig(b"same-graph-xxxxx", None),
        }
        clusters = cluster_runs(signatures, config=DedupConfig(), oldest_first=["early", "late"])
        assert clusters[0].representative == "early"
        assert clusters[0].duplicates == ["late"]

    def test_a_singleton_is_not_a_cluster(self) -> None:
        signatures = {"only": self._sig(b"xxxxxxxxxxxxxxxx", None)}
        assert cluster_runs(signatures, config=DedupConfig()) == []

    def test_an_implausible_cluster_is_refused(self) -> None:
        """A five-hundred-member cluster means the fingerprint lost its power."""
        signatures = {f"run{i}": self._sig(b"same-graph-xxxxx", None) for i in range(10)}
        clusters = cluster_runs(signatures, config=DedupConfig(max_cluster_size=5))
        assert clusters == []

    def test_runs_without_signatures_are_reported(self) -> None:
        signatures = {"a": self._sig(None, None), "b": self._sig(b"x" * 16, None)}
        assert unresolved_causes(signatures) == {"a"}

    def test_summary_counts(self) -> None:
        signatures = {
            "a": self._sig(b"g1" * 8, None),
            "b": self._sig(b"g1" * 8, None),
            "c": self._sig(None, b"c1" * 8),
            "d": self._sig(None, b"c1" * 8),
        }
        clusters = cluster_runs(signatures, config=DedupConfig())
        counts = summarise(clusters)
        assert counts["clusters"] == 2
        assert counts["duplicates"] == 2
        assert counts["by_root_graph"] == 1
        assert counts["by_cause_tuple"] == 1


class TestTitles:
    @pytest.mark.parametrize(
        ("bug_id", "must_contain"),
        [
            ("2150245", ["libwacom9-surface", "third-party"]),
            # Both packages a triager needs: the one apt loops on and the one
            # that fixes it.
            ("2150319", ["lintian", "libfile-libmagic-perl", "deadlock"]),
        ],
    )
    def test_titles_name_the_actionable_packages(
        self, bug_id: str, must_contain: list[str], interner: Interner
    ) -> None:
        run, result = ingest(
            interner,
            apt=f"lp{bug_id}-apt.log",
            main=f"lp{bug_id}-main.log",
            bug_id=bug_id,
        )
        proposed = propose_title(run, result, interner)
        for needle in must_contain:
            assert needle in proposed.title, proposed.title

    def test_the_release_pair_leads(self, interner: Interner) -> None:
        run, result = ingest(interner, apt="lp2150319-apt.log", main="lp2150319-main.log")
        assert propose_title(run, result, interner).title.startswith("noble\u2192resolute:")

    def test_titles_fit(self, interner: Interner) -> None:
        for bug_id in ("2150245", "2150319", "2169028"):
            run, result = ingest(
                interner,
                apt=f"lp{bug_id}-apt.log",
                main=f"lp{bug_id}-main.log",
                bug_id=bug_id,
            )
            proposed = propose_title(run, result, interner)
            assert len(proposed.title) <= MAX_TITLE

    def test_trimming_never_loses_the_blamed_package(self, interner: Interner) -> None:
        """An earlier phrasing trimmed away the one package that fixes the bug."""
        run, result = ingest(interner, apt="lp2150319-apt.log", main="lp2150319-main.log")
        proposed = propose_title(run, result, interner)
        assert not proposed.truncated
        assert "libfile-libmagic-perl" in proposed.title

    def test_truncated_evidence_is_marked_unconfident(self, interner: Interner) -> None:
        run, result = ingest(
            interner,
            apt="lp2169028-apt.log",
            main="lp2169028-main.log",
            bug_id="2169028",
        )
        proposed = propose_title(run, result, interner)
        assert not proposed.confident
        assert "unconfirmed" in proposed.title

    def test_the_release_pair_degrades_one_half_at_a_time(self, interner: Interner) -> None:
        """A bug with only an apt.log still knows its source release."""
        run, result = ingest(interner, apt="lp2150319-c19-apt.log", bug_id="2150319")
        assert run.from_series == "noble"
        assert run.to_series == ""
        assert propose_title(run, result, interner).title.startswith("noble\u2192?:")

    def test_the_reporters_title_is_never_read(self, interner: Interner) -> None:
        run, result = ingest(interner, apt="lp2150319-apt.log", main="lp2150319-main.log")
        renamed = run.model_copy(update={"current_title": "Ubgrade does not work"})
        assert (
            propose_title(renamed, result, interner).title
            == propose_title(run, result, interner).title
        )

    def test_every_cause_renders_something_specific(self, interner: Interner) -> None:
        """A title that says only "failed" is unsearchable."""
        for cause in Cause:
            finding = Finding(
                cause=cause,
                rule="test",
                root_pkgs=(interner.package("examplepkg"),),
                cascade_size=3,
            )
            detail = render_detail(finding, interner)
            assert detail
            assert detail == detail.strip()
            assert "None" not in detail

    def test_no_findings_yields_an_honest_title(self, interner: Interner) -> None:
        from uru_doctor.diagnose import DiagnosisResult

        run = UpgradeRun(from_series="noble", to_series="resolute")
        proposed = propose_title(run, DiagnosisResult(), interner)
        assert not proposed.confident
        assert "no failure recorded" in proposed.title


class TestClusterTitle:
    def test_the_most_specific_title_represents_a_cluster(self, interner: Interner) -> None:
        left, left_result = ingest(interner, apt="lp2150319-apt.log")
        right, right_result = ingest(interner, apt="lp2150319-c19-apt.log", bug_id="2150319")
        chosen = title_for_cluster(
            [
                propose_title(left, left_result, interner),
                propose_title(right, right_result, interner),
            ]
        )
        assert chosen is not None
        assert "libfile-libmagic-perl" in chosen.title

    def test_selection_is_deterministic(self, interner: Interner) -> None:
        run, result = ingest(interner, apt="lp2150319-apt.log", main="lp2150319-main.log")
        titles = [propose_title(run, result, interner) for _ in range(3)]
        assert title_for_cluster(titles) == title_for_cluster(list(reversed(titles)))

    def test_an_empty_cluster_yields_nothing(self) -> None:
        assert title_for_cluster([]) is None


def test_verdict_fields_are_all_populated(interner: Interner) -> None:
    """Every field on a verdict must mean something; none are placeholders."""
    left, left_result = ingest(interner, apt="lp2150319-apt.log")
    right, right_result = ingest(interner, apt="lp2150319-c19-apt.log")
    verdict = score_pair(
        left, right, left_result.findings, right_result.findings, interner, DedupConfig()
    )
    for field in dataclass_fields(verdict):
        assert getattr(verdict, field.name) is not None
    assert verdict.reason


class TestHeldOutClustering:
    """Three bugs Launchpad has not linked, which share one root cause.

    LP#2150339, LP#2151847 and LP#2169028 are all the libpeas 1.0-0 to 1.0-1
    transition: ``python3-gi`` requires a newer ``gedit``/``eog``, which
    require ``libpeas-1.0-1`` at version ``1.38.1-4ubuntu1``, which ``Breaks``
    the installed ``libpeas-1.0-0`` that apt keeps. All three carry zero
    duplicates on Launchpad.
    """

    def _corpus(self, interner: Interner) -> dict[str, Signature]:
        out: dict[str, Signature] = {}
        for bug_id in ("2150339", "2151847", "2169028", "2155743", "2150245"):
            run, result = ingest(
                interner,
                apt=f"lp{bug_id}-apt.log",
                main=f"lp{bug_id}-main.log",
                bug_id=bug_id,
            )
            out[bug_id] = build_signature(run, result.findings, interner)
        return out

    def test_the_two_questing_reports_share_a_root_graph(self, interner: Interner) -> None:
        """Tier 0: byte-identical blamed subgraph from different machines."""
        signatures = self._corpus(interner)
        assert signatures["2150339"].root_graph is not None
        assert signatures["2150339"].root_graph == signatures["2151847"].root_graph

    def test_all_three_libpeas_bugs_cluster(self, interner: Interner) -> None:
        """Tier 1 must extend the tier-0 cluster, not form a rival.

        An earlier version skipped runs already assigned, so bug 2169028 --
        which matches the other two only at tier 1 -- was reported as a
        singleton.
        """
        clusters = cluster_runs(
            self._corpus(interner),
            config=DedupConfig(),
            oldest_first=["2150339", "2151847", "2155743", "2169028", "2150245"],
        )
        libpeas = next(c for c in clusters if "2150339" in c.members)
        assert set(libpeas.members) == {"2150339", "2151847", "2169028"}
        assert libpeas.representative == "2150339"

    def test_the_unrelated_bugs_stay_out(self, interner: Interner) -> None:
        clusters = cluster_runs(self._corpus(interner), config=DedupConfig())
        clustered = {m for c in clusters for m in c.members}
        assert "2155743" not in clustered
        assert "2150245" not in clustered

    def test_sharing_a_victim_is_not_sharing_a_cause(self, interner: Interner) -> None:
        """LP#2151847 and LP#2155743 both have the libkirigami holdback.

        They are still different bugs: 2151847 failed because apt never
        converged on libpeas, 2155743 because of the holdback itself. Sharing
        a root package is the gate for scoring, not a verdict.
        """
        left, left_result = ingest(interner, apt="lp2151847-apt.log", main="lp2151847-main.log")
        right, right_result = ingest(interner, apt="lp2155743-apt.log", main="lp2155743-main.log")
        verdict = score_pair(
            left,
            right,
            left_result.findings,
            right_result.findings,
            interner,
            DedupConfig(),
        )
        assert "libkirigami-data" in verdict.shared_roots
        assert not verdict.duplicate

    def test_the_cluster_title_names_the_shared_cause(self, interner: Interner) -> None:
        titles = []
        for bug_id in ("2150339", "2151847", "2169028"):
            run, result = ingest(
                interner,
                apt=f"lp{bug_id}-apt.log",
                main=f"lp{bug_id}-main.log",
                bug_id=bug_id,
            )
            titles.append(propose_title(run, result, interner))
        chosen = title_for_cluster(titles)
        assert chosen is not None
        assert "libpeas-1.0-1" in chosen.title


class TestSignatureStability:
    """A signature must not depend on how it was computed.

    Signatures are persisted and compared across sessions, so anything that
    varies with the ingest order of a corpus makes them worthless.
    """

    def _signature(self, bug_id: str, interner: Interner) -> bytes | None:
        run, result = ingest(
            interner,
            apt=f"lp{bug_id}-apt.log",
            main=f"lp{bug_id}-main.log",
            bug_id=bug_id,
        )
        return build_signature(run, result.findings, interner).root_graph

    def test_independent_of_the_interner_instance(self) -> None:
        """Two logs of one bug must agree whether ingested together or apart.

        ``canonical_digest`` sorted node *indices* and emitted the names in
        that order, so the sequence followed interning order. The same pair
        hashed equal through a shared interner and unequal through two -- so a
        corpus built incrementally would never match anything.
        """
        import tempfile
        from pathlib import Path

        from uru_doctor.store import Store

        def fresh() -> Interner:
            return Interner(Store.open(Path(tempfile.mkdtemp())))

        shared = fresh()
        together = [self._signature(b, shared) for b in ("2150339", "2151847")]
        apart = [self._signature(b, fresh()) for b in ("2150339", "2151847")]

        assert together[0] == together[1]
        assert apart[0] == apart[1]
        assert together == apart

    def test_independent_of_ingest_order(self) -> None:
        import tempfile
        from pathlib import Path

        from uru_doctor.store import Store

        forward = Interner(Store.open(Path(tempfile.mkdtemp())))
        first = {b: self._signature(b, forward) for b in ("2150245", "2150339")}

        backward = Interner(Store.open(Path(tempfile.mkdtemp())))
        second = {b: self._signature(b, backward) for b in ("2150339", "2150245")}
        assert first == second

    def test_victim_order_is_independent_of_ingest_order(self) -> None:
        """Not just the signature: everything a reader sees.

        The victim *set* was already stable while its *order* was not. Cascade
        order is breadth-first from the root, which is meaningful, but the order
        within one depth was edge-storage order -- node-index order, which is
        sorted interned-id order, which is first-seen order. Reports show only
        the first dozen victims, so two people reading the same bug saw
        different packages.
        """
        import tempfile
        from pathlib import Path

        from uru_doctor.store import Store

        def victims(bug_id: str, preload: tuple[str, ...]) -> tuple[str, ...]:
            interner = Interner(Store.open(Path(tempfile.mkdtemp())))
            for other in preload:
                ingest(
                    interner,
                    apt=f"lp{other}-apt.log",
                    main=f"lp{other}-main.log",
                    bug_id=other,
                )
            run, result = ingest(
                interner,
                apt=f"lp{bug_id}-apt.log",
                main=f"lp{bug_id}-main.log",
                bug_id=bug_id,
            )
            assert result.primary is not None
            del run
            return tuple(interner.package_label(p) for p in result.primary.victim_pkgs)

        alone = victims("2150245", ())
        after_one = victims("2150245", ("2150339",))
        after_two = victims("2150245", ("2169197", "2150339"))
        assert alone == after_one == after_two
        assert alone, "expected a cascade to order"

    def test_oscillating_package_is_independent_of_ingest_order(self) -> None:
        """The livelock tie-break reached the bug title.

        ``detect_oscillations`` tie-broke equal reversal counts on ``pkg_id``.
        On LP#2150339 ``gedit`` and ``gir1.2-peas-1.0`` both reverse 19 times,
        so which one the title named depended on which was interned first.
        """
        import tempfile
        from pathlib import Path

        from uru_doctor.store import Store
        from uru_doctor.title import propose_title

        def title_of(preload: tuple[str, ...]) -> str:
            interner = Interner(Store.open(Path(tempfile.mkdtemp())))
            for other in preload:
                ingest(
                    interner,
                    apt=f"lp{other}-apt.log",
                    main=f"lp{other}-main.log",
                    bug_id=other,
                )
            run, result = ingest(
                interner,
                apt="lp2150339-apt.log",
                main="lp2150339-main.log",
                bug_id="2150339",
            )
            return propose_title(run, result, interner).title

        assert title_of(()) == title_of(("2150245",)) == title_of(("2169251", "2155743"))
        assert "gedit" in title_of(())
