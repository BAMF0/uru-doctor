"""Tests for :mod:`uru_doctor.ingest`."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from uru_doctor.apt.roots import analyse
from uru_doctor.ingest import (
    COHERENCE_SLACK_S,
    LogSet,
    check_coherence,
    discover,
    ingest_attachments,
    ingest_directory,
    is_terminal_error,
    read_log_set,
)
from uru_doctor.intern import Interner
from uru_doctor.models import Arch, Frontend, LogSource, Phase, ProblemType
from uru_doctor.parsers.apportmeta import ApportMeta, parse_apport_meta
from uru_doctor.parsers.mainlog import parse_main_log

from .conftest import FIXTURES, fixture_text


def lp_meta(bug_id: str) -> ApportMeta:
    payload = json.loads((FIXTURES / "lp" / f"bug{bug_id}.json").read_text())
    return parse_apport_meta(payload["description"], tags=payload["tags"])


def lp_run(bug_id: str, interner: Interner, *, with_main: bool = True):
    attachments = {LogSource.APT: fixture_text(f"apt/lp{bug_id}-apt.log")}
    if with_main:
        attachments[LogSource.MAIN] = fixture_text(f"logs/lp{bug_id}-main.log")
    return ingest_attachments(attachments, interner, meta=lp_meta(bug_id), bug_id=int(bug_id))


def write_logs(root: Path, **logs: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name, text in logs.items():
        (root / name.replace("__", ".").replace("_log", ".log")).write_text(text)
    return root


class TestRealBugIngest:
    @pytest.mark.parametrize(
        ("bug_id", "phase", "frontend"),
        [
            ("2150245", Phase.CALCULATE, Frontend.TEXT),
            ("2150319", Phase.PRE_DIST_UPGRADE, Frontend.TEXT),
            ("2169028", Phase.PRE_DIST_UPGRADE, Frontend.KDE),
        ],
    )
    def test_environment_is_captured(
        self, bug_id: str, phase: Phase, frontend: Frontend, interner: Interner
    ) -> None:
        run = lp_run(bug_id, interner)
        assert run.bug_id == int(bug_id)
        assert run.release_pair == "noble\u2192resolute"
        assert run.apt_version == "2.8.3"
        assert run.arch is Arch.AMD64
        assert run.problem_type is ProblemType.BUG
        assert run.terminal_phase is phase
        assert run.frontend is frontend

    def test_no_bug_reached_dpkg(self, interner: Interner) -> None:
        """All three are planning failures; nothing was written."""
        for bug_id in ("2150245", "2150319", "2169028"):
            run = lp_run(bug_id, interner)
            assert run.dpkg_wrote is False
            assert not run.reached_dpkg

    def test_warnings_are_kept_apart_from_errors(self, interner: Interner) -> None:
        run = lp_run("2150319", interner)
        assert len(run.apt_error_entries) == 1
        assert len(run.apt_warning_entries) == 1
        errors = [interner.text(e) for e in run.apt_error_entries]
        assert "pkgProblemResolver" in errors[0]
        assert all("dl.google.com" not in e for e in errors)


class TestParseOrdering:
    """The apt log must be interned before the ``Foreign`` list is resolved.

    Getting this backwards raises nothing and loses nothing visible -- it just
    quietly fails to mark anything third-party, so the ``Conflicts``
    reorientation does nothing and LP#2150245 blames the Ubuntu package its
    PPA broke. Hence the order is owned by ingest, not by callers.
    """

    def test_third_party_resolves_to_arch_qualified_names(self, interner: Interner) -> None:
        run = lp_run("2150245", interner)
        names = {interner.package_label(p) for p in run.third_party}
        assert "libwacom9-surface" in names
        # Resolution found the ``:amd64`` form the apt log uses, so the set is
        # larger than main.log's bare list.
        assert len(run.third_party) == 14

    def test_the_ppa_is_blamed_not_the_ubuntu_package(self, interner: Interner) -> None:
        run = lp_run("2150245", interner)
        report = analyse(run.graphs[0], interner, third_party=run.third_party)
        assert report.reoriented == 1
        surface = next(
            r for r in report.roots if interner.package_label(r.pkg_id) == "libwacom9-surface"
        )
        assert surface.cascade_size > 40

    def test_a_bug_with_no_foreign_packages_resolves_to_nothing(self, interner: Interner) -> None:
        assert lp_run("2169028", interner).third_party == ()


class TestEvidenceCompleteness:
    """A truncated log is the one case where naming a cause is forbidden."""

    def test_the_truncated_bug_is_flagged(self, interner: Interner) -> None:
        """LP#2169028 stops at ``Quirks.PreDistUpgradeCache``, no error, no abort."""
        run = lp_run("2169028", interner)
        assert not run.evidence_complete
        assert run.terminal_phase is Phase.PRE_DIST_UPGRADE

    def test_aborted_runs_are_complete(self, interner: Interner) -> None:
        for bug_id in ("2150245", "2150319"):
            assert lp_run(bug_id, interner).evidence_complete

    def test_a_benign_error_does_not_make_evidence_complete(self) -> None:
        """``failed to import AptClone`` is logged and the run carries on.

        Counting any ``ERROR`` as terminal marked the truncated bug as having
        complete evidence, on the strength of a missing optional module.
        """
        assert not is_terminal_error("failed to import AptClone")
        assert not is_terminal_error("failed to import apport python module, ...")
        assert not is_terminal_error("Package foo has no priority set")

    def test_an_unknown_error_is_treated_as_terminal(self) -> None:
        """Missing a real failure is worse than over-reporting a survived one."""
        assert is_terminal_error("Dist-upgrade failed: 'E:...'")
        assert is_terminal_error("something nobody has seen before")

    def test_a_screen_reexec_is_not_complete_evidence(self, interner: Interner) -> None:
        """The run continued in a different log."""
        run = ingest_attachments(
            {LogSource.MAIN: fixture_text("logs/local-main-reexec.log")}, interner
        )
        assert run.terminal_phase is Phase.SCREEN_REEXEC
        assert not run.evidence_complete

    def test_a_successful_run_is_complete(self, interner: Interner) -> None:
        run = ingest_attachments({LogSource.MAIN: fixture_text("logs/local-main.log")}, interner)
        assert run.terminal_phase is Phase.POST_INSTALL_SCRIPTS
        assert run.evidence_complete


class TestBrokenCounts:
    """Three different numbers, kept distinct on purpose."""

    def test_apt_count_and_observed_set_differ(self, interner: Interner) -> None:
        """apt counts at a pass boundary; we count every package ever broken.

        For LP#2150245 apt says 22 and 434 packages carry a broken bit at some
        point, because the resolver breaks and re-fixes as it explores.
        Reporting either as the other would be confident nonsense.
        """
        run = lp_run("2150245", interner)
        assert run.apt_broken_count == 22
        assert run.counts.broken == 434

    def test_the_graph_is_not_all_broken(self, interner: Interner) -> None:
        """The graph holds blamers and candidates too.

        Treating every node as broken reported 964 broken packages for this
        bug.
        """
        run = lp_run("2150245", interner)
        assert len(run.graphs[0].nodes.ids) == 964
        assert run.counts.broken < len(run.graphs[0].nodes.ids)

    def test_counts_match_the_packed_ids(self, interner: Interner) -> None:
        run = lp_run("2150245", interner)
        assert len(run.pkgs.ids("broken")) == run.counts.broken

    @pytest.mark.parametrize(
        ("bug_id", "apt_says"), [("2150245", 22), ("2150319", 16), ("2169028", 7)]
    )
    def test_apt_counts_match_the_logs(
        self, bug_id: str, apt_says: int, interner: Interner
    ) -> None:
        assert lp_run(bug_id, interner).apt_broken_count == apt_says


class TestCoherence:
    """``/var/log/dist-upgrade`` is archived wholesale, so one directory can
    hold logs from unrelated runs.

    The directory name is the moment of *archiving*, not of the run.
    """

    def test_logs_from_a_different_run_are_rejected(self, interner: Interner) -> None:
        main_text = (
            "2026-06-23 11:09:38,989 INFO release-upgrader version '26.10.2' started\n"
            "2026-06-23 11:09:39,328 INFO re-exec inside screen: '[...]'\n"
        )
        # An apt log from five months earlier, as really found on disk.
        log_set = LogSet(
            texts={
                LogSource.MAIN: main_text,
                LogSource.APT: "Log time: 2026-01-16 13:17:13.800118\n",
            }
        )
        main = parse_main_log(main_text.splitlines(), interner)
        stale = check_coherence(log_set, main)
        assert LogSource.APT in stale
        assert stale[LogSource.APT] == datetime(2026, 1, 16, 13, 17, 13)

    def test_logs_from_the_same_run_are_kept(self, interner: Interner) -> None:
        main_text = (
            "2026-06-23 11:09:39,397 INFO apt version: '3.2.0'\n"
            "2026-06-23 11:28:43,823 DEBUG running Quirks.PostCleanup\n"
        )
        log_set = LogSet(
            texts={
                LogSource.MAIN: main_text,
                LogSource.APT: "Log time: 2026-06-23 11:09:40.123456\n",
            }
        )
        main = parse_main_log(main_text.splitlines(), interner)
        assert check_coherence(log_set, main) == {}

    def test_slack_tolerates_jitter(self, interner: Interner) -> None:
        """A log starting shortly before main.log is the same run."""
        main_text = "2026-06-23 11:10:00,000 INFO apt version: '3.2.0'\n"
        log_set = LogSet(
            texts={
                LogSource.MAIN: main_text,
                LogSource.APT: "Log time: 2026-06-23 11:05:00.000000\n",
            }
        )
        main = parse_main_log(main_text.splitlines(), interner)
        assert check_coherence(log_set, main) == {}
        assert COHERENCE_SLACK_S >= 300

    def test_no_main_log_means_no_judgement(self, interner: Interner) -> None:
        """Unable to prove they belong is not proof that they do not."""
        log_set = LogSet(texts={LogSource.APT: "Log time: 2020-01-01 00:00:00.0\n"})
        main = parse_main_log([], interner)
        assert check_coherence(log_set, main) == {}

    def test_rejected_logs_are_dropped_from_the_run(self, interner: Interner) -> None:
        run = ingest_attachments(
            {
                LogSource.MAIN: (
                    "2026-06-23 11:09:38,989 INFO release-upgrader version '26.10.2' started\n"
                ),
                LogSource.APT: "Log time: 2026-01-16 13:17:13.800118\n",
            },
            interner,
        )
        assert LogSource.APT not in run.logs_present
        assert run.graphs == ()


class TestDirectoryDiscovery:
    def test_attempts_are_numbered_newest_first(self, tmp_path: Path) -> None:
        (tmp_path / "main.log").write_text("2026-06-23 11:00:00,000 INFO x\n")
        for name in ("20260116-1315", "20260623-1109"):
            sub = tmp_path / name
            sub.mkdir()
            (sub / "main.log").write_text("2026-01-16 13:15:00,000 INFO x\n")

        found = list(discover(tmp_path))
        assert [attempt for attempt, _ in found] == [0, 1, 2]
        assert found[1][1].name == "20260623-1109"
        assert found[2][1].name == "20260116-1315"

    def test_non_timestamp_directories_are_ignored(self, tmp_path: Path) -> None:
        (tmp_path / "main.log").write_text("2026-06-23 11:00:00,000 INFO x\n")
        (tmp_path / "backup").mkdir()
        (tmp_path / "backup" / "main.log").write_text("x\n")
        assert [a for a, _ in discover(tmp_path)] == [0]

    def test_a_directory_with_no_logs_yields_nothing(self, tmp_path: Path) -> None:
        (tmp_path / "unrelated.txt").write_text("x\n")
        assert list(discover(tmp_path)) == []

    def test_a_missing_directory_yields_nothing(self, tmp_path: Path) -> None:
        assert list(discover(tmp_path / "nope")) == []

    def test_the_top_level_attempt_is_primary(self, tmp_path: Path, interner: Interner) -> None:
        (tmp_path / "main.log").write_text("2026-06-23 11:00:00,000 INFO apt version: '3.2.0'\n")
        sub = tmp_path / "20260116-1315"
        sub.mkdir()
        (sub / "main.log").write_text("2026-01-16 13:15:00,000 INFO apt version: '3.1.0'\n")

        result = ingest_directory(tmp_path, interner)
        assert len(result.runs) == 2
        primary = result.primary
        assert primary is not None
        assert primary.attempt == 0
        assert primary.apt_version == "3.2.0"

    def test_an_empty_log_is_still_recorded_as_present(self, tmp_path: Path) -> None:
        """An existing but empty log is evidence in itself."""
        (tmp_path / "main.log").write_text("2026-06-23 11:00:00,000 INFO x\n")
        (tmp_path / "apt-term.log").write_text("")
        log_set = read_log_set(tmp_path)
        assert log_set.has(LogSource.APT_TERM)
        assert log_set.texts[LogSource.APT_TERM].strip() == ""


class TestDpkgDetermination:
    """Whether packages were written cannot be read off which files exist."""

    def test_an_empty_apt_term_means_nothing_was_written(self, interner: Interner) -> None:
        run = ingest_attachments(
            {
                LogSource.MAIN: "2026-01-01 10:00:00,000 INFO apt version: '3.2.0'\n",
                LogSource.APT_TERM: (
                    "\nLog started: 2026-01-01  10:00:01\nLog ended: 2026-01-01  10:00:02\n"
                ),
            },
            interner,
        )
        assert run.dpkg_wrote is False

    def test_a_non_empty_block_means_dpkg_ran(self, interner: Interner) -> None:
        run = ingest_attachments(
            {
                LogSource.MAIN: "2026-01-01 10:00:00,000 INFO apt version: '3.2.0'\n",
                LogSource.APT_TERM: (
                    "Log started: 2026-01-01  10:00:01\n"
                    "Setting up foo (1.0) ...\n"
                    "Log ended: 2026-01-01  10:00:02\n"
                ),
            },
            interner,
        )
        assert run.dpkg_wrote is True

    def test_absence_of_both_logs_means_nothing_was_written(self, interner: Interner) -> None:
        """The only safe inference from absence."""
        run = ingest_attachments(
            {LogSource.MAIN: "2026-01-01 10:00:00,000 INFO apt version: '3.2.0'\n"},
            interner,
        )
        assert run.dpkg_wrote is False

    def test_metadata_can_settle_it_without_the_log(self, interner: Interner) -> None:
        """LP#2150319 declares both dpkg logs as empty keys in its description."""
        meta = lp_meta("2150319")
        assert meta.dpkg_produced_no_output
        run = ingest_attachments(
            {LogSource.HISTORY: "\nStart-Date: 2026-04-25  10:49:00\n"},
            interner,
            meta=meta,
        )
        assert run.dpkg_wrote is False


class TestFieldSafety:
    def test_unknown_fields_are_rejected(self) -> None:
        """pydantic's default would drop a typo'd field in silence.

        It did exactly that to the third-party package set, with no complaint
        from pydantic or mypy, and the only symptom was a worse diagnosis.
        """
        from pydantic import ValidationError

        from uru_doctor.models import UpgradeRun

        with pytest.raises(ValidationError):
            UpgradeRun(third_partee=(1, 2, 3))  # type: ignore[call-arg]

    def test_the_third_party_field_exists(self) -> None:
        from uru_doctor.models import UpgradeRun

        assert "third_party" in UpgradeRun.model_fields
