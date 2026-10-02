# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for :mod:`uru_doctor.cli`.

Driven through Typer's ``CliRunner`` rather than by calling the command
functions, because most of what can go wrong here is in the wiring: an exit
code that does not match the failure, a message on stdout that corrupts a
redirected report, a store opened in the wrong place.

Exit codes are asserted everywhere. They are the part of a CLI that scripts
depend on and the part a human never notices is wrong.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from uru_doctor.cli import EXIT_FAIL, EXIT_IMPERFECT, EXIT_OK, EXIT_USAGE, app

from .conftest import FIXTURES, fixture_text

runner = CliRunner()

#: Bugs with both logs recorded, laid out on disk as the upgrader writes them.
LAID_OUT = ("2150245", "2150319", "2150339", "2151847", "2155743", "2169028")


def _layout(root: Path, bug_id: str) -> Path:
    """Write one bug's fixtures into a dist-upgrade-shaped directory.

    The on-disk filenames differ from the apport attachment titles, and
    ``ingest_directory`` keys off the on-disk ones, so the test has to use
    those rather than the fixture names.
    """
    directory = root / bug_id
    directory.mkdir(parents=True, exist_ok=True)
    for relative, filename in (
        (f"apt/lp{bug_id}-apt.log", "apt.log"),
        (f"logs/lp{bug_id}-main.log", "main.log"),
        (f"logs/lp{bug_id}-aptterm.log", "apt-term.log"),
        (f"logs/lp{bug_id}-history.log", "history.log"),
    ):
        source = FIXTURES / relative
        if source.is_file():
            (directory / filename).write_text(source.read_text())
    return directory


@pytest.fixture
def logs(tmp_path: Path) -> Path:
    """One laid-out bug directory."""
    return _layout(tmp_path / "logs", "2150245")


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    """Several laid-out bug directories, including the libpeas trio."""
    root = tmp_path / "corpus"
    for bug_id in LAID_OUT:
        _layout(root, bug_id)
    return root


@pytest.fixture
def ingested(tmp_path: Path, corpus: Path) -> Path:
    """A populated store, with the working directory set beside it."""
    state = tmp_path / "state"
    result = runner.invoke(
        app,
        ["ingest", *[str(p) for p in sorted(corpus.iterdir())], "--config", _conf(tmp_path, state)],
    )
    assert result.exit_code == EXIT_OK, result.output
    return state


def _conf(tmp_path: Path, state: Path) -> str:
    """Write a config pointing the store somewhere disposable."""
    path = tmp_path / "uru-doctor.toml"
    path.write_text(f'[paths]\nstate_dir = "{state}"\n')
    return str(path)


class TestTopLevel:
    def test_version(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == EXIT_OK
        assert "uru-doctor" in result.output

    def test_bare_invocation_shows_help(self) -> None:
        """No arguments must explain itself rather than do something."""
        result = runner.invoke(app, [])
        assert "diagnose" in result.output
        assert "dedup" in result.output

    def test_every_command_has_help(self) -> None:
        for command in ("diagnose", "title", "ingest", "dedup", "show", "rules", "stats"):
            result = runner.invoke(app, [command, "--help"])
            assert result.exit_code == EXIT_OK, command
            assert result.output.strip(), command


class TestDiagnose:
    def test_names_the_cause(self, logs: Path) -> None:
        result = runner.invoke(app, ["diagnose", str(logs)])
        assert result.exit_code == EXIT_OK, result.output
        assert "libwacom9-surface" in result.output
        assert "third_party_pin" in result.output

    def test_markdown(self, logs: Path) -> None:
        result = runner.invoke(app, ["diagnose", str(logs), "--markdown"])
        assert result.exit_code == EXIT_OK
        assert result.stdout.startswith("# ")
        assert "## Diagnosis" in result.stdout

    def test_json_is_valid_and_labels_both_broken_counts(self, logs: Path) -> None:
        """A consumer must not be able to mistake one broken count for the other."""
        result = runner.invoke(app, ["diagnose", str(logs), "--json"])
        assert result.exit_code == EXIT_OK
        payload = json.loads(result.stdout)
        assert payload["cause"] == "third_party_pin"
        assert payload["root_packages"] == ["libwacom9-surface"]
        assert payload["apt_broken_count"] != payload["observed_broken_count"]
        assert "broken" not in payload  # never an unqualified one

    def test_json_has_no_unlabelled_interned_ids(self, logs: Path) -> None:
        """The record must survive leaving the machine that made it.

        Interned integers and packed byte arrays are meaningless without the
        store that produced them, so the exported record carries names.
        """
        payload = json.loads(runner.invoke(app, ["diagnose", str(logs), "--json"]).stdout)
        for name in payload["root_packages"]:
            assert isinstance(name, str)
            assert not name.isdigit()

    def test_markdown_and_json_are_mutually_exclusive(self, logs: Path) -> None:
        result = runner.invoke(app, ["diagnose", str(logs), "--markdown", "--json"])
        assert result.exit_code == EXIT_USAGE

    def test_out_writes_a_file(self, logs: Path, tmp_path: Path) -> None:
        target = tmp_path / "nested" / "report.md"
        result = runner.invoke(app, ["diagnose", str(logs), "-m", "-o", str(target)])
        assert result.exit_code == EXIT_OK
        assert target.read_text().startswith("# ")

    def test_missing_path(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["diagnose", str(tmp_path / "nope")])
        assert result.exit_code == EXIT_FAIL
        assert "no such path" in result.output

    def test_file_instead_of_directory(self, tmp_path: Path) -> None:
        target = tmp_path / "apt.log"
        target.write_text("hello")
        result = runner.invoke(app, ["diagnose", str(target)])
        assert result.exit_code == EXIT_FAIL
        assert "not a directory" in result.output

    def test_directory_with_no_logs_says_what_it_wanted(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        result = runner.invoke(app, ["diagnose", str(empty)])
        assert result.exit_code == EXIT_FAIL
        assert "main.log" in result.output and "apt.log" in result.output

    def test_leaves_no_state_behind(self, logs: Path, tmp_path: Path) -> None:
        """A question must not create a store in the working directory.

        Interning is a write, but that is the tool's problem, not the user's.
        """
        workdir = tmp_path / "cwd"
        workdir.mkdir()
        previous = Path.cwd()
        try:
            os.chdir(workdir)
            assert runner.invoke(app, ["diagnose", str(logs)]).exit_code == EXIT_OK
        finally:
            os.chdir(previous)
        assert list(workdir.iterdir()) == []

    def test_all_attempts_reports_archived_runs(self, tmp_path: Path) -> None:
        root = _layout(tmp_path / "multi", "2150245")
        archived = root / "20260623-1109"
        archived.mkdir()
        (archived / "main.log").write_text(fixture_text("logs/lp2150339-main.log"))
        (archived / "apt.log").write_text(fixture_text("apt/lp2150339-apt.log"))

        one = runner.invoke(app, ["diagnose", str(root)])
        many = runner.invoke(app, ["diagnose", str(root), "--all-attempts"])
        assert one.exit_code == many.exit_code == EXIT_OK
        assert "archived attempt" not in one.output
        assert "archived attempt 1" in many.output


class TestStrict:
    """``--strict`` separates "could not read it" from "could not explain it"."""

    def test_clean_logs_exit_zero(self, logs: Path) -> None:
        result = runner.invoke(app, ["diagnose", str(logs), "--strict"])
        assert result.exit_code == EXIT_OK, result.output

    def test_unparseable_line_exits_three(self, tmp_path: Path) -> None:
        root = tmp_path / "dirty"
        root.mkdir()
        (root / "main.log").write_text(fixture_text("logs/lp2150339-main.log"))
        apt = fixture_text("apt/lp2150339-apt.log").splitlines()[:200]
        apt.append("Blorp Fnord gibberish that no grammar matches")
        (root / "apt.log").write_text("\n".join(apt) + "\n")

        lenient = runner.invoke(app, ["diagnose", str(root)])
        strict = runner.invoke(app, ["diagnose", str(root), "--strict"])
        assert lenient.exit_code == EXIT_OK
        assert strict.exit_code == EXIT_IMPERFECT
        assert "imperfect parse" in strict.output
        # The distinction is the point: the diagnosis is not withdrawn.
        assert "may still be correct" in strict.output


class TestTitle:
    def test_prints_one_line_on_stdout(self, logs: Path) -> None:
        result = runner.invoke(app, ["title", str(logs)])
        assert result.exit_code == EXIT_OK
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        assert len(lines) == 1
        assert lines[0].startswith("noble→resolute: ")

    def test_low_confidence_warns_off_stdout(self, tmp_path: Path) -> None:
        """The warning must not pollute a piped title."""
        root = tmp_path / "partial"
        root.mkdir()
        (root / "apt.log").write_text(fixture_text("apt/lp2169028-apt.log"))
        (root / "main.log").write_text(fixture_text("logs/lp2169028-main.log"))
        result = runner.invoke(app, ["title", str(root)])
        assert result.exit_code == EXIT_OK
        assert len([x for x in result.stdout.splitlines() if x.strip()]) == 1


class TestIngestAndQuery:
    def test_ingest_then_stats(self, ingested: Path, tmp_path: Path) -> None:
        result = runner.invoke(app, ["stats", "--config", _conf(tmp_path, ingested)])
        assert result.exit_code == EXIT_OK, result.output
        assert "runs" in result.output
        assert "causes" in result.output

    def test_local_directories_report_no_bugs(self, ingested: Path, tmp_path: Path) -> None:
        """A store of local directories has no bug ids, and must say zero.

        ``stats`` built a Python set over the raw column, which counts ``None``
        as a member, so a store holding nothing but directories claimed one bug.
        """
        result = runner.invoke(app, ["stats", "--config", _conf(tmp_path, ingested)])
        assert "bugs" in result.output
        line = next(x for x in result.output.splitlines() if x.strip().startswith("bugs"))
        assert line.split()[-1] == "0"

    def test_blamed_packages_are_labelled_not_keyed(self, ingested: Path, tmp_path: Path) -> None:
        """The store keeps ``name:arch``; a human wants ``name``."""
        result = runner.invoke(app, ["stats", "--config", _conf(tmp_path, ingested)])
        assert ":amd64" not in result.output

    def test_dedup_finds_the_known_cluster(self, ingested: Path, tmp_path: Path) -> None:
        result = runner.invoke(app, ["dedup", "--config", _conf(tmp_path, ingested)])
        assert result.exit_code == EXIT_OK, result.output
        assert "root-graph" in result.output
        # The libpeas trio: three bugs, one fault.
        assert "2150339" in result.output
        assert "2151847" in result.output

    def test_dedup_always_states_the_tier(self, ingested: Path, tmp_path: Path) -> None:
        """Tiers are not equally strong and must never be flattened."""
        result = runner.invoke(app, ["dedup", "--config", _conf(tmp_path, ingested)])
        assert "tier" in result.output

    def test_dedup_markdown(self, ingested: Path, tmp_path: Path) -> None:
        result = runner.invoke(app, ["dedup", "-m", "--config", _conf(tmp_path, ingested)])
        assert result.exit_code == EXIT_OK
        assert result.stdout.startswith("# Upgrade failure digest")

    def test_dedup_on_empty_store_reports_once(self, tmp_path: Path) -> None:
        """The double-report regression.

        ``typer.Exit`` subclasses ``RuntimeError``, so the store's
        schema-version handler caught every deliberate exit and re-reported it
        as ``error: 1`` beneath the real message.
        """
        state = tmp_path / "empty-state"
        result = runner.invoke(app, ["dedup", "--config", _conf(tmp_path, state)])
        assert result.exit_code == EXIT_FAIL
        assert result.output.count("error:") == 1
        assert "store is empty" in result.output

    def test_show_a_stored_run(self, ingested: Path, tmp_path: Path, corpus: Path) -> None:
        key = f"dir:{corpus / '2150245'}#0"
        result = runner.invoke(app, ["show", key, "--config", _conf(tmp_path, ingested)])
        assert result.exit_code == EXIT_OK, result.output
        assert result.stdout.startswith("# ")
        assert "libwacom9-surface" in result.stdout

    def test_show_unknown_key_lists_known_ones(self, ingested: Path, tmp_path: Path) -> None:
        result = runner.invoke(app, ["show", "lp:9999999#0", "--config", _conf(tmp_path, ingested)])
        assert result.exit_code == EXIT_FAIL
        assert "known keys" in result.output

    def test_ingest_is_idempotent_on_the_same_key(
        self, ingested: Path, tmp_path: Path, corpus: Path
    ) -> None:
        """Re-ingesting replaces rather than duplicates."""
        config = _conf(tmp_path, ingested)
        before = runner.invoke(app, ["stats", "--config", config]).output
        again = runner.invoke(app, ["ingest", str(corpus / "2150245"), "--config", config])
        assert again.exit_code == EXIT_OK
        after = runner.invoke(app, ["stats", "--config", config]).output
        runs_before = next(x for x in before.splitlines() if x.strip().startswith("runs"))
        runs_after = next(x for x in after.splitlines() if x.strip().startswith("runs"))
        assert runs_before == runs_after


class TestRules:
    def test_lists_every_rule(self) -> None:
        result = runner.invoke(app, ["rules"])
        assert result.exit_code == EXIT_OK
        assert "resolver.livelock" in result.output
        assert "evidence.truncated" in result.output

    def test_explain(self) -> None:
        result = runner.invoke(app, ["rules", "--explain", "resolver.livelock"])
        assert result.exit_code == EXIT_OK
        assert "resolver_livelock" in result.output
        # Provenance is the point: a reader must be able to check the claim.
        assert "livelock" in result.output.lower()

    def test_explain_unknown_rule(self) -> None:
        result = runner.invoke(app, ["rules", "--explain", "nope"])
        assert result.exit_code == EXIT_FAIL
        assert "no such rule" in result.output


class TestConfig:
    def test_missing_config_file(self, logs: Path) -> None:
        result = runner.invoke(app, ["diagnose", str(logs), "--config", "/no/such.toml"])
        assert result.exit_code == EXIT_FAIL
        assert "no such config file" in result.output

    def test_unknown_config_key_is_rejected(self, tmp_path: Path, logs: Path) -> None:
        """Config models forbid extras, so a typo must not be silently ignored."""
        path = tmp_path / "bad.toml"
        path.write_text('[paths]\nstate_dirr = "x"\n')
        result = runner.invoke(app, ["diagnose", str(logs), "--config", str(path)])
        assert result.exit_code == EXIT_FAIL
        assert "invalid config" in result.output

    def test_report_config_is_honoured(self, tmp_path: Path, logs: Path) -> None:
        path = tmp_path / "capped.toml"
        path.write_text("[report]\nmax_cascade_shown = 2\n")
        result = runner.invoke(app, ["diagnose", str(logs), "-m", "--config", str(path)])
        assert result.exit_code == EXIT_OK
        assert "and 48 more" in result.stdout

    def test_title_length_is_honoured(self, tmp_path: Path, logs: Path) -> None:
        path = tmp_path / "short.toml"
        path.write_text("[title]\nmax_length = 48\n")
        result = runner.invoke(app, ["title", str(logs), "--config", str(path)])
        assert result.exit_code == EXIT_OK
        assert len(result.stdout.strip()) <= 48


class TestSuccessfulUpgrade:
    """The case that matters most for trust.

    Anyone evaluating this tool points it at their own machine first, where
    the upgrade worked. A successful resolve is not a quiet one -- apt breaks
    and repairs packages as it searches -- so without a positive finding for
    "nothing went wrong", the largest piece of that transient churn became the
    answer. It reported ``libqt5core5t64 could not be resolved`` about an
    upgrade that had completed days earlier.
    """

    def _successful(self, tmp_path: Path) -> Path:
        """LP#2169251 completed its upgrade; strip the post-install failure.

        What remains is a log of a successful upgrade whose resolver trace
        still contains real holdbacks and unsatisfiable virtuals.
        """
        root = tmp_path / "ok"
        root.mkdir()
        main = [
            line
            for line in fixture_text("logs/lp2169251-main.log").splitlines()
            if "ERROR" not in line
        ]
        (root / "main.log").write_text("\n".join(main) + "\n")
        (root / "apt.log").write_text(fixture_text("apt/lp2169251-apt.log"))
        (root / "history.log").write_text(fixture_text("logs/lp2169251-history.log"))
        (root / "apt-term.log").write_text(fixture_text("logs/lp2169251-aptterm.log"))
        return root

    def test_reports_success_not_a_resolver_root(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["diagnose", str(self._successful(tmp_path)), "--json"])
        assert result.exit_code == EXIT_OK, result.output
        payload = json.loads(result.stdout)
        assert payload["cause"] == "upgrade_succeeded"
        assert payload["upgrade_completed"] is True

    def test_title_does_not_invent_a_failure(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["title", str(self._successful(tmp_path))])
        assert result.exit_code == EXIT_OK
        assert "could not be resolved" not in result.stdout
        assert "no error" in result.stdout

    def test_real_failures_still_win(self, tmp_path: Path) -> None:
        """The success rule must stay silent when anything actually failed.

        LP#2169251 as recorded completed its upgrade *and* failed a
        post-install script. The failure is the answer.
        """
        root = _layout(tmp_path / "broken", "2169251")
        payload = json.loads(runner.invoke(app, ["diagnose", str(root), "--json"]).stdout)
        assert payload["cause"] == "post_install_script_error"


class TestRedaction:
    """Logs read from disk must be redacted, like logs fetched from the web.

    They were not. ``read_log_set`` passed ``redacted=False`` with no comment,
    while ``lp/read.py`` used the redacting default and ``IngestConfig.redact``
    claimed to be on. The record is persisted and the Markdown report quotes
    log lines verbatim for pasting into a public bug, so whether a hostname
    reached the page depended only on whether some finding happened to match
    ``uname information:``.
    """

    def _with_pii(self, tmp_path: Path) -> Path:
        root = tmp_path / "pii"
        root.mkdir()
        main = fixture_text("logs/lp2150245-main.log").replace("redacted-host", "secret-laptop")
        assert "secret-laptop" in main
        (root / "main.log").write_text(main)
        (root / "apt.log").write_text(fixture_text("apt/lp2150245-apt.log"))
        return root

    def test_markdown_report_carries_no_hostname(self, tmp_path: Path) -> None:
        root = self._with_pii(tmp_path)
        result = runner.invoke(app, ["diagnose", str(root), "--markdown"])
        assert result.exit_code == EXIT_OK, result.output
        assert "secret-laptop" not in result.stdout

    def test_redaction_can_be_turned_off_deliberately(self, tmp_path: Path) -> None:
        """Off is a choice, not a default."""
        root = self._with_pii(tmp_path)
        path = tmp_path / "raw.toml"
        path.write_text("[ingest]\nredact = false\n")
        with_redaction = runner.invoke(app, ["diagnose", str(root), "--json"])
        without = runner.invoke(app, ["diagnose", str(root), "--json", "--config", str(path)])
        assert with_redaction.exit_code == without.exit_code == EXIT_OK
        # The diagnosis is unaffected either way; only the PII differs.
        assert json.loads(with_redaction.stdout)["cause"] == (json.loads(without.stdout)["cause"])

    def test_redaction_does_not_damage_the_evidence(self, tmp_path: Path) -> None:
        """Redaction must not cost coverage or lose the release pair."""
        root = self._with_pii(tmp_path)
        payload = json.loads(runner.invoke(app, ["diagnose", str(root), "--json"]).stdout)
        assert payload["from_series"] == "noble"
        assert payload["to_series"] == "resolute"
        assert payload["cause"] == "third_party_pin"
        strict = runner.invoke(app, ["diagnose", str(root), "--strict"])
        assert strict.exit_code == EXIT_OK
