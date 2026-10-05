# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for :mod:`uru_doctor_cli.cli`.

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
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from conftest import FIXTURES, fixture_text
from typer.testing import CliRunner
from uru_doctor_cli.cli import EXIT_FAIL, EXIT_IMPERFECT, EXIT_OK, EXIT_USAGE, app

from uru_doctor.models import UpgradeRun
from uru_doctor.store import Store

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


#: Bug ids used by the ``swept`` fixture.
#:
#: Three bugs served identical logs, so they diagnose identically and cluster
#: at ``root-graph`` tier. That is what the worklist's strongest proposal is
#: made of, and building it from a sweep rather than by hand means the
#: classification runs over real diagnoses carrying real bug numbers -- which
#: an ``ingest`` of directories cannot provide, because those runs have no bug
#: id to join Launchpad state to.
SWEPT = (2150339, 2151847, 2169028)


@pytest.fixture
def swept(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A store of Launchpad-numbered runs, collected through a mock transport."""
    apt = fixture_text("apt/lp2150339-apt.log")
    main = fixture_text("logs/lp2150339-main.log")
    api = "https://api.launchpad.net/devel"

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "searchTasks" in url:
            return httpx.Response(
                200,
                json={
                    "entries": [
                        {
                            "bug_link": f"{api}/bugs/{bug_id}",
                            "status": "New",
                            "date_created": "2026-09-29T10:00:00+00:00",
                            "title": f"Bug #{bug_id}",
                        }
                        for bug_id in SWEPT
                    ]
                },
            )
        if "+attachment" in url:
            return httpx.Response(
                200, content=(main if url.endswith("/1/data") else apt).encode()
            )
        if url.endswith("/attachments"):
            bug_id = int(url.rsplit("/", 2)[-2])
            return httpx.Response(
                200,
                json={
                    "entries": [
                        {
                            "title": "VarLogDistupgradeAptlog.txt",
                            "data_link": f"{api}/bugs/{bug_id}/+attachment/0/data",
                        },
                        {
                            "title": "VarLogDistupgradeMainlog.txt",
                            "data_link": f"{api}/bugs/{bug_id}/+attachment/1/data",
                        },
                    ]
                },
            )
        if "/bugs/" in url:
            bug_id = int(url.rsplit("/", 1)[-1])
            return httpx.Response(
                200,
                json={
                    "id": bug_id,
                    "title": "upgrade failed",
                    "description": "ProblemType: Bug\n",
                    "tags": [],
                    "number_of_duplicates": 0,
                    "date_created": "2026-09-29T10:00:00+00:00",
                },
            )
        return httpx.Response(404)

    _patch_launchpad(monkeypatch, httpx.MockTransport(handler))
    state = tmp_path / "swept-state"
    result = runner.invoke(app, ["sweep", "--config", _conf(tmp_path, state)])
    assert result.exit_code == EXIT_OK, result.output
    # A sweep legitimately records each bug's status from the search, and
    # re-seeding would put it back anyway, so the statuses stay. Only the
    # watermark is cleared, so that a refresh in a test takes a predictable
    # path rather than depending on when the sweep happened.
    with Store.open(state) as store:
        store._conn.execute("DELETE FROM meta WHERE key = 'status_watermark'")
        store.commit()
    return state


def _patch_launchpad(
    monkeypatch: pytest.MonkeyPatch, transport: httpx.MockTransport
) -> None:
    """Make every Launchpad client the CLI builds use the mock transport.

    Patching ``__post_init__`` rather than injecting a client is what makes
    this work for commands that construct their own: the suite must not touch
    the network, and a test that forgets to pass a client would silently reach
    the live API.
    """
    import uru_doctor_cli.lp as lp

    original = lp.Launchpad.__post_init__

    def post_init(self: lp.Launchpad) -> None:
        original(self)
        self.client = httpx.Client(transport=transport, follow_redirects=True)
        self.sleep = lambda _s: None
        object.__setattr__(
            self, "config", self.config.model_copy(update={"min_interval_s": 0.0})
        )

    monkeypatch.setattr(lp.Launchpad, "__post_init__", post_init)


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
        for command in (
            "diagnose",
            "title",
            "ingest",
            "dedup",
            "related",
            "history",
            "coverage",
            "show",
            "rules",
            "stats",
        ):
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
        """The default is the verdict table, as fetch and sweep print it."""
        key = f"dir:{corpus / '2150245'}#0"
        result = runner.invoke(app, ["show", key, "--config", _conf(tmp_path, ingested)])
        assert result.exit_code == EXIT_OK, result.output
        assert "proposed title" in result.stdout
        assert "libwacom9-surface" in result.stdout

    def test_show_renders_markdown_on_request(
        self, ingested: Path, tmp_path: Path, corpus: Path
    ) -> None:
        key = f"dir:{corpus / '2150245'}#0"
        result = runner.invoke(
            app, ["show", key, "--markdown", "--config", _conf(tmp_path, ingested)]
        )
        assert result.exit_code == EXIT_OK, result.output
        assert result.stdout.startswith("# ")
        assert "libwacom9-surface" in result.stdout

    def test_show_refuses_two_formats(self, ingested: Path, tmp_path: Path, corpus: Path) -> None:
        """Resolving the conflict by precedence would ignore an explicit flag."""
        key = f"dir:{corpus / '2150245'}#0"
        result = runner.invoke(
            app, ["show", key, "--table", "--markdown", "--config", _conf(tmp_path, ingested)]
        )
        assert result.exit_code == EXIT_USAGE
        assert "pass one" in result.output

    def test_show_table_matches_what_diagnose_printed(
        self, ingested: Path, tmp_path: Path, corpus: Path
    ) -> None:
        """The whole point of the table: it is the same verdict, re-read.

        ``corroborated`` and ``notes`` are not persisted, so a result rebuilt
        from stored findings alone silently drops the "corroborated by apt"
        qualifier and every withheld-rule note. Comparing against ``diagnose``,
        which never touches the store, is what catches that regression.
        """
        fresh = runner.invoke(app, ["diagnose", str(corpus / "2150245")])
        assert fresh.exit_code == EXIT_OK, fresh.output
        key = f"dir:{corpus / '2150245'}#0"
        stored = runner.invoke(app, ["show", key, "--config", _conf(tmp_path, ingested)])
        assert stored.exit_code == EXIT_OK, stored.output

        def rows(text: str) -> list[str]:
            keep = ("cause", "confidence", "blast radius", "fragile", "evidence", "note:")
            return [
                " ".join(line.split())
                for line in text.splitlines()
                if line.strip().startswith(keep)
            ]

        assert rows(stored.stdout) == rows(fresh.stdout)
        assert rows(stored.stdout)

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


class TestRecordContract:
    """The ``--json`` record is an interface, so its shape is pinned.

    A consumer reading a renamed field sees absence, not an error -- the same
    failure ``extra="forbid"`` prevents on the way in. Pinning the key set
    means a field cannot be dropped or renamed without someone deciding to.
    """

    #: Every key the record promises. Adding one is a deliberate edit here.
    EXPECTED: frozenset[str] = frozenset(
        {
            "schema",
            "key",
            "bug_id",
            "attempt",
            "from_series",
            "to_series",
            "title",
            "title_confident",
            "cause",
            "severity",
            "confidence",
            "root_packages",
            "cascade_size",
            "fragile",
            "candidate_invalid",
            "corroborated",
            "terminal_phase",
            "evidence_complete",
            "dpkg_wrote",
            "upgrade_completed",
            "logs_present",
            "apt_broken_count",
            "observed_broken_count",
            "rules_fired",
            "rules_withheld",
            "notes",
            "lex_lines",
            "lex_unmatched",
            "lex_coverage",
            "unknown_shapes",
            "tool_version",
            "rules_digest",
            "reported_at",
            "duplicate_of",
            "duplicate_count",
            "signature",
        }
    )

    def test_key_set_is_exactly_as_promised(self, logs: Path) -> None:
        payload = json.loads(runner.invoke(app, ["diagnose", str(logs), "--json"]).stdout)
        assert set(payload) == self.EXPECTED

    def test_schema_version_is_present_and_an_integer(self, logs: Path) -> None:
        """A consumer must be able to refuse a record it predates."""
        payload = json.loads(runner.invoke(app, ["diagnose", str(logs), "--json"]).stdout)
        assert isinstance(payload["schema"], int)
        assert payload["schema"] >= 1

    def test_coverage_is_in_the_record(self, logs: Path) -> None:
        """Gate 1 of the triage procedure has to be reachable from a script.

        The terminal output reported coverage and the JSON did not, so a human
        could tell a partial parse from a complete one and a script could not.
        Every agent and cron job driving this reads the record, which made the
        tool's most important self-check the one thing automation could not
        see.
        """
        payload = json.loads(runner.invoke(app, ["diagnose", str(logs), "--json"]).stdout)
        assert payload["lex_lines"] > 0
        assert payload["lex_unmatched"] == 0
        assert payload["lex_coverage"] == 1.0
        assert payload["unknown_shapes"] == []

    def test_imperfect_parse_is_visible_in_the_record(self, tmp_path: Path) -> None:
        """And the masked shape is named, so the gap can be fixed from it."""
        root = tmp_path / "dirty"
        root.mkdir()
        (root / "main.log").write_text(fixture_text("logs/lp2150339-main.log"))
        apt = fixture_text("apt/lp2150339-apt.log").splitlines()[:200]
        apt.append("Blorp Fnord gibberish that no grammar matches")
        (root / "apt.log").write_text("\n".join(apt) + "\n")

        payload = json.loads(runner.invoke(app, ["diagnose", str(root), "--json"]).stdout)
        assert payload["lex_unmatched"] == 1
        assert payload["lex_coverage"] < 1.0
        assert len(payload["unknown_shapes"]) == 1
        shape = payload["unknown_shapes"][0]
        assert shape["count"] == 1
        assert "Blorp" in shape["template"]

    def test_verdict_is_attributed_to_a_policy(self, logs: Path) -> None:
        """Signatures are compared across sessions, so the policy is recorded.

        Without this, a cluster that changes tier between two corpus passes has
        two indistinguishable explanations: the logs describe different faults,
        or the tool changed underneath.
        """
        payload = json.loads(runner.invoke(app, ["diagnose", str(logs), "--json"]).stdout)
        assert payload["tool_version"]
        assert payload["rules_digest"]

    def test_both_broken_counts_stay_labelled(self, logs: Path) -> None:
        """Re-asserted here because the key set above would not catch a merge."""
        payload = json.loads(runner.invoke(app, ["diagnose", str(logs), "--json"]).stdout)
        assert payload["apt_broken_count"] != payload["observed_broken_count"]
        assert "broken" not in payload


class TestMachineReadableEverywhere:
    """Every command that answers a question can answer it to a script.

    ``--json`` existed only on ``diagnose``, so anything automating the corpus
    had to screen-scrape Rich tables -- which meant the alternative to
    scraping was reimplementing the tool's own logic, and that is how a second,
    disagreeing source of truth gets built.
    """

    def test_ingest_emits_records(self, tmp_path: Path, corpus: Path) -> None:
        state = tmp_path / "state"
        result = runner.invoke(
            app,
            [
                "ingest",
                *[str(p) for p in sorted(corpus.iterdir())],
                "--json",
                "--config", _conf(tmp_path, state),
            ],
        )
        assert result.exit_code == EXIT_OK, result.output
        records = json.loads(result.stdout)
        assert len(records) == len(LAID_OUT)
        assert all(r["schema"] >= 1 for r in records)
        assert all(r["rules_digest"] for r in records)

    def test_dedup_emits_clusters_with_tiers(self, tmp_path: Path, ingested: Path) -> None:
        result = runner.invoke(
            app, ["dedup", "--json", "--config", _conf(tmp_path, ingested)]
        )
        assert result.exit_code == EXIT_OK, result.output
        payload = json.loads(result.stdout)
        assert payload["runs"] == len(LAID_OUT)
        assert payload["clusters"], "the libpeas trio should cluster"
        for cluster in payload["clusters"]:
            # Never a bare "duplicate" boolean: root-graph is safe to act on
            # and evidence-similarity is a suggestion, and collapsing them
            # discards the only thing that says how much to trust it.
            assert cluster["tier"] in {"root-graph", "cause-tuple", "evidence-similarity"}
            assert "duplicate" not in cluster

    def test_dedup_rejects_two_output_formats(self, tmp_path: Path, ingested: Path) -> None:
        result = runner.invoke(
            app, ["dedup", "--json", "--markdown", "--config", _conf(tmp_path, ingested)]
        )
        assert result.exit_code == EXIT_USAGE

    def test_show_emits_the_stored_record(
        self, tmp_path: Path, ingested: Path, corpus: Path
    ) -> None:
        # Keyed by directory, not bug id: a run ingested from disk has no bug
        # number, which is the whole reason run keys are not bug numbers.
        key = f"dir:{corpus / '2150245'}#0"
        result = runner.invoke(
            app, ["show", key, "--json", "--config", _conf(tmp_path, ingested)]
        )
        assert result.exit_code == EXIT_OK, result.output
        payload = json.loads(result.stdout)
        assert payload["key"] == key
        assert payload["cause"] == "third_party_pin"
        assert payload["root_packages"] == ["libwacom9-surface"]

    def test_show_reports_the_stored_policy_not_the_current_one(
        self, tmp_path: Path, ingested: Path, corpus: Path
    ) -> None:
        """``show`` reports what was recorded, including which policy made it.

        Recomputing here would hide exactly the drift the stamp exists to
        expose: a run diagnosed months ago would silently acquire today's
        digest and look as though nothing had changed.
        """
        key = f"dir:{corpus / '2150245'}#0"
        payload = json.loads(
            runner.invoke(
                app, ["show", key, "--json", "--config", _conf(tmp_path, ingested)]
            ).stdout
        )
        assert payload["tool_version"]
        assert payload["rules_digest"]

    def test_stats_emits_a_summary(self, tmp_path: Path, ingested: Path) -> None:
        result = runner.invoke(
            app, ["stats", "--json", "--config", _conf(tmp_path, ingested)]
        )
        assert result.exit_code == EXIT_OK, result.output
        payload = json.loads(result.stdout)
        assert payload["totals"]["runs"] == len(LAID_OUT)
        assert payload["causes"]
        assert payload["coverage"]["runs_with_trace"] > 0

    def test_stats_reports_corpus_coverage(self, tmp_path: Path, ingested: Path) -> None:
        """A gap in one of many stored runs is invisible in that run's report.

        The corpus is where an unseen apt shape turns up first, so the
        aggregate has to be askable without re-ingesting everything.
        """
        payload = json.loads(
            runner.invoke(app, ["stats", "--json", "--config", _conf(tmp_path, ingested)]).stdout
        )
        coverage = payload["coverage"]
        assert coverage["lines"] > 0
        assert coverage["unmatched"] == 0
        assert coverage["runs_imperfect"] == 0
        assert coverage["coverage"] == 1.0
        assert coverage["unknown_shapes"] == []


class TestStrictEverywhere:
    """``--strict`` has to work on the commands that collect, not just diagnose.

    ``fetch`` and ``ingest`` are where a new apt version is met; ``diagnose``
    is where someone looks at a single directory they already care about.
    Having the check only on the last of those put it furthest from where it
    was needed.
    """

    def _dirty(self, tmp_path: Path) -> Path:
        root = tmp_path / "dirty"
        root.mkdir()
        (root / "main.log").write_text(fixture_text("logs/lp2150339-main.log"))
        apt = fixture_text("apt/lp2150339-apt.log").splitlines()[:200]
        apt.append("Blorp Fnord gibberish that no grammar matches")
        (root / "apt.log").write_text("\n".join(apt) + "\n")
        return root

    def test_ingest_exits_three_on_a_gap(self, tmp_path: Path) -> None:
        state = tmp_path / "state"
        conf = _conf(tmp_path, state)
        dirty = self._dirty(tmp_path)
        lenient = runner.invoke(app, ["ingest", str(dirty), "--config", conf])
        strict = runner.invoke(app, ["ingest", str(dirty), "--strict", "--config", conf])
        assert lenient.exit_code == EXIT_OK, lenient.output
        assert strict.exit_code == EXIT_IMPERFECT

    def test_ingest_warns_even_without_strict(self, tmp_path: Path) -> None:
        """A corpus pass is the usual way a gap first shows up.

        Reporting it only under ``--strict`` means it is silent in exactly the
        case where nobody is checking an exit code.
        """
        state = tmp_path / "state"
        result = runner.invoke(
            app, ["ingest", str(self._dirty(tmp_path)), "--config", _conf(tmp_path, state)]
        )
        assert result.exit_code == EXIT_OK
        assert "imperfect parse" in result.output

    def test_clean_corpus_is_silent(self, tmp_path: Path, corpus: Path) -> None:
        state = tmp_path / "state"
        result = runner.invoke(
            app,
            [
                "ingest",
                *[str(p) for p in sorted(corpus.iterdir())],
                "--strict",
                "--config", _conf(tmp_path, state),
            ],
        )
        assert result.exit_code == EXIT_OK, result.output
        assert "imperfect parse" not in result.output

    def test_the_warning_is_not_repeated_under_strict(self, tmp_path: Path) -> None:
        """Said once. Printing it unconditionally and again from the strict
        handler reported the same gap twice, which reads like two gaps."""
        state = tmp_path / "state"
        result = runner.invoke(
            app,
            ["ingest", str(self._dirty(tmp_path)), "--strict", "--config", _conf(tmp_path, state)],
        )
        assert result.exit_code == EXIT_IMPERFECT
        assert result.output.count("imperfect parse") == 1


class TestCoverageCommand:
    """The grammar-gap loop as a command.

    Gate 1 of the triage procedure lived in a script inside a skill directory,
    which meant it could not be run over a freshly collected batch -- and a
    batch is where an unseen apt shape turns up first.
    """

    def _dirty(self, tmp_path: Path) -> Path:
        root = tmp_path / "dirty"
        root.mkdir()
        (root / "main.log").write_text(fixture_text("logs/lp2150339-main.log"))
        apt = fixture_text("apt/lp2150339-apt.log").splitlines()[:200]
        apt += [
            "Blorp Fnord gibberish that no grammar matches",
            "Zarp 12 Quux 44 numeric variant",
            "Zarp 97 Quux 13 numeric variant",
        ]
        (root / "apt.log").write_text("\n".join(apt) + "\n")
        return root

    def test_clean_corpus_reports_full_coverage(self, tmp_path: Path, ingested: Path) -> None:
        result = runner.invoke(app, ["coverage", "--config", _conf(tmp_path, ingested)])
        assert result.exit_code == EXIT_OK, result.output
        assert "100.0000%" in result.output
        assert "0 lines unrecognised" in result.output

    def test_clean_corpus_passes_strict(self, tmp_path: Path, ingested: Path) -> None:
        result = runner.invoke(
            app, ["coverage", "--strict", "--config", _conf(tmp_path, ingested)]
        )
        assert result.exit_code == EXIT_OK, result.output

    def test_a_gap_is_found_and_attributed(self, tmp_path: Path, ingested: Path) -> None:
        config = _conf(tmp_path, ingested)
        assert (
            runner.invoke(app, ["ingest", str(self._dirty(tmp_path)), "--config", config]).exit_code
            == EXIT_OK
        )
        result = runner.invoke(app, ["coverage", "--config", config])
        assert result.exit_code == EXIT_OK, result.output
        assert "3 lines unrecognised in 1 run" in result.output
        # The offending run is named, so the gap can be reproduced.
        assert "dirty" in result.output

    def test_variants_of_one_shape_collapse(self, tmp_path: Path, ingested: Path) -> None:
        """Ten thousand numeric variants are one grammar gap, not ten thousand.

        Masked rather than raw: this is what makes a gap legible instead of
        drowning the report in its own volume, and the masked form is what a
        new pattern in ``apt/grammar.py`` gets written from.
        """
        config = _conf(tmp_path, ingested)
        runner.invoke(app, ["ingest", str(self._dirty(tmp_path)), "--config", config])
        payload = json.loads(
            runner.invoke(app, ["coverage", "--json", "--config", config]).stdout
        )
        shapes = {s["template"]: s["count"] for s in payload["unknown_shapes"]}
        # The two Zarp lines differ only in their numbers.
        collapsed = [t for t in shapes if "Zarp" in t]
        assert len(collapsed) == 1, shapes
        assert shapes[collapsed[0]] == 2

    def test_strict_exits_three_on_a_gap(self, tmp_path: Path, ingested: Path) -> None:
        config = _conf(tmp_path, ingested)
        runner.invoke(app, ["ingest", str(self._dirty(tmp_path)), "--config", config])
        result = runner.invoke(app, ["coverage", "--strict", "--config", config])
        assert result.exit_code == EXIT_IMPERFECT

    def test_worst_offender_comes_first(self, tmp_path: Path, ingested: Path) -> None:
        """Not sorted by key: a 3,000-line gap must not sort below a one-line one."""
        config = _conf(tmp_path, ingested)
        runner.invoke(app, ["ingest", str(self._dirty(tmp_path)), "--config", config])
        payload = json.loads(
            runner.invoke(app, ["coverage", "--json", "--config", config]).stdout
        )
        counts = [row["unmatched"] for row in payload["imperfect"]]
        assert counts == sorted(counts, reverse=True)

    def test_empty_store_says_so(self, tmp_path: Path) -> None:
        state = tmp_path / "empty"
        result = runner.invoke(app, ["coverage", "--config", _conf(tmp_path, state)])
        assert result.exit_code == EXIT_OK
        assert "no stored run" in result.output

    def test_unmeasured_runs_are_not_silently_counted(self, tmp_path: Path) -> None:
        """A corpus stored before coverage existed must say so, not claim 100%.

        The two reasons a run shows no lines -- it had no resolver trace, or
        nobody measured one -- are opposite facts, and this codebase is careful
        about exactly that kind of conflation elsewhere (the four things called
        "broken"). Reported separately, with the remedy, because re-ingesting
        is what fixes it.
        """
        state = tmp_path / "legacy"
        with Store.open(state) as store:
            store.put_run(UpgradeRun(bug_id=4242))  # no stamp, no coverage
            store.commit()
        result = runner.invoke(app, ["coverage", "--config", _conf(tmp_path, state)])
        assert result.exit_code == EXIT_OK, result.output
        assert "before coverage was recorded" in result.output
        assert "re-ingest" in result.output

        payload = json.loads(
            runner.invoke(
                app, ["coverage", "--json", "--config", _conf(tmp_path, state)]
            ).stdout
        )
        assert payload["unmeasured"] == ["lp:4242#0"]
        assert payload["runs_with_trace"] == 0


class TestRelatedCommand:
    """The triager's second question: have we seen this fault before?"""

    def test_finds_the_libpeas_trio(self, tmp_path: Path, ingested: Path, corpus: Path) -> None:
        """Three bugs, three reporters, three different packages blamed.

        They are one ``libpeas-1.0-1`` transition. This is the case the whole
        corpus side of the tool exists for.
        """
        key = f"dir:{corpus / '2150339'}#0"
        payload = json.loads(
            runner.invoke(
                app, ["related", key, "--json", "--config", _conf(tmp_path, ingested)]
            ).stdout
        )
        found = {
            entry["key"]
            for tier in payload["tiers"].values()
            for entry in tier
        }
        assert f"dir:{corpus / '2151847'}#0" in found
        assert f"dir:{corpus / '2169028'}#0" in found

    def test_tiers_are_reported_separately(
        self, tmp_path: Path, ingested: Path, corpus: Path
    ) -> None:
        """Strongest first, and never merged into one word called "duplicate".

        ``dedup`` groups the trio into a single ``root-graph`` cluster because
        clusters extend across tiers. Pairwise from 2150339 the two neighbours
        are *not* equally strong, and flattening that would discard the only
        information that says how much to trust each one.
        """
        key = f"dir:{corpus / '2150339'}#0"
        payload = json.loads(
            runner.invoke(
                app, ["related", key, "--json", "--config", _conf(tmp_path, ingested)]
            ).stdout
        )
        assert set(payload["tiers"]) == {"root-graph", "cause-tuple"}
        # Both tiers are populated for this subject, which is the point: the
        # two neighbours are not equally strong.
        assert payload["tiers"]["root-graph"], payload
        assert payload["tiers"]["cause-tuple"], payload
        # A run cannot appear in two tiers; the stronger claim wins.
        graph = {e["key"] for e in payload["tiers"]["root-graph"]}
        tuples = {e["key"] for e in payload["tiers"]["cause-tuple"]}
        assert not (graph & tuples)

    def test_shared_roots_are_separate_from_the_tiers(
        self, tmp_path: Path, ingested: Path, corpus: Path
    ) -> None:
        """A shared root is a lead; a shared subgraph is a verdict."""
        key = f"dir:{corpus / '2150339'}#0"
        payload = json.loads(
            runner.invoke(
                app, ["related", key, "--json", "--config", _conf(tmp_path, ingested)]
            ).stdout
        )
        stronger = {e["key"] for tier in payload["tiers"].values() for e in tier}
        for entry in payload["shared_roots"]:
            assert entry["key"] not in stronger
            assert entry["shared_roots"] >= 1

    def test_an_unrelated_run_has_no_neighbours(
        self, tmp_path: Path, ingested: Path, corpus: Path
    ) -> None:
        key = f"dir:{corpus / '2150245'}#0"
        result = runner.invoke(app, ["related", key, "--config", _conf(tmp_path, ingested)])
        assert result.exit_code == EXIT_OK, result.output
        payload = json.loads(
            runner.invoke(
                app, ["related", key, "--json", "--config", _conf(tmp_path, ingested)]
            ).stdout
        )
        assert not payload["tiers"]["root-graph"]

    def test_unknown_key_lists_known_ones(self, tmp_path: Path, ingested: Path) -> None:
        result = runner.invoke(
            app, ["related", "lp:9999999#0", "--config", _conf(tmp_path, ingested)]
        )
        assert result.exit_code == EXIT_FAIL
        assert "known keys" in result.output


class TestHistoryCommand:
    """Is this package a recurring transition or a one-off?"""

    def test_a_root_is_reported_as_a_root(self, tmp_path: Path, ingested: Path) -> None:
        payload = json.loads(
            runner.invoke(
                app,
                ["history", "libpeas-1.0-1", "--json", "--config", _conf(tmp_path, ingested)],
            ).stdout
        )
        assert len(payload["roles"]["root"]) == 3
        # Across different release pairs, which is what distinguishes an
        # archive transition from one machine's misconfiguration.
        assert len({e["release"] for e in payload["roles"]["root"]}) > 1

    def test_a_victim_is_never_counted_as_a_cause(
        self, tmp_path: Path, ingested: Path
    ) -> None:
        """``eog`` is implicated in three unrelated bugs and causes none.

        A triager seeing it in a bug title would be misled, which is the
        inversion this tool exists to correct -- so the two roles are reported
        apart and never summed into one number.
        """
        config = _conf(tmp_path, ingested)
        payload = json.loads(
            runner.invoke(app, ["history", "eog", "--json", "--config", config]).stdout
        )
        assert "root" not in payload["roles"]
        assert len(payload["roles"]["victim"]) == 3
        # And said out loud, because a reader scanning a list for "root" will
        # not notice an absence.
        plain = runner.invoke(app, ["history", "eog", "--config", config])
        assert "never a root" in plain.output

    def test_a_bare_name_covers_every_architecture(
        self, tmp_path: Path, ingested: Path
    ) -> None:
        payload = json.loads(
            runner.invoke(
                app,
                ["history", "libpeas-1.0-1", "--json", "--config", _conf(tmp_path, ingested)],
            ).stdout
        )
        assert payload["spellings"] == ["libpeas-1.0-1:amd64"]

    def test_an_unknown_package_fails_with_a_hint(
        self, tmp_path: Path, ingested: Path
    ) -> None:
        result = runner.invoke(
            app, ["history", "no-such-package", "--config", _conf(tmp_path, ingested)]
        )
        assert result.exit_code == EXIT_FAIL
        assert "no stored run mentions" in result.output

    def test_an_explicit_architecture_narrows(self, tmp_path: Path, ingested: Path) -> None:
        """The corpus has no i386 libpeas, so asking for one must not match amd64."""
        result = runner.invoke(
            app, ["history", "libpeas-1.0-1:i386", "--config", _conf(tmp_path, ingested)]
        )
        assert result.exit_code == EXIT_FAIL


class TestSweep:
    """Collection, which is the entry point for triage.

    Driven through a mock transport: the suite must not touch the network.
    Launchpad is a shared service, it rate-limits, and a test that depends on a
    live bug fails for reasons unrelated to the code.
    """

    API = "https://api.launchpad.net/devel"

    def _task(self, bug_id: int, status: str = "New", day: int = 29) -> dict[str, object]:
        return {
            "bug_link": f"{self.API}/bugs/{bug_id}",
            "status": status,
            "date_created": f"2026-09-{day:02d}T10:00:00+00:00",
            "title": f"Bug #{bug_id} in ubuntu-release-upgrader (Ubuntu)",
        }

    def _transport(
        self,
        tasks: list[dict[str, object]],
        *,
        logs_for: set[int] | None = None,
        rate_limit_after: int | None = None,
    ) -> tuple[httpx.MockTransport, list[int]]:
        """Serve a search page plus each bug's logs. Records bugs fetched."""
        apt = fixture_text("apt/lp2150339-apt.log")
        main = fixture_text("logs/lp2150339-main.log")
        fetched: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "searchTasks" in url:
                return httpx.Response(200, json={"entries": tasks})
            if "+attachment" in url:
                body = main if url.endswith("/1/data") else apt
                return httpx.Response(200, content=body.encode())
            if url.endswith("/attachments"):
                bug_id = int(url.rsplit("/", 2)[-2])
                if logs_for is not None and bug_id not in logs_for:
                    return httpx.Response(200, json={"entries": []})
                return httpx.Response(
                    200,
                    json={
                        "entries": [
                            {
                                "title": "VarLogDistupgradeAptlog.txt",
                                "data_link": f"{self.API}/bugs/{bug_id}/+attachment/0/data",
                            },
                            {
                                "title": "VarLogDistupgradeMainlog.txt",
                                "data_link": f"{self.API}/bugs/{bug_id}/+attachment/1/data",
                            },
                        ]
                    },
                )
            if "/bugs/" in url:
                bug_id = int(url.rsplit("/", 1)[-1])
                if rate_limit_after is not None and len(fetched) >= rate_limit_after:
                    return httpx.Response(429, text="slow down")
                fetched.append(bug_id)
                return httpx.Response(
                    200,
                    json={
                        "id": bug_id,
                        "title": "upgrade failed",
                        "description": "ProblemType: Bug\n",
                        "tags": [],
                        "number_of_duplicates": 0,
                        "date_created": "2026-09-29T10:00:00+00:00",
                    },
                )
            return httpx.Response(404)

        return (httpx.MockTransport(handler), fetched)

    def _patch(self, monkeypatch: pytest.MonkeyPatch, transport: httpx.MockTransport) -> None:
        _patch_launchpad(monkeypatch, transport)

    def test_dry_run_spends_no_log_requests(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Deciding whether to spend half an hour is a listing-only question."""
        transport, fetched = self._transport([self._task(1), self._task(2)])
        self._patch(monkeypatch, transport)
        result = runner.invoke(
            app,
            ["sweep", "--dry-run", "--config", _conf(tmp_path, tmp_path / "state")],
        )
        assert result.exit_code == EXIT_OK, result.output
        assert fetched == []
        assert "LP#1" in result.output

    def test_dry_run_shows_the_cost(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        transport, _ = self._transport([self._task(1), self._task(2)])
        self._patch(monkeypatch, transport)
        result = runner.invoke(
            app, ["sweep", "--dry-run", "--config", _conf(tmp_path, tmp_path / "state")]
        )
        assert "requests" in result.output

    def test_fetches_diagnoses_and_stores(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        transport, fetched = self._transport([self._task(1), self._task(2)])
        self._patch(monkeypatch, transport)
        state = tmp_path / "state"
        config = _conf(tmp_path, state)
        result = runner.invoke(app, ["sweep", "--config", config])
        assert result.exit_code == EXIT_OK, result.output
        assert sorted(fetched) == [1, 2]
        stats = json.loads(runner.invoke(app, ["stats", "--json", "--config", config]).stdout)
        assert stats["totals"]["bugs"] == 2

    def test_bug_status_is_recorded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """It comes free in the search response, and it is ground truth.

        The bug's own resolution is the second-strongest evidence for whether
        this tool is right. ``fetch`` cannot get it without a third request per
        bug; ``sweep`` gets it for nothing.
        """
        transport, _ = self._transport([self._task(1, "Invalid"), self._task(2, "Won't Fix")])
        self._patch(monkeypatch, transport)
        config = _conf(tmp_path, tmp_path / "state")
        payload = json.loads(
            runner.invoke(app, ["sweep", "--json", "--config", config]).stdout
        )
        assert payload["fetched"] == 2
        with Store.open(tmp_path / "state") as store:
            statuses = {r.bug_id: r.bug_status for r in store.iter_runs()}
        assert statuses == {1: "Invalid", 2: "Won't Fix"}

    def test_closed_bugs_are_not_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A sweep must collect the bugs whose resolution is the evidence."""
        transport, fetched = self._transport(
            [self._task(1, "Won't Fix"), self._task(2, "Fix Released")]
        )
        self._patch(monkeypatch, transport)
        runner.invoke(app, ["sweep", "--config", _conf(tmp_path, tmp_path / "state")])
        assert sorted(fetched) == [1, 2]

    def test_already_known_bugs_are_not_refetched(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        transport, fetched = self._transport([self._task(1), self._task(2)])
        self._patch(monkeypatch, transport)
        config = _conf(tmp_path, tmp_path / "state")
        runner.invoke(app, ["sweep", "--config", config])
        fetched.clear()
        second = runner.invoke(app, ["sweep", "--config", config])
        assert second.exit_code == EXIT_OK, second.output
        assert fetched == []

    def test_the_limit_leaves_the_rest_for_next_time(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The cap is a stop, not a filter: the remainder must not be skipped."""
        tasks = [self._task(i, day=20 + i) for i in range(1, 6)]
        transport, fetched = self._transport(tasks)
        self._patch(monkeypatch, transport)
        config = _conf(tmp_path, tmp_path / "state")

        first = runner.invoke(app, ["sweep", "--limit", "2", "--json", "--config", config])
        payload = json.loads(first.stdout)
        assert payload["fetched"] == 2
        assert payload["remaining"] == 3
        assert fetched == [1, 2], "oldest first, so the watermark can advance safely"

        second = json.loads(
            runner.invoke(app, ["sweep", "--limit", "2", "--json", "--config", config]).stdout
        )
        assert second["fetched"] == 2
        assert sorted(fetched) == [1, 2, 3, 4]

    def test_rate_limiting_keeps_what_it_already_stored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A 429 partway through must not discard the bugs already handled.

        Marching on would collect the same refusal and burn the recovery
        window; rolling back would mean a sweep interrupted near the end of a
        half-hour pass achieved nothing.
        """
        tasks = [self._task(i, day=20 + i) for i in range(1, 5)]
        transport, _fetched = self._transport(tasks, rate_limit_after=2)
        self._patch(monkeypatch, transport)
        config = _conf(tmp_path, tmp_path / "state")
        result = runner.invoke(app, ["sweep", "--config", config])
        assert result.exit_code == EXIT_OK, result.output
        assert "rate limited" in result.output
        stats = json.loads(runner.invoke(app, ["stats", "--json", "--config", config]).stdout)
        assert stats["totals"]["bugs"] == 2, "the two it managed must survive"

    def test_the_watermark_does_not_pass_unhandled_bugs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The property that makes interruption safe rather than lossy.

        After a 429 at bug 2 of 4, the mark must sit at bug 2's date -- not at
        bug 4's. Anything beyond it has not been stored, and once the mark is
        past a bug's creation date the search will never offer it again.
        """
        tasks = [self._task(i, day=20 + i) for i in range(1, 5)]
        transport, _ = self._transport(tasks, rate_limit_after=2)
        self._patch(monkeypatch, transport)
        runner.invoke(app, ["sweep", "--config", _conf(tmp_path, tmp_path / "state")])
        with Store.open(tmp_path / "state") as store:
            mark = store.sweep_watermark()
        assert mark is not None
        assert mark.day == 22, f"watermark ran ahead to day {mark.day}"

    def test_a_bug_with_no_logs_is_counted_not_hidden(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """LP#2161332 attached two screenshots.

        "No upgrade logs were attached" is the correct answer and the commonest
        reason a report cannot be triaged, so it is reported rather than buried.
        """
        transport, _ = self._transport([self._task(1), self._task(2)], logs_for={1})
        self._patch(monkeypatch, transport)
        payload = json.loads(
            runner.invoke(
                app, ["sweep", "--json", "--config", _conf(tmp_path, tmp_path / "state")]
            ).stdout
        )
        assert payload["no_logs"] == [2]

    def test_since_overrides_the_watermark(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        transport, _ = self._transport([self._task(1)])
        self._patch(monkeypatch, transport)
        payload = json.loads(
            runner.invoke(
                app,
                [
                    "sweep",
                    "--since",
                    "2026-01-01",
                    "--json",
                    "--config",
                    _conf(tmp_path, tmp_path / "state"),
                ],
            ).stdout
        )
        assert payload["since"].startswith("2026-01-01")

    def test_a_bad_since_is_a_usage_error(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            ["sweep", "--since", "last tuesday", "--config", _conf(tmp_path, tmp_path / "state")],
        )
        assert result.exit_code == EXIT_USAGE

    def test_nothing_new_is_not_a_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        transport, _ = self._transport([])
        self._patch(monkeypatch, transport)
        result = runner.invoke(
            app, ["sweep", "--config", _conf(tmp_path, tmp_path / "state")]
        )
        assert result.exit_code == EXIT_OK, result.output

    def test_the_imperfect_warning_is_not_repeated_under_strict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Said once. The same duplicate-print slip as in ``ingest``.

        Fixed there, then reintroduced here by copying the shape rather than
        the lesson -- which is why both now have a test.
        """
        apt = fixture_text("apt/lp2150339-apt.log").splitlines()[:200]
        apt.append("Blorp Fnord gibberish that no grammar matches")
        dirty = "\n".join(apt) + "\n"
        main = fixture_text("logs/lp2150339-main.log")

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "searchTasks" in url:
                return httpx.Response(200, json={"entries": [self._task(1)]})
            if "+attachment" in url:
                body = main if url.endswith("/1/data") else dirty
                return httpx.Response(200, content=body.encode())
            if url.endswith("/attachments"):
                return httpx.Response(
                    200,
                    json={
                        "entries": [
                            {
                                "title": "VarLogDistupgradeAptlog.txt",
                                "data_link": f"{self.API}/bugs/1/+attachment/0/data",
                            },
                            {
                                "title": "VarLogDistupgradeMainlog.txt",
                                "data_link": f"{self.API}/bugs/1/+attachment/1/data",
                            },
                        ]
                    },
                )
            return httpx.Response(
                200,
                json={
                    "id": 1,
                    "title": "t",
                    "description": "ProblemType: Bug\n",
                    "tags": [],
                    "number_of_duplicates": 0,
                },
            )

        self._patch(monkeypatch, httpx.MockTransport(handler))
        result = runner.invoke(
            app, ["sweep", "--strict", "--config", _conf(tmp_path, tmp_path / "state")]
        )
        assert result.exit_code == EXIT_IMPERFECT, result.output
        assert result.output.count("imperfect parse") == 1


class TestProgressDisplay:
    """Progress must never reach the thing a command exists to produce.

    ``--json`` and ``--markdown`` write a document to stdout that is meant to
    be redirected. A spinner in the middle of it is corruption, not noise.
    """

    def test_a_disabled_tracker_is_a_safe_no_op(self) -> None:
        """So no caller has to ask whether progress is on."""
        from uru_doctor_cli.cli import Tracker

        tracker = Tracker(None, None)
        tracker.start("anything", total=5)
        tracker.context("LP#1")
        tracker.note("working")
        tracker.advance()
        tracker.advance("done")
        tracker.callback("via the client")
        assert tracker.task is None

    def test_no_display_when_the_console_is_not_a_terminal(self) -> None:
        """A cron job or a `2>log` capture must get no control codes."""
        from io import StringIO

        from rich.console import Console
        from uru_doctor_cli.cli import _progress

        with _progress(console=Console(file=StringIO(), force_terminal=False)) as tracker:
            assert tracker.display is None

    def test_one_task_at_a_time(self) -> None:
        """A second phase must not leave the first drawing itself.

        A sweep showed ``searching Launchpad 0/?`` stuck above the real bar for
        its whole run, because the phase that had moved on still had a row.
        """
        from io import StringIO

        from rich.console import Console
        from uru_doctor_cli.cli import _progress

        console = Console(file=StringIO(), force_terminal=True, width=100)
        with _progress(console=console) as tracker:
            assert tracker.display is not None
            tracker.start("first", total=3)
            tracker.advance()
            tracker.start("second", total=None)
            assert len(tracker.display.tasks) == 1
            assert tracker.display.tasks[0].description == "second"

    def test_an_indeterminate_phase_clears_the_previous_total(self) -> None:
        """Rich reads ``total=None`` as "leave it alone" on both reset and update.

        Resetting therefore kept the previous phase's total and drew
        ``clustering 0/7`` -- a bar measuring seven of something that was no
        longer being counted. Replacing the task is what actually clears it.
        """
        from io import StringIO

        from rich.console import Console
        from uru_doctor_cli.cli import _progress

        console = Console(file=StringIO(), force_terminal=True, width=100)
        with _progress(console=console) as tracker:
            assert tracker.display is not None
            tracker.start("counted", total=7)
            tracker.start("uncountable", total=None)
            assert tracker.display.tasks[0].total is None

    def test_the_prefix_keeps_the_subject_visible(self) -> None:
        """Otherwise the label is whatever the client last said.

        ``GET 6003872/data`` tells you the tool is alive but not what it is
        working on, and an opaque attachment id is the least useful half.
        """
        from io import StringIO

        from rich.console import Console
        from uru_doctor_cli.cli import _progress

        console = Console(file=StringIO(), force_terminal=True, width=100)
        with _progress(console=console) as tracker:
            assert tracker.display is not None
            tracker.start("fetching", total=2)
            tracker.context("LP#2169028")
            tracker.callback("GET 6003872/data")
            assert tracker.display.tasks[0].description == "LP#2169028 GET 6003872/data"

    def test_a_new_phase_drops_the_old_prefix(self) -> None:
        from io import StringIO

        from rich.console import Console
        from uru_doctor_cli.cli import _progress

        console = Console(file=StringIO(), force_terminal=True, width=100)
        with _progress(console=console) as tracker:
            assert tracker.display is not None
            tracker.start("fetching", total=1)
            tracker.context("LP#1")
            tracker.start("clustering", total=None)
            tracker.note("working")
            assert tracker.display.tasks[0].description == "working"

    def test_json_output_stays_parseable(self, tmp_path: Path, ingested: Path) -> None:
        """The end-to-end guarantee, however the bar is rendered."""
        for argv in (
            ["dedup", "--json"],
            ["stats", "--json"],
            ["coverage", "--json"],
        ):
            result = runner.invoke(
                app, [*argv, "--config", _conf(tmp_path, ingested)]
            )
            assert result.exit_code == EXIT_OK, (argv, result.output)
            json.loads(result.stdout)

    def test_markdown_output_has_no_control_codes(self, logs: Path) -> None:
        result = runner.invoke(app, ["diagnose", str(logs), "--markdown"])
        assert result.exit_code == EXIT_OK, result.output
        assert "\x1b[" not in result.stdout
        assert result.stdout.lstrip().startswith("# ")

    def test_title_remains_one_clean_line(self, logs: Path) -> None:
        """It exists to be piped, so nothing may share its stdout."""
        result = runner.invoke(app, ["title", str(logs)])
        assert result.exit_code == EXIT_OK
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        assert len(lines) == 1
        assert "\x1b[" not in result.stdout


class TestQueue:
    """The worklist: what still needs a decision.

    Driven against a store built by ``ingest`` so that the classification runs
    over real diagnoses rather than hand-written rows -- the hand-written cases
    live in ``test_worklist.py``. What is being tested here is the wiring:
    that Launchpad state reaches the buckets, that counts stay exact when rows
    are capped, and that the thing refuses to guess.
    """

    @staticmethod
    def _state(state: Path, bug_id: int, **kwargs: object) -> None:
        from uru_doctor.store import BugState

        with Store.open(state) as store:
            store.put_bug_states([BugState(bug_id=bug_id, **kwargs)])  # type: ignore[arg-type]
            store.commit()

    def test_empty_store_says_so(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["queue", "--config", _conf(tmp_path, tmp_path / "state")]
        )
        assert result.exit_code == EXIT_FAIL
        assert "empty" in result.output

    def test_unknown_status_is_reported_not_guessed(
        self, tmp_path: Path, ingested: Path
    ) -> None:
        """An ingested corpus has no Launchpad state at all.

        Every row must land in ``status-unknown`` rather than being filed as
        outstanding work, because nothing here knows whether these bugs are
        already closed.
        """
        result = runner.invoke(app, ["queue", "--config", _conf(tmp_path, ingested)])
        assert result.exit_code == EXIT_OK, result.output
        assert "status-unknown" in result.output
        assert "refresh" in result.output

    def test_never_read_is_reported_as_stale(self, tmp_path: Path, ingested: Path) -> None:
        """Not fresh merely because there is no timestamp to contradict it."""
        payload = json.loads(
            runner.invoke(
                app, ["queue", "--json", "--config", _conf(tmp_path, ingested)]
            ).stdout
        )
        assert payload["launchpad_state"]["stale"] is True
        assert payload["launchpad_state"]["newest_check"] is None

    def test_closed_bugs_are_counted_never_listed(
        self, tmp_path: Path, swept: Path
    ) -> None:
        for bug_id in SWEPT:
            self._state(swept, bug_id, status="Invalid", checked_at="2026-10-05")
        result = runner.invoke(app, ["queue", "--config", _conf(tmp_path, swept)])
        assert result.exit_code == EXIT_OK, result.output
        assert "nothing waiting on a decision" in result.output
        assert "need nothing" in result.output
        assert "3 Invalid" in result.output

    def test_counts_stay_exact_when_rows_are_capped(
        self, tmp_path: Path, swept: Path
    ) -> None:
        """Narrowing the view must not narrow the arithmetic.

        A reader who works through a capped bucket believing it was the whole
        backlog is worse off than one who was never shown it.
        """
        payload = json.loads(
            runner.invoke(
                app,
                ["queue", "--json", "--limit", "1", "--config", _conf(tmp_path, swept)],
            ).stdout
        )
        # Three bugs with identical logs: one master and two proposed duplicates.
        assert payload["counts"]["mark-duplicate"] == 2
        assert payload["counts"]["diagnosed-unrecorded"] == 1
        result = runner.invoke(
            app, ["queue", "--limit", "1", "--config", _conf(tmp_path, swept)]
        )
        assert "showing 1 of 2" in result.output

    def test_bucket_filter_narrows_rows_but_not_counts(
        self, tmp_path: Path, swept: Path
    ) -> None:
        """A reader who asked about one bucket still needs the whole arithmetic."""
        payload = json.loads(
            runner.invoke(
                app,
                [
                    "queue",
                    "--json",
                    "-b",
                    "candidate-invalid",
                    "--config",
                    _conf(tmp_path, swept),
                ],
            ).stdout
        )
        assert payload["items"] == []
        assert payload["counts"]["mark-duplicate"] == 2
        assert payload["actionable"] == 3

    def test_unknown_bucket_is_a_usage_error(self, tmp_path: Path, swept: Path) -> None:
        result = runner.invoke(
            app, ["queue", "-b", "nonsense", "--config", _conf(tmp_path, swept)]
        )
        assert result.exit_code == EXIT_USAGE
        assert "mark-duplicate" in result.output

    def test_markdown_and_json_are_exclusive(self, tmp_path: Path, swept: Path) -> None:
        result = runner.invoke(
            app, ["queue", "--markdown", "--json", "--config", _conf(tmp_path, swept)]
        )
        assert result.exit_code == EXIT_USAGE

    def test_markdown_dates_itself(self, tmp_path: Path, ingested: Path) -> None:
        result = runner.invoke(
            app, ["queue", "--markdown", "--config", _conf(tmp_path, ingested)]
        )
        assert result.exit_code == EXIT_OK, result.output
        assert "# Triage worklist" in result.output
        assert "never been read" in result.output

    def test_json_carries_a_schema(self, tmp_path: Path, swept: Path) -> None:
        payload = json.loads(
            runner.invoke(
                app, ["queue", "--json", "--config", _conf(tmp_path, swept)]
            ).stdout
        )
        assert payload["schema"] == 1

    def test_a_launchpad_duplicate_leaves_the_worklist(
        self, tmp_path: Path, swept: Path
    ) -> None:
        """The whole mechanism, end to end.

        LP#2169028 and LP#2151847 share a root-cause subgraph, so the tool
        proposes marking one a duplicate of the other. Recording that
        Launchpad already thinks so must clear the row -- without any local
        note that a human did it.
        """
        config = _conf(tmp_path, swept)
        for bug_id in SWEPT:
            self._state(swept, bug_id, status="New", checked_at="2026-10-05")
        before = json.loads(
            runner.invoke(app, ["queue", "--json", "--config", config]).stdout
        )
        proposed = {
            item["bug_id"] for item in before["items"] if item["bucket"] == "mark-duplicate"
        }
        assert proposed, "expected the libpeas trio to produce a duplicate proposal"

        for bug_id in proposed:
            self._state(swept, bug_id, is_duplicate=True, checked_at="2026-10-05")
        after = json.loads(
            runner.invoke(app, ["queue", "--json", "--config", config]).stdout
        )
        assert after["counts"]["mark-duplicate"] == 0
        assert after["done_by_status"]["already a duplicate"] == len(proposed)

    def test_a_contradicting_master_is_reported(
        self, tmp_path: Path, swept: Path
    ) -> None:
        config = _conf(tmp_path, swept)
        for bug_id in SWEPT:
            self._state(swept, bug_id, status="New", checked_at="2026-10-05")
        before = json.loads(
            runner.invoke(app, ["queue", "--json", "--config", config]).stdout
        )
        victim = next(
            item for item in before["items"] if item["bucket"] == "mark-duplicate"
        )
        self._state(
            swept,
            victim["bug_id"],
            status="New",
            is_duplicate=True,
            duplicate_of=999999,
            checked_at="2026-10-05",
        )
        after = json.loads(
            runner.invoke(app, ["queue", "--json", "--config", config]).stdout
        )
        conflict = next(
            item for item in after["items"] if item["bucket"] == "duplicate-conflict"
        )
        assert conflict["bug_id"] == victim["bug_id"]
        assert "LP#999999" in conflict["action"]
        assert victim["master"] in conflict["action"]


class TestRefresh:
    """Re-reading Launchpad's verdict on bugs already stored.

    The steady state has to be cheap or nobody will run it, and it has to be
    honest about what it did not reach or the worklist built on it is fiction.
    """

    API = "https://api.launchpad.net/devel"

    def _transport(
        self,
        tasks: list[dict[str, object]],
        *,
        duplicates: set[int] = frozenset(),
        truncate: bool = False,
        masters: dict[int, int] | None = None,
    ) -> tuple[httpx.MockTransport, list[str]]:
        """Serve the two triage listings, plus per-bug lookups."""
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            calls.append(url)
            if "searchTasks" in url:
                entries = [
                    task
                    for task in tasks
                    if not (
                        "omit_duplicates=true" in url
                        and int(str(task["bug_link"]).rsplit("/", 1)[-1]) in duplicates
                    )
                ]
                body: dict[str, object] = {"entries": entries}
                if truncate:
                    body["next_collection_link"] = (
                        f"{self.API}/ubuntu/+source/ubuntu-release-upgrader"
                        "?ws.op=searchTasks&more=1"
                    )
                return httpx.Response(200, json=body)
            if "/+bug/" in url:
                return httpx.Response(200, json={"status": "Triaged"})
            if "/bugs/" in url:
                bug_id = int(url.rsplit("/", 1)[-1])
                master = (masters or {}).get(bug_id)
                return httpx.Response(
                    200,
                    json={
                        "id": bug_id,
                        "title": "upgrade failed",
                        "description": "",
                        "tags": [],
                        "number_of_duplicates": 0,
                        "duplicate_of_link": (
                            f"{self.API}/bugs/{master}" if master else None
                        ),
                        "date_created": "2026-09-29T10:00:00+00:00",
                    },
                )
            return httpx.Response(404)

        return (httpx.MockTransport(handler), calls)

    def _task(self, bug_id: int, status: str = "New") -> dict[str, object]:
        return {
            "bug_link": f"{self.API}/bugs/{bug_id}",
            "status": status,
            "date_created": "2026-09-29T10:00:00+00:00",
            "title": f"Bug #{bug_id}",
        }

    def _patch(self, monkeypatch: pytest.MonkeyPatch, transport: httpx.MockTransport) -> None:
        TestSweep._patch(self, monkeypatch, transport)  # type: ignore[arg-type]

    def test_an_empty_store_has_nothing_to_refresh(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["refresh", "--config", _conf(tmp_path, tmp_path / "state")]
        )
        assert result.exit_code == EXIT_FAIL
        assert "no Launchpad bugs" in result.output

    def test_the_steady_state_is_two_requests(
        self, tmp_path: Path, swept: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One listing including duplicates, one excluding. That is the budget.

        It must not grow with the corpus: this is the command a triager runs
        before every session, and the whole design of the worklist assumes it
        is close to free.
        """
        with Store.open(swept) as store:
            store.advance_status_watermark(datetime(2026, 10, 1, tzinfo=UTC))
            store.commit()
        transport, calls = self._transport([self._task(2169028, "Triaged")])
        self._patch(monkeypatch, transport)
        result = runner.invoke(app, ["refresh", "--config", _conf(tmp_path, swept)])
        assert result.exit_code == EXIT_OK, result.output
        assert len(calls) == 2, calls
        assert "modified_since=2026-10-01" in calls[0]

    def test_a_status_change_is_recorded_and_reported(
        self, tmp_path: Path, swept: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        transport, _ = self._transport([self._task(2169028, "Won't Fix")])
        self._patch(monkeypatch, transport)
        result = runner.invoke(app, ["refresh", "--config", _conf(tmp_path, swept)])
        assert result.exit_code == EXIT_OK, result.output
        assert "Won't Fix" in result.output
        with Store.open(swept) as store:
            assert store.bug_states()[2169028].status == "Won't Fix"

    def test_a_newly_marked_duplicate_is_noticed(
        self, tmp_path: Path, swept: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The signal Launchpad's own default hides.

        A bug drops out of the default search the moment somebody marks it,
        which is exactly when a triage tool needs to see it.
        """
        transport, _ = self._transport(
            [self._task(2169028)], duplicates={2169028}
        )
        self._patch(monkeypatch, transport)
        result = runner.invoke(app, ["refresh", "--config", _conf(tmp_path, swept)])
        assert result.exit_code == EXIT_OK, result.output
        assert "newly marked a duplicate" in result.output
        with Store.open(swept) as store:
            assert store.bug_states()[2169028].is_duplicate is True

    def test_an_unmodified_bug_is_confirmed_current(
        self, tmp_path: Path, swept: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Absence from a *complete* listing is positive evidence.

        Without this the age of a corpus would be the age of its least
        recently changed bug, so a worklist over bugs that are all correctly
        quiet would report itself permanently stale.
        """
        from uru_doctor.store import BugState

        with Store.open(swept) as store:
            store.put_bug_states(
                [BugState(bug_id=2150339, status="Triaged", checked_at="2020-01-01")]
            )
            store.commit()
        transport, _ = self._transport([self._task(2169028)])
        self._patch(monkeypatch, transport)
        assert (
            runner.invoke(app, ["refresh", "--config", _conf(tmp_path, swept)]).exit_code
            == EXIT_OK
        )
        with Store.open(swept) as store:
            state = store.bug_states()[2150339]
        assert state.status == "Triaged"
        assert state.checked_at != "2020-01-01"

    def test_a_truncated_listing_does_not_confirm_anything(
        self, tmp_path: Path, swept: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The bug this flag exists to prevent.

        This package has far more bugs than the listing will page through, so
        treating absence as "unmodified" would stamp every unread bug as
        confirmed current.
        """
        from uru_doctor.store import BugState

        with Store.open(swept) as store:
            store.put_bug_states(
                [BugState(bug_id=2150339, status="Triaged", checked_at="2020-01-01")]
            )
            store.commit()
        transport, _ = self._transport([self._task(2169028)], truncate=True)
        self._patch(monkeypatch, transport)
        result = runner.invoke(app, ["refresh", "--config", _conf(tmp_path, swept)])
        assert result.exit_code == EXIT_OK, result.output
        with Store.open(swept) as store:
            assert store.bug_states()[2150339].checked_at == "2020-01-01"
        assert "beyond the listing" in result.output

    def test_deep_resolves_a_master(
        self, tmp_path: Path, swept: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        transport, _ = self._transport(
            [self._task(2169028)],
            duplicates={2169028},
            masters={2169028: 2150339},
        )
        self._patch(monkeypatch, transport)
        result = runner.invoke(
            app, ["refresh", "--deep", "-n", "2", "--config", _conf(tmp_path, swept)]
        )
        assert result.exit_code == EXIT_OK, result.output
        with Store.open(swept) as store:
            assert store.bug_states()[2169028].duplicate_of == 2150339

    def test_dry_run_spends_nothing(
        self, tmp_path: Path, swept: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        transport, calls = self._transport([self._task(2169028)])
        self._patch(monkeypatch, transport)
        result = runner.invoke(
            app, ["refresh", "--dry-run", "--config", _conf(tmp_path, swept)]
        )
        assert result.exit_code == EXIT_OK, result.output
        assert calls == []
        assert "listing request" in result.output

    def test_dry_run_does_not_promise_a_full_pass_is_cheap(
        self, tmp_path: Path, swept: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A full pass walks Launchpad's queue, not this corpus.

        An earlier estimate divided the corpus size by the page size and
        promised six seconds for a pass that takes four minutes.
        """
        transport, _ = self._transport([self._task(2169028)])
        self._patch(monkeypatch, transport)
        payload = json.loads(
            runner.invoke(
                app,
                ["refresh", "--dry-run", "--json", "--config", _conf(tmp_path, swept)],
            ).stdout
        )
        assert payload["full_pass"] is True
        assert payload["listing_requests_max"] == 80

    def test_the_sweep_watermark_is_left_alone(
        self, tmp_path: Path, swept: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Advancing the sweep mark skips bugs; this one must not touch it."""
        with Store.open(swept) as store:
            before = store.sweep_watermark()
        transport, _ = self._transport([self._task(2169028)])
        self._patch(monkeypatch, transport)
        runner.invoke(app, ["refresh", "--config", _conf(tmp_path, swept)])
        with Store.open(swept) as store:
            assert store.sweep_watermark() == before
            assert store.status_watermark() is not None
