"""Tests for :mod:`uru_doctor.phases` and :mod:`uru_doctor.parsers.mainlog`."""

from __future__ import annotations

import pytest

from uru_doctor.intern import Interner
from uru_doctor.models import Level, Phase
from uru_doctor.parsers.mainlog import (
    iter_records,
    parse_main_log,
    resolve_third_party,
    split_apt_messages,
)
from uru_doctor.phases import PhaseTracker, phase_for

from .conftest import fixture_text


def main_log(name: str, interner: Interner):
    return parse_main_log(fixture_text(f"logs/{name}").splitlines(), interner)


def rec(message: str, *, level: str = "DEBUG", ms: int = 0) -> str:
    return f"2026-04-25 10:49:{ms // 1000:02d},{ms % 1000:03d} {level} {message}"


class TestRecordFolding:
    """Records are delimited by timestamps, not by newlines.

    The upgrader logs deb822 stanzas, PGP blocks and tracebacks as single
    records. One fixture contains a 20-line PGP public key inside one
    ``examining:`` record.
    """

    def test_continuation_lines_fold_into_the_record(self) -> None:
        records = list(
            iter_records(
                [
                    rec("examining: 'Types: deb"),
                    "URIs: http://gb.archive.ubuntu.com/ubuntu/",
                    "Suites: noble'",
                    rec("next thing", ms=1000),
                ]
            )
        )
        assert len(records) == 2
        assert records[0].continuation == (
            "URIs: http://gb.archive.ubuntu.com/ubuntu/",
            "Suites: noble'",
        )
        assert records[0].full.count("\n") == 2
        assert records[1].message == "next thing"

    def test_orphan_leading_lines_are_dropped(self) -> None:
        """A log can begin mid-record if a previous run was truncated."""
        records = list(iter_records(["trailing junk", " more junk", rec("real")]))
        assert [r.message for r in records] == ["real"]

    def test_timestamps_are_relative_to_the_first_record(self) -> None:
        records = list(iter_records([rec("a", ms=1500), rec("b", ms=4200)]))
        assert records[0].t_ms == 0
        assert records[1].t_ms == 2700

    def test_a_pgp_key_block_is_one_record(self, interner: Interner) -> None:
        log = main_log("lp2150319-main.log", interner)
        # 259 physical lines fold to far fewer logical records.
        assert log.record_count == 120
        assert len(log.events) == log.record_count

    def test_levels_are_mapped(self) -> None:
        levels = [
            r.level
            for r in iter_records(
                [rec("a", level=lv) for lv in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")]
            )
        ]
        assert levels == [
            Level.DEBUG,
            Level.INFO,
            Level.WARNING,
            Level.ERROR,
            Level.ERROR,
        ]


class TestAptMessageSplitting:
    """``W:`` is never a cause. This is the LP#2150319 misdirection.

    The upgrader flattens apt's whole message stack into one string, mixing a
    cosmetically alarming Google Chrome warning with the actual resolver error.
    The bug was triaged as a Chrome problem for that reason.
    """

    def test_the_chrome_warning_is_separated_from_the_real_error(self) -> None:
        stack = (
            "'W:Skipping acquire of configured file 'main/binary-i386/Packages' as "
            "repository 'https://dl.google.com/linux/chrome-stable/deb stable InRelease' "
            "doesn't support architecture 'i386', E:Error, pkgProblemResolver::Resolve "
            "generated breaks, this may be caused by held packages.'"
        )
        pieces = split_apt_messages(stack)
        assert len(pieces) == 2
        assert pieces[0].is_warning
        assert "dl.google.com" in pieces[0].text
        assert pieces[1].is_error
        assert pieces[1].text.startswith("Error, pkgProblemResolver::Resolve")

    def test_commas_inside_a_message_do_not_split_it(self) -> None:
        """The error text itself contains commas.

        Splitting on ``", "`` alone shreds "Error, pkgProblemResolver::Resolve
        generated breaks, this may be caused by held packages." into three.
        """
        pieces = split_apt_messages(
            "E:Error, pkgProblemResolver::Resolve generated breaks, this may be "
            "caused by held packages."
        )
        assert len(pieces) == 1
        assert pieces[0].text.endswith("held packages.")

    def test_a_prefix_inside_a_url_does_not_split(self) -> None:
        """``E:`` must be at a real boundary, not anywhere in the text."""
        pieces = split_apt_messages("W:Failed to fetch https://host/a,E:b/File.deb nope")
        assert len(pieces) == 1
        assert pieces[0].is_warning

    def test_many_warnings_then_one_error(self) -> None:
        pieces = split_apt_messages(
            "W:Ignoring file 'a.migrate' in directory '/etc/apt/sources.list.d/', "
            "W:Ignoring file 'b.migrate' in directory '/etc/apt/sources.list.d/', "
            "E:Unable to correct problems, you have held broken packages."
        )
        assert [p.is_error for p in pieces] == [False, False, True]

    def test_an_unprefixed_message_is_treated_as_an_error(self) -> None:
        """Erring toward causal is right here: an unprefixed message in an
        ``ERROR`` record is a failure, and dropping it would lose the cause."""
        pieces = split_apt_messages("'Not enough free space'")
        assert len(pieces) == 1
        assert pieces[0].is_error

    def test_empty_stack_yields_nothing(self) -> None:
        assert split_apt_messages("''") == ()
        assert split_apt_messages("") == ()

    def test_real_log_errors_exclude_warnings(self, interner: Interner) -> None:
        log = main_log("lp2150319-main.log", interner)
        assert len(log.apt_errors) == 1
        assert "pkgProblemResolver" in log.apt_errors[0].text
        assert len(log.apt_warnings) == 1
        assert "dl.google.com" in log.apt_warnings[0].text
        assert all("dl.google.com" not in e.text for e in log.apt_errors)

    def test_held_broken_packages_error_is_captured(self, interner: Interner) -> None:
        """LP#2150245 reports two errors and nine warnings."""
        log = main_log("lp2150245-main.log", interner)
        texts = [e.text for e in log.apt_errors]
        assert any("held broken packages" in t for t in texts)
        assert len(log.apt_warnings) == 9


class TestPhaseTracking:
    def test_markers_come_from_upgrader_source_strings(self) -> None:
        assert phase_for("running Quirks.StartUpgrade").phase is Phase.COMMIT
        assert phase_for("checkViewDepends()").phase is Phase.VIEW_DEPENDS
        assert phase_for("Upgradable, but held- back: x") is None

    def test_the_two_updates_are_distinguished_by_showerrors(self) -> None:
        """The first update's failures are swallowed; the second's are fatal."""
        first = phase_for("running doUpdate() (showErrors=False)")
        second = phase_for("running doUpdate() (showErrors=True)")
        assert first is not None and first.phase is Phase.INITIAL_UPDATE
        assert second is not None and second.phase is Phase.SECOND_UPDATE

    def test_phases_never_regress(self) -> None:
        """``openCache()`` recurs five times, the last after dpkg finished."""
        tracker = PhaseTracker()
        tracker.feed("running Quirks.StartUpgrade", 1)
        assert tracker.current is Phase.COMMIT
        assert tracker.feed("openCache()", 2) is Phase.COMMIT
        assert tracker.regressions == 1

    def test_exit_markers_do_not_advance_the_phase(self) -> None:
        tracker = PhaseTracker()
        tracker.feed("openCache()", 1)
        assert tracker.feed("/openCache(), new cache size 1234", 2) is Phase.CACHE_OPEN


class TestCommitBoundary:
    """``COMMIT`` decides whether the machine was modified, so it must be exact."""

    def test_a_quirk_commit_is_not_the_dist_upgrade_commit(self) -> None:
        """``MyCache.commit`` logs at INFO, and quirks call it.

        ``_maybe_prevent_flatpak_auto_removal`` commits during
        PostInitialUpdate. Treating that as ``COMMIT`` made LP#2150319 -- a
        resolver failure that never touched the system -- look like a
        half-finished upgrade.
        """
        assert phase_for("cache.commit()") is None

    def test_the_returned_variant_is_commit_specific(self) -> None:
        """Only ``doDistUpgrade`` logs ``cache.commit() returned``."""
        marker = phase_for("cache.commit() returned None")
        assert marker is not None and marker.phase is Phase.COMMIT

    @pytest.mark.parametrize(
        ("name", "phase", "committed"),
        [
            ("local-main.log", Phase.POST_INSTALL_SCRIPTS, True),
            ("lp2150245-main.log", Phase.CALCULATE, False),
            ("lp2150319-main.log", Phase.PRE_DIST_UPGRADE, False),
            ("lp2169028-main.log", Phase.PRE_DIST_UPGRADE, False),
            ("local-main-reexec.log", Phase.SCREEN_REEXEC, False),
        ],
    )
    def test_real_logs_land_in_the_right_phase(
        self, name: str, phase: Phase, committed: bool, interner: Interner
    ) -> None:
        log = main_log(name, interner)
        assert log.terminal_phase is phase
        assert log.reached_commit is committed

    def test_a_screen_reexec_is_not_a_failure(self, interner: Interner) -> None:
        """The log simply moves to a new file; nothing went wrong."""
        log = main_log("local-main-reexec.log", interner)
        assert log.terminal_phase is Phase.SCREEN_REEXEC
        assert not log.aborted
        assert not log.errors


class TestRunMetadata:
    def test_versions_and_releases(self, interner: Interner) -> None:
        log = main_log("lp2169028-main.log", interner)
        got = {k: interner.text(v) for k, v in log.meta.items()}
        assert got["apt_version"] == "2.8.3"
        assert got["python_version"] == "3.12.3"
        assert got["upgrader_version"] == "26.04.25"
        assert got["view"] == "DistUpgradeViewKDE"
        assert got["from_release"] == "noble"
        assert got["to_release"] == "resolute"
        assert got["kernel"] == "6.8.0-142-generic"

    def test_any_release_pair_is_handled(self, interner: Interner) -> None:
        """The tool is pointed at noble to resolute but must not assume it."""
        log = main_log("local-main.log", interner)
        assert interner.text(log.meta["from_release"]) == "resolute"
        assert interner.text(log.meta["to_release"]) == "stonking"

    def test_cache_sizes_are_collected(self, interner: Interner) -> None:
        log = main_log("lp2169028-main.log", interner)
        assert log.cache_sizes == [92231, 92231, 84775]

    def test_abort_is_detected(self, interner: Interner) -> None:
        assert main_log("lp2150319-main.log", interner).aborted
        assert not main_log("local-main.log", interner).aborted


class TestPackageLists:
    def test_the_held_back_typo_is_matched_exactly(self, interner: Interner) -> None:
        """``Upgradable, but held- back`` is spelled that way upstream."""
        log = main_log("local-main.log", interner)
        assert [interner.package_label(p) for p in log.held_back] == [
            "python3-cryptography-vectors"
        ]

    def test_full_delta_of_a_successful_run(self, interner: Interner) -> None:
        log = main_log("local-main.log", interner)
        assert len(log.packages["upgraded"]) == 932
        assert len(log.packages["installed"]) == 35
        assert len(log.packages["removed"]) == 2
        assert len(log.packages["kept"]) == 2138
        assert len(log.packages["obsolete"]) == 32

    def test_versions_in_parentheses_are_stripped(self, interner: Interner) -> None:
        log = parse_main_log([rec("Install: foo (1.2-3) bar (4.5)")], interner)
        assert [interner.package_label(p) for p in log.packages["installed"]] == [
            "foo",
            "bar",
        ]

    def test_an_empty_list_is_not_a_missing_list(self, interner: Interner) -> None:
        log = parse_main_log([rec("Obsolete: ")], interner)
        assert log.packages["obsolete"] == ()
        assert "obsolete" in log.packages


class TestForeignPackages:
    """The ``Foreign`` list is the upgrader's own third-party verdict.

    It feeds the ``Conflicts`` blame reorientation in
    :mod:`uru_doctor.apt.roots`, which is what makes LP#2150245 resolve to the
    PPA rather than to the Ubuntu package it broke.
    """

    def test_the_surface_ppa_is_reported_as_foreign(self, interner: Interner) -> None:
        log = main_log("lp2150245-main.log", interner)
        names = {interner.package_label(p) for p in log.foreign}
        assert "libwacom9-surface" in names
        assert "linux-image-surface" in names
        assert len(log.foreign) == 13

    def test_before_and_after_are_kept_apart(self, interner: Interner) -> None:
        """After the rewrite, archive packages look foreign too.

        One fixture's *after* list contains ``coreutils``, because at that
        point nothing has a resolute candidate yet. Using the wrong list would
        mark the entire archive third-party.
        """
        log = main_log("local-main.log", interner)
        before = {interner.package_label(p) for p in log.foreign}
        after = {interner.package_label(p) for p in log.foreign_after}
        assert before == {"acli", "firefox", "python3-ubuntu-lint", "ubuntu-lint"}
        assert "ca-certificates" in after
        assert "ca-certificates" not in before

    def test_no_third_party_sources_yields_an_empty_list(self, interner: Interner) -> None:
        log = main_log("lp2169028-main.log", interner)
        assert log.foreign == ()


class TestThirdPartyResolution:
    """Bridging the two logs' package-naming conventions.

    ``main.log`` writes ``libwacom9-surface``; the apt trace writes
    ``libwacom9-surface:amd64``. They intern to different ids, so the
    ``Foreign`` list has to be re-resolved against the names apt actually used
    before it can mark anything third-party.
    """

    def test_architecture_qualified_names_are_found(self, interner: Interner) -> None:
        log = main_log("lp2150245-main.log", interner)
        # Interning the arch-qualified form is what the apt log would do.
        qualified = interner.package("libwacom9-surface:amd64")

        resolved = resolve_third_party(log, interner)
        assert qualified in resolved
        assert len(resolved) > len(log.foreign)

    def test_resolution_is_a_superset_of_the_bare_list(self, interner: Interner) -> None:
        """Nothing is ever dropped, even when no architecture is found."""
        log = main_log("lp2150245-main.log", interner)
        resolved = resolve_third_party(log, interner)
        assert set(log.foreign) <= set(resolved)

    def test_resolution_is_idempotent(self, interner: Interner) -> None:
        log = main_log("lp2150245-main.log", interner)
        interner.package("libwacom9-surface:amd64")
        once = resolve_third_party(log, interner)
        assert resolve_third_party(log, interner) == once

    def test_an_explicit_architecture_is_not_widened(self, interner: Interner) -> None:
        """``i386`` orphans in bug 2169028 depend on the arch being distinct."""
        amd = interner.package("libfoo1:amd64")
        i386 = interner.package("libfoo1:i386")
        assert interner.packages_named("libfoo1:i386") == (i386,)
        assert set(interner.packages_named("libfoo1")) == {amd, i386}

    def test_an_empty_foreign_list_resolves_to_nothing(self, interner: Interner) -> None:
        log = main_log("lp2169028-main.log", interner)
        assert resolve_third_party(log, interner) == ()
