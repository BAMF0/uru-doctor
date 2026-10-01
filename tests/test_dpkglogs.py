"""Tests for :mod:`uru_doctor.parsers.history` and
:mod:`uru_doctor.parsers.aptterm`."""

from __future__ import annotations

from datetime import datetime

import pytest

from uru_doctor.parsers.aptterm import FailureKind, parse_apt_term
from uru_doctor.parsers.history import parse_history, parse_package_list

from .conftest import fixture_text


def history(name: str = "local-history.log"):
    return parse_history(fixture_text(f"logs/{name}").splitlines())


def term(name: str):
    return parse_apt_term(fixture_text(f"logs/{name}").splitlines())


class TestPackageListParsing:
    """Commas appear *inside* the parentheses, so the list cannot be split."""

    def test_an_upgrade_carries_both_versions(self) -> None:
        changes = parse_package_list("openvpn:amd64 (2.7.0-1ubuntu1.1, 2.7.3-1ubuntu2)")
        assert len(changes) == 1
        assert changes[0].name == "openvpn:amd64"
        assert changes[0].previous == "2.7.0-1ubuntu1.1"
        assert changes[0].version == "2.7.3-1ubuntu2"
        assert changes[0].is_upgrade
        assert not changes[0].automatic

    def test_automatic_is_not_a_version(self) -> None:
        changes = parse_package_list("libzxing4:amd64 (3.0.2+ds-2, automatic)")
        assert changes[0].version == "3.0.2+ds-2"
        assert changes[0].previous == ""
        assert changes[0].automatic

    def test_splitting_on_commas_would_shred_the_list(self) -> None:
        """Three entries, six commas. A naive split yields six fragments."""
        changes = parse_package_list("a:amd64 (1.0, automatic), b:amd64 (2.0, 2.1), c:i386 (3.0)")
        assert [c.name for c in changes] == ["a:amd64", "b:amd64", "c:i386"]
        assert changes[1].is_upgrade
        assert changes[2].version == "3.0"

    def test_epoch_and_tilde_versions_survive(self) -> None:
        changes = parse_package_list("firefox:amd64 (1:140.0+build1~ubuntu1, 2:141.0~b1)")
        assert changes[0].previous == "1:140.0+build1~ubuntu1"
        assert changes[0].version == "2:141.0~b1"

    def test_an_empty_field_yields_nothing(self) -> None:
        assert parse_package_list("") == ()
        assert parse_package_list("   ") == ()


class TestHistoryStanzas:
    def test_two_space_date_separator(self) -> None:
        """apt writes ``Start-Date: 2026-06-23  11:13:22`` with two spaces."""
        log = history()
        assert log.transactions[0].start == datetime(2026, 6, 23, 11, 13, 22)
        assert log.transactions[0].end == datetime(2026, 6, 23, 11, 13, 23)

    def test_real_transaction_contents(self) -> None:
        log = history()
        first = log.transactions[0]
        assert len(first.changes["Install"]) == 35
        assert len(first.changes["Upgrade"]) == 932
        assert len(first.changes["Remove"]) == 2
        assert first.total_changes == 969
        assert not first.failed

    def test_requested_by_is_redacted_but_present(self) -> None:
        assert history().transactions[0].requested_by.startswith("redacted-user")

    def test_names_spans_fields_in_order(self) -> None:
        names = history().transactions[0].names("Install", "Remove")
        assert len(names) == 37
        assert "libjpeg-turbo8:amd64" in names


class TestDuplicateTransactions:
    """One attempt can produce several identical transactions.

    The upgrader commits, reopens the cache, re-runs its planning quirks and
    commits again. apt writes a full history entry from the *planned* state
    each time, so the same 969 packages appear twice -- once for 0.68s and once
    for fourteen minutes.
    """

    def test_the_file_holds_two_identical_transactions(self) -> None:
        log = history()
        assert len(log.transactions) == 2
        first, second = log.transactions
        assert first.names() == second.names()
        assert first.duration_s < 2
        assert second.duration_s > 800

    def test_collapsing_removes_the_double_count(self) -> None:
        log = history()
        assert sum(t.total_changes for t in log.transactions) == 1938
        assert sum(t.total_changes for t in log.collapsed) == 969

    def test_collapsing_keeps_the_transaction_that_did_the_work(self) -> None:
        """969 packages in 0.68 seconds is not physically possible."""
        kept = history().collapsed
        assert len(kept) == 1
        assert kept[0].duration_s > 800

    def test_distinct_transactions_are_not_collapsed(self) -> None:
        log = parse_history(
            [
                "Start-Date: 2026-01-01  10:00:00",
                "Install: a:amd64 (1.0)",
                "End-Date: 2026-01-01  10:00:05",
                "",
                "Start-Date: 2026-01-01  11:00:00",
                "Install: b:amd64 (1.0)",
                "End-Date: 2026-01-01  11:00:05",
            ]
        )
        assert len(log.collapsed) == 2


class TestStaleTransactions:
    """``history.log`` survives from one release upgrade to the next.

    A bug whose ``UpgradeStatus`` says ``Upgraded to noble`` ships a
    ``history.log`` containing that earlier successful upgrade as well as the
    failed attempt. Reading the file as a whole and concluding "packages were
    installed" misreports a planning failure as a half-upgraded system.
    """

    def test_an_older_transaction_is_excluded(self) -> None:
        log = history()
        window_start = datetime(2026, 6, 23, 11, 13, 20)
        window_end = datetime(2026, 6, 23, 11, 30, 0)
        assert len(log.within(window_start, window_end)) == 2

        # A window a year later must match nothing.
        assert (
            log.within(
                datetime(2027, 6, 23, 11, 0, 0),
                datetime(2027, 6, 23, 12, 0, 0),
            )
            == []
        )

    def test_clock_skew_is_tolerated(self) -> None:
        log = history()
        # Window starts four minutes after the transaction did.
        assert log.within(
            datetime(2026, 6, 23, 11, 17, 0),
            datetime(2026, 6, 23, 11, 30, 0),
        )

    def test_no_window_keeps_everything(self) -> None:
        """Being unable to establish staleness is not a reason to discard."""
        log = history()
        assert len(log.within(None, None)) == len(log.transactions)


class TestTermBlockFraming:
    """A non-empty block is the only reliable proof that dpkg ran."""

    def test_the_successful_run_has_one_empty_and_one_real_block(self) -> None:
        log = term("local-aptterm-success.log")
        assert len(log.blocks) == 2
        assert log.blocks[0].is_empty
        assert not log.blocks[1].is_empty
        assert log.blocks[1].line_count > 3000

    def test_blank_lines_between_blocks_are_not_blocks(self) -> None:
        """The file opens with a blank line and separates blocks with one.

        Counting those as blocks invented two phantom empty blocks per file,
        which would then be mistaken for the genuine empty block that proves a
        no-op commit.
        """
        log = term("local-aptterm-success.log")
        assert len(log.blocks) == 2
        assert all(b.start is not None for b in log.blocks)

    def test_the_empty_block_is_a_real_no_op_commit(self) -> None:
        log = term("local-aptterm-success.log")
        empty = log.blocks[0]
        assert empty.duration_s == pytest.approx(1.0)
        assert empty.configured == 0
        assert empty.unpacked == 0

    def test_dpkg_ran_ignores_the_empty_block(self) -> None:
        log = term("local-aptterm-success.log")
        assert log.dpkg_ran
        assert len(log.substantive) == 1

    def test_an_unframed_excerpt_is_still_parsed(self) -> None:
        """Hand-attached excerpts have no ``Log started:`` line."""
        log = parse_apt_term(
            [
                "dpkg: error processing package foo (--configure):",
                " installed foo package post-installation script"
                " subprocess returned error exit status 1",
            ]
        )
        assert len(log.blocks) == 1
        assert len(log.roots) == 1

    def test_a_block_that_never_closes_is_truncated(self) -> None:
        log = parse_apt_term(["Log started: 2026-01-01  10:00:00", "Setting up foo (1.0) ..."])
        assert log.truncated
        assert log.blocks[0].truncated

    def test_a_log_with_only_empty_blocks_means_nothing_was_written(self) -> None:
        log = parse_apt_term(
            [
                "",
                "Log started: 2026-01-01  10:00:00",
                "Log ended: 2026-01-01  10:00:01",
                "",
            ]
        )
        assert len(log.blocks) == 1
        assert not log.dpkg_ran


class TestDpkgCascade:
    """The reference cascade: one root, thirty-four victims.

    ``python3``'s postinst fails because a byte-compile hook chokes on a
    non-UTF-8 file shipped by ``llvm-21-tools``; everything depending on
    ``python3`` is then left unconfigured.
    """

    def test_one_root_and_thirty_four_victims(self) -> None:
        log = term("local-aptterm-dpkgfail.log")
        assert len(log.failures) == 35
        assert len(log.roots) == 1
        assert log.roots[0].package == "python3"

    def test_victims_are_identified_by_their_reason_line(self) -> None:
        log = term("local-aptterm-dpkgfail.log")
        block = log.blocks[0]
        assert len(block.victims) == 34
        assert all(v.kind == FailureKind.DEPENDENCY for v in block.victims)
        assert all("dependency problems" in v.reason for v in block.victims)

    def test_the_summary_does_not_distinguish_roots_from_victims(self) -> None:
        """``Errors were encountered while processing:`` lists all 35.

        Trusting it would report thirty-five separate faults.
        """
        log = term("local-aptterm-dpkgfail.log")
        assert len(log.blocks[0].summary) == 35
        assert "python3" in log.blocks[0].summary
        assert "sssd-common" in log.blocks[0].summary

    def test_the_root_reason_and_exit_status(self) -> None:
        root = term("local-aptterm-dpkgfail.log").roots[0]
        assert root.kind == FailureKind.MAINTAINER_SCRIPT
        assert root.exit_status == 4
        assert root.action == "--configure"
        assert "postinst maintainer script" in root.reason

    def test_blame_is_redirected_to_the_hook_package(self) -> None:
        """``python3`` ran the hook; ``llvm-21-tools`` shipped the broken file.

        Reporting ``python3`` would send everyone to the wrong package, which
        is what the raw dpkg output invites.
        """
        root = term("local-aptterm-dpkgfail.log").roots[0]
        assert root.package == "python3"
        assert root.blamed_package == "llvm-21-tools"
        assert root.culprit == "llvm-21-tools"

    def test_syntax_warnings_never_reach_the_reason(self) -> None:
        """Twenty ``SyntaxWarning`` lines sit directly above the real error.

        They name ``hplip`` files and are entirely innocent -- the apt-term
        analogue of the Chrome ``W:`` misdirection in ``main.log``.
        """
        log = term("local-aptterm-dpkgfail.log")
        for failure in log.failures:
            assert "SyntaxWarning" not in failure.reason
            assert "hplip/pcard" not in failure.reason


class TestFailureClassification:
    def test_a_file_conflict_names_the_other_package(self) -> None:
        log = parse_apt_term(
            [
                "dpkg: error processing archive /var/cache/apt/archives/foo_1.0.deb (--unpack):",
                " trying to overwrite '/usr/bin/thing', which is also in package bar-ppa 2.0",
            ]
        )
        failure = log.roots[0]
        assert failure.kind == FailureKind.FILE_CONFLICT
        assert failure.conflicting_package == "bar-ppa"
        assert failure.conflicting_path == "/usr/bin/thing"
        assert failure.archive.endswith("foo_1.0.deb")
        assert failure.package == ""

    def test_a_dependency_victim_is_not_a_root(self) -> None:
        log = parse_apt_term(
            [
                "dpkg: error processing package sssd (--configure):",
                " dependency problems - leaving unconfigured",
            ]
        )
        assert log.roots == ()
        assert log.failures[0].is_victim

    def test_unprocessed_triggers_are_also_victims(self) -> None:
        log = parse_apt_term(
            [
                "dpkg: error processing package gnome-menus (--configure):",
                " dependency problems - leaving triggers unprocessed",
            ]
        )
        assert log.roots == ()

    def test_an_unrecognised_reason_is_still_reported(self) -> None:
        """A reason we cannot classify must not be silently dropped."""
        log = parse_apt_term(
            [
                "dpkg: error processing package foo (--configure):",
                " something nobody has seen before",
            ]
        )
        assert len(log.roots) == 1
        assert log.roots[0].kind == FailureKind.OTHER
        assert log.roots[0].reason == "something nobody has seen before"

    def test_a_hook_failure_does_not_redirect_a_dependency_victim(self) -> None:
        """A stray hook line must not invent a culprit for unrelated failures."""
        log = parse_apt_term(
            [
                "error running python rtupdate hook some-package",
                "dpkg: error processing package victim (--configure):",
                " dependency problems - leaving unconfigured",
            ]
        )
        assert log.failures[0].blamed_package == ""
        assert log.failures[0].culprit == "victim"

    def test_subprocess_exit_code_is_captured(self) -> None:
        log = parse_apt_term(
            [
                "Log started: 2026-01-01  10:00:00",
                "E: Sub-process /usr/bin/dpkg returned an error code (1)",
                "Log ended: 2026-01-01  10:00:01",
            ]
        )
        assert log.blocks[0].subprocess_code == 1

    def test_counts_exclude_diversions(self) -> None:
        """``Removing 'diversion of ...'`` is not a package removal."""
        log = parse_apt_term(
            [
                "Removing diversion of /lib/foo to /lib/foo.distrib by bar",
                "Removing old-package (1.0) ...",
            ]
        )
        assert log.blocks[0].removed == 1


class TestXorgFixup:
    def test_the_trivial_log_says_nothing_went_wrong(self) -> None:
        text = fixture_text("logs/local-xorg-fixup.log")
        assert "No xorg.conf, exiting" in text
        assert "Traceback" not in text
