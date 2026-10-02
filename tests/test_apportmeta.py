"""Tests for :mod:`uru_doctor.parsers.apportmeta`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from uru_doctor.models import LogSource, ProblemType
from uru_doctor.parsers.apportmeta import (
    ApportMeta,
    attachment_source,
    is_irrelevant_attachment,
    normalise_attachment_name,
    parse_apport_fields,
    parse_apport_meta,
    sniff_source,
)

from .conftest import FIXTURES, fixture_text


def lp_bug(bug_id: str) -> dict[str, object]:
    return json.loads((FIXTURES / "lp" / f"bug{bug_id}.json").read_text())


def meta(bug_id: str) -> ApportMeta:
    payload = lp_bug(bug_id)
    return parse_apport_meta(
        str(payload["description"]),
        tags=list(payload["tags"]),  # type: ignore[arg-type]
    )


class TestAttachmentNaming:
    """Names come from the apport hook, not from the filenames.

    The hook is
    ``/usr/share/apport/package-hooks/source_ubuntu-release-upgrader.py``.
    """

    @pytest.mark.parametrize(
        ("title", "expected"),
        [
            ("VarLogDistupgradeAptlog.txt", LogSource.APT),
            ("VarLogDistupgradeMainlog.txt", LogSource.MAIN),
            ("VarLogDistupgradeApttermlog.txt", LogSource.APT_TERM),
            ("VarLogDistupgradeTermlog.txt", LogSource.TERM),
            ("VarLogDistupgradeScreenlog.txt", LogSource.SCREENLOG),
            ("VarLogDistupgradeXorgFixuplog.txt", LogSource.XORG_FIXUP),
        ],
    )
    def test_canonical_hook_keys(self, title: str, expected: LogSource) -> None:
        assert attachment_source(title) is expected

    def test_history_has_an_interposed_apt(self) -> None:
        """``history.log`` is attached as ``VarLogDistupgradeAptHistorylog``.

        The ``Apt`` is not in the filename, so any rule that derives the key
        from the path gets this one wrong and silently loses the log.
        """
        assert attachment_source("VarLogDistupgradeAptHistorylog.txt") is LogSource.HISTORY
        assert attachment_source("VarLogDistupgradeHistorylog.txt") is LogSource.HISTORY

    def test_the_doubled_txt_suffix(self) -> None:
        """apport appends ``.txt``, so ``CurrentDmesg.txt`` doubles it.

        Two of the three sample bugs show ``CurrentDmesg.txt.txt`` and one
        shows ``CurrentDmesg.txt``.
        """
        assert normalise_attachment_name("CurrentDmesg.txt.txt") == "currentdmesg"
        assert normalise_attachment_name("CurrentDmesg.txt") == "currentdmesg"
        assert is_irrelevant_attachment("CurrentDmesg.txt.txt")
        assert is_irrelevant_attachment("CurrentDmesg.txt")

    def test_a_txt_inside_the_key_is_not_stripped(self) -> None:
        """``VarLogDistupgradeLspcitxt`` ends in ``txt`` without a dot.

        Stripping bare ``txt`` rather than ``.txt`` would corrupt the key.
        """
        assert normalise_attachment_name("VarLogDistupgradeLspcitxt.txt") == (
            "varlogdistupgradelspcitxt"
        )

    def test_hand_attached_plain_filenames(self) -> None:
        """One fixture's reporter attached a bare ``main.log``."""
        assert attachment_source("main.log") is LogSource.MAIN
        assert attachment_source("apt.log") is LogSource.APT
        assert attachment_source("screenlog.0") is LogSource.SCREENLOG
        assert attachment_source("/tmp/foo/apt-term.log") is LogSource.APT_TERM

    def test_a_sentence_title_is_unknown_not_irrelevant(self) -> None:
        """A real attachment is titled with its own diagnosis.

        ``Holding Back lintian rather than change libfile-libmagic-perl`` is a
        genuine apt log excerpt. It must be sniffed, not discarded.
        """
        title = "Holding Back lintian rather than change libfile-libmagic-perl"
        assert attachment_source(title) is None
        assert not is_irrelevant_attachment(title)

    def test_known_noise_is_skipped_without_downloading(self) -> None:
        """Avoiding fetches matters: the LP API answers 429 under load."""
        for title in (
            "Dependencies.txt",
            "JournalErrors.txt",
            "ProcCpuinfoMinimal.txt",
            "VarLogDistupgradeAptclonesystemstate.tar.gz",
            "VarLogDistupgradeLspcitxt.txt",
        ):
            assert is_irrelevant_attachment(title), title
            assert attachment_source(title) is None

    def test_images_are_skipped(self) -> None:
        assert is_irrelevant_attachment("image.png")
        assert is_irrelevant_attachment("Screenshot from 2026-04-25.PNG")
        assert not is_irrelevant_attachment("main.log")


class TestContentSniffing:
    """Titles are unreliable, so content decides."""

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("apt/lp2169028-apt.log", LogSource.APT),
            ("apt/local-apt3-success.log", LogSource.APT),
            ("logs/local-main.log", LogSource.MAIN),
            ("logs/lp2150245-main.log", LogSource.MAIN),
            ("logs/local-history.log", LogSource.HISTORY),
        ],
    )
    def test_real_logs_are_recognised(self, path: str, expected: LogSource) -> None:
        assert sniff_source(fixture_text(path)) is expected

    def test_an_apt_excerpt_without_a_banner_is_still_apt(self) -> None:
        """The sentence-titled attachment is an excerpt with no ``Log time:``."""
        excerpt = (
            "  Investigating (0) lintian:amd64 < 2.117.0ubuntu1 -> 2.121.0 @ii umU >\n"
            "  Broken lintian:amd64 Depends on libfile-libmagic-perl:amd64 < none >\n"
            "  Holding Back lintian rather than change libfile-libmagic-perl\n"
        )
        assert sniff_source(excerpt) is LogSource.APT

    def test_prose_is_not_a_log(self) -> None:
        assert sniff_source("I tried to upgrade and it broke. Please help.") is None
        assert sniff_source("") is None


class TestFieldParsing:
    def test_preamble_is_separated_from_fields(self) -> None:
        """The reporter's own words must never be mistaken for a field."""
        preamble, fields = parse_apport_fields(
            "I tried to upgrade.\nIt failed.\n\nProblemType: Bug\nPackage: foo 1.0\n"
        )
        assert preamble == "I tried to upgrade.\nIt failed."
        assert fields == {"ProblemType": "Bug", "Package": "foo 1.0"}

    def test_continuation_lines_fold_in(self) -> None:
        preamble, fields = parse_apport_fields(
            "ProcEnviron:\n LANG=en_GB.UTF-8\n SHELL=/bin/bash\nSourcePackage: x\n"
        )
        assert preamble == ""
        assert fields["ProcEnviron"] == "LANG=en_GB.UTF-8\nSHELL=/bin/bash"
        assert fields["SourcePackage"] == "x"

    def test_a_key_with_an_empty_value_is_still_a_key(self) -> None:
        """apport inlines attachment keys with no value."""
        _, fields = parse_apport_fields("VarLogDistupgradeApttermlog:\nPackage: x 1\n")
        assert fields["VarLogDistupgradeApttermlog"] == ""
        assert "VarLogDistupgradeApttermlog" in fields

    def test_a_blank_line_does_not_end_the_field_block(self) -> None:
        """apport emits blank lines mid-report; stopping there truncates it."""
        _, fields = parse_apport_fields("ProblemType: Bug\n\nSourcePackage: foo\n")
        assert fields["SourcePackage"] == "foo"

    def test_colons_in_values_survive(self) -> None:
        _, fields = parse_apport_fields("CurrentDesktop: ubuntu:GNOME\n")
        assert fields["CurrentDesktop"] == "ubuntu:GNOME"

    def test_an_epoch_version_survives(self) -> None:
        _, fields = parse_apport_fields("Package: ubuntu-release-upgrader-core 1:24.04.28\n")
        assert fields["Package"] == "ubuntu-release-upgrader-core 1:24.04.28"


class TestRealApportMetadata:
    def test_surface_bug_fields(self) -> None:
        got = meta("2150245")
        assert got.problem_type is ProblemType.BUG
        assert got.package == "ubuntu-release-upgrader-core"
        assert got.package_version == "1:24.04.28"
        assert got.source_package == "ubuntu-release-upgrader"
        assert got.distro_release == "24.04"
        assert got.architecture == "amd64"
        assert got.current_desktop == "ubuntu:GNOME"
        assert "dist-upgrade" in got.tags

    def test_multiline_values_are_preserved(self) -> None:
        got = meta("2150245")
        assert len(got.fields["ProcEnviron"].splitlines()) == 5
        assert len(got.fields["CrashReports"].splitlines()) == 3

    def test_the_reporters_own_words_are_kept(self) -> None:
        got = meta("2150245")
        assert got.preamble.startswith("Ubuntu 24.04 lts")
        assert "aborted" in got.preamble

    def test_an_sru_groomed_description_still_parses(self) -> None:
        """LP#2150319's description was rewritten for the SRU process.

        The ``[ Impact ]`` template lands in the preamble and the apport fields
        below it survive.
        """
        got = meta("2150319")
        assert got.preamble.startswith("[ Impact ]")
        assert got.distro_release == "24.04"
        assert got.problem_type is ProblemType.BUG


class TestThirdPartyKernel:
    """Independent of the apt log, and of ``main.log``'s ``Foreign`` list.

    ``/proc/version_signature`` is created by Ubuntu's kernel packaging, and
    the apport hook attaches it only ``if_exists``. So an absent field means a
    kernel Ubuntu did not build.
    """

    def test_the_surface_kernel_is_detected(self) -> None:
        got = meta("2150245")
        assert got.kernel_release == "6.18.7-surface-1"
        assert not got.has_version_signature
        assert got.has_third_party_kernel

    @pytest.mark.parametrize("bug_id", ["2150319", "2169028"])
    def test_ubuntu_kernels_are_not_flagged(self, bug_id: str) -> None:
        got = meta(bug_id)
        assert got.has_version_signature
        assert got.version_signature.startswith("Ubuntu ")
        assert not got.has_third_party_kernel

    def test_the_uname_whitelist_is_the_backstop(self) -> None:
        """When the signature field was edited away, the flavour decides."""
        assert not ApportMeta(kernel_release="6.8.0-142-generic").has_third_party_kernel
        assert not ApportMeta(kernel_release="6.8.0-51-lowlatency").has_third_party_kernel
        assert ApportMeta(kernel_release="6.18.7-surface-1").has_third_party_kernel
        assert ApportMeta(kernel_release="6.11.0-xanmod1").has_third_party_kernel

    def test_an_unknown_kernel_is_not_guessed_at(self) -> None:
        assert not ApportMeta().has_third_party_kernel

    def test_a_non_ubuntu_signature_outranks_a_plausible_uname(self) -> None:
        """The stronger signal wins when the two disagree."""
        got = ApportMeta(
            kernel_release="6.8.0-142-generic",
            version_signature="Debian 6.8.0-1",
            has_version_signature=True,
        )
        assert got.has_third_party_kernel


class TestDerivedContext:
    def test_installation_media_release(self) -> None:
        assert meta("2150245").installation_release == "24.04"
        assert meta("2150319").installation_release == "22.04"

    def test_a_kubuntu_flavour_is_parsed(self) -> None:
        """``Kubuntu 23.10 "Mantic Minotaur"``."""
        assert meta("2169028").installation_release == "23.10"

    def test_chained_upgrades_are_noticed_but_not_blamed(self) -> None:
        assert meta("2150319").is_chained_upgrade
        assert meta("2169028").is_chained_upgrade
        assert not meta("2150245").is_chained_upgrade

    def test_declared_attachments_cross_check_the_list(self) -> None:
        """apport inlines the keys, so the description says what should exist."""
        assert set(meta("2150319").declared_attachments) == {
            "VarLogDistupgradeAptHistorylog",
            "VarLogDistupgradeApttermlog",
        }

    def test_media_check_pass_and_skip_are_both_fine(self) -> None:
        assert not ApportMeta(casper_md5="pass").media_check_failed
        assert not ApportMeta(casper_md5="skip").media_check_failed
        assert not ApportMeta().media_check_failed
        assert ApportMeta(casper_md5="fail").media_check_failed

    def test_all_real_bugs_passed_their_media_check(self) -> None:
        for bug_id in ("2150245", "2150319", "2169028"):
            assert not meta(bug_id).media_check_failed


class TestProblemTypeParsing:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Bug", ProblemType.BUG),
            ("Crash", ProblemType.CRASH),
            ("Package", ProblemType.PACKAGE),
            ("  crash  ", ProblemType.CRASH),
            ("PACKAGE", ProblemType.PACKAGE),
            ("nonsense", ProblemType.UNKNOWN),
            ("", ProblemType.UNKNOWN),
            (None, ProblemType.UNKNOWN),
        ],
    )
    def test_parse_is_tolerant(self, raw: str | None, expected: ProblemType) -> None:
        """A field anyone can edit must not be able to abort the analysis."""
        assert ProblemType.parse(raw) is expected


def test_every_lp_fixture_is_parseable() -> None:
    """Guards the fixtures themselves against a bad regeneration.

    Asserts only what is true of all of them. An earlier version hardcoded
    three fixtures all on 24.04, which broke the moment the corpus grew to
    include questing reports and one bug that attached no logs at all.
    """
    paths = sorted((FIXTURES / "lp").glob("*.json"))
    assert len(paths) >= 3
    for path in paths:
        payload = json.loads(path.read_text())
        got = parse_apport_meta(payload["description"], tags=payload["tags"])
        assert got.preamble, f"{path.name} has no reporter text"
        # Every bug filed by apport names a release and a source package. The
        # one hand-filed report in the corpus (LP#2161332, two screenshots)
        # has neither, which is itself the thing its fixture exercises.
        if got.problem_type is not ProblemType.UNKNOWN:
            assert got.source_package == "ubuntu-release-upgrader"
            assert got.distro_release
            assert got.architecture


def test_the_release_spread_is_covered() -> None:
    """The corpus must not silently narrow to one source release.

    apt 2.8 (noble) and apt 3.x (questing) have different debug vocabularies,
    so a corpus that drifted to one of them would stop testing the other.
    """
    releases = set()
    for path in sorted((FIXTURES / "lp").glob("*.json")):
        payload = json.loads(path.read_text())
        got = parse_apport_meta(payload["description"], tags=payload["tags"])
        if got.distro_release:
            releases.add(got.distro_release)
    assert {"24.04", "25.10"} <= releases


def test_fixtures_contain_no_absolute_home_paths() -> None:
    """The LP fixtures are redacted like the logs are."""
    for path in sorted((FIXTURES / "lp").glob("*.json")):
        text = path.read_text()
        assert "/home/" not in text or "/home/user" in text
        assert Path.home().name not in text
