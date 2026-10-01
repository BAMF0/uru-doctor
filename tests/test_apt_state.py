"""Tests for apt's package-state blob.

The flag format is one apt explicitly reserves the right to change, and it
already differs between the apt 2.8 that a 24.04 upgrade runs and the apt 3.2
on a current development release. These tests pin the vocabulary that has been
observed so that a change in a future apt fails loudly here rather than
quietly degrading a diagnosis somewhere downstream.
"""

from __future__ import annotations

import pytest

from uru_doctor.apt.state import (
    InstallStatus,
    StateVocabulary,
    parse_state,
    parse_states,
    strip_states,
)
from uru_doctor.models import Mode, VerSelect

#: Every flag blob observed across apt 2.8.3 and apt 3.2.0 in six real logs.
#:
#: Three of these broke an earlier implementation and are the reason the decoder
#: classifies tokens by shape rather than by fixed position: ``@un H`` has no
#: mode-prefix group at all, ``@un pumN Ib`` has a four-character one, and
#: ``@pi ...`` carries a dpkg status pair that no enumeration of previously seen
#: pairs would have included.
OBSERVED_FLAGS: tuple[str, ...] = (
    "@ii umU Ib",
    "@un uN",
    "@ii gK",
    "@un uN Ib",
    "@ii gK Ib",
    "@ii mK Ib",
    "@ii mK",
    "@ii umU NPb IPb",
    "@ii mR",
    "@ii umH Ib",
    "@ii umU IPb",
    "@ii umR",
    "@ii mK NPb IPb",
    "@ii umU",
    "@ii mP",
    "@un uN IPb",
    "@un umN Ib",
    "@un umN",
    "@ii gK NPb IPb",
    "@un umH",
    "@ii umH",
    "@un uH",
    "@ii ugH Ib",
    "@ii ugH",
    "@un H",
    "@un mH",
    "@un pumN Ib",
    "@pi umR",
)


class TestVocabulary:
    """Every observed blob must decode with nothing left over."""

    @pytest.mark.parametrize("flags", OBSERVED_FLAGS)
    def test_decodes_without_unknown_tokens(self, flags: str) -> None:
        state = parse_state(f"< 1.0 -> 2.0 {flags} >")
        assert state is not None
        assert state.unknown_tokens == (), f"{flags} left {state.unknown_tokens} undecoded"

    @pytest.mark.parametrize("flags", OBSERVED_FLAGS)
    def test_decodes_mode_and_status(self, flags: str) -> None:
        state = parse_state(f"< 1.0 -> 2.0 {flags} >")
        assert state is not None
        assert state.mode is not Mode.UNKNOWN, f"{flags} gave no mode"
        assert state.status is not InstallStatus.UNKNOWN, f"{flags} gave no status"

    @pytest.mark.parametrize("flags", OBSERVED_FLAGS)
    def test_keeps_blob_verbatim(self, flags: str) -> None:
        """The raw blob survives decoding.

        This is the insurance policy: when apt emits something this build
        cannot interpret, the exact token is still recorded, still comparable
        and still usable for deduplication.
        """
        state = parse_state(f"< 1.0 -> 2.0 {flags} >")
        assert state is not None
        assert state.raw == flags

    def test_whole_vocabulary_reports_nothing_unknown(self) -> None:
        vocabulary = StateVocabulary()
        for flags in OBSERVED_FLAGS:
            parse_state(f"< 1.0 -> 2.0 {flags} >", vocabulary)
        assert not vocabulary.has_unknown, vocabulary.unknown


class TestUnknownTokensAreReported:
    """An unrecognised token is surfaced, never silently dropped."""

    def test_records_unknown(self) -> None:
        vocabulary = StateVocabulary()
        state = parse_state("< 1.0 @ii zzQ Xb >", vocabulary)
        assert state is not None
        assert "zzQ" in state.unknown_tokens
        assert "Xb" in state.unknown_tokens
        assert vocabulary.has_unknown

    def test_known_tokens_still_decode_alongside_unknown(self) -> None:
        """A partially-understood blob yields what it can.

        Degrading to "I got the status but not the rest" is strictly better
        than discarding the line.
        """
        state = parse_state("< 1.0 @ii WEIRD Ib >")
        assert state is not None
        assert state.status is InstallStatus.INSTALLED
        assert state.inst_broken
        assert state.unknown_tokens == ("WEIRD",)


class TestVersionSeparator:
    """The separator is the most informative token in the whole log."""

    def test_arrow_means_candidate_selected(self) -> None:
        state = parse_state("< 3.12.3-0ubuntu2.1 -> 3.14.3-0ubuntu2 @ii umU >")
        assert state is not None
        assert state.selection is VerSelect.SELECTED
        assert state.cur_version == "3.12.3-0ubuntu2.1"
        assert state.cand_version == "3.14.3-0ubuntu2"

    def test_pipe_means_candidate_declined(self) -> None:
        state = parse_state("< none | 1.23-2build2 @un uH >")
        assert state is not None
        assert state.selection is VerSelect.AVAILABLE_NOT_SELECTED
        assert state.cur_version is None
        assert state.cand_version == "1.23-2build2"

    def test_bare_version_has_no_candidate(self) -> None:
        state = parse_state("< 1.2.39-5build2 @ii mR >")
        assert state is not None
        assert state.selection is VerSelect.NONE
        assert state.cand_version is None

    def test_arrow_is_not_mistaken_for_the_closing_bracket(self) -> None:
        """Regression: ``->`` contains ``>``.

        An earlier pattern excluded ``>`` from the version field, so the arrow
        terminated the match, the flag blob was never seen, and every package
        actually being upgraded decoded as mode UNKNOWN -- silently breaking the
        common case while the rarer non-upgrade cases kept working.
        """
        state = parse_state("< 1.0 -> 2.0 @ii umU Ib >")
        assert state is not None
        assert state.mode is Mode.UPGRADE
        assert state.raw == "@ii umU Ib"

    def test_epoch_colons_survive(self) -> None:
        state = parse_state("< 4:24.2.7-0ubuntu0.24.04.6 | 4:26.2.5.2-0ubuntu0.26.04.1 @ii umR >")
        assert state is not None
        assert state.cur_version == "4:24.2.7-0ubuntu0.24.04.6"
        assert state.cand_version == "4:26.2.5.2-0ubuntu0.26.04.1"


class TestDiagnosticPredicates:
    """The derived properties the root-cause rules actually branch on."""

    def test_blocks_as_new_dependency(self) -> None:
        """``< none | cand @un uH >`` is the holdback signature.

        This exact state on ``libfile-libmagic-perl`` is what stalled every
        24.04-to-26.04 upgrade with lintian installed.
        """
        state = parse_state("< none | 1.23-2build2 @un uH >")
        assert state is not None
        assert state.blocks_as_new_dependency
        assert not state.is_unsatisfiable_virtual

    def test_unsatisfiable_virtual(self) -> None:
        """``< none @un H >`` is a dependency nothing provides."""
        state = parse_state("< none @un H >")
        assert state is not None
        assert state.is_unsatisfiable_virtual
        assert not state.blocks_as_new_dependency

    def test_installed_and_held_is_neither(self) -> None:
        """An installed held package is a third, distinct situation.

        It needs permission to upgrade, not to be installed, so it must not
        satisfy the new-dependency predicate.
        """
        state = parse_state("< 13.6.0-1build2 | 13.11.0-1build1 @ii umH >")
        assert state is not None
        assert not state.blocks_as_new_dependency
        assert not state.is_unsatisfiable_virtual
        assert state.has_unselected_candidate
        assert state.is_installed

    def test_broken_bits(self) -> None:
        state = parse_state("< 1.0 @ii mK Ib >")
        assert state is not None
        assert state.inst_broken
        assert not state.now_broken
        assert state.any_broken

    def test_garbage_prefix_marks_auto_installed(self) -> None:
        from uru_doctor.models import NodeBits

        state = parse_state("< 1.0 @ii gK >")
        assert state is not None
        assert state.bits & (1 << NodeBits.AUTO_INSTALLED)


class TestDpkgStatusPairs:
    """The leading field is dpkg's desired/current pair, decoded by rule."""

    @pytest.mark.parametrize(
        ("token", "expected"),
        [
            ("ii", InstallStatus.INSTALLED),
            ("un", InstallStatus.NOT_INSTALLED),
            ("rc", InstallStatus.NOT_INSTALLED),
            ("pi", InstallStatus.INSTALLED),
            ("iU", InstallStatus.UNKNOWN),
            ("iu", InstallStatus.HALF_CONFIGURED),
            ("hi", InstallStatus.INSTALLED),
            ("if", InstallStatus.HALF_CONFIGURED),
        ],
    )
    def test_decodes_pair(self, token: str, expected: InstallStatus) -> None:
        state = parse_state(f"< 1.0 @{token} umU >")
        assert state is not None
        assert state.status is expected

    def test_rejects_a_non_status_leading_token(self) -> None:
        """A token that is not a valid pair is reported, not guessed at."""
        state = parse_state("< 1.0 @qq umU >")
        assert state is not None
        assert state.status is InstallStatus.UNKNOWN
        assert "qq" in state.unknown_tokens


class TestMultipleStates:
    """Some lines carry two state expressions."""

    LINE = (
        "Upgrading: libfoo:amd64 < 1.0 | 2.0 @ii umH > due to libbar:amd64"
        " Depends on libbaz:amd64 < 3.0 -> 4.0 @ii umU Ib > (= 4.0)"
    )

    def test_parses_both(self) -> None:
        states = parse_states(self.LINE)
        assert len(states) == 2
        assert states[0].mode is Mode.HOLD
        assert states[1].mode is Mode.UPGRADE

    def test_strip_leaves_prose_and_packages(self) -> None:
        """Stripping states is what lets the grammar match a short skeleton.

        Verb recognition then survives a change to the state format, which is
        the format apt reserves the right to change.
        """
        skeleton = " ".join(strip_states(self.LINE).split())
        assert skeleton == (
            "Upgrading: libfoo:amd64 due to libbar:amd64"
            " Depends on libbaz:amd64 (= 4.0)"
        )


class TestAbsentState:
    def test_no_state_expression_returns_none(self) -> None:
        assert parse_state("Entering ResolveByKeep") is None

    def test_empty_brackets_do_not_crash(self) -> None:
        state = parse_state("< >")
        assert state is not None
        assert state.cur_version is None
        assert state.mode is Mode.UNKNOWN
