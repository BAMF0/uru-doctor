# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for the ``apt.log`` lexer and grammar.

The central test here is :class:`TestRealLogCoverage`, which asserts that every
line of every recorded log is recognised. That is a strong claim and it is
deliberately strong: the grammar was built from six real logs and was *still*
incomplete at four separate points during development, each gap found by the
unclassified-line reporter rather than by inspection. Pinning coverage at 100%
means the next gap fails a test instead of silently producing a worse
diagnosis.

The claim is defensible because the grammar is closed. The upgrader enables
exactly three apt debug streams and no others, so the set of line shapes is
finite and enumerable rather than open-ended.
"""

from __future__ import annotations

import pytest

from tests.conftest import APT_FIXTURES, apt_log, fixture_text
from uru_doctor.apt.grammar import Dialect, Verb, variant_for_version
from uru_doctor.apt.lexer import LexStats, dialect_of, lex, lex_line, measure_depth
from uru_doctor.models import AptStream, DepType


def lex_all(text: str) -> tuple[list, LexStats]:
    stats = LexStats()
    tokens = list(lex(text.splitlines(), stats))
    return (tokens, stats)


class TestRealLogCoverage:
    """Every line of every recorded log must be recognised."""

    @pytest.mark.parametrize(("relative", "dialect"), APT_FIXTURES)
    def test_full_coverage(self, relative: str, dialect: str) -> None:
        _, stats = lex_all(fixture_text(relative))
        assert stats.unmatched == 0, (
            f"{relative}: {stats.unmatched} unrecognised line(s)\n"
            + "\n".join(f"  {count:5}x {shape}" for shape, count in stats.top_unknown(10))
        )

    @pytest.mark.parametrize(("relative", "dialect"), APT_FIXTURES)
    def test_no_unknown_state_tokens(self, relative: str, dialect: str) -> None:
        """No flag token in any real log goes undecoded."""
        _, stats = lex_all(fixture_text(relative))
        assert not stats.vocabulary.has_unknown, (
            f"{relative}: undecoded state tokens {stats.vocabulary.unknown}"
        )

    @pytest.mark.parametrize(("relative", "dialect"), APT_FIXTURES)
    def test_finds_resolver_content(self, relative: str, dialect: str) -> None:
        """Each fixture actually exercises the resolver stream.

        Guards against a fixture that passes the coverage test by containing
        nothing interesting.
        """
        _, stats = lex_all(fixture_text(relative))
        resolver = sum(
            count
            for verb, count in stats.by_verb.items()
            if verb in (Verb.BROKEN, Verb.INVESTIGATING, Verb.CONSIDERING)
        )
        assert resolver > 0, f"{relative} has no resolver traffic"


class TestDialect:
    """apt 2.8 and apt 3.2 both occur in the same corpus."""

    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            ("2.8.3", Dialect.APT2),
            ("2.7.14build2", Dialect.APT2),
            ("3.2.0", Dialect.APT3),
            ("3.1.6ubuntu2", Dialect.APT3),
            ("", Dialect.UNKNOWN),
            (None, Dialect.UNKNOWN),
        ],
    )
    def test_from_version_string(self, version: str | None, expected: Dialect) -> None:
        assert variant_for_version(version) is expected

    def test_detects_apt2_from_content(self) -> None:
        """The ``p`` mode prefix was only ever seen in apt 2.8 output.

        A fallback for when ``main.log`` is missing and the version line is
        therefore unavailable. Only a hint -- its absence implies nothing.
        """
        tokens, _ = lex_all(fixture_text("apt/lp2169028-apt.log"))
        assert dialect_of(tokens) is Dialect.APT2


class TestDepth:
    """Indentation encodes the resolver's recursion depth."""

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("Broken foo:amd64 Depends on bar:amd64 < 1.0 @ii mK >", 0),
            ("  Considering foo:amd64 0 as a solution to bar:amd64 -1", 2),
            ("       Delayed Removing: foo:amd64 as upgrade is not an option for bar:amd64", 7),
            ("\tDone", 8),
            ("  \tDone", 8),
        ],
    )
    def test_measure(self, line: str, expected: int) -> None:
        assert measure_depth(line) == expected

    def test_real_logs_reach_deep_recursion(self) -> None:
        """Depth genuinely matters: real logs nest far.

        If this ever collapses to a handful of levels, either the parser has
        stopped reading indentation or the corpus has lost its hard cases.
        """
        tokens, _ = lex_all(fixture_text("apt/lp2169028-apt.log"))
        assert max(token.depth for token in tokens) >= 20


class TestBrokenLine:
    """The blame record, which everything downstream is built from."""

    def test_parses_subject_object_dep_and_constraint(self) -> None:
        token = lex_line(
            "Broken python3-apt:amd64 Depends on python3:amd64"
            " < 3.12.3-0ubuntu2.1 -> 3.14.3-0ubuntu2 @ii umU > (< 3.13)",
            1,
        )
        assert token.verb is Verb.BROKEN
        assert token.subject == "python3-apt:amd64"
        assert token.object == "python3:amd64"
        assert token.dep is DepType.DEPENDS
        assert token.constraint == "< 3.13"

    def test_state_describes_the_object(self) -> None:
        """apt attributes the state to the dependency, not the dependent.

        Reading it as the subject's state points the holdback detector at
        entirely the wrong package.
        """
        token = lex_line(
            "Broken lintian:amd64 Depends on libfile-libmagic-perl:amd64"
            " < none | 1.23-2build2 @un uH >",
            1,
        )
        assert token.state is not None
        assert token.state.cand_version == "1.23-2build2"
        assert token.state.blocks_as_new_dependency

    def test_unversioned_dependency_has_no_constraint(self) -> None:
        token = lex_line(
            "Broken libxmlsec1-1:amd64 Conflicts on libxmlsec1:amd64 < none @un H >", 1
        )
        assert token.verb is Verb.BROKEN
        assert token.dep is DepType.CONFLICTS
        assert token.constraint == ""

    @pytest.mark.parametrize(
        ("spelling", "expected"),
        [
            ("Depends", DepType.DEPENDS),
            ("Pre-Depends", DepType.PRE_DEPENDS),
            ("PreDepends", DepType.PRE_DEPENDS),
            ("Breaks", DepType.BREAKS),
            ("Conflicts", DepType.CONFLICTS),
            ("Recommends", DepType.RECOMMENDS),
            ("Replaces", DepType.REPLACES),
        ],
    )
    def test_relationship_spellings(self, spelling: str, expected: DepType) -> None:
        token = lex_line(f"Broken a:amd64 {spelling} on b:amd64 < 1.0 @ii mK >", 1)
        assert token.dep is expected


class TestVerbsFoundLate:
    """Shapes the first draft of the grammar missed.

    Each of these was found by the unclassified-line reporter while running
    against a real log, not by reading apt's source. They are kept as explicit
    tests because they are the evidence that the reporter works.
    """

    def test_reinstated(self) -> None:
        token = lex_line("  Re-Instated libfoo:amd64", 1)
        assert token.verb is Verb.REINSTATED
        assert token.subject == "libfoo:amd64"

    def test_upgrading_due_to_breaks_field(self) -> None:
        token = lex_line("  Upgrading libfoo:amd64 due to Breaks field in libbar:amd64", 1)
        assert token.verb is Verb.UPGRADING_DUE_TO_FIELD
        assert token.dep is DepType.BREAKS
        assert token.object == "libbar:amd64"

    def test_upgrading_due_to_with_state(self) -> None:
        token = lex_line(
            "            Upgrading libfoo:amd64 < 1.0 | 2.0 @ii umH > due to libbar:amd64", 1
        )
        assert token.verb is Verb.UPGRADING_DUE_TO
        assert token.depth == 12

    def test_upgrading_colon_form_with_dependency_clause(self) -> None:
        token = lex_line(
            "   Upgrading: a:amd64 < 1.0 | 2.0 @ii umH > due to b:amd64"
            " Depends on c:amd64 < 3.0 | 4.0 @ii umH > (= 4.0)",
            1,
        )
        assert token.verb is Verb.UPGRADING_DUE_TO_DEP
        assert (token.subject, token.object, token.third) == ("a:amd64", "b:amd64", "c:amd64")
        assert token.constraint == "= 4.0"

    def test_cant_be_satisfied(self) -> None:
        """A stronger claim than ``Broken``, and it has no verb keyword."""
        token = lex_line(
            "  libselinux1-dev:amd64 Depends on libselinux1:amd64"
            " < 3.8.1-1build1 -> 3.9-4 @ii umU > (= 3.8.1-1build2) can't be satisfied!",
            1,
        )
        assert token.verb is Verb.CANT_BE_SATISFIED
        assert token.subject == "libselinux1-dev:amd64"
        assert token.object == "libselinux1:amd64"
        assert token.constraint == "= 3.8.1-1build2"

    def test_cant_be_satisfied_with_dep_suffix(self) -> None:
        token = lex_line(
            "    a:amd64 Depends on b:amd64 < 1.0 -> 2.0 @ii umU > (= 1.0)"
            " can't be satisfied! (dep)",
            1,
        )
        assert token.verb is Verb.CANT_BE_SATISFIED

    def test_keeping_package_both_capitalisations(self) -> None:
        upper = lex_line("  Keeping Package libfoo:amd64 due to Depends", 1)
        lower = lex_line(" Keeping package libfoo:amd64", 1)
        assert upper.verb is Verb.KEEPING_PACKAGE
        assert lower.verb is Verb.KEEPING_PACKAGE

    def test_package_dep_line_with_echoed_name(self) -> None:
        token = lex_line(
            "Package linux-headers-6.14.0-37-generic:amd64"
            " linux-headers-6.14.0-37-generic:amd64 Depends on"
            " linux-headers-6.14.0-37:amd64 < 6.14.0-37.37 @ii mP >",
            1,
        )
        assert token.verb is Verb.PACKAGE_DEP
        assert token.object == "linux-headers-6.14.0-37:amd64"

    def test_try_installing_before_changing(self) -> None:
        """apt weighing the fix for a holdback, and declining it."""
        token = lex_line(
            "  Try Installing libreoffice-core-nogui:amd64"
            " < none | 4:26.2.5.2-0ubuntu0.26.04.1 @un umH >"
            " before changing python3-uno:amd64",
            1,
        )
        assert token.verb is Verb.TRY_INSTALLING_BEFORE
        assert token.object == "python3-uno:amd64"

    def test_ignore_mark_keep_protected(self) -> None:
        token = lex_line(
            "      Ignore MarkKeep of libfoo:amd64 < none -> 1.0 @un pumN Ib >"
            " as its mode (Install) is protected",
            1,
        )
        assert token.verb is Verb.IGNORE_MARK_KEEP_PROTECTED

    def test_or_group_keep(self) -> None:
        assert lex_line("  Or group keep for python3-uno:amd64", 1).verb is Verb.OR_GROUP_KEEP

    def test_removing_colon_not_possible(self) -> None:
        token = lex_line("    Removing: libfoo:amd64 as upgrade is not possible", 1)
        assert token.verb is Verb.REMOVING_NOT_POSSIBLE

    def test_reinst_failed(self) -> None:
        token = lex_line("  Reinst Failed because of imagemagick-7-common:amd64", 1)
        assert token.verb is Verb.REINST_FAILED


class TestAmbiguousPrefixes:
    """Verbs whose patterns could shadow one another.

    Three pairs genuinely overlap, and the pattern table's order is what
    arbitrates them. These tests pin that order so a later reordering cannot
    quietly reclassify lines.
    """

    def test_removing_rather_than_change_beats_bare_removing(self) -> None:
        token = lex_line("  Removing libjpeg-turbo8:amd64 rather than change libjpeg8:amd64", 1)
        assert token.verb is Verb.REMOVING_RATHER
        assert token.object == "libjpeg8:amd64"

    def test_bare_removing_still_matches(self) -> None:
        assert lex_line("  Removing libfoo:amd64", 1).verb is Verb.REMOVING

    def test_breaks_field_beats_plain_due_to(self) -> None:
        """Otherwise ``object`` is captured as the literal word ``Breaks``."""
        token = lex_line("  Upgrading a:amd64 due to Breaks field in b:amd64", 1)
        assert token.verb is Verb.UPGRADING_DUE_TO_FIELD
        assert token.object == "b:amd64"

    def test_delayed_removing_beats_removing_colon(self) -> None:
        token = lex_line(
            "   Delayed Removing: a:amd64 as upgrade is not an option for b:amd64 (1.0)", 1
        )
        assert token.verb is Verb.DELAYED_REMOVING
        assert token.constraint == "1.0"


class TestStreamAttribution:
    @pytest.mark.parametrize(
        ("line", "stream"),
        [
            ("Broken a:amd64 Depends on b:amd64 < 1.0 @ii mK >", AptStream.RESOLVER),
            ("  MarkInstall a:amd64 < 1.0 -> 2.0 @ii umU > FU=0", AptStream.MARKER),
            ("  Installing b:amd64 as Depends of a:amd64", AptStream.AUTOINSTALL),
            ("Log time: 2026-04-25 10:49:55.123456", AptStream.SECTION),
        ],
    )
    def test_stream(self, line: str, stream: AptStream) -> None:
        assert lex_line(line, 1).stream is stream


class TestMarkerLines:
    def test_from_user_flag(self) -> None:
        """``FU=1`` means the change was requested, not inferred.

        Provenance that makes a package a more credible root.
        """
        requested = lex_line("  MarkInstall a:amd64 < none -> 1.0 @un uN > FU=1", 1)
        inferred = lex_line("  MarkInstall a:amd64 < none -> 1.0 @un uN > FU=0", 1)
        assert requested.from_user is True
        assert inferred.from_user is False

    def test_missing_fu_is_unknown_not_false(self) -> None:
        assert lex_line("  MarkKeep a:amd64 < 1.0 @ii mK >", 1).from_user is None


class TestScores:
    def test_negative_scores_parse(self) -> None:
        """apt's scores go negative, and the sign is meaningful."""
        token = lex_line(
            "  Considering libfile-libmagic-perl:amd64 0 as a solution to lintian:amd64 -1", 1
        )
        assert token.verb is Verb.CONSIDERING
        assert token.score_src == 0
        assert token.score_dst == -1

    def test_large_scores_parse(self) -> None:
        token = lex_line("  Considering python3:amd64 448 as a solution to bup:amd64 0", 1)
        assert (token.score_src, token.score_dst) == (448, 0)


class TestRobustness:
    """Malformed input must not raise. Truncated logs are normal."""

    def test_blank_lines(self) -> None:
        tokens, stats = lex_all("\n\n   \n")
        assert tokens == []
        assert stats.blank == 3

    def test_truncated_final_line(self) -> None:
        tokens, _ = lex_all(apt_log("Broken a:amd64 Depends on b:amd64 < 1.0 @ii") + "Broke")
        assert tokens  # did not raise

    def test_oversized_line_is_counted_not_parsed(self) -> None:
        _, stats = lex_all("Broken " + "x" * 20000)
        assert stats.oversized == 1
        assert stats.unmatched == 0

    def test_unrecognised_line_is_reported_with_a_masked_shape(self) -> None:
        """The feedback loop that found four real verbs."""
        _, stats = lex_all("Flibbertigibbet libfoo:amd64 version 1.2.3 sideways")
        assert stats.unmatched == 1
        shapes = dict(stats.top_unknown())
        assert "Flibbertigibbet <PKG> version <VER> sideways" in shapes
