# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for :mod:`uru_doctor.i18n` and non-English log handling.

Ubuntu's upgrade logs are not reliably English, and which parts are translated
follows the code that produced them rather than any rule of thumb. These tests
pin down the boundary, because getting it wrong is silent: a mis-parsed
translated log yields an empty graph and zero counts, not an error.
"""

from __future__ import annotations

import json

import pytest

from uru_doctor.apt.grammar import DEP, dep_type
from uru_doctor.apt.lexer import LexStats, lex
from uru_doctor.apt.sections import read_sections
from uru_doctor.diagnose import corroborated_causes, diagnose
from uru_doctor.i18n import (
    APT_MESSAGES,
    DEP_TYPE_NAMES,
    DPKG_MESSAGES,
    LOCALE_DIR,
    catalogue_for,
    dep_type_aliases,
    dpkg_verb_patterns,
    language_of,
    localise,
)
from uru_doctor.intern import Interner
from uru_doctor.models import Cause, DepType, LogSource, Phase
from uru_doctor.parsers.apportmeta import parse_apport_meta
from uru_doctor.parsers.aptterm import parse_apt_term
from uru_doctor.title import propose_title

from .conftest import FIXTURES, fixture_text, ingest_one

#: Skip the catalogue-dependent tests where no translations are installed,
#: which is the normal state of a minimal container.
_HAS_CATALOGUES = (LOCALE_DIR / "it" / "LC_MESSAGES").is_dir()
needs_catalogues = pytest.mark.skipif(
    not _HAS_CATALOGUES, reason="no system gettext catalogues installed"
)


def lp(bug_id: str, interner: Interner, *, extra: tuple[str, ...] = ()):
    payload = json.loads((FIXTURES / "lp" / f"bug{bug_id}.json").read_text())
    meta = parse_apport_meta(payload["description"], tags=payload["tags"])
    attachments = {
        LogSource.APT: fixture_text(f"apt/lp{bug_id}-apt.log"),
        LogSource.MAIN: fixture_text(f"logs/lp{bug_id}-main.log"),
    }
    if "aptterm" in extra:
        attachments[LogSource.APT_TERM] = fixture_text(f"logs/lp{bug_id}-aptterm.log")
    if "history" in extra:
        attachments[LogSource.HISTORY] = fixture_text(f"logs/lp{bug_id}-history.log")
    run = ingest_one(attachments, interner, meta=meta, bug_id=int(bug_id))
    term = (
        parse_apt_term(attachments[LogSource.APT_TERM].splitlines(), locale=run.locale)
        if LogSource.APT_TERM in attachments
        else None
    )
    return (run, diagnose(run, interner, meta=meta, term=term), meta)


class TestLocaleParsing:
    @pytest.mark.parametrize(
        ("locale", "expected"),
        [
            ("ca_ES", ("ca_ES", "ca")),
            ("it_IT", ("it_IT", "it")),
            # Brazilian Portuguese has its own catalogue and differs from pt.
            ("pt_BR", ("pt_BR", "pt")),
            ("en_GB.UTF-8", ("en_GB", "en")),
            ("de_DE@euro", ("de_DE", "de")),
            ("ca", ("ca",)),
            # "C" and "POSIX" mean untranslated; asking gettext would waste a
            # filesystem probe per message.
            ("C", ()),
            ("POSIX", ()),
            ("", ()),
            (None, ()),
        ],
    )
    def test_candidate_languages(self, locale: str | None, expected: tuple[str, ...]) -> None:
        assert language_of(locale) == expected


class TestWhatIsTranslated:
    """The boundary between translated and untranslated output."""

    def test_the_resolver_trace_verbs_are_not_translated(self) -> None:
        """apt's debug lines have no ``_()`` around the verbs themselves."""
        for text in (
            fixture_text("apt/lp2169197-apt.log"),
            fixture_text("apt/lp2169251-apt.log"),
        ):
            assert "Investigating (" in text
            assert "Broken " in text

    def test_the_dependency_names_are_translated(self) -> None:
        """The discovery that mattered most.

        ``pkgCache::DepType()`` returns a translated string and apt
        interpolates it straight into its debug output, so the trace is
        partly localised after all.
        """
        catalan = fixture_text("apt/lp2169197-apt.log")
        italian = fixture_text("apt/lp2169251-apt.log")
        assert "as Depèn of" in catalan
        assert "as Dipende of" in italian
        assert "Rompe on" in italian

    def test_the_upgraders_own_errors_are_not_translated(self) -> None:
        """``logging.error`` calls are plain Python strings."""
        italian = fixture_text("logs/lp2169251-main.log")
        assert "failed to import AptClone" in italian
        assert "got error from PostInstallScript" in italian

    def test_the_apt_error_stack_is_translated(self) -> None:
        catalan = fixture_text("logs/lp2169197-main.log")
        assert "ha trencat coses" in catalan
        assert "generated breaks" not in catalan

    def test_dpkg_output_is_translated(self) -> None:
        italian = fixture_text("logs/lp2169251-aptterm.log")
        assert "Configurazione di" in italian
        assert "dpkg: attenzione:" in italian


@needs_catalogues
class TestMessageCatalogue:
    def test_known_messages_translate(self) -> None:
        for locale in ("ca_ES", "it_IT", "de_DE"):
            catalogue = catalogue_for(locale)
            assert catalogue.available
            assert catalogue.apt["resolver_breaks"] != APT_MESSAGES["resolver_breaks"]

    def test_the_catalan_resolver_error_is_recognised(self) -> None:
        catalogue = catalogue_for("ca_ES")
        assert catalogue.matches(
            "resolver_breaks",
            "E:Error, pkgProblemResolver::Resolve ha trencat coses, potser a causa"
            " de paquets retinguts.",
        )

    def test_the_italian_held_broken_error_is_recognised(self) -> None:
        """This message has no translation-independent anchor at all.

        Every word is translated, and its Chinese and Japanese forms contain no
        Latin text, so only the catalogue can identify it.
        """
        catalogue = catalogue_for("it_IT")
        assert catalogue.matches(
            "held_broken",
            "Impossibile correggere i problemi, ci sono pacchetti danneggiati bloccati.",
        )

    def test_english_is_still_recognised_in_a_localised_run(self) -> None:
        """A reporter's locale may be set while apt still answers in English."""
        catalogue = catalogue_for("it_IT")
        assert catalogue.matches("held_broken", APT_MESSAGES["held_broken"])

    def test_the_c_locale_falls_back_to_english(self) -> None:
        catalogue = catalogue_for("C")
        assert not catalogue.available
        assert catalogue.matches("held_broken", APT_MESSAGES["held_broken"])

    def test_anchors_work_without_a_catalogue(self) -> None:
        """``pkgProblemResolver::Resolve`` survives translation."""
        catalogue = catalogue_for("C")
        assert catalogue.matches(
            "resolver_breaks",
            "E:Error, pkgProblemResolver::Resolve ha trencat coses, potser a causa"
            " de paquets retinguts.",
        )

    def test_the_french_anchor_variant(self) -> None:
        """The French catalogue says ``pkgProblem::Resolve``, not the full name.

        Which is why the anchor stops at ``pkgProblem``.
        """
        catalogue = catalogue_for("C")
        assert catalogue.matches(
            "resolver_breaks",
            "Erreur, pkgProblem::Resolve a g\u00e9n\u00e9r\u00e9 des ruptures",
        )

    def test_held_broken_has_no_anchor_by_design(self) -> None:
        """Recorded as an explicit omission, not an oversight."""
        from uru_doctor.i18n import ANCHORS

        assert ANCHORS["held_broken"] == ()
        assert not catalogue_for("C").matches(
            "held_broken", "\u554f\u984c\u3092\u89e3\u6c7a\u3059\u308b\u3053\u3068"
        )

    def test_localise_returns_the_input_when_unknown(self) -> None:
        assert localise("not a real msgid", "it_IT", domains=("dpkg",)) == ("not a real msgid")


@needs_catalogues
class TestDepTypeAliases:
    def test_translated_names_resolve(self) -> None:
        assert dep_type("Dep\u00e8n") is DepType.DEPENDS
        assert dep_type("Dipende") is DepType.DEPENDS
        assert dep_type("Rompe") is DepType.BREAKS
        assert dep_type("Raccomanda") is DepType.RECOMMENDS

    def test_a_multiword_translation_resolves(self) -> None:
        """Italian renders ``Conflicts`` as ``Va in conflitto``.

        With spaces, so no single-word pattern can match it -- which is why
        the grammar's dependency position is permissive.
        """
        assert dep_type("Va in conflitto") is DepType.CONFLICTS

    def test_a_parenthesised_translation_resolves(self) -> None:
        """German renders ``PreDepends`` as ``Hängt ab von (vorher)``.

        With parentheses, which the grammar's dependency position used to
        exclude outright -- it had been widened for spaces when Italian
        ``Va in conflitto`` turned up, and not for the next punctuation class
        along. Five lines of LP#2168919 went unread as a result, found by the
        first live ``sweep``.
        """
        assert dep_type("Hängt ab von (vorher)") is DepType.PRE_DEPENDS

    def test_a_parenthesised_name_lexes_in_context(self) -> None:
        """The alias table already knew it; the pattern could not reach it.

        Worth asserting through the lexer rather than through ``dep_type``
        alone, because the gap was in the grammar and a unit test on the alias
        table passed throughout.
        """
        from uru_doctor.apt.grammar import Verb
        from uru_doctor.apt.lexer import lex

        tokens = list(
            lex(["Installing libfoo:amd64 as Hängt ab von (vorher) of libbar:amd64"])
        )
        assert [tok.verb for tok in tokens] == [Verb.INSTALLING_AS]
        assert tokens[0].dep is DepType.PRE_DEPENDS
        assert tokens[0].subject == "libfoo:amd64"
        assert tokens[0].object == "libbar:amd64"

    def test_a_dependency_name_cannot_swallow_the_state_blob(self) -> None:
        """``<`` and ``>`` stay excluded from the dependency position.

        Those bracket the state blob, and letting a name absorb it would turn
        a line into confident nonsense rather than into a visible miss -- the
        worse of the two failures.
        """
        assert "<" in DEP or "[^<>" in DEP

    def test_english_still_resolves_without_a_lookup(self) -> None:
        assert dep_type("Depends") is DepType.DEPENDS
        assert dep_type("Pre-Depends") is DepType.PRE_DEPENDS
        assert dep_type("breaks") is DepType.BREAKS

    def test_unknown_names_are_not_guessed(self) -> None:
        assert dep_type("Flurble") is DepType.UNKNOWN
        assert dep_type(None) is DepType.UNKNOWN
        assert dep_type("") is DepType.UNKNOWN

    def test_all_nine_names_are_covered(self) -> None:
        aliases = dep_type_aliases()
        for name in DEP_TYPE_NAMES:
            assert name.lower() in aliases

    def test_the_grammar_position_is_permissive(self) -> None:
        """Enumerating the English names cost 31% of coverage on Catalan."""
        assert "Depends" not in DEP
        assert "Conflicts" not in DEP


class TestLexerCoverageAcrossLanguages:
    """Any unlexed line is a verb the analysis cannot see."""

    @pytest.mark.parametrize(
        "name",
        [
            "lp2169197-apt.log",
            "lp2169251-apt.log",
        ],
    )
    def test_translated_logs_lex_completely(self, name: str) -> None:
        stats = LexStats()
        list(lex(fixture_text(f"apt/{name}").splitlines(), stats))
        assert stats.coverage == 1.0, stats.top_unknown(4)

    def test_the_whole_corpus_lexes_completely(self) -> None:
        total = matched = 0
        for path in sorted((FIXTURES / "apt").glob("*.log")):
            stats = LexStats()
            list(lex(path.read_text().splitlines(), stats))
            assert stats.coverage == 1.0, f"{path.name}: {stats.top_unknown(3)}"
            total += stats.lines - stats.blank
            matched += stats.matched
        assert matched == total
        assert total > 28_000

    def test_the_package_dep_constraint_variant(self) -> None:
        """``Package X X Depends on Y <state> (>= V)``.

        The trailing constraint was missing from the grammar. Every English
        occurrence in the corpus is a versionless kernel-header dependency, so
        the anchored pattern matched them all and the gap stayed invisible
        until a translated log supplied one. The language was incidental.
        """
        from uru_doctor.apt.grammar import Verb

        tokens = list(
            lex(
                [
                    "Package gconf-service-backend:amd64 gconf-service-backend:amd64"
                    " Dipende on libxml2:amd64 < 2.9.14 @ii mP > (>= 2.7.4)",
                    "Package linux-tools-6.14.0-37-generic:amd64"
                    " linux-tools-6.14.0-37-generic:amd64 Depends on"
                    " linux-tools-6.14.0-37:amd64 < 6.14.0-37.37 @ii mP >",
                ]
            )
        )
        assert [t.verb for t in tokens] == [Verb.PACKAGE_DEP, Verb.PACKAGE_DEP]
        assert tokens[0].constraint == ">= 2.7.4"
        assert tokens[0].dep is DepType.DEPENDS


@needs_catalogues
class TestTranslatedDpkgOutput:
    def test_verb_patterns_accept_both_languages(self) -> None:
        pattern = dpkg_verb_patterns("it_IT")["setting_up"]
        assert pattern.search("Configurazione di foo (1.0)...")
        assert pattern.search("Setting up foo (1.0) ...")

    def test_verb_patterns_handle_trailing_verbs(self) -> None:
        """German and Japanese put the package name before the verb."""
        for locale, sample in (
            ("de_DE", "foo (1.0) wird eingerichtet ..."),
            ("ja_JP", "foo (1.0) \u3092\u8a2d\u5b9a\u3057\u3066\u3044\u307e\u3059 ..."),
        ):
            pattern = dpkg_verb_patterns(locale)["setting_up"]
            assert pattern.search(sample), locale

    def test_the_italian_term_log_is_counted(self) -> None:
        """Parsed as English this yields zero of everything."""
        text = fixture_text("logs/lp2169251-aptterm.log")
        english = parse_apt_term(text.splitlines())
        localised = parse_apt_term(text.splitlines(), locale="it_IT")

        assert sum(b.configured for b in english.substantive) == 0
        assert sum(b.configured for b in localised.substantive) > 3000
        assert sum(b.unpacked for b in localised.substantive) > 3000

    def test_dpkg_ran_is_detected_either_way(self) -> None:
        """Block framing is untranslated, so this survives regardless."""
        text = fixture_text("logs/lp2169251-aptterm.log")
        assert parse_apt_term(text.splitlines()).dpkg_ran
        assert parse_apt_term(text.splitlines(), locale="it_IT").dpkg_ran

    def test_the_dpkg_messages_table_is_complete(self) -> None:
        for key in ("setting_up", "unpacking", "removing", "errors_encountered"):
            assert key in DPKG_MESSAGES


class TestCatalanBug:
    """LP#2169197, locale ca_ES."""

    def test_the_locale_is_captured(self, interner: Interner) -> None:
        run, _, _ = lp("2169197", interner)
        assert run.locale == "ca_ES"

    def test_the_graph_is_built(self, interner: Interner) -> None:
        """Enumerating English dep names left most of this absent."""
        run, _, _ = lp("2169197", interner)
        assert run.graphs
        assert run.counts.broken > 300

    @needs_catalogues
    def test_the_catalan_error_corroborates(self, interner: Interner) -> None:
        run, result, _ = lp("2169197", interner)
        assert run.apt_error_entries
        causes = corroborated_causes(run, interner)
        assert Cause.RESOLVER_LIVELOCK in causes
        assert result.corroborated

    def test_a_cause_is_identified(self, interner: Interner) -> None:
        run, result, _ = lp("2169197", interner)
        assert result.primary is not None
        assert result.primary.cause is Cause.RESOLVER_LIVELOCK
        assert propose_title(run, result, interner).confident


class TestPostUpgradeFailure:
    """LP#2169251: the upgrade succeeded and the machine broke afterwards.

    A materially different kind of bug, and the corpus had no example of it.
    """

    def test_the_upgrade_completed(self, interner: Interner) -> None:
        run, result, _ = lp("2169251", interner, extra=("aptterm", "history"))
        assert run.terminal_phase is Phase.POST_INSTALL_SCRIPTS
        assert run.dpkg_wrote is True
        assert result.upgrade_completed
        assert run.counts.upgraded > 2800

    def test_the_post_install_failure_is_primary(self, interner: Interner) -> None:
        """The Xorg fixup script, which is exactly the reported symptom."""
        _, result, _ = lp("2169251", interner, extra=("aptterm", "history"))
        assert result.primary is not None
        assert result.primary.cause is Cause.POST_INSTALL_SCRIPT_ERROR
        assert "xorg_fix_proprietary" in result.primary.summary

    def test_resolver_findings_are_demoted_not_dropped(self, interner: Interner) -> None:
        """They explain the held-back packages; they cannot explain the fault.

        Ranked on blast radius alone, a sixteen-package holdback from a
        *successful* resolve displaced the only error in the log.
        """
        _, result, _ = lp("2169251", interner, extra=("aptterm", "history"))
        holdback = next(f for f in result.findings if f.cause is Cause.HELD_PACKAGE_BLOCKS_UPGRADE)
        assert holdback.cascade_size > result.primary.cascade_size
        assert result.findings.index(result.primary) < result.findings.index(holdback)

    def test_dpkg_logs_are_not_needed_to_see_it_completed(self, interner: Interner) -> None:
        """Reporters often attach only apt.log and main.log.

        Taking the absence of the dpkg logs as proof that dpkg never ran
        marked this completed upgrade as never having started.
        """
        run, result, _ = lp("2169251", interner)
        assert LogSource.APT_TERM not in run.logs_present
        assert run.dpkg_wrote is True
        assert result.upgrade_completed

    def test_a_pre_commit_failure_keeps_its_resolver_findings(self, interner: Interner) -> None:
        """The demotion must not touch runs that failed before dpkg."""
        _, result, _ = lp("2169197", interner)
        assert not result.upgrade_completed
        assert result.primary.cause is Cause.RESOLVER_LIVELOCK


class TestNonEnglishFixtures:
    def test_both_locales_are_represented(self) -> None:
        locales = set()
        for bug_id in ("2169197", "2169251"):
            text = fixture_text(f"logs/lp{bug_id}-main.log")
            for line in text.splitlines():
                if "locale:" in line:
                    locales.add(line.split("locale:")[1].strip().split()[0])
                    break
        assert locales == {"'ca_ES'", "'it_IT'"}

    def test_the_sections_parse(self) -> None:
        for bug_id in ("2169197", "2169251"):
            log = read_sections(fixture_text(f"apt/lp{bug_id}-apt.log").splitlines())
            assert log.primary is not None
            assert log.primary.tokens
