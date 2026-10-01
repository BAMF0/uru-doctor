"""Tests for root-cause extraction.

These are the tests that say what the tool is *for*. The claims are checked
against the real bugs rather than against invented logs wherever possible,
because the value of the tool is that it reaches the conclusion a human reached
after weeks, and only a real log can demonstrate that.

:class:`TestLintianHoldback` is the headline. LP#2150319 took the release team
from April to May to diagnose, needed a quirk in ``DistUpgradeQuirks.py`` to
fix, and could not be reproduced on a clean install. The tool has to find
``libfile-libmagic-perl``, classify it as a holdback, and flag it fragile --
the last of which is the explanation for the irreproducibility.
"""

from __future__ import annotations

import pytest

from tests.conftest import (
    apt_log,
    broken,
    fixture_text,
    graph_of,
    holdback_block,
    named_root,
    pin_cascade,
    sectioned,
)
from uru_doctor.apt.graph import build_graph
from uru_doctor.apt.roots import analyse, cascade_tree
from uru_doctor.intern import Interner
from uru_doctor.models import Cause, Decision, Mode, Severity
from uru_doctor.parsers.mainlog import parse_main_log, resolve_third_party


def roots_of(text: str, interner: Interner, **kwargs: object) -> object:
    graph = graph_of(text, interner)
    return analyse(graph, interner, **kwargs)  # type: ignore[arg-type]


def real_roots(relative: str, interner: Interner, **kwargs: object) -> object:
    log = sectioned(fixture_text(relative))
    primary = log.primary
    assert primary is not None
    graph = build_graph(primary, interner)
    return analyse(graph, interner, **kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# The real bugs
# ---------------------------------------------------------------------------


class TestSurfacePpaConflict:
    """LP#2150245: ``libwacom-surface Upgrade form 24LTS to 26LTS fails``.

    Closed Invalid with thirteen duplicates because, as the apt maintainer put
    it, "The surface PPA is not supported by Ubuntu". The log says:

    .. code-block:: text

        Broken libwacom9-surface Conflicts on libwacom9 < none -> 2.18.0-1 @un pumN >
        Broken libinput10 Depends on libwacom9 < none | 2.18.0-1 @un umH > (>= 2.18.0)
          Considering libwacom9 15 as a solution to libwacom9-surface 16
          Fixing libwacom9-surface via keep of libwacom9
          Holding Back libinput10 rather than change libwacom9

    The PPA's ``libwacom9-surface`` conflicts with the archive's ``libwacom9``,
    so ``libwacom9`` cannot be installed, so ``libinput10`` and fifty other
    packages are stranded.
    """

    def test_blocked_package_is_a_holdback_root(self, interner: Interner) -> None:
        """Without origin data, the finding is still correct and actionable.

        ``libwacom9`` cannot be installed and fifty packages are blocked, which
        is a true and useful statement even before we know why.
        """
        report = real_roots("apt/lp2150245-apt.log", interner)
        root = named_root(report, interner, "libwacom9")
        assert root is not None
        assert root.cause is Cause.HOLDBACK_BLOCKS_NEW_DEP
        assert root.cascade_size > 40

    def test_origin_data_reorients_the_blame(self, interner: Interner) -> None:
        """With the PPA known, the culprit is the PPA.

        ``Conflicts`` is symmetric, so apt's direction carries no judgement
        about fault. Taken literally it blames the Ubuntu package and files the
        PPA -- the only thing anyone can act on -- as a victim.

        The origin evidence arrives through the real chain: ``main.log``'s
        ``Foreign`` list, re-resolved against the architecture-qualified names
        the apt trace uses.
        """
        main = parse_main_log(fixture_text("logs/lp2150245-main.log").splitlines(), interner)
        log = sectioned(fixture_text("apt/lp2150245-apt.log"))
        graph = build_graph(log.primary, interner)
        report = analyse(graph, interner, third_party=resolve_third_party(main, interner))

        assert report.reoriented == 1
        root = named_root(report, interner, "libwacom9-surface")
        assert root is not None
        assert root.cause is Cause.THIRD_PARTY_PIN
        assert root.cascade_size > 40

    def test_the_cause_survives_the_overlay_path(self, interner: Interner) -> None:
        """Reorienting and classifying must consult the same evidence.

        When the third-party set arrived only as a post-build overlay,
        reorientation fired but ``classify`` still read the graph's node bit,
        so the root was correctly found and then mislabelled
        ``transitional_breaks``. Both routes must agree.
        """
        log = sectioned(fixture_text("apt/lp2150245-apt.log"))
        surface = "libwacom9-surface"

        at_build = build_graph(
            log.primary, interner, third_party=[interner.package(f"{surface}:amd64")]
        )
        bit_path = analyse(at_build, interner)

        main = parse_main_log(fixture_text("logs/lp2150245-main.log").splitlines(), interner)
        overlay_path = analyse(
            build_graph(log.primary, interner),
            interner,
            third_party=resolve_third_party(main, interner),
        )

        assert named_root(bit_path, interner, surface).cause is Cause.THIRD_PARTY_PIN
        assert (
            named_root(overlay_path, interner, surface).cause
            is named_root(bit_path, interner, surface).cause
        )

    def test_without_origin_data_nothing_is_reoriented(self, interner: Interner) -> None:
        """Reorientation requires evidence; it is never guessed at."""
        report = real_roots("apt/lp2150245-apt.log", interner)
        assert report.reoriented == 0

    def test_asymmetric_edges_are_never_reoriented(self, interner: Interner) -> None:
        """``Depends`` genuinely names its cause, third-party or not."""
        text = apt_log(
            broken("victim:amd64", "Depends", "ppa-pkg:amd64", "1.0 -> 2.0 @ii umU", "= 1.0")
        )
        log = sectioned(text)
        graph = build_graph(log.primary, interner, third_party=[interner.package("victim:amd64")])
        report = analyse(graph, interner)
        assert report.reoriented == 0
        assert interner.package_label(report.top.pkg_id) == "ppa-pkg"

    def test_two_third_party_endpoints_are_not_reoriented(self, interner: Interner) -> None:
        """With both sides foreign there is no basis for a preference."""
        text = apt_log(broken("a-ppa:amd64", "Conflicts", "b-ppa:amd64", "1.0 @ii mK"))
        log = sectioned(text)
        graph = build_graph(
            log.primary,
            interner,
            third_party=[interner.package("a-ppa:amd64"), interner.package("b-ppa:amd64")],
        )
        assert analyse(graph, interner).reoriented == 0


class TestConflictingStateSightings:
    """apt revises a decision, then asserts a conflict against the new state.

    ``libwacom9`` appears in LP#2150245 as both ``@un umH`` with a declined
    candidate and ``@un pumN`` as a fresh install -- both on blame lines. The
    declined candidate is the informative one: a package apt refused to take is
    why something broke; one it agreed to install is not.
    """

    def test_declined_candidate_wins_over_selected(self, interner: Interner) -> None:
        text = apt_log(
            broken("x:amd64", "Conflicts", "target:amd64", "none -> 2.0 @un pumN"),
            broken("y:amd64", "Depends", "target:amd64", "none | 2.0 @un umH", ">= 2.0"),
        )
        report = roots_of(text, interner)
        root = named_root(report, interner, "target")
        assert root.mode is Mode.HOLD
        assert root.cause is Cause.HOLDBACK_BLOCKS_NEW_DEP

    def test_order_in_the_log_does_not_matter(self, interner: Interner) -> None:
        """The preference is by informativeness, not by position."""
        reversed_order = apt_log(
            broken("y:amd64", "Depends", "target:amd64", "none | 2.0 @un umH", ">= 2.0"),
            broken("x:amd64", "Conflicts", "target:amd64", "none -> 2.0 @un pumN"),
        )
        root = named_root(roots_of(reversed_order, interner), interner, "target")
        assert root.mode is Mode.HOLD


class TestLintianHoldback:
    """LP#2150319: ``[SRU] lintian breaks upgrade from 24.04 to 26.04``.

    The real sequence in the log is:

    .. code-block:: text

        Broken lintian Depends on libfile-libmagic-perl < none | 1.23-2build2 @un uH >
          Considering libfile-libmagic-perl 0 as a solution to lintian -1
          MarkKeep lintian < 2.117.0ubuntu1.4 -> 2.129.0ubuntu2 @ii umU Ib > FU=0
          Holding Back lintian rather than change libfile-libmagic-perl

    apt needed to install ``libfile-libmagic-perl`` to upgrade ``lintian``,
    declined by one point of score, and held ``lintian`` back instead -- which
    left it broken and failed the whole resolve.
    """

    def test_finds_the_blocker_as_a_root(self, interner: Interner) -> None:
        report = real_roots("apt/lp2150319-apt.log", interner)
        root = named_root(report, interner, "libfile-libmagic-perl")
        assert root is not None, "libfile-libmagic-perl was not identified as a root"

    def test_classifies_as_holdback(self, interner: Interner) -> None:
        report = real_roots("apt/lp2150319-apt.log", interner)
        root = named_root(report, interner, "libfile-libmagic-perl")
        assert root.cause is Cause.HOLDBACK_BLOCKS_NEW_DEP
        assert root.severity is Severity.HIGH

    def test_records_the_one_point_score_margin(self, interner: Interner) -> None:
        """The margin is why the bug was irreproducible.

        apt scored installing the dependency at 0 against holding lintian back
        at -1. A one-point preference means the outcome turns on incidental
        system state, which is exactly why a clean container upgraded fine
        while dozens of real machines did not.
        """
        report = real_roots("apt/lp2150319-apt.log", interner)
        root = named_root(report, interner, "libfile-libmagic-perl")
        assert root.score_margin == 1
        assert root.fragile is True

    def test_names_the_remedy(self, interner: Interner) -> None:
        """The fix the SRU actually shipped was to mark it for install."""
        report = real_roots("apt/lp2150319-apt.log", interner)
        root = named_root(report, interner, "libfile-libmagic-perl")
        assert "mark libfile-libmagic-perl for install" in root.detail["fix"]

    def test_apt_chose_to_hold_back(self, interner: Interner) -> None:
        report = real_roots("apt/lp2150319-apt.log", interner)
        root = named_root(report, interner, "libfile-libmagic-perl")
        assert root.remedy is Decision.HOLD_BACK_RATHER_THAN_CHANGE


class TestKubuntuCascade:
    """LP#2169028: ``unable to update kubuntu to 26-04``.

    The reporter blamed BleachBit and go-mtpfs. Neither appears anywhere in the
    evidence. The actual content is a large set of held and stale packages, led
    by a python3 ABI transition that breaks every extension pinned below 3.13.
    """

    def test_compresses_broken_packages_into_few_roots(self, interner: Interner) -> None:
        """The whole point: report the causes, not the symptoms."""
        report = real_roots("apt/lp2169028-apt.log", interner, evidence_complete=False)
        assert report.victims > 60
        assert len(report.roots) < report.victims / 3

    def test_python3_is_the_dominant_root(self, interner: Interner) -> None:
        report = real_roots("apt/lp2169028-apt.log", interner, evidence_complete=False)
        top = report.top
        assert interner.package_label(top.pkg_id) == "python3"
        assert top.cause is Cause.EXACT_PIN_BROKEN_BY_UPGRADE
        assert top.cascade_size > 30

    def test_python3_transition_is_described(self, interner: Interner) -> None:
        report = real_roots("apt/lp2169028-apt.log", interner, evidence_complete=False)
        top = report.top
        assert top.detail["from"].startswith("3.12")
        assert top.detail["to"].startswith("3.14")
        assert top.constraint == "< 3.13"

    def test_finds_the_abi_virtual_packages(self, interner: Interner) -> None:
        """``python3-numpy-abi9`` has no provider at all.

        Distinct from a holdback: there is no candidate to decline.
        """
        report = real_roots("apt/lp2169028-apt.log", interner, evidence_complete=False)
        root = named_root(report, interner, "python3-numpy-abi9")
        assert root is not None
        assert root.cause is Cause.UNSATISFIABLE_VIRTUAL
        assert root.detail["kind"] == "virtual"

    def test_finds_the_i386_orphan(self, interner: Interner) -> None:
        report = real_roots("apt/lp2169028-apt.log", interner, evidence_complete=False)
        root = named_root(report, interner, "libva-driver-abi-1.20:i386")
        assert root is not None

    def test_finds_the_t64_transition(self, interner: Interner) -> None:
        report = real_roots("apt/lp2169028-apt.log", interner, evidence_complete=False)
        root = named_root(report, interner, "libqt6xml6t64")
        assert root is not None
        assert root.cause is Cause.T64_TRANSITION
        assert root.detail["partner"] == "libqt6xml6:amd64"

    def test_nothing_is_left_unclassified(self, interner: Interner) -> None:
        """Every root gets a mechanism.

        An ``UNKNOWN`` root is not a failure of the tool -- it is surfaced for
        human review by design -- but on a log this thoroughly understood there
        should be none, and a regression that reintroduces one should fail here.
        """
        report = real_roots("apt/lp2169028-apt.log", interner, evidence_complete=False)
        unknown = [
            interner.package_label(root.pkg_id)
            for root in report.roots
            if root.cause is Cause.UNKNOWN
        ]
        assert unknown == []

    def test_truncated_evidence_lowers_confidence(self, interner: Interner) -> None:
        """This bug's log stops mid-run, so no root is a confirmed terminal cause."""
        from uru_doctor.models import Confidence

        complete = real_roots("apt/lp2169028-apt.log", interner, evidence_complete=True)
        partial = real_roots("apt/lp2169028-apt.log", interner, evidence_complete=False)
        assert complete.top.confidence is Confidence.STRONG
        assert partial.top.confidence is Confidence.MODERATE


class TestDevCascade:
    """The ``libselinux1-dev`` cascade from a local apt 3.2 log.

    ``libselinux1`` upgrades past an exact-version pin, which removes
    ``libselinux1-dev`` and cascades through ``libmount-dev``,
    ``libgio-2.0-dev``, ``libglib2.0-dev`` and the GTK ``-dev`` chain. A tool
    reporting symptoms lists fourteen broken packages; the answer is two roots.
    """

    def test_compresses_fourteen_victims_into_a_handful_of_roots(self, interner: Interner) -> None:
        report = real_roots("apt/local-apt3-devcascade.log", interner)
        assert report.victims >= 12
        assert len(report.roots) <= 5

    def test_libselinux1_is_the_dominant_root(self, interner: Interner) -> None:
        report = real_roots("apt/local-apt3-devcascade.log", interner)
        root = named_root(report, interner, "libselinux1")
        assert root is not None
        assert root.cause is Cause.EXACT_PIN_BROKEN_BY_UPGRADE
        assert root.cascade_size >= 10

    def test_cascade_reaches_the_gtk_dev_chain(self, interner: Interner) -> None:
        """The chain is transitive, not a flat list of direct dependents."""
        log = sectioned(fixture_text("apt/local-apt3-devcascade.log"))
        graph = build_graph(log.primary, interner)
        report = analyse(graph, interner)
        root = named_root(report, interner, "libselinux1")
        reached = {interner.package_label(graph.nodes.ids[n]) for n in root.cascade}
        assert "libselinux1-dev" in reached
        assert "libglib2.0-dev" in reached

    def test_section_collapsing_applies(self, interner: Interner) -> None:
        """This log contains the resolve more than once."""
        log = sectioned(fixture_text("apt/local-apt3-devcascade.log"))
        assert log.collapsed >= 1


class TestGnomeChurn:
    """Transitional Breaks and Conflicts, plus a cycle.

    Ordinary archive churn must be classified as such rather than landing in
    the needs-human pile, and the mutually-conflicting pair must still produce
    a root.
    """

    def test_churn_is_low_severity(self, interner: Interner) -> None:
        report = real_roots("apt/local-apt3-gnome.log", interner)
        transitional = [root for root in report.roots if root.cause is Cause.TRANSITIONAL_BREAKS]
        assert transitional
        assert all(root.severity is Severity.LOW for root in transitional)

    def test_conflicts_count_as_transitional(self, interner: Interner) -> None:
        """A Conflicts apt settles by removal is the same churn as a Breaks.

        Before this was recognised, ``libgjs0g`` -- a plain
        ``Conflicts`` resolved by removing the old package -- fell through to
        UNKNOWN and demanded human attention it did not deserve.
        """
        report = real_roots("apt/local-apt3-gnome.log", interner)
        root = named_root(report, interner, "libgjs0g")
        assert root is not None
        assert root.cause is Cause.TRANSITIONAL_BREAKS
        assert root.detail["relationship"] == "conflicts"

    def test_cycle_is_broken_and_reported(self, interner: Interner) -> None:
        report = real_roots("apt/local-apt3-gnome.log", interner)
        assert report.cycles_broken >= 1

    def test_nothing_unclassified(self, interner: Interner) -> None:
        report = real_roots("apt/local-apt3-gnome.log", interner)
        assert [r for r in report.roots if r.cause is Cause.UNKNOWN] == []


class TestSuccessfulResolveIsQuiet:
    """A clean resolve must not manufacture problems.

    The negative control. Without it, a rule that fires on everything would
    pass every other test in this file.
    """

    def test_no_high_severity_holdbacks(self, interner: Interner) -> None:
        report = real_roots("apt/local-apt3-success.log", interner)
        holdbacks = [
            root
            for root in report.roots
            if root.cause in (Cause.HOLDBACK_BLOCKS_NEW_DEP, Cause.HELD_PACKAGE_BLOCKS_UPGRADE)
        ]
        assert holdbacks == []


# ---------------------------------------------------------------------------
# Mechanism isolation
# ---------------------------------------------------------------------------


class TestHoldbackMechanism:
    """Synthetic, so the premise is exactly one holdback."""

    def test_detects_the_blocker_not_the_victim(self, interner: Interner) -> None:
        """The root is the package apt refused to install.

        Blaming ``lintian`` -- the package that is visibly broken -- is the
        mistake this whole module exists to avoid.
        """
        report = roots_of(holdback_block(), interner)
        assert interner.package_label(report.top.pkg_id) == "libfile-libmagic-perl"
        assert report.top.cause is Cause.HOLDBACK_BLOCKS_NEW_DEP

    def test_installed_but_held_is_a_different_cause(self, interner: Interner) -> None:
        """An installed held package needs permission to upgrade, not install.

        Same refusal by apt, different remedy, so a different class.
        """
        text = apt_log(
            broken(
                "python3-pyqt6:amd64",
                "Depends",
                "python3-pyqt6.sip:amd64",
                "13.6.0-1build2 | 13.11.0-1build1 @ii umH",
                ">= 13.8",
            )
        )
        report = roots_of(text, interner)
        root = named_root(report, interner, "python3-pyqt6.sip")
        assert root.cause is Cause.HELD_PACKAGE_BLOCKS_UPGRADE
        assert "allow python3-pyqt6.sip to upgrade" in root.detail["fix"]

    @pytest.mark.parametrize(("margin", "fragile"), [(0, True), (1, True), (2, True), (9, False)])
    def test_fragility_follows_the_score_margin(
        self, interner: Interner, margin: int, fragile: bool
    ) -> None:
        text = holdback_block(score_blocker=0, score_dependent=-margin)
        report = roots_of(text, interner, fragile_margin=2)
        assert report.top.fragile is fragile

    def test_holdback_stays_high_with_a_single_victim(self, interner: Interner) -> None:
        """Blast radius must not demote a holdback.

        A holdback stops the upgrade dead whether it breaks one package or
        forty, so unlike a pin it is not judged on cascade size.
        """
        report = roots_of(holdback_block(), interner)
        assert report.top.cascade_size == 1
        assert report.top.severity is Severity.HIGH


class TestPinMechanism:
    def test_root_is_the_upgraded_package(self, interner: Interner) -> None:
        report = roots_of(pin_cascade(), interner)
        assert interner.package_label(report.top.pkg_id) == "python3"
        assert report.top.cause is Cause.EXACT_PIN_BROKEN_BY_UPGRADE

    def test_cascade_counts_every_victim(self, interner: Interner) -> None:
        victims = tuple(f"python3-pkg{n}:amd64" for n in range(12))
        report = roots_of(pin_cascade(victims=victims), interner)
        assert report.top.cascade_size == 12

    def test_single_victim_pin_is_demoted(self, interner: Interner) -> None:
        """One over-tight dependent is a footnote, forty is the headline.

        Without this, a corpus reports a dozen HIGH roots of which eleven have
        a single victim, and the one that broke forty is lost among them.
        """
        report = roots_of(pin_cascade(victims=("python3-only:amd64",)), interner)
        assert report.top.severity is Severity.MEDIUM
        assert report.top.detail["demoted"] == "single victim"

    def test_large_cascade_promotes(self, interner: Interner) -> None:
        victims = tuple(f"python3-pkg{n}:amd64" for n in range(8))
        report = roots_of(pin_cascade(victims=victims), interner, min_cascade_for_high=5)
        assert report.top.severity is Severity.HIGH


class TestUnsatisfiableVirtual:
    def test_no_candidate_at_all(self, interner: Interner) -> None:
        text = apt_log(
            broken("i965-va-driver:i386", "Depends", "libva-driver-abi-1.20:i386", "none @un H")
        )
        report = roots_of(text, interner)
        root = named_root(report, interner, "libva-driver-abi-1.20:i386")
        assert root.cause is Cause.UNSATISFIABLE_VIRTUAL

    def test_distinguished_from_a_holdback(self, interner: Interner) -> None:
        """The difference is whether a candidate exists.

        ``< none @un H >`` cannot be fixed by marking it for install; nothing
        provides it. ``< none | 1.0 @un uH >`` can.
        """
        unsatisfiable = roots_of(
            apt_log(broken("a:amd64", "Depends", "virtual-abi-9:amd64", "none @un H")), interner
        )
        holdback = roots_of(
            apt_log(broken("a:amd64", "Depends", "real-pkg:amd64", "none | 1.0 @un uH")), interner
        )
        assert unsatisfiable.top.cause is Cause.UNSATISFIABLE_VIRTUAL
        assert holdback.top.cause is Cause.HOLDBACK_BLOCKS_NEW_DEP


class TestThirdPartyTakesPriority:
    """Origin outranks mechanism, because the action does not depend on it.

    An unsupported archive is closed Invalid however the breakage technically
    happened. The mechanism is still recorded so the report can explain itself.
    """

    def test_third_party_root_is_classified_by_origin(self, interner: Interner) -> None:
        text = apt_log(
            broken("libwacom9:amd64", "Depends", "libwacom9-surface:amd64", "none | 2.0 @un uH")
        )
        log = sectioned(text)
        blocker = interner.package("libwacom9-surface:amd64")
        graph = build_graph(log.primary, interner, third_party=[blocker])
        report = analyse(graph, interner)
        root = named_root(report, interner, "libwacom9-surface")
        assert root.cause is Cause.THIRD_PARTY_PIN
        assert root.severity is Severity.HIGH

    def test_mechanism_is_still_recorded(self, interner: Interner) -> None:
        text = apt_log(
            broken("libwacom9:amd64", "Depends", "libwacom9-surface:amd64", "none | 2.0 @un uH")
        )
        log = sectioned(text)
        blocker = interner.package("libwacom9-surface:amd64")
        graph = build_graph(log.primary, interner, third_party=[blocker])
        root = named_root(analyse(graph, interner), interner, "libwacom9-surface")
        assert "hold" in root.detail["mechanism"]


class TestRemovalCascade:
    def test_removed_package_blames_its_dependents(self, interner: Interner) -> None:
        removed = "3.8.1-1build1 @ii mR"
        text = apt_log(
            broken("libmount-dev:amd64", "Depends", "libselinux1-dev:amd64", removed),
            broken("libgio-2.0-dev:amd64", "Depends", "libselinux1-dev:amd64", removed),
        )
        report = roots_of(text, interner)
        root = named_root(report, interner, "libselinux1-dev")
        assert root.cause is Cause.REMOVAL_CASCADE
        assert root.mode is Mode.REMOVE
        assert root.cascade_size == 2


# ---------------------------------------------------------------------------
# Graph properties
# ---------------------------------------------------------------------------


class TestBlameDirection:
    """Blame must flow from cause to victim, not the reverse.

    Getting this backwards inverts every diagnosis while still producing
    plausible-looking output, which makes it worth a dedicated test.
    """

    def test_dependency_is_blamed_not_the_dependent(self, interner: Interner) -> None:
        text = apt_log(
            broken("victim:amd64", "Depends", "cause:amd64", "1.0 -> 2.0 @ii umU", "= 1.0")
        )
        report = roots_of(text, interner)
        assert interner.package_label(report.top.pkg_id) == "cause"
        assert report.victims == 1

    def test_autoinstall_edges_do_not_create_roots(self, interner: Interner) -> None:
        """``Installing B as Depends of A`` is context, not fault.

        Counting it as blame would make every metapackage the root of
        everything in the transaction.
        """
        text = apt_log("  Installing libfoo:amd64 as Depends of ubuntu-desktop:amd64")
        report = roots_of(text, interner)
        assert report.roots == []


class TestCascadeOrdering:
    def test_breadth_first(self, interner: Interner) -> None:
        """Immediate victims come first, so an elided report shows the nearest.

        ``root -> a -> deep`` must list ``a`` before ``deep``.
        """
        text = apt_log(
            broken("a:amd64", "Depends", "root:amd64", "1.0 -> 2.0 @ii umU", "= 1.0"),
            broken("b:amd64", "Depends", "root:amd64", "1.0 -> 2.0 @ii umU", "= 1.0"),
            broken("deep:amd64", "Depends", "a:amd64", "1.0 @ii mR"),
        )
        report = roots_of(text, interner)
        graph = graph_of(text, interner)
        names = [interner.package_label(graph.nodes.ids[n]) for n in report.top.cascade]
        assert names.index("deep") > names.index("a")


class TestCycles:
    """Mutually-blaming packages must still be reported.

    The ``t64`` renames do this: old and new declare conflicts against each
    other, so neither has in-degree zero and a naive root finder returns
    nothing at all.
    """

    def test_mutual_conflict_still_yields_a_root(self, interner: Interner) -> None:
        text = apt_log(
            broken("libfoo1:amd64", "Conflicts", "libfoo1t64:amd64", "1.0 @ii mK"),
            broken("libfoo1t64:amd64", "Conflicts", "libfoo1:amd64", "2.0 @ii mK"),
        )
        report = roots_of(text, interner)
        assert report.roots, "a cycle produced no roots at all"
        assert report.cycles_broken >= 1

    def test_promotion_is_recorded(self, interner: Interner) -> None:
        """A promoted root is marked, so a reader knows it was arbitrated."""
        text = apt_log(
            broken("a:amd64", "Conflicts", "b:amd64", "1.0 @ii mK"),
            broken("b:amd64", "Conflicts", "a:amd64", "2.0 @ii mK"),
        )
        report = roots_of(text, interner)
        assert any(root.cycle_broken for root in report.roots)


class TestEmptyAndDegenerate:
    def test_no_blame_edges_yields_no_roots(self, interner: Interner) -> None:
        report = roots_of(apt_log("  MarkKeep libfoo:amd64 < 1.0 @ii mK > FU=0"), interner)
        assert report.roots == []
        assert report.top is None

    def test_compression_string_is_readable(self, interner: Interner) -> None:
        report = roots_of(pin_cascade(), interner)
        assert "\u2192" in report.compression
        assert "roots" in report.compression


class TestCascadeRendering:
    def test_tree_includes_root_and_victims(self, interner: Interner) -> None:
        report = roots_of(pin_cascade(victims=("a:amd64", "b:amd64")), interner)
        graph = graph_of(pin_cascade(victims=("a:amd64", "b:amd64")), interner)
        lines = cascade_tree(graph, interner, report.top)
        assert lines[0].startswith("python3")
        assert any("a" in line for line in lines[1:])

    def test_wide_cascade_is_elided_with_a_count(self, interner: Interner) -> None:
        """A forty-victim cascade needs a number, not forty lines."""
        victims = tuple(f"v{n}:amd64" for n in range(20))
        text = pin_cascade(victims=victims)
        report = roots_of(text, interner)
        lines = cascade_tree(graph_of(text, interner), interner, report.top, max_width=5)
        assert any("and 15 more" in line for line in lines)
