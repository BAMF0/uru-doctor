# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for :mod:`uru_doctor.report`.

A report is the one artefact a human reads, so these tests are mostly about
honesty rather than formatting: that a number is labelled with which number it
is, that a package name is a package name, that an absent fact is reported
absent rather than as zero, and that nothing from the bug's prose leaks into
the conclusions.

Several assert the absence of specific bugs that reached a rendered page. Those
are named in the test so a future change that reintroduces one fails against a
description of why it was wrong, not just a diff.
"""

from __future__ import annotations

import json
import re

import pytest

from uru_doctor.config import DedupConfig, ReportConfig
from uru_doctor.dedup import build_signature, cluster_runs
from uru_doctor.diagnose import diagnose
from uru_doctor.ingest import ingest_attachments
from uru_doctor.intern import Interner
from uru_doctor.models import Cause, DepType, LogSource, UpgradeRun
from uru_doctor.parsers.apportmeta import parse_apport_meta
from uru_doctor.parsers.mainlog import BULK_LIST_PREFIXES
from uru_doctor.report import (
    MAX_QUOTE_CHARS,
    RunEntry,
    _elide,
    _packages,
    plural,
    render_corpus,
    render_run,
)
from uru_doctor.title import propose_title

from .conftest import FIXTURES

#: Recorded bugs with enough evidence to render a full page, plus the two
#: degenerate shapes that must also render: no logs at all, and an apt log
#: with no ``main.log`` beside it.
RENDERABLE = (
    "2150245",
    "2150319",
    "2150339",
    "2151847",
    "2155743",
    "2161332",
    "2169028",
    "2169197",
    "2169251",
)


def _load(bug_id: str, interner: Interner, *, suffix: str = "") -> tuple[UpgradeRun, object]:
    """Ingest and diagnose one recorded bug."""
    run_id = f"{bug_id}{suffix}"
    meta = None
    path = FIXTURES / "lp" / f"bug{bug_id}.json"
    if path.is_file():
        payload = json.loads(path.read_text())
        meta = parse_apport_meta(payload["description"], tags=payload["tags"])
    attachments = {}
    for name, source in (
        (f"apt/lp{run_id}-apt.log", LogSource.APT),
        (f"logs/lp{run_id}-main.log", LogSource.MAIN),
        (f"logs/lp{run_id}-aptterm.log", LogSource.APT_TERM),
        (f"logs/lp{run_id}-history.log", LogSource.HISTORY),
    ):
        candidate = FIXTURES / name
        if candidate.is_file():
            attachments[source] = candidate.read_text()
    run = ingest_attachments(attachments, interner, meta=meta, bug_id=int(bug_id))
    return (run, diagnose(run, interner, meta=meta))


def _render(bug_id: str, interner: Interner, **kwargs: object) -> str:
    run, result = _load(bug_id, interner)
    return render_run(run, result, interner, **kwargs)  # type: ignore[arg-type]


#: The corpus as it really is: every recorded bug, plus the second reporter's
#: lone apt.log on 2150319. Including it matters because it is the only run
#: that shares a bug number with another, and so the only one that exercises
#: label disambiguation and a second cluster.
CORPUS: tuple[tuple[str, str], ...] = (
    *((bug_id, "") for bug_id in RENDERABLE),
    ("2150319", "-c19"),
)


@pytest.fixture
def entries(interner: Interner) -> list[RunEntry]:
    out = []
    for bug_id, suffix in CORPUS:
        run, result = _load(bug_id, interner, suffix=suffix)
        out.append(
            RunEntry(
                key=f"lp:{bug_id}#{suffix.lstrip('-') or '0'}",
                run=run,
                result=result,  # type: ignore[arg-type]
                title=propose_title(run, result, interner),  # type: ignore[arg-type]
            )
        )
    return out


class TestRendersAtAll:
    """Every recorded shape must produce a page without raising."""

    @pytest.mark.parametrize("bug_id", RENDERABLE)
    def test_renders(self, bug_id: str, interner: Interner) -> None:
        text = _render(bug_id, interner)
        assert text.startswith("# ")
        assert text.endswith("\n")
        assert "## Diagnosis" in text

    def test_run_with_no_logs_renders(self, interner: Interner) -> None:
        """The no-evidence case is a real outcome, not an error path.

        LP#2161332 attached nothing. A tool that crashes or produces an empty
        page here is useless for the commonest triage action there is: telling
        a reporter which file to attach.
        """
        text = _render("2161332", interner)
        assert "no upgrade logs were attached" in text
        assert "Evidence incomplete" in text

    def test_apt_log_without_main_log_renders(self, interner: Interner) -> None:
        """A second reporter's lone apt.log still has to produce a page."""
        run, result = _load("2150319", interner, suffix="-c19")
        text = render_run(run, result, interner)  # type: ignore[arg-type]
        assert run.logs_present == (LogSource.APT,)
        assert not run.events  # Nothing to quote; the graph is the evidence.
        assert "resolver section" in text


class TestNoBulkDumps:
    """The 54 kB-line regression.

    ``event_indices`` matched the root package inside the upgrader's bulk
    package dumps -- ``Upgrade:`` and nine others, each listing the whole
    working set -- and the renderer quoted them. Two reports came to 450 kB,
    and the quoted "evidence" said only that the package was part of the
    upgrade, which is true of every package in it.
    """

    @pytest.mark.parametrize("bug_id", RENDERABLE)
    def test_no_absurd_lines(self, bug_id: str, interner: Interner) -> None:
        text = _render(bug_id, interner)
        longest = max((len(line) for line in text.splitlines()), default=0)
        # Generous: prose and package listings legitimately run long. A bulk
        # dump is thousands of characters, so this still catches it.
        assert longest < 2000, f"longest line {longest}"

    @pytest.mark.parametrize("bug_id", RENDERABLE)
    def test_no_bulk_prefix_is_quoted(self, bug_id: str, interner: Interner) -> None:
        text = _render(bug_id, interner)
        for prefix in BULK_LIST_PREFIXES:
            assert f": {prefix}" not in text, f"quoted a bulk dump: {prefix}"

    def test_evidence_excludes_bulk_lines(self, interner: Interner) -> None:
        """Checked at the source, not just the renderer.

        The filter belongs to evidence selection so that every consumer
        benefits; asserting it only on rendered output would let a future
        caller reintroduce it.
        """
        run, result = _load("2169251", interner)
        for finding in result.findings:  # type: ignore[attr-defined]
            for index in finding.evidence:
                event = run.events[index]
                text = interner.render(event.template_id, event.args)
                assert not text.startswith(BULK_LIST_PREFIXES)

    def test_elide_keeps_both_ends(self) -> None:
        text = "START" + "x" * 5000 + "END"
        out = _elide(text)
        assert out.startswith("START")
        assert out.endswith("END")
        assert len(out) <= MAX_QUOTE_CHARS
        assert "chars…]" in out

    def test_elide_leaves_short_text_alone(self) -> None:
        assert _elide("short") == "short"


class TestNoRawEnumsLeak:
    """The ``Relationship: 6`` regression.

    ``root.dep`` is a :class:`DepType` and was tested against ``BLAME_EDGES``,
    which holds :class:`EdgeKind` members. Two unrelated ``IntEnum``\\s compare
    equal by value, so the condition selected ``RECOMMENDS`` and ``DEPENDS``
    and dropped ``PRE_DEPENDS``, ``BREAKS`` and ``CONFLICTS`` -- and the one
    value that survived reached the page as the bare string ``6``.
    """

    @pytest.mark.parametrize("bug_id", RENDERABLE)
    def test_relationship_is_a_word(self, bug_id: str, interner: Interner) -> None:
        text = _render(bug_id, interner)
        for value in re.findall(r"^- Relationship: `([^`]*)`$", text, re.MULTILINE):
            assert not value.isdigit(), f"raw enum value: {value!r}"
            assert value.replace("-", "_").upper() in DepType.__members__

    def test_conflicts_relationship_survives(self, interner: Interner) -> None:
        """The buggy condition excluded CONFLICTS entirely.

        LP#2150245's root is a third-party package apt settles by conflict,
        so this is the case that proved the filter was wrong rather than
        merely odd.
        """
        assert "- Relationship: `conflicts`" in _render("2150245", interner)

    @pytest.mark.parametrize("bug_id", RENDERABLE)
    def test_no_bare_enum_repr(self, bug_id: str, interner: Interner) -> None:
        text = _render(bug_id, interner)
        for pattern in ("DepType.", "EdgeKind.", "Mode.", "Decision.", "Severity.INFO>"):
            assert pattern not in text


class TestPackageNames:
    """Victim lists must be package names, not vertex indices."""

    @pytest.mark.parametrize("bug_id", RENDERABLE)
    def test_victims_are_plausible_names(self, bug_id: str, interner: Interner) -> None:
        text = _render(bug_id, interner)
        for listing in re.findall(r"^Affected: (.+)$", text, re.MULTILINE):
            for name in re.findall(r"`([^`]+)`", listing):
                assert not name.isdigit(), f"vertex index rendered as a package: {name}"
                assert re.match(r"^[a-z0-9]", name), name

    def test_known_cascade_is_named_correctly(self, interner: Interner) -> None:
        """LP#2150245's victims are the wacom/mutter/gnome-shell chain.

        ``Root.cascade`` holds vertex indices and was assigned straight into
        ``Finding.victim_pkgs``, which holds package ids. Both are small
        integers, so the output was plausible package names from the same log
        -- just the wrong ones. Pinning the real chain is what detects that.
        """
        text = _render("2150245", interner)
        for name in ("libwacom9", "libinput10", "libmutter-18-0", "gnome-shell"):
            assert f"`{name}`" in text

    def test_labels_are_deduplicated(self, interner: Interner) -> None:
        """One package can hold two ids.

        ``resolve_third_party`` keeps both ``libwacom9-surface`` and
        ``libwacom9-surface:amd64`` so the graph overlay matches either
        spelling; ``package_label`` strips the suffix and they collapse. The
        foreign list showed the package twice and said "14" when it meant 13.
        """
        run, _ = _load("2150245", interner)
        labels = _packages(run.third_party, interner)
        assert len(labels) == len(set(labels))
        assert "libwacom9-surface" in labels

    def test_absent_ids_are_dropped(self, interner: Interner) -> None:
        assert _packages([0, 0], interner) == []


class TestCountsAreDistinguished:
    """The three meanings of "broken" must never be merged.

    On LP#2150245 apt's own total is 22 while 434 packages were observed broken
    at some point. Both are correct answers to different questions, and a page
    that prints either as "broken packages" invites an argument with a number
    the tool never made.
    """

    def test_both_broken_counts_are_labelled(self, interner: Interner) -> None:
        run, _ = _load("2150245", interner)
        text = _render("2150245", interner)
        assert f"as apt last reported it: {run.apt_broken_count:,}" in text
        assert f"observed at any point during resolution: {run.counts.broken:,}" in text
        assert run.apt_broken_count != run.counts.broken

    def test_no_unqualified_broken_count(self, interner: Interner) -> None:
        text = _render("2150245", interner)
        assert not re.search(r"^- Broken: ", text, re.MULTILINE)

    def test_missing_counts_are_not_rendered_as_zero(self, interner: Interner) -> None:
        """LP#2161332 attached nothing, so every counter is absent.

        Printing a column of zeroes asserts the upgrade touched nothing, which
        is a claim about the run. "Not recorded" is the only honest rendering.
        """
        text = _render("2161332", interner)
        assert "Nothing recorded" in text
        assert "Broken, as apt last reported it: 0" not in text

    def testplural(self) -> None:
        assert plural(1, "package") == "1 package"
        assert plural(2, "package") == "2 packages"
        assert plural(1500, "run") == "1,500 runs"
        assert plural(1, "relation") == "1 relation"


class TestCandidateInvalid:
    """Third-party findings get their own section, and only when earned."""

    def test_candidate_invalid_is_flagged(self, interner: Interner) -> None:
        text = _render("2150245", interner)
        assert "Candidate Invalid" in text
        assert "## Third-party packages" in text
        assert "suggestion for a human, not a verdict" in text

    def test_not_a_candidate_when_third_party_is_incidental(self, interner: Interner) -> None:
        """LP#2150319 has an imagemagick PPA but was fixed by an SRU.

        Testing every finding rather than the primary one flagged this bug as
        a candidate for Invalid on the strength of four victims of a PPA that
        had nothing to do with the deadlock.
        """
        run, result = _load("2150319", interner)
        assert not result.is_candidate_invalid  # type: ignore[attr-defined]
        text = render_run(run, result, interner)  # type: ignore[arg-type]
        assert "**Candidate Invalid.**" not in text

    def test_origin_is_not_invented(self, interner: Interner) -> None:
        """The logs do not record which PPA a package came from.

        ``ReportConfig.separate_third_party`` once promised grouping by
        origin, but the upgrader writes a flat ``Foreign`` list and
        ``UpgradeRun.origins`` is never populated. Guessing from name suffixes
        would be inference dressed as fact, so the page says so instead.
        """
        text = _render("2150245", interner)
        assert "not where they came from" in text
        assert "ppa:" not in text.lower()

    def test_section_can_be_disabled(self, interner: Interner) -> None:
        config = ReportConfig(separate_third_party=False)
        text = _render("2150245", interner, config=config)
        assert "## Third-party packages" not in text


class TestEvidenceIsAttributed:
    """Every quote carries a source and a line number."""

    @pytest.mark.parametrize("bug_id", RENDERABLE)
    def test_quotes_are_attributed(self, bug_id: str, interner: Interner) -> None:
        text = _render(bug_id, interner)
        for block in re.findall(r"<summary>Evidence</summary>\n\n```\n(.*?)```", text, re.S):
            for line in block.strip().splitlines():
                assert re.match(r"^[\w.\-]+\.(log|0)(\s\(derived\))?:\d+", line), line

    def test_resolver_findings_cite_the_graph(self, interner: Interner) -> None:
        """Resolver evidence is a subgraph, not a sentence.

        There is often no line that singles the package out, so the page cites
        the apt.log offset of the section instead of quoting nothing.
        """
        text = _render("2150339", interner)
        assert re.search(r"resolver section \d+ of `apt\.log`, from line [\d,]+", text)

    def test_graph_citation_is_not_repeated(self, interner: Interner) -> None:
        """Every root in one section cites the same line.

        Five identical citations read like a mistake, so it is stated once.
        """
        text = _render("2150245", interner)
        assert text.count("resolver section 0 of `apt.log`") == 1

    def test_rules_are_explained_once(self, interner: Interner) -> None:
        text = _render("2150245", interner)
        assert "## Method" in text
        assert text.count("Resolve the named root package, not its victims") == 1


class TestHonestyAboutUncertainty:
    """ "No" and "don't know" must not render the same."""

    def test_incomplete_evidence_is_flagged(self, interner: Interner) -> None:
        text = _render("2169028", interner)
        assert "Evidence incomplete" in text
        assert "may not be the whole failure" in text

    def test_complete_evidence_is_not_flagged(self, interner: Interner) -> None:
        run, result = _load("2150245", interner)
        assert run.evidence_complete
        assert "Evidence incomplete" not in render_run(run, result, interner)  # type: ignore[arg-type]

    def test_unknown_dpkg_state_says_unknown(self, interner: Interner) -> None:
        """``dpkg_wrote`` is a tri-state and must render as three states."""
        run, _ = _load("2161332", interner)
        assert run.dpkg_wrote is None
        assert "| dpkg wrote to the system | unknown |" in _render("2161332", interner)

    def test_known_dpkg_state_says_no(self, interner: Interner) -> None:
        run, _ = _load("2150245", interner)
        assert run.dpkg_wrote is False
        assert "| dpkg wrote to the system | no |" in _render("2150245", interner)

    def test_post_upgrade_failure_is_distinguished(self, interner: Interner) -> None:
        """LP#2169251 finished the upgrade and then failed.

        A materially different bug from the rest: the machine is upgraded and
        broken rather than un-upgraded and intact, and the remedy differs.
        """
        text = _render("2169251", interner)
        assert "The upgrade finished" in text
        assert "upgraded and faulty" in text

    def test_warnings_are_separated_from_errors(self, interner: Interner) -> None:
        """apt's ``W:`` lines misdirected LP#2150319 for weeks."""
        text = _render("2150245", interner)
        assert "which are not evidence of the failure" in text

    def test_corroboration_is_not_overclaimed(self, interner: Interner) -> None:
        text = _render("2150245", interner)
        assert "never the sole basis" in text

    def test_fragile_decisions_are_disclosed(self, interner: Interner) -> None:
        text = _render("2150245", interner)
        assert "## Fragile decision" in text
        assert "irreproducible on a clean install" in text


class TestNoProseLeaks:
    """The directive: conclusions come from logs, never from the bug's text.

    Asserted on the rendered page as well as in the signatures, because the
    report is where a reporter's wording would be most tempting to reuse.
    """

    def test_reporter_prose_is_not_a_conclusion(self, interner: Interner) -> None:
        payload = json.loads((FIXTURES / "lp" / "bug2150245.json").read_text())
        text = _render("2150245", interner)
        diagnosis = text[text.index("## Diagnosis") : text.index("## What apt itself said")]
        # Distinctive words from the reporter's own description must not
        # appear in the diagnosis. The title may be echoed once, labelled as
        # the current title, for a triager's convenience only.
        for word in ("I ", "my ", "tried", "please"):
            assert word not in diagnosis, f"reporter prose in diagnosis: {word!r}"
        assert payload["description"][:80] not in text

    def test_states_its_own_basis(self, interner: Interner) -> None:
        text = _render("2150245", interner)
        assert "from the attached logs alone" in text
        assert "No bug titles, descriptions, tags or reporter prose" in text


class TestMarkdownIsWellFormed:
    @pytest.mark.parametrize("bug_id", RENDERABLE)
    def test_fences_balance(self, bug_id: str, interner: Interner) -> None:
        text = _render(bug_id, interner)
        assert text.count("\n```") % 2 == 0, "unbalanced code fence"

    @pytest.mark.parametrize("bug_id", RENDERABLE)
    def test_details_balance(self, bug_id: str, interner: Interner) -> None:
        text = _render(bug_id, interner)
        assert text.count("<details>") == text.count("</details>")

    @pytest.mark.parametrize("bug_id", RENDERABLE)
    def test_single_h1(self, bug_id: str, interner: Interner) -> None:
        text = _render(bug_id, interner)
        assert len(re.findall(r"^# ", text, re.MULTILINE)) == 1

    @pytest.mark.parametrize("bug_id", RENDERABLE)
    def test_no_empty_table_cells_for_known_facts(self, bug_id: str, interner: Interner) -> None:
        text = _render(bug_id, interner)
        assert "|  |" not in text.replace("| | |", "")

    @pytest.mark.parametrize("bug_id", RENDERABLE)
    def test_no_unrendered_placeholders(self, bug_id: str, interner: Interner) -> None:
        text = _render(bug_id, interner)
        for leak in ("{}", "{0}", "None", "()", "''"):
            assert leak not in text, f"unrendered value: {leak}"


class TestConfigIsHonoured:
    def test_cascade_listing_is_capped(self, interner: Interner) -> None:
        config = ReportConfig(max_cascade_shown=3)
        text = _render("2150245", interner, config=config)
        listing = re.search(r"^Affected: (.+)$", text, re.MULTILINE)
        assert listing is not None
        assert listing.group(1).count("`") == 6  # three names, two ticks each
        assert "and 47 more" in listing.group(1)

    def test_fragile_section_can_be_disabled(self, interner: Interner) -> None:
        text = _render("2150245", interner, config=ReportConfig(show_fragile_section=False))
        assert "## Fragile decision" not in text

    def test_caveats_can_be_disabled(self, interner: Interner) -> None:
        text = _render("2161332", interner, config=ReportConfig(show_needs_human=False))
        assert "## Caveats" not in text


class TestCorpusDigest:
    def test_renders(self, entries: list[RunEntry], interner: Interner) -> None:
        signatures = {
            e.key: build_signature(e.run, e.result.findings, interner)  # type: ignore[attr-defined]
            for e in entries
        }
        clusters = cluster_runs(signatures, config=DedupConfig(), oldest_first=sorted(signatures))
        text = render_corpus(entries, clusters)
        assert text.startswith("# Upgrade failure digest")
        assert "## By cause" in text

    def test_tier_is_always_stated(self, entries: list[RunEntry], interner: Interner) -> None:
        """The tiers are not equally strong and must not be flattened.

        ``root-graph`` means an identical root-cause subgraph and is safe to
        act on. ``evidence-similarity`` is a weighted Jaccard score and is a
        suggestion. Calling both "duplicate" throws away the tiering.
        """
        signatures = {
            e.key: build_signature(e.run, e.result.findings, interner)  # type: ignore[attr-defined]
            for e in entries
        }
        clusters = cluster_runs(signatures, config=DedupConfig(), oldest_first=sorted(signatures))
        text = render_corpus(entries, clusters)
        assert clusters, "expected the libpeas cluster"
        for cluster in clusters:
            assert f"matched on **{cluster.tier}**" in text

    def test_colliding_labels_are_disambiguated(self, interner: Interner) -> None:
        """Two runs of one bug must not render identically.

        A second reporter's logs are a separate run sharing the bug number. If
        both say only ``LP#2150319`` the cluster looks like the same report
        listed twice, which is indistinguishable from a clustering bug.
        """
        built = []
        for suffix in ("", "-c19"):
            run, result = _load("2150319", interner, suffix=suffix)
            built.append(
                RunEntry(
                    key=f"lp:2150319#{suffix or '0'}",
                    run=run,
                    result=result,  # type: ignore[arg-type]
                    title=propose_title(run, result, interner),  # type: ignore[arg-type]
                )
            )
        signatures = {
            e.key: build_signature(e.run, e.result.findings, interner)  # type: ignore[attr-defined]
            for e in built
        }
        clusters = cluster_runs(signatures, config=DedupConfig(), oldest_first=sorted(signatures))
        text = render_corpus(built, clusters)
        assert "lp:2150319#0" in text
        assert "lp:2150319#-c19" in text or "lp:2150319#c19" in text

    def test_no_hardcoded_corpus_size(self, entries: list[RunEntry]) -> None:
        """The prose must count the corpus, not assume it.

        It said "a corpus of nine" while rendering ten runs.
        """
        text = render_corpus(entries, [])
        assert f"{len(entries):,} runs diagnosed" in text
        for written in ("corpus of nine", "corpus of eight", "corpus of ten"):
            assert written not in text

    def test_candidate_invalid_is_collected(self, entries: list[RunEntry]) -> None:
        text = render_corpus(entries, [])
        assert "## Candidate Invalid" in text
        assert "LP#2150245" in text

    def test_needs_human_is_collected(self, entries: list[RunEntry]) -> None:
        text = render_corpus(entries, [])
        assert "## Needs a human read" in text
        assert "LP#2161332" in text

    def test_incomplete_runs_are_listed(self, entries: list[RunEntry]) -> None:
        text = render_corpus(entries, [])
        assert "## Incomplete evidence" in text
        assert "treat their causes as provisional" in text.lower()

    def test_cause_table_covers_every_run(self, entries: list[RunEntry]) -> None:
        text = render_corpus(entries, [])
        table = text[text.index("## By cause") : text.index("##", text.index("## By cause") + 5)]
        total = sum(int(n.replace(",", "")) for n in re.findall(r"\| (\d[\d,]*) \|", table))
        assert total == len(entries)

    def test_empty_corpus_renders(self) -> None:
        assert render_corpus([], []).startswith("# Upgrade failure digest")

    def test_clusters_are_capped(self, entries: list[RunEntry], interner: Interner) -> None:
        signatures = {
            e.key: build_signature(e.run, e.result.findings, interner)  # type: ignore[attr-defined]
            for e in entries
        }
        clusters = cluster_runs(signatures, config=DedupConfig(), oldest_first=sorted(signatures))
        text = render_corpus(entries, clusters, config=ReportConfig(max_clusters=1))
        assert "further cluster" in text


class TestKnownGroundTruth:
    """The report must say what the evidence says, for bugs whose answer is known."""

    @pytest.mark.parametrize(
        ("bug_id", "package", "cause"),
        [
            ("2150245", "libwacom9-surface", Cause.THIRD_PARTY_PIN),
            ("2150319", "libfile-libmagic-perl", Cause.RESOLVER_LIVELOCK),
            ("2150339", "libpeas-1.0-1", Cause.RESOLVER_LIVELOCK),
            ("2155743", "libkirigami-data", Cause.HELD_PACKAGE_BLOCKS_UPGRADE),
        ],
    )
    def test_names_the_right_package_and_cause(
        self, bug_id: str, package: str, cause: Cause, interner: Interner
    ) -> None:
        text = _render(bug_id, interner)
        assert package in text
        assert f"cause `{cause.value}`" in text

    def test_livelock_table_names_the_blocker(self, interner: Interner) -> None:
        """LP#2150339's blocker is libpeas-1.0-1, oscillating on gedit."""
        text = _render("2150339", interner)
        assert "## Resolver oscillation" in text
        assert "| `gedit` | 19 | `libpeas-1.0-1` |" in text

    def test_contradicts_a_wrong_tag_without_citing_it(self, interner: Interner) -> None:
        """LP#2155743 is tagged ``third-party-packages`` but is not one.

        Forty-six foreign packages are present and none is a root; the cause is
        a held Ubuntu package. The report must reach that from the logs and
        must not be swayed by the tag -- nor cite the tag as evidence.
        """
        run, result = _load("2155743", interner)
        assert not result.is_candidate_invalid  # type: ignore[attr-defined]
        assert run.third_party
        text = render_run(run, result, interner)  # type: ignore[arg-type]
        assert "libkirigami-data" in text
        assert "third-party-packages" not in text
