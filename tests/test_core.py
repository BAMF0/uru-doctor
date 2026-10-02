"""Tests for sectioning, the CSR graph, interning, the store and sanitising.

The invariants here are the ones that make the rest of the tool trustworthy:
that a resolve logged four times is counted once, that a canonical graph digest
is stable, that re-ingesting a report changes nothing, and that a committed
fixture carries no personal data.
"""

from __future__ import annotations

import pytest

from tests.conftest import apt_log, broken, fixture_text, graph_of, sectioned
from uru_doctor.apt.graph import (
    canonical_digest,
    iter_edges,
    normalise_constraint,
    normalise_version,
)
from uru_doctor.apt.sections import read_sections
from uru_doctor.intern import Interner, canonical_package_key, mask_line, render_template
from uru_doctor.models import (
    Arch,
    Cause,
    Event,
    Finding,
    Phase,
    Signature,
    UpgradeRun,
    unpack_u32,
)
from uru_doctor.store import Store

# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


class TestSectionCollapsing:
    """The upgrader logs one problem four times.

    Two resolver passes per resolve (``Starting`` then ``Starting 2``), and the
    whole calculation run twice -- once to preview and once for real. Every
    count the tool reports is fourfold inflated unless identical sections are
    collapsed.
    """

    def test_identical_sections_collapse(self) -> None:
        section = apt_log(broken("a:amd64", "Depends", "b:amd64", "1.0 @ii mK"))
        log = read_sections((section * 4).splitlines())
        assert len(log.sections) == 1
        assert log.collapsed == 3

    def test_differing_sections_are_kept(self) -> None:
        first = apt_log(broken("a:amd64", "Depends", "b:amd64", "1.0 @ii mK"))
        second = apt_log(broken("c:amd64", "Depends", "d:amd64", "2.0 @ii mK"))
        log = read_sections((first + second).splitlines())
        assert len(log.sections) == 2
        assert log.collapsed == 0

    def test_line_numbers_do_not_defeat_collapsing(self) -> None:
        """Two copies of a resolve differ in line numbers and nothing else.

        The content hash deliberately excludes positions, or the duplicates it
        exists to catch would all look distinct.
        """
        section = apt_log(broken("a:amd64", "Depends", "b:amd64", "1.0 @ii mK"))
        padded = section + "\n\n\n" + section
        log = read_sections(padded.splitlines())
        assert log.collapsed == 1

    def test_real_log_collapses(self) -> None:
        log = sectioned(fixture_text("apt/local-apt3-devcascade.log"))
        assert log.collapsed >= 1


class TestSectionFraming:
    """Real logs are not well-formed, and none of it may raise."""

    def test_empty_log_time_runs_are_dropped(self) -> None:
        """Headers arrive in runs of three before anything interesting."""
        text = "Log time: a\nLog time: b\nLog time: c\n" + apt_log(
            broken("a:amd64", "Depends", "b:amd64", "1.0 @ii mK")
        )
        log = read_sections(text.splitlines())
        assert len(log.sections) == 1

    def test_tokens_before_any_header_still_get_a_section(self) -> None:
        """Logs excerpted into a bug description start mid-stream."""
        log = read_sections([broken("a:amd64", "Depends", "b:amd64", "1.0 @ii mK"), "Done"])
        assert len(log.sections) == 1

    def test_resolve_by_keep_without_starting(self) -> None:
        """Occurs in real logs and must not be read as truncation."""
        log = read_sections(
            ["Log time: x", "Entering ResolveByKeep", "  MarkKeep a:amd64 < 1.0 @ii mK >"]
        )
        assert log.sections[0].resolve_by_keep
        assert not log.truncated

    def test_truncation_needs_a_started_resolve(self) -> None:
        started = read_sections(["Log time: x", "Starting pkgProblemResolver with broken count: 3"])
        assert started.truncated

    def test_complete_real_logs_are_not_truncated(self) -> None:
        """Regression: an earlier rule flagged every clean log as truncated.

        The final section of a successful run is frequently a bare
        ``Entering ResolveByKeep`` with no ``Starting``, hence no ``Done`` to
        expect.
        """
        for name in ("local-apt3-success", "local-apt3-gnome", "local-apt3-devcascade"):
            log = sectioned(fixture_text(f"apt/{name}.log"))
            assert not log.truncated, name

    def test_mid_resolve_cut_is_truncated(self) -> None:
        text = fixture_text("apt/lp2169028-apt.log")
        log = read_sections(text.splitlines()[:500])
        assert log.truncated


class TestPrimarySection:
    """The failing section, not the last one."""

    def test_prefers_the_section_with_conflicts(self) -> None:
        """A clean ``openCache()`` often comes last, while unwinding.

        Choosing by position would report "no problem" on a bug that has one.
        """
        interesting = apt_log(broken("a:amd64", "Depends", "b:amd64", "1.0 @ii mK Ib"))
        quiet = "Log time: later\n  MarkKeep z:amd64 < 1.0 @ii mK > FU=0\n"
        log = read_sections((interesting + quiet).splitlines())
        primary = log.primary
        assert primary is not None
        assert primary.has_conflict

    def test_highest_broken_count_wins(self) -> None:
        low = apt_log(broken("a:amd64", "Depends", "b:amd64", "1.0 @ii mK")).replace(
            "broken count: 1", "broken count: 2"
        )
        high = apt_log(broken("c:amd64", "Depends", "d:amd64", "1.0 @ii mK")).replace(
            "broken count: 1", "broken count: 19"
        )
        log = read_sections((low + high).splitlines())
        assert log.primary is not None
        assert log.primary.broken_count == 19

    def test_broken_count_is_the_worst_not_the_last(self) -> None:
        """The second pass reports the count it began with.

        A resolve that improved from eleven to two still had eleven problems.
        """
        text = (
            "Log time: x\n"
            "Starting pkgProblemResolver with broken count: 11\n"
            "Starting 2 pkgProblemResolver with broken count: 2\n"
            "Done\n"
        )
        log = read_sections(text.splitlines())
        assert log.sections[0].broken_count == 11
        assert log.sections[0].passes == 2


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class TestCsrStructure:
    def test_offsets_are_monotonic_and_sized(self, interner: Interner) -> None:
        graph = graph_of(
            apt_log(
                broken("a:amd64", "Depends", "root:amd64", "1.0 -> 2.0 @ii umU", "= 1.0"),
                broken("b:amd64", "Depends", "root:amd64", "1.0 -> 2.0 @ii umU", "= 1.0"),
            ),
            interner,
        )
        offsets = graph.edges.offset_list
        assert len(offsets) == len(graph.nodes) + 1
        assert list(offsets) == sorted(offsets)
        assert offsets[-1] == len(graph.edges)

    def test_nodes_are_sorted_by_interned_id(self, interner: Interner) -> None:
        """Sorted vertices are what make the canonical digest free."""
        graph = graph_of(
            apt_log(
                broken("zzz:amd64", "Depends", "aaa:amd64", "1.0 @ii mR"),
                broken("mmm:amd64", "Depends", "aaa:amd64", "1.0 @ii mR"),
            ),
            interner,
        )
        ids = list(graph.nodes.ids)
        assert ids == sorted(ids)

    def test_index_of_round_trips(self, interner: Interner) -> None:
        graph = graph_of(apt_log(broken("a:amd64", "Depends", "b:amd64", "1.0 @ii mR")), interner)
        for index, pkg_id in enumerate(graph.nodes.ids):
            assert graph.nodes.index_of(pkg_id) == index

    def test_index_of_missing_is_none(self, interner: Interner) -> None:
        graph = graph_of(apt_log(broken("a:amd64", "Depends", "b:amd64", "1.0 @ii mR")), interner)
        assert graph.nodes.index_of(999_999) is None

    def test_parallel_arrays_have_equal_length(self, interner: Interner) -> None:
        graph = graph_of(fixture_text("apt/lp2150319-apt.log"), interner)
        count = len(graph.nodes)
        for field in ("cur_ver", "cand_ver", "raw_flags"):
            assert len(unpack_u32(getattr(graph.nodes, field))) == count
        edges = len(graph.edges)
        assert len(graph.edges.kinds) == edges
        assert len(graph.edges.score_flags) == edges


class TestCanonicalDigest:
    """The duplicate fingerprint."""

    def test_deterministic(self, interner: Interner) -> None:
        text = apt_log(broken("a:amd64", "Depends", "b:amd64", "1.0 -> 2.0 @ii umU", "= 1.0"))
        first = graph_of(text, interner)
        second = graph_of(text, interner)
        nodes = list(range(len(first.nodes)))
        assert canonical_digest(first, interner, nodes) == canonical_digest(second, interner, nodes)

    def test_insensitive_to_unrelated_packages(self, interner: Interner) -> None:
        """The digest covers the subgraph given, not the whole transaction.

        Two reports of one bug differ in everything else that happened to be
        in the upgrade, so a fingerprint sensitive to that would never match.
        """
        core = broken("a:amd64", "Depends", "b:amd64", "1.0 -> 2.0 @ii umU", "= 1.0")
        bare = graph_of(apt_log(core), interner)
        noisy = graph_of(
            apt_log(core, "  MarkInstall unrelated:amd64 < 1.0 -> 2.0 @ii umU > FU=0"),
            interner,
        )
        bare_nodes = [bare.nodes.index_of(p) for p in bare.nodes.ids]
        noisy_subset = [
            noisy.nodes.index_of(interner.package(name)) for name in ("a:amd64", "b:amd64")
        ]
        assert canonical_digest(bare, interner, [n for n in bare_nodes if n is not None]) == (
            canonical_digest(noisy, interner, [n for n in noisy_subset if n is not None])
        )

    def test_default_granularity_merges_differing_boundaries(self, interner: Interner) -> None:
        """``(< 46.0.1~)`` and ``(< 46.0.7~)`` are one bug.

        Both appear in the corpus for the same underlying
        ``python3-cryptography-vectors`` conflict. The default granularity
        keeps the operator and drops the boundary version, which is the only
        setting under which those two reports cluster together.
        """
        first = graph_of(
            apt_log(broken("a:amd64", "Breaks", "b:amd64", "1.0 @ii mK", "< 46.0.1~")), interner
        )
        second = graph_of(
            apt_log(broken("a:amd64", "Breaks", "b:amd64", "1.0 @ii mK", "< 46.0.7~")), interner
        )
        nodes = list(range(len(first.nodes)))
        assert canonical_digest(first, interner, nodes) == canonical_digest(second, interner, nodes)

    def test_exact_granularity_keeps_them_apart(self, interner: Interner) -> None:
        """The stricter setting is available and genuinely stricter."""
        first = graph_of(
            apt_log(broken("a:amd64", "Breaks", "b:amd64", "1.0 @ii mK", "< 46.0.1~")), interner
        )
        second = graph_of(
            apt_log(broken("a:amd64", "Breaks", "b:amd64", "1.0 @ii mK", "< 46.0.7~")), interner
        )
        nodes = list(range(len(first.nodes)))
        assert canonical_digest(first, interner, nodes, granularity="exact") != canonical_digest(
            second, interner, nodes, granularity="exact"
        )

    def test_operator_still_distinguishes(self, interner: Interner) -> None:
        """``(= v)`` and ``(< v)`` are different failures."""
        equal = graph_of(
            apt_log(broken("a:amd64", "Depends", "b:amd64", "1.0 @ii mK", "= 2.0")), interner
        )
        less = graph_of(
            apt_log(broken("a:amd64", "Depends", "b:amd64", "1.0 @ii mK", "< 2.0")), interner
        )
        nodes = list(range(len(equal.nodes)))
        assert canonical_digest(equal, interner, nodes) != canonical_digest(less, interner, nodes)

    def test_different_packages_differ(self, interner: Interner) -> None:
        one = graph_of(apt_log(broken("a:amd64", "Depends", "b:amd64", "1.0 @ii mK")), interner)
        two = graph_of(apt_log(broken("c:amd64", "Depends", "d:amd64", "1.0 @ii mK")), interner)
        assert canonical_digest(one, interner, list(range(len(one.nodes)))) != (
            canonical_digest(two, interner, list(range(len(two.nodes))))
        )


class TestVersionNormalisation:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("4:26.2.5.2-0ubuntu0.26.04.1", "26.2.5.2"),
            ("1.23-2build2", "1.23"),
            ("46.0.7~rc1-1", "46.0.7"),
            ("3.13", "3.13"),
            ("2:1.0.9-1build6", "1.0.9"),
        ],
    )
    def test_version(self, raw: str, expected: str) -> None:
        assert normalise_version(raw) == expected

    @pytest.mark.parametrize(
        ("raw", "granularity", "expected"),
        [
            ("= 4:26.2.5.2-0ubuntu0.26.04.1", "exact", "= 4:26.2.5.2-0ubuntu0.26.04.1"),
            ("= 4:26.2.5.2-0ubuntu0.26.04.1", "upstream", "= 26.2.5.2"),
            ("= 4:26.2.5.2-0ubuntu0.26.04.1", "major", "= 26"),
            ("= 4:26.2.5.2-0ubuntu0.26.04.1", "operator", "="),
            ("< 3.13", "operator", "<"),
            ("", "operator", ""),
            (">=", "operator", ">="),
        ],
    )
    def test_constraint(self, raw: str, granularity: str, expected: str) -> None:
        assert normalise_constraint(raw, granularity) == expected


class TestEdgeScores:
    def test_zero_margin_is_distinguished_from_absent(self, interner: Interner) -> None:
        """A genuine ``0`` versus ``0`` pair occurs and is maximally fragile.

        ``Considering libavcodec62 0 as a solution to calibre-bin 0`` appears in
        a real log. Treating ``(0, 0)`` as "no data" suppressed the strongest
        fragility signal available, so presence is tracked explicitly.
        """
        scored = graph_of(
            apt_log(
                broken("dep:amd64", "Depends", "blocker:amd64", "none | 1.0 @un uH"),
                "  Considering blocker:amd64 0 as a solution to dep:amd64 0",
                "  Holding Back dep:amd64 rather than change blocker:amd64",
            ),
            interner,
        )
        unscored = graph_of(
            apt_log(
                broken("dep:amd64", "Depends", "blocker:amd64", "none | 1.0 @un uH"),
                "  Holding Back dep:amd64 rather than change blocker:amd64",
            ),
            interner,
        )
        with_scores = [e for e in iter_edges(scored) if e.has_scores]
        without = [e for e in iter_edges(unscored) if e.has_scores]
        assert with_scores and with_scores[0].score_margin == 0
        assert not without


class TestBuilderDeduplication:
    def test_repeated_broken_line_is_one_edge(self, interner: Interner) -> None:
        """The same assertion appears once per resolver pass."""
        line = broken("a:amd64", "Depends", "b:amd64", "1.0 @ii mR")
        graph = graph_of(apt_log(line, line, line), interner)
        assert len(graph.edges) == 1

    def test_shallowest_depth_is_kept(self, interner: Interner) -> None:
        """A conflict reported at depth 0 is top-level; at depth 12 it is a
        consequence of walking into a subtree."""
        graph = graph_of(
            apt_log(
                broken("a:amd64", "Depends", "b:amd64", "1.0 @ii mR", indent=12),
                broken("a:amd64", "Depends", "b:amd64", "1.0 @ii mR", indent=0),
            ),
            interner,
        )
        assert iter_edges(graph)[0].depth == 0

    def test_self_edges_are_dropped(self, interner: Interner) -> None:
        """``Package A A Depends on B`` echoes the name; A->A says nothing."""
        graph = graph_of(
            apt_log("Package a:amd64 a:amd64 Depends on a:amd64 < 1.0 @ii mP >"), interner
        )
        assert len(graph.edges) == 0


# ---------------------------------------------------------------------------
# Interning
# ---------------------------------------------------------------------------


class TestMasking:
    REAL_LINES = (
        "dpkg: error processing archive /tmp/apt/042-libfoo1_1.2.3-4_amd64.deb (--unpack):",
        "trying to overwrite '/usr/lib/libfoo.so.1', which is also in package libbar1 1.0-2",
        "Broken lintian:amd64 Depends on libfile-libmagic-perl:amd64"
        " < none | 1.23-2build2 @un uH >",
        "  MarkInstall gcc-15:amd64 < 15.2.0-16ubuntu1 -> 15.3.0-1ubuntu1 @ii umU Ib > FU=0",
        "  Considering libfile-libmagic-perl:amd64 0 as a solution to lintian:amd64 -1",
        "installed libbar1 package post-installation script subprocess"
        " returned error exit status 1",
    )

    @pytest.mark.parametrize("line", REAL_LINES)
    def test_round_trip(self, line: str) -> None:
        """A masked line reconstructs exactly, up to whitespace.

        Regression: masks used to be applied one at a time over the whole line,
        so the captured tokens accumulated in mask order while the placeholders
        sat in positional order. The two lists disagreed and the line could not
        be rebuilt.
        """
        pattern, args = mask_line(line)
        assert render_template(pattern, args) == " ".join(line.split())

    def test_victims_of_one_root_share_a_template(self) -> None:
        """Forty ``python3-*`` breakages must be one template, not forty.

        Document frequency is what makes similarity scoring meaningful, and it
        is destroyed if every victim forks its own template.
        """
        patterns = {
            mask_line(
                f"Broken python3-{name}:amd64 Depends on python3:amd64"
                " < 3.12.3-0ubuntu2.1 -> 3.14.3-0ubuntu2 @ii umU > (< 3.13)"
            )[0]
            for name in ("apt", "yaml", "numpy", "lxml", "dbus", "tk", "gi")
        }
        assert len(patterns) == 1

    @pytest.mark.parametrize(
        "name",
        ["gcc-15:amd64", "libpython3.14-minimal:amd64", "liblua5.5-0:amd64", "libqt6xml6t64:amd64"],
    )
    def test_package_names_with_digits_survive(self, name: str) -> None:
        """Package references are masked before numbers.

        Otherwise ``gcc-15:amd64`` becomes ``gcc-<N>:amd64`` and two unrelated
        packages collide.
        """
        pattern, _ = mask_line(f"MarkKeep {name} < 1.0 @ii mK >")
        assert pattern == "MarkKeep <PKG> < <VER> @ii mK >"

    def test_distinct_failures_stay_distinct(self) -> None:
        holdback, _ = mask_line(
            "Broken lintian:amd64 Depends on libfile-libmagic-perl:amd64 < none | 1.0 @un uH >"
        )
        pin, _ = mask_line(
            "Broken python3-apt:amd64 Depends on python3:amd64 < 1.0 -> 2.0 @ii umU > (< 3.13)"
        )
        assert holdback != pin


class TestPackageKeys:
    @pytest.mark.parametrize(
        ("ref", "key"),
        [
            ("libfoo1:amd64", "libfoo1:amd64"),
            ("i965-va-driver:i386", "i965-va-driver:i386"),
            ("libgamemode0:i386:any", "libgamemode0:i386:any"),
            ("tzdata", "tzdata"),
        ],
    )
    def test_canonical_key(self, ref: str, key: str) -> None:
        assert canonical_package_key(ref) == key

    def test_architecture_is_part_of_identity(self, interner: Interner) -> None:
        """Merging architectures would erase the i386-orphan cause entirely."""
        assert interner.package("libva2:amd64") != interner.package("libva2:i386")

    def test_amd64_is_hidden_in_display_only(self, interner: Interner) -> None:
        pkg = interner.package("libfoo1:amd64")
        assert interner.package_key(pkg) == "libfoo1:amd64"
        assert interner.package_label(pkg) == "libfoo1"

    def test_other_architectures_are_shown(self, interner: Interner) -> None:
        pkg = interner.package("i965-va-driver:i386")
        assert interner.package_label(pkg) == "i965-va-driver:i386"


class TestInternStability:
    def test_same_text_same_id(self, interner: Interner) -> None:
        assert interner.string("@ii umU Ib") == interner.string("@ii umU Ib")

    def test_absent_is_zero(self, interner: Interner) -> None:
        """Zero means absent so a packed array needs no presence mask."""
        assert interner.string(None) == 0
        assert interner.string("") == 0
        assert interner.text(0) == ""

    def test_unknown_id_resolves_empty_rather_than_raising(self, interner: Interner) -> None:
        """A report must not explode on a dangling reference."""
        assert interner.text(999_999) == ""
        assert interner.package_key(999_999) == ""


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


def make_run(store: Store, interner: Interner, *, bug_id: int = 1) -> UpgradeRun:
    template, args = interner.template("Broken a:amd64 Depends on b:amd64 < 1.0 @ii mR >")
    root = interner.package("python3:amd64")
    victim = interner.package("python3-apt:amd64")
    return UpgradeRun(
        bug_id=bug_id,
        from_series="noble",
        to_series="resolute",
        arch=Arch.AMD64,
        terminal_phase=Phase.CALCULATE,
        events=(Event(template_id=template, args=args),),
        findings=(
            Finding(
                cause=Cause.EXACT_PIN_BROKEN_BY_UPGRADE,
                root_pkgs=(root,),
                victim_pkgs=(victim,),
                cascade_size=1,
            ),
        ),
        signature=Signature(root_graph=b"\xde\xad\xbe\xef"),
    )


class TestStoreIdempotency:
    def test_reingest_does_not_duplicate_derived_rows(
        self, store: Store, interner: Interner
    ) -> None:
        """Ingest must be safely resumable.

        Derived rows are deleted and rewritten rather than appended, so running
        ingest twice over the same directory leaves identical tables.
        """
        run = make_run(store, interner)
        store.put_run(run)
        store.commit()
        first = (store.document_frequencies(), store.top_blaming_packages())
        store.put_run(run)
        store.commit()
        assert (store.document_frequencies(), store.top_blaming_packages()) == first
        assert store.stats()["runs"] == 1

    def test_binary_blobs_round_trip(self, store: Store, interner: Interner) -> None:
        """Packed arrays are full of high bytes and must not be read as UTF-8."""
        run = make_run(store, interner)
        store.put_run(run)
        store.commit()
        loaded = store.get_run("lp:1#0")
        assert loaded is not None
        assert loaded.signature.root_graph == b"\xde\xad\xbe\xef"

    def test_document_frequency_counts_reports_not_lines(
        self, store: Store, interner: Interner
    ) -> None:
        """A template appearing forty times in one log counts once."""
        template, args = interner.template("Broken a:amd64 Depends on b:amd64 < 1.0 @ii mR >")
        run = UpgradeRun(
            bug_id=7,
            events=tuple(Event(template_id=template, args=args) for _ in range(40)),
        )
        store.put_run(run)
        store.commit()
        assert store.document_frequencies()[template] == 1

    def test_local_runs_without_a_bug_id_get_distinct_keys(self, store: Store) -> None:
        """SQLite allows NULL in a primary key, so a synthetic key is used."""
        store.put_run(UpgradeRun(bug_id=None, source_dir="/a"))
        store.put_run(UpgradeRun(bug_id=None, source_dir="/b"))
        store.commit()
        assert store.stats()["runs"] == 2


class TestStoreQueries:
    def test_signature_grouping(self, store: Store, interner: Interner) -> None:
        store.put_run(make_run(store, interner, bug_id=1))
        store.put_run(make_run(store, interner, bug_id=2))
        store.commit()
        groups = store.keys_by_signature("root_graph")
        assert sorted(groups[b"\xde\xad\xbe\xef"]) == ["lp:1#0", "lp:2#0"]

    def test_rejects_an_arbitrary_signature_column(self, store: Store) -> None:
        """The column name is interpolated into SQL, so it is allowlisted."""
        with pytest.raises(ValueError, match="not a signature column"):
            store.keys_by_signature("payload")

    def test_top_blaming_packages(self, store: Store, interner: Interner) -> None:
        store.put_run(make_run(store, interner, bug_id=1))
        store.put_run(make_run(store, interner, bug_id=2))
        store.commit()
        top = store.top_blaming_packages()
        assert top[0][1] == "python3:amd64"
        assert top[0][2] == 2

    def test_newer_schema_is_refused(self, store: Store, tmp_path: object) -> None:
        """Better to refuse a store than to misread it."""
        store.meta_put("schema_version", "999")
        store.commit()
        path = store.path
        store.close()
        with pytest.raises(RuntimeError, match="schema version 999"):
            Store(path)


# ---------------------------------------------------------------------------
# Sanitising and redaction
# ---------------------------------------------------------------------------


class TestSanitize:
    def test_carriage_return_overwrite_keeps_the_last_segment(self) -> None:
        from uru_doctor.parsers.sanitize import sanitize_line

        line = "(Reading database ... 5%\r(Reading database ... 100% 512345 files)"
        assert sanitize_line(line) == "(Reading database ... 100% 512345 files)"

    def test_repeated_progress_without_cr_collapses(self) -> None:
        from uru_doctor.parsers.sanitize import sanitize_line

        line = "(Reading database ...(Reading database ... 5%(Reading database ... 45% done)"
        assert sanitize_line(line) == "(Reading database ... done)"

    def test_ansi_sequences_removed(self) -> None:
        from uru_doctor.parsers.sanitize import sanitize_line

        assert sanitize_line("\x1b[1;32mSetting up\x1b[0m libfoo1") == "Setting up libfoo1"


class TestRedaction:
    def test_hostname_and_user(self) -> None:
        from uru_doctor.parsers.sanitize import redact

        text = redact("uname information: 'Linux coruscant 7.0.0-22-generic'")
        assert "coruscant" not in text
        assert "redacted-host" in text

    def test_home_directory_account_name(self) -> None:
        from uru_doctor.parsers.sanitize import redact

        assert redact("/home/alice/.config/x") == "/home/redacted-user/.config/x"

    @pytest.mark.parametrize("version", ["2.20.0.1", "6.14.0.37", "1.2.3.4", "255.255.255.255"])
    def test_four_part_versions_survive(self, version: str) -> None:
        """Versions are the evidence and must not be eaten as addresses.

        A bare dotted-quad rule destroyed ``libva2 2.20.0.1``, so address
        redaction requires network context instead.
        """
        from uru_doctor.parsers.sanitize import redact

        assert version in redact(f"libfoo requires {version} exactly")

    @pytest.mark.parametrize(
        "line",
        [
            "connecting to http://192.168.1.47/ubuntu",
            "client 10.0.0.5 connected",
            "from 172.16.31.9 failed",
            "peer 192.168.0.1:8080 reset",
            "nameserver=1.1.1.1",
        ],
    )
    def test_addresses_in_network_context_are_removed(self, line: str) -> None:
        from uru_doctor.parsers.sanitize import redact

        assert redact(line) != line

    def test_idempotent(self) -> None:
        """A committed fixture can be regenerated and diffed."""
        from uru_doctor.parsers.sanitize import redact

        once = redact("alice@host:~$ x\n/home/alice/y\nfrom 10.0.0.1 ok")
        assert redact(once) == once

    def test_ppa_origins_survive(self) -> None:
        """An unsupported PPA's identity is the whole third-party finding."""
        from uru_doctor.parsers.sanitize import redact

        line = "ppa.launchpadcontent.net/linux-surface/release/ubuntu noble/main"
        assert redact(line) == line


class TestFixturesAreClean:
    """Committed fixtures are real logs from real machines."""

    @pytest.mark.parametrize(
        "secret", ["coruscant", "bamf0", "doug-MINIPC", "/home/bamf0", "@canonical.com"]
    )
    def test_no_personal_data(self, secret: str) -> None:
        from tests.conftest import FIXTURES

        hits = [
            path.name
            for path in FIXTURES.rglob("*.log")
            if secret in path.read_text(encoding="utf-8", errors="replace")
        ]
        assert hits == [], f"{secret!r} leaked into {hits}"

    def test_package_evidence_preserved(self) -> None:
        """Redaction must not have taken the evidence with it."""
        text = fixture_text("apt/lp2150319-apt.log")
        assert "libfile-libmagic-perl" in text
        assert "@un uH" in text
