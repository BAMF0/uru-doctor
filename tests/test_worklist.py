# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for the triage worklist: :mod:`uru_doctor.worklist` and its store.

Two kinds of test live here.

The **classification** tests state one premise each. A bucket is a judgement
about what a human should do next, and the cost of getting one wrong is a
triager acting on a wrong proposal -- so each rule is pinned by a case
containing that rule and nothing else.

The **projection** tests are about cost. The worklist's whole claim to scale is
that it reads indexed columns and never a payload, which is not something a
reader can verify by inspection and is trivially broken by a well-meaning
refactor. So the SQL is asserted against directly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tests.test_core import make_run
from uru_doctor.config import Config
from uru_doctor.dedup import Tier, cluster_runs, tier_index, tier_name
from uru_doctor.intern import Interner
from uru_doctor.models import Cause, Signature
from uru_doctor.store import CLOSED_STATUSES, BugState, Store, TriageRow
from uru_doctor.worklist import Bucket, classify

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)


def row(
    bug_id: int,
    *,
    cause: Cause | None = Cause.RESOLVER_LIVELOCK,
    status: str = "New",
    evidence_complete: bool = True,
    duplicate_of: int | None = None,
    is_duplicate: bool | None = None,
    checked: datetime | None = NOW,
    state: bool = True,
) -> TriageRow:
    """One projected run, with everything irrelevant defaulted away."""
    return TriageRow(
        run_key=f"lp:{bug_id}#0",
        bug_id=bug_id,
        label=f"LP#{bug_id}",
        cause=cause,
        third_party=cause is Cause.THIRD_PARTY_PIN,
        evidence_complete=evidence_complete,
        current_title="",
        duplicate_count=0,
        lex_lines=100,
        lex_unmatched=0,
        state=(
            BugState(
                bug_id=bug_id,
                status=status,
                duplicate_of=duplicate_of,
                is_duplicate=is_duplicate,
                checked_at=checked.isoformat() if checked else "",
            )
            if state
            else None
        ),
    )


def bucket_of(rows: list[TriageRow], bug_id: int, clusters: object = ()) -> Bucket:
    worklist = classify(rows, clusters)  # type: ignore[arg-type]
    return next(item.bucket for item in worklist.items if item.row.bug_id == bug_id)


def one_cluster(master: int, *members: int, tier: str = Tier.ROOT_GRAPH) -> list[object]:
    """A cluster object shaped like :class:`~uru_doctor.dedup.Cluster`."""
    from uru_doctor.dedup import Cluster

    keys = [f"lp:{m}#0" for m in (master, *members)]
    return [
        Cluster(
            key=b"digest",
            tier=tier,
            members=keys,
            representative=f"lp:{master}#0",
        )
    ]


class TestBuckets:
    """One premise per test. A bucket is a proposal to a human."""

    def test_unknown_status_is_separated_before_anything_else(self) -> None:
        """A status nobody has read cannot be classified, and is not guessed.

        It comes first precisely because every other rule reads the status:
        filing an unread bug as "diagnosed and still New" would invent the one
        fact that is missing.
        """
        rows = [row(1, state=False)]
        assert bucket_of(rows, 1) == Bucket.STATUS_UNKNOWN

    def test_empty_status_counts_as_unknown_not_as_a_status(self) -> None:
        rows = [row(1, status="")]
        assert bucket_of(rows, 1) == Bucket.STATUS_UNKNOWN

    def test_root_graph_duplicate_is_proposed_for_marking(self) -> None:
        rows = [row(1), row(2)]
        worklist = classify(rows, one_cluster(1, 2))  # type: ignore[arg-type]
        buckets = {i.row.bug_id: i.bucket for i in worklist.items}
        # The master is not its own duplicate.
        assert buckets[1] == Bucket.DIAGNOSED_UNRECORDED
        assert buckets[2] == Bucket.MARK_DUPLICATE
        item = next(i for i in worklist.items if i.row.bug_id == 2)
        assert item.master == "LP#1"
        assert item.tier == Tier.ROOT_GRAPH
        assert "LP#1" in item.action

    def test_cause_tuple_clusters_are_never_proposed_for_marking(self) -> None:
        """Only the strongest tier is offered as a mechanical action.

        ``cause-tuple`` is the same cause and roots at the same phase, which is
        a lead rather than a verdict, and the corpus contains a sixteen-member
        ``cause-tuple`` cluster of ``no_failure_recorded`` reports that are not
        duplicates of each other at all.
        """
        rows = [row(1), row(2)]
        clusters = one_cluster(1, 2, tier=Tier.CAUSE_TUPLE)
        assert bucket_of(rows, 2, clusters) != Bucket.MARK_DUPLICATE

    @pytest.mark.parametrize("cause", [Cause.NO_FAILURE_RECORDED, Cause.UNKNOWN])
    def test_a_non_diagnosis_is_never_proposed_for_marking(self, cause: Cause) -> None:
        """A non-diagnosis is not a shared root cause.

        This is the guard that stops the worklist opening with fifteen wrong
        actions: a cluster built on the *absence* of a finding groups reports
        that have nothing in common except being unreadable.
        """
        rows = [row(1, cause=cause), row(2, cause=cause)]
        assert bucket_of(rows, 2, one_cluster(1, 2)) != Bucket.MARK_DUPLICATE

    def test_a_bug_launchpad_already_calls_a_duplicate_is_done(self) -> None:
        """The whole point: acting on Launchpad is what clears a row."""
        rows = [row(1), row(2, is_duplicate=True)]
        assert bucket_of(rows, 2, one_cluster(1, 2)) == Bucket.DONE

    def test_disagreement_about_the_master_is_reported(self) -> None:
        rows = [row(1), row(2, is_duplicate=True, duplicate_of=99)]
        worklist = classify(rows, one_cluster(1, 2))  # type: ignore[arg-type]
        item = next(i for i in worklist.items if i.row.bug_id == 2)
        assert item.bucket == Bucket.DUPLICATE_CONFLICT
        assert "LP#99" in item.action
        assert "LP#1" in item.action

    def test_agreement_about_the_master_is_not_a_conflict(self) -> None:
        rows = [row(1), row(2, is_duplicate=True, duplicate_of=1)]
        assert bucket_of(rows, 2, one_cluster(1, 2)) == Bucket.DONE

    def test_no_cluster_is_not_read_as_disagreement(self) -> None:
        """Absence of evidence is not evidence of disagreement.

        The corpus routinely finds no partner for a run. If that counted as
        contradicting Launchpad, every bug Launchpad had grouped and this tool
        had not would be reported as a conflict.
        """
        rows = [row(1, is_duplicate=True, duplicate_of=99)]
        assert bucket_of(rows, 1) == Bucket.DONE

    def test_candidate_invalid_follows_the_primary_cause_only(self) -> None:
        """Not "some finding mentioned a PPA".

        Any machine with a few PPAs has one implicated somewhere, so the
        broader test flags bugs whose real cause is an Ubuntu package -- the
        exact inversion this tool exists to correct.
        """
        third_party = row(1, cause=Cause.THIRD_PARTY_PIN)
        ubuntu_fault = TriageRow(**{**vars_of(row(2)), "third_party": True})
        assert bucket_of([third_party], 1) == Bucket.CANDIDATE_INVALID
        assert bucket_of([ubuntu_fault], 2) != Bucket.CANDIDATE_INVALID

    def test_confident_diagnosis_on_a_new_bug_wants_a_status(self) -> None:
        assert bucket_of([row(1)], 1) == Bucket.DIAGNOSED_UNRECORDED

    def test_incomplete_with_a_diagnosis_says_the_status_may_be_stale(self) -> None:
        """Incomplete is a claim the logs can contradict."""
        rows = [row(1, status="Incomplete")]
        worklist = classify(rows)
        item = worklist.items[0]
        assert item.bucket == Bucket.DIAGNOSED_UNRECORDED
        assert "Incomplete may be stale" in item.action

    def test_incomplete_without_a_diagnosis_is_waiting_on_the_reporter(self) -> None:
        rows = [row(1, status="Incomplete", evidence_complete=False)]
        worklist = classify(rows)
        assert worklist.items[0].bucket == Bucket.NEEDS_READ
        assert "waiting on the reporter" in worklist.items[0].action

    def test_unreadable_but_already_assessed_is_not_work(self) -> None:
        """A human has taken a view; "I cannot read this" adds nothing to it.

        Without this gate the worklist fills with old reports somebody triaged
        years ago -- seven of them in the development corpus.
        """
        rows = [row(1, status="Triaged", evidence_complete=False)]
        assert bucket_of(rows, 1) == Bucket.DONE

    def test_unreadable_and_unassessed_wants_reading(self) -> None:
        rows = [row(1, evidence_complete=False)]
        assert bucket_of(rows, 1) == Bucket.NEEDS_READ

    @pytest.mark.parametrize("status", sorted(CLOSED_STATUSES))
    def test_closed_bugs_are_counted_never_listed(self, status: str) -> None:
        rows = [row(1, status=status)]
        worklist = classify(rows)
        assert worklist.actionable == 0
        assert worklist.counts[Bucket.DONE] == 1
        assert worklist.done_by_status == {status: 1}

    def test_incomplete_is_not_treated_as_closed(self) -> None:
        """It can expire, and a log may have arrived since."""
        assert "Incomplete" not in CLOSED_STATUSES

    def test_every_row_lands_in_exactly_one_bucket(self) -> None:
        rows = [
            row(1),
            row(2, status="Invalid"),
            row(3, state=False),
            row(4, cause=Cause.THIRD_PARTY_PIN),
            row(5, evidence_complete=False),
            row(6, is_duplicate=True),
        ]
        worklist = classify(rows, one_cluster(1, 6))  # type: ignore[arg-type]
        assert len(worklist.items) == len(rows)
        assert sum(worklist.counts.values()) == len(rows)
        assert {i.row.bug_id for i in worklist.items} == {1, 2, 3, 4, 5, 6}


def vars_of(item: TriageRow) -> dict[str, object]:
    """Field values of a slotted frozen dataclass, for building variants."""
    return {
        name: getattr(item, name)
        for name in (
            "run_key",
            "bug_id",
            "label",
            "cause",
            "third_party",
            "evidence_complete",
            "current_title",
            "duplicate_count",
            "lex_lines",
            "lex_unmatched",
            "state",
        )
    }


class TestFreshness:
    """The worklist has to be able to date itself, or it is just an opinion."""

    def test_never_checked_is_stale(self) -> None:
        """Not "fresh because there is no timestamp to contradict me"."""
        worklist = classify([row(1, state=False)])
        assert worklist.oldest_check is None
        assert worklist.stale(now=NOW, after_days=7)

    def test_recent_checks_are_not_stale(self) -> None:
        worklist = classify([row(1, checked=NOW - timedelta(hours=1))])
        assert not worklist.stale(now=NOW, after_days=7)

    def test_the_oldest_check_decides(self) -> None:
        """One unconfirmed bug makes the whole list suspect, by design."""
        worklist = classify([row(1, checked=NOW), row(2, checked=NOW - timedelta(days=30))])
        assert worklist.newest_check == NOW
        assert worklist.stale(now=NOW, after_days=7)

    def test_duplicates_without_a_master_are_reported_for_a_deep_pass(self) -> None:
        worklist = classify([row(1, is_duplicate=True), row(2, is_duplicate=True)])
        assert worklist.deep_unknown == (1, 2)

    def test_a_known_master_is_not_reported_as_unknown(self) -> None:
        worklist = classify([row(1, is_duplicate=True, duplicate_of=7)])
        assert worklist.deep_unknown == ()


class TestTiers:
    """The tier index that ``cluster_members`` stores."""

    def test_round_trips(self) -> None:
        for tier in (Tier.ROOT_GRAPH, Tier.CAUSE_TUPLE, Tier.EVIDENCE):
            assert tier_name(tier_index(tier)) == tier

    def test_strongest_tier_sorts_first(self) -> None:
        """``ORDER BY tier`` has to mean "best first" for the column to help."""
        assert tier_index(Tier.ROOT_GRAPH) < tier_index(Tier.CAUSE_TUPLE)
        assert tier_index(Tier.CAUSE_TUPLE) < tier_index(Tier.EVIDENCE)

    def test_an_unknown_tier_does_not_crash(self) -> None:
        assert tier_index("from-the-future") == 3
        assert tier_name(99) == Tier.NONE


class TestBugState:
    """Merging what several callers learn at several prices."""

    def test_round_trips(self, store: Store) -> None:
        store.put_bug_states([BugState(bug_id=1, status="New", checked_at=NOW.isoformat())])
        assert store.bug_states()[1].status == "New"

    def test_an_empty_status_does_not_erase_a_known_one(self, store: Store) -> None:
        """``fetch`` knows a master but can never know a status.

        It fetches the bug, not its tasks, so it has nothing to say about
        status -- and saying it loudly would blank whatever a sweep had read.
        """
        store.put_bug_states([BugState(bug_id=1, status="Triaged")])
        store.put_bug_states([BugState(bug_id=1, status="", duplicate_of=9)])
        state = store.bug_states()[1]
        assert state.status == "Triaged"
        assert state.duplicate_of == 9

    def test_a_cheap_pass_does_not_erase_a_resolved_master(self, store: Store) -> None:
        """The cheap pass sees *that* a bug is a duplicate, not *of what*."""
        store.put_bug_states([BugState(bug_id=1, duplicate_of=9, is_duplicate=True)])
        store.put_bug_states([BugState(bug_id=1, status="New", is_duplicate=True)])
        assert store.bug_states()[1].duplicate_of == 9

    def test_is_duplicate_is_tri_state(self, store: Store) -> None:
        store.put_bug_states([BugState(bug_id=1, status="New")])
        assert store.bug_states()[1].is_duplicate is None
        store.put_bug_states([BugState(bug_id=1, status="New", is_duplicate=False)])
        assert store.bug_states()[1].is_duplicate is False

    def test_touch_confirms_without_changing(self, store: Store) -> None:
        store.put_bug_states([BugState(bug_id=1, status="New", checked_at="2026-01-01")])
        store.touch_bug_states([1], "2026-10-05")
        state = store.bug_states()[1]
        assert state.status == "New"
        assert state.checked_at == "2026-10-05"

    def test_touch_never_invents_a_row(self, store: Store) -> None:
        """A bug with no row has a status nobody read.

        Writing a fresh timestamp against an absent status would claim
        knowledge of exactly the thing that is missing.
        """
        store.touch_bug_states([404], "2026-10-05")
        assert 404 not in store.bug_states()

    def test_watermark_is_monotonic(self, store: Store) -> None:
        later = datetime(2026, 10, 5, tzinfo=UTC)
        store.advance_status_watermark(later)
        store.advance_status_watermark(datetime(2026, 1, 1, tzinfo=UTC))
        assert store.status_watermark() == later

    def test_the_status_watermark_is_not_the_sweep_watermark(self, store: Store) -> None:
        """They mean different things and advancing one must not move the other.

        The sweep mark is about creation and skips bugs when it advances; this
        one is about modification and only skips re-reading an unchanged
        verdict.
        """
        store.advance_status_watermark(datetime(2026, 10, 5, tzinfo=UTC))
        assert store.sweep_watermark() is None


class TestStaleOrdering:
    """The deep pass picks its batch by staleness, and that is its resumability."""

    @staticmethod
    def _corpus(store: Store, interner: Interner, *bug_ids: int) -> None:
        for bug_id in bug_ids:
            store.put_run(make_run(store, interner, bug_id=bug_id))

    def test_never_checked_sorts_before_any_timestamp(
        self, store: Store, interner: Interner
    ) -> None:
        self._corpus(store, interner, 1, 2)
        store.put_bug_states([BugState(bug_id=1, status="New", checked_at="2020-01-01")])
        assert store.stale_bug_ids(2) == [2, 1]

    def test_oldest_check_comes_first(self, store: Store, interner: Interner) -> None:
        self._corpus(store, interner, 1, 2)
        store.put_bug_states(
            [
                BugState(bug_id=1, status="New", checked_at="2026-10-01"),
                BugState(bug_id=2, status="New", checked_at="2020-01-01"),
            ]
        )
        assert store.stale_bug_ids(2) == [2, 1]

    def test_an_empty_restriction_means_no_candidates(
        self, store: Store, interner: Interner
    ) -> None:
        """Not "no restriction".

        Conflating the two made a deep pass pointed at an empty group fall
        back to the whole corpus and spend its entire request budget on the
        four oldest bugs in the store instead of the three it was aimed at.
        """
        self._corpus(store, interner, 1, 2)
        assert store.stale_bug_ids(5, among=[]) == []
        assert store.stale_bug_ids(5, among=None) == [1, 2]

    def test_a_restriction_is_honoured(self, store: Store, interner: Interner) -> None:
        self._corpus(store, interner, 1, 2, 3)
        assert store.stale_bug_ids(5, among=[3, 1]) == [1, 3]


class TestProjectionsAvoidPayloads:
    """The scaling claim, made executable.

    The worklist is linear in a corpus of thousands only because it reads
    indexed columns. That is invisible in the output and a refactor that adds
    one convenient field from the payload would undo it silently, so the SQL
    is asserted against directly.
    """

    def test_triage_rows_never_selects_the_payload(self, store: Store) -> None:
        traced: list[str] = []
        store._conn.set_trace_callback(traced.append)
        try:
            store.triage_rows()
        finally:
            store._conn.set_trace_callback(None)
        assert traced, "expected at least one statement"
        assert not any("payload" in sql.lower() for sql in traced)

    def test_signature_rows_never_selects_the_payload(self, store: Store) -> None:
        traced: list[str] = []
        store._conn.set_trace_callback(traced.append)
        try:
            store.signature_rows()
        finally:
            store._conn.set_trace_callback(None)
        assert not any("payload" in sql.lower() for sql in traced)

    def test_cluster_facts_never_selects_the_payload(self, store: Store) -> None:
        traced: list[str] = []
        store._conn.set_trace_callback(traced.append)
        try:
            store.cluster_facts()
        finally:
            store._conn.set_trace_callback(None)
        assert not any("payload" in sql.lower() for sql in traced)

    def test_clustering_from_columns_equals_clustering_from_payloads(
        self, store: Store, interner: Interner
    ) -> None:
        """The equivalence the fast path depends on.

        If these ever diverge, ``dedup`` and ``queue`` would report different
        duplicate groupings for one corpus, and the cheaper one would be the
        wrong one.
        """
        for bug_id in range(1, 6):
            run = make_run(store, interner, bug_id=bug_id)
            store.put_run(
                run.model_copy(
                    update={
                        "signature": Signature(
                            root_graph=b"graph" if bug_id % 2 else b"other",
                            cause_tuple=b"tuple",
                        )
                    }
                )
            )
        config = Config()

        from_payload = {
            f"lp:{run.bug_id}#{run.attempt}": run.signature
            for run in store.iter_runs(primary_only=True)
        }
        from_columns = store.signature_rows(primary_only=True)
        assert from_payload == from_columns

        def shape(clusters: object) -> list[tuple[str, str, tuple[str, ...]]]:
            return sorted(
                (c.tier, c.representative, tuple(sorted(c.members)))
                for c in clusters  # type: ignore[attr-defined]
            )

        assert shape(
            cluster_runs(from_payload, config=config.dedup, oldest_first=sorted(from_payload))
        ) == shape(
            cluster_runs(from_columns, config=config.dedup, oldest_first=sorted(from_columns))
        )
