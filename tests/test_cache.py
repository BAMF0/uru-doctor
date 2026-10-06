# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for :mod:`uru_doctor.cache` -- what a ``clean`` would reclaim.

The classification is the whole safety story: a wrong "unusable" verdict
deletes a log a run was diagnosed from, so each class is pinned by a case
containing that class and nothing else.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import fixture_text
from uru_doctor.cache import plan_clean, resolve
from uru_doctor.store import CachedAttachment, Store


def _row(cache: Path, bug_id: int, name: str, content: bytes | None = b"x") -> CachedAttachment:
    """One row; ``content`` also writes the file it points at."""
    path = cache / f"{bug_id}-{name.replace('/', '_')}"
    if content is not None:
        path.write_bytes(content)
    return CachedAttachment(
        bug_id=bug_id, name=name, etag=None, path=path, size=len(content or b"")
    )


@pytest.fixture
def cache(tmp_path: Path) -> Path:
    directory = tmp_path / "attachments"
    directory.mkdir()
    return directory


class TestPlanClean:
    def test_an_orphan_file_is_reclaimed(self, cache: Path) -> None:
        orphan = cache / "2161332-screenshot.png"
        orphan.write_bytes(b"\x89PNG" * 100)
        plan = plan_clean([], cache)
        assert plan.orphans == (orphan,)
        assert plan.orphan_bytes == orphan.stat().st_size
        assert plan.reclaimable_bytes == plan.orphan_bytes

    def test_a_row_whose_file_is_gone_is_stale(self, cache: Path) -> None:
        row = _row(cache, 1, "apt.log", content=None)
        plan = plan_clean([row], cache)
        assert plan.stale == (row,)
        # Nothing to reclaim on disk: the file is already gone.
        assert plan.reclaimable_files == 0

    def test_a_named_log_is_kept(self, cache: Path) -> None:
        row = _row(cache, 1, "apt.log")
        plan = plan_clean([row], cache)
        assert plan.kept == (row,)
        assert plan.empty

    def test_an_irrelevant_name_is_unusable(self, cache: Path) -> None:
        row = _row(cache, 1, "VarLogDistupgradeAptclonesystemstate.tar.gz", b"t" * 500)
        plan = plan_clean([row], cache)
        assert plan.unusable == (row,)
        assert plan.unusable_bytes == 500

    def test_an_unknown_name_with_log_content_is_kept(self, cache: Path) -> None:
        """The sniff, not the name, decides: a hand-renamed log is still a log."""
        head = fixture_text("apt/lp2150339-apt.log")[:64_000].encode()
        row = _row(cache, 1, "my-upgrade-log", head)
        plan = plan_clean([row], cache)
        assert plan.kept == (row,)

    def test_an_unknown_name_with_binary_content_is_unusable(self, cache: Path) -> None:
        row = _row(cache, 1, "screenshot-of-the-error", b"\x89PNG\r\n\x1a\n" * 200)
        plan = plan_clean([row], cache)
        assert plan.unusable == (row,)

    def test_relative_paths_resolve_by_filename(self, cache: Path) -> None:
        """Rows written with a relative ``state_dir`` record relative paths.

        Those resolve only from the directory the fetch ran in, so ``clean``
        falls back to the filename inside the one cache directory it knows.
        """
        file = cache / "1-apt.log"
        file.write_bytes(b"x" * 100)
        row = CachedAttachment(
            bug_id=1,
            name="apt.log",
            etag=None,
            path=Path(".uru-doctor/attachments/1-apt.log"),
            size=100,
        )
        assert resolve(row, cache) == file
        plan = plan_clean([row], cache)
        assert plan.stale == ()
        assert plan.kept == (row,)

    def test_bytes_come_from_the_file_not_the_row(self, cache: Path) -> None:
        """The row's ``size`` is a fetch-time claim; the file is the truth."""
        row = _row(cache, 1, "VarLogDistupgradeAptclonesystemstate.tar.gz", b"t" * 500)
        row = CachedAttachment(
            bug_id=row.bug_id, name=row.name, etag=None, path=row.path, size=0
        )
        plan = plan_clean([row], cache)
        assert plan.unusable_bytes == 500

    def test_subdirectories_are_skipped(self, cache: Path) -> None:
        (cache / "nested").mkdir()
        plan = plan_clean([], cache)
        assert plan.orphans == ()

    def test_a_missing_cache_dir_is_an_empty_plan(self, tmp_path: Path) -> None:
        plan = plan_clean([], tmp_path / "never-existed")
        assert plan.empty

    def test_everything_forces_usable_logs_but_keeps_the_distinction(
        self, cache: Path
    ) -> None:
        """The report owes ``--yes`` the difference between a log and a PNG."""
        log = _row(cache, 1, "apt.log", b"x" * 100)
        junk = _row(cache, 2, "screenshot", b"\x89PNG" * 100)
        plan = plan_clean([log, junk], cache, everything=True)
        assert plan.forced == (log,)
        assert plan.forced_bytes == 100
        assert plan.unusable == (junk,)
        assert plan.kept == ()


class TestAttachmentRows:
    def test_put_rows_drop_roundtrip(self, tmp_path: Path) -> None:
        with Store.open(tmp_path) as store:
            store.attachment_put(1, "apt.log", '"etag"', tmp_path / "1-apt.log", 123)
            store.attachment_put(1, "main.log", None, tmp_path / "1-main.log", 45)
            rows = store.attachment_rows()
            assert {(r.bug_id, r.name) for r in rows} == {(1, "apt.log"), (1, "main.log")}
            by_name = {r.name: r for r in rows}
            assert by_name["apt.log"].etag == '"etag"'
            assert by_name["apt.log"].size == 123
            assert by_name["main.log"].etag is None
            store.attachment_drop(1, "apt.log")
            assert [r.name for r in store.attachment_rows()] == ["main.log"]
