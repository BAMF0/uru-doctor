# SPDX-License-Identifier: GPL-2.0-or-later
"""Deciding which cached attachments nobody can miss, without deleting any.

The attachment cache exists so that re-fetching a bug is a conditional GET.
It is read by exactly one code path -- the Launchpad client's downloader --
so everything the corpus *is* (runs, signatures, diagnoses) survives its
loss, and what a deletion costs is a re-download, at pacing, only if that
bug is ever fetched again. This module classifies; the CLI deletes.

Three kinds of entry are reclaimable without tradeoffs at all:

- **orphan files**: on disk with no ``attachments`` row. Nothing tracks
  them, so nothing will ever look for them.
- **stale rows**: an ``attachments`` row whose file is gone. The row's only
  use is pointing at the file, and it points at nothing.
- **unusable content**: bytes that can never produce a run. The name is
  classified irrelevant, or the name is unknown and re-sniffing the cached
  copy finds no log source -- the same decision the fetcher made when it
  discarded the content, reproduced offline with the same bytes and the same
  limit. Even a future, broader ``sniff_source`` loses nothing here: nothing
  re-ingests from the cache independently, and a re-fetch re-downloads and
  re-sniffs regardless.

Everything else -- the logs a run was diagnosed from -- is kept unless
``everything`` is asked for, and the plan says how much of it there is in
plain numbers, because that is the one deletion with a real price.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

from uru_doctor.parsers.apportmeta import attachment_source, is_irrelevant_attachment, sniff_source
from uru_doctor.parsers.sanitize import read_log

if TYPE_CHECKING:
    from collections.abc import Sequence

    from uru_doctor.store import CachedAttachment

__all__ = ["CleanPlan", "plan_clean", "resolve"]

_SNIFF_LIMIT: Final = 256 * 1024
"""How much of a cached file to sniff. Must match the fetcher's limit."""


@dataclass(frozen=True, slots=True)
class CleanPlan:
    """What a ``clean`` would reclaim, classified so the report can say why.

    Byte counts come from the files themselves where they exist; a row's
    recorded ``size`` is a fetch-time claim and the file is the truth.
    """

    orphans: tuple[Path, ...] = ()
    """Files no ``attachments`` row tracks."""

    stale: tuple[CachedAttachment, ...] = ()
    """Rows whose file is gone. Dropping them reclaims no bytes, only lies."""

    unusable: tuple[CachedAttachment, ...] = ()
    """Rows whose bytes can never produce a run. File and row both go."""

    forced: tuple[CachedAttachment, ...] = ()
    """Usable logs, reclaimed only because ``everything`` was asked for."""

    kept: tuple[CachedAttachment, ...] = ()
    """Usable logs, staying."""

    orphan_bytes: int = 0
    unusable_bytes: int = 0
    forced_bytes: int = 0
    kept_bytes: int = 0

    @property
    def reclaimable_files(self) -> int:
        return len(self.orphans) + len(self.unusable) + len(self.forced)

    @property
    def rows_dropped(self) -> int:
        return len(self.stale) + len(self.unusable) + len(self.forced)

    @property
    def reclaimable_bytes(self) -> int:
        return self.orphan_bytes + self.unusable_bytes + self.forced_bytes

    @property
    def empty(self) -> bool:
        """Nothing to do: no orphans, no stale rows, nothing reclaimable."""
        return not (self.orphans or self.stale or self.unusable or self.forced)


def resolve(row: CachedAttachment, cache_dir: Path) -> Path | None:
    """The file a row points at, or ``None`` if it is gone.

    Two candidates, because a row written with a relative ``state_dir``
    records a relative path, which resolves only from the directory the
    fetch ran in. The cache layout is flat and every filename embeds its bug
    id, so falling back to the one directory we *do* know is exact, not a
    guess.
    """
    if row.path.is_file():
        return row.path
    candidate = cache_dir / row.path.name
    return candidate if candidate.is_file() else None


def _unusable(name: str, file: Path) -> bool:
    """Whether these bytes can never produce a run.

    The fetch-time decision, reproduced offline: a name known to be
    irrelevant, or a name nobody knows whose content sniffs as no log
    source. ``read_log`` decodes exactly as at fetch time and the limit
    matches, so the answer is the one the fetcher reached.
    """
    if is_irrelevant_attachment(name):
        return True
    if attachment_source(name) is not None:
        return False
    try:
        head = file.read_bytes()[:_SNIFF_LIMIT]
    except OSError:
        # Unreadable is not "unusable"; a file that cannot be read cannot be
        # classified, and classifying it as trash would be a guess.
        return False
    return sniff_source(read_log(head, redacted=False), limit=_SNIFF_LIMIT) is None


def plan_clean(
    rows: Sequence[CachedAttachment], cache_dir: Path, *, everything: bool = False
) -> CleanPlan:
    """Classify the whole cache. Pure: no deletion, no writes.

    Classification still runs under ``everything``: the difference between a
    usable log and a useless screenshot is exactly what the report owes the
    person about to type ``--yes``, and it costs one 256KB read per file.
    """
    by_name = {row.path.name for row in rows}

    orphans: list[Path] = []
    orphan_bytes = 0
    if cache_dir.is_dir():
        for entry in sorted(cache_dir.iterdir()):
            if not entry.is_file() or entry.name in by_name:
                continue
            orphans.append(entry)
            orphan_bytes += entry.stat().st_size

    stale: list[CachedAttachment] = []
    unusable: list[CachedAttachment] = []
    forced: list[CachedAttachment] = []
    kept: list[CachedAttachment] = []
    unusable_bytes = forced_bytes = kept_bytes = 0

    for row in rows:
        file = resolve(row, cache_dir)
        if file is None:
            stale.append(row)
            continue
        size = file.stat().st_size
        if _unusable(row.name, file):
            unusable.append(row)
            unusable_bytes += size
        elif everything:
            forced.append(row)
            forced_bytes += size
        else:
            kept.append(row)
            kept_bytes += size

    return CleanPlan(
        orphans=tuple(orphans),
        stale=tuple(stale),
        unusable=tuple(unusable),
        forced=tuple(forced),
        kept=tuple(kept),
        orphan_bytes=orphan_bytes,
        unusable_bytes=unusable_bytes,
        forced_bytes=forced_bytes,
        kept_bytes=kept_bytes,
    )
