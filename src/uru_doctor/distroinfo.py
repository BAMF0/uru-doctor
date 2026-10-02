# SPDX-License-Identifier: GPL-2.0-or-later
"""Ubuntu release metadata, read from ``distro-info-data``.

The alternative is a hardcoded table of codenames, which is wrong the moment a
new release opens and is a recurring source of embarrassment in tooling that
has to reason about upgrade paths. ``/usr/share/distro-info/ubuntu.csv`` is
shipped by ``distro-info-data``, is updated by the archive, and already knows
every release this tool will ever see.

What the tool actually needs from it:

- codename to version and back, so ``noble`` can be printed as ``24.04 LTS``
  and a bug tagged ``24.04`` can be matched to ``noble``
- an ordering, so that "is this an upgrade or a downgrade" is answerable and
  ``noble -> resolute`` can be distinguished from ``resolute -> noble``
- LTS status, because the LTS-to-LTS path is the one being enabled and has
  different support rules from an interim upgrade
- end-of-life dates, so a bug reported against a dead source release can be
  separated from one against a live one

If the file is missing -- a container, a non-Ubuntu machine -- everything
degrades to "unknown" rather than raising. Diagnosis does not depend on this;
it only makes output legible.
"""

from __future__ import annotations

import csv
from datetime import date
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, ConfigDict

#: Where ``distro-info-data`` installs the Ubuntu table.
UBUNTU_CSV = Path("/usr/share/distro-info/ubuntu.csv")


class Series(BaseModel):
    """One Ubuntu release."""

    model_config = ConfigDict(frozen=True)

    version: str
    """``"24.04 LTS"`` exactly as the CSV spells it, including the LTS suffix."""

    codename: str
    """``"Noble Numbat"``."""

    series: str
    """``"noble"`` -- the short name apt and the upgrader use everywhere."""

    created: date | None = None
    release: date | None = None
    eol: date | None = None
    eol_esm: date | None = None

    @property
    def is_lts(self) -> bool:
        return "LTS" in self.version

    @property
    def number(self) -> str:
        """``"24.04"`` -- the version without the LTS suffix."""
        return self.version.replace(" LTS", "").strip()

    @property
    def sort_key(self) -> tuple[int, int]:
        """``(year, month)`` for ordering.

        Derived from the version number rather than the release date, because
        the development release has a release date in the future and sorting on
        dates would misplace it.
        """
        try:
            year, month = self.number.split(".")[:2]
            return (int(year), int(month))
        except (ValueError, IndexError):  # pragma: no cover - malformed CSV row
            return (0, 0)

    def is_eol_on(self, when: date) -> bool:
        """Whether standard support had ended by ``when``.

        ESM is deliberately ignored: a bug against a release that is only alive
        under ESM is still a bug the release team does not act on through this
        path.
        """
        return self.eol is not None and self.eol < when

    def __str__(self) -> str:
        return f"{self.series} ({self.version})"


def _parse_date(value: str) -> date | None:
    value = value.strip()
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:  # pragma: no cover - the CSV has been ISO for years
        return None


class SeriesTable(BaseModel):
    """Every known release, indexed for the lookups this tool performs."""

    model_config = ConfigDict(frozen=True)

    entries: tuple[Series, ...] = ()

    @classmethod
    def load(cls, path: Path | None = None) -> SeriesTable:
        """Read the CSV, returning an empty table if it is unavailable."""
        source = path or UBUNTU_CSV
        if not source.is_file():
            return cls()
        rows: list[Series] = []
        with source.open(newline="", encoding="utf-8") as handle:
            for raw in csv.DictReader(handle):
                series = (raw.get("series") or "").strip()
                if not series:
                    continue
                rows.append(
                    Series(
                        version=(raw.get("version") or "").strip(),
                        codename=(raw.get("codename") or "").strip(),
                        series=series,
                        created=_parse_date(raw.get("created") or ""),
                        release=_parse_date(raw.get("release") or ""),
                        eol=_parse_date(raw.get("eol") or ""),
                        eol_esm=_parse_date(raw.get("eol-esm") or ""),
                    )
                )
        return cls(entries=tuple(sorted(rows, key=lambda s: s.sort_key)))

    def by_series(self, series: str) -> Series | None:
        """Look up by short name, e.g. ``"noble"``."""
        wanted = series.strip().lower()
        for entry in self.entries:
            if entry.series == wanted:
                return entry
        return None

    def by_version(self, version: str) -> Series | None:
        """Look up by version number, with or without the LTS suffix.

        Bug reports spell this inconsistently -- ``24.04``, ``24.04 LTS``,
        ``Ubuntu 24.04`` -- so the needle is normalised before comparison.
        """
        wanted = version.replace("LTS", "").replace("Ubuntu", "").strip()
        for entry in self.entries:
            if entry.number == wanted:
                return entry
        return None

    def resolve(self, value: str) -> Series | None:
        """Look up by whatever a log or bug field happens to contain."""
        if not value:
            return None
        return self.by_series(value) or self.by_version(value)

    def label(self, series: str) -> str:
        """Render a short name for humans, falling back to the input.

        ``"noble"`` becomes ``"noble (24.04 LTS)"``; an unrecognised name is
        returned unchanged rather than hidden.
        """
        found = self.by_series(series)
        return str(found) if found else series

    def is_upgrade(self, from_series: str, to_series: str) -> bool | None:
        """Whether this is a forward upgrade. None when either end is unknown."""
        src, dst = self.by_series(from_series), self.by_series(to_series)
        if src is None or dst is None:
            return None
        return dst.sort_key > src.sort_key

    def is_lts_to_lts(self, from_series: str, to_series: str) -> bool | None:
        """Whether both ends are LTS releases.

        The path this tool exists for. An LTS-to-LTS upgrade is only offered
        after the ``.1`` point release, which is why bugs filed before then
        attract "not supported yet" comments that are correct but unhelpful.
        """
        src, dst = self.by_series(from_series), self.by_series(to_series)
        if src is None or dst is None:
            return None
        return src.is_lts and dst.is_lts

    def intermediate(self, from_series: str, to_series: str) -> tuple[Series, ...]:
        """Releases strictly between two endpoints.

        An LTS-to-LTS upgrade skips these entirely, which is exactly why it
        breaks in ways an interim upgrade never does: two years of transitions
        land at once.
        """
        src, dst = self.by_series(from_series), self.by_series(to_series)
        if src is None or dst is None:
            return ()
        lo, hi = src.sort_key, dst.sort_key
        if lo > hi:
            lo, hi = hi, lo
        return tuple(e for e in self.entries if lo < e.sort_key < hi)


@lru_cache(maxsize=1)
def series_table() -> SeriesTable:
    """The process-wide table. Cached; the file does not change under us."""
    return SeriesTable.load()
