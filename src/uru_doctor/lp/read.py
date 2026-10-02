# SPDX-License-Identifier: GPL-2.0-or-later
"""Read bugs and their logs from Launchpad, anonymously.

Read-only by construction: there is no code here that can write to Launchpad,
and the client is never handed credentials. Retitling and duplicate-marking are
proposals for a human to apply.

Three things about this API are load-bearing and were all found the hard way.

**It returns 429 readily, and recovering costs about a minute.** Spacing
requests out is therefore much cheaper than retrying them, which is why
requests are serialised with a measured minimum gap rather than issued
concurrently. Parallelism makes a corpus fetch slower, not faster.

**A third of the useful attachments are hand-uploaded under unpredictable
names.** Reporters attach ``apt.log``, ``aptlog.txt``, ``my-upgrade-log`` and
worse. Fetching only the names apport generates loses them, so an unrecognised
name is downloaded and identified by its contents --
:func:`~uru_doctor.parsers.apportmeta.sniff_source` -- while a name known to be
irrelevant is skipped without a request. "Unknown" and "irrelevant" are
different answers and must not be collapsed.

**The attachment listing is a separate request from the bug, and the data is a
third.** So a bug with four logs costs six requests, and at three seconds each
a hundred-bug corpus is half an hour. ETags are cached in the store, which
makes a re-fetch nearly free.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Final

import httpx

from uru_doctor.config import LaunchpadConfig
from uru_doctor.models import LogSource
from uru_doctor.parsers.apportmeta import (
    attachment_source,
    is_irrelevant_attachment,
    sniff_source,
)
from uru_doctor.parsers.sanitize import read_log
from uru_doctor.store import Store

__all__ = [
    "AttachmentRef",
    "BugRecord",
    "Launchpad",
    "LaunchpadError",
    "RateLimited",
]

_RETRY_STATUS: Final[frozenset[int]] = frozenset({429, 500, 502, 503, 504})

_SNIFF_LIMIT: Final = 256 * 1024
"""How much of an unrecognised attachment to read before identifying it.

``sniff_source`` looks at the first lines. Reading a whole hand-uploaded
tarball to discover it is a tarball would defeat the point.
"""


class LaunchpadError(RuntimeError):
    """A request failed in a way retrying will not fix."""


class RateLimited(LaunchpadError):
    """Still being refused after every retry.

    Separate from :class:`LaunchpadError` so a corpus fetch can stop entirely
    rather than march through the remaining bugs collecting the same failure.
    """


@dataclass(frozen=True, slots=True)
class AttachmentRef:
    """One attachment, before deciding whether to download it."""

    title: str
    data_url: str
    source: LogSource | None = None
    """Identified from the title alone. ``None`` means unknown, not useless."""

    irrelevant: bool = False
    """Known to contain no upgrade evidence, so not worth a request."""

    @property
    def worth_fetching(self) -> bool:
        return not self.irrelevant and bool(self.data_url)


@dataclass(frozen=True, slots=True)
class BugRecord:
    """What a bug says about itself.

    The prose fields are carried because the report shows the current title for
    a triager's convenience and ``parse_apport_meta`` reads the description.
    None of them may reach a diagnosis or a signature: that is enforced in
    :mod:`uru_doctor.dedup` by :data:`~uru_doctor.dedup.EXCLUDED_FROM_SIGNATURES`,
    not here.
    """

    bug_id: int
    title: str = ""
    description: str = ""
    tags: tuple[str, ...] = ()
    duplicate_of: int | None = None
    duplicate_count: int = 0
    created: datetime | None = None
    attachments: tuple[AttachmentRef, ...] = ()

    @property
    def log_attachments(self) -> tuple[AttachmentRef, ...]:
        return tuple(a for a in self.attachments if a.worth_fetching)


def _bug_id_from_link(link: str | None) -> int | None:
    """``.../bugs/2150245`` to ``2150245``."""
    if not link:
        return None
    tail = link.rstrip("/").rsplit("/", 1)[-1]
    return int(tail) if tail.isdigit() else None


def _parse_created(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


@dataclass(slots=True)
class Launchpad:
    """A rate-limited, anonymous Launchpad reader.

    ``client`` is injectable so that tests can supply an
    :class:`httpx.MockTransport` and so a caller can set its own timeouts. When
    omitted one is built from ``config``.
    """

    config: LaunchpadConfig = field(default_factory=LaunchpadConfig)
    store: Store | None = None
    """Used only as an ETag and body cache. Optional; fetching works without it."""

    cache_dir: Path | None = None
    client: httpx.Client | None = None
    sleep: Any = time.sleep
    """Injectable so tests do not actually wait out the backoff."""

    _last_request: float = 0.0
    _owns_client: bool = False

    def __post_init__(self) -> None:
        if self.client is None:
            self.client = httpx.Client(
                headers={"User-Agent": self.config.user_agent, "Accept": "application/json"},
                timeout=httpx.Timeout(30.0, read=120.0),
                follow_redirects=True,
            )
            self._owns_client = True

    # -- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        if self._owns_client and self.client is not None:
            self.client.close()

    def __enter__(self) -> Launchpad:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- transport ----------------------------------------------------------

    def _pace(self) -> None:
        """Wait out the minimum interval since the last request."""
        gap = self.config.min_interval_s - (time.monotonic() - self._last_request)
        if self._last_request and gap > 0:
            self.sleep(gap)

    def _request(self, url: str, *, headers: dict[str, str] | None = None) -> httpx.Response:
        """GET with pacing and backoff. Raises rather than returning a failure."""
        assert self.client is not None  # set in __post_init__
        attempts = self.config.max_retries + 1
        for attempt in range(1, attempts + 1):
            self._pace()
            self._last_request = time.monotonic()
            try:
                response = self.client.get(url, headers=headers)
            except httpx.HTTPError as exc:
                if attempt == attempts:
                    raise LaunchpadError(f"{url}: {exc}") from exc
                self.sleep(self.config.backoff_base_s * 2**attempt)
                continue

            if response.status_code in _RETRY_STATUS and attempt < attempts:
                # Honour Retry-After when given; Launchpad usually is not, and
                # its 429s need tens of seconds rather than the milliseconds a
                # naive backoff would start with.
                wait = _retry_after(response) or self.config.backoff_base_s * 2**attempt
                self.sleep(wait)
                continue

            if response.status_code == 429:
                raise RateLimited(f"{url}: still rate-limited after {attempts} attempts")
            if response.status_code == 404:
                raise LaunchpadError(f"{url}: not found")
            if response.status_code >= 400:
                raise LaunchpadError(f"{url}: HTTP {response.status_code}")
            return response

        raise LaunchpadError(f"{url}: gave up")

    def _json(self, url: str) -> dict[str, Any]:
        response = self._request(url)
        try:
            payload = response.json()
        except ValueError as exc:
            raise LaunchpadError(f"{url}: response was not JSON") from exc
        if not isinstance(payload, dict):
            raise LaunchpadError(f"{url}: expected a JSON object")
        return payload

    # -- bugs ---------------------------------------------------------------

    def bug(self, bug_id: int) -> BugRecord:
        """Fetch a bug and its attachment listing. Two requests."""
        base = self.config.api_base.rstrip("/")
        payload = self._json(f"{base}/bugs/{bug_id}")
        listing = self._json(f"{base}/bugs/{bug_id}/attachments")

        refs: list[AttachmentRef] = []
        for entry in listing.get("entries", []):
            if not isinstance(entry, dict):
                continue
            title = str(entry.get("title") or "")
            refs.append(
                AttachmentRef(
                    title=title,
                    data_url=str(entry.get("data_link") or ""),
                    source=attachment_source(title),
                    irrelevant=is_irrelevant_attachment(title),
                )
            )

        return BugRecord(
            bug_id=bug_id,
            title=str(payload.get("title") or ""),
            description=str(payload.get("description") or ""),
            tags=tuple(str(t) for t in payload.get("tags") or ()),
            duplicate_of=_bug_id_from_link(payload.get("duplicate_of_link")),
            duplicate_count=int(payload.get("number_of_duplicates") or 0),
            created=_parse_created(payload.get("date_created")),
            attachments=tuple(refs),
        )

    # -- attachments --------------------------------------------------------

    def _cached(self, bug_id: int, title: str) -> tuple[str | None, bytes | None]:
        if self.store is None:
            return (None, None)
        etag, path = self.store.attachment_etag(bug_id, title)
        if path is not None and path.is_file():
            try:
                return (etag, path.read_bytes())
            except OSError:
                return (etag, None)
        return (etag, None)

    def _remember(self, bug_id: int, title: str, etag: str | None, data: bytes) -> None:
        if self.store is None or self.cache_dir is None:
            return
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in title)[:80]
        target = self.cache_dir / f"{bug_id}-{safe}"
        try:
            target.write_bytes(data)
        except OSError:
            return
        self.store.attachment_put(bug_id, title, etag, target, len(data))

    def _download(self, ref: AttachmentRef, bug_id: int) -> bytes | None:
        """Fetch one attachment, honouring the cache and the size cap.

        Returns ``None`` when the body is unavailable, which is not an error:
        attachments are sometimes removed, and one missing log should not stop
        the rest of a bug being diagnosed.
        """
        etag, cached = self._cached(bug_id, ref.title)
        headers = {"If-None-Match": etag} if etag and cached is not None else None
        try:
            response = self._request(ref.data_url, headers=headers)
        except LaunchpadError:
            return cached

        if response.status_code == 304 and cached is not None:
            return cached

        data = response.content
        cap = self.config.max_attachment_bytes
        if len(data) > cap:
            # Keep the tail: a truncated upgrade log is interesting at the end,
            # which is where it stopped.
            data = data[-cap:]
        self._remember(bug_id, ref.title, response.headers.get("ETag"), data)
        return data

    def logs(self, bug_id: int) -> tuple[dict[LogSource, str], BugRecord]:
        """Fetch a bug's parseable logs, keyed by source.

        Unrecognised names are downloaded and identified by content rather than
        skipped, because roughly a third of the useful attachments on real bugs
        are hand-uploaded under names no table predicts. Names already known to
        be irrelevant cost no request at all.

        A source already filled by a confidently-named attachment is not
        overwritten by a sniffed one: apport's key is better evidence than the
        first few lines of a file a reporter named ``log.txt``.
        """
        record = self.bug(bug_id)
        out: dict[LogSource, str] = {}

        for ref in sorted(record.log_attachments, key=lambda r: r.source is None):
            if ref.source is not None and ref.source in out:
                continue
            data = self._download(ref, bug_id)
            if not data:
                continue

            source = ref.source
            if source is None:
                source = sniff_source(
                    read_log(data[:_SNIFF_LIMIT], redacted=False),
                    limit=_SNIFF_LIMIT,
                )
                if source is None or source in out:
                    continue

            out[source] = read_log(data, max_bytes=self.config.max_attachment_bytes)

        return (out, record)


def _retry_after(response: httpx.Response) -> float | None:
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        return None
