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
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlencode

import httpx

from uru_doctor.models import LogSource
from uru_doctor.parsers.apportmeta import (
    attachment_source,
    is_irrelevant_attachment,
    sniff_source,
)
from uru_doctor.parsers.sanitize import read_log
from uru_doctor.store import Store
from uru_doctor_cli.config import LaunchpadConfig

__all__ = [
    "ALL_STATUSES",
    "DEFAULT_TARGET",
    "AttachmentRef",
    "BugRecord",
    "BugRef",
    "Launchpad",
    "LaunchpadError",
    "RateLimited",
]

_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)
"""Sort key for a task with no parseable creation date.

Sorts it oldest, which is the safe direction: a bug whose date cannot be read
is handled before the watermark advances past it rather than after.
"""

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
class BugRef:
    """One bug task from a search, before any of its logs are fetched.

    Everything here arrives in the search response, so a sweep knows what it is
    about to spend requests on -- and knows each bug's status without asking
    for it separately.
    """

    bug_id: int
    status: str = ""
    """Launchpad's status, e.g. ``New``, ``Invalid``, ``Won't Fix``."""

    created: datetime | None = None
    title: str = ""
    """The task title, which embeds the bug's. Display only, never an input."""

    is_duplicate: bool | None = None
    """Whether Launchpad considers this bug a duplicate of another.

    ``None`` means not determined. The task entry carries no duplicate field
    at all -- verified against the live API, see :data:`OMIT_DUPLICATES_NOTE`
    -- so this is filled by :meth:`Launchpad.search_triage`, which infers it
    from the difference between a search that omits duplicates and one that
    does not. *Which* bug this duplicates is a separate and much more
    expensive question; only :meth:`Launchpad.bug` can answer it.
    """


#: Why ``omit_duplicates=false`` is passed explicitly.
#:
#: Launchpad's ``searchTasks`` omits bugs marked as duplicates by default, and
#: the default is wrong here for the same reason the status default is.
#: Measured against the live API on 2026-10-05 over ``created_since=2026-09-25``
#: for ``ubuntu-release-upgrader``: the default returned 36 tasks and
#: ``omit_duplicates=false`` returned 49, hiding 13 bugs.
#:
#: Four of those thirteen were already in a local corpus, stored as ``New``
#: with no duplicate recorded, because they had been swept *before* anyone
#: marked them. A bug therefore does not merely start out invisible -- it
#: *becomes* invisible the moment it is triaged, which is precisely when a
#: triage tool most needs to notice. Accepting the default means the corpus can
#: never see Launchpad's own duplicate verdicts, and so can never be checked
#: against them.
#:
#: Two of the thirteen, LP#2169028 and LP#2169157, are duplicates of LP#2168855
#: -- which is exactly the master this tool had already chosen for them from
#: the logs alone, at ``root-graph`` tier.
OMIT_DUPLICATES_NOTE: Final = (
    "searchTasks hides duplicates by default; measured 36 vs 49 tasks on 2026-10-05"
)


#: Statuses a sweep asks for explicitly.
#:
#: Launchpad's ``searchTasks`` defaults to **open** bugs only. Measured against
#: the live API over one week of ``ubuntu-release-upgrader`` reports, the
#: default returned 23 tasks and hid two ``Won't Fix`` ones.
#:
#: That default is the wrong one here. A bug's own resolution is the
#: second-strongest ground truth available for checking this tool -- LP#2150245
#: closing Invalid with thirteen duplicates is what confirms its verdict -- so
#: a sweep that accepted the default would systematically exclude its own best
#: evidence, and would do so silently.
ALL_STATUSES: Final[tuple[str, ...]] = (
    "New",
    "Incomplete",
    "Opinion",
    "Invalid",
    "Won't Fix",
    "Expired",
    "Confirmed",
    "Triaged",
    "In Progress",
    "Fix Committed",
    "Fix Released",
)

#: The source package whose bugs this tool is about.
DEFAULT_TARGET: Final = "/ubuntu/+source/ubuntu-release-upgrader"


@dataclass(frozen=True, slots=True)
class TriageSearch:
    """The result of a triage listing, and whether it saw the whole queue.

    ``complete`` exists because the two facts a refresh draws from a listing
    are asymmetric. A bug that *is* returned carries its status, and that is
    true either way. A bug that is *not* returned has only been shown not to
    have changed -- and only if the listing actually reached the end. For a
    package with more bugs than ``max_pages`` will fetch, it does not, and
    treating absence as confirmation would silently stamp thousands of unread
    bugs as current.
    """

    refs: tuple[BugRef, ...]
    complete: bool

    def __iter__(self) -> Iterator[BugRef]:
        return iter(self.refs)

    def __len__(self) -> int:
        return len(self.refs)


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

    status: str = ""
    """Launchpad's status, when the caller already knows it.

    Not fetched by :meth:`Launchpad.bug`: status lives on the bug's *tasks*,
    which is a third request per bug at three seconds each. ``searchTasks``
    returns it for free, so ``sweep`` supplies it here and ``fetch`` leaves it
    empty. Safe to differ because this is ground truth for *checking* a
    diagnosis and is excluded from every signature.
    """

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


def _short_url(url: str) -> str:
    """The tail of an API URL, for a one-line progress message.

    A full Launchpad API URL is 90 characters of which the last two segments
    are the only informative part, and a progress line that wraps is worse
    than no progress line.
    """
    without_query = url.split("?", 1)[0].rstrip("/")
    parts = without_query.rsplit("/", 2)
    return "/".join(parts[-2:]) if len(parts) >= 2 else without_query


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

    progress: Callable[[str], None] | None = None
    """Called with a short description of whatever is about to take time.

    Exists because this client is mostly *waiting*: at a three-second minimum
    interval, a bug costing six requests spends eighteen seconds asleep, and a
    caller that reports nothing until a bug completes looks hung. The messages
    are deliberately phrased for a human watching a terminal rather than for a
    log.

    ``None`` means silent, which is what a library caller and every test want.
    """

    _last_request: float = 0.0
    _owns_client: bool = False

    def _say(self, message: str) -> None:
        if self.progress is not None:
            self.progress(message)

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
        """Wait out the minimum interval since the last request.

        Announced, because this is where the time goes. Spacing requests is
        cheaper than recovering from a 429, but it means most of a sweep's
        wall-clock is spent here and a caller that says nothing during it
        appears to have stopped.
        """
        gap = self.config.min_interval_s - (time.monotonic() - self._last_request)
        if self._last_request and gap > 0:
            self._say(f"pacing {gap:.1f}s")
            self.sleep(gap)

    def _request(self, url: str, *, headers: dict[str, str] | None = None) -> httpx.Response:
        """GET with pacing and backoff. Raises rather than returning a failure."""
        assert self.client is not None  # set in __post_init__
        attempts = self.config.max_retries + 1
        for attempt in range(1, attempts + 1):
            self._pace()
            self._say(f"GET {_short_url(url)}")
            self._last_request = time.monotonic()
            try:
                response = self.client.get(url, headers=headers)
            except httpx.HTTPError as exc:
                if attempt == attempts:
                    raise LaunchpadError(f"{url}: {exc}") from exc
                wait = self.config.backoff_base_s * 2**attempt
                self._say(f"retrying in {wait:.0f}s after {type(exc).__name__}")
                self.sleep(wait)
                continue

            if response.status_code in _RETRY_STATUS and attempt < attempts:
                # Honour Retry-After when given; Launchpad usually is not, and
                # its 429s need tens of seconds rather than the milliseconds a
                # naive backoff would start with.
                wait = _retry_after(response) or self.config.backoff_base_s * 2**attempt
                # Said out loud because a 429 wait is tens of seconds, and a
                # silent one is indistinguishable from a hang.
                self._say(
                    f"HTTP {response.status_code}, waiting {wait:.0f}s "
                    f"(attempt {attempt} of {attempts})"
                )
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

    def _collect_tasks(
        self,
        *,
        created_since: datetime | None,
        modified_since: datetime | None,
        statuses: Sequence[str],
        target: str,
        page_size: int,
        max_pages: int,
        omit_duplicates: bool,
    ) -> tuple[list[BugRef], bool]:
        """Walk the listing. Returns the tasks and whether it reached the end.

        The completeness flag is load-bearing rather than informational.
        ``ubuntu-release-upgrader`` has far more bugs than ``max_pages`` will
        fetch, so a caller that treats "absent from the listing" as "not
        modified" would silently mark thousands of unread bugs as confirmed
        current. Absent from a *complete* listing means something; absent from
        a truncated one means nothing at all.
        """
        base = self.config.api_base.rstrip("/")
        params: list[tuple[str, str]] = [
            ("ws.op", "searchTasks"),
            ("ws.size", str(page_size)),
            ("omit_duplicates", "true" if omit_duplicates else "false"),
            *(("status", status) for status in statuses),
        ]
        if created_since is not None:
            # Date only: the API accepts a full timestamp but compares
            # inclusively, so re-running a sweep within the same day would
            # otherwise re-fetch the boundary bug on every pass.
            params.append(("created_since", created_since.date().isoformat()))
        if modified_since is not None:
            params.append(("modified_since", modified_since.date().isoformat()))
        url = f"{base}{target}?{urlencode(params)}"

        collected: list[BugRef] = []
        complete = False
        for page in range(max_pages):
            self._say(f"searching, page {page + 1}")
            payload = self._json(url)
            entries = payload.get("entries")
            if not isinstance(entries, list):
                raise LaunchpadError(f"searchTasks returned no entries list: {url}")
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                bug_id = _bug_id_from_link(entry.get("bug_link"))
                if bug_id is None:
                    continue
                collected.append(
                    BugRef(
                        bug_id=bug_id,
                        status=str(entry.get("status") or ""),
                        created=_parse_created(entry.get("date_created")),
                        title=str(entry.get("title") or ""),
                    )
                )
            next_link = payload.get("next_collection_link")
            if not isinstance(next_link, str) or not next_link:
                complete = True
                break
            url = next_link

        # ``total_size`` comes back null on this collection, so there is
        # nothing to cross-check the count against; the entries are the answer.
        collected.sort(key=lambda ref: (ref.created or _EPOCH, ref.bug_id))
        return (collected, complete)

    def search_tasks(
        self,
        *,
        created_since: datetime | None = None,
        modified_since: datetime | None = None,
        statuses: Sequence[str] = ALL_STATUSES,
        target: str = DEFAULT_TARGET,
        page_size: int = 50,
        max_pages: int = 40,
        omit_duplicates: bool = False,
    ) -> Iterator[BugRef]:
        """Yield bug tasks for the target package, oldest first.

        One request per page.

        ``statuses`` defaults to :data:`ALL_STATUSES` rather than to
        Launchpad's own default, which silently omits closed bugs -- see that
        constant for the measurement and why it matters.

        ``omit_duplicates`` defaults to ``False`` for the same reason, and the
        default here is likewise the opposite of the API's; see
        :data:`OMIT_DUPLICATES_NOTE`.

        ``modified_since`` is what makes refreshing triage state cheap. A
        status change or a duplicate marking modifies the bug, so asking only
        for tasks modified since the last check is one request in the steady
        state regardless of how large the corpus is. Measured against the live
        API: 14 tasks modified in the preceding day against a full page of 100
        over five weeks.

        Ordered oldest-first, because a watermark can only advance safely over
        bugs that have actually been handled. The API's own order is
        newest-first, so processing in arrival order and then storing the
        newest timestamp seen would skip everything older on the next run.
        Sorting means every page is fetched before the first item is yielded;
        a caller that needs to know whether the listing was truncated wants
        :meth:`search_triage` or :meth:`_collect_tasks`.

        ``max_pages`` is a stop, not a target. At three seconds a request a
        runaway pagination loop is a slow one, and a sweep that silently walks
        four thousand bugs is not what anyone asked for.
        """
        collected, _ = self._collect_tasks(
            created_since=created_since,
            modified_since=modified_since,
            statuses=statuses,
            target=target,
            page_size=page_size,
            max_pages=max_pages,
            omit_duplicates=omit_duplicates,
        )
        yield from collected

    def search_triage(
        self,
        *,
        modified_since: datetime | None = None,
        target: str = DEFAULT_TARGET,
        page_size: int = 50,
        max_pages: int = 40,
    ) -> TriageSearch:
        """Current status for every matching bug, and whether it is a duplicate.

        Two searches rather than one, because the bug *task* entry a search
        returns has no duplicate field -- verified against the live API, whose
        task entries carry ``status``, ``date_created``, ``importance`` and
        twenty-odd other keys, none of them about duplication. So duplication
        is inferred structurally: the bugs present when duplicates are included
        and absent when they are excluded are exactly the duplicates.

        That costs twice the *listing* requests, which is the cheap half of
        talking to this API -- two requests in the steady state against one
        request per bug for the alternative. It yields only the boolean;
        :meth:`bug` and :meth:`duplicate_of` are the only ways to learn which
        bug is the master.

        Returns a :class:`TriageSearch` rather than a bare list because
        ``complete`` changes what a caller may conclude from a bug's *absence*,
        and that is the difference between confirming a verdict and inventing
        one.
        """
        search = partial(
            self._collect_tasks,
            created_since=None,
            modified_since=modified_since,
            statuses=ALL_STATUSES,
            target=target,
            page_size=page_size,
            max_pages=max_pages,
        )
        self._say("searching, including duplicates")
        everything, complete = search(omit_duplicates=False)
        self._say("searching, excluding duplicates")
        plain, plain_complete = search(omit_duplicates=True)
        not_duplicates = {ref.bug_id for ref in plain}
        return TriageSearch(
            refs=tuple(
                replace(ref, is_duplicate=ref.bug_id not in not_duplicates)
                for ref in everything
            ),
            complete=complete and plain_complete,
        )

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

    def task_status(self, bug_id: int, *, target: str = DEFAULT_TARGET) -> str:
        """This package's task status for one bug. One request.

        The escape hatch from the listing's page limit. A search covers fifty
        bugs per request but only reaches ``max_pages`` of them, and this
        package has far more bugs than that -- so a bug filed years ago cannot
        be reached by listing at all, at any price. Addressing its task
        directly can, at one request each.

        Returns an empty string when the bug has no task against this package,
        which is not an error: a bug can be retargeted after it was collected.
        """
        base = self.config.api_base.rstrip("/")
        try:
            payload = self._json(f"{base}{target}/+bug/{bug_id}")
        except LaunchpadError:
            return ""
        return str(payload.get("status") or "")

    def duplicate_of(self, bug_id: int) -> tuple[int | None, int]:
        """``(master bug id or None, duplicate count)``. One request.

        Separate from :meth:`bug` because that fetches the attachment listing
        too, and a refresh wants none of it: at three seconds a request,
        halving the cost of the per-bug pass halves the cost of the only part
        of refreshing that does not scale.
        """
        base = self.config.api_base.rstrip("/")
        payload = self._json(f"{base}/bugs/{bug_id}")
        return (
            _bug_id_from_link(payload.get("duplicate_of_link")),
            int(payload.get("number_of_duplicates") or 0),
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

        wanted = sorted(record.log_attachments, key=lambda r: r.source is None)
        for index, ref in enumerate(wanted, start=1):
            self._say(f"LP#{bug_id} attachment {index}/{len(wanted)}: {ref.title}")
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
