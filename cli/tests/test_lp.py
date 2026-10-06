# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for :mod:`uru_doctor_cli.lp`.

Everything here runs against :class:`httpx.MockTransport`. The test suite must
not touch the network: Launchpad is a shared service, it rate-limits, and a
test that depends on a live bug fails for reasons that have nothing to do with
the code.

The responses are shaped like the real API's -- ``entries`` lists,
``data_link`` URLs, ``duplicate_of_link`` -- because that shape is the thing
being parsed.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from conftest import fixture_text
from uru_doctor_cli.config import LaunchpadConfig
from uru_doctor_cli.lp import (
    AttachmentRef,
    BugRecord,
    Launchpad,
    LaunchpadError,
    RateLimited,
)

from uru_doctor.models import LogSource
from uru_doctor.store import Store

API = "https://api.launchpad.net/devel"


def _bug_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": 2150319,
        "title": "upgrade from noble to resolute failed",
        "description": "ProblemType: Bug\nDistroRelease: Ubuntu 24.04\n",
        "tags": ["dist-upgrade", "resolute"],
        "number_of_duplicates": 2,
        "duplicate_of_link": None,
        "date_created": "2026-06-23T11:09:00+00:00",
    }
    payload.update(overrides)
    return payload


def _attachments(*titles: str) -> dict[str, object]:
    return {
        "entries": [
            {"title": title, "data_link": f"{API}/bugs/2150319/+attachment/{i}/data"}
            for i, title in enumerate(titles)
        ]
    }


class Recorder:
    """A mock transport that records the URLs it was asked for."""

    def __init__(self, routes: dict[str, httpx.Response]) -> None:
        self.routes = routes
        self.urls: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.urls.append(url)
        # Longest prefix first. ``/bugs/2150319`` is a prefix of
        # ``/bugs/2150319/+attachment/0/data``, so insertion order decided
        # which route answered and every attachment came back as the bug JSON.
        for prefix in sorted(self.routes, key=len, reverse=True):
            response = self.routes[prefix]
            if url.startswith(prefix):
                # httpx reuses the response object; copy so repeated requests
                # each get a readable stream.
                return httpx.Response(
                    response.status_code,
                    content=response.content,
                    headers=response.headers,
                )
        return httpx.Response(404, text="not found")


def _client(recorder: Recorder) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(recorder), follow_redirects=True)


def _launchpad(recorder: Recorder, **kwargs: object) -> Launchpad:
    """A client with pacing and backoff disabled, so tests do not wait."""
    config = LaunchpadConfig(min_interval_s=0.0, backoff_base_s=0.001, max_retries=3)
    return Launchpad(
        config=config,
        client=_client(recorder),
        sleep=lambda _seconds: None,
        **kwargs,  # type: ignore[arg-type]
    )


def _routes(*titles: str, **bodies: str) -> dict[str, httpx.Response]:
    routes: dict[str, httpx.Response] = {
        f"{API}/bugs/2150319/attachments": httpx.Response(200, json=_attachments(*titles)),
        f"{API}/bugs/2150319": httpx.Response(200, json=_bug_payload()),
    }
    for index, title in enumerate(titles):
        body = bodies.get(f"a{index}", f"contents of {title}")
        routes[f"{API}/bugs/2150319/+attachment/{index}/data"] = httpx.Response(
            200, content=body.encode()
        )
    return routes


class TestBug:
    def test_parses_the_record(self) -> None:
        recorder = Recorder(_routes("VarLogDistupgradeAptlog.txt"))
        with _launchpad(recorder) as client:
            record = client.bug(2150319)
        assert record.bug_id == 2150319
        assert record.tags == ("dist-upgrade", "resolute")
        assert record.duplicate_count == 2
        assert record.created is not None

    def test_duplicate_of_link_is_reduced_to_a_number(self) -> None:
        routes = _routes("VarLogDistupgradeAptlog.txt")
        routes[f"{API}/bugs/2150319"] = httpx.Response(
            200,
            json=_bug_payload(duplicate_of_link=f"{API}/bugs/2150245"),
        )
        recorder = Recorder(routes)
        with _launchpad(recorder) as client:
            assert client.bug(2150319).duplicate_of == 2150245

    def test_missing_bug_raises(self) -> None:
        with _launchpad(Recorder({})) as client, pytest.raises(LaunchpadError, match="not found"):
            client.bug(2150319)

    def test_non_json_response_raises(self) -> None:
        recorder = Recorder({f"{API}/bugs/2150319": httpx.Response(200, text="<html>")})
        with _launchpad(recorder) as client, pytest.raises(LaunchpadError, match="not JSON"):
            client.bug(2150319)

    def test_costs_two_requests(self) -> None:
        """One for the bug, one for the listing. Worth knowing, at 3s each."""
        recorder = Recorder(_routes("VarLogDistupgradeAptlog.txt"))
        with _launchpad(recorder) as client:
            client.bug(2150319)
        assert len(recorder.urls) == 2


class TestAttachmentSelection:
    """ "Unknown" and "irrelevant" are different answers."""

    def test_irrelevant_attachments_cost_no_request(self) -> None:
        """Measured: skipping these is most of the time saved on a corpus."""
        recorder = Recorder(
            _routes(
                "VarLogDistupgradeAptlog.txt",
                "Dependencies.txt",
                "JournalErrors.txt",
                "CurrentDmesg.txt",
                "screenshot.png",
            )
        )
        with _launchpad(recorder) as client:
            client.logs(2150319)
        fetched = [u for u in recorder.urls if "+attachment" in u]
        assert len(fetched) == 1

    def test_unknown_names_are_fetched_and_sniffed(self) -> None:
        """A third of useful attachments are hand-uploaded under odd names."""
        apt = fixture_text("apt/lp2150319-apt.log")[:200_000]
        recorder = Recorder(_routes("my-upgrade-log.txt", a0=apt))
        with _launchpad(recorder) as client:
            logs, _ = client.logs(2150319)
        assert LogSource.APT in logs

    def test_unidentifiable_content_is_discarded(self) -> None:
        recorder = Recorder(_routes("notes.txt", a0="just some prose about my laptop"))
        with _launchpad(recorder) as client:
            logs, _ = client.logs(2150319)
        assert logs == {}

    def test_named_attachment_beats_a_sniffed_one(self) -> None:
        """apport's key is better evidence than a reporter's filename.

        Both files here look like an apt log; the one apport named must win,
        and the ambiguous one must not overwrite it.
        """
        apt = fixture_text("apt/lp2150319-apt.log")[:200_000]
        routes = _routes("random-name.txt", "VarLogDistupgradeAptlog.txt", a0=apt, a1=apt)
        recorder = Recorder(routes)
        with _launchpad(recorder) as client:
            logs, _ = client.logs(2150319)
        assert list(logs) == [LogSource.APT]

    def test_logs_are_keyed_by_source(self) -> None:
        routes = _routes(
            "VarLogDistupgradeAptlog.txt",
            "VarLogDistupgradeMainlog.txt",
            a0=fixture_text("apt/lp2150319-apt.log")[:100_000],
            a1=fixture_text("logs/lp2150319-main.log"),
        )
        with _launchpad(Recorder(routes)) as client:
            logs, _ = client.logs(2150319)
        assert set(logs) == {LogSource.APT, LogSource.MAIN}

    def test_empty_attachment_is_skipped_not_stored(self) -> None:
        recorder = Recorder(_routes("VarLogDistupgradeAptlog.txt", a0=""))
        with _launchpad(recorder) as client:
            logs, _ = client.logs(2150319)
        assert logs == {}

    def test_missing_body_does_not_abandon_the_bug(self) -> None:
        """An attachment can be removed after the listing was written."""
        routes = _routes("VarLogDistupgradeAptlog.txt", "VarLogDistupgradeMainlog.txt")
        del routes[f"{API}/bugs/2150319/+attachment/0/data"]
        routes[f"{API}/bugs/2150319/+attachment/1/data"] = httpx.Response(
            200, content=fixture_text("logs/lp2150319-main.log").encode()
        )
        with _launchpad(Recorder(routes)) as client:
            logs, _ = client.logs(2150319)
        assert LogSource.MAIN in logs


class TestRateLimiting:
    """429 is the normal failure here, not an exceptional one."""

    def test_retries_then_succeeds(self) -> None:
        state = {"calls": 0}
        body = fixture_text("logs/lp2150319-main.log").encode()

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if url.endswith("/attachments"):
                return httpx.Response(200, json=_attachments("VarLogDistupgradeMainlog.txt"))
            if "+attachment" in url:
                return httpx.Response(200, content=body)
            state["calls"] += 1
            if state["calls"] < 3:
                return httpx.Response(429, text="slow down")
            return httpx.Response(200, json=_bug_payload())

        client = Launchpad(
            config=LaunchpadConfig(min_interval_s=0.0, backoff_base_s=0.001, max_retries=5),
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            sleep=lambda _s: None,
        )
        with client:
            logs, _ = client.logs(2150319)
        assert state["calls"] == 3
        assert LogSource.MAIN in logs

    def test_persistent_429_raises_rate_limited(self) -> None:
        """A distinct exception, so a corpus fetch can stop instead of looping."""
        recorder = Recorder({f"{API}/bugs/2150319": httpx.Response(429, text="no")})
        with _launchpad(recorder) as client, pytest.raises(RateLimited):
            client.bug(2150319)

    def test_retry_after_is_honoured(self) -> None:
        waits: list[float] = []
        state = {"calls": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            state["calls"] += 1
            if state["calls"] == 1:
                return httpx.Response(429, headers={"Retry-After": "42"})
            return httpx.Response(200, json=_bug_payload())

        client = Launchpad(
            config=LaunchpadConfig(min_interval_s=0.0, backoff_base_s=0.001),
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            sleep=waits.append,
        )
        with client:
            client._json(f"{API}/bugs/2150319")
        assert 42.0 in waits

    def test_server_errors_are_retried(self) -> None:
        state = {"calls": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            state["calls"] += 1
            if state["calls"] < 2:
                return httpx.Response(503)
            return httpx.Response(200, json=_bug_payload())

        client = Launchpad(
            config=LaunchpadConfig(min_interval_s=0.0, backoff_base_s=0.001),
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            sleep=lambda _s: None,
        )
        with client:
            assert client._json(f"{API}/bugs/2150319")["id"] == 2150319

    def test_requests_are_paced(self) -> None:
        """Spacing requests is cheaper than recovering from a 429."""
        waits: list[float] = []
        recorder = Recorder(_routes("VarLogDistupgradeAptlog.txt"))
        client = Launchpad(
            config=LaunchpadConfig(min_interval_s=3.0, backoff_base_s=0.001),
            client=_client(recorder),
            sleep=waits.append,
        )
        with client:
            client.bug(2150319)
        # The first request is not delayed; the second is.
        assert len(waits) == 1
        assert 0 < waits[0] <= 3.0


class TestSizeCap:
    def test_oversized_attachment_keeps_the_tail(self) -> None:
        """A truncated upgrade log is interesting at the end."""
        body = "HEAD\n" + ("x" * 5000) + "\nTAIL-MARKER\n"
        recorder = Recorder(_routes("VarLogDistupgradeMainlog.txt", a0=body))
        client = Launchpad(
            config=LaunchpadConfig(
                min_interval_s=0.0, backoff_base_s=0.001, max_attachment_bytes=1024
            ),
            client=_client(recorder),
            sleep=lambda _s: None,
        )
        with client:
            data = client._download(
                AttachmentRef(
                    title="VarLogDistupgradeMainlog.txt",
                    data_url=f"{API}/bugs/2150319/+attachment/0/data",
                    source=LogSource.MAIN,
                ),
                2150319,
            )
        assert data is not None
        assert data.endswith(b"TAIL-MARKER\n")
        assert len(data) <= 1024


class TestCaching:
    def test_etag_is_sent_and_304_uses_the_cache(self, tmp_path: Path) -> None:
        body = fixture_text("logs/lp2150319-main.log").encode()
        seen: list[str | None] = []

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if url.endswith("/attachments"):
                return httpx.Response(200, json=_attachments("VarLogDistupgradeMainlog.txt"))
            if "+attachment" in url:
                seen.append(request.headers.get("If-None-Match"))
                if request.headers.get("If-None-Match") == '"abc"':
                    return httpx.Response(304)
                return httpx.Response(200, content=body, headers={"ETag": '"abc"'})
            return httpx.Response(200, json=_bug_payload())

        config = LaunchpadConfig(min_interval_s=0.0, backoff_base_s=0.001)
        with Store.open(tmp_path / "state") as store:
            for _ in range(2):
                client = Launchpad(
                    config=config,
                    store=store,
                    cache_dir=tmp_path / "attachments",
                    client=httpx.Client(transport=httpx.MockTransport(handler)),
                    sleep=lambda _s: None,
                )
                with client:
                    logs, _ = client.logs(2150319)
                assert LogSource.MAIN in logs
            store.commit()

        assert seen == [None, '"abc"'], "second fetch must offer the ETag"


class TestReadOnly:
    def test_no_write_verbs_anywhere(self) -> None:
        """The module must not be able to modify Launchpad.

        Asserted on the compiled code rather than the source text, because the
        source mentions credentials in prose to explain their absence and a
        substring search over the whole file matched the explanation.
        """
        import uru_doctor_cli.lp as module

        names = set()
        for value in vars(module).values():
            code = getattr(value, "__code__", None)
            if code is not None:
                names.update(code.co_names)
                for const in code.co_consts:
                    inner = getattr(const, "co_names", ())
                    names.update(inner)
        for verb in ("post", "patch", "put", "delete", "auth"):
            assert verb not in names, f"write capability present: {verb}"

    def test_record_carries_prose_but_marks_it(self) -> None:
        """Prose is fetched for display, and must not be a diagnostic input."""
        from uru_doctor.dedup import EXCLUDED_FROM_SIGNATURES

        record = BugRecord(bug_id=1, title="my laptop broke", tags=("foo",))
        assert record.title
        assert "current_title" in EXCLUDED_FROM_SIGNATURES
        assert "tags" in EXCLUDED_FROM_SIGNATURES


class TestAttachmentRef:
    @pytest.mark.parametrize(
        ("title", "worth"),
        [
            ("VarLogDistupgradeAptlog.txt", True),
            ("my-weird-log.txt", True),
            ("Dependencies.txt", False),
            ("screenshot.png", False),
            ("JournalErrors.txt", False),
        ],
    )
    def test_worth_fetching(self, title: str, worth: bool) -> None:
        from uru_doctor.parsers.apportmeta import attachment_source, is_irrelevant_attachment

        ref = AttachmentRef(
            title=title,
            data_url="https://example.invalid/data",
            source=attachment_source(title),
            irrelevant=is_irrelevant_attachment(title),
        )
        assert ref.worth_fetching is worth

    def test_no_data_url_is_not_worth_fetching(self) -> None:
        assert not AttachmentRef(title="apt.log", data_url="").worth_fetching


def test_config_has_no_second_attachment_table() -> None:
    """One source of truth for attachment names.

    ``LaunchpadConfig`` carried a ``wanted_attachments`` list whose last three
    entries -- ``Dependencies``, ``ProcCpuinfoMinimal`` and
    ``VarLogDistupgradeLspcitxt`` -- are classified irrelevant by the code that
    actually decides. It was unused, so the disagreement was invisible.
    """
    assert not hasattr(LaunchpadConfig(), "wanted_attachments")
    assert json.dumps(LaunchpadConfig().model_dump(), default=str)


def _task(
    bug_id: int,
    status: str = "New",
    created: str = "2026-09-29T10:00:00+00:00",
    assignee: str | None = None,
) -> dict:
    """One ``searchTasks`` entry, shaped like the real API's.

    The default omits ``assignee_link``, as only a hand-built entry would;
    ``assignee=""`` sends the explicit null the API sends for an *unassigned*
    task -- the distinction ``BugRef.assignee`` preserves.
    """
    entry = {
        "bug_link": f"{API}/bugs/{bug_id}",
        "status": status,
        "date_created": created,
        "title": f'Bug #{bug_id} in ubuntu-release-upgrader (Ubuntu): "upgrade failed"',
    }
    if assignee is not None:
        entry["assignee_link"] = f"{API}/~{assignee}" if assignee else None
    return entry


class TestSearchTasks:
    """Finding bugs to fetch, rather than being handed a list.

    Without this the queue is curated by hand, which means the tool only ever
    sees bugs somebody already decided were interesting -- the selection bias
    the rest of the design exists to remove.
    """

    def _search(self, payload: dict, **kwargs: object) -> tuple[list, Recorder]:
        recorder = Recorder(
            {f"{API}/ubuntu/+source/ubuntu-release-upgrader": httpx.Response(200, json=payload)}
        )
        with _launchpad(recorder) as client:
            return (list(client.search_tasks(**kwargs)), recorder)  # type: ignore[arg-type]

    def test_parses_ids_statuses_and_dates(self) -> None:
        refs, _ = self._search({"entries": [_task(2168863, "New"), _task(2168919, "Won't Fix")]})
        assert [r.bug_id for r in refs] == [2168863, 2168919]
        assert {r.status for r in refs} == {"New", "Won't Fix"}
        assert all(r.created is not None for r in refs)

    def test_an_assignee_link_becomes_a_username(self) -> None:
        refs, _ = self._search({"entries": [_task(1, assignee="bamf0")]})
        assert refs[0].assignee == "bamf0"

    def test_a_null_assignee_is_unassigned_not_unknown(self) -> None:
        """The API sends the key with a null value; that is a fact ('')."""
        refs, _ = self._search({"entries": [_task(1, assignee="")]})
        assert refs[0].assignee == ""

    def test_an_absent_assignee_key_is_unknown_not_unassigned(self) -> None:
        """Only a hand-built entry omits the key -- verified against the live
        API, whose task entries always carry ``assignee_link``."""
        refs, _ = self._search({"entries": [_task(1)]})
        assert refs[0].assignee is None

    def test_closed_statuses_are_requested_explicitly(self) -> None:
        """Launchpad's default omits closed bugs, and that is the wrong default.

        Measured against the live API over one week of release-upgrader
        reports: the default returned 23 tasks and hid two ``Won't Fix`` ones.
        A bug's own resolution is the second-strongest ground truth there is,
        so accepting the default would make a sweep exclude its own best
        evidence -- silently.
        """
        _, recorder = self._search({"entries": []})
        url = recorder.urls[0]
        for status in ("Invalid", "Won%27t+Fix", "Fix+Released", "Expired"):
            assert status in url, f"{status} not requested: {url}"

    def test_results_are_oldest_first(self) -> None:
        """A watermark can only advance over bugs already handled.

        The API returns newest-first. Processing in that order and then storing
        the newest timestamp seen would move the mark past everything older,
        which would never be swept again.
        """
        refs, _ = self._search(
            {
                "entries": [
                    _task(3, created="2026-09-30T10:00:00+00:00"),
                    _task(1, created="2026-09-28T10:00:00+00:00"),
                    _task(2, created="2026-09-29T10:00:00+00:00"),
                ]
            }
        )
        assert [r.bug_id for r in refs] == [1, 2, 3]

    def test_created_since_is_sent_as_a_date(self) -> None:
        """The API compares inclusively, so a timestamp re-fetches the boundary."""
        from datetime import UTC, datetime

        _, recorder = self._search(
            {"entries": []},
            created_since=datetime(2026, 9, 28, 14, 30, tzinfo=UTC),
        )
        assert "created_since=2026-09-28" in recorder.urls[0]
        assert "14%3A30" not in recorder.urls[0]

    def test_pagination_is_followed(self) -> None:
        pages = {
            "page1": {
                "entries": [_task(1, created="2026-09-28T10:00:00+00:00")],
                "next_collection_link": f"{API}/page2",
            },
            "page2": {"entries": [_task(2, created="2026-09-29T10:00:00+00:00")]},
        }

        def handler(request: httpx.Request) -> httpx.Response:
            key = "page2" if "page2" in str(request.url) else "page1"
            return httpx.Response(200, json=pages[key])

        client = Launchpad(
            config=LaunchpadConfig(min_interval_s=0.0, backoff_base_s=0.001),
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            sleep=lambda _s: None,
        )
        with client:
            assert [r.bug_id for r in client.search_tasks()] == [1, 2]

    def test_pagination_is_bounded(self) -> None:
        """A runaway loop at three seconds a request is a slow afternoon."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"entries": [_task(1)], "next_collection_link": f"{API}/more"},
            )

        client = Launchpad(
            config=LaunchpadConfig(min_interval_s=0.0, backoff_base_s=0.001),
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            sleep=lambda _s: None,
        )
        with client:
            refs = list(client.search_tasks(max_pages=3))
        assert len(refs) == 3

    def test_a_task_without_a_bug_link_is_skipped(self) -> None:
        """Not fatal: one malformed entry must not abandon the page."""
        refs, _ = self._search({"entries": [{"status": "New"}, _task(7)]})
        assert [r.bug_id for r in refs] == [7]

    def test_a_missing_entries_list_raises(self) -> None:
        """Distinct from an empty one: no entries is an answer, no list is not."""
        with pytest.raises(LaunchpadError, match="no entries list"):
            self._search({"total_size": 0})

    def test_an_empty_result_is_not_an_error(self) -> None:
        refs, _ = self._search({"entries": []})
        assert refs == []

    def test_a_task_with_an_unparseable_date_sorts_oldest(self) -> None:
        """Safe direction: handled before the watermark can move past it."""
        refs, _ = self._search(
            {
                "entries": [
                    _task(1, created="2026-09-29T10:00:00+00:00"),
                    _task(2, created="not a date"),
                ]
            }
        )
        assert [r.bug_id for r in refs] == [2, 1]


class TestProgressReporting:
    """The client is mostly *waiting*, and silence looks like a hang.

    At a three-second minimum interval a bug costing six requests spends
    eighteen seconds asleep. ``sweep`` reported nothing until a whole bug
    completed, so a fifty-bug pass appeared to do nothing for a quarter of an
    hour.
    """

    def test_requests_are_announced(self) -> None:
        said: list[str] = []
        recorder = Recorder(_routes("VarLogDistupgradeAptlog.txt"))
        with _launchpad(recorder, progress=said.append) as client:
            client.bug(2150319)
        assert any(message.startswith("GET ") for message in said)

    def test_pacing_is_announced(self) -> None:
        """The dominant cost, and the one that used to be invisible."""
        said: list[str] = []
        waits: list[float] = []
        recorder = Recorder(_routes("VarLogDistupgradeAptlog.txt"))
        client = Launchpad(
            config=LaunchpadConfig(min_interval_s=3.0, backoff_base_s=0.001),
            client=_client(recorder),
            sleep=waits.append,
            progress=said.append,
        )
        with client:
            client.bug(2150319)
        assert waits, "precondition: the second request is paced"
        assert any(message.startswith("pacing ") for message in said), said

    def test_a_rate_limit_wait_is_announced(self) -> None:
        """Tens of seconds of silence is indistinguishable from a hang."""
        said: list[str] = []
        state = {"calls": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            state["calls"] += 1
            if state["calls"] == 1:
                return httpx.Response(429, headers={"Retry-After": "42"})
            return httpx.Response(200, json=_bug_payload())

        client = Launchpad(
            config=LaunchpadConfig(min_interval_s=0.0, backoff_base_s=0.001),
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            sleep=lambda _s: None,
            progress=said.append,
        )
        with client:
            client._json(f"{API}/bugs/2150319")
        assert any("429" in message and "42" in message for message in said), said

    def test_attachments_are_counted(self) -> None:
        """Which of four logs is downloading, not merely that one is."""
        said: list[str] = []
        recorder = Recorder(
            _routes("VarLogDistupgradeAptlog.txt", "VarLogDistupgradeMainlog.txt")
        )
        with _launchpad(recorder, progress=said.append) as client:
            client.logs(2150319)
        assert any("attachment 1/2" in message for message in said), said
        assert any("attachment 2/2" in message for message in said), said

    def test_the_search_announces_pages(self) -> None:
        recorder = Recorder(
            {
                f"{API}/ubuntu/+source/ubuntu-release-upgrader": httpx.Response(
                    200, json={"entries": []}
                )
            }
        )
        said: list[str] = []
        with _launchpad(recorder, progress=said.append) as client:
            list(client.search_tasks())
        assert any("page 1" in message for message in said), said

    def test_silent_by_default(self) -> None:
        """A library caller and every test want nothing printed.

        Asserted by construction: there is no console in this module, so the
        only way a message escapes is through the injected callback.
        """
        recorder = Recorder(_routes("VarLogDistupgradeAptlog.txt"))
        with _launchpad(recorder) as client:
            assert client.progress is None
            client.bug(2150319)

    def test_messages_are_short_enough_for_one_line(self) -> None:
        """A progress line that wraps is worse than no progress line.

        A full Launchpad API URL is ninety characters of which the last two
        segments are the only informative part.
        """
        said: list[str] = []
        recorder = Recorder(_routes("VarLogDistupgradeAptlog.txt"))
        with _launchpad(recorder, progress=said.append) as client:
            client.logs(2150319)
        assert said
        for message in said:
            assert len(message) <= 60, message


class TestOmitDuplicates:
    """Launchpad hides duplicates by default, and that default is wrong here.

    Measured against the live API on 2026-10-05 over
    ``created_since=2026-09-25``: the default returned 36 tasks and
    ``omit_duplicates=false`` returned 49, hiding 13 bugs. Four of the thirteen
    were already in the development corpus, stored as ``New`` with no duplicate
    recorded, because they had been swept *before* anyone marked them.

    So a bug does not merely start out invisible -- it *becomes* invisible the
    moment somebody triages it, which is exactly when a triage tool needs to
    notice.
    """

    def _url(self, **kwargs: object) -> str:
        recorder = Recorder(
            {
                f"{API}/ubuntu/+source/ubuntu-release-upgrader": httpx.Response(
                    200, json={"entries": [_task(1)]}
                )
            }
        )
        with _launchpad(recorder) as client:
            list(client.search_tasks(**kwargs))  # type: ignore[arg-type]
        return recorder.urls[0]

    def test_duplicates_are_included_by_default(self) -> None:
        assert "omit_duplicates=false" in self._url()

    def test_can_still_be_asked_to_omit_them(self) -> None:
        """The exclusion is needed to *detect* duplicates by difference."""
        assert "omit_duplicates=true" in self._url(omit_duplicates=True)

    def test_modified_since_is_sent_as_a_date(self) -> None:
        """What makes a refresh one request rather than one per fifty bugs."""
        url = self._url(modified_since=datetime(2026, 10, 3, 14, 30, tzinfo=UTC))
        assert "modified_since=2026-10-03" in url
        assert "14%3A30" not in url


class TestSearchTriage:
    """Learning status and duplication from the listing alone."""

    def _triage(
        self, with_dupes: list[dict], without_dupes: list[dict]
    ) -> tuple[object, Recorder]:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            calls.append(url)
            entries = without_dupes if "omit_duplicates=true" in url else with_dupes
            return httpx.Response(200, json={"entries": entries})

        recorder = Recorder({})
        recorder.urls = calls
        with Launchpad(
            config=LaunchpadConfig(min_interval_s=0.0),
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            sleep=lambda _: None,
        ) as client:
            return (client.search_triage(), recorder)

    def test_the_difference_identifies_duplicates(self) -> None:
        """The task entry has no duplicate field, so this is the cheap route.

        Verified against the live API: a task entry carries ``status``,
        ``date_created``, ``importance`` and twenty-odd other keys, none of
        them about duplication.
        """
        search, _ = self._triage(
            with_dupes=[_task(1), _task(2), _task(3)],
            without_dupes=[_task(1), _task(3)],
        )
        flags = {ref.bug_id: ref.is_duplicate for ref in search}  # type: ignore[attr-defined]
        assert flags == {1: False, 2: True, 3: False}

    def test_it_costs_two_listings_not_one_request_per_bug(self) -> None:
        _, recorder = self._triage([_task(1)], [_task(1)])
        assert len(recorder.urls) == 2

    def test_a_complete_listing_is_reported_as_complete(self) -> None:
        search, _ = self._triage([_task(1)], [_task(1)])
        assert search.complete is True  # type: ignore[attr-defined]

    def test_a_truncated_listing_is_reported_as_incomplete(self) -> None:
        """The flag changes what absence from the listing may be read to mean.

        ``ubuntu-release-upgrader`` has far more bugs than ``max_pages`` will
        fetch. A caller that treated "absent" as "unmodified" would stamp every
        unread bug as confirmed current -- which is the one lie the whole
        refresh mechanism exists to avoid.
        """

        def handler(request: httpx.Request) -> httpx.Response:
            # Always another page, so pagination can only end by hitting the cap.
            return httpx.Response(
                200,
                json={
                    "entries": [_task(1)],
                    "next_collection_link": f"{API}/next",
                },
            )

        with Launchpad(
            config=LaunchpadConfig(min_interval_s=0.0),
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            sleep=lambda _: None,
        ) as client:
            search = client.search_triage(max_pages=2)
        assert search.complete is False


class TestDuplicateOf:
    """Resolving a master, which only the bug resource can answer."""

    def test_reads_the_master_and_the_count(self) -> None:
        recorder = Recorder(
            {
                f"{API}/bugs/2169028": httpx.Response(
                    200,
                    json=_bug_payload(
                        duplicate_of_link=f"{API}/bugs/2168855",
                        number_of_duplicates=0,
                    ),
                )
            }
        )
        with _launchpad(recorder) as client:
            assert client.duplicate_of(2169028) == (2168855, 0)

    def test_costs_one_request_not_the_attachment_listing_too(self) -> None:
        """Halving the per-bug cost halves the only pass that does not scale."""
        recorder = Recorder(
            {f"{API}/bugs/1": httpx.Response(200, json=_bug_payload(duplicate_of_link=None))}
        )
        with _launchpad(recorder) as client:
            assert client.duplicate_of(1) == (None, 2)
        assert len(recorder.urls) == 1


class TestTaskStatus:
    """The escape hatch from the listing's page limit."""

    def test_reads_this_package_s_task_status(self) -> None:
        recorder = Recorder(
            {
                f"{API}/ubuntu/+source/ubuntu-release-upgrader/+bug/40792": httpx.Response(
                    200, json={"status": "Triaged"}
                )
            }
        )
        with _launchpad(recorder) as client:
            assert client.task_status(40792) == "Triaged"

    def test_a_missing_task_is_empty_not_an_error(self) -> None:
        """A bug can be retargeted after it was collected."""
        with _launchpad(Recorder({})) as client:
            assert client.task_status(404) == ""
