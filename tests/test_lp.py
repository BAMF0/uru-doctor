# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for :mod:`uru_doctor.lp.read`.

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
from pathlib import Path

import httpx
import pytest

from uru_doctor.config import LaunchpadConfig
from uru_doctor.lp.read import (
    AttachmentRef,
    BugRecord,
    Launchpad,
    LaunchpadError,
    RateLimited,
)
from uru_doctor.models import LogSource
from uru_doctor.store import Store

from .conftest import fixture_text

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
        import uru_doctor.lp.read as module

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
