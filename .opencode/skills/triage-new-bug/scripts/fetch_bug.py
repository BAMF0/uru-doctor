#!/usr/bin/env python3
"""Fetch a Launchpad bug's metadata and upgrade logs, politely.

    ./fetch_bug.py 2169197 [2169251 ...]

Writes into ``/tmp/opencode/aptlogs/``:

    bug<ID>.json        trimmed bug: title, tags, attachment titles, description
    att_<ID>.json       raw attachment listing, as the fixture recorder wants it
    new<ID>-apt.log     /var/log/dist-upgrade/apt.log
    new<ID>-main.log    main.log
    new<ID>-aptterm.log apt-term.log, when attached
    new<ID>-history.log history.log, when attached

Why a script rather than ad-hoc curl:

**The API rate-limits with HTTP 429** and wants roughly a minute to recover, so
requests are spaced and 429 is retried with backoff rather than silently
producing a truncated log. A corpus pass that ignores this fails halfway
through and leaves half-written files behind.

**``webfetch`` does not work against Launchpad.** It gets blocked; plain HTTP
from curl or urllib is fine.

**Most attachments are not worth fetching.** ``Dependencies.txt``,
``CurrentDmesg.txt.txt``, ``JournalErrors.txt``, the apt-clone tarball and any
screenshot contain no upgrade evidence, and skipping them is most of the saved
time. The skip list is read from ``uru_doctor.parsers.apportmeta`` so it cannot
drift from what the tool itself believes.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

OUT = Path("/tmp/opencode/aptlogs")
API = "https://api.launchpad.net/devel/bugs"

#: Attachment title to local suffix. Only these are downloaded.
WANTED: dict[str, str] = {
    "VarLogDistupgradeAptlog.txt": "apt",
    "VarLogDistupgradeMainlog.txt": "main",
    "VarLogDistupgradeApttermlog.txt": "aptterm",
    "VarLogDistupgradeAptHistorylog.txt": "history",
    # Spellings seen on older bugs.
    "VarLogDistupgradeHistorylog.txt": "history",
    "VarLogDistupgradeTermlog.txt": "term",
}

PAUSE = 3.0
"""Seconds between requests. Below about two the API starts answering 429."""


def get(url: str, *, attempts: int = 4) -> bytes:
    """GET with backoff on 429 and 503.

    The scheme is checked because attachment URLs come from the API response
    rather than from the caller, and :func:`urllib.request.urlopen` will
    happily open ``file://``.
    """
    if not url.startswith("https://"):
        msg = f"refusing non-https url: {url}"
        raise ValueError(msg)
    delay = PAUSE
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(url, timeout=90) as response:
                return bytes(response.read())
        except urllib.error.HTTPError as error:
            if error.code not in (429, 503) or attempt == attempts:
                raise
            wait = delay * (2**attempt)
            print(f"    HTTP {error.code}; waiting {wait:.0f}s", file=sys.stderr)
            time.sleep(wait)
    msg = f"gave up on {url}"
    raise RuntimeError(msg)


def skip(title: str) -> bool:
    """Whether the tool already knows this attachment is irrelevant."""
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "src"))
        from uru_doctor.parsers.apportmeta import is_irrelevant_attachment
    except ImportError:
        # Fall back to a literal list rather than fetching everything.
        return title.lower().endswith((".png", ".jpg", ".jpeg", ".gz", ".tar.gz"))
    return is_irrelevant_attachment(title)


def fetch(bug_id: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    print(f"=== LP#{bug_id} ===")

    bug = json.loads(get(f"{API}/{bug_id}"))
    time.sleep(PAUSE)
    attachments = json.loads(get(f"{API}/{bug_id}/attachments"))
    time.sleep(PAUSE)

    titles = [entry.get("title", "") for entry in attachments.get("entries", [])]
    (OUT / f"att_{bug_id}.json").write_text(json.dumps(attachments, indent=2))
    (OUT / f"bug{bug_id}.json").write_text(
        json.dumps(
            {
                "id": bug.get("id"),
                "title": bug.get("title", ""),
                "tags": bug.get("tags", []),
                "attachments": titles,
                "description": bug.get("description", ""),
            },
            indent=2,
        )
    )

    print(f"  title: {bug.get('title', '')}")
    print(f"  tags:  {bug.get('tags', [])}")
    print(f"  dups:  {bug.get('number_of_duplicates')}  dup_of: {bug.get('duplicate_of_link')}")

    found = 0
    for entry in attachments.get("entries", []):
        title = entry.get("title", "")
        suffix = WANTED.get(title)
        if suffix is None:
            print(f"  skip  {title}" if skip(title) else f"  UNKNOWN attachment: {title}")
            continue
        target = OUT / f"new{bug_id}-{suffix}.log"
        data = get(entry["data_link"])
        target.write_bytes(data)
        print(f"  got   {target.name}  ({len(data):,} bytes)")
        found += 1
        time.sleep(PAUSE)

    if not found:
        print("  NO LOGS ATTACHED -- this is the no-evidence case; still worth testing")


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    for bug_id in argv:
        fetch(bug_id.strip().lstrip("#"))
    print(f"\nwrote to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
