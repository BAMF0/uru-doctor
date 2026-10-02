#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Fetch a Launchpad bug's metadata and upgrade logs, politely.

    ./fetch_bug.py 2169197 [2169251 ...]

Writes into ``/tmp/opencode/aptlogs/``:

    bug<ID>.json        trimmed bug: title, tags, attachment titles, description
    new<ID>-apt.log     /var/log/dist-upgrade/apt.log
    new<ID>-main.log    main.log
    new<ID>-aptterm.log apt-term.log, when attached
    new<ID>-history.log history.log, when attached

This is a thin wrapper around :mod:`uru_doctor.lp.read`, which owns the
rate-limiting, the retry policy and the decision about which attachments are
worth downloading. It was once a standalone implementation of all three, and
the copies drifted: the module learned to sniff hand-uploaded attachments by
content while this script still skipped them, so a bug whose reporter had
named their log ``upgrade.txt`` looked like it had none.

What the module knows, and why none of it is re-stated here:

**Launchpad answers 429 readily** and takes about a minute to forgive one, so
requests are spaced rather than parallelised.

**Most attachments are not worth fetching.** ``Dependencies.txt``,
``JournalErrors.txt``, the apt-clone tarball and any screenshot contain no
upgrade evidence. The list lives in ``uru_doctor.parsers.apportmeta`` beside
the code that reads the files it names.

**An unrecognised name is not an irrelevant one.** Roughly a third of the
useful attachments on real bugs are hand-uploaded under names no table
predicts, so they are downloaded and identified by their contents.

``webfetch`` does not work against Launchpad -- it gets blocked -- but plain
HTTP does, which is what this uses.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "src"))

from uru_doctor.lp.read import Launchpad, LaunchpadError, RateLimited  # noqa: E402
from uru_doctor.models import LogSource  # noqa: E402

OUT = Path("/tmp/opencode/aptlogs")

#: Local filename suffix per log source, matching what ``record_fixtures.py``
#: and ``check_bug.py`` expect.
SUFFIX: dict[LogSource, str] = {
    LogSource.APT: "apt",
    LogSource.MAIN: "main",
    LogSource.APT_TERM: "aptterm",
    LogSource.HISTORY: "history",
    LogSource.TERM: "term",
    LogSource.XORG_FIXUP: "xorgfixup",
    LogSource.SCREENLOG: "screenlog",
}


def fetch(client: Launchpad, bug_id: int) -> bool:
    print(f"=== LP#{bug_id} ===")
    try:
        logs, record = client.logs(bug_id)
    except RateLimited as exc:
        print(f"  RATE LIMITED: {exc}", file=sys.stderr)
        raise
    except LaunchpadError as exc:
        print(f"  FAILED: {exc}", file=sys.stderr)
        return False

    (OUT / f"bug{bug_id}.json").write_text(
        json.dumps(
            {
                "id": bug_id,
                "title": record.title,
                "tags": list(record.tags),
                "attachments": [a.title for a in record.attachments],
                "description": record.description,
            },
            indent=2,
        )
    )

    print(f"  title: {record.title}")
    print(f"  tags:  {list(record.tags)}")
    print(f"  dups:  {record.duplicate_count}  dup_of: {record.duplicate_of}")
    for ref in record.attachments:
        if ref.irrelevant:
            print(f"  skip  {ref.title}")

    for source, text in sorted(logs.items(), key=lambda kv: kv[0].value):
        suffix = SUFFIX.get(source)
        if suffix is None:
            continue
        target = OUT / f"new{bug_id}-{suffix}.log"
        target.write_text(text, encoding="utf-8")
        print(f"  got   {target.name}  ({len(text):,} chars)")

    if not logs:
        print("  NO LOGS ATTACHED -- this is the no-evidence case; still worth testing")
    return True


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    with Launchpad() as client:
        for raw in argv:
            try:
                fetch(client, int(raw.strip().lstrip("#")))
            except RateLimited:
                print("\nStopped: wait a minute and retry.", file=sys.stderr)
                return 1
            except ValueError:
                print(f"not a bug number: {raw!r}", file=sys.stderr)
                return 2
    print(f"\nwrote to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
