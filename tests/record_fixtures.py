"""Regenerate the recorded log fixtures.

Run with ``uv run python -m tests.record_fixtures``.

The fixtures are real logs from real bug reports and from this developer's own
machine, passed through :mod:`uru_doctor.parsers.sanitize` so that no hostname,
username, home-directory path, email address or network address survives.
Package names, versions, constraints and apt state blobs are kept untouched,
because those are the evidence.

Keeping the generator in the repository rather than hand-editing the fixtures
means a reviewer can re-run it against the sources and diff the result, and the
redaction is reproducible: :func:`uru_doctor.parsers.sanitize.redact` is
idempotent, so a second pass over an already-redacted file is a no-op.

Sources are listed in :data:`SOURCES`. Those under ``/var/log/dist-upgrade``
exist only on the machine this was developed on; those under ``/tmp`` are
Launchpad attachments fetched by hand. Either way the fixtures are committed, so
the test suite never needs the network or any particular machine.
"""

from __future__ import annotations

import sys
from pathlib import Path

from uru_doctor.parsers.sanitize import read_log

FIXTURES = Path(__file__).parent / "fixtures"

#: ``(destination, source, provenance)``.
#:
#: The provenance note is written into a manifest beside the fixtures so that a
#: reader can tell which apt dialect and which failure mode each one exercises
#: without having to open it.
SOURCES: tuple[tuple[str, str, str], ...] = (
    (
        "apt/lp2169028-apt.log",
        "/tmp/opencode/aptlogs/b2169028-apt.log",
        "LP#2169028 'unable to update kubuntu to 26-04'; apt 2.8.3; noble->resolute. "
        "74 broken packages reducing to 21 roots, python3 owning 39. Contains the "
        "apt-2.8-only state shapes @un H, @un pumN Ib and @ii ugH.",
    ),
    (
        "logs/lp2169028-main.log",
        "/tmp/opencode/aptlogs/b2169028-main.log",
        "LP#2169028 main.log; ends mid-run at Quirks.PreDistUpgradeCache with no "
        "error recorded. The truncated-evidence case.",
    ),
    (
        "apt/lp2150319-apt.log",
        "/tmp/opencode/aptlogs/b2150319-apt.log",
        "LP#2150319 '[SRU] lintian breaks upgrade from 24.04 to 26.04'; apt 2.8.x. "
        "The holdback: libfile-libmagic-perl declined with an apt score margin of 1, "
        "which is why the bug was irreproducible on a clean install.",
    ),
    (
        "apt/lp2150245-apt.log",
        "/tmp/opencode/aptlogs/b2150245-apt.log",
        "LP#2150245 'libwacom-surface Upgrade form 24LTS to 26LTS fails'; apt 2.8.x. "
        "Third-party blocker from the unsupported linux-surface PPA. Closed Invalid "
        "with THIRTEEN Launchpad-confirmed duplicates, whose titles range from "
        "'Ubgrade does not work' to 'upgrade to 26.4' -- free ground truth for the "
        "deduplicator, which must cluster them on root identity alone.",
    ),
    (
        "logs/lp2150245-main.log",
        "/tmp/opencode/aptlogs/b2150245-main.log",
        "LP#2150245 main.log; names the third-party packages in its Foreign list.",
    ),
    (
        "logs/lp2150319-main.log",
        "/tmp/opencode/aptlogs/b2150319-main.log",
        "LP#2150319 main.log. Contains the give-up line, where apt's comma-joined "
        "error stack mixes a Google Chrome i386 W: warning next to the real "
        "E: pkgProblemResolver error -- the adjacency that sent the reporter and "
        "three commenters chasing Chrome for weeks.",
    ),
    (
        "apt/local-apt3-success.log",
        "/var/log/dist-upgrade/apt.log",
        "Developer machine, apt 3.2.0, resolute->stonking, resolve succeeded. "
        "Negative control: a clean resolve must produce no high-severity roots.",
    ),
    (
        "apt/local-apt3-gnome.log",
        "/var/log/dist-upgrade/20260116-1315/apt.log",
        "Developer machine, apt 3.2.0. GNOME transitional Breaks and Conflicts "
        "resolved by removal, plus a mutually-conflicting pair that forces the "
        "cycle-breaking path in root finding.",
    ),
    (
        "apt/local-apt3-devcascade.log",
        "/var/log/dist-upgrade/20260623-1109/apt.log",
        "Developer machine, apt 3.2.0. The libselinux1-dev cascade: libselinux1 "
        "upgrades past an exact-version pin, which removes libselinux1-dev and "
        "cascades through libmount-dev, libgio-2.0-dev, libglib2.0-dev and the "
        "GTK -dev chain. Also exercises section collapsing, since the resolve is "
        "logged four times.",
    ),
    (
        "logs/local-main.log",
        "/var/log/dist-upgrade/main.log",
        "Developer machine main.log, apt 3.2.0, complete run through to "
        "PostInstallScript. Exercises every phase marker.",
    ),
    (
        "logs/local-main-reexec.log",
        "/var/log/dist-upgrade/20260116-1317/main.log",
        "Developer machine main.log that ends at 're-exec inside screen'. The stub "
        "case: a parser trusting this would conclude the upgrade never started.",
    ),
    (
        "logs/local-history.log",
        "/var/log/dist-upgrade/history.log",
        "apt history.log with single lines of several hundred kilobytes listing two "
        "thousand packages.",
    ),
)


def record(*, verbose: bool = True) -> tuple[int, list[str]]:
    """Write every available fixture. Returns ``(written, skipped)``."""
    written = 0
    skipped: list[str] = []
    manifest: list[str] = [
        "# Recorded log fixtures",
        "",
        "Generated by `uv run python -m tests.record_fixtures`. Do not hand-edit.",
        "",
        "All content is passed through `uru_doctor.parsers.sanitize.read_log`, which",
        "strips terminal escapes and replaces hostnames, usernames, home-directory",
        "account names, email addresses and network addresses. Package names,",
        "versions, dependency constraints and apt state blobs are preserved, because",
        "they are what the tests assert on.",
        "",
    ]

    for destination, source, provenance in SOURCES:
        src = Path(source)
        target = FIXTURES / destination
        if not src.is_file():
            skipped.append(f"{destination} (missing source {source})")
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        cleaned = read_log(src.read_bytes(), redacted=True)
        target.write_text(cleaned + "\n", encoding="utf-8")
        written += 1
        if verbose:
            print(f"wrote {destination}  ({len(cleaned):,} bytes)")
        manifest.append(f"## `{destination}`")
        manifest.append("")
        manifest.append(provenance)
        manifest.append("")

    (FIXTURES / "MANIFEST.md").write_text("\n".join(manifest), encoding="utf-8")
    return (written, skipped)


def main() -> int:
    written, skipped = record()
    print(f"\n{written} fixture(s) written to {FIXTURES}")
    for note in skipped:
        print(f"skipped: {note}")
    if not written:
        print("nothing recorded -- no sources available on this machine", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
