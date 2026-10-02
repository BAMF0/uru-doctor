#!/usr/bin/env python3
"""Run uru-doctor over fetched bugs and print every verification gate.

    uv run .opencode/skills/triage-new-bug/scripts/check_bug.py 2169197 [...]
    uv run .opencode/skills/triage-new-bug/scripts/check_bug.py --fixtures

With ``--fixtures`` it runs the committed corpus instead, which is the
regression check.

Print everything, decide nothing. The gates below are ordered so that the
cheapest and most consequential failure -- incomplete lexing -- is seen before
any attention is spent on the diagnosis it produced. A diagnosis drawn from a
68%-lexed log is not a wrong answer to argue with; it is an answer to an
unrelated question.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "src"))

from uru_doctor.apt.lexer import LexStats, lex  # noqa: E402
from uru_doctor.apt.livelock import detect_oscillations  # noqa: E402
from uru_doctor.apt.sections import read_sections  # noqa: E402
from uru_doctor.config import DedupConfig  # noqa: E402
from uru_doctor.dedup import build_signature, cluster_runs, summarise  # noqa: E402
from uru_doctor.diagnose import diagnose  # noqa: E402
from uru_doctor.ingest import ingest_attachments  # noqa: E402
from uru_doctor.intern import Interner  # noqa: E402
from uru_doctor.models import LogSource  # noqa: E402
from uru_doctor.parsers.apportmeta import parse_apport_meta  # noqa: E402
from uru_doctor.parsers.aptterm import parse_apt_term  # noqa: E402
from uru_doctor.parsers.sanitize import read_log  # noqa: E402
from uru_doctor.store import Store  # noqa: E402
from uru_doctor.title import phase_note, propose_title  # noqa: E402

CACHE = Path("/tmp/opencode/aptlogs")
FIXTURES = ROOT / "tests" / "fixtures"

_KINDS = {
    "apt": LogSource.APT,
    "main": LogSource.MAIN,
    "aptterm": LogSource.APT_TERM,
    "history": LogSource.HISTORY,
}


def load_fetched(bug_id: str) -> tuple[dict[LogSource, str], object | None]:
    meta = None
    path = CACHE / f"bug{bug_id}.json"
    if path.is_file():
        payload = json.loads(path.read_text())
        meta = parse_apport_meta(payload["description"], tags=payload["tags"])
    attachments: dict[LogSource, str] = {}
    for kind, source in _KINDS.items():
        candidate = CACHE / f"new{bug_id}-{kind}.log"
        if candidate.is_file():
            attachments[source] = read_log(candidate.read_bytes())
    return (attachments, meta)


def bug_of(run_id: str) -> str:
    """The bug a run id belongs to.

    One bug can carry more than one upgrade. On bug 2150319 a second reporter
    attached their own logs in comment 19, recorded as ``2150319-c19``. Those
    are a separate *run* -- separate apt log, separate graph, separate
    signature -- sharing the bug's description and tags, so dedup should be
    able to pair them the way it pairs two bugs.
    """
    return run_id.split("-", 1)[0]


def load_fixture(run_id: str) -> tuple[dict[LogSource, str], object | None]:
    meta = None
    path = FIXTURES / "lp" / f"bug{bug_of(run_id)}.json"
    if path.is_file():
        payload = json.loads(path.read_text())
        meta = parse_apport_meta(payload["description"], tags=payload["tags"])
    attachments: dict[LogSource, str] = {}
    for name, source in (
        (f"apt/lp{run_id}-apt.log", LogSource.APT),
        (f"logs/lp{run_id}-main.log", LogSource.MAIN),
        (f"logs/lp{run_id}-aptterm.log", LogSource.APT_TERM),
        (f"logs/lp{run_id}-history.log", LogSource.HISTORY),
    ):
        candidate = FIXTURES / name
        if candidate.is_file():
            attachments[source] = candidate.read_text()
    return (attachments, meta)


def report(bug_id: str, attachments: dict[LogSource, str], meta: object | None) -> dict:
    interner = Interner(Store.open(Path(tempfile.mkdtemp())))
    run = ingest_attachments(attachments, interner, meta=meta, bug_id=int(bug_of(bug_id)))
    term = (
        parse_apt_term(attachments[LogSource.APT_TERM].splitlines(), locale=run.locale)
        if LogSource.APT_TERM in attachments
        else None
    )
    result = diagnose(run, interner, meta=meta, term=term)
    title = propose_title(run, result, interner)

    print(f"\n{'=' * 92}\nLP#{bug_id}")

    # ---- GATE 1: lexing. Nothing below this means anything until it passes.
    if LogSource.APT in attachments:
        stats = LexStats()
        list(lex(attachments[LogSource.APT].splitlines(), stats))
        flag = "OK " if stats.coverage == 1.0 else "FAIL"
        print(f"  [{flag}] lexer coverage {stats.coverage:.4%}  unmatched={stats.unmatched}")
        for shape, count in stats.top_unknown(5):
            print(f"         !! {count}x {shape[:86]}")
        unknown_flags = stats.vocabulary.unknown
        print(
            f"  [{'OK ' if not unknown_flags else 'FAIL'}] state flags: "
            f"{unknown_flags or 'all decoded'}"
        )

    # ---- GATE 2: did we understand the run at all?
    print(
        f"  [   ] {run.release_pair}  locale={run.locale or '-'}  apt={run.apt_version}"
        f"  {run.frontend.name}"
    )
    print(f"  [   ] {phase_note(run)}")
    print(
        f"  [   ] evidence_complete={run.evidence_complete}"
        f"  dpkg_wrote={run.dpkg_wrote}  upgrade_completed={result.upgrade_completed}"
    )
    print(f"  [   ] logs={[s.value for s in run.logs_present]}")

    # ---- GATE 3: the three counts, which mean different things.
    print(
        f"  [   ] apt_says_broken={run.apt_broken_count}"
        f"  observed_broken={run.counts.broken}"
        f"  up={run.counts.upgraded} inst={run.counts.installed} rm={run.counts.removed}"
        f"  held={run.counts.held_back}"
    )

    # ---- GATE 4: corroboration and third-party evidence.
    print(f"  [   ] apt E: {[interner.text(e)[:58] for e in run.apt_error_entries]}")
    print(f"  [   ] corroborated: {sorted(c.value for c in result.corroborated) or 'NONE'}")
    print(
        f"  [   ] third_party={len(run.third_party)}"
        f"  candidate_invalid={result.is_candidate_invalid}"
    )

    # ---- GATE 5: livelock, which outranks blast radius and so must be exact.
    if LogSource.APT in attachments:
        section = read_sections(attachments[LogSource.APT].splitlines()).primary
        if section is not None:
            weak = detect_oscillations(section, interner, min_reversals=1)
            strong = [o for o in weak if o.reversals >= 5]
            print(
                f"  [   ] oscillations: {len(strong)} strong / {len(weak)} any"
                f"  (reversal counts {sorted({o.reversals for o in weak}) or '-'})"
            )
            for osc in strong[:3]:
                print(
                    f"         {interner.package_label(osc.pkg_id):24}"
                    f" rev={osc.reversals:3} pos={osc.position:.1%}"
                    f" terminal={osc.is_terminal}"
                    f" blocked_by={interner.package_label(osc.blocked_by) or '-'}"
                )

    if term is not None:
        print(
            f"  [   ] apt-term: blocks={len(term.blocks)} dpkg_ran={term.dpkg_ran}"
            f" setup={sum(b.configured for b in term.substantive)}"
            f" failures={len(term.failures)} roots={len(term.roots)}"
        )

    # ---- The answer.
    print(f"\n  TITLE: {title.title}")
    print(f"         confident={title.confident}  len={len(title.title)}")
    print(f"  fired: {list(result.fired)}")
    for index, finding in enumerate(result.findings[:6], 1):
        print(
            f"   {index}. {finding.cause.value:28} casc={finding.cascade_size:3}"
            f" {finding.severity.name:6} {finding.rule:30}"
        )
        print(f"      {finding.summary[:96]}")
    for caveat in result.caveats:
        print(f"   !! {caveat.summary}")
    if result.notes:
        print(f"  notes: {result.notes}")

    return {"signature": build_signature(run, result.findings, interner), "title": title}


def main(argv: list[str]) -> int:
    if argv == ["--fixtures"]:
        # Discover runs, not bugs: a bug with two reporters' logs has two.
        # Bugs with no logs at all still need listing -- that is the
        # no-evidence case, and 2161332 is in the corpus to cover it.
        ids = sorted(
            {p.stem.removeprefix("bug") for p in (FIXTURES / "lp").glob("bug*.json")}
            | {
                p.name.removeprefix("lp").removesuffix("-apt.log")
                for p in (FIXTURES / "apt").glob("lp*-apt.log")
            }
        )
        loader = load_fixture
    elif argv:
        ids = [a.strip().lstrip("#") for a in argv]
        loader = load_fetched
    else:
        print(__doc__)
        return 2

    collected: dict[str, object] = {}
    titles: dict[str, object] = {}
    for bug_id in ids:
        attachments, meta = loader(bug_id)
        if not attachments and meta is None:
            print(f"\nLP#{bug_id}: nothing cached -- run fetch_bug.py first")
            continue
        out = report(bug_id, attachments, meta)
        collected[bug_id] = out["signature"]
        titles[bug_id] = out["title"]

    if len(collected) > 1:
        print(f"\n{'=' * 92}\nCLUSTERS")
        clusters = cluster_runs(collected, config=DedupConfig(), oldest_first=sorted(collected))
        for cluster in clusters:
            print(f"  [{cluster.tier}] {sorted(cluster.members)}")
        print(f"  {summarise(clusters)}")
        clustered = {m for c in clusters for m in c.members}
        print(f"  singletons: {sorted(set(collected) - clustered)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
