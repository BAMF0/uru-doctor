# SPDX-License-Identifier: GPL-2.0-or-later
"""Command line interface.

Commands split along one line: whether they write to the record store.

``diagnose``, ``title`` and ``rules`` answer a question about something you
hand them and leave nothing behind. ``ingest`` and ``fetch`` build the corpus,
and ``dedup``, ``show``, ``stats``, ``related``, ``history`` and ``coverage``
read it back. Interning is a write -- it has to be, since the point of the
store is that template and package ids are stable across runs -- so a command
that only answers a question uses a throwaway store rather than creating
``.uru-doctor/`` in whatever directory you happened to be standing in.

The three corpus-reading commands exist because a diagnosis of one bug is only
half a triage decision. ``related`` and ``history`` answer "have we seen this
before, and was this package ever actually the cause"; ``coverage`` answers
"how much of what we stored did we actually read". All three query data the
store had been indexing with nothing able to ask for it.

Nothing here writes to Launchpad. The tool proposes titles and duplicate
groupings; a human applies them. That is not timidity about the code, it is
that the judgement "this bug is Invalid" belongs to someone accountable for it,
and a tool that acted on its own verdicts would have to be right far more often
than this one can promise.

Exit codes are meant for scripts: ``0`` success, ``1`` a real failure, ``2``
bad usage, and ``3`` for ``--strict`` when the logs parsed but not perfectly.
Three is separate because "I could not read part of this log" is a different
answer from "this bug has no diagnosis", and a corpus run wants to tell them
apart.
"""

from __future__ import annotations

import json
import sys
import tempfile
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Final, TypedDict

import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

import uru_doctor.rules  # noqa: F401  -- import registers every rule in RULES
from uru_doctor import __version__
from uru_doctor.config import Config, load_config
from uru_doctor.dedup import Cluster, Tier, build_signature, cluster_runs, summarise
from uru_doctor.diagnose import DiagnosisResult, diagnose, explain
from uru_doctor.ingest import IngestResult, ingest_attachments, ingest_directory
from uru_doctor.intern import Interner
from uru_doctor.lp.read import BugRecord, BugRef, Launchpad, LaunchpadError, RateLimited
from uru_doctor.models import LogSource, Signature, UpgradeRun
from uru_doctor.parsers.apportmeta import parse_apport_meta
from uru_doctor.report import RunEntry, plural, render_corpus, render_run
from uru_doctor.rules.registry import all_rules, rules_digest
from uru_doctor.store import Store, run_key_for
from uru_doctor.title import ProposedTitle, propose_title

EXIT_OK: Final = 0
EXIT_FAIL: Final = 1
EXIT_USAGE: Final = 2
_UNKNOWN_SHAPES_SHOWN: Final = 5
"""How many distinct unrecognised shapes to list before summarising.

Enough to see whether a gap is one new verb or a whole dialect, few enough
that an imperfect parse does not scroll the verdict off the screen.
"""

EXIT_IMPERFECT: Final = 3
"""``--strict`` found a log it could not fully parse.

Distinct from a failure because the diagnosis may still be sound; it means the
grammar has a gap and the result deserves a human's eye.
"""

app = typer.Typer(
    name="uru-doctor",
    help=(
        "Diagnose, deduplicate and retitle Ubuntu Release Upgrader bugs from their upgrade logs."
    ),
    no_args_is_help=True,
    add_completion=False,
)

out = Console()
err = Console(stderr=True)


# -- progress ----------------------------------------------------------------
#
# Which console the bar draws on is load-bearing.
#
# Rich moves a live region out of the way of ``Console.print`` only for *its
# own* console. A bar on stderr while verdicts print to stdout means two
# programs drawing on one terminal, and the result is a bar stamped through the
# middle of a report.
#
# So the bar goes wherever the document is not:
#
# - ``--json`` and ``--markdown`` write a document to stdout that is meant to
#   be redirected. The bar must be on stderr, and nothing else prints to stdout
#   during the run, so there is nothing to collide with.
# - In human mode the verdicts *are* the stdout output, so the bar shares that
#   console and Rich interleaves them correctly.
#
# Either way it is disabled when the target is not a terminal, so a cron job or
# a `2>log` capture gets no control codes. Rich decides that from the console,
# which is why the console is asked rather than ``sys.stderr``.


@contextmanager
def _progress(*, console: Console | None = None) -> Iterator[Tracker]:
    """A live progress display, or a silent stand-in.

    Worth having rather than printing per-item lines because this tool spends
    most of its wall-clock *waiting*: Launchpad is paced at three seconds a
    request, so a bug costing six requests is eighteen seconds during which
    nothing at all used to be printed. A sweep of fifty bugs looked hung for a
    quarter of an hour.

    The returned tracker is a no-op when disabled, so a caller never has to ask
    whether progress is on.
    """
    target = console if console is not None else err
    if not target.is_terminal:
        yield Tracker(None, None)
        return
    display = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=24),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=target,
        # Leaves the terminal as it was found: the summary the command prints
        # afterwards is the record, and a leftover bar competing with it is
        # just noise.
        transient=True,
    )
    with display:
        yield Tracker(display, None)


@dataclass(slots=True)
class Tracker:
    """A single-line progress bar that may not exist.

    Collapses the "is progress enabled?" question into one place. Every method
    is a no-op when ``display`` is ``None``, which is the case under ``--json``
    with stderr redirected, in a cron job, and in tests.

    Deliberately **one** task for the whole command, re-described and re-totalled
    as the work changes phase. Adding a second task leaves the first alive and
    unfinished -- a sweep showed ``searching Launchpad 0/?`` stuck above the
    real bar for its entire run, because a phase that has moved on still had a
    row drawing itself.
    """

    display: Progress | None
    task: TaskID | None
    prefix: str = ""
    """Stable context the per-request messages hang off, e.g. ``LP#2169028``.

    Without it the label is whatever the client last said -- ``GET
    6003872/data`` -- which tells you the tool is alive but not what it is
    working on, and an opaque attachment id is the least useful half of the
    answer.
    """

    def start(self, description: str, total: int | None) -> None:
        """Begin, or re-purpose, the single task.

        ``total=None`` is a spinner with no bar, which is the honest rendering
        when the amount of work is not yet known -- the Launchpad search is
        several paced requests and the page count only emerges as it goes, and
        pair scoring short-circuits so its work cannot be counted up front.

        The task is removed and re-added rather than reset, because Rich reads
        ``total=None`` on both ``reset`` and ``update`` as "leave the total
        alone". Resetting therefore kept the previous phase's total and drew
        ``clustering 0/7`` -- a bar measuring seven of something that was no
        longer being counted.
        """
        if self.display is None:
            return
        self.prefix = ""
        if self.task is not None:
            self.display.remove_task(self.task)
        self.task = self.display.add_task(description, total=total)

    def context(self, prefix: str) -> None:
        """Set the stable part of the label and show it immediately."""
        self.prefix = prefix
        self.note("")

    def advance(self, description: str | None = None) -> None:
        """Count one item done, optionally relabelling first."""
        if self.display is None or self.task is None:
            return
        if description is not None:
            self.display.update(self.task, description=self._label(description))
        self.display.advance(self.task)

    def note(self, description: str) -> None:
        """Change the label without counting progress.

        This is what the Launchpad client's callback drives: "pacing 2.8s",
        "GET bugs/2168863". The item is not finished, but the tool is visibly
        doing something, which is the whole point.
        """
        if self.display is not None and self.task is not None:
            self.display.update(self.task, description=self._label(description))

    def _label(self, description: str) -> str:
        if not self.prefix:
            return description
        return f"{self.prefix} {description}".rstrip()

    @property
    def callback(self) -> Callable[[str], None]:
        """A ``progress`` callable for :class:`~uru_doctor.lp.read.Launchpad`."""
        return self.note


# -- shared plumbing ---------------------------------------------------------


def _fail(message: str, code: int = EXIT_FAIL) -> None:
    """Report a problem on stderr and stop.

    On stderr so that ``uru-doctor diagnose … --markdown > report.md`` produces
    a report or an empty file, never a file with an error message in the middle
    of it.
    """
    err.print(f"[bold red]error:[/] {message}")
    raise typer.Exit(code)


def _config(path: Path | None) -> Config:
    try:
        return load_config(path)
    except FileNotFoundError:
        _fail(f"no such config file: {path}")
    except (ValueError, TypeError) as exc:
        # Config models are ``extra="forbid"``, so a typo'd key lands here
        # rather than being silently ignored.
        _fail(f"invalid config: {exc}")
    raise AssertionError("unreachable")


@contextmanager
def _scratch_store() -> Iterator[Store]:
    """A store that exists for one command and is then thrown away.

    Interning cannot be done without writing, but a question about one
    directory should not leave state behind in the current working directory.
    The cost is that corpus-wide template frequencies are unavailable, which
    only affects evidence-similarity scoring -- and that needs a corpus, so it
    was never going to work on a single run anyway.
    """
    with (
        tempfile.TemporaryDirectory(prefix="uru-doctor-") as temporary,
        Store.open(Path(temporary)) as store,
    ):
        yield store


@contextmanager
def _state_store(config: Config) -> Iterator[Store]:
    try:
        with Store.open(config.paths.state_dir) as store:
            yield store
    except typer.Exit:
        # ``typer.Exit`` subclasses ``RuntimeError``, so the handler below
        # caught every deliberate exit raised inside the ``with`` body and
        # re-reported it -- ``uru-doctor dedup`` on an empty store printed its
        # real message and then "error: 1", the stringified exit code.
        raise
    except RuntimeError as exc:
        # Raised when the store was written by a newer schema version.
        _fail(str(exc))


def _diagnose_run(
    run: UpgradeRun, interner: Interner, config: Config
) -> tuple[UpgradeRun, DiagnosisResult, ProposedTitle, Signature]:
    """Diagnose a run and stamp it with the policy that produced the verdict.

    Returns the stamped run as well, because the stamp belongs to the record
    rather than to this function's caller: whatever gets stored, reported or
    serialised has to carry it, and threading it separately is how it would
    come to be missing from one of the three.
    """
    result = diagnose(
        run,
        interner,
        enabled=config.rules.enabled,
        disabled=config.rules.disabled,
    )
    stamped = run.model_copy(
        update={"tool_version": __version__, "rules_digest": rules_digest()}
    )
    title = propose_title(stamped, result, interner, max_length=config.title.max_length)
    signature = build_signature(
        stamped,
        result.findings,
        interner,
        granularity=config.dedup.version_granularity,
    )
    return (stamped, result, title, signature)


def _ingest(root: Path, interner: Interner, config: Config) -> IngestResult:
    if not root.exists():
        _fail(f"no such path: {root}")
    if not root.is_dir():
        _fail(f"not a directory: {root}\nPoint me at a dist-upgrade log directory.")
    result = ingest_directory(root, interner, redact=config.ingest.redact)
    if not result.runs:
        _fail(
            f"no upgrade logs found under {root}\n"
            "Expected at least one of main.log or apt.log, either there or in "
            "a dated subdirectory such as 20260623-1109."
        )
    return result


def _key_for(run: UpgradeRun) -> str:
    return run_key_for(run.bug_id, run.attempt, run.source_dir)


# -- terminal rendering ------------------------------------------------------


def _verdict_table(run: UpgradeRun, result: DiagnosisResult, title: ProposedTitle) -> Table:
    """The compact answer, for a terminal.

    Not the Markdown page rendered narrow. A terminal reader wants the verdict
    and the three or four facts that qualify it; the page exists for pasting
    into a bug, where the evidence and the provenance matter.
    """
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="dim", no_wrap=True)
    table.add_column(overflow="fold")

    primary = result.primary
    table.add_row("proposed title", f"[bold]{title.title}[/]")
    if primary is not None:
        table.add_row("cause", primary.cause.value)
        table.add_row(
            "confidence",
            f"{primary.confidence.name.lower()}"
            + (", corroborated by apt" if primary.cause in result.corroborated else ""),
        )
        if primary.cascade_size:
            table.add_row("blast radius", plural(primary.cascade_size, "package"))
        if primary.fragile:
            table.add_row("fragile", "yes -- near-tied resolver scores")
    else:
        table.add_row("cause", "[yellow]no rule matched[/]")

    table.add_row("release", run.release_pair)
    table.add_row("stopped at", run.terminal_phase.name)
    table.add_row(
        "wrote to system",
        {True: "yes", False: "no", None: "unknown"}[run.dpkg_wrote],
    )
    table.add_row("logs", ", ".join(s.value for s in run.logs_present) or "none")
    if not run.evidence_complete:
        table.add_row("evidence", "[yellow]incomplete -- some rules withheld[/]")
    if result.is_candidate_invalid:
        table.add_row("third party", "[yellow]candidate Invalid[/]")
    return table


def _print_run(
    run: UpgradeRun,
    result: DiagnosisResult,
    title: ProposedTitle,
) -> None:
    """Render one run's verdict to the terminal.

    Coverage is read off ``run.lex`` rather than passed in. It used to be a
    separate optional argument, which meant every call site could forget it --
    and ``fetch`` did, so the one command that meets a new apt version first
    was also the one that could not say whether it had understood the log.
    """
    # The heading is kept short because Rich truncates a rule's title to the
    # terminal width, silently and from the right. With the attempt number
    # appended, a long temporary path pushed it off the end -- so the one thing
    # distinguishing two reports of the same directory was the thing that
    # disappeared. Anything load-bearing goes in the table, which wraps.
    if run.bug_id:
        heading = f"LP#{run.bug_id}"
    elif run.source_dir:
        heading = Path(run.source_dir).name or run.source_dir
    else:
        heading = "run"
    out.print()
    out.rule(f"[bold]{heading}[/]")
    if run.attempt:
        out.print(f"[yellow]archived attempt {run.attempt}[/] -- not the most recent run")
    if run.source_dir and not run.bug_id and run.source_dir != heading:
        out.print(f"[dim]{run.source_dir}[/]")
    out.print(_verdict_table(run, result, title))
    if run.lex.lines:
        style = "green" if run.lex.perfect else "yellow"
        out.print(
            f"[{style}]lexer coverage {run.lex.coverage:.4%}"
            f"  ({run.lex.unmatched:,} of {run.lex.lines:,} lines unrecognised)[/]"
        )
        # The masked shapes, not the raw lines: ten thousand variants of one
        # unrecognised form are one grammar gap, and printing them raw buries
        # that under its own volume.
        for template, count in run.lex.unknown_shapes[:_UNKNOWN_SHAPES_SHOWN]:
            out.print(f"  [yellow]unrecognised[/] {count:>5,}x  [dim]{template}[/]")
        remaining = len(run.lex.unknown_shapes) - _UNKNOWN_SHAPES_SHOWN
        if remaining > 0:
            out.print(f"  [dim]... and {plural(remaining, 'further shape')}[/]")
    for note in result.notes:
        out.print(f"[dim]note: {note}[/]")


#: Version of the ``--json`` record shape.
#:
#: Bumped when a key is removed or its meaning changes; adding a key does not
#: bump it. Present so that a consumer can refuse a record it does not
#: understand instead of silently reading a renamed field as absent -- which is
#: the same failure that ``extra="forbid"`` prevents on the way in.
JSON_SCHEMA_VERSION: Final = 1


def _json_record(
    run: UpgradeRun,
    result: DiagnosisResult,
    title: ProposedTitle,
    signature: Signature,
    interner: Interner,
) -> dict[str, object]:
    """A machine-readable triage record.

    Deliberately not ``UpgradeRun.model_dump()``: that carries packed byte
    arrays and interned integers, which are meaningless without the store that
    produced them. This is the subset that survives being written to a file and
    read somewhere else.

    Lexer coverage is in here because it is the tool's own statement about how
    much of the evidence it could read, and a consumer that cannot see it
    cannot apply the first gate of the triage procedure -- coverage at exactly
    100%. It was missing while the terminal output had it, so a human reading
    the report could tell a partial parse from a complete one and a script
    could not. ``tests/test_cli.py`` pins the key set for the same reason.
    """
    primary = result.primary
    return {
        "schema": JSON_SCHEMA_VERSION,
        "key": _key_for(run),
        "bug_id": run.bug_id,
        "attempt": run.attempt,
        "from_series": run.from_series,
        "to_series": run.to_series,
        "title": title.title,
        "title_confident": title.confident,
        "cause": primary.cause.value if primary else None,
        "severity": primary.severity.name.lower() if primary else None,
        "confidence": primary.confidence.name.lower() if primary else None,
        "root_packages": list(interner.package_names(primary.root_pkgs)) if primary else [],
        "cascade_size": primary.cascade_size if primary else 0,
        "fragile": bool(primary and primary.fragile),
        "candidate_invalid": result.is_candidate_invalid,
        "corroborated": sorted(c.value for c in result.corroborated),
        "terminal_phase": run.terminal_phase.name,
        "evidence_complete": run.evidence_complete,
        "dpkg_wrote": run.dpkg_wrote,
        "upgrade_completed": result.upgrade_completed,
        "logs_present": [s.value for s in run.logs_present],
        # Both broken counts, named. They differ by an order of magnitude and
        # a consumer that sees one unlabelled "broken" will misreport it.
        "apt_broken_count": run.apt_broken_count,
        "observed_broken_count": run.counts.broken,
        "rules_fired": list(result.fired),
        "rules_withheld": list(result.skipped_incomplete),
        "notes": list(result.notes),
        # How much of the resolver trace was actually read. ``lex_lines == 0``
        # means there was no trace to read -- an absent apt.log is not a
        # grammar gap -- which is why the raw line count is exposed next to
        # the ratio rather than only the ratio.
        "lex_lines": run.lex.lines,
        "lex_unmatched": run.lex.unmatched,
        "lex_coverage": run.lex.coverage,
        "unknown_shapes": [
            {"template": template, "count": count} for template, count in run.lex.unknown_shapes
        ],
        # Which policy produced the verdict above. A cluster whose members
        # disagree on these was diagnosed by two different tools.
        "tool_version": run.tool_version,
        "rules_digest": run.rules_digest,
        # Launchpad's own account of the bug, when it came from there. Never
        # an input to any of the above.
        "reported_at": run.reported_at.isoformat() if run.reported_at else None,
        "duplicate_of": run.duplicate_of,
        "duplicate_count": run.duplicate_count,
        "signature": {
            "root_graph": signature.root_graph.hex() if signature.root_graph else None,
            "cause_tuple": signature.cause_tuple.hex() if signature.cause_tuple else None,
        },
    }


def _write(text: str, destination: Path | None, *, label: str) -> None:
    if destination is None:
        out.file.write(text)
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")
    err.print(f"[green]wrote[/] {label} to {destination}")


def _imperfect(runs: Iterable[UpgradeRun]) -> list[str]:
    """Describe every run whose resolver trace did not fully lex.

    Shared by ``diagnose``, ``fetch`` and ``ingest`` so that the three agree on
    what "imperfect" means. They did not previously agree, because only
    ``diagnose`` could measure it at all.
    """
    lines: list[str] = []
    for run in runs:
        if run.lex.perfect:
            continue
        where = f"LP#{run.bug_id}" if run.bug_id else f"attempt {run.attempt}"
        lines.append(
            f"{where}: {run.lex.unmatched:,} of {run.lex.lines:,} lines unrecognised "
            f"({run.lex.coverage:.4%} coverage)"
        )
    return lines


def _finish_strict(imperfect: Sequence[str], *, strict: bool) -> None:
    """Exit :data:`EXIT_IMPERFECT` when ``--strict`` saw a gap.

    Always raises :class:`typer.Exit` under ``--strict`` with findings, so it
    must be the last thing a command does.
    """
    if not (strict and imperfect):
        return
    for line in imperfect:
        err.print(f"[yellow]imperfect parse:[/] {line}")
    err.print(
        "[dim]The diagnosis above may still be correct; --strict reports "
        "that the grammar has a gap.[/]"
    )
    raise typer.Exit(EXIT_IMPERFECT)


def _policy_drift(
    clusters: Iterable[Cluster],
    policies: Mapping[str, tuple[str, str]],
) -> set[str]:
    """Representatives of clusters whose members were diagnosed differently.

    A cluster that changes tier between two corpus passes has two possible
    explanations -- the logs describe different faults, or the tool changed
    underneath -- and until runs carried a policy stamp those were
    indistinguishable. A mixed cluster is not wrong, but its tier was computed
    from signatures that two different rule sets produced, so it is not
    evidence of anything until the corpus is re-ingested.

    Runs with no stamp at all are ignored rather than treated as a distinct
    policy: they were stored before stamping existed, and reporting drift on
    every pre-existing cluster would make the warning noise on first upgrade.
    """
    drifted: set[str] = set()
    for cluster in clusters:
        seen = {
            policies[member]
            for member in cluster.members
            if policies.get(member, ("", "")) != ("", "")
        }
        if len(seen) > 1:
            drifted.add(cluster.representative)
    return drifted


class CorpusCoverage(TypedDict):
    """Aggregate lexer coverage over a whole store.

    A ``TypedDict`` rather than a loose ``dict[str, object]`` so that the
    terminal renderer cannot format a count as a string or a ratio as a count
    without mypy objecting. The JSON encoder accepts it unchanged.
    """

    runs_with_trace: int
    runs_imperfect: int
    lines: int
    unmatched: int
    coverage: float
    unknown_shapes: list[dict[str, object]]


def _run_from_bug(
    attachments: dict[LogSource, str],
    record: BugRecord,
    interner: Interner,
    config: Config,
    *,
    bug_id: int,
    status: str,
) -> UpgradeRun:
    """Build a run from a fetched bug, carrying its Launchpad metadata.

    Shared by ``fetch`` and ``sweep`` so the two cannot disagree about which
    fields reach the record. They would: ``duplicate_count`` and ``reported_at``
    were already fetched and silently dropped once, and a second copy of this
    block is how a third field goes the same way.

    Every Launchpad field set here is prior triage or prose, and none of it
    reaches a diagnosis or a signature --
    :data:`~uru_doctor.dedup.EXCLUDED_FROM_SIGNATURES` enforces that, and
    ``tests/test_dedup.py`` asserts it.
    """
    meta = parse_apport_meta(record.description, tags=record.tags)
    ingested = ingest_attachments(attachments, interner, meta=meta, bug_id=bug_id)
    return ingested.only().model_copy(
        update={
            "current_title": record.title,
            "tags": record.tags,
            "duplicate_of": record.duplicate_of,
            "duplicate_count": record.duplicate_count,
            "reported_at": record.created,
            # ``sweep`` knows this from the search response; ``fetch`` does
            # not, and an empty string means "not known" rather than "not set".
            "bug_status": status or record.status,
        }
    )


def _resolve_key(store: Store, key: str) -> str:
    """Turn a user-supplied key or bug number into one stored run key.

    A bare bug number is accepted because that is how a triager refers to a
    bug, but it can name several runs -- a bug with archived earlier attempts
    has one per attempt. The primary run is chosen, and the ambiguity is
    reported rather than resolved silently: an archived attempt is a *different
    upgrade*, and answering a question about the wrong one looks exactly like
    answering it about the right one.

    Fails with the known keys when nothing matches, because the keys are not
    guessable -- a locally ingested directory has no bug number at all.
    """
    if store.has_run(key):
        return key
    if key.isdigit():
        candidates = store.get_runs_for_bug(int(key))
        primary = [r for r in candidates if r.is_primary] or candidates
        if primary:
            chosen = run_key_for(primary[0].bug_id, primary[0].attempt, primary[0].source_dir)
            if len(candidates) > 1:
                err.print(
                    f"[dim]LP#{key} has {plural(len(candidates), 'stored run')}; "
                    f"using {chosen}[/]"
                )
            return chosen
    known = store.run_keys(primary_only=True)[:10]
    hint = ("\nknown keys: " + ", ".join(known)) if known else ""
    _fail(f"no stored run matches {key!r}{hint}")
    raise AssertionError("unreachable")


def _corpus_coverage(store: Store, tracker: Tracker | None = None) -> CorpusCoverage:
    """Aggregate lexer coverage across every stored run.

    A grammar gap in one of forty stored runs is invisible in that run's own
    report once it has scrolled past, and the corpus is where an unseen shape
    turns up first -- so the aggregate belongs in ``stats``.

    The totals come from an indexed query; the unrecognised shapes need the
    payloads, so they are only gathered when something actually failed to lex.
    On a healthy corpus this costs one aggregate row -- which is why the
    optional tracker only starts counting inside that branch.
    """
    traces, imperfect, lines, unmatched = store.coverage_totals()
    shapes: dict[str, int] = {}
    if imperfect:
        if tracker is not None:
            total = len(store.run_keys(primary_only=False))
            tracker.start(f"scanning {plural(total, 'run')} for unread shapes", total=total)
        for run in store.iter_runs(primary_only=False):
            for template, count in run.lex.unknown_shapes:
                shapes[template] = shapes.get(template, 0) + count
            if tracker is not None:
                tracker.advance()
    return CorpusCoverage(
        runs_with_trace=traces,
        runs_imperfect=imperfect,
        lines=lines,
        unmatched=unmatched,
        coverage=((lines - unmatched) / lines) if lines else 1.0,
        # Sorted by count then text: dict order here follows first-seen order,
        # which depends on ingest order, and ordering output by that is the
        # mistake this codebase has already made four times.
        unknown_shapes=[
            {"template": template, "count": count}
            for template, count in sorted(shapes.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
    )


# -- commands ----------------------------------------------------------------

ConfigOption = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="Path to uru-doctor.toml. Default: search upward."),
]
OutOption = Annotated[
    Path | None,
    typer.Option("--out", "-o", help="Write to this file instead of stdout."),
]


@app.command("diagnose")
def diagnose_cmd(
    path: Annotated[
        Path,
        typer.Argument(
            metavar="DIRECTORY",
            help="A dist-upgrade log directory, e.g. /var/log/dist-upgrade.",
        ),
    ],
    markdown: Annotated[
        bool, typer.Option("--markdown", "-m", help="Emit the full Markdown report.")
    ] = False,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit a machine-readable record.")
    ] = False,
    strict: Annotated[
        bool,
        typer.Option("--strict", help=f"Exit {EXIT_IMPERFECT} if any log parsed imperfectly."),
    ] = False,
    all_attempts: Annotated[
        bool,
        typer.Option("--all-attempts", help="Also report archived earlier attempts."),
    ] = False,
    out_path: OutOption = None,
    config_path: ConfigOption = None,
) -> None:
    """Diagnose an upgrade failure from its logs.

    Reads the directory, leaves nothing behind, and says what stopped the
    upgrade and which package to blame. Use --markdown for a page suitable for
    pasting into a bug report.
    """
    if markdown and as_json:
        _fail("choose one of --markdown or --json", EXIT_USAGE)
    config = _config(config_path)

    with _scratch_store() as store:
        interner = Interner(store)
        # The lexing happens inside _ingest, before anything is printed, and a
        # 30,000-line resolver trace is seconds rather than milliseconds. The
        # loop below is comparatively instant, so the spinner belongs here.
        document = markdown or as_json
        with _progress(console=err if document else out) as tracker:
            tracker.start(f"reading {Path(path).name or path}", total=None)
            result = _ingest(path, interner, config)
        runs = result.runs if all_attempts else [r for r in result.runs if r.is_primary]
        store.commit()

        documents: list[str] = []
        records: list[dict[str, object]] = []
        diagnosed: list[UpgradeRun] = []

        for run in runs:
            stamped, diagnosis, title, signature = _diagnose_run(run, interner, config)
            diagnosed.append(stamped)

            if markdown:
                documents.append(
                    render_run(
                        stamped,
                        diagnosis,
                        interner,
                        config=config.report,
                        title=title,
                        key=_key_for(stamped),
                    )
                )
            elif as_json:
                records.append(_json_record(stamped, diagnosis, title, signature, interner))
            else:
                _print_run(stamped, diagnosis, title)

        for skipped in result.skipped:
            err.print(f"[dim]skipped {skipped}[/]")

        if markdown:
            _write("\n\n".join(documents), out_path, label="report")
        elif as_json:
            payload = records[0] if len(records) == 1 else records
            _write(json.dumps(payload, indent=2) + "\n", out_path, label="record")

    _finish_strict(_imperfect(diagnosed), strict=strict)


@app.command()
def title(
    path: Annotated[Path, typer.Argument(metavar="DIRECTORY")],
    config_path: ConfigOption = None,
) -> None:
    """Print just the proposed bug title.

    One line on stdout and nothing else, so it can be piped.
    """
    config = _config(config_path)
    with _scratch_store() as store:
        interner = Interner(store)
        result = _ingest(path, interner, config)
        run = result.primary or result.runs[0]
        _, _, proposed, _ = _diagnose_run(run, interner, config)
        store.commit()
    print(proposed.title)
    if not proposed.confident:
        err.print("[yellow]low confidence: the logs do not clearly name a cause[/]")


@app.command()
def ingest(
    paths: Annotated[
        list[Path],
        typer.Argument(metavar="DIRECTORY...", help="One or more dist-upgrade directories."),
    ],
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit a machine-readable record per stored run.")
    ] = False,
    strict: Annotated[
        bool,
        typer.Option("--strict", help=f"Exit {EXIT_IMPERFECT} if any log parsed imperfectly."),
    ] = False,
    out_path: OutOption = None,
    config_path: ConfigOption = None,
) -> None:
    """Add upgrade logs to the record store, for corpus-wide work.

    Unlike diagnose, this persists: the store accumulates the template and
    package vocabulary that duplicate detection needs, and holds the diagnosed
    runs that dedup and show read back.
    """
    config = _config(config_path)
    with _state_store(config) as store:
        interner = Interner(store)
        records: list[dict[str, object]] = []
        diagnosed: list[UpgradeRun] = []
        # Nothing prints to stdout per directory, so the bar can live there in
        # human mode and must not under --json.
        with _progress(console=err if as_json else out) as tracker:
            tracker.start(f"ingesting {plural(len(paths), 'directory', 'directories')}",
                          total=len(paths))
            for path in paths:
                # Lexing is the slow part -- 30,000 lines of resolver trace per
                # bug is seconds, not milliseconds -- and a corpus pass over
                # forty directories was silent until it finished.
                tracker.note(Path(path).name or str(path))
                result = _ingest(path, interner, config)
                for run in result.runs:
                    stamped, diagnosis, proposed, signature = _diagnose_run(
                        run, interner, config
                    )
                    store.put_run(stamped.with_findings(diagnosis.findings, signature))
                    diagnosed.append(stamped)
                    if as_json:
                        records.append(
                            _json_record(stamped, diagnosis, proposed, signature, interner)
                        )
                for skipped in result.skipped:
                    err.print(f"[dim]skipped {skipped}[/]")
                tracker.advance()
        store.commit()
        totals = store.stats()

    imperfect = _imperfect(diagnosed)
    if as_json:
        _write(json.dumps(records, indent=2) + "\n", out_path, label="records")
    else:
        held = f"store now holds {plural(totals['runs'], 'run')}"
        if totals["bugs"]:
            held += f" across {plural(totals['bugs'], 'bug')}"
        out.print(f"[green]stored {plural(len(diagnosed), 'run')}[/]; {held}")
        out.print(f"[dim]{config.paths.state_dir}[/]")
        # A corpus pass is the usual way a grammar gap first shows up, and the
        # whole point of ingesting many logs is to meet shapes one directory
        # does not contain. Reporting it without --strict means it is visible
        # even when nothing is checking the exit code -- but not under
        # --strict as well, which would say the same thing twice.
        if not strict:
            for line in imperfect:
                err.print(f"[yellow]imperfect parse:[/] {line}")

    _finish_strict(imperfect, strict=strict)


@app.command()
def fetch(
    bugs: Annotated[
        list[int],
        typer.Argument(metavar="BUG_ID...", help="Launchpad bug numbers."),
    ],
    save: Annotated[
        bool, typer.Option("--save/--no-save", help="Add the runs to the record store.")
    ] = True,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit a machine-readable record per bug.")
    ] = False,
    strict: Annotated[
        bool,
        typer.Option("--strict", help=f"Exit {EXIT_IMPERFECT} if any log parsed imperfectly."),
    ] = False,
    out_path: OutOption = None,
    config_path: ConfigOption = None,
) -> None:
    """Fetch bugs from Launchpad and diagnose them.

    Anonymous and read-only: this cannot write to Launchpad, and no
    credentials are ever used. Proposed titles and duplicate groupings are for
    a human to apply.

    Launchpad answers 429 readily and takes about a minute to forgive one, so
    requests are spaced rather than parallelised and ETags are cached. A bug
    with four logs costs six requests; expect a few seconds each.

    This is where a new apt version is met first, so it reports lexer coverage
    and honours --strict: a bug whose resolver trace did not fully lex has been
    diagnosed from partial evidence, and that is worth hearing about before the
    verdict is believed.
    """
    config = _config(config_path)
    store_ctx = _state_store(config) if save else _scratch_store()
    with store_ctx as store:
        interner = Interner(store)
        cache = config.paths.state_dir / "attachments" if save else None
        records: list[dict[str, object]] = []
        diagnosed: list[UpgradeRun] = []
        with (
            _progress(console=err if as_json else out) as tracker,
            Launchpad(
                config=config.launchpad,
                store=store,
                cache_dir=cache,
                progress=tracker.callback,
            ) as client,
        ):
            tracker.start(f"fetching {plural(len(bugs), 'bug')}", total=len(bugs))
            for bug_id in bugs:
                tracker.context(f"LP#{bug_id}")
                try:
                    attachments, record = client.logs(bug_id)
                except RateLimited as exc:
                    # Stop rather than march through the rest collecting the
                    # same refusal.
                    _fail(f"{exc}\nWait a minute and retry.")
                except LaunchpadError as exc:
                    err.print(f"[yellow]skipped LP#{bug_id}:[/] {exc}")
                    tracker.advance()
                    continue

                run = _run_from_bug(
                    attachments, record, interner, config, bug_id=bug_id, status=""
                )
                stamped, diagnosis, proposed, signature = _diagnose_run(run, interner, config)
                if save:
                    store.put_run(stamped.with_findings(diagnosis.findings, signature))
                if not attachments:
                    err.print(f"[yellow]LP#{bug_id} has no usable logs attached[/]")
                diagnosed.append(stamped)
                if as_json:
                    records.append(
                        _json_record(stamped, diagnosis, proposed, signature, interner)
                    )
                else:
                    _print_run(stamped, diagnosis, proposed)
                tracker.advance()
        store.commit()

    # Individual failures are warnings, because one unreachable bug should not
    # abandon a corpus fetch. Every bug failing is a different situation: the
    # command did nothing, and a script needs to hear about it.
    if not diagnosed:
        _fail(f"fetched none of the {plural(len(bugs), 'bug')} requested")

    if as_json:
        _write(json.dumps(records, indent=2) + "\n", out_path, label="records")

    _finish_strict(_imperfect(diagnosed), strict=strict)


@app.command()
def dedup(
    out_path: OutOption = None,
    markdown: Annotated[
        bool, typer.Option("--markdown", "-m", help="Emit the Markdown digest.")
    ] = False,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable clusters.")
    ] = False,
    config_path: ConfigOption = None,
) -> None:
    """Group stored runs that report the same fault.

    Grouping uses log-derived structure only -- the root-cause subgraph, the
    causes, the phase -- and never titles, tags or descriptions. The tier is
    always reported, because the tiers are not equally strong: root-graph means
    an identical root-cause subgraph, while evidence-similarity is a score.
    """
    if markdown and as_json:
        _fail("choose one of --markdown or --json", EXIT_USAGE)
    config = _config(config_path)
    with _state_store(config) as store:
        interner = Interner(store)
        entries: list[RunEntry] = []
        signatures: dict[str, Signature] = {}
        document = as_json or markdown
        with _progress(console=err if document else out) as tracker:
            # Every payload is deserialised here, so this is linear in corpus
            # size and the clustering after it is worse than linear. A total is
            # available cheaply from the key list, so the bar is a real one.
            total = len(store.run_keys(primary_only=True))
            tracker.start(f"loading {plural(total, 'run')}", total=total)
            for run in store.iter_runs(primary_only=True):
                # Findings are on the stored run; re-diagnosing would be
                # wasteful and could drift from what was recorded.
                result = DiagnosisResult(findings=run.findings)
                entries.append(
                    RunEntry(
                        key=_key_for(run),
                        run=run,
                        result=result,
                        title=propose_title(
                            run, result, interner, max_length=config.title.max_length
                        ),
                    )
                )
                signatures[_key_for(run)] = run.signature
                tracker.advance()

            if not entries:
                _fail("the store is empty; run `uru-doctor ingest` first")

            # Pair scoring is quadratic in the worst case, and unlike the load
            # above it cannot be counted in advance -- the tiers short-circuit.
            tracker.start("clustering", total=None)
            clusters = cluster_runs(
                signatures,
                config=config.dedup,
                oldest_first=sorted(signatures),
            )
        store.replace_clusters(
            (
                cluster.tier,
                cluster.representative or None,
                [(member, 0, 1.0) for member in cluster.members],
            )
            for cluster in clusters
        )
        store.commit()

        policies = {
            entry.key: (entry.run.tool_version, entry.run.rules_digest) for entry in entries
        }
        drifted = _policy_drift(clusters, policies)

        if markdown:
            _write(
                render_corpus(entries, clusters, config=config.report),
                out_path,
                label="digest",
            )
            return

        if as_json:
            _write(
                json.dumps(
                    {
                        "schema": JSON_SCHEMA_VERSION,
                        "runs": len(entries),
                        "summary": summarise(clusters),
                        "clusters": [
                            {
                                # Always the tier, never a bare "duplicate"
                                # boolean: root-graph is safe to act on and
                                # evidence-similarity is a suggestion, and
                                # collapsing them discards the only thing that
                                # says how much to trust the grouping.
                                "tier": cluster.tier,
                                "representative": cluster.representative,
                                "members": list(cluster.members),
                                "duplicates": cluster.duplicates,
                                "size": cluster.size,
                                "policy_drift": cluster.representative in drifted,
                            }
                            for cluster in clusters
                        ],
                    },
                    indent=2,
                )
                + "\n",
                out_path,
                label="clusters",
            )
            return

        stats = summarise(clusters)
        out.print(
            f"{plural(len(entries), 'run')}: {plural(stats['clusters'], 'cluster')} "
            f"covering {plural(stats['duplicates'], 'candidate duplicate')}"
        )
        table = Table(box=None, pad_edge=False)
        table.add_column("tier", style="dim")
        table.add_column("master")
        table.add_column("duplicates", overflow="fold")
        labels = {entry.key: entry.label for entry in entries}
        for cluster in clusters[: config.report.max_clusters]:
            table.add_row(
                cluster.tier,
                labels.get(cluster.representative, cluster.representative),
                ", ".join(labels.get(k, k) for k in cluster.duplicates),
            )
        if clusters:
            out.print(table)
        else:
            out.print("[dim]no two runs share a structure[/]")

        for key in drifted:
            out.print(
                f"[yellow]policy drift:[/] cluster {labels.get(key, key)} mixes runs "
                "diagnosed by different rule sets -- re-ingest before trusting the tier"
            )


@app.command()
def show(
    key: Annotated[
        str,
        typer.Argument(help="Run key, e.g. lp:2150245#0, or a bare bug number."),
    ],
    markdown: Annotated[
        bool, typer.Option("--markdown", "-m", help="Emit the full Markdown report.")
    ] = True,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit the machine-readable record instead.")
    ] = False,
    out_path: OutOption = None,
    config_path: ConfigOption = None,
) -> None:
    """Show a stored run's report."""
    config = _config(config_path)
    with _state_store(config) as store:
        interner = Interner(store)
        candidates: list[UpgradeRun] = []
        if key.isdigit():
            # Every attempt, not just the primary: this command renders
            # reports, and an archived attempt's report is a thing someone
            # might legitimately want. ``related`` narrows to one instead,
            # because a question about "the same fault" has to be about one
            # upgrade.
            candidates = store.get_runs_for_bug(int(key))
        else:
            found = store.get_run(key)
            if found is not None:
                candidates = [found]
        if not candidates:
            known = store.run_keys(primary_only=True)[:10]
            hint = ("\nknown keys: " + ", ".join(known)) if known else ""
            _fail(f"no stored run matches {key!r}{hint}")

        records: list[dict[str, object]] = []
        for run in candidates:
            result = DiagnosisResult(findings=run.findings)
            proposed = propose_title(run, result, interner, max_length=config.title.max_length)
            if as_json:
                # The stored signature, not a recomputed one: this command
                # reports what was recorded, and recomputing here would hide
                # exactly the drift that the policy stamp exists to expose.
                records.append(_json_record(run, result, proposed, run.signature, interner))
            elif markdown:
                out.file.write(
                    render_run(
                        run,
                        result,
                        interner,
                        config=config.report,
                        title=proposed,
                        key=_key_for(run),
                    )
                )
            else:
                _print_run(run, result, proposed)

        if as_json:
            payload = records[0] if len(records) == 1 else records
            _write(json.dumps(payload, indent=2) + "\n", out_path, label="record")


@app.command()
def rules(
    rule_name: Annotated[
        str | None,
        typer.Option("--explain", "-e", metavar="NAME", help="Explain one rule in full."),
    ] = None,
) -> None:
    """List the diagnostic rules, or explain one.

    Every finding names the rule that produced it, so this is how to find out
    what a verdict was based on.
    """
    if rule_name is not None:
        found = explain(rule_name)
        if found is None:
            _fail(f"no such rule: {rule_name}\nRun `uru-doctor rules` for the list.")
            return
        out.print(f"[bold]{found.name}[/]")
        out.print(f"  cause       {found.cause.value}")
        out.print(f"  severity    {found.severity.name.lower()}")
        out.print(f"  confidence  {found.confidence.name.lower()}")
        if found.phase_hint:
            out.print(f"  phase       {found.phase_hint}")
        if found.provenance:
            out.print(f"  derived from\n    {found.provenance}")
        if found.remedy:
            out.print(f"  remedy\n    {found.remedy}")
        if not found.requires_complete_evidence:
            out.print("  [dim]runs even on truncated logs[/]")
        return

    table = Table(box=None, pad_edge=False)
    table.add_column("rule")
    table.add_column("cause", style="dim")
    table.add_column("needs full logs", justify="center")
    for item in all_rules():
        table.add_row(
            item.name,
            item.cause.value,
            "yes" if item.requires_complete_evidence else "[dim]no[/]",
        )
    out.print(table)
    out.print(f"[dim]{len(all_rules())} rules. `--explain NAME` for detail.[/]")


@app.command()
def stats(
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit a machine-readable summary.")
    ] = False,
    out_path: OutOption = None,
    config_path: ConfigOption = None,
) -> None:
    """Summarise the record store."""
    config = _config(config_path)
    with _state_store(config) as store:
        interner = Interner(store)
        totals = store.stats()
        causes = store.cause_histogram()
        # Labelled, not keyed: the store holds the canonical ``name:arch`` form
        # so that the two spellings of a package intern to one id, but
        # ``libpeas-1.0-1:amd64`` is not how anyone refers to it.
        blamed = [
            (interner.package_label(pkg_id), count)
            for pkg_id, _, count in store.top_blaming_packages(limit=config.report.top_packages)
        ]
        with _progress(console=err if as_json else out) as tracker:
            coverage = _corpus_coverage(store, tracker)

    if as_json:
        _write(
            json.dumps(
                {
                    "schema": JSON_SCHEMA_VERSION,
                    "state_dir": str(config.paths.state_dir),
                    "totals": {k: v for k, v in totals.items()},
                    "causes": [{"cause": c, "runs": n} for c, n in causes],
                    "most_blamed": [{"package": p, "runs": n} for p, n in blamed],
                    "coverage": coverage,
                },
                indent=2,
            )
            + "\n",
            out_path,
            label="summary",
        )
        return

    out.print(f"[bold]{config.paths.state_dir}[/]")
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="dim")
    table.add_column(justify="right")
    for name in ("runs", "bugs", "clusters", "packages", "templates", "strings"):
        table.add_row(name, f"{totals[name]:,}")
    table.add_row("size", f"{totals['db_bytes'] / 1e6:,.1f} MB")
    out.print(table)

    # Corpus-wide coverage, because a grammar gap in one of forty stored runs
    # is invisible in that run's own report once it has scrolled away.
    if coverage["runs_with_trace"]:
        imperfect_runs = coverage["runs_imperfect"]
        style = "green" if not imperfect_runs else "yellow"
        out.print(
            f"\n[{style}]lexer coverage {coverage['coverage']:.4%} over "
            f"{coverage['lines']:,} lines in {plural(coverage['runs_with_trace'], 'trace')}"
            f"; {plural(imperfect_runs, 'run')} imperfect[/]"
        )

    if causes:
        out.print("\n[bold]causes[/]")
        for cause, count in causes:
            out.print(f"  {count:>5,}  {cause}")
    if blamed:
        out.print("\n[bold]most blamed packages[/]")
        for name, count in blamed:
            out.print(f"  {count:>5,}  {name}")


@app.command()
def sweep(
    since: Annotated[
        str | None,
        typer.Option(
            "--since",
            metavar="YYYY-MM-DD",
            help="Override the stored watermark. Use --since 2026-01-01 for a first pass.",
        ),
    ] = None,
    limit: Annotated[
        int | None,
        typer.Option("--limit", "-n", help="Cap how many new bugs to fetch logs for."),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="List what would be fetched and stop. One request."),
    ] = False,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit a machine-readable record per bug.")
    ] = False,
    strict: Annotated[
        bool,
        typer.Option("--strict", help=f"Exit {EXIT_IMPERFECT} if any log parsed imperfectly."),
    ] = False,
    out_path: OutOption = None,
    config_path: ConfigOption = None,
) -> None:
    """Collect newly reported release-upgrader bugs and diagnose them.

    The entry point for triage. Without this, the bug list has to be curated by
    hand, which means the tool only ever sees bugs somebody already decided
    were interesting -- reintroducing exactly the selection bias the rest of
    the design removes.

    Read-only and anonymous, like every other Launchpad path here.

    Resumable, because it has to be: at roughly six requests per bug and three
    seconds between them, a hundred bugs is half an hour, and Launchpad answers
    429 readily. The watermark advances only over bugs actually handled and
    never moves backward, so an interrupted sweep loses nothing and the next
    run continues rather than starting over. Use --dry-run to see what a pass
    would cost before spending it.

    Closed bugs are included deliberately. Launchpad's search omits them by
    default, and a bug's own resolution is the second-strongest ground truth
    there is -- so taking the default would quietly exclude the best evidence
    for whether this tool is right.
    """
    config = _config(config_path)
    watermark: datetime | None = None
    if since is not None:
        try:
            watermark = datetime.fromisoformat(since).replace(tzinfo=UTC)
        except ValueError:
            _fail(f"--since must be an ISO date like 2026-01-01, not {since!r}", EXIT_USAGE)

    cap = limit if limit is not None else config.launchpad.sweep_max_bugs

    with _state_store(config) as store:
        interner = Interner(store)
        if watermark is None:
            watermark = store.sweep_watermark()
        known = store.known_bug_ids()
        cache = config.paths.state_dir / "attachments"

        records: list[dict[str, object]] = []
        diagnosed: list[UpgradeRun] = []
        no_logs: list[int] = []
        failed: list[str] = []
        seen = 0
        reached: datetime | None = None

        # Document to stdout under --json, so the bar goes to stderr; otherwise
        # the verdicts are the stdout output and the bar shares that console.
        with (
            _progress(console=err if as_json else out) as tracker,
            Launchpad(
                config=config.launchpad,
                store=store,
                cache_dir=cache,
                progress=tracker.callback,
            ) as client,
        ):
            # The search is itself several paced requests, so it gets a task of
            # its own with no total -- the page count is not known in advance,
            # and a bar that cannot fill is worse than a spinner.
            tracker.start("searching Launchpad", total=None)
            try:
                found = list(
                    client.search_tasks(
                        created_since=watermark,
                        page_size=config.launchpad.sweep_page_size,
                    )
                )
            except RateLimited as exc:
                _fail(f"{exc}\nWait a minute and retry; the watermark is unchanged.")
                return
            except LaunchpadError as exc:
                _fail(f"could not search Launchpad: {exc}")
                return

            fresh = [ref for ref in found if ref.bug_id not in known]
            if dry_run:
                _report_dry_run(found, fresh, watermark, cap, as_json, out_path)
                return

            planned = fresh[:cap]
            tracker.start(f"fetching {plural(len(planned), 'bug')}", total=len(planned))

            for ref in planned:
                tracker.context(f"LP#{ref.bug_id}")
                try:
                    attachments, record = client.logs(ref.bug_id)
                except RateLimited as exc:
                    # Stop, keep what is already stored, and leave the
                    # watermark where the last handled bug put it. Marching on
                    # would collect the same refusal and burn the recovery
                    # window; rewinding would strand the bugs in between.
                    err.print(f"[yellow]rate limited after {plural(seen, 'bug')}:[/] {exc}")
                    break
                except LaunchpadError as exc:
                    # A single unreachable bug must not abandon the pass, but
                    # the watermark must not move past it either -- it has not
                    # been handled, and it will not be offered again once the
                    # mark is beyond its creation date.
                    failed.append(f"LP#{ref.bug_id}: {exc}")
                    err.print(f"[yellow]skipped LP#{ref.bug_id}:[/] {exc}")
                    continue

                run = _run_from_bug(
                    attachments,
                    record,
                    interner,
                    config,
                    bug_id=ref.bug_id,
                    status=ref.status,
                )
                stamped, diagnosis, proposed, signature = _diagnose_run(run, interner, config)
                store.put_run(stamped.with_findings(diagnosis.findings, signature))
                diagnosed.append(stamped)
                seen += 1
                if not attachments:
                    # Not a failure. LP#2161332 attached two screenshots, and
                    # "no upgrade logs were attached" is the correct, useful
                    # answer -- it is also the commonest reason a report cannot
                    # be triaged, so it is counted rather than buried.
                    no_logs.append(ref.bug_id)

                # Advance only over a bug that is now stored, and only to its
                # own creation date. Anything newer has not been handled yet.
                if ref.created is not None:
                    reached = ref.created if reached is None else max(reached, ref.created)

                if as_json:
                    records.append(
                        _json_record(stamped, diagnosis, proposed, signature, interner)
                    )
                else:
                    _print_run(stamped, diagnosis, proposed)
                tracker.advance()

            if reached is not None:
                store.advance_watermark(reached)
            store.commit()

        remaining = max(0, len(fresh) - seen)

    if as_json:
        _write(
            json.dumps(
                {
                    "schema": JSON_SCHEMA_VERSION,
                    "since": watermark.isoformat() if watermark else None,
                    "tasks_found": len(found),
                    "new_bugs": len(fresh),
                    "fetched": seen,
                    "remaining": remaining,
                    "watermark": reached.isoformat() if reached else None,
                    "no_logs": no_logs,
                    "failed": failed,
                    "runs": records,
                },
                indent=2,
            )
            + "\n",
            out_path,
            label="sweep",
        )
    else:
        out.print()
        out.print(
            f"[green]swept {plural(seen, 'new bug')}[/] "
            f"of {len(fresh)} new in {plural(len(found), 'task')}"
        )
        if no_logs:
            out.print(
                f"[yellow]{plural(len(no_logs), 'bug')} with no usable logs:[/] "
                + ", ".join(f"LP#{b}" for b in no_logs)
            )
        if remaining:
            out.print(f"[dim]{remaining} still to do -- run sweep again[/]")
        if reached is not None:
            out.print(f"[dim]watermark now {reached.date().isoformat()}[/]")
        # Not under --strict as well, which would say the same thing twice.
        if not strict:
            for line in _imperfect(diagnosed):
                err.print(f"[yellow]imperfect parse:[/] {line}")

    _finish_strict(_imperfect(diagnosed), strict=strict)


def _report_dry_run(
    found: Sequence[BugRef],
    fresh: Sequence[BugRef],
    watermark: datetime | None,
    cap: int,
    as_json: bool,
    out_path: Path | None,
) -> None:
    """Say what a sweep would cost, having spent only the search requests.

    Worth its own path because the expensive part is the logs, and deciding
    whether to spend half an hour is a question the listing alone can answer.
    """
    planned = list(fresh[:cap])
    if as_json:
        _write(
            json.dumps(
                {
                    "schema": JSON_SCHEMA_VERSION,
                    "since": watermark.isoformat() if watermark else None,
                    "tasks_found": len(found),
                    "new_bugs": len(fresh),
                    "would_fetch": [
                        {
                            "bug_id": ref.bug_id,
                            "status": ref.status,
                            "created": ref.created.isoformat() if ref.created else None,
                        }
                        for ref in planned
                    ],
                },
                indent=2,
            )
            + "\n",
            out_path,
            label="plan",
        )
        return

    out.print(
        f"{plural(len(found), 'task')} since "
        f"{watermark.date().isoformat() if watermark else 'the beginning'}; "
        f"{plural(len(fresh), 'new bug')}"
    )
    if not planned:
        out.print("[dim]nothing to do[/]")
        return
    table = Table(box=None, pad_edge=False)
    table.add_column("bug")
    table.add_column("status", style="dim")
    table.add_column("reported", style="dim")
    for ref in planned:
        table.add_row(
            f"LP#{ref.bug_id}",
            ref.status,
            ref.created.date().isoformat() if ref.created else "?",
        )
    out.print(table)
    # The cost, because this is the number the decision turns on.
    out.print(
        f"[dim]~{len(planned) * 6} requests, "
        f"~{len(planned) * 6 * 3 // 60} min at the configured pacing[/]"
    )


@app.command()
def coverage(
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit a machine-readable coverage report.")
    ] = False,
    strict: Annotated[
        bool,
        typer.Option("--strict", help=f"Exit {EXIT_IMPERFECT} if the corpus has any gap."),
    ] = False,
    limit: Annotated[
        int, typer.Option("--limit", "-n", help="Unrecognised shapes to list.")
    ] = 20,
    out_path: OutOption = None,
    config_path: ConfigOption = None,
) -> None:
    """Report how much of the stored corpus the lexer actually recognised.

    The grammar-gap loop, as a command. An unrecognised line is not a visible
    error -- it is a verb the conflict graph cannot see, and the failure mode is
    a confident diagnosis of partial evidence. So the question "is anything
    going unread?" has to be cheap to ask and has to cover the whole corpus,
    because a gap in one of forty stored runs is invisible in that run's own
    report once it has scrolled past.

    The masked shapes are the output worth having: they are what a new pattern
    in apt/grammar.py gets written from. Ten thousand variants of one
    unrecognised form appear as one entry with a count.
    """
    config = _config(config_path)
    with _state_store(config) as store, _progress(console=err if as_json else out) as tracker:
        totals = _corpus_coverage(store, tracker)
        offenders = store.imperfect_runs()
        unexplained = store.unclassified_templates(limit=limit)
        unmeasured = store.unmeasured_runs()

    if as_json:
        _write(
            json.dumps(
                {
                    "schema": JSON_SCHEMA_VERSION,
                    **totals,
                    "imperfect": [
                        {"key": key, "lines": lines, "unmatched": unmatched}
                        for key, lines, unmatched in offenders
                    ],
                    # Stored before coverage was recorded. Not the same as
                    # having no trace, and not folded into the ratio: "100% of
                    # what I measured" over a mostly unmeasured corpus is the
                    # kind of true-but-useless number that gets quoted.
                    "unmeasured": unmeasured,
                    # Distinct from unknown_shapes: these lexed fine but no
                    # rule claimed them. A gap in the grammar and a gap in the
                    # rules are different repairs.
                    "unexplained_templates": [
                        {"template": pattern, "runs": n} for _, pattern, n in unexplained
                    ],
                },
                indent=2,
            )
            + "\n",
            out_path,
            label="coverage",
        )
        _finish_strict([f"{k}: {u:,} unrecognised" for k, _, u in offenders], strict=strict)
        return

    if not totals["runs_with_trace"]:
        if unmeasured:
            out.print(
                f"[yellow]{plural(len(unmeasured), 'run')} stored before coverage was "
                f"recorded[/]; re-ingest to measure"
            )
        else:
            out.print("[dim]no stored run has a resolver trace to lex[/]")
        return

    style = "green" if not totals["runs_imperfect"] else "yellow"
    out.print(
        f"[{style}]lexer coverage {totals['coverage']:.4%}[/] over "
        f"{totals['lines']:,} lines in {plural(totals['runs_with_trace'], 'trace')}"
    )
    out.print(
        f"{plural(totals['unmatched'], 'line')} unrecognised in "
        f"{plural(totals['runs_imperfect'], 'run')}"
    )

    if offenders:
        out.print("\n[bold]runs with a gap[/]  [dim](worst first)[/]")
        for key, lines, unmatched in offenders[: config.report.max_clusters]:
            out.print(f"  {unmatched:>6,} of {lines:<8,} {key}")

    if unmeasured:
        out.print(
            f"\n[yellow]{plural(len(unmeasured), 'run')} stored before coverage was "
            f"recorded[/] [dim]-- not counted above; re-ingest to measure[/]"
        )

    shapes = totals["unknown_shapes"][:limit]
    if shapes:
        out.print("\n[bold]unrecognised shapes[/]  [dim](masked; write patterns from these)[/]")
        for shape in shapes:
            out.print(f"  {shape['count']:>6,}x  [dim]{shape['template']}[/]")

    if unexplained:
        # Lexed but unexplained is a different repair from unlexed: the line
        # was understood and no rule claimed it, which is a missing rule rather
        # than a missing pattern.
        out.print("\n[bold]lexed but unexplained[/]  [dim](no rule claimed these)[/]")
        for _, pattern, count in unexplained:
            out.print(f"  {count:>6,}  [dim]{pattern}[/]")

    _finish_strict([f"{k}: {u:,} unrecognised" for k, _, u in offenders], strict=strict)


@app.command()
def related(
    key: Annotated[
        str,
        typer.Argument(help="Run key, e.g. lp:2150245#0, or a bare bug number."),
    ],
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit a machine-readable answer.")
    ] = False,
    out_path: OutOption = None,
    config_path: ConfigOption = None,
) -> None:
    """Show stored runs that report the same fault as this one.

    The triager's second question. The first is "what broke this upgrade", which
    `diagnose` answers; the second is "have we seen this before, and what
    happened to those bugs" -- and until now the data sat in an indexed table
    with no way to ask it.

    Answered in the same tiers `dedup` uses, strongest first, because they are
    not equally strong: an identical root-cause subgraph is safe to act on, the
    same causes and roots at the same phase is weaker, and a shared root
    package alone is a lead. Shared-root overlap is reported as a count rather
    than a verdict -- one root in common out of eleven is a coincidence worth a
    glance, all of them is the same fault, and the tool does not pretend to
    know where the line is.

    Matching is on log-derived structure only. Titles, tags and descriptions
    are not consulted here any more than they are in `dedup`.
    """
    config = _config(config_path)
    with _state_store(config) as store:
        run_key = _resolve_key(store, key)
        subject = store.get_run(run_key)
        if subject is None:  # pragma: no cover -- _resolve_key just found it
            _fail(f"no stored run matches {key!r}")
            return

        same_graph = store.runs_with_signature(run_key, "root_graph")
        same_tuple = [
            k for k in store.runs_with_signature(run_key, "cause_tuple") if k not in set(same_graph)
        ]
        stronger = set(same_graph) | set(same_tuple)
        shared = [
            (k, n) for k, n in store.runs_sharing_roots(run_key) if k not in stronger
        ]
        # Only what is needed to label the rows; a full payload per neighbour
        # would make this command cost the whole corpus.
        labels = {
            k: store.get_run(k) for k in [*same_graph, *same_tuple, *(k for k, _ in shared)]
        }

    def describe(neighbour_key: str) -> dict[str, object]:
        neighbour = labels.get(neighbour_key)
        return {
            "key": neighbour_key,
            "bug_id": neighbour.bug_id if neighbour else None,
            "cause": (
                neighbour.top_finding.cause.value
                if neighbour and neighbour.top_finding
                else None
            ),
            # Launchpad's own verdict, when known. Free ground truth -- and the
            # reason this command is worth having: "these three are the same
            # fault and one of them is already closed Invalid" is a decision.
            "duplicate_of": neighbour.duplicate_of if neighbour else None,
            "duplicate_count": neighbour.duplicate_count if neighbour else 0,
        }

    if as_json:
        _write(
            json.dumps(
                {
                    "schema": JSON_SCHEMA_VERSION,
                    "key": run_key,
                    "cause": (
                        subject.top_finding.cause.value if subject.top_finding else None
                    ),
                    "tiers": {
                        Tier.ROOT_GRAPH: [describe(k) for k in same_graph],
                        Tier.CAUSE_TUPLE: [describe(k) for k in same_tuple],
                    },
                    "shared_roots": [
                        {**describe(k), "shared_roots": n} for k, n in shared
                    ],
                },
                indent=2,
            )
            + "\n",
            out_path,
            label="related runs",
        )
        return

    out.print()
    out.rule(f"[bold]related to {run_key}[/]")
    if subject.top_finding is not None:
        out.print(f"[dim]cause[/] {subject.top_finding.cause.value}")

    def tier_table(entries: Sequence[tuple[str, str]]) -> Table:
        table = Table(box=None, pad_edge=False, show_header=False)
        table.add_column(style="dim", no_wrap=True)
        table.add_column(overflow="fold")
        table.add_column(style="dim", overflow="fold")
        for neighbour_key, note in entries:
            neighbour = labels.get(neighbour_key)
            verdict = ""
            if neighbour is not None and neighbour.duplicate_of:
                verdict = f"already a duplicate of LP#{neighbour.duplicate_of}"
            elif neighbour is not None and neighbour.duplicate_count:
                verdict = f"{plural(neighbour.duplicate_count, 'duplicate')} already linked"
            table.add_row(note, neighbour_key, verdict)
        return table

    if same_graph:
        out.print("\n[bold]root-graph[/]  [dim]identical root-cause subgraph; safe to act on[/]")
        out.print(tier_table([(k, "same subgraph") for k in same_graph]))
    if same_tuple:
        out.print("\n[bold]cause-tuple[/]  [dim]same causes and roots, same phase[/]")
        out.print(tier_table([(k, "same cause tuple") for k in same_tuple]))
    if shared:
        out.print("\n[bold]shared roots[/]  [dim]a lead, not a verdict[/]")
        out.print(
            tier_table(
                [
                    (k, f"{plural(n, 'root')} in common")
                    for k, n in shared[: config.report.max_clusters]
                ]
            )
        )

    if not (same_graph or same_tuple or shared):
        out.print("\n[dim]no stored run shares a root package with this one[/]")


@app.command()
def history(
    package: Annotated[
        str,
        typer.Argument(help="Package name, with or without :arch."),
    ],
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit a machine-readable answer.")
    ] = False,
    out_path: OutOption = None,
    config_path: ConfigOption = None,
) -> None:
    """Show which stored runs implicate a package, and in what capacity.

    "Is this a recurring transition or a one-off?" -- asked every time a
    package turns up as a root, and answerable only against a corpus.

    Root and victim are reported separately and never summed. They are
    opposite findings: the whole premise of this tool is that the packages a
    reporter blames are usually the victims rather than the cause, so a
    package that is a victim thirty times and a root never is evidence *for*
    its innocence, and a single number would erase exactly that.

    A bare name matches every architecture, because the upgrader's `Foreign`
    list omits `:arch` for the native one while the resolver trace writes it
    in full. Pass an explicit architecture to narrow.
    """
    config = _config(config_path)
    with _state_store(config) as store:
        spellings = store.packages_matching(package)
        if not spellings:
            _fail(
                f"no stored run mentions {package!r}\n"
                "Package names come from the logs; try `uru-doctor stats` for the "
                "ones the corpus knows."
            )
            return
        pkg_ids = [pkg_id for pkg_id, _ in spellings]
        by_role: dict[str, list[str]] = {}
        for run_key, role in store.runs_with_package(pkg_ids):
            by_role.setdefault(role, []).append(run_key)
        details = {
            k: store.get_run(k) for k in {k for keys in by_role.values() for k in keys}
        }

    def describe(run_key: str) -> dict[str, object]:
        found = details.get(run_key)
        return {
            "key": run_key,
            "bug_id": found.bug_id if found else None,
            "cause": found.top_finding.cause.value if found and found.top_finding else None,
            "release": found.release_pair if found else "",
            "duplicate_of": found.duplicate_of if found else None,
        }

    if as_json:
        _write(
            json.dumps(
                {
                    "schema": JSON_SCHEMA_VERSION,
                    "package": package,
                    "spellings": [name for _, name in spellings],
                    # Roles kept apart on purpose; see the docstring.
                    "roles": {
                        role: [describe(k) for k in sorted(keys)]
                        for role, keys in sorted(by_role.items())
                    },
                },
                indent=2,
            )
            + "\n",
            out_path,
            label="history",
        )
        return

    out.print()
    out.rule(f"[bold]{package}[/]")
    if len(spellings) > 1 or spellings[0][1] != package:
        out.print(f"[dim]interned as[/] {', '.join(name for _, name in spellings)}")
    if not by_role:
        out.print("[dim]known to the corpus, but no run implicates it[/]")
        return

    # Root first: it is the only role that answers "is this the cause?".
    for role in ("root", "victim", "failed", "held_back"):
        keys = by_role.get(role)
        if not keys:
            continue
        out.print(f"\n[bold]{role}[/] in {plural(len(keys), 'run')}")
        table = Table(box=None, pad_edge=False, show_header=False)
        table.add_column(overflow="fold")
        table.add_column(style="dim", no_wrap=True)
        table.add_column(no_wrap=True)
        for run_key in sorted(keys)[: config.report.max_clusters]:
            found = details.get(run_key)
            table.add_row(
                run_key,
                found.release_pair if found else "",
                found.top_finding.cause.value if found and found.top_finding else "-",
            )
        out.print(table)

    if "root" not in by_role and "victim" in by_role:
        # Worth saying out loud, because it is the inversion the tool exists
        # to correct and a reader scanning a list will not notice an absence.
        out.print(
            "\n[dim]never a root in this corpus -- implicated only as a victim, "
            "which is evidence against blaming it[/]"
        )


@app.callback(invoke_without_command=True)
def main(
    version: Annotated[bool, typer.Option("--version", help="Show the version and exit.")] = False,
) -> None:
    if version:
        out.print(f"uru-doctor {__version__}")
        raise typer.Exit(EXIT_OK)


def run(argv: Sequence[str] | None = None) -> int:
    """Entry point that returns an exit code instead of raising.

    Useful in tests, and makes ``python -m uru_doctor`` behave.
    """
    try:
        app(args=list(argv) if argv is not None else None, standalone_mode=False)
    except typer.Exit as exit_:
        return int(exit_.exit_code)
    except typer.BadParameter as bad:
        err.print(f"[bold red]usage:[/] {bad}")
        return EXIT_USAGE
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(run())
