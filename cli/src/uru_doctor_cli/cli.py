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
from uru_doctor import __version__ as LIBRARY_VERSION
from uru_doctor.dedup import Cluster, Tier, build_signature, cluster_runs, summarise, tier_index
from uru_doctor.diagnose import DiagnosisResult, diagnose, explain
from uru_doctor.ingest import IngestResult, ingest_attachments, ingest_directory
from uru_doctor.intern import Interner
from uru_doctor.models import LogSource, Signature, UpgradeRun
from uru_doctor.parsers.apportmeta import parse_apport_meta
from uru_doctor.report import RunEntry, plural, render_corpus, render_run, render_worklist
from uru_doctor.rules.registry import all_rules, rules_digest
from uru_doctor.store import BugState, Store, run_key_for
from uru_doctor.title import ProposedTitle, propose_title
from uru_doctor.worklist import BUCKET_HELP, Bucket, Item, Worklist, classify
from uru_doctor.worklist import todo as pick_todo
from uru_doctor_cli import __version__ as CLI_VERSION
from uru_doctor_cli.config import CliConfig as Config
from uru_doctor_cli.config import load_cli_config as load_config
from uru_doctor_cli.lp import BugRecord, BugRef, Launchpad, LaunchpadError, RateLimited

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
    epilog=(
        "Exit status: 0 success, 1 error, 2 bad usage, 3 imperfect parse under --strict.\n\n"
        "Launchpad access is anonymous and read-only."
    ),
    context_settings={"help_option_names": ["-h", "--help"]},
    no_args_is_help=True,
    add_completion=True,
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
        """A ``progress`` callable for :class:`~uru_doctor_cli.lp.Launchpad`."""
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
    # The library version is stamped, not the CLI's: the record is a library
    # artifact, and the check is "was this produced by this analysis code".
    stamped = run.model_copy(
        update={"tool_version": LIBRARY_VERSION, "rules_digest": rules_digest()}
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


def _warn_recomputed_policy(run: UpgradeRun) -> None:
    """Warn when a re-rendered verdict is not the one that was recorded.

    ``show`` reconstructs the verdict and the title from the stored log record
    rather than reading them back, because neither is persisted. So what it
    prints is *today's* reading of an old record. Usually that is the same
    reading. When the rules or the apt grammar have moved since, it
    legitimately is not -- and a reader who is holding this output next to the
    sweep it came from, wondering why the cause changed, is owed the answer
    rather than left to find it.

    Runs carrying no stamp predate stamping. Warning on those would fire on
    every pre-existing record and so teach the reader to ignore the warning,
    which is the same reason :func:`_policy_drift` passes over them.
    """
    if not run.rules_digest:
        return
    current = rules_digest()
    if run.rules_digest == current:
        return
    # stderr, so that --out and a pipe both still get a clean report.
    err.print(
        f"[yellow]policy drift:[/] stored verdict came from "
        f"{run.tool_version or 'an unrecorded version'} with rules "
        f"{run.rules_digest}; the verdict below was recomputed with "
        f"{LIBRARY_VERSION} and rules {current}."
    )
    err.print("[dim]Re-fetch or re-ingest this run to store the current verdict.[/]")


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
    typer.Option(
        "--config", "-c", metavar="FILE", help="Path to uru-doctor.toml. Default: search upward."
    ),
]
OutOption = Annotated[
    Path | None,
    typer.Option("--out", "-o", metavar="FILE", help="Write to this file instead of stdout."),
]


@app.command("diagnose", rich_help_panel="Inspect one upgrade")
def diagnose_cmd(
    path: Annotated[
        Path,
        typer.Argument(
            metavar="DIR",
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

    Reads DIR, leaves nothing behind, and says what stopped the upgrade and
    which package to blame. --markdown gives a page suitable for pasting
    into a bug report.

    \b
    Examples:
      uru-doctor diagnose /var/log/dist-upgrade
      uru-doctor diagnose --markdown -o report.md /var/log/dist-upgrade
      uru-doctor diagnose --json .
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


@app.command(rich_help_panel="Inspect one upgrade")
def title(
    path: Annotated[Path, typer.Argument(metavar="DIR")],
    config_path: ConfigOption = None,
) -> None:
    """Print just the proposed bug title.

    One line on stdout and nothing else, so it can be piped.

    \b
    Example:
      uru-doctor title /var/log/dist-upgrade
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


@app.command(rich_help_panel="Collect the corpus")
def ingest(
    paths: Annotated[
        list[Path],
        typer.Argument(metavar="DIR...", help="One or more dist-upgrade directories."),
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

    Unlike diagnose this persists: the store accumulates the vocabulary that
    duplicate detection needs, and holds the diagnosed runs that dedup and
    show read back.

    \b
    Example:
      uru-doctor ingest /var/log/dist-upgrade ./unpacked-*/
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


@app.command(rich_help_panel="Collect the corpus")
def fetch(
    bugs: Annotated[
        list[int],
        typer.Argument(metavar="BUG...", help="Launchpad bug numbers."),
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
    credentials are ever used. Requests are paced (~3s apart) and
    attachments cached; a bug costs about six requests, so expect a few
    seconds each.

    \b
    Examples:
      uru-doctor fetch 2150339 2151847
      uru-doctor fetch --no-save --json 2150339
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
                    # ``fetch`` cannot learn a status -- that lives on the
                    # bug's tasks and this path never asks for them -- but it
                    # does know the master, so recording the half it has means
                    # a later `refresh` only has to fill in the status. No row
                    # at all would make the bug indistinguishable from one
                    # nobody has ever looked at.
                    if record.duplicate_of is not None:
                        store.put_bug_states(
                            [
                                BugState(
                                    bug_id=bug_id,
                                    duplicate_of=record.duplicate_of,
                                    is_duplicate=True,
                                    checked_at=datetime.now(UTC).isoformat(),
                                )
                            ]
                        )
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


@app.command(rich_help_panel="Examine the corpus")
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

    Grouping uses log-derived structure only -- never titles, tags or
    descriptions -- and always reports the tier: root-graph is an identical
    root-cause subgraph and safe to act on; evidence-similarity is a score.

    \b
    Example:
      uru-doctor dedup
    """
    if markdown and as_json:
        _fail("choose one of --markdown or --json", EXIT_USAGE)
    config = _config(config_path)
    with _state_store(config) as store:
        entries: list[RunEntry] = []
        document = as_json or markdown
        with _progress(console=err if document else out) as tracker:
            # Signatures, labels and policy stamps are all indexed columns, so
            # the common path costs two narrow scans. Only the Markdown digest
            # needs the records themselves, and it is the only path that pays
            # for them.
            tracker.start("reading signatures", total=None)
            signatures = store.signature_rows(primary_only=True)
            if not signatures:
                _fail("the store is empty; run `uru-doctor ingest` first")
            facts = store.cluster_facts(primary_only=True)

            if markdown:
                interner = Interner(store)
                total = len(signatures)
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
                    tracker.advance()

            # Grouping is a hash bucket per signature column, so it is linear;
            # the quadratic part is tier-2 scoring, which happens per bucket
            # elsewhere and not here. The count is not knowable in advance
            # because the tiers short-circuit.
            tracker.start("clustering", total=None)
            clusters = cluster_runs(
                signatures,
                config=config.dedup,
                oldest_first=sorted(signatures),
            )
        store.replace_clusters(
            (
                cluster.representative,
                facts[cluster.representative].cause
                if cluster.representative in facts
                else None,
                [(member, tier_index(cluster.tier), 1.0) for member in cluster.members],
            )
            for cluster in clusters
        )
        store.commit()

        policies = {key: fact.policy for key, fact in facts.items()}
        drifted = _policy_drift(clusters, policies)
        labels = {key: fact.label for key, fact in facts.items()}

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
                        "runs": len(signatures),
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
            f"{plural(len(signatures), 'run')}: {plural(stats['clusters'], 'cluster')} "
            f"covering {plural(stats['duplicates'], 'candidate duplicate')}"
        )
        table = Table(box=None, pad_edge=False)
        table.add_column("tier", style="dim")
        table.add_column("master")
        table.add_column("duplicates", overflow="fold")
        labels = {key: fact.label for key, fact in facts.items()}
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


@app.command(rich_help_panel="Examine the corpus")
def related(
    key: Annotated[
        str,
        typer.Argument(metavar="KEY", help="Run key, e.g. lp:2150245#0, or a bare bug number."),
    ],
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit a machine-readable answer.")
    ] = False,
    out_path: OutOption = None,
    config_path: ConfigOption = None,
) -> None:
    """Show stored runs that report the same fault as this one.

    The triager's second question -- "have we seen this before?" -- answered
    in the same tiers dedup reports, strongest first: an identical root-cause
    subgraph is safe to act on, a shared root package alone is a lead, not a
    verdict. Matching is on log-derived structure only.

    \b
    Example:
      uru-doctor related lp:2150339#0
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


@app.command(rich_help_panel="Examine the corpus")
def history(
    package: Annotated[
        str,
        typer.Argument(metavar="PKG", help="Package name, with or without :arch."),
    ],
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit a machine-readable answer.")
    ] = False,
    out_path: OutOption = None,
    config_path: ConfigOption = None,
) -> None:
    """Show which stored runs implicate a package, and in what capacity.

    Root and victim are reported separately and never summed: a package
    implicated only as victim is evidence against blaming it, which is the
    inversion this tool exists to correct. A bare name matches every
    architecture; pass an explicit :arch to narrow.

    \b
    Example:
      uru-doctor history libpeas-1.0-1
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


@app.command(rich_help_panel="Examine the corpus")
def coverage(
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit a machine-readable coverage report.")
    ] = False,
    strict: Annotated[
        bool,
        typer.Option("--strict", help=f"Exit {EXIT_IMPERFECT} if the corpus has any gap."),
    ] = False,
    limit: Annotated[
        int, typer.Option("--limit", "-n", metavar="N", help="Unrecognised shapes to list.")
    ] = 20,
    out_path: OutOption = None,
    config_path: ConfigOption = None,
) -> None:
    """Report how much of the stored corpus the lexer actually recognised.

    Names the runs with a grammar gap and lists the masked shapes that new
    lexer patterns get written from. An unrecognised line is a silently
    dropped fact, not a visible error, so this has to be cheap to ask.

    \b
    Example:
      uru-doctor coverage --strict
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


@app.command(rich_help_panel="Examine the corpus")
def show(
    key: Annotated[
        str,
        typer.Argument(metavar="KEY", help="Run key, e.g. lp:2150245#0, or a bare bug number."),
    ],
    table: Annotated[
        bool,
        typer.Option(
            "--table",
            "-t",
            help="Emit the compact verdict table, as fetch and sweep do. The default.",
        ),
    ] = False,
    markdown: Annotated[
        bool, typer.Option("--markdown", "-m", help="Emit the full Markdown report instead.")
    ] = False,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit the machine-readable record instead.")
    ] = False,
    out_path: OutOption = None,
    config_path: ConfigOption = None,
) -> None:
    """Show a stored run's report.

    Prints the same verdict table that fetch and sweep print, so a sweep can
    be read back without going to Launchpad again. The table is recomputed
    from the stored logs, so it says so when the rules have moved since.

    \b
    Examples:
      uru-doctor show 2150245
      uru-doctor show lp:2150245#0
      uru-doctor show --markdown 2150245
      uru-doctor show --json 2150245
    """
    if table and markdown:
        # Resolving this by precedence would silently ignore whichever flag
        # lost, and the one thing the reader was explicit about is the format.
        _fail("--table and --markdown select different formats; pass one.", code=EXIT_USAGE)
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
            # Only the table mode re-diagnoses, and it has to. A
            # ``DiagnosisResult`` rebuilt from stored findings carries no
            # ``corroborated`` set and no ``notes``, because neither is
            # persisted -- and the verdict table prints both. Rebuilding would
            # therefore drop the "corroborated by apt" qualifier and every
            # withheld-rule note, so the table would differ from the sweep that
            # produced it in precisely the places a reader is checking. Rules
            # are pure over the stored record, so this re-reads nothing from
            # the network.
            #
            # The other two modes keep the stored findings deliberately:
            # ``--json`` is a report of what was recorded, and the Markdown
            # page states its own provenance in a footer.
            if as_json or markdown:
                result = DiagnosisResult(findings=run.findings)
            else:
                result = diagnose(
                    run,
                    interner,
                    enabled=config.rules.enabled,
                    disabled=config.rules.disabled,
                )
            proposed = propose_title(run, result, interner, max_length=config.title.max_length)

            if as_json:
                # The stored signature, not a recomputed one: this command
                # reports what was recorded, and recomputing here would hide
                # exactly the drift that the policy stamp exists to expose.
                # The record carries that stamp, so a consumer can detect the
                # drift itself -- which is why this mode does not warn.
                records.append(_json_record(run, result, proposed, run.signature, interner))
                continue

            # Both human formats recompute the proposed title, so both can
            # disagree with the record they are rendering.
            _warn_recomputed_policy(run)
            if markdown:
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


@app.command(rich_help_panel="Examine the corpus")
def rules(
    rule_name: Annotated[
        str | None,
        typer.Option("--explain", "-e", metavar="NAME", help="Explain one rule in full."),
    ] = None,
) -> None:
    """List the diagnostic rules, or explain one.

    Every finding names the rule that produced it, so this is how to find
    out what a verdict was based on.

    \b
    Example:
      uru-doctor rules --explain resolver.roots
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


@app.command(rich_help_panel="Examine the corpus")
def stats(
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit a machine-readable summary.")
    ] = False,
    out_path: OutOption = None,
    config_path: ConfigOption = None,
) -> None:
    """Summarise the record store.

    Includes corpus-wide lexer coverage: a grammar gap in one of forty
    stored runs is invisible in that run's own report once it has scrolled
    away.

    \b
    Example:
      uru-doctor stats
    """
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


@app.command(rich_help_panel="Collect the corpus")
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
        typer.Option("--limit", "-n", metavar="N", help="Cap how many new bugs to fetch logs for."),
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

    The entry point for triage. Resumable, because it has to be: the
    watermark advances only over bugs actually stored and never moves
    backward, so an interrupted pass loses nothing and the next one
    continues. Read-only and anonymous, like every Launchpad path here.

    \b
    Examples:
      uru-doctor sweep --dry-run   # what would this pass cost?
      uru-doctor sweep --since 2026-01-01
      uru-doctor sweep -n 20
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

            # The search already carries every bug's status, including the
            # ones already stored -- and those are exactly the bugs whose
            # status a sweep otherwise freezes forever, since it skips them.
            # Recording them here costs no requests at all.
            store.put_bug_states(
                [
                    BugState(
                        bug_id=ref.bug_id,
                        status=ref.status,
                        is_duplicate=ref.is_duplicate,
                        assignee=ref.assignee,
                        checked_at=datetime.now(UTC).isoformat(),
                    )
                    for ref in found
                    if ref.bug_id in known
                ]
            )

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
                # The worklist reads `bug_state`, not the payload, so a bug
                # swept but never recorded here would show up as "status
                # unknown" immediately after being collected with its status
                # in hand.
                store.put_bug_states(
                    [
                        BugState(
                            bug_id=ref.bug_id,
                            status=ref.status,
                            duplicate_of=record.duplicate_of,
                            is_duplicate=ref.is_duplicate,
                            assignee=ref.assignee,
                            checked_at=datetime.now(UTC).isoformat(),
                        )
                    ]
                )
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


# -- acting on the corpus ----------------------------------------------------

#: Pages one triage listing will walk, per duplicate-inclusion pass.
#:
#: The same stop as ``search_tasks``'s own default, named here because the
#: refresh estimate has to agree with it. It is a cap on a *listing*, so a
#: package with more bugs than ``40 * page_size`` cannot be fully enumerated
#: and ``TriageSearch.complete`` comes back false -- which is precisely the
#: case ``refresh --deep`` exists to cover.
_TRIAGE_MAX_PAGES: Final = 40


def _worklist(store: Store, config: Config) -> Worklist:
    """Classify the whole store without deserialising a single payload.

    Two narrow queries and an O(n) bucketing. Clusters are recomputed here
    rather than read back from the ``clusters`` table on purpose: clustering
    from the indexed signature columns costs about a fifth of a second over ten
    thousand runs and is always current, where a cached grouping would need a
    staleness check that could only ever tell you to go and run ``dedup``.
    """
    signatures = store.signature_rows(primary_only=True)
    clusters = cluster_runs(
        signatures, config=config.dedup, oldest_first=sorted(signatures)
    )
    return classify(store.triage_rows(primary_only=True), clusters)


@app.command(rich_help_panel="Act on the corpus")
def refresh(
    all_bugs: Annotated[
        bool,
        typer.Option("--all", help="Re-read every bug, ignoring the watermark."),
    ] = False,
    deep: Annotated[
        bool,
        typer.Option("--deep", help="Also learn which bug each duplicate duplicates."),
    ] = False,
    limit: Annotated[
        int | None,
        typer.Option("--limit", "-n", metavar="N", help="Cap the per-bug pass of --deep."),
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Say what this would cost and stop.")
    ] = False,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit a machine-readable summary.")
    ] = False,
    out_path: OutOption = None,
    config_path: ConfigOption = None,
) -> None:
    """Re-read Launchpad's verdict on the bugs already in the store.

    What keeps ``queue`` honest. ``sweep`` only ever looks at bugs it has not
    seen, so a status it recorded once is frozen for good -- and a bug's status
    is exactly what changes when somebody triages it.

    Cheap by design: ``searchTasks`` returns status in the task entry, so one
    request covers fifty bugs, and asking only for bugs modified since the last
    pass makes the steady state a single request however large the corpus is.
    Bugs the search does not return were not modified, which is positive
    evidence that what is already recorded is still current.

    \b
    Examples:
      uru-doctor refresh            # one request, usually
      uru-doctor refresh --all      # re-read everything
      uru-doctor refresh --deep     # also resolve duplicate masters
    """
    config = _config(config_path)
    with _state_store(config) as store:
        known = store.known_bug_ids()
        if not known:
            _fail("the store holds no Launchpad bugs; run `uru-doctor sweep` first")

        watermark = None if all_bugs else store.status_watermark()
        cap = limit if limit is not None else config.launchpad.max_deep_bugs

        if dry_run:
            _report_refresh_plan(store, config, known, watermark, cap, deep, as_json, out_path)
            return

        now = datetime.now(UTC)
        stamp = now.isoformat()
        changed: list[tuple[int, str, str]] = []
        newly_duplicate: list[int] = []
        resolved: list[tuple[int, int]] = []
        before = store.bug_states()

        with (
            _progress(console=err if as_json else out) as tracker,
            Launchpad(
                config=config.launchpad,
                store=store,
                cache_dir=config.paths.state_dir / "attachments",
                progress=tracker.callback,
            ) as client,
        ):
            tracker.start("reading Launchpad statuses", total=None)
            try:
                search = client.search_triage(
                    modified_since=watermark,
                    page_size=config.launchpad.sweep_page_size,
                )
            except RateLimited as exc:
                _fail(f"{exc}\nWait a minute and retry; nothing was changed.")
                return
            except LaunchpadError as exc:
                _fail(f"could not search Launchpad: {exc}")
                return

            seen = [ref for ref in search.refs if ref.bug_id in known]
            states = [
                BugState(
                    bug_id=ref.bug_id,
                    status=ref.status,
                    is_duplicate=ref.is_duplicate,
                    assignee=ref.assignee,
                    checked_at=stamp,
                )
                for ref in seen
            ]
            for state in states:
                was = before.get(state.bug_id)
                if was is None or was.status != state.status:
                    changed.append((state.bug_id, was.status if was else "", state.status))
                if state.is_duplicate and not (was and was.is_duplicate):
                    newly_duplicate.append(state.bug_id)
            store.put_bug_states(states)

            # A bug the listing did not return was not modified since the
            # watermark, so its recorded verdict is confirmed current and only
            # its timestamp moves. That inference is valid *only* if the
            # listing reached the end: this package has far more bugs than
            # ``max_pages`` will fetch, so on a truncated pass absence means
            # "never looked", and stamping it as confirmed would be the one
            # lie this whole mechanism exists to prevent.
            unreached = sorted(known - {s.bug_id for s in states})
            if search.complete:
                store.touch_bug_states(unreached, stamp)
                unreached = []

            if deep:
                targets = _deep_targets(store, config, cap, unreached)
                if targets:
                    tracker.start(f"resolving {plural(len(targets), 'bug')}", total=len(targets))
                    deep_states: list[BugState] = []
                    recorded = store.bug_states()
                    for bug_id in targets:
                        tracker.context(f"LP#{bug_id}")
                        current = recorded.get(bug_id)
                        status = current.status if current else ""
                        try:
                            # Status first, and only when it is actually
                            # missing: an unlisted bug needs it and a listed
                            # one already has it, so paying for both would
                            # double the cost of the expensive pass to learn
                            # something already known.
                            if not status or bug_id in set(unreached):
                                status = client.task_status(bug_id) or status
                            master, _ = client.duplicate_of(bug_id)
                        except RateLimited as exc:
                            err.print(f"[yellow]rate limited after {len(deep_states)}:[/] {exc}")
                            break
                        except LaunchpadError as exc:
                            err.print(f"[yellow]skipped LP#{bug_id}:[/] {exc}")
                            continue
                        if current is None or current.status != status:
                            changed.append(
                                (bug_id, current.status if current else "", status)
                            )
                        deep_states.append(
                            BugState(
                                bug_id=bug_id,
                                status=status,
                                duplicate_of=master,
                                is_duplicate=(
                                    True if master is not None
                                    else (current.is_duplicate if current else None)
                                ),
                                checked_at=stamp,
                            )
                        )
                        if master is not None:
                            resolved.append((bug_id, master))
                        tracker.advance()
                    store.put_bug_states(deep_states)
                    unreached = [b for b in unreached if b not in {s.bug_id for s in deep_states}]

            if seen or watermark is None:
                store.advance_status_watermark(now)
            store.commit()

        # One query, not one per bug: this used to call ``bug_states()`` inside
        # the comprehension, which is a full read of the table per bug.
        final = store.bug_states()
        unchecked = sum(1 for bug_id in known if not final.get(bug_id, BugState(bug_id)).status)

    if as_json:
        _write(
            json.dumps(
                {
                    "schema": JSON_SCHEMA_VERSION,
                    "modified_since": watermark.isoformat() if watermark else None,
                    "tasks_seen": len(search),
                    "listing_complete": search.complete,
                    "in_corpus": len(seen),
                    "not_reached": unreached,
                    "status_changed": [
                        {"bug_id": bug_id, "was": before_status, "now": after_status}
                        for bug_id, before_status, after_status in changed
                    ],
                    "newly_duplicate": newly_duplicate,
                    "masters_resolved": [
                        {"bug_id": b, "duplicate_of": m} for b, m in resolved
                    ],
                    "never_checked": unchecked,
                },
                indent=2,
            )
            + "\n",
            out_path,
            label="refresh",
        )
        return

    out.print(
        f"[green]checked {plural(len(seen), 'bug')}[/] of {len(known)} in the corpus"
        + (f" modified since {watermark.date().isoformat()}" if watermark else "")
    )
    if changed:
        table = Table(box=None, pad_edge=False)
        table.add_column("bug")
        table.add_column("was", style="dim")
        table.add_column("now")
        for bug_id, before_status, after_status in changed[: config.queue.max_rows]:
            table.add_row(f"LP#{bug_id}", before_status or "unknown", after_status)
        out.print(table)
        if len(changed) > config.queue.max_rows:
            out.print(f"[dim]… and {len(changed) - config.queue.max_rows} more[/]")
    else:
        out.print("[dim]no status changed[/]")
    if newly_duplicate:
        out.print(
            f"[yellow]{plural(len(newly_duplicate), 'bug')} newly marked a duplicate:[/] "
            + ", ".join(f"LP#{b}" for b in newly_duplicate[:10])
        )
    for bug_id, master in resolved:
        out.print(f"[dim]LP#{bug_id} duplicates LP#{master}[/]")
    if unreached:
        # Said out loud because the alternative is a worklist that looks
        # complete and is not. The per-bug pass is the only way to reach these.
        out.print(
            f"[yellow]{plural(len(unreached), 'bug')} beyond the listing's "
            f"{config.launchpad.sweep_page_size * 40}-task window[/] -- their recorded "
            "status is unconfirmed; `uru-doctor refresh --deep` reaches them one at a time"
        )
    if unchecked and not all_bugs:
        out.print(
            f"[dim]{plural(unchecked, 'bug')} never checked -- "
            f"`uru-doctor refresh --all` would read them[/]"
        )


def _deep_targets(
    store: Store, config: Config, cap: int, unreached: Sequence[int] = ()
) -> list[int]:
    """Which bugs to spend per-bug requests on, most informative first.

    A deep pass costs a request or two per bug, so which bugs it picks matters
    more than how many it takes. The order is by how much is missing:

    1. Bugs the listing could not reach at all. Nothing else can read their
       status, so for these the per-bug request is not an optimisation but the
       only route.
    2. Bugs Launchpad already calls duplicates. A master is known to exist and
       is the one fact absent.
    3. Bugs with outstanding work, where a master contradicting this tool's own
       is the other thing worth knowing.

    Within each group the order is least-recently-checked first, which is what
    makes a capped pass resumable: repeated runs walk the corpus round-robin
    instead of re-reading its head.
    """
    worklist = _worklist(store, config)
    targets: list[int] = []
    for group in (
        list(unreached),
        list(worklist.deep_unknown),
        [
            item.row.bug_id
            for item in worklist.items
            if item.bucket.actionable and item.row.bug_id is not None
        ],
    ):
        if len(targets) >= cap:
            break
        chosen = set(targets)
        candidates = [b for b in dict.fromkeys(group) if b not in chosen]
        targets += store.stale_bug_ids(cap - len(targets), among=candidates)
    return targets


def _report_refresh_plan(
    store: Store,
    config: Config,
    known: set[int],
    watermark: datetime | None,
    cap: int,
    deep: bool,
    as_json: bool,
    out_path: Path | None,
) -> None:
    """Say what a refresh would cost without spending anything on finding out.

    The listing is two requests per page -- one including duplicates, one
    excluding. How many pages is a property of *Launchpad's* bug list, not of
    this corpus: a full pass walks the package's whole queue, which for
    ``ubuntu-release-upgrader`` is far more than ``max_pages`` will fetch. An
    earlier version of this estimate divided the corpus size by the page size
    and promised six seconds for a pass that takes four minutes.

    A watermarked pass is the cheap one and genuinely is two requests, because
    ``modified_since`` leaves almost nothing to page through.
    """
    full_pass = watermark is None
    cheap = 2 * (_TRIAGE_MAX_PAGES if full_pass else 1)
    deep_targets = _deep_targets(store, config, cap) if deep else []
    # Two per bug in the worst case: the task carries the status, the bug
    # carries the master, and neither carries the other.
    seconds = int((cheap + 2 * len(deep_targets)) * config.launchpad.min_interval_s)

    if as_json:
        _write(
            json.dumps(
                {
                    "schema": JSON_SCHEMA_VERSION,
                    "modified_since": watermark.isoformat() if watermark else None,
                    "bugs_known": len(known),
                    "full_pass": full_pass,
                    "listing_requests_max": cheap,
                    "deep_requests": len(deep_targets),
                    "would_resolve": deep_targets,
                    "estimated_seconds": seconds,
                },
                indent=2,
            )
            + "\n",
            out_path,
            label="plan",
        )
        return

    out.print(f"{plural(len(known), 'bug')} in the corpus")
    out.print(
        f"[dim]up to {cheap} listing request(s)"
        + (f" + up to {2 * len(deep_targets)} per-bug request(s)" if deep else "")
        + f", ~{seconds // 60}m{seconds % 60:02d}s at the configured pacing[/]"
    )
    if full_pass:
        out.print(
            "[dim]a full pass walks Launchpad's whole queue for this package, "
            "not just this corpus; later passes use the watermark and cost two[/]"
        )
    if deep and deep_targets:
        out.print("[dim]would resolve: " + ", ".join(f"LP#{b}" for b in deep_targets[:12]) + "[/]")


@app.command(rich_help_panel="Act on the corpus")
def queue(
    bucket: Annotated[
        str | None,
        typer.Option("--bucket", "-b", metavar="NAME", help="Show one bucket only."),
    ] = None,
    limit: Annotated[
        int | None,
        typer.Option("--limit", "-n", metavar="N", help="Rows per bucket. Counts stay exact."),
    ] = None,
    titles: Annotated[
        bool,
        typer.Option("--titles", help="Include each bug's current Launchpad title."),
    ] = False,
    do_refresh: Annotated[
        bool, typer.Option("--refresh", help="Re-read Launchpad statuses first.")
    ] = False,
    markdown: Annotated[
        bool, typer.Option("--markdown", "-m", help="Emit the Markdown worklist.")
    ] = False,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit a machine-readable worklist.")
    ] = False,
    out_path: OutOption = None,
    config_path: ConfigOption = None,
) -> None:
    """What still needs a decision, and what has already had one.

    Reads the store; add ``--refresh`` to re-read Launchpad first. Rows leave
    this list because Launchpad changed, never because the tool remembers you
    looking -- so it reports how old its copy of Launchpad is, and says when
    that is too old to rely on.

    Every row is a proposal. A third-party cause is a *candidate* Invalid;
    whether a bug is Invalid is a judgement for a human.

    \b
    Examples:
      uru-doctor queue
      uru-doctor queue --refresh
      uru-doctor queue -b mark-duplicate
    """
    if markdown and as_json:
        _fail("choose one of --markdown or --json", EXIT_USAGE)

    chosen: Bucket | None = None
    if bucket is not None:
        try:
            chosen = Bucket(bucket)
        except ValueError:
            names = ", ".join(b.value for b in Bucket)
            _fail(f"unknown bucket {bucket!r}; expected one of: {names}", EXIT_USAGE)

    if do_refresh:
        refresh(as_json=False, out_path=None, config_path=config_path)
        out.print()

    config = _config(config_path)
    rows = limit if limit is not None else config.queue.max_rows
    with _state_store(config) as store:
        if not store.run_keys(primary_only=True):
            _fail("the store is empty; run `uru-doctor sweep` first")
        worklist = _worklist(store, config)
        lookup = _titles_for(store, worklist) if titles else {}

    now = datetime.now(UTC)
    stale = worklist.stale(now=now, after_days=config.queue.stale_after_days)

    if as_json:
        _write(
            json.dumps(_queue_json(worklist, chosen, now, stale), indent=2) + "\n",
            out_path,
            label="worklist",
        )
        return
    if markdown:
        _write(
            render_worklist(
                worklist,
                chosen=chosen,
                max_rows=rows,
                stale=stale,
                titles=lookup,
            ),
            out_path,
            label="worklist",
        )
        return

    _print_worklist(worklist, chosen, rows, stale=stale, titles=lookup)


def _titles_for(store: Store, worklist: Worklist) -> dict[str, str]:
    """Current Launchpad titles for the actionable rows.

    Read from the ``current_title`` column, which is already in the projection,
    so this costs nothing extra -- it exists as a separate step only because
    a worklist is read for its *actions* and a column of upstream prose pushes
    them off the right-hand edge.
    """
    return {
        item.row.run_key: item.row.current_title
        for item in worklist.items
        if item.bucket.actionable and item.row.current_title
    }


def _queue_json(
    worklist: Worklist, chosen: Bucket | None, now: datetime, stale: bool
) -> dict[str, object]:
    """The machine-readable worklist.

    Counts are unconditional and exact even when ``--bucket`` narrows the
    rows, because a consumer that asked about one bucket still needs to know
    it is looking at a fifth of the backlog.
    """
    items = [
        item
        for item in worklist.items
        if item.bucket.actionable and (chosen is None or item.bucket is chosen)
    ]
    return {
        "schema": JSON_SCHEMA_VERSION,
        "generated_at": now.isoformat(),
        "launchpad_state": {
            "newest_check": (
                worklist.newest_check.isoformat() if worklist.newest_check else None
            ),
            "oldest_check": (
                worklist.oldest_check.isoformat() if worklist.oldest_check else None
            ),
            "never_checked": worklist.unchecked,
            "stale": stale,
        },
        "counts": {bucket.value: worklist.counts.get(bucket, 0) for bucket in Bucket},
        "actionable": worklist.actionable,
        "done_by_status": dict(sorted(worklist.done_by_status.items())),
        "deep_unknown": list(worklist.deep_unknown),
        "items": [
            {
                "bucket": item.bucket.value,
                "key": item.row.run_key,
                "bug_id": item.row.bug_id,
                "status": item.row.status,
                "cause": item.row.cause.value if item.row.cause else None,
                "action": item.action,
                "master": item.master or None,
                "tier": item.tier or None,
                "duplicate_count": item.row.duplicate_count,
                "evidence_complete": item.row.evidence_complete,
                "checked_at": item.row.state.checked_at if item.row.state else None,
            }
            for item in items
        ],
    }


def _freshness(worklist: Worklist, stale: bool) -> str:
    """One line on how much to trust the rows below it."""
    if worklist.newest_check is None:
        return "[yellow]Launchpad state never read -- run `uru-doctor refresh --all`[/]"
    age = datetime.now(UTC) - worklist.newest_check
    hours = int(age.total_seconds() // 3600)
    when = f"{hours}h ago" if hours < 48 else f"{hours // 24}d ago"
    style = "yellow" if stale else "dim"
    note = ""
    if stale:
        oldest = worklist.oldest_check
        note = (
            f"; oldest is {(datetime.now(UTC) - oldest).days}d old -- refresh"
            if oldest
            else "; refresh"
        )
    return f"[{style}]Launchpad state as of {when}{note}[/]"


def _print_worklist(
    worklist: Worklist,
    chosen: Bucket | None,
    max_rows: int,
    *,
    stale: bool,
    titles: Mapping[str, str],
) -> None:
    """The worklist, for a terminal."""
    out.print(
        f"[bold]{plural(worklist.actionable, 'bug')} waiting on a decision[/] "
        f"of {len(worklist.items)} in the corpus"
    )
    out.print(_freshness(worklist, stale))

    shown = 0
    for bucket in Bucket:
        if not bucket.actionable or (chosen is not None and bucket is not chosen):
            continue
        items = worklist.of(bucket)
        if not items:
            continue
        shown += 1
        out.print()
        out.rule(f"[bold]{bucket.value}[/]  {len(items)}", align="left")
        out.print(f"[dim]{BUCKET_HELP[bucket]}[/]")

        table = Table(box=None, pad_edge=False)
        table.add_column("bug")
        table.add_column("status", style="dim")
        table.add_column("cause", style="dim")
        table.add_column("proposed action", overflow="fold")
        if titles:
            table.add_column("current title", style="dim", overflow="fold")
        for item in items[:max_rows]:
            row = [
                item.label,
                item.row.status or "unknown",
                item.row.cause.value if item.row.cause else "none",
                item.action,
            ]
            if titles:
                row.append(titles.get(item.row.run_key, ""))
            table.add_row(*row)
        out.print(table)
        if len(items) > max_rows:
            out.print(
                f"[dim]… showing {max_rows} of {len(items)}; "
                f"`--limit {len(items)}` for all[/]"
            )

    if not shown:
        out.print("\n[green]nothing waiting on a decision[/]")

    done = worklist.counts.get(Bucket.DONE, 0)
    if done and chosen is None:
        breakdown = ", ".join(
            f"{count} {status}" for status, count in sorted(worklist.done_by_status.items())
        )
        out.print(f"\n[dim]{plural(done, 'bug')} need nothing: {breakdown}[/]")
    if worklist.deep_unknown:
        out.print(
            f"[dim]{plural(len(worklist.deep_unknown), 'bug')} Launchpad calls a duplicate "
            f"without us knowing of what -- `uru-doctor refresh --deep` resolves them[/]"
        )
    if worklist.unchecked and chosen is None:
        out.print(
            f"[dim]{plural(worklist.unchecked, 'bug')} never checked against Launchpad[/]"
        )


def _todo_json(
    plate: Sequence[Item],
    me: str,
    worklist: Worklist,
    now: datetime,
    stale: bool,
) -> dict[str, object]:
    """The machine-readable plate. Same freshness block as the worklist."""
    items = list(plate)
    return {
        "schema": JSON_SCHEMA_VERSION,
        "generated_at": now.isoformat(),
        "launchpad_state": {
            "newest_check": (
                worklist.newest_check.isoformat() if worklist.newest_check else None
            ),
            "oldest_check": (
                worklist.oldest_check.isoformat() if worklist.oldest_check else None
            ),
            "never_checked": worklist.unchecked,
            "stale": stale,
        },
        "assignee": me or None,
        "counts": {
            "in_progress": sum(1 for i in items if i.row.status == "In Progress"),
            "triaged": sum(1 for i in items if i.row.status == "Triaged"),
        },
        "items": [
            {
                "key": item.row.run_key,
                "bug_id": item.row.bug_id,
                "status": item.row.status,
                "assignee": item.row.state.assignee if item.row.state else None,
                "cause": item.row.cause.value if item.row.cause else None,
                "title": item.row.current_title or None,
                "checked_at": item.row.state.checked_at if item.row.state else None,
            }
            for item in items
        ],
    }


def _print_todo(
    plate: Sequence[Item], me: str, worklist: Worklist, stale: bool, max_rows: int
) -> None:
    """The plate, for a terminal."""
    out.print(f"[bold]{plural(len(plate), 'bug')} on your plate[/]")
    out.print(_freshness(worklist, stale))
    if not me:
        out.print(
            "[yellow]launchpad.user is not set -- In Progress bugs cannot be "
            "matched to you, so only Triaged are listed[/]"
        )
    if not plate:
        out.print("\n[green]nothing taken on[/]")
        return

    out.print()
    table = Table(box=None, pad_edge=False)
    table.add_column("bug")
    table.add_column("status", style="dim")
    table.add_column("assignee", style="dim")
    table.add_column("cause", style="dim")
    table.add_column("title", overflow="fold")
    for item in plate[:max_rows]:
        state = item.row.state
        table.add_row(
            item.label,
            item.row.status,
            (state.assignee or "—") if state else "?",
            item.row.cause.value if item.row.cause else "none",
            item.row.current_title,
        )
    out.print(table)
    if len(plate) > max_rows:
        out.print(
            f"[dim]… showing {max_rows} of {len(plate)}; `--limit {len(plate)}` for all[/]"
        )


@app.command(rich_help_panel="Act on the corpus")
def todo(
    assignee: Annotated[
        str | None,
        typer.Option(
            "--assignee",
            "-a",
            metavar="NAME",
            help="Whose plate. Default: launchpad.user from the config.",
        ),
    ] = None,
    limit: Annotated[
        int | None,
        typer.Option("--limit", "-n", metavar="N", help="Rows listed. Counts stay exact."),
    ] = None,
    do_refresh: Annotated[
        bool, typer.Option("--refresh", help="Re-read Launchpad statuses first.")
    ] = False,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit a machine-readable list.")
    ] = False,
    out_path: OutOption = None,
    config_path: ConfigOption = None,
) -> None:
    """What you have already taken on: Triaged bugs, and your In Progress ones.

    The inverse of ``queue``: these bugs have had their decision. Every
    Triaged bug in the corpus is listed -- the backlog is anybody's to pick
    up -- plus the In Progress bugs assigned to you, since somebody else's
    in-flight work is not your list. The client is anonymous, so "you" comes
    from ``launchpad.user`` in the config, or from ``--assignee``.

    Reads the store, so it is exactly as current as the last ``refresh`` --
    the same rule as ``queue``, and the same flag fixes it.

    \b
    Examples:
      uru-doctor todo
      uru-doctor todo --refresh
      uru-doctor todo --assignee bamf0
    """
    if do_refresh:
        refresh(as_json=False, out_path=None, config_path=config_path)
        out.print()

    config = _config(config_path)
    me = assignee if assignee is not None else config.launchpad.user
    rows = limit if limit is not None else config.queue.max_rows
    with _state_store(config) as store:
        if not store.run_keys(primary_only=True):
            _fail("the store is empty; run `uru-doctor sweep` first")
        worklist = _worklist(store, config)

    plate = pick_todo(worklist.items, assignee=me)
    now = datetime.now(UTC)
    stale = worklist.stale(now=now, after_days=config.queue.stale_after_days)

    if as_json:
        _write(
            json.dumps(_todo_json(plate, me, worklist, now, stale), indent=2) + "\n",
            out_path,
            label="todo",
        )
        return

    _print_todo(plate, me, worklist, stale, rows)


@app.callback(invoke_without_command=True)
def main(
    version: Annotated[bool, typer.Option("--version", help="Show the version and exit.")] = False,
) -> None:
    if version:
        # The CLI's version first -- that is the distribution a user installed --
        # with the library's alongside, because both matter in a bug report once
        # they can diverge.
        out.print(f"uru-doctor {CLI_VERSION} (library {LIBRARY_VERSION})")
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
