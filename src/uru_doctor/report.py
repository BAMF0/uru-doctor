# SPDX-License-Identifier: GPL-2.0-or-later
"""Render a diagnosis as Markdown.

This module is the product. Everything upstream of it exists to make these
pages trustworthy, and the one rule it follows is that **a reader must be able
to check every claim without rerunning the tool**. So each verdict carries the
log lines that produced it, each number says which of several similar numbers
it is, and anything the evidence does not support is said to be unsupported
rather than quietly omitted.

Three habits follow from that.

*Separate the counts.* "Broken" means four different things in one bug --
apt's own running total, the packages observed broken at any point, the targets
of blame edges, and the graph's node count. On LP#2150245 those are 22, 434,
148 and 964. Printing any one of them as "broken packages" invites a reader to
argue with a number the tool never claimed.

*Attribute, never assert.* A quoted line is prefixed with its source and line
number so a triager can open the attachment and look. Where the structural
evidence is stronger than the textual evidence -- as it is for every resolver
finding, whose real provenance is a graph rather than a sentence -- the apt.log
section offset is cited instead.

*Distinguish "no" from "don't know".* ``dpkg_wrote`` is a tri-state and
``evidence_complete`` gates nineteen rules. A report that renders a truncated
log the same way as a complete one is worse than no report, because it looks
equally confident.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

from uru_doctor.config import ReportConfig
from uru_doctor.dedup import Cluster, summarise
from uru_doctor.diagnose import DiagnosisResult, explain
from uru_doctor.intern import Interner
from uru_doctor.models import Cause, Decision, Finding, UpgradeRun
from uru_doctor.title import ProposedTitle, phase_note, propose_title

__all__ = ["MAX_QUOTE_CHARS", "RunEntry", "plural", "render_corpus", "render_run"]

_RULE: Final = "---"

MAX_QUOTE_CHARS: Final = 320
"""Longest quoted log line before eliding the middle.

Evidence selection already drops the upgrader's bulk package dumps, which is
where the 45 kB lines come from. This is the backstop: a future upgrader will
add a bulk prefix this tool does not know, and the failure mode should be an
elided quote rather than a report with a single 54 kB line in it.
"""

_DECISION_WORDS: Final[dict[Decision, str]] = {
    Decision.UNKNOWN: "no decision recorded",
    Decision.FIX_VIA_REMOVE: "apt proposed removing it",
    Decision.FIX_VIA_KEEP: "apt proposed keeping it at the installed version",
    Decision.REMOVE_RATHER_THAN_CHANGE: "apt removed it rather than change it",
    Decision.HOLD_BACK_RATHER_THAN_CHANGE: "apt held it back rather than change it",
    Decision.KEEP_DUE_TO: "apt kept it because of another package",
    Decision.ADDED_TO_REMOVE_LIST: "apt added it to the removal list",
}

#: ``Finding.detail`` keys worth showing, in reading order, with labels.
#:
#: An allow-list rather than a dump: ``detail`` also carries machine flags such
#: as ``candidate_invalid`` and ``advisory`` that have already been turned into
#: sections of their own, and repeating them as raw key/value pairs makes a
#: report look like a debug trace.
_DETAIL_LABELS: Final[tuple[tuple[str, str], ...]] = (
    ("relationship", "Relationship"),
    ("constraint", "Unsatisfied constraint"),
    ("dependency", "Required dependency"),
    ("blocked_by", "Blocked by"),
    ("forced_by", "Forced by"),
    ("oscillating_package", "Oscillating package"),
    ("reversals", "Keep/upgrade reversals"),
    ("kind", "Kind"),
    ("mechanism", "Mechanism"),
    ("candidate", "Candidate version"),
    ("installed", "Installed version"),
    ("from", "From"),
    ("to", "To"),
    ("arch", "Architecture"),
    ("partner", "Other package"),
    ("fix", "Proposed fix"),
    ("failing_package", "Failing package"),
    ("conflicts_with", "Conflicts with"),
    ("script", "Script"),
    ("path", "Path"),
    ("exit_status", "Exit status"),
    ("exception", "Exception"),
    ("required", "Required"),
    ("cycle_broken", "Dependency cycle broken"),
    ("promoted", "Promoted"),
    ("demoted", "Demoted"),
    ("remedy_command", "Suggested command"),
    ("upstream", "Logged by (upstream)"),
    ("narrowest_margin", "Narrowest score margin"),
)


@dataclass(frozen=True, slots=True)
class RunEntry:
    """One diagnosed run, ready to be written up.

    Carries the title rather than recomputing it so that the per-bug page and
    the corpus digest cannot disagree about what this run should be called.
    Recomputing in each renderer meant two code paths had to stay in step, and
    a title is the one output a triager copies by hand.
    """

    key: str
    """Run key as dedup and the store spell it, e.g. ``lp:2150245#0``."""

    run: UpgradeRun
    result: DiagnosisResult
    title: ProposedTitle

    @property
    def label(self) -> str:
        """Short human reference.

        The bug number when there is one, otherwise the directory's own name:
        a corpus ingested from disk is organised by the person who ingested it,
        so ``2150339`` or ``customer-42`` means more to them than
        ``dir:/long/path/to/it#0``. Collisions are resolved by
        :func:`_display_labels`, which falls back to the full key.
        """
        if self.run.bug_id is not None:
            return f"LP#{self.run.bug_id}"
        if self.run.source_dir:
            name = PurePosixPath(self.run.source_dir).name or self.run.source_dir
            return f"{name}#{self.run.attempt}" if self.run.attempt else name
        return self.key


# -- small helpers -----------------------------------------------------------


def _code(text: str) -> str:
    """Inline code span, with backticks in the content neutralised.

    Package names and version constraints contain ``+``, ``.``, ``~`` and
    ``<``, all of which mean something in Markdown or HTML. Quoting is simpler
    than escaping and reads better in a plain-text terminal too.
    """
    cleaned = text.replace("`", "'")
    return f"`{cleaned}`" if cleaned else "_none_"


def plural(count: int, singular: str, irregular: str = "") -> str:
    """``3 packages`` / ``1 package``, with a thousands separator.

    ``irregular`` supplies a plural that is not formed by adding ``s``.
    """
    word = singular if count == 1 else (irregular or f"{singular}s")
    return f"{count:,} {word}"


def _elide(text: str, limit: int = MAX_QUOTE_CHARS) -> str:
    """Shorten a quote from the middle, keeping both ends.

    The middle goes rather than the tail because a log line's ends are the
    informative parts -- the message at the front, the error or version at the
    back -- and a tail-truncated line hides exactly the bit a reader wanted.
    """
    if len(text) <= limit:
        return text
    keep = (limit - 24) // 2
    dropped = len(text) - 2 * keep
    return f"{text[:keep]} […{dropped:,} chars…] {text[-keep:]}"


def _packages(pkg_ids: Iterable[int], interner: Interner) -> list[str]:
    """Labels for interned package ids: deduplicated, order preserved.

    Deduplication is by rendered label, not by id, because one package can
    hold two ids. ``resolve_third_party`` deliberately keeps both the bare
    ``libwacom9-surface`` from ``main.log`` and the ``libwacom9-surface:amd64``
    from the apt trace so that the graph overlay matches whichever spelling a
    log uses; ``package_label`` then strips the native-architecture suffix and
    the two collapse. Correct for matching, wrong for display -- it put the
    same package in one list twice and inflated the count beside it.
    """
    out: list[str] = []
    seen: set[str] = set()
    for pkg_id in pkg_ids:
        if not pkg_id:
            continue
        label = interner.package_label(pkg_id)
        if label and label not in seen:
            seen.add(label)
            out.append(label)
    return out


def _listing(names: Sequence[str], limit: int) -> str:
    """Comma-joined code spans, elided with a true count.

    A forty-victim cascade needs a number, not forty lines.
    """
    if not names:
        return "_none_"
    shown = [_code(n) for n in names[:limit]]
    if len(names) > limit:
        shown.append(f"… and {len(names) - limit:,} more")
    return ", ".join(shown)


def _quote_events(
    run: UpgradeRun,
    interner: Interner,
    indices: Sequence[int],
    *,
    limit: int,
) -> list[str]:
    """Render evidence indices as ``source:line: text`` lines.

    Events hold a template id and interned arguments, not raw text, so the
    quote is reconstructed. Whitespace was normalised when the template was
    mined, which matters for apt's indented resolver trace: the words are
    exact, the leading indentation is gone. Depth is recorded on graph edges
    instead, and is cited structurally rather than quoted.
    """
    out: list[str] = []
    for index in indices[:limit]:
        if not 0 <= index < len(run.events):
            # A findings tuple outliving the run it came from; skip rather
            # than raise, since a wrong quote is worse than a missing one.
            continue
        event = run.events[index]
        text = interner.render(event.template_id, event.args)
        if not text:
            continue
        mark = f" [{event.level.name}]" if event.level.is_problem else ""
        out.append(f"{event.source.value}:{event.line_no}{mark}: {_elide(text)}")
    return out


def _confidence_line(finding: Finding, result: DiagnosisResult) -> str:
    bits = [
        f"cause `{finding.cause.value}`",
        f"confidence {finding.confidence.name}",
        f"severity {finding.severity.name}",
    ]
    if finding.cause in result.corroborated:
        bits.append("corroborated by apt's own error")
    if finding.fragile:
        bits.append("**fragile**")
    return " · ".join(bits)


# -- sections ----------------------------------------------------------------


def _header(entry: RunEntry) -> list[str]:
    run, result, title = entry.run, entry.result, entry.title
    lines = [f"# {title.title}", ""]

    ident = [entry.label]
    if run.attempt:
        ident.append(f"attempt {run.attempt}")
    if run.duplicate_of:
        ident.append(f"marked duplicate of LP#{run.duplicate_of}")
    lines.append(" · ".join(ident))
    lines.append("")

    if run.current_title and run.current_title != title.title:
        # Shown for the triager's benefit only. The current title is excluded
        # from signatures on purpose: titles are reporter prose, and matching
        # on them is how triage tools talk themselves into false duplicates.
        lines += [f"Current title: {run.current_title}", ""]

    if not title.confident:
        lines += [
            "> **Low confidence.** The proposed title is a guess; see Caveats.",
            "",
        ]
    if not run.evidence_complete:
        withheld = len(result.skipped_incomplete)
        lines += [
            f"> **Evidence incomplete.** {withheld} rule(s) could not run. "
            "Findings below are what the surviving fragments support, which "
            "may not be the whole failure.",
            "",
        ]
    if result.is_candidate_invalid:
        lines += [
            "> **Candidate Invalid.** The package that stopped this upgrade "
            "does not come from Ubuntu. See "
            "[Third-party packages](#third-party-packages). This is a "
            "suggestion for a human, not a verdict.",
            "",
        ]
    if result.upgrade_completed:
        lines += [
            "> **The upgrade finished.** This is a post-upgrade failure: the "
            "machine is upgraded and faulty, rather than un-upgraded and "
            "intact.",
            "",
        ]
    return lines


def _run_facts(run: UpgradeRun, result: DiagnosisResult) -> list[str]:
    """The run's own description of itself, before any interpretation."""
    rows: list[tuple[str, str]] = [
        ("Release", run.release_pair),
        ("Stage reached", phase_note(run)),
    ]
    if run.arch.value != "unknown":
        rows.append(("Architecture", run.arch.value))
    if run.apt_version:
        rows.append(("apt version", _code(run.apt_version)))
    if run.upgrader_version:
        rows.append(("Upgrader", _code(run.upgrader_version)))
    if run.locale:
        rows.append(("Locale", _code(run.locale)))
    if run.frontend.value != "unknown":
        rows.append(("Frontend", run.frontend.value))
    if run.server_mode:
        rows.append(("Server mode", "yes"))
    if run.kernel:
        rows.append(("Kernel", _code(run.kernel)))

    wrote = {True: "yes", False: "no", None: "unknown"}[run.dpkg_wrote]
    rows.append(("dpkg wrote to the system", wrote))
    rows.append(("Upgrade completed", "yes" if result.upgrade_completed else "no"))
    rows.append(
        (
            "Logs parsed",
            ", ".join(_code(s.value) for s in run.logs_present) or "_none_",
        )
    )

    lines = ["## The run", "", "| | |", "| --- | --- |"]
    lines += [f"| {name} | {value} |" for name, value in rows]
    lines.append("")
    return lines


def _counts(run: UpgradeRun) -> list[str]:
    """Package counts, each labelled with what it actually counts.

    The two broken counts are deliberately adjacent and deliberately named at
    length. They differ by an order of magnitude and conflating them is the
    single easiest way to publish a wrong number.
    """
    counts = run.counts
    rows = [
        ("Upgraded", counts.upgraded),
        ("Newly installed", counts.installed),
        ("Removed", counts.removed),
        ("Held back", counts.held_back),
        ("Failed", counts.failed),
        ("Obsolete", counts.obsolete),
        ("Unauthenticated", counts.unauthenticated),
    ]
    if not any(value for _, value in rows) and not counts.broken and not run.graphs:
        # No logs reached the counters at all. A column of zeroes implies the
        # upgrade touched nothing, which is a finding; "not recorded" is the
        # truth.
        return [
            "## Counts",
            "",
            "Nothing recorded: no log carrying these numbers was attached.",
            "",
        ]

    lines = ["## Counts", ""]
    lines += [f"- {name}: {value:,}" for name, value in rows if value]
    lines += [
        f"- Broken, as apt last reported it: {run.apt_broken_count:,}",
        f"- Broken, observed at any point during resolution: {counts.broken:,}",
    ]
    if run.apt_broken_count and counts.broken > run.apt_broken_count:
        lines.append(
            "  (The second is larger because the resolver breaks and repairs "
            "packages as it searches. Neither number is wrong; they answer "
            "different questions.)"
        )
    lines.append("")
    return lines


def _finding_block(
    finding: Finding,
    run: UpgradeRun,
    result: DiagnosisResult,
    interner: Interner,
    config: ReportConfig,
    *,
    level: str = "###",
    seen_graphs: set[int] | None = None,
) -> list[str]:
    roots = _packages(finding.root_pkgs, interner)
    heading = ", ".join(roots) if roots else finding.cause.value.replace("_", " ")
    lines = [f"{level} {heading}", "", _confidence_line(finding, result), ""]

    if finding.summary:
        lines += [finding.summary, ""]

    facts: list[str] = []
    if finding.remedy is not Decision.UNKNOWN:
        facts.append(f"- What apt did: {_DECISION_WORDS[finding.remedy]}")
    if finding.score_margin is not None:
        facts.append(f"- Score margin: {finding.score_margin}")
    for key, label in _DETAIL_LABELS:
        value = finding.detail.get(key)
        if value:
            facts.append(f"- {label}: {_code(value)}")
    if facts:
        lines += [*facts, ""]

    if finding.cascade_size:
        victims = _packages(finding.victim_pkgs, interner)
        lines += [
            f"**Blast radius: {plural(finding.cascade_size, 'package')}** "
            "reachable from this root in the blame graph.",
            "",
        ]
        if victims:
            lines += [
                f"Affected: {_listing(victims, config.max_cascade_shown)}",
                "",
            ]

    lines += _provenance(finding, run, interner, config, seen_graphs)
    return lines


def _provenance(
    finding: Finding,
    run: UpgradeRun,
    interner: Interner,
    config: ReportConfig,
    seen_graphs: set[int] | None = None,
) -> list[str]:
    """Where to look to check this finding by hand.

    Deliberately does not explain the *rule*. Several findings normally come
    from one rule, and repeating its provenance and remedy under each one
    drowns the part that differs. Rules are explained once, in
    :func:`_method`.
    """
    lines: list[str] = []
    quotes = _quote_events(run, interner, finding.evidence, limit=config.max_cascade_shown)
    if quotes:
        lines += [
            "<details><summary>Evidence</summary>",
            "",
            "```",
            *quotes,
            "```",
            "",
            "</details>",
            "",
        ]
        return lines

    if finding.graph_index is None or finding.graph_index >= len(run.graphs):
        return lines

    # Resolver findings usually have no quotable sentence: the evidence is a
    # subgraph of apt's trace, not a message. Cite the offset instead, and only
    # the first time this section is referenced -- every root in one graph
    # cites the same line, and five identical citations read like a mistake.
    graph = run.graphs[finding.graph_index]
    if seen_graphs is not None and finding.graph_index in seen_graphs:
        return lines
    if seen_graphs is not None:
        seen_graphs.add(finding.graph_index)
    lines += [
        f"Evidence: resolver section {graph.section_index} of `apt.log`, from "
        f"line {graph.first_line:,} ({plural(len(graph.nodes), 'package')}, "
        f"{plural(len(graph.edges), 'relation')}). Every root below is drawn "
        "from this section.",
        "",
    ]
    return lines


def _method(result: DiagnosisResult) -> list[str]:
    """Explain each rule that fired, once.

    A reader who distrusts a finding wants to know how it was reached and what
    in the upstream code produces the line it rests on. That is a property of
    the rule, so it belongs in one place.
    """
    rules = [r for name in result.fired if (r := explain(name)) is not None]
    rules = [r for r in rules if r.provenance or r.remedy]
    if not rules:
        return []
    lines = ["## Method", ""]
    for rule in rules:
        lines.append(f"**`{rule.name}`** — {rule.phase_hint or rule.cause.value}")
        if rule.provenance:
            lines.append(f"  - Derived from: {rule.provenance}")
        if rule.remedy:
            lines.append(f"  - Suggested remedy: {rule.remedy}")
        lines.append("")
    return lines


def _diagnosis(entry: RunEntry, interner: Interner, config: ReportConfig) -> list[str]:
    run, result = entry.run, entry.result
    primary = result.primary
    if primary is None:
        return [
            "## Diagnosis",
            "",
            "No rule matched. The logs record no failure this tool recognises, "
            "which is itself worth knowing: it means the bug needs a human "
            "read rather than that the upgrade was fine.",
            "",
        ]

    seen_graphs: set[int] = set()
    lines = ["## Diagnosis", ""]
    lines += _finding_block(primary, run, result, interner, config, seen_graphs=seen_graphs)

    # Findings are compared by identity, not value. ``Finding`` is a frozen
    # model and so looks hashable, but its ``detail`` dict is not, and ``==``
    # would conflate two genuinely distinct findings that happen to agree on
    # every field -- which the same cause firing on two graphs does.
    elsewhere = {id(f) for f in result.caveats}
    if config.separate_third_party:
        elsewhere |= {id(f) for f in result.third_party_findings}
    elsewhere |= {id(f) for f in result.findings if f.detail.get("advisory") == "true"}
    rest = [f for f in result.findings if f is not primary and id(f) not in elsewhere]
    if rest:
        lines += [_RULE, "", "### Also found", ""]
        for finding in rest:
            lines += _finding_block(
                finding, run, result, interner, config, level="####", seen_graphs=seen_graphs
            )
    return lines


def _apt_said(run: UpgradeRun, result: DiagnosisResult, interner: Interner) -> list[str]:
    """apt's own terminal errors, and which causes they corroborate."""
    errors = [interner.text(e) for e in run.apt_error_entries]
    errors = [e for e in errors if e]
    if not errors and not result.corroborated:
        return []

    lines = ["## What apt itself said", ""]
    if errors:
        lines += ["```", *errors, "```", ""]
    if result.corroborated:
        causes = ", ".join(f"`{c.value}`" for c in sorted(result.corroborated))
        lines += [
            f"These messages are consistent with: {causes}.",
            "",
            "Corroboration raises a finding's rank but is never the sole "
            "basis for one -- apt's error text is translated, and several "
            "distinct faults share a single message.",
            "",
        ]
    warnings = [interner.text(w) for w in run.apt_warning_entries]
    warnings = [w for w in warnings if w]
    if warnings:
        lines += [
            "<details><summary>"
            f"{len(warnings)} apt warning(s), which are not evidence of the "
            "failure</summary>",
            "",
            "```",
            *warnings[:20],
            "```",
            "",
            "</details>",
            "",
        ]
    return lines


def _third_party(entry: RunEntry, interner: Interner, config: ReportConfig) -> list[str]:
    """The candidate-Invalid section.

    Named for what it contains rather than for the conclusion, because the
    conclusion is a human's to draw. A machine with a few PPAs is the normal
    state of a machine that files one of these bugs, so the presence of
    third-party packages is unremarkable; what matters is whether one of them
    is the thing that stopped the upgrade.
    """
    if not config.separate_third_party:
        return []
    run, result = entry.run, entry.result
    findings = result.third_party_findings
    foreign = _packages(run.third_party, interner)
    if not findings and not foreign:
        return []

    lines = ["## Third-party packages", ""]
    if result.is_candidate_invalid:
        lines += [
            "**Candidate Invalid.** The primary cause is a package Ubuntu does "
            "not ship, so there is likely nothing to fix in Ubuntu. Worth "
            "confirming by hand before closing.",
            "",
        ]
    elif findings:
        lines += [
            "Third-party packages are involved but are **not** the primary "
            "cause, so this is not a candidate for Invalid. Recorded because "
            "they shape the failure and a reader will otherwise wonder.",
            "",
        ]

    # Implicated packages are collected across findings and stated once.
    # Rendering "Implicated:" inside a per-finding loop interleaved it between
    # two summaries that say nearly the same thing, which reads as though the
    # tool found two separate problems.
    implicated: list[str] = []
    for finding in findings:
        for name in finding.detail.get("third_party_packages", "").split(","):
            name = name.strip()
            if name and name not in implicated:
                implicated.append(name)
    for finding in findings:
        roots = _packages(finding.root_pkgs, interner)
        for name in roots:
            if name not in implicated:
                implicated.append(name)
    if implicated:
        lines += [
            f"Implicated in the failure: {_listing(implicated, config.top_packages)}",
            "",
        ]

    summaries: list[str] = []
    for finding in findings:
        if finding.summary and finding.summary not in summaries:
            summaries.append(finding.summary)
    if summaries:
        lines += [f"- {summary}" for summary in summaries] + [""]

    if foreign:
        lines += [
            f"The upgrader listed {plural(len(foreign), 'package')} not from "
            "Ubuntu on this system:",
            "",
            _listing(sorted(foreign), config.top_packages),
            "",
            "The logs name these packages but not where they came from -- the "
            "upgrader writes a flat `Foreign` list with no origin attached -- "
            "so they are not grouped by PPA here. Guessing the PPA from name "
            "suffixes would be inference dressed as fact.",
            "",
        ]
    return lines


def _livelock(run: UpgradeRun, interner: Interner, config: ReportConfig) -> list[str]:
    """Oscillation detail, when the resolver failed to converge."""
    if not run.oscillations:
        return []
    lines = [
        "## Resolver oscillation",
        "",
        "apt reversed its decision on these packages repeatedly and was still "
        "doing so when the trace ended, which is non-convergence rather than "
        "an unsatisfiable dependency:",
        "",
        "| Package | Reversals | Blocked by | Forced by |",
        "| --- | --- | --- | --- |",
    ]
    ranked = sorted(run.oscillations, key=lambda o: -o[1])
    for pkg_id, reversals, blocked_by, forced_by in ranked[: config.max_cascade_shown]:
        lines.append(
            f"| {_code(interner.package_label(pkg_id))} | {reversals} | "
            f"{_code(interner.package_label(blocked_by))} | "
            f"{_code(interner.package_label(forced_by))} |"
        )
    lines.append("")
    return lines


def _fragile(result: DiagnosisResult, config: ReportConfig) -> list[str]:
    if not config.show_fragile_section:
        return []
    fragile = [f for f in result.findings if f.fragile]
    if not fragile:
        return []
    margins = [f.score_margin for f in fragile if f.score_margin is not None]
    lines = [
        "## Fragile decision",
        "",
        "apt chose between near-equally scored options here"
        + (f" (narrowest margin: {min(margins)})" if margins else "")
        + ". Such outcomes depend on incidental system state, so this bug may "
        "be irreproducible on a clean install and may attract duplicates that "
        "look inconsistent with each other. That is a property of the fault, "
        "not of the reports.",
        "",
    ]
    for finding in fragile:
        packages = finding.detail.get("fragile_packages", "")
        if packages:
            lines += [f"- Close call on: {_code(packages)}"]
    if lines[-1].startswith("- "):
        lines.append("")
    return lines


def _caveats(result: DiagnosisResult, config: ReportConfig) -> list[str]:
    if not config.show_needs_human:
        return []
    lines: list[str] = []
    caveats = result.caveats
    if caveats or result.notes:
        lines += ["## Caveats", ""]
        for caveat in caveats:
            lines.append(f"- {caveat.summary}")
        for note in result.notes:
            if result.skipped_incomplete and "withheld" in note:
                continue  # The collapsed list below names them individually.
            lines.append(f"- {note}")
        lines.append("")
    if result.skipped_incomplete:
        lines += [
            "<details><summary>"
            f"{len(result.skipped_incomplete)} rule(s) withheld for lack of "
            "evidence</summary>",
            "",
            ", ".join(f"`{name}`" for name in sorted(result.skipped_incomplete)),
            "",
            "</details>",
            "",
        ]
    return lines


def _footer(entry: RunEntry) -> list[str]:
    result = entry.result
    fired = ", ".join(f"`{name}`" for name in result.fired) or "_none_"
    return [
        _RULE,
        "",
        f"Rules fired: {fired} (of {result.considered} eligible).",
        "",
        "Generated by `uru-doctor` from the attached logs alone. No bug "
        "titles, descriptions, tags or reporter prose were used to reach "
        "these conclusions.",
        "",
    ]


# -- entry points ------------------------------------------------------------


def render_run(
    run: UpgradeRun,
    result: DiagnosisResult,
    interner: Interner,
    *,
    config: ReportConfig | None = None,
    title: ProposedTitle | None = None,
    key: str = "",
) -> str:
    """Render one diagnosed run as a Markdown page."""
    config = config or ReportConfig()
    entry = RunEntry(
        key=key or (f"lp:{run.bug_id}#{run.attempt}" if run.bug_id else "run"),
        run=run,
        result=result,
        title=title or propose_title(run, result, interner),
    )
    lines: list[str] = []
    lines += _header(entry)
    lines += _diagnosis(entry, interner, config)
    lines += _apt_said(run, result, interner)
    lines += _livelock(run, interner, config)
    lines += _third_party(entry, interner, config)
    lines += _fragile(result, config)
    lines += _run_facts(run, result)
    lines += _counts(run)
    lines += _caveats(result, config)
    lines += _method(result)
    lines += _footer(entry)
    return "\n".join(lines).rstrip() + "\n"


def _display_labels(entries: Sequence[RunEntry]) -> dict[str, str]:
    """Unique display names, keyed by run key.

    One bug can carry several runs -- a second reporter attaching their own
    logs, or an archived earlier attempt -- and they all answer to the same
    ``LP#`` number. Rendering them identically makes a two-member cluster look
    like the same report listed twice, which is indistinguishable from a bug
    in the clustering. Where a label is not unique the full run key is used,
    since that is what dedup and the store actually matched on.
    """
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.label] = counts.get(entry.label, 0) + 1
    return {
        entry.key: (entry.label if counts[entry.label] == 1 else f"{entry.label} ({entry.key})")
        for entry in entries
    }


def _cluster_block(
    cluster: Cluster,
    entries: dict[str, RunEntry],
    names: dict[str, str],
    config: ReportConfig,
) -> list[str]:
    members = cluster.members
    representative = entries.get(cluster.representative)
    heading = representative.title.title if representative else cluster.representative
    lines = [
        f"### {heading}",
        "",
        f"{plural(cluster.size, 'run')}, matched on **{cluster.tier}**. "
        f"Suggested master: {names.get(cluster.representative, cluster.representative)}.",
        "",
    ]
    for key in members[: config.max_members_shown]:
        entry = entries.get(key)
        if entry is None:
            lines.append(f"- {key}")
            continue
        marker = " ← master" if key == cluster.representative else ""
        note = "" if entry.run.evidence_complete else " _(incomplete logs)_"
        lines.append(f"- {names.get(key, entry.label)}: {entry.title.detail}{note}{marker}")
    if len(members) > config.max_members_shown:
        lines.append(f"- … and {len(members) - config.max_members_shown:,} more")
    lines.append("")
    return lines


def render_corpus(
    entries: Sequence[RunEntry],
    clusters: Sequence[Cluster],
    *,
    config: ReportConfig | None = None,
) -> str:
    """Render a corpus digest: what clusters with what, and what stands alone.

    The tier is printed for every cluster because the tiers are not equally
    strong. ``root-graph`` means two runs share an identical root-cause
    subgraph and is safe to act on; ``evidence-similarity`` is a weighted
    Jaccard score and is a suggestion. Collapsing them into one word called
    "duplicate" would be the whole value of the tiering thrown away.
    """
    config = config or ReportConfig()
    by_key = {entry.key: entry for entry in entries}
    names = _display_labels(entries)
    shown = list(clusters[: config.max_clusters])
    stats = summarise(clusters)

    lines = [
        "# Upgrade failure digest",
        "",
        f"{plural(len(entries), 'run')} diagnosed. "
        f"{plural(stats['clusters'], 'cluster')} covering "
        f"{plural(stats['duplicates'], 'candidate duplicate')}; "
        f"largest cluster {stats['largest']:,}.",
        "",
        "Clusters are built from log-derived structure only -- the root-cause "
        "subgraph, the causes, the phase -- and never from titles, tags or "
        "descriptions. Two reports of the same fault therefore group even when "
        "they describe it in different words or different languages.",
        "",
    ]

    by_cause: dict[Cause, list[RunEntry]] = {}
    for entry in entries:
        primary = entry.result.primary
        cause = primary.cause if primary else Cause.UNKNOWN
        by_cause.setdefault(cause, []).append(entry)
    lines += ["## By cause", "", "| Cause | Runs |", "| --- | --- |"]
    for cause, group in sorted(by_cause.items(), key=lambda kv: (-len(kv[1]), kv[0].value)):
        lines.append(f"| `{cause.value}` | {len(group):,} |")
    lines.append("")

    if shown:
        lines += ["## Clusters", ""]
        for cluster in shown:
            lines += _cluster_block(cluster, by_key, names, config)
        if len(clusters) > len(shown):
            lines += [f"… and {len(clusters) - len(shown):,} further cluster(s).", ""]

    clustered = {member for cluster in clusters for member in cluster.members}
    singletons = [entry for entry in entries if entry.key not in clustered]
    if singletons:
        lines += [
            "## Unmatched",
            "",
            "No other run in this corpus shares their structure. That is not "
            "evidence of uniqueness: a corpus of "
            f"{plural(len(entries), 'run')} will not find a pair for "
            "everything, and these may well match something outside it.",
            "",
        ]
        for entry in singletons:
            lines.append(f"- {names[entry.key]}: {entry.title.detail}")
        lines.append("")

    invalid = [e for e in entries if e.result.is_candidate_invalid]
    if invalid and config.separate_third_party:
        lines += [
            "## Candidate Invalid",
            "",
            "The primary cause in each of these is a package Ubuntu does not "
            "ship. They can usually be dispatched together, but each still "
            "wants a human's eye.",
            "",
        ]
        for entry in invalid:
            lines.append(f"- {names[entry.key]}: {entry.title.detail}")
        lines.append("")

    needs_human = [
        e
        for e in entries
        if (p := e.result.primary) is None or p.cause.needs_human or not e.title.confident
    ]
    if needs_human and config.show_needs_human:
        lines += [
            "## Needs a human read",
            "",
            "Either no rule matched, or the evidence was too thin to name a cause with confidence.",
            "",
        ]
        for entry in needs_human:
            why = (
                "no rule matched"
                if entry.result.primary is None
                else ("low confidence" if not entry.title.confident else "unrecognised cause")
            )
            lines.append(f"- {names[entry.key]}: {why}")
        lines.append("")

    incomplete = [e for e in entries if not e.run.evidence_complete]
    if incomplete:
        lines += [
            f"## Incomplete evidence ({len(incomplete)})",
            "",
            "Diagnosed from partial logs. Treat their causes as provisional "
            "and their absence from a cluster as uninformative.",
            "",
        ]
        for entry in incomplete:
            present = ", ".join(s.value for s in entry.run.logs_present) or "nothing usable"
            lines.append(f"- {names[entry.key]}: {present}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
