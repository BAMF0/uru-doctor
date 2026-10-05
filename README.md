# uru-doctor

Diagnose, deduplicate and retitle Ubuntu Release Upgrader bugs from their
upgrade logs.

`ubuntu-release-upgrader` bugs arrive in bulk, with titles like "upgrade
failed" and an apt resolver trace tens of thousands of lines long. The same
archive fault arrives a dozen times under a dozen different descriptions, and
the packages a reporter blames are usually the victims rather than the cause.
This reads the logs, works out which package actually stopped the upgrade,
groups the reports that share that cause, and proposes a title that names it.

Everything it concludes comes from the logs. Bug titles, descriptions, tags and
reporter prose are never inputs to a diagnosis or a duplicate grouping, and
that is enforced by tests rather than merely intended: a tool that learns from
triage prose reproduces the triage mistakes already in the corpus.

It proposes rather than acts. There is no code here that can write to
Launchpad.

## Install

```sh
uv tool install git+https://github.com/BAMF0/uru-doctor.git
uru-doctor --version
```

Python 3.12 or newer. Runtime dependencies are `pydantic`, `typer`, `rich` and
`httpx`. To work on the tool itself rather than use it, see *Development*
below.

## Quickstart

Point it at a log directory, whether your own machine's or one unpacked from a
bug:

```sh
uru-doctor diagnose /var/log/dist-upgrade
```

On a machine whose upgrade worked, it says so, which is less trivial than it
sounds. See *How it decides* below.

```
───────────────────────── /var/log/dist-upgrade ─────────────────────────
proposed title   resolute→stonking: the upgrade completed with no error
                 recorded
cause            upgrade_succeeded
confidence       strong
release          resolute→stonking
stopped at       POST_INSTALL_SCRIPTS
wrote to system  yes
logs             apt-term.log, apt.log, history.log, main.log, screenlog.0,
                 xorg_fixup.log
lexer coverage 100.0000%  (0 of 447 lines unrecognised)
```

On the logs from bug 2150245:

```
──────────────────────────────── 2150245 ────────────────────────────────
proposed title   noble→resolute: third-party libwacom9-surface cannot be
                 upgraded, blocking 50 packages
cause            third_party_pin
confidence       strong, corroborated by apt
blast radius     50 packages
fragile          yes -- near-tied resolver scores
release          noble→resolute
stopped at       CALCULATE
wrote to system  no
logs             apt.log, main.log
third party      candidate Invalid
lexer coverage 100.0000%  (0 of 3,695 lines unrecognised)
```

A full report, suitable for pasting into a bug:

```sh
uru-doctor diagnose /var/log/dist-upgrade --markdown -o report.md
```

Just the title, for piping:

```sh
uru-doctor title /var/log/dist-upgrade
```

Fetch bugs from Launchpad, anonymously, and build a corpus:

```sh
uru-doctor fetch 2150339 2151847 2169028
uru-doctor dedup
```
```
3 runs: 1 cluster covering 2 candidate duplicates
tier        master      duplicates
root-graph  LP#2150339  LP#2151847, LP#2169028
```

Those three were filed separately, by three reporters, describing three
different packages. They are one `libpeas-1.0-1` transition, and nobody had
linked them.

Or let it find the bugs itself, which is the usual way in:

```sh
uru-doctor sweep --dry-run     # what would this cost?
uru-doctor sweep
```

```
25 tasks since 2026-09-28; 25 new bugs
bug         status       reported
LP#2168855  Incomplete   2026-09-29
LP#2168863  New          2026-09-29
LP#2168919  Won't Fix    2026-09-29
...
~48 requests, ~2 min at the configured pacing
```

Without this the queue is curated by hand, which means the tool only ever sees
bugs somebody already decided were interesting, reintroducing exactly the
selection bias the rest of the design removes.

Ask the corpus about a fault, or about a package:

```sh
uru-doctor related lp:2150339#0
uru-doctor history libpeas-1.0-1
```

```
root-graph   identical root-cause subgraph; safe to act on
  same subgraph       LP#2151847
cause-tuple  same causes and roots, same phase
  same cause tuple    LP#2169028
```

A shared root package alone is reported as a count, not a verdict. One root
in common out of eleven is a coincidence worth a glance, all of them is the
same fault, and the tool does not pretend to know where the line is.
`history` keeps the roles apart. `libpeas-1.0-1` is a root in three bugs across
two different release pairs, which is what an archive transition looks like.
`eog` turns up in three bugs and causes none of them, and gets told so:

```
never a root in this corpus -- implicated only as a victim, which is
evidence against blaming it
```

That inversion is the thing this tool exists to correct, so the two roles are
never summed into one number.

Then ask what is actually left to do:

```sh
uru-doctor refresh    # two requests
uru-doctor queue
```

```
18 bugs waiting on a decision of 44 in the corpus
Launchpad state as of 0h ago

mark-duplicate  2 ───────────────────────────────────────────────────────
Same root-cause subgraph as an earlier bug, which Launchpad has not linked.
The strongest tier there is: safe to act on.
bug         status     cause              proposed action
LP#2169106  Confirmed  resolver_livelock  mark as a duplicate of LP#2169035
LP#2169157  New        resolver_livelock  mark as a duplicate of LP#2168855

diagnosed-unrecorded  6 ─────────────────────────────────────────────────
Confidently diagnosed, but the status does not say so. Nothing is wrong;
nobody has written it down.
...
26 bugs need nothing: 2 Confirmed, 7 Fix Released, 1 Invalid, 9 Triaged,
2 Won't Fix, 3 already a duplicate
```

A diagnosis is not a triage decision, and the gap between the two is where
work accumulates: a duplicate nobody marked, a cause nobody recorded, a
third-party bug nobody closed. `queue` is that gap, in buckets ordered by how
safe the proposed action is.

Rows leave the list because *Launchpad* changed — a status was set, a duplicate
was marked — and never because the tool noted you looking at one. There is no
local "done" flag, deliberately: it would be a second opinion about a fact
Launchpad already owns, and the two would diverge the first time anyone used
the web UI. The cost of that choice is that the list is exactly as current as
the last `refresh`, so it carries its own age and says when that age has
stopped being good enough.

`refresh` is built to be run without thinking about it. `searchTasks` returns
each bug's status in the task entry, so one request covers fifty bugs, and
asking only for bugs *modified* since the last pass makes the steady state two
requests however large the corpus is. Bugs the search does not return were not
modified, which is positive evidence that what is already recorded is still
current — provided the listing reached the end, which the tool checks, because
this package has more bugs than any listing will page through.

Check how much of the corpus was actually read:

```sh
uru-doctor coverage --strict
```

The grammar-gap loop as a command. It names the run with the gap, lists the
masked shapes a new pattern gets written from (variants of one shape collapse
into one entry with a count), and separates a line that would not lex from one
that lexed and no rule claimed, because those are different repairs.

## Commands

### Inspect one upgrade

| | |
| --- | --- |
| `diagnose DIR` | Diagnose a log directory. Leaves no state behind. |
| `title DIR` | Print only the proposed title, for piping. |

### Collect the corpus

| | |
| --- | --- |
| `ingest DIR...` | Add runs to the record store, for corpus work. |
| `fetch BUG...` | Fetch named bugs from Launchpad and diagnose them. |
| `sweep` | Collect newly reported bugs from Launchpad. Resumable. |

### Examine the corpus

| | |
| --- | --- |
| `dedup` | Group stored runs that report the same fault. |
| `related KEY` | Stored runs reporting the same fault as this one, in tiers. |
| `history PKG` | Which runs implicate a package, as root or as victim. |
| `coverage` | How much of the stored corpus the lexer recognised. |
| `show KEY` | Re-render a stored run's verdict; `--markdown` for the full report. |
| `rules` | List the diagnostic rules; `--explain NAME` for one. |
| `stats` | Summarise the record store, with corpus-wide lexer coverage. |

### Act on the corpus

| | |
| --- | --- |
| `queue` | What still needs a decision, in buckets. `--bucket NAME` for one. |
| `refresh` | Re-read Launchpad's status on stored bugs. Two requests. |

Every command takes `-h`/`--help`. The twelve that answer a question also take
`--json`: `diagnose`, `ingest`, `fetch`, `sweep`, `dedup`, `related`,
`history`, `coverage`, `show`, `stats`, `queue` and `refresh`.

## Behaviour

**Machine-readable output.** Every `--json` record carries a `schema` number,
so a consumer can refuse one it predates, and reports lexer coverage alongside
the verdict, because "I could not read a tenth of this log" qualifies a
diagnosis and a consumer that cannot see it cannot apply the check the tool
applies to itself.

**Imperfect parses.** `--strict` exits `3` when a log parsed imperfectly, on
`diagnose`, `fetch`, `sweep`, `ingest` and `coverage`. It is on the collecting
commands deliberately: a new apt version turns up in a sweep long before
anyone points `diagnose` at it.

**Progress and pacing.** Anything that takes time shows progress: `sweep`,
`fetch`, `ingest`, `dedup`, `coverage`, `stats` and `diagnose`. Launchpad is
paced at three seconds a request, so a bug costing six requests spends
eighteen seconds waiting, and the bar names what it is waiting on:
`LP#2169035 pacing 2.2s`, `GET 6003872/data`, `HTTP 429, waiting 42s (attempt
2 of 6)`. The bar is drawn on whichever stream is not carrying the document
and is switched off entirely when that stream is not a terminal, so
`uru-doctor sweep --json > runs.json` still writes nothing but JSON and
`uru-doctor title DIR` prints one line fit for a pipe.

**Sweeps are resumable.** A hundred bugs at six requests each is half an hour,
and Launchpad answers 429 readily and takes about a minute to forgive one.
Requests are therefore spaced rather than parallelised, ETags are cached, and
`sweep` keeps a watermark. The mark advances only over bugs actually stored
and never moves backward, so an interrupted pass loses nothing and the next
one continues. It reports how many remain.

**Closed bugs stay in.** Launchpad's search omits closed bugs by default, and
a bug's own resolution is the second-strongest ground truth there is. Taking
the default would quietly exclude the best evidence for whether this tool is
right, so closed bugs are included. `sweep` also records each bug's status,
which `searchTasks` returns for free.

**Duplicates stay in too, for the same reason and a sharper one.**
`searchTasks` also omits bugs marked as duplicates by default. Measured on
2026-10-05 over one week of release-upgrader reports, the default returned 36
tasks and `omit_duplicates=false` returned 49 — hiding thirteen bugs. Four of
the thirteen were already in the local corpus, stored as `New` with no
duplicate recorded, because they had been swept *before* anyone marked them.
So a bug does not merely start out invisible: it *becomes* invisible the moment
somebody triages it, which is exactly when a triage tool needs to notice. Two
of those thirteen, 2169028 and 2169157, are duplicates of 2168855 — which is
the master this tool had already picked for them from the logs alone, at
`root-graph` tier.

**Launchpad's verdict is cached, not merged into the record.** `bug_state` is
a table of its own, keyed by bug rather than by run, and refreshing it never
rewrites a stored `UpgradeRun`. A diagnosis has to stay reproducible from the
record, and a record edited after the fact by a network call is not that. So
`UpgradeRun.bug_status` keeps its own meaning — what Launchpad said when the
bug was ingested — and the table holds what it says now. Neither is ever an
input to a diagnosis or a signature.

## Exit status

| Code | Meaning |
| --- | --- |
| `0` | success |
| `1` | failure |
| `2` | bad usage |
| `3` | `--strict` found a log that parsed imperfectly |

Three is separate because "I could not read part of this log" is a different
answer from "this bug has no diagnosis".

## How it decides

**The resolver trace is a graph, not a list of errors.** apt's debug output
names every package it considered breaking. Most of those are consequences.
Blame edges (`Breaks` and unsatisfiable `Depends`) are followed to the nodes
where blame originates, which reduces eighty-six broken packages to eleven
roots, one of which owns forty of them. The root is what gets named.

**apt's own error message is evidence.** When apt gives up it names a
*mechanism*: `Unable to correct problems, you have held broken packages`
implicates a hold, not whichever conflict happens to be largest. On bug
2150245 the biggest root is `gir1.2-gio-2.0` with 98 victims: real, but not
the failure, because apt resolved it and moved on. Ranking by blast radius
alone would put the resolved conflict above the unresolved one.

**Non-convergence is a distinct failure.** A livelocked package strands almost
nothing, so any ranking by consequence buries it. But when apt reverses its
decision on a package nineteen times and is still doing so when the trace ends,
the reason the upgrade failed is that the resolver never finished, and the
error it printed names no package at all. The thresholds come from the corpus:
reversal counts are bimodal, 1–2 for noise and 16–20 for real livelocks, with
nothing in between.

**The upgrader's own conclusion outranks the graph.** When no desktop
metapackage is installed the upgrader guesses one and marks it, and the upgrade
stops if that fails. The metapackage is then broken by a single unsatisfiable
dependency, so it strands nothing and loses every ranking by consequence to
roots apt had already resolved and moved past. Three reports of exactly that —
2168863, 2168909 and 2168919 — came back as three different causes
(`holdback_blocks_new_dep`, `update_failed`, `transitional_breaks`), none right
and no two clustered. A statement about why the run ended beats an inference
about a decision made on the way there. It still loses to non-convergence,
because a livelocked resolver is *why* the mark failed.

**A message is not a failure unless the run stopped.** The upgrader refreshes
the package lists twice: once before rewriting `sources.list`, where failure is
expected because the user's existing entries may be unreachable and the result
is discarded, and once after, where failure aborts. Both log the same line. One
dead PPA therefore writes `doUpdate() failed completely` into every upgrade
including the successful ones, and because the environment is ranked above the
packages — correctly, in general — that recovered error took the headline on a
run that died ninety seconds later for an unrelated reason. The discriminator
is in the log: `showErrors=True` marks the call that matters.

**A successful upgrade needs a positive finding.** A clean resolve is not a
quiet one: apt breaks and repairs packages as it searches, so a working
upgrade's trace still contains holdbacks and unsatisfiable virtuals. Without
something that says "nothing went wrong", the largest piece of that transient
churn becomes the answer.

**Duplicates are matched on structure, in tiers, and the tier is always
reported.** `root-graph` means two runs share an identical root-cause subgraph
and is safe to act on. `cause-tuple` is the same causes and roots at the same
phase. `evidence-similarity` is a weighted Jaccard score over log templates and
is a suggestion. Collapsing them into one word called "duplicate" would throw
away the only information that tells you how much to trust it.

**A verdict names the policy that produced it.** Every diagnosed run records
the tool version and a digest over the rules, and `dedup` says so when a
cluster mixes them. Signatures are compared across sessions, so a cluster that
drops a tier between two passes has two possible explanations: the logs
describe different faults, or the tool changed underneath. Without the stamp
they are indistinguishable. The digest covers what can change a ranking
(priority, severity, confidence, which rules exist) and deliberately not
prose, because a reworded remedy that looks like a policy change makes the
warning noise.

**A re-read verdict says when it is not the stored one.** Neither the proposed
title nor the diagnosis is persisted -- both are recomputed from the stored
logs -- so `show` is answering with today's rules about an older record. When
the stamp on that record no longer matches the current rules, `show` says so
on stderr before the report, naming both digests. Otherwise the one case where
re-reading a sweep disagrees with the sweep is the one case that looks like a
bug. `--json` is exempt: it reports the stored findings and the stored stamp,
leaving the comparison to the consumer. Runs stored before stamping existed
carry no digest and are passed over rather than warned about, for the same
reason `dedup` passes over them.

**Translated logs.** apt's error stack and all of `apt-term.log` are
translated, but the resolver verbs are not. Dependency names *are* (`Depèn`,
`Dipende`, `Va in conflitto`), so known English messages are forward-translated
through the system gettext catalogues, with fallback anchors that survive
translation. `pkgProblem::Resolve` keeps its identifier even in French.

## What it will not do

It will not tell you a bug is Invalid. Third-party findings get their own
section labelled *candidate* Invalid, and that is as far as it goes. The
judgement belongs to someone accountable for it. `queue` holds the same line:
it proposes, counts and orders, and the one bucket that touches this is called
`candidate-invalid` and says the call is yours. Note that the test is the
*primary* cause only — any machine with a few PPAs has one implicated
somewhere, and the broader test flags bugs whose real cause is an Ubuntu
package. In the development corpus that is three bugs out of four.

It will not remember what you have done. There is no local "triaged",
"acknowledged" or "dismissed" state anywhere, and `queue` derives every row
from Launchpad's current status and duplicate links. A local flag would be a
second opinion about a fact Launchpad owns.

It will not guess which PPA a package came from. The upgrader writes a flat
`Foreign` list with no origin attached, so grouping by PPA would mean inferring
from package-name suffixes and presenting the inference as fact.

It will not use the bug's own words. See above: this is the constraint the
design is built around. There is no model in the loop either, and a config
file containing an `[llm]` section is refused rather than ignored. If a model
is ever wanted here, the narrow defensible use is drafting prose *from* a
finished finding, never producing or ranking one.

It will not conflate the four things called "broken". On bug 2150245 apt
reports 22, 434 packages were observed broken at some point during resolution,
148 are the targets of blame edges, and the graph holds 964 nodes. All four are
correct answers to different questions, and the report labels which is which.

## Configuration

Optional. `uru-doctor.toml` at the root of a corpus, or `--config FILE`. The
checked-in file documents every option that something actually reads, and lists
the ones that are defined but not yet wired up rather than presenting them as
settings. A test enforces both directions.

State lives in `.uru-doctor/` at the corpus root: the record store that
`dedup`, `related`, `history`, `coverage`, `show`, `stats` and `queue` read,
and the attachment cache that `fetch` and `sweep` fill. The `[paths] state_dir`
option moves it. `diagnose` and `title` leave nothing behind.

The corpus-wide commands are built to stay usable at a corpus of thousands:
`queue`, `refresh` and `dedup`'s default output read indexed columns only, and
clustering is a linear hash bucket over two indexed signature columns. Only
`dedup --markdown`, which quotes titles and per-run facts, needs the stored
records themselves.

Logs read from disk are redacted by default (hostnames, usernames, home paths,
emails, IPs) because the Markdown report quotes log lines verbatim for pasting
into a public bug.

## Development

```sh
uv sync
uv run pytest
uv run ruff check src tests
uv run mypy src/uru_doctor
```

`.opencode/skills/triage-new-bug/` holds the workflow for validating the tool
against a new bug, including the ordered checks that have to pass before a
verdict means anything. [AGENTS.md](AGENTS.md) holds the rest of the
contributor guidance: the test-corpus policy and coverage gates, the design
invariants a change must preserve, and the traps that have already bitten.

`uru-doctor` is written largely in conjunction with Claude Opus 5.5 using
OpenCode.

## Licence

GNU General Public License, version 2 or later (`GPL-2.0-or-later`). The full
text is in [`LICENSE`](LICENSE). These are the same terms as
[`ubuntu-release-upgrader`](https://code.launchpad.net/~ubuntu-core-dev/ubuntu-release-upgrader/trunk),
whose logs this tool reads and whose message strings it quotes, so a diagnosis
that turns out to belong in `DistUpgradeQuirks` can move upstream without a
licence conversation.
