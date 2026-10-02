# uru-doctor

> [!NOTE]
> `uru-doctor` is written largely in conjunction with Claude Opus 5.5 using OpenCode

Diagnose, deduplicate and retitle Ubuntu Release Upgrader bugs from their
upgrade logs.

`ubuntu-release-upgrader` bugs arrive in bulk, with titles like "upgrade
failed" and an apt resolver trace tens of thousands of lines long. The same
archive fault arrives a dozen times under a dozen different descriptions, and
the packages a reporter blames are usually the victims rather than the cause.
This reads the logs, works out which package actually stopped the upgrade,
groups the reports that share that cause, and proposes a title that names it.

Everything it concludes comes from the logs. Bug titles, descriptions, tags and
reporter prose are never inputs to a diagnosis or a duplicate grouping — that
is enforced by tests, not just intended — because a tool that learns from
triage prose reproduces the triage mistakes already in the corpus.

It proposes; it does not act. There is no code here that can write to
Launchpad.

## Install

```sh
uv sync
uv run uru-doctor --help
```

Python 3.12 or newer. Runtime dependencies are `pydantic`, `typer`, `rich` and
`httpx`.

## Use

Point it at a log directory — your own machine's, or one unpacked from a bug:

```sh
uru-doctor diagnose /var/log/dist-upgrade
```

On a machine whose upgrade worked, it says so, which is less trivial than it
sounds; see *How it decides* below.

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

A machine-readable record:

```sh
uru-doctor diagnose /var/log/dist-upgrade --json
```

Every command that answers a question can answer it to a script: `diagnose`,
`fetch`, `sweep`, `ingest`, `dedup`, `related`, `history`, `coverage`, `show`
and `stats` all take `--json`. The record carries a `schema` number so a
consumer can refuse one it predates, and it reports lexer coverage alongside
the verdict — because "I could not read a tenth of this log" qualifies a
diagnosis, and a consumer that cannot see it cannot apply the check the tool
applies to itself.

`--strict` exits `3` when a log parsed imperfectly, on `diagnose`, `fetch`,
`sweep`, `ingest` and `coverage`. It is on the collecting commands
deliberately: a new apt version turns up in a sweep long before anyone points
`diagnose` at it — which is exactly how the `Or group remove` gap was found.

Anything that takes time shows progress: `sweep`, `fetch`, `ingest`, `dedup`,
`coverage`, `stats` and `diagnose`. Launchpad is paced at three seconds a
request, so a bug costing six requests spends eighteen seconds waiting, and the
bar names what it is waiting on — `LP#2169035 pacing 2.2s`, `GET
6003872/data`, `HTTP 429, waiting 42s (attempt 2 of 6)`.

The bar is drawn on whichever stream is not carrying the document, and is
switched off entirely when that stream is not a terminal. So
`uru-doctor sweep --json > runs.json` still writes nothing but JSON, and
`uru-doctor title DIR` still prints one line fit for a pipe.

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
bugs somebody already decided were interesting — reintroducing exactly the
selection bias the rest of the design removes.

`sweep` keeps a watermark and is resumable, because it has to be: six requests
per bug at three seconds each makes a hundred bugs half an hour, and Launchpad
answers 429 readily. The mark advances only over bugs actually stored and never
moves backward, so an interrupted pass loses nothing and the next one continues.
It reports how many remain.

Closed bugs are included deliberately. Launchpad's search omits them by
default — measured, that hid two `Won't Fix` bugs in one sample week — and a
bug's own resolution is the second-strongest ground truth there is, so taking
the default would quietly exclude the best evidence for whether this tool is
right. `sweep` also records each bug's status, which `searchTasks` returns for
free.

The first live sweep found a grammar gap on its first run: two lines of
`Or group remove for teamviewer:amd64` in LP#2168863, dropping coverage to
99.9527%. `Or group keep for` had been enumerated and its sibling had not —
both sit adjacent to each other in `libapt-pkg`. That is what the coverage
gate is for.

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

`history` keeps the roles apart. `libpeas-1.0-1` is a root in three bugs across
two different release pairs, which is what an archive transition looks like;
`eog` turns up in three bugs and causes none of them, and gets told so:

```
never a root in this corpus -- implicated only as a victim, which is
evidence against blaming it
```

That inversion is the thing this tool exists to correct, so the two roles are
never summed into one number.

Check how much of the corpus was actually read:

```sh
uru-doctor coverage --strict
```

The grammar-gap loop as a command. It names the run with the gap, lists the
masked shapes a new pattern gets written from — variants of one shape collapse
into one entry with a count — and separates a line that would not lex from one
that lexed and no rule claimed, because those are different repairs.

### Commands

| | |
| --- | --- |
| `diagnose DIR` | Diagnose a log directory. Leaves no state behind. |
| `title DIR` | Print only the proposed title. |
| `ingest DIR...` | Add runs to the record store, for corpus work. |
| `sweep` | Collect newly reported bugs from Launchpad. Resumable. |
| `fetch BUG_ID...` | Fetch named bugs from Launchpad and diagnose them. |
| `dedup` | Group stored runs that report the same fault. |
| `related KEY` | Stored runs reporting the same fault as this one, in tiers. |
| `history PKG` | Which runs implicate a package, as root or as victim. |
| `coverage` | How much of the stored corpus the lexer recognised. |
| `show KEY` | Re-render a stored run's report. |
| `rules` | List the diagnostic rules; `--explain NAME` for one. |
| `stats` | Summarise the record store, with corpus-wide lexer coverage. |

Exit codes: `0` success, `1` failure, `2` bad usage, `3` for `--strict` when a
log parsed imperfectly. Three is separate because "I could not read part of
this log" is a different answer from "this bug has no diagnosis".

## How it decides

**The resolver trace is a graph, not a list of errors.** apt's debug output
names every package it considered breaking. Most of those are consequences.
Blame edges — `Breaks` and unsatisfiable `Depends` — are followed to the nodes
where blame originates, which reduces eighty-six broken packages to eleven
roots, one of which owns forty of them. The root is what gets named.

**apt's own error message is evidence, and it was being ignored.** When apt
gives up it names a *mechanism*: `Unable to correct problems, you have held
broken packages` implicates a hold, not whichever conflict happens to be
largest. On bug 2150245 the biggest root is `gir1.2-gio-2.0` with 98 victims —
real, and not the failure, because apt resolved it and moved on. Ranking by
blast radius alone put the resolved conflict above the unresolved one.

**Non-convergence is a distinct failure.** A livelocked package strands almost
nothing, so any ranking by consequence buries it. But when apt reverses its
decision on a package nineteen times and is still doing so when the trace ends,
the reason the upgrade failed is that the resolver never finished, and the
error it printed names no package at all. The thresholds are measured, not
chosen: reversal counts in the corpus are bimodal, 1–2 for noise and 16–20 for
real livelocks, with nothing in between.

**A successful upgrade needs a positive finding.** A clean resolve is not a
quiet one — apt breaks and repairs packages as it searches — so a working
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
drops a tier between two passes has two possible explanations — the logs
describe different faults, or the tool changed underneath — and without the
stamp they are indistinguishable. The digest covers what can change a ranking
(priority, severity, confidence, which rules exist) and deliberately not
prose, because a reworded remedy that looks like a policy change makes the
warning noise.

**Translated logs.** apt's error stack and all of `apt-term.log` are
translated; the resolver verbs are not. Dependency names *are*
(`Depèn`, `Dipende`, `Va in conflitto`), and enumerating the English ones cost
31% of coverage on a Catalan log. Known English messages are forward-translated
through the system gettext catalogues, with fallback anchors that survive
translation — `pkgProblem::Resolve` keeps its identifier even in French.

## What it will not do

It will not tell you a bug is Invalid. Third-party findings get their own
section labelled *candidate* Invalid, and that is as far as it goes. The
judgement belongs to someone accountable for it.

It will not guess which PPA a package came from. The upgrader writes a flat
`Foreign` list with no origin attached, so grouping by PPA would mean inferring
from package-name suffixes and presenting the inference as fact.

It will not use the bug's own words. See above; this is the constraint the
design is built around. There is no model in the loop either: a `[llm]` config
section and a `title.llm_polish` flag existed as unimplemented design intent,
and both are now gone — a documented-but-inert option that contradicts the
central claim is an invitation to implement it. A config file containing
`[llm]` is refused rather than ignored, and the SQLite cache that existed to
serve it is dropped. If a model is ever wanted here, the narrow defensible use
is drafting prose *from* a finished finding, never producing or ranking one.

It will not conflate the four things called "broken". On bug 2150245 apt
reports 22, 434 packages were observed broken at some point during resolution,
148 are the targets of blame edges, and the graph holds 964 nodes. All four are
correct answers to different questions, and the report labels which is which.

## Configuration

Optional. `uru-doctor.toml` at the root of a corpus, or `--config`. The
checked-in file documents every option that something actually reads, and lists
the ones that are defined but not yet wired up rather than presenting them as
settings. A test enforces both directions.

Logs read from disk are redacted by default — hostnames, usernames, home
paths, emails, IPs — because the Markdown report quotes log lines verbatim for
pasting into a public bug.

## Development

```sh
uv run pytest
uv run ruff check src tests
uv run mypy src/uru_doctor
```

The test corpus is 37 recorded fixtures from real Launchpad bugs in three
languages, with provenance in `tests/fixtures/MANIFEST.md`. The lexer is held
at **100% coverage over 29,037 lines of real apt logs across twelve traces**:
not 99.9%, because an unrecognised line is a silently dropped fact rather than
a visible error.

Ground truth for the recorded bugs is checked against outcomes that are
independent of this tool — the upstream fix, the bug's resolution, the log read
by hand — in that order. Triager tags are the weakest evidence and sometimes
wrong: bug 2155743 is tagged `third-party-packages` and has 46 foreign packages
installed, none of which is the cause.

`.opencode/skills/triage-new-bug/` holds the workflow for validating the tool
against a new bug, including the ordered checks that have to pass before a
verdict means anything.

## Licence

GNU General Public License, version 2 or later (`GPL-2.0-or-later`). The full
text is in [`LICENSE`](LICENSE), copied verbatim from
`/usr/share/common-licenses/GPL-2`.

These are the same terms as
[`ubuntu-release-upgrader`](https://code.launchpad.net/~ubuntu-core-dev/ubuntu-release-upgrader/trunk),
whose `debian/copyright` declares GPL-2+ for everything but one imported test
helper. Matching deliberately: this tool reads that package's logs, quotes its
message strings, and cites its functions as provenance, so code should be able
to move in either direction — a diagnosis that turns out to belong in
`DistUpgradeQuirks` should be contributable without a licence conversation.
