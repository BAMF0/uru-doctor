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

### Commands

| | |
| --- | --- |
| `diagnose DIR` | Diagnose a log directory. Leaves no state behind. |
| `title DIR` | Print only the proposed title. |
| `ingest DIR...` | Add runs to the record store, for corpus work. |
| `fetch BUG_ID...` | Fetch bugs from Launchpad and diagnose them. |
| `dedup` | Group stored runs that report the same fault. |
| `show KEY` | Re-render a stored run's report. |
| `rules` | List the diagnostic rules; `--explain NAME` for one. |
| `stats` | Summarise the record store. |

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
design is built around.

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

Every source file carries an `SPDX-License-Identifier` line. The copyright
holder is **not** yet asserted anywhere: the author address is a Canonical one,
which usually means the employer holds copyright, and that is not something to
guess at. Add a `Copyright (C)` line to the files and a `debian/copyright` if
this is ever packaged.
