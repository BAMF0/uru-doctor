---
name: triage-new-bug
description: Use when validating or improving uru-doctor against new Ubuntu release-upgrader bug reports. Triggers on a Launchpad bug URL or number (bugs.launchpad.net, LP#2169197, "check this bug", "try these bugs"), on "verify the diagnosis", "the title is wrong", "coverage dropped", or on adding apt.log, main.log, apt-term.log or history.log fixtures. Covers fetching logs within Launchpad's rate limits, the ordered verification gates, establishing ground truth, and recording fixtures with tests.
---

# Triaging a new bug against uru-doctor

A new bug is a test of the tool, not a task for it. The goal of this workflow is
to find out where the tool is **wrong**, and the main obstacle is that it is
almost never wrong loudly. A log it cannot lex produces a confident diagnosis of
a fraction of the evidence. A signature field dropped in silence produces a
slightly worse answer. Every correctness problem found so far looked like a
plausible result until something was measured.

So: measure first, read the logs second, form an opinion last.

## 1. Fetch

```bash
uv run .opencode/skills/triage-new-bug/scripts/fetch_bug.py 2169197 2169251
```

Facts the script encodes, worth knowing if you work around it:

- **`webfetch` does not work on Launchpad.** It gets blocked. `curl` and
  `urllib` are fine.
- **The API answers HTTP 429 under load** and wants roughly a minute to
  recover. Space requests ~3s apart and back off on 429, or a corpus pass dies
  halfway leaving truncated files.
- **Do not fetch every attachment.** `Dependencies.txt`,
  `CurrentDmesg.txt.txt`, `JournalErrors.txt`, the apt-clone tarball and
  screenshots hold no upgrade evidence. `is_irrelevant_attachment()` is the
  authority; the script reads it so the two cannot drift apart.
- **A bug with no logs is still a test case.** LP#2161332 attached two
  screenshots. The correct output is `no upgrade logs were attached`, and
  getting that honest rather than inventing a cause is worth checking.

### Finding bugs to fetch

`uru-doctor sweep` does this now, and is the normal way in:

```bash
uru-doctor sweep --dry-run        # what would a pass cost?
uru-doctor sweep --limit 5        # fetch, diagnose, store
```

It keeps a watermark, includes closed bugs, records each bug's status, and is
resumable. Prefer it to driving `searchTasks` by hand. What follows is the API
detail behind it, which still matters if you are debugging the sweep itself.

`searchTasks` on the source package lists them, and is a plain read-only GET:

```
https://api.launchpad.net/devel/ubuntu/+source/ubuntu-release-upgrader
  ?ws.op=searchTasks&created_since=YYYY-MM-DD&ws.size=50
```

Verified against the live API. Each entry carries `bug_link` (the id is its
last path segment), `status`, `date_created` and an `http_etag`;
`next_collection_link` paginates and `total_size` comes back `null`, so count
the entries rather than trusting a total.

Three findings worth having:

- **`status` is in the task entry**, so a sweep gets the bug's own resolution
  without a second request per bug. That matters because the resolution is
  ground-truth rank 2 below, and a per-bug request for it would cost another
  three seconds each. `fetch` therefore leaves `bug_status` empty and `sweep`
  fills it in — tolerable only because the field is used to *check* a
  diagnosis, never to produce one.
- **The default omits closed bugs.** With no `status` parameter the API returns
  only open ones. Over one sample week that hid two `Won't Fix` bugs — and
  closed bugs are exactly where ground truth lives, so a sweep that takes the
  default systematically excludes its own best evidence. `ALL_STATUSES` passes
  all eleven explicitly.
- **Results come back newest-first**, which is the wrong order for a watermark.
  A mark can only advance over bugs already handled, so `search_tasks` sorts
  oldest-first before yielding; processing in arrival order and storing the
  newest timestamp seen would skip everything older on the next run.

At ~3s per request and ~6 requests per bug, a hundred-bug sweep is half an
hour. That is why the watermark is monotonic and advances only over bugs
actually stored: being interrupted is the normal case, not the exceptional one.

Also record, from the bug page: status, `number_of_duplicates`,
`duplicate_of_link`, triager tags, and whether a comment or linked upstream
commit names a cause. That is the ground truth for step 4.

## 2. Run cold

```bash
uv run .opencode/skills/triage-new-bug/scripts/check_bug.py 2169197 2169251
```

Run this **before** reading the logs yourself. Once you have read the apt log
you will find the tool's answer plausible whatever it says, and the one thing
worth protecting is your ability to be surprised by it.

## 3. The gates, in order

The order matters. Each gate makes the ones below it meaningful.

### Gate 1 — lexer coverage must be exactly 100%

Not 99.9%. An unmatched line is a verb the graph cannot see, and the failure
mode is a confident diagnosis of partial evidence.

Available from the tool itself, on every path — this is also the gate you can
apply without the harness:

```bash
uru-doctor diagnose DIR --json | jq '.lex_coverage, .unknown_shapes'
uru-doctor fetch 2169197 --strict   # exit 3 if the trace did not fully lex
uru-doctor coverage --strict        # the whole corpus, worst offender first
```

`uru-doctor coverage` is the one to run after a batch. It names the offending
run, lists the **masked** shapes a new pattern gets written from, and separates
two different repairs: a shape that would not lex needs a pattern in
`apt/grammar.py`, while one that lexed and no rule claimed needs a *rule*.
Variants collapse — two `Zarp 12 Quux 44` / `Zarp 97 Quux 13` lines are one
entry with a count, which is what keeps a gap legible instead of drowning it.

`fetch` could not report coverage at all until the `stats` out-parameter was
threaded into `ingest_attachments`, which is why this harness used to re-lex
`apt.log` by hand. Worth knowing because the two measurements were not the
same: the harness measured `apt.log` alone, the diagnosis used every log, and
nothing compared them. `tests/test_ingest.py::TestCoverageIsReported` now
asserts the two ingest paths agree.

This gate has caught every grammar gap so far:

| Symptom | Cause |
| --- | --- |
| 68.7% on Catalan, 78.6% on Italian | apt prints dependency-type names through `_()`. `Depends` becomes `Depèn`/`Dipende`, and Italian `Conflicts` is `Va in conflitto` — with spaces |
| 5 unmatched of 798 | `Re-Instated <pkg> (N vs N)` — the score-pair variant |
| 7 unmatched | `Package X X Depends on Y <state> (>= V)` — missing optional trailing constraint. Every English occurrence in the corpus happened to be versionless, so the gap was invisible for ten logs |
| 82.9% | `Setting <PKG> NOT as auto-installed (...)`, `Ignore MarkGarbage`, `Removing: ... not an option for ...` |
| 99.9527% on LP#2168863 | `Or group remove for <PKG>`. `Or group keep for` was enumerated and its sibling was not — the two strings sit adjacent in `libapt-pkg`. Found by the first live `sweep`, which is the point of putting coverage on the collecting path |
| 99.7534% on LP#2168919 | German renders `PreDepends` as `Hängt ab von (vorher)`. The dependency position had been widened for *spaces* when Italian `Va in conflitto` appeared, and not for the next punctuation class along. The alias table already resolved the name; the pattern could not reach it, so a unit test on `dep_type` passed throughout |

### Known open gap: upgrader prose inside `apt.log`

Four lines of LP#2168919 still do not lex, and they are **not** a grammar bug
to be fixed the same way:

```
»kubuntu-desktop« kann nicht installiert werden
Es war nicht möglich, ein erforderliches Paket zu installieren. Bitte
melden Sie diesen Fehler, indem Sie im Terminal den Befehl
»ubuntu-bug ubuntu-release-upgrader-core« eingeben.
```

That is the upgrader's own user-facing error, from
`DistUpgradeCache.py:897` (`_("Can't install '%s'")` plus
`_("It was impossible to install a required package. ...")`), interleaved into
`apt.log` because `_stopAptResolverLog()` restores stdout before `view.error`.

Why it is not a one-line fix:

- It is **upgrader prose, not an apt verb**, so it belongs to a different
  grammar than the one the lexer implements.
- The `ubuntu-release-upgrader` gettext domain is **not installed** on a
  machine that merely has `apt`, so the forward-translation trick that handles
  apt and dpkg messages does not apply. Only one of the four lines carries a
  translation-surviving anchor (`ubuntu-bug ubuntu-release-upgrader-core`); the
  rest are pure prose, and enumerating prose in ninety languages is the mistake
  this codebase already refuses to make.
- There is a **real diagnosis** hiding in it — a required meta-package could
  not be installed, and the message names it — so the tempting fix is a new
  rule. That needs ground truth first (§4). LP#2168919 is `Won't Fix`, which
  says nothing about whether `kubuntu-desktop` was the cause.

The honest intermediate position: classify an interleaved upgrader block as
*not a resolver verb* rather than parse its contents, so coverage stops
reporting a grammar gap that is not one. Do not do this by matching prose.

Fix by adding the pattern to `apt/grammar.py`, then re-check **every** fixture —
a widened pattern can swallow lines another pattern was matching.

**Check the whole upstream family, not the line you saw.** `strings` on
`libapt-pkg` is the fastest way:

```bash
strings /usr/lib/*/libapt-pkg.so.* | grep -i "or group"
#   Or group remove for
#   Or group keep for
```

Two of the gaps above were one half of an upstream pair. Adding only the half
that appeared leaves the other invisible until some future log contains it, and
there is no reason to pay for that twice. A verb enum and a pattern table that
cover the pair are also what keeps keep-vs-remove distinguishable downstream:
one shared token would make "apt kept this" and "apt deleted this" the same
fact.

`lex_lines == 0` is **not** a gap. A bug that attached only `main.log`, or two
screenshots like LP#2161332, has nothing to lex, and reporting that as
imperfect would make every log-less bug look like a parser bug — and would make
`--strict` useless on exactly the corpus pass where it should be informative.
Check `lex_lines` before believing `lex_coverage`.

Unknown state flags must likewise be empty. `apt/state.py` decodes all 28
observed shapes; a new one means a new apt version. This one is still only in
the harness: the vocabulary is a property of the scan rather than of the run.

### Gate 2 — did the tool understand the run?

- `release_pair` should not be `unknown→unknown`. One half is fine
  (`noble→?`) when only `apt.log` was attached.
- `locale` drives all i18n. If it is set and non-English, Gate 1 was load-bearing.
- **`evidence_complete`** must be false only when the logs genuinely record no
  ending. A benign `ERROR failed to import AptClone` once made a truncated log
  look complete; see `_BENIGN_ERRORS`.
- **`upgrade_completed`** decides the whole failure class. If the upgrade
  finished and the machine broke afterwards, resolver holdbacks cannot be the
  cause — they appear in every successful upgrade. LP#2169251 is the reference.
- **`dpkg_wrote`** must never be inferred from which files exist alone. apport
  attaches on existence not content; a successful run's first `apt-term.log`
  block is *empty*; `history.log` lists the full planned set even for a no-op
  commit. `main.log` reaching `COMMIT` outranks the absence of dpkg logs.

### Gate 3 — the three "broken" counts are different numbers

For LP#2150245: apt says **22**, observed broken is **434**, blame-edge targets
are **148**, and total graph nodes are **964**. All four are legitimate answers
to different questions. Conflating them produces confident nonsense; an early
version reported 964 broken packages by treating every node as broken.

### Gate 4 — corroboration and third-party evidence

apt names a *mechanism* when it gives up, and that is checkable evidence about
which of a dozen roots actually stopped the upgrade. If `corroborated` is empty
on a bug that has an `E:` line, the match is broken — most likely because the
message is translated.

`candidate_invalid` must reflect the **primary** finding only. Any machine with
a few PPAs has some third-party package implicated somewhere; LP#2155743 has 46
foreign entries including `systemd` and `udev`, **none of which is a root**. A
triager tagged it `third-party-packages` and the log evidence does not support
that. Being third-party makes a root actionable, not causal.

### Gate 5 — livelock, because it outranks blast radius

A livelocked package strands almost nothing, so it is allowed to beat a
hundred-package cascade. That power makes false positives expensive.

- Reversal counts are **bimodal**: 1–2 is normal exploration, 16–20 is a
  livelock, and nothing has ever landed between 3 and 15. If the new bug breaks
  that, the threshold needs re-deriving from the measurement, not nudging.
- `terminal=True` is required. An oscillation apt *escaped* is a detour it
  recovered from. Every genuine one sits at 99–100% through the section.
- Group by **blocker**, not by oscillating package. Several packages stuck on
  one package is one fault. Ungrouped, LP#2151847's primary cause turned on 18
  reversals versus 17 — noise.

### Gate 6 — signature stability

Run the corpus pass and check the cluster **tier**, not just the membership.
A cluster that drops from `root-graph` to `cause-tuple` means the precise
signature stopped matching, and the usual reason is that something in it
depends on *how* it was computed rather than *what* it describes.

**Rule out the tool before suspecting the logs.** Every diagnosed run now
carries `tool_version` and `rules_digest`, so a tier change has a checkable
explanation:

```bash
uru-doctor dedup --json | jq '.clusters[] | select(.policy_drift)'
```

A cluster flagged `policy_drift` mixes runs diagnosed by different rule sets,
and its tier was computed from signatures two different policies produced — so
it is not evidence of anything until the corpus is re-ingested. Re-ingest
first, *then* read the tier. Without the stamp these two causes were
indistinguishable, and the wrong one is much more interesting, so it is the one
that gets investigated.

`rules_digest` deliberately ignores `provenance`, `remedy` and `phase_hint`:
rewording a remedy must not look like a policy change, or the warning becomes
noise and stops being read.

Signatures are persisted and compared across sessions, so anything that varies
with ingest order makes them worthless. Writing this skill's harness — which
builds a fresh interner per bug, unlike the ad-hoc scripts used until then —
surfaced two such faults immediately:

- `canonical_digest` sorted node *indices* and emitted the names in that
  order, so the name sequence followed interning order. The same two logs
  hashed equal through one interner and unequal through two.
- `Root.cascade` holds vertex indices, and the resolver rules assigned them
  straight into `victim_pkgs`, which holds package ids. Both are small
  integers, and with one interner per run a low index resolves to some
  plausible package from the same log, so every victim list had been quietly
  wrong — bug 2150245's victims came back as budgie packages from an unrelated
  report once an interner was shared.

If you add a field to a signature, add it to
`TestSignatureStability` too.

## 4. Establish ground truth before changing anything

The tool disagreeing with a bug title means nothing; titles are the problem it
exists to solve. Rank evidence like this:

1. **An upstream fix.** The strongest. `DistUpgradeQuirks._fix_lintian_resolver_deadlock`
   has `Fixes LP: #2150319` in its docstring and marks `libfile-libmagic-perl`
   for install — which is exactly what the tool concluded from the log alone.
2. **The bug's own resolution.** LP#2150245 closed Invalid with 13 duplicates
   confirms the surface PPA.
3. **The log itself**, read by hand, after the tool has had its turn. Verify
   the mechanism, not the package name: for the libpeas cluster, confirm
   `libpeas-1.0-1 Breaks on libpeas-1.0-0` which apt keeps.
4. **Triager tags.** Weakest. They are a guess, and `third-party-packages` on
   LP#2155743 is one the evidence contradicts.

**Ask the corpus before reading the log.** Two questions the store can answer
that a single bug cannot, and both change what the log means:

```bash
uru-doctor related lp:2150339#0    # same fault, in tiers, strongest first
uru-doctor history libpeas-1.0-1   # root in 3 bugs across 2 release pairs
```

A package that is a root across *different release pairs* is an archive
transition rather than one machine's misconfiguration. And a package that is a
**victim many times and a root never** is evidence against blaming it —
`history eog` reports three bugs and no causes, which is exactly the inversion
this tool exists to correct. `history` keeps the roles apart and never sums
them, because one number would erase that.

If the tool and ground truth agree, record a fixture and move on. If they
disagree, find out which is wrong before writing code.

## 5. Fixing

Principles that have survived contact with eight bugs:

- **Derive thresholds from measured distributions.** `MIN_REVERSALS = 5` sits
  in an empty gap between 2 and 16 observed across the corpus. Print the
  distribution; do not pick a number that makes this bug pass.
- **Prefer upstream strings to invented patterns.** Every rule's `provenance`
  points at a `logging.error` or `_()` call in
  `/usr/lib/python3/dist-packages/DistUpgrade/`. A test enforces it.
- **Use the same catalogues the tools used.** For anything translated, forward-
  translate the known English msgid via `i18n.py` rather than writing per-
  language patterns. Ninety languages cannot be hand-maintained.
- **Fix the layer, not the symptom.** `cluster_runs` not extending across tiers
  was the bug; special-casing 2169028 would not have been.
- **A rule firing is not a rule ranking.** Most wrong answers were ranking
  errors with every rule working. Check `fired` separately from the order.

## 6. Lock it in

Record the fixture with provenance that explains **why it exists**:

```python
# tests/record_fixtures.py  -> SOURCES / LP_SOURCES
(
    (
        "apt/lp2169197-apt.log",
        "/tmp/opencode/aptlogs/new2169197-apt.log",
        "LP#2169197, locale ca_ES. apt prints dependency-type names through _(), "
        "so 'Depends' arrives as 'Depèn' and coverage fell to 68.7% -- most of the "
        "conflict graph simply absent.",
    ),
)
```

```bash
uv run python -m tests.record_fixtures
rg -i "$(whoami)|$(hostname)|@gmail" tests/fixtures/   # must be silent
```

Then write tests that encode the reasoning, not just the result — a test whose
docstring explains what went wrong is what stops the fix being undone. Add the
ground-truth assertion to `TestHeldOutBugs` in `tests/test_diagnose.py`.

Finally, the full regression:

```bash
uv run .opencode/skills/triage-new-bug/scripts/check_bug.py --fixtures
uv run pytest tests/ -q && uv run ruff check src/ tests/ && uv run mypy src/uru_doctor/
```

The `--fixtures` pass is not optional. Two fixes so far looked clean and
changed an earlier bug's answer.

## Traps that have actually bitten

- **`ruff format` silently undoes `python - <<'PY'` string patches.** It
  reflows multi-line calls, so a later `str.replace` finds nothing and reports
  success. Twice this left a parameter unthreaded and the behaviour unchanged.
  After any scripted patch, `grep` for the new text.
- **An out-parameter that one call site forgets is invisible.** `ingest_logs`
  took `stats: LexStats | None`; `ingest_directory` passed it and
  `ingest_attachments` did not. Consequence: `fetch` — the command that meets a
  new apt version *first* — was the one command that could not report whether
  it had understood the log, and the gap survived because the harness measured
  coverage separately and nothing compared the two. Fixed by making the
  function return the measurement instead of accepting somewhere to put it, so
  forgetting is a type error. If a value is load-bearing, do not let it be
  optional at the call site.
- **`CREATE INDEX` in the schema on a column `_migrate` adds.** `_SCHEMA` runs
  before `_migrate`, and its `CREATE TABLE IF NOT EXISTS runs` is a no-op
  against an existing store — so the index statement referenced a column that
  did not exist yet and the store could not be opened *at all*. It worked
  perfectly on a fresh store, which is every test that does not deliberately
  build an old one. Indexes over migrated columns belong in `_migrate`, after
  the `ALTER TABLE`s. `TestAdditiveMigration` builds a genuine schema-1 store
  by dropping the columns back off.
- **A schema version that is never written back.** `_check_version` refused a
  *newer* store and inserted the number only when absent, so a migrated store
  kept claiming version 1 forever and an older build would read it as its own.
  Schema 2 drops a table schema 1 queries unconditionally, so that downgrade
  crashes rather than quietly misreporting — luck, not design.
- **Removing a validator can start leaking what it was validating.**
  `LlmConfig` had a hand-written check that refused an inline `api_key`
  *without quoting it*. Deleting the model handed the job to pydantic's generic
  extra-forbidden path, which embeds `input_value=` — and the CLI prints the
  whole message to stderr. The test still passed, because the secret appearing
  in the error message happened to satisfy `match="api_key"`. A test that
  passes for the wrong reason is worse than no test; `load_config` now renders
  validation failures as locations and reasons only, and
  `test_rejected_values_are_not_echoed` checks the traceback too, because
  `raise ... from exc` would put the original straight back.
- **A watermark that advances past unhandled work.** `sweep` must move the mark
  only over bugs it actually stored, and only to *that bug's* creation date.
  Advancing to the newest task in the listing is the obvious implementation and
  it silently skips every bug between the last one handled and the newest one
  seen — permanently, because once the mark is past a bug's creation date the
  search never offers it again. Also monotonic: a pass cut short by a 429 must
  not rewind a mark a further-reaching pass had already set.
  `test_the_watermark_does_not_pass_unhandled_bugs` fails loudly on both.
- **Launchpad's search defaults exclude closed bugs.** See §1. The ones it hides
  are the ones whose resolution is the ground truth.
- **A progress bar on the wrong console corrupts the output.** Rich moves a live
  region out of the way of `Console.print` only for *its own* console. A bar on
  stderr while verdicts print to stdout is two programs drawing on one
  terminal, and the bar lands in the middle of a report. `_progress()` therefore
  takes the console: stderr when `--json`/`--markdown` is writing a document to
  stdout, otherwise stdout alongside the verdicts. Also off entirely when the
  target is not a terminal, so `2>log` gets no control codes.
- **`total=None` does not clear a Rich task's total.** Both `Progress.reset` and
  `Progress.update` read it as "leave the total alone", so re-purposing a task
  from a counted phase to an uncountable one drew `clustering 0/7` — a bar
  measuring seven of something no longer being counted. Remove and re-add the
  task instead. One task per command, too: adding a second leaves the first
  drawing itself, which stuck `searching Launchpad 0/?` above the real bar for
  a whole sweep.
- **`jaccard([], []) == 1.0`.** A bug with only `apt.log` has no log *events*,
  so two unrelated reports scored a perfect match. Absence of evidence is not
  evidence of similarity.
- **pydantic's default `extra="ignore"`** dropped a whole field with no
  complaint from pydantic or mypy. `Frozen` now sets `extra="forbid"`.
- **`functools.cached_property` does not work on a `slots=True` dataclass.**
- **`str.splitlines()` splits on bare `\r`**, which defeated
  `collapse_carriage_returns` entirely and stored 440 progress fragments as
  separate events.
- **The fixture recorder can destroy its own manifest.** Re-running it after
  `/tmp` is cleaned keeps the committed fixtures and used to delete their
  provenance notes. Fixed, but check `MANIFEST.md` entry count matches the
  fixture count.
- **Directory-based log grouping is unsafe.** `/var/log/dist-upgrade` is
  archived wholesale, so a `YYYYMMDD-HHMM` directory can hold a `main.log` from
  June beside an `apt.log` from January. `check_coherence()` handles it; do not
  reintroduce trust in the directory name.
- **Hardcoded counts in tests** (`assert len(paths) == 3`) break the moment the
  corpus grows. Assert properties.
- **Vertex indices and package ids are both small integers**, so confusing them
  type-checks, runs, and produces plausible-looking package names. `mypy` will
  not catch it: `PkgId` is an `int` alias. If a list of packages looks right
  but *oddly* right, resolve it through two different interners and compare.
- **Unrelated `IntEnum`s compare equal by value.** `root.dep in BLAME_EDGES`
  tests a `DepType` against a set of `EdgeKind` members; it type-checks, and it
  silently selects `RECOMMENDS` and `DEPENDS` because they share the integers 1
  and 6 with `BREAKS` and `UNSATISFIABLE`. Membership tests across two enums are
  always a bug even when the result looks sensible. `Cause` and `LogSource` are
  safe here only because they are `StrEnum`.
- **Interned ids must never be a sort key or a tie-break.** Ids are assigned
  in first-seen order, so any ordering that falls back to one depends on what
  was ingested beforehand. This has now bitten four times: `canonical_digest`
  sorting node indices, `Root.cascade`'s BFS frontier, `detect_oscillations`
  tie-breaking equal reversal counts on `pkg_id` (which decided whether the
  title said `gedit` or `gir1.2-peas-1.0`), and a `set` of forcing packages
  indexed with `[0]`. Sort by name. The giveaway is output that is stable in
  *content* but not in *order* — check the order explicitly, because a set
  comparison will pass.
- **A successful upgrade needs a positive finding.** A clean resolve is not a
  quiet one: apt breaks and repairs packages as it searches, so a working
  upgrade's trace still holds holdbacks and unsatisfiable virtuals. Without
  `upgrader.no-failure` emitting `UPGRADE_SUCCEEDED`, the largest piece of that
  churn became the answer, and pointing the tool at a healthy
  `/var/log/dist-upgrade` reported `libqt5core5t64 could not be resolved` about
  an upgrade that had finished days earlier. Run it on a machine that worked;
  that is the first thing anyone evaluating it will do.
- **A line that matches is not a line that is evidence.** The upgrader logs its
  whole working set on single lines — `Upgrade:` and nine others listed in
  `BULK_LIST_PREFIXES` — so a substring search for any package matches all of
  them, and the match means only "this package was in the upgrade". Filtering
  these by size does not work: real evidence reaches 53 tokens while a short
  `Obsolete:` list is 21, so the bands overlap. Match the known prefixes.

## Where things live

| Concern | File |
| --- | --- |
| apt verbs and patterns | `src/uru_doctor/apt/grammar.py` |
| state blob decoding | `src/uru_doctor/apt/state.py` |
| roots, cascades, causes | `src/uru_doctor/apt/roots.py` |
| oscillation detection | `src/uru_doctor/apt/livelock.py` |
| translated messages | `src/uru_doctor/i18n.py` |
| parse order, coherence | `src/uru_doctor/ingest.py` |
| rules and provenance | `src/uru_doctor/rules/` |
| ranking policy | `src/uru_doctor/diagnose.py` |
| signatures and clusters | `src/uru_doctor/dedup.py` |
| title templates | `src/uru_doctor/title.py` |
| fixture provenance | `tests/record_fixtures.py`, `tests/fixtures/MANIFEST.md` |
