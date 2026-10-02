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

This gate has caught every grammar gap so far:

| Symptom | Cause |
| --- | --- |
| 68.7% on Catalan, 78.6% on Italian | apt prints dependency-type names through `_()`. `Depends` becomes `Depèn`/`Dipende`, and Italian `Conflicts` is `Va in conflitto` — with spaces |
| 5 unmatched of 798 | `Re-Instated <pkg> (N vs N)` — the score-pair variant |
| 7 unmatched | `Package X X Depends on Y <state> (>= V)` — missing optional trailing constraint. Every English occurrence in the corpus happened to be versionless, so the gap was invisible for ten logs |
| 82.9% | `Setting <PKG> NOT as auto-installed (...)`, `Ignore MarkGarbage`, `Removing: ... not an option for ...` |

Fix by adding the pattern to `apt/grammar.py`, then re-check **every** fixture —
a widened pattern can swallow lines another pattern was matching.

Unknown state flags must likewise be empty. `apt/state.py` decodes all 28
observed shapes; a new one means a new apt version.

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
    "apt/lp2169197-apt.log",
    "/tmp/opencode/aptlogs/new2169197-apt.log",
    "LP#2169197, locale ca_ES. apt prints dependency-type names through _(), "
    "so 'Depends' arrives as 'Depèn' and coverage fell to 68.7% -- most of the "
    "conflict graph simply absent.",
),
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
