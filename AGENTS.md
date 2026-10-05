# AGENTS.md

Guidance for agents and contributors working on uru-doctor itself. User-facing
documentation lives in [README.md](README.md). The tool diagnoses, deduplicates
and retitles Ubuntu Release Upgrader bugs from their upgrade logs; it proposes
and never acts.

## Development

```sh
uv sync
uv run pytest
uv run ruff check src tests
uv run mypy src/uru_doctor
```

After any change that affects the grammar, the rules, ranking or fixtures, run
the full regression — two fixes so far looked clean and changed an earlier
bug's answer:

```sh
uv run .opencode/skills/triage-new-bug/scripts/check_bug.py --fixtures
uv run pytest tests/ -q && uv run ruff check src/ tests/ && uv run mypy src/uru_doctor/
```

## Design invariants

Changes must preserve these. Most are enforced by tests; all are deliberate.

- **Logs are the only input** to a diagnosis or a duplicate grouping. Bug
  titles, descriptions, tags and reporter prose are never inputs — a tool that
  learns from triage prose reproduces the triage mistakes already in the
  corpus. Enforced by tests.
- **Proposes, never acts.** No code path writes to Launchpad.
- **No model in the loop.** A config file containing an `[llm]` section is
  refused rather than ignored. The narrow defensible use is drafting prose
  *from* a finished finding, never producing or ranking one.
- **No local triage state.** No "triaged", "acknowledged" or "dismissed" flags
  anywhere; `queue` derives every row from Launchpad's current status and
  duplicate links. Rows leave the list because Launchpad changed.
- **Verdicts are not persisted.** Titles and diagnoses are recomputed from the
  stored logs on every read. Records carry `tool_version` and `rules_digest`;
  the digest covers what can change a ranking (priority, severity, confidence,
  which rules exist) and deliberately not prose, so a reworded remedy must not
  look like a policy change. `dedup` reports `policy_drift` when a cluster
  mixes digests; re-ingest before reading the tier.
- **`bug_state` is a separate table**, keyed by bug. Refreshing it never
  rewrites a stored `UpgradeRun`, and neither it nor `UpgradeRun.bug_status`
  is ever an input to a diagnosis or a signature.
- **Machine-readable output carries a `schema` number and lexer coverage**, so
  a consumer can refuse a record it predates and can see when a diagnosis
  rests on partial logs.
- **`--strict` exits `3` on an imperfect parse**, and it is on the collecting
  commands (`fetch`, `sweep`, `ingest`, `coverage`) deliberately: a new apt
  version turns up in a sweep long before anyone points `diagnose` at it.
- **Redaction is on by default** for logs read from disk (hostnames, usernames,
  home paths, emails, IPs) — the Markdown report quotes log lines verbatim for
  pasting into public bugs.
- **Corpus-wide commands read indexed columns only.** `queue`, `refresh` and
  `dedup`'s default output never deserialise a stored record; a test asserts
  the projections do not select `payload`, because a refactor adding one
  convenient field would undo this silently. Only `dedup --markdown` needs the
  records themselves.
- **The four "broken" counts are different numbers.** On bug 2150245: apt
  reports 22, observed broken is 434, blame-edge targets are 148, graph nodes
  are 964. All four are correct answers to different questions; reports label
  which is which.
- **Candidate-Invalid tests the primary cause only.** Any machine with a few
  PPAs has a third-party package implicated somewhere. Use
  `TriageRow.candidate_invalid`, never the `third_party` column — the column
  put three genuine Ubuntu faults (`holdback_blocks_new_dep`, `update_failed`,
  `post_install_script_error`) in `candidate-invalid`.
- **The checked-in `uru-doctor.toml` documents every option** something
  actually reads, and lists defined-but-unwired options as such rather than
  presenting them as settings. A test enforces both directions.

## Test corpus and ground truth

- 47 recorded fixtures from real Launchpad bugs in six languages; provenance in
  `tests/fixtures/MANIFEST.md`, recorded via `tests/record_fixtures.py`.
- The lexer is held at **100% coverage over 40,404 lines of real apt logs
  across sixteen traces** — not 99.9%, because an unrecognised line is a
  silently dropped fact rather than a visible error.
- One trace is held out of that gate, and it is the only one: LP#2168919's
  `apt.log` carries four lines of the upgrader's own user-facing error,
  interleaved into the resolver log. The exclusion is pinned by a test
  asserting the gap is exactly those four lines, so it cannot absorb a new
  one. Do not write patterns that match prose; the full story and the intended
  fix are in the `triage-new-bug` skill under *Known open gap*.
- Ground truth is ranked: the upstream fix, then the bug's resolution, then
  the log read by hand. Triager tags are the weakest evidence and sometimes
  wrong — LP#2155743 is tagged `third-party-packages` with 46 foreign packages
  installed, none of which is the cause; LP#2169214 is the same inversion
  produced by the tool itself (a `kubuntu-desktop` metapackage was the cause,
  not the 139 foreign packages).
- When a test corpus is supposed to be committed, check `git ls-files`, not
  `ls`.

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
| worklist buckets | `src/uru_doctor/worklist.py` |
| Launchpad triage state | `bug_state` table in `src/uru_doctor/store.py` |
| title templates | `src/uru_doctor/title.py` |
| fixture provenance | `tests/record_fixtures.py`, `tests/fixtures/MANIFEST.md` |

## Traps that have actually bitten (general)

Domain traps — apt log semantics, the upgrader's messages, Launchpad's API,
diagnosis ranking — live in the `triage-new-bug` skill. These bite during any
change.

- **`ruff format` silently undoes `python - <<'PY'` string patches.** It
  reflows multi-line calls, so a later `str.replace` finds nothing and reports
  success. Twice this left a parameter unthreaded. After any scripted patch,
  `grep` for the new text.
- **An out-parameter that one call site forgets is invisible.** `ingest_logs`
  took `stats: LexStats | None`; `ingest_attachments` never passed it, so
  `fetch` — the command that meets a new apt version first — could not report
  lexer coverage. Fixed by returning the measurement, so forgetting is a type
  error. If a value is load-bearing, do not let it be optional at the call
  site.
- **`CREATE INDEX` in the schema on a column `_migrate` adds.** `_SCHEMA` runs
  before `_migrate`, and its `CREATE TABLE IF NOT EXISTS` is a no-op on an
  existing store, so the index referenced a column that did not exist yet and
  the store could not be opened at all — while working perfectly on a fresh
  store, which is every test that does not build an old one. Indexes over
  migrated columns belong in `_migrate`, after the `ALTER TABLE`s.
  `TestAdditiveMigration` builds a genuine schema-1 store by dropping the
  columns back off.
- **A schema version that is never written back.** A migrated store kept
  claiming version 1 forever, and an older build would read it as its own.
- **Removing a validator can start leaking what it was validating.** Deleting
  a hand-written check handed the job to pydantic's generic extra-forbidden
  path, which embeds `input_value=` — and the CLI prints the whole message.
  The test still passed, because the secret appearing in the error happened to
  satisfy `match="api_key"`. A test that passes for the wrong reason is worse
  than no test; `test_rejected_values_are_not_echoed` checks the traceback
  too, because `raise ... from exc` would put the original straight back.
- **pydantic's default `extra="ignore"`** dropped a whole field with no
  complaint from pydantic or mypy. `Frozen` now sets `extra="forbid"`.
- **`functools.cached_property` does not work on a `slots=True` dataclass.**
- **`str.splitlines()` splits on bare `\r`**, which defeated
  `collapse_carriage_returns` entirely and stored 440 progress fragments as
  separate events.
- **Naive timestamps from the store crash staleness arithmetic.** A
  `checked_at` without a zone subtracts against `datetime.now(UTC)` as a
  `TypeError` and takes the whole command down. Normalise at the parse
  boundary, not at each use.
- **`ALTER TABLE ADD COLUMN` lands the column after `payload`.** SQLite keeps
  large values in overflow pages, so a column added behind a 54KB blob costs
  more to scan. Small in absolute terms — decide on schema grounds — but a
  "narrow projection" that reads trailing columns is not as narrow as it
  looks.
- **Unrelated `IntEnum`s compare equal by value.** `root.dep in BLAME_EDGES`
  tests a `DepType` against a set of `EdgeKind` members; it type-checks, and
  silently selects `RECOMMENDS` and `DEPENDS` because they share the integers
  1 and 6 with `BREAKS` and `UNSATISFIABLE`. Membership tests across two enums
  are always a bug even when the result looks sensible. (`Cause` and
  `LogSource` are safe only because they are `StrEnum`.)
- **Vertex indices and package ids are both small integers**, so confusing
  them type-checks, runs, and produces plausible-looking package names —
  `mypy` will not catch it: `PkgId` is an `int` alias. If a list of packages
  looks right but *oddly* right, resolve it through two different interners
  and compare.
- **Interned ids must never be a sort key or a tie-break.** Ids are assigned
  in first-seen order, so any ordering that falls back to one depends on what
  was ingested beforehand. This has bitten four times. Sort by name. The
  giveaway is output stable in *content* but not in *order* — check the order
  explicitly, because a set comparison will pass.
- **`jaccard([], []) == 1.0`.** A bug with only `apt.log` has no log events,
  so two unrelated reports scored a perfect match. Absence of evidence is not
  evidence of similarity.
- **An empty restriction is not the absence of a restriction.** `among=[]`
  meaning "no candidates" and `among=None` meaning "no filter" are one typo
  apart, and a falsy check conflates them — a deep refresh aimed at three
  specific bugs spent its whole budget on the four oldest in the store.
  Distinguish empty from unknown.
- **A progress bar on the wrong console corrupts the output.** Rich moves a
  live region out of the way of `Console.print` only for its own console. The
  bar goes on whichever stream is not carrying the document (stderr when
  `--json`/`--markdown` write to stdout), and off entirely when that stream is
  not a terminal. `total=None` does not clear a task's total — remove and
  re-add the task. One task per command, too: a second leaves the first
  drawing itself.
- **A watermark that advances past unhandled work** silently skips every bug
  between the last one handled and the newest one seen — permanently, because
  once the mark is past a bug's creation date the search never offers it
  again. `sweep`'s mark moves only over bugs actually stored, to *that bug's*
  creation date, and never backward.
  `test_the_watermark_does_not_pass_unhandled_bugs` fails loudly on both.
- **Hardcoded counts in tests** (`assert len(paths) == 3`) break the moment
  the corpus grows. Assert properties.
- **An unanchored `.gitignore` pattern ate the fixture corpus.** `logs/`
  matches at *any* depth, so `tests/fixtures/logs/` was never committed —
  and nothing failed, because `fixture_text` calls `pytest.skip`: a fresh
  clone quietly skipped half the ground-truth suite and reported success.
  Twenty-one files. Anchor state-directory patterns with a leading slash
  (`/logs/`).
- **The fixture recorder can destroy its own manifest.** Re-running it after
  `/tmp` is cleaned keeps the committed fixtures and used to delete their
  provenance notes. Check `MANIFEST.md` entry count matches the fixture count.

## Validating against a new bug

Load the `triage-new-bug` skill (`.opencode/skills/triage-new-bug/SKILL.md`).
It covers fetching logs within Launchpad's rate limits, the six ordered
verification gates, establishing ground truth, and recording fixtures with
tests.
