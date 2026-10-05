# Changelog

All notable changes to `uru-doctor` (the library) and `uru-doctor-cli` (the
command-line frontend) are recorded here. The two distributions are versioned
independently from a single repository; where an entry touches only one of
them, it says so.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/). While either
package is pre-1.0, a minor bump may change its public surface; the library's
public surface is the set of names re-exported from `uru_doctor/__init__.py`.

## [Unreleased]

## [0.2.0] - 2026-10-05

The library/frontend split. For anyone using `uru-doctor` as a command-line
tool nothing visible changes; for anyone importing it, the import paths below
are the whole story.

### Changed

- **The project is now two distributions.** `uru-doctor` is the library --
  log parsing, diagnosis, dedup, titles, reports, the record store -- and its
  only runtime dependency is `pydantic`. The commands and the read-only
  Launchpad client moved to a new `uru-doctor-cli` distribution, which
  provides the `uru-doctor` command as before and depends on
  `uru-doctor>=0.2,<0.3`. A test (`tests/test_layering.py`) fails any import
  of `typer`, `rich`, `httpx` or the CLI package from the library.
- `uru_doctor.cli` moved to `uru_doctor_cli.cli`.
- `uru_doctor.lp.read` moved to `uru_doctor_cli.lp`.
- `uru_doctor.config` now holds only the sections the library reads
  (`ingest`, `apt`, `rules`, `dedup`, `title`, `report`). `PathsConfig`,
  `LaunchpadConfig` and `QueueConfig` moved to `uru_doctor_cli.config`, whose
  `CliConfig` subclasses the library's `Config`. `load_config` gained a
  `model` parameter so frontends validate against their own tree.
- The Launchpad user-agent now tracks the CLI package version instead of a
  hardcoded string.
- Stored records stamp the *library* version as `tool_version`. Records
  written by 0.1.0 will report policy drift on first read after the upgrade
  and are re-ingested, exactly as the drift mechanism is designed to do.

### Added

- A curated public API in `uru_doctor/__init__.py` (`ingest_directory`,
  `ingest_attachments`, `diagnose`, `propose_title`, `build_signature`,
  `Store`, `MemoryBackend`, and friends). These names are the supported
  surface; anything reachable only through a submodule may move.
- `uru_doctor.memory.MemoryBackend`: an in-memory interning backend, so a
  one-shot diagnosis needs no SQLite database. It deliberately reports no
  document frequency, which degrades dedup scoring to the plain Jaccard
  ratio; use `uru_doctor.Store` for a corpus.
- This changelog, and tests that pin the version agreement between
  `pyproject.toml`, each package's `__version__`, and the newest entry here.

### Removed

- `uru_doctor.diagnose.signature_for`, a placeholder that returned an empty
  `Signature`. The real implementation is `uru_doctor.dedup.build_signature`.

## [0.1.0]

Pre-split development: one distribution containing the analysis code, the
commands and the Launchpad client.

[Unreleased]: https://github.com/BAMF0/uru-doctor/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/BAMF0/uru-doctor/releases/tag/v0.2.0
