"""SQLite persistence: the interning tables, the records, and the caches.

The store is a cache in the strict sense -- deleting it loses nothing that
re-ingesting the logs cannot rebuild. That is a deliberate property, and it is
why there is no migration machinery beyond additive ``ALTER TABLE``: if a
schema change is ever too awkward to express additively, the correct answer is
to delete the store and re-ingest, not to write a data migration.

Two shapes of data live here, for two different access patterns.

**Indexed scalars**, in typed columns: the questions a triager asks across the
whole corpus -- which bugs share a root-cause hash, which bugs implicate
``python3``, how many failed before ``COMMIT`` -- are indexed queries, not full
scans of deserialised objects.

**Opaque blobs**, in a ``payload`` column plus the packed graph arrays: the full
:class:`~uru_doctor.models.UpgradeRun` is stored as JSON alongside its indexed
projection. The projection is derived and can be recomputed; the payload is the
truth. This is what makes a schema change additive by default -- a new indexed
column is backfilled from payloads that already contain the data.

Everything runs in WAL mode so that a long ``ingest`` and an interactive
``show`` can overlap without locking each other out.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

from uru_doctor.models import (
    Cause,
    PkgId,
    StrId,
    TemplateId,
    UpgradeRun,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

#: Bumped only when a change cannot be made additively. Recorded in ``meta`` so
#: that a store written by a newer version is refused rather than misread.
SCHEMA_VERSION = 1

#: Default location, relative to the working directory. Mirrors the layout the
#: ``.gitignore`` already excludes.
DEFAULT_STATE_DIR = Path(".uru-doctor")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Interning -----------------------------------------------------------------
-- Append-only. Ids are stable for the life of the store, which is what lets a
-- packed blob written today still resolve months later.

CREATE TABLE IF NOT EXISTS strings (
    id   INTEGER PRIMARY KEY,
    text TEXT    NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS packages (
    id   INTEGER PRIMARY KEY,
    name TEXT    NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS templates (
    id      INTEGER PRIMARY KEY,
    pattern TEXT    NOT NULL UNIQUE
);

-- Records -------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS runs (
    run_key           TEXT    NOT NULL PRIMARY KEY,
    bug_id            INTEGER,
    attempt           INTEGER NOT NULL,
    is_primary        INTEGER NOT NULL DEFAULT 1,
    source_dir        TEXT,
    from_series       TEXT,
    to_series         TEXT,
    arch              TEXT,
    problem_type      TEXT,
    apt_version       TEXT,
    upgrader_version  TEXT,
    terminal_phase    INTEGER NOT NULL DEFAULT 0,
    evidence_complete INTEGER NOT NULL DEFAULT 1,
    reached_dpkg      INTEGER NOT NULL DEFAULT 0,
    top_cause         TEXT,
    cascade_size      INTEGER NOT NULL DEFAULT 0,
    fragile           INTEGER NOT NULL DEFAULT 0,
    third_party       INTEGER NOT NULL DEFAULT 0,
    current_title     TEXT,
    started_at        TEXT,
    ingested_at       TEXT    NOT NULL,
    diagnosed_at      TEXT,
    apport_dupe       BLOB,
    root_graph        BLOB,
    cause_tuple       BLOB,
    payload           TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_runs_bug        ON runs(bug_id);
CREATE INDEX IF NOT EXISTS idx_runs_cause      ON runs(top_cause);
CREATE INDEX IF NOT EXISTS idx_runs_root_graph ON runs(root_graph);
CREATE INDEX IF NOT EXISTS idx_runs_apport     ON runs(apport_dupe);
CREATE INDEX IF NOT EXISTS idx_runs_tuple      ON runs(cause_tuple);
CREATE INDEX IF NOT EXISTS idx_runs_series     ON runs(to_series);

-- Which templates a report contained, one row per distinct template.
-- Document frequency is COUNT(*) over this table rather than a counter on
-- `templates`, because a keyed table makes re-ingest idempotent for free: the
-- primary key absorbs duplicates and a delete-then-insert cannot drift.
CREATE TABLE IF NOT EXISTS run_templates (
    run_key     TEXT    NOT NULL,
    template_id INTEGER NOT NULL,
    PRIMARY KEY (run_key, template_id)
);

CREATE INDEX IF NOT EXISTS idx_run_templates_tpl ON run_templates(template_id);

-- Which packages a report implicates, and in what capacity. Exists so that
-- "which bugs blame python3?" is an indexed lookup instead of a scan that
-- deserialises every payload.
CREATE TABLE IF NOT EXISTS run_packages (
    run_key TEXT    NOT NULL,
    pkg_id  INTEGER NOT NULL,
    role    TEXT    NOT NULL,
    PRIMARY KEY (run_key, pkg_id, role)
);

CREATE INDEX IF NOT EXISTS idx_run_packages_pkg ON run_packages(pkg_id, role);

-- Clustering ----------------------------------------------------------------

CREATE TABLE IF NOT EXISTS clusters (
    cluster_id   INTEGER PRIMARY KEY,
    canonical    TEXT    NOT NULL,
    cause        TEXT,
    member_count INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS cluster_members (
    cluster_id INTEGER NOT NULL,
    run_key    TEXT    NOT NULL,
    tier       INTEGER NOT NULL,
    score      REAL,
    PRIMARY KEY (cluster_id, run_key)
);

CREATE INDEX IF NOT EXISTS idx_cluster_members_run ON cluster_members(run_key);

-- Caches --------------------------------------------------------------------

-- Keyed on a digest of exactly the text the model saw, so a prompt change
-- invalidates naturally and a re-run costs nothing.
CREATE TABLE IF NOT EXISTS llm_cache (
    fingerprint TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    model_id    TEXT NOT NULL,
    response    TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

-- Launchpad attachment cache. ETags let a re-fetch be a conditional GET, which
-- matters because Launchpad rate-limits hard enough to return 429 in practice.
CREATE TABLE IF NOT EXISTS attachments (
    bug_id     INTEGER NOT NULL,
    name       TEXT    NOT NULL,
    etag       TEXT,
    path       TEXT    NOT NULL,
    size       INTEGER NOT NULL DEFAULT 0,
    fetched_at TEXT    NOT NULL,
    PRIMARY KEY (bug_id, name)
);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def run_key_for(bug_id: int | None, attempt: int, source_dir: str = "") -> str:
    """Build the primary key for a run.

    A synthetic text key rather than ``(bug_id, attempt)`` because SQLite
    permits NULL in primary-key columns, so a composite key containing a
    nullable ``bug_id`` would not actually be unique for locally ingested
    directories that have no bug number.
    """
    if bug_id is not None:
        return f"lp:{bug_id}#{attempt}"
    return f"dir:{source_dir}#{attempt}"


class Store:
    """SQLite-backed state, and the :class:`~uru_doctor.intern.InternBackend`.

    Safe to delete at any time; everything here is derived from the logs.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._closed = False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        # WAL so an interactive command can read while an ingest writes;
        # busy_timeout so the second writer waits rather than failing outright.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._check_version()
        self._migrate()
        self._conn.commit()

    @classmethod
    def open(cls, state_dir: Path | None = None) -> Store:
        """Open (creating if needed) the store under ``state_dir``."""
        directory = state_dir or DEFAULT_STATE_DIR
        return cls(directory / "uru-doctor.db")

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Commit and close. Safe to call more than once.

        Idempotent because a context manager and an explicit close are both
        reasonable, and a test or a CLI error path can easily do both.
        """
        if self._closed:
            return
        self._closed = True
        self._conn.commit()
        self._conn.close()

    def commit(self) -> None:
        self._conn.commit()

    # -- schema -------------------------------------------------------------

    def _check_version(self) -> None:
        """Refuse a store written by a newer schema rather than misread it."""
        row = self._conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            return
        found = int(row["value"])
        if found > SCHEMA_VERSION:
            raise RuntimeError(
                f"{self.path} was written by schema version {found}, "
                f"but this build understands at most {SCHEMA_VERSION}. "
                f"Delete it and re-ingest -- it is only a cache."
            )

    def _migrate(self) -> None:
        """Apply additive migrations. Idempotent, guarded by introspection."""
        # No migrations yet. When one is needed it belongs here, guarded by a
        # PRAGMA table_info check so that running it twice is harmless:
        #
        #   if "new_column" not in self._columns("runs"):
        #       self._conn.execute("ALTER TABLE runs ADD COLUMN new_column TEXT")

    def _columns(self, table: str) -> set[str]:
        rows = self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        return {row["name"] for row in rows}

    # -- InternBackend ------------------------------------------------------

    def intern_string(self, text: str) -> StrId:
        # Ids start at 1 because 0 is reserved for "absent"; SQLite's implicit
        # rowid already starts at 1, so nothing special is needed.
        cur = self._conn.execute("SELECT id FROM strings WHERE text = ?", (text,))
        row = cur.fetchone()
        if row is not None:
            return int(row["id"])
        cur = self._conn.execute("INSERT INTO strings (text) VALUES (?)", (text,))
        return int(cur.lastrowid or 0)

    def intern_package(self, name: str) -> PkgId:
        cur = self._conn.execute("SELECT id FROM packages WHERE name = ?", (name,))
        row = cur.fetchone()
        if row is not None:
            return int(row["id"])
        cur = self._conn.execute("INSERT INTO packages (name) VALUES (?)", (name,))
        return int(cur.lastrowid or 0)

    def intern_template(self, pattern: str) -> TemplateId:
        cur = self._conn.execute("SELECT id FROM templates WHERE pattern = ?", (pattern,))
        row = cur.fetchone()
        if row is not None:
            return int(row["id"])
        cur = self._conn.execute("INSERT INTO templates (pattern) VALUES (?)", (pattern,))
        return int(cur.lastrowid or 0)

    def string_text(self, str_id: StrId) -> str | None:
        row = self._conn.execute("SELECT text FROM strings WHERE id = ?", (str_id,)).fetchone()
        return None if row is None else str(row["text"])

    def package_name(self, pkg_id: PkgId) -> str | None:
        row = self._conn.execute("SELECT name FROM packages WHERE id = ?", (pkg_id,)).fetchone()
        return None if row is None else str(row["name"])

    def template_pattern(self, template_id: TemplateId) -> str | None:
        row = self._conn.execute(
            "SELECT pattern FROM templates WHERE id = ?", (template_id,)
        ).fetchone()
        return None if row is None else str(row["pattern"])

    def document_frequencies(self) -> dict[TemplateId, int]:
        """Template id to the number of reports containing it.

        One aggregate rather than a query per template: scoring needs the whole
        map, and a corpus of a few hundred reports makes this a few
        milliseconds.
        """
        rows = self._conn.execute(
            "SELECT template_id, COUNT(*) AS df FROM run_templates GROUP BY template_id"
        ).fetchall()
        return {int(r["template_id"]): int(r["df"]) for r in rows}

    def document_count(self) -> int:
        """Number of ingested reports, the IDF denominator."""
        row = self._conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()
        return int(row["n"]) if row else 0

    def unclassified_templates(self, limit: int = 50) -> list[tuple[TemplateId, str, int]]:
        """Templates that look like errors but no rule claimed.

        The feedback loop that keeps this tool honest about new failure modes.
        A template is surfaced when it occurs in reports whose top cause is
        ``UNKNOWN``, ordered by how many reports it appears in, so the most
        widespread unexplained shape is dealt with first.
        """
        rows = self._conn.execute(
            """
            SELECT t.id, t.pattern, COUNT(*) AS n
              FROM run_templates rt
              JOIN templates t ON t.id = rt.template_id
              JOIN runs r      ON r.run_key = rt.run_key
             WHERE r.top_cause IS NULL OR r.top_cause IN (?, ?)
             GROUP BY t.id
             ORDER BY n DESC, t.id ASC
             LIMIT ?
            """,
            (Cause.UNKNOWN.value, Cause.NO_FAILURE_RECORDED.value, limit),
        ).fetchall()
        return [(int(r["id"]), str(r["pattern"]), int(r["n"])) for r in rows]

    # -- runs ---------------------------------------------------------------

    def put_run(self, run: UpgradeRun) -> str:
        """Insert or replace a run, and rebuild its derived index rows.

        Idempotent: ingesting the same directory twice produces identical
        tables, because the derived rows are deleted and rewritten rather than
        appended to. That property is what makes ``ingest`` safely resumable.
        """
        key = run_key_for(run.bug_id, run.attempt, run.source_dir)
        top = run.top_finding
        third_party = any(f.cause is Cause.THIRD_PARTY_PIN for f in run.findings)

        self._conn.execute(
            """
            INSERT INTO runs (
                run_key, bug_id, attempt, is_primary, source_dir,
                from_series, to_series, arch, problem_type,
                apt_version, upgrader_version,
                terminal_phase, evidence_complete, reached_dpkg,
                top_cause, cascade_size, fragile, third_party,
                current_title, started_at, ingested_at, diagnosed_at,
                apport_dupe, root_graph, cause_tuple, payload
            ) VALUES (
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?
            )
            ON CONFLICT(run_key) DO UPDATE SET
                bug_id            = excluded.bug_id,
                attempt           = excluded.attempt,
                is_primary        = excluded.is_primary,
                source_dir        = excluded.source_dir,
                from_series       = excluded.from_series,
                to_series         = excluded.to_series,
                arch              = excluded.arch,
                problem_type      = excluded.problem_type,
                apt_version       = excluded.apt_version,
                upgrader_version  = excluded.upgrader_version,
                terminal_phase    = excluded.terminal_phase,
                evidence_complete = excluded.evidence_complete,
                reached_dpkg      = excluded.reached_dpkg,
                top_cause         = excluded.top_cause,
                cascade_size      = excluded.cascade_size,
                fragile           = excluded.fragile,
                third_party       = excluded.third_party,
                current_title     = excluded.current_title,
                started_at        = excluded.started_at,
                diagnosed_at      = excluded.diagnosed_at,
                apport_dupe       = excluded.apport_dupe,
                root_graph        = excluded.root_graph,
                cause_tuple       = excluded.cause_tuple,
                payload           = excluded.payload
            """,
            (
                key,
                run.bug_id,
                run.attempt,
                int(run.is_primary),
                run.source_dir,
                run.from_series,
                run.to_series,
                run.arch.value,
                run.problem_type.value,
                run.apt_version,
                run.upgrader_version,
                int(run.terminal_phase),
                int(run.evidence_complete),
                int(run.reached_dpkg),
                top.cause.value if top else None,
                top.cascade_size if top else 0,
                int(bool(top and top.fragile)),
                int(third_party),
                run.current_title,
                run.started_at.isoformat() if run.started_at else None,
                _now(),
                _now() if run.findings else None,
                run.signature.apport_dupe,
                run.signature.root_graph,
                run.signature.cause_tuple,
                run.model_dump_json(),
            ),
        )

        # Derived rows: delete then insert, so a re-ingest cannot accumulate.
        self._conn.execute("DELETE FROM run_templates WHERE run_key = ?", (key,))
        template_ids = {e.template_id for e in run.events}
        if template_ids:
            self._conn.executemany(
                "INSERT OR IGNORE INTO run_templates (run_key, template_id) VALUES (?, ?)",
                [(key, t) for t in sorted(template_ids)],
            )

        self._conn.execute("DELETE FROM run_packages WHERE run_key = ?", (key,))
        rows: set[tuple[str, int, str]] = set()
        for finding in run.findings:
            for pkg in finding.root_pkgs:
                rows.add((key, pkg, "root"))
            for pkg in finding.victim_pkgs:
                rows.add((key, pkg, "victim"))
        for pkg in run.pkgs.ids("failed"):
            rows.add((key, pkg, "failed"))
        for pkg in run.pkgs.ids("held_back"):
            rows.add((key, pkg, "held_back"))
        if rows:
            self._conn.executemany(
                "INSERT OR IGNORE INTO run_packages (run_key, pkg_id, role) VALUES (?, ?, ?)",
                sorted(rows),
            )
        return key

    def get_run(self, key: str) -> UpgradeRun | None:
        row = self._conn.execute("SELECT payload FROM runs WHERE run_key = ?", (key,)).fetchone()
        if row is None:
            return None
        return UpgradeRun.model_validate_json(row["payload"])

    def get_runs_for_bug(self, bug_id: int) -> list[UpgradeRun]:
        rows = self._conn.execute(
            "SELECT payload FROM runs WHERE bug_id = ? ORDER BY attempt", (bug_id,)
        ).fetchall()
        return [UpgradeRun.model_validate_json(r["payload"]) for r in rows]

    def iter_runs(self, *, primary_only: bool = True) -> Iterator[UpgradeRun]:
        """Stream every run.

        Streams rather than returning a list because ``diagnose`` and ``dedup``
        both walk the whole corpus and there is no reason to hold every payload
        string in memory at once.
        """
        sql = "SELECT payload FROM runs"
        if primary_only:
            sql += " WHERE is_primary = 1"
        sql += " ORDER BY bug_id, attempt"
        for row in self._conn.execute(sql):
            yield UpgradeRun.model_validate_json(row["payload"])

    def run_keys(self, *, primary_only: bool = True) -> list[str]:
        sql = "SELECT run_key FROM runs"
        if primary_only:
            sql += " WHERE is_primary = 1"
        return [str(r["run_key"]) for r in self._conn.execute(sql)]

    def has_run(self, key: str) -> bool:
        row = self._conn.execute("SELECT 1 FROM runs WHERE run_key = ?", (key,)).fetchone()
        return row is not None

    def delete_run(self, key: str) -> None:
        for table in ("run_templates", "run_packages", "cluster_members"):
            self._conn.execute(f"DELETE FROM {table} WHERE run_key = ?", (key,))
        self._conn.execute("DELETE FROM runs WHERE run_key = ?", (key,))

    # -- corpus queries -----------------------------------------------------

    def cause_histogram(self) -> list[tuple[str, int]]:
        rows = self._conn.execute(
            """
            SELECT COALESCE(top_cause, 'not_diagnosed') AS cause, COUNT(*) AS n
              FROM runs WHERE is_primary = 1
             GROUP BY cause ORDER BY n DESC
            """
        ).fetchall()
        return [(str(r["cause"]), int(r["n"])) for r in rows]

    def top_blaming_packages(self, limit: int = 20) -> list[tuple[PkgId, str, int]]:
        """Packages blamed as a root across the most reports.

        The cross-corpus view that turns a pile of individual bugs into a
        shortlist of things to actually fix.
        """
        rows = self._conn.execute(
            """
            SELECT rp.pkg_id, p.name, COUNT(DISTINCT rp.run_key) AS n
              FROM run_packages rp
              JOIN packages p ON p.id = rp.pkg_id
             WHERE rp.role = 'root'
             GROUP BY rp.pkg_id
             ORDER BY n DESC, p.name ASC
             LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [(int(r["pkg_id"]), str(r["name"]), int(r["n"])) for r in rows]

    def runs_blaming(self, pkg_id: PkgId) -> list[str]:
        rows = self._conn.execute(
            "SELECT DISTINCT run_key FROM run_packages WHERE pkg_id = ? AND role = 'root'",
            (pkg_id,),
        ).fetchall()
        return [str(r["run_key"]) for r in rows]

    def keys_by_signature(self, column: str) -> dict[bytes, list[str]]:
        """Group run keys by a signature column, for exact-match deduplication.

        ``column`` is one of ``apport_dupe``, ``root_graph`` or ``cause_tuple``.
        Validated against a allowlist because it is interpolated into SQL.
        """
        if column not in {"apport_dupe", "root_graph", "cause_tuple"}:
            raise ValueError(f"not a signature column: {column}")
        out: dict[bytes, list[str]] = {}
        rows = self._conn.execute(
            f"SELECT run_key, {column} AS sig FROM runs "
            f"WHERE {column} IS NOT NULL AND is_primary = 1"
        ).fetchall()
        for row in rows:
            out.setdefault(bytes(row["sig"]), []).append(str(row["run_key"]))
        return out

    def phase_histogram(self) -> list[tuple[int, int]]:
        rows = self._conn.execute(
            """
            SELECT terminal_phase AS phase, COUNT(*) AS n
              FROM runs WHERE is_primary = 1
             GROUP BY phase ORDER BY phase
            """
        ).fetchall()
        return [(int(r["phase"]), int(r["n"])) for r in rows]

    # -- clusters -----------------------------------------------------------

    def replace_clusters(
        self, clusters: Iterable[tuple[str, str | None, list[tuple[str, int, float]]]]
    ) -> None:
        """Replace all clusters wholesale.

        Clustering is a pure function of the corpus, so it is recomputed rather
        than incrementally maintained. Wholesale replacement removes any
        possibility of a stale edge surviving a rule change.
        """
        self._conn.execute("DELETE FROM cluster_members")
        self._conn.execute("DELETE FROM clusters")
        for canonical, cause, members in clusters:
            cur = self._conn.execute(
                "INSERT INTO clusters (canonical, cause, member_count, created_at) "
                "VALUES (?, ?, ?, ?)",
                (canonical, cause, len(members), _now()),
            )
            cluster_id = int(cur.lastrowid or 0)
            self._conn.executemany(
                "INSERT INTO cluster_members (cluster_id, run_key, tier, score) "
                "VALUES (?, ?, ?, ?)",
                [(cluster_id, key, tier, score) for key, tier, score in members],
            )

    def iter_clusters(self) -> Iterator[tuple[int, str, str | None, list[tuple[str, int, float]]]]:
        for row in self._conn.execute(
            "SELECT cluster_id, canonical, cause FROM clusters ORDER BY member_count DESC"
        ).fetchall():
            cid = int(row["cluster_id"])
            members = [
                (str(m["run_key"]), int(m["tier"]), float(m["score"] or 0.0))
                for m in self._conn.execute(
                    "SELECT run_key, tier, score FROM cluster_members WHERE cluster_id = ?",
                    (cid,),
                ).fetchall()
            ]
            yield (cid, str(row["canonical"]), row["cause"], members)

    # -- LLM cache ----------------------------------------------------------

    def llm_get(self, fingerprint: str) -> str | None:
        row = self._conn.execute(
            "SELECT response FROM llm_cache WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return None if row is None else str(row["response"])

    def llm_put(self, fingerprint: str, kind: str, model_id: str, response: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO llm_cache (fingerprint, kind, model_id, response, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (fingerprint, kind, model_id, response, _now()),
        )

    # -- attachment cache ---------------------------------------------------

    def attachment_etag(self, bug_id: int, name: str) -> tuple[str | None, Path | None]:
        row = self._conn.execute(
            "SELECT etag, path FROM attachments WHERE bug_id = ? AND name = ?", (bug_id, name)
        ).fetchone()
        if row is None:
            return (None, None)
        return (row["etag"], Path(str(row["path"])))

    def attachment_put(
        self, bug_id: int, name: str, etag: str | None, path: Path, size: int
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO attachments (bug_id, name, etag, path, size, fetched_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (bug_id, name, etag, str(path), size, _now()),
        )

    # -- meta ---------------------------------------------------------------

    def meta_get(self, key: str) -> str | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row["value"])

    def meta_put(self, key: str, value: str) -> None:
        self._conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))

    def stats(self) -> dict[str, Any]:
        """Counts for ``uru-doctor stats``."""

        def count(table: str) -> int:
            row = self._conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
            return int(row["n"]) if row else 0

        return {
            "runs": count("runs"),
            "bugs": len({r["bug_id"] for r in self._conn.execute("SELECT bug_id FROM runs")}),
            "strings": count("strings"),
            "packages": count("packages"),
            "templates": count("templates"),
            "clusters": count("clusters"),
            "llm_cached": count("llm_cache"),
            "db_bytes": self.path.stat().st_size if self.path.exists() else 0,
        }


def dumps_compact(obj: Any) -> str:
    """JSON with no incidental whitespace, for payload columns."""
    return json.dumps(obj, separators=(",", ":"), default=str)
