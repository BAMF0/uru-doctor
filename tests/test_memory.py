# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for :mod:`uru_doctor.memory`.

The memory backend exists so a one-shot question -- ingest this directory,
diagnose this bug -- needs no SQLite database. The tests pin the two things
that must hold: the ids behave exactly like the store's (stable, never
:data:`~uru_doctor.models.ABSENT`), and a full ingest-diagnose run through it
produces the same answer the store-backed path does.
"""

from __future__ import annotations

from pathlib import Path

from uru_doctor.diagnose import diagnose
from uru_doctor.ingest import ingest_attachments
from uru_doctor.intern import Interner
from uru_doctor.memory import MemoryBackend
from uru_doctor.models import ABSENT, Cause, LogSource
from uru_doctor.store import Store

from .conftest import fixture_text


class TestIds:
    def test_round_trip(self) -> None:
        backend = MemoryBackend()
        str_id = backend.intern_string("amd64")
        pkg_id = backend.intern_package("lintian:amd64")
        template_id = backend.intern_template("Setting up <PKG>")
        assert backend.string_text(str_id) == "amd64"
        assert backend.package_name(pkg_id) == "lintian:amd64"
        assert backend.template_pattern(template_id) == "Setting up <PKG>"

    def test_ids_are_stable(self) -> None:
        backend = MemoryBackend()
        assert backend.intern_string("amd64") == backend.intern_string("amd64")
        assert backend.intern_package("lintian") == backend.intern_package("lintian")
        assert backend.intern_template("<PKG>") == backend.intern_template("<PKG>")

    def test_ids_start_past_absent(self) -> None:
        """0 is :data:`ABSENT` everywhere, on both backends."""
        backend = MemoryBackend()
        assert backend.intern_string("x") != ABSENT
        assert backend.intern_package("x") != ABSENT
        assert backend.intern_template("x") != ABSENT

    def test_unknown_ids_resolve_to_none(self) -> None:
        backend = MemoryBackend()
        assert backend.string_text(999) is None
        assert backend.package_name(999) is None
        assert backend.template_pattern(999) is None

    def test_no_document_tracking(self) -> None:
        """No run table means no document frequency, said plainly.

        This is what makes IDF weighting degrade to the plain Jaccard ratio
        rather than silently claiming every template is unique.
        """
        backend = MemoryBackend()
        backend.intern_template("Setting up <PKG>")
        assert backend.document_frequencies() == {}
        assert backend.document_count() == 0
        assert Interner(backend).idf_weights() == {}


class TestOneShot:
    def test_diagnosis_matches_the_store_backed_one(self, tmp_path: Path) -> None:
        """The library's headline flow, without a database.

        LP#2150319 is the lintian holdback; the cause must come out the same
        regardless of which backend interned the strings.
        """
        attachments = {
            LogSource.APT: fixture_text("apt/lp2150319-apt.log"),
            LogSource.MAIN: fixture_text("logs/lp2150319-main.log"),
        }

        memory = Interner(MemoryBackend())
        memory_run = ingest_attachments(dict(attachments), memory, bug_id=2150319).only()
        memory_result = diagnose(memory_run, memory)

        with Store.open(tmp_path / "state") as store:
            persisted = Interner(store)
            stored_run = ingest_attachments(dict(attachments), persisted, bug_id=2150319).only()
            stored_result = diagnose(stored_run, persisted)

        assert memory_result.primary is not None
        assert memory_result.primary.cause == stored_result.primary.cause == (
            Cause.RESOLVER_LIVELOCK
        )
