# SPDX-License-Identifier: GPL-2.0-or-later
"""An in-memory :class:`~uru_doctor.intern.InternBackend`.

The store is the right backend for a corpus: it persists, and its
``run_templates`` table is what makes IDF-weighted dedup honest. But a
one-shot question -- ingest this directory, diagnose this bug -- has nothing
to persist, and making the caller open a SQLite database for it would be
ceremony around a dictionary. This backend is that dictionary.

What it deliberately does not do is track document frequency. Only a store
knows which report contained which template (see
:class:`~uru_doctor.intern.InternBackend`), so :meth:`document_frequencies`
returns empty and :meth:`document_count` returns zero. The consequence is
narrow and explicit: :meth:`uru_doctor.intern.Interner.idf_weights` is empty,
and pairwise scoring falls back to the plain Jaccard ratio. If you are
clustering a corpus, use :class:`uru_doctor.store.Store`.
"""

from __future__ import annotations

from uru_doctor.models import PkgId, StrId, TemplateId


class MemoryBackend:
    """Dict-backed interning for one process, with no persistence.

    Ids start at 1, matching the store: 0 is :data:`~uru_doctor.models.ABSENT`
    everywhere, and keeping the same convention means a record built against
    one backend is never silently reinterpreted against the other.
    """

    def __init__(self) -> None:
        self._strings: dict[str, StrId] = {}
        self._packages: dict[str, PkgId] = {}
        self._templates: dict[str, TemplateId] = {}
        self._string_text: dict[StrId, str] = {}
        self._package_name: dict[PkgId, str] = {}
        self._template_pattern: dict[TemplateId, str] = {}

    def intern_string(self, text: str) -> StrId:
        existing = self._strings.get(text)
        if existing is not None:
            return existing
        str_id = StrId(len(self._strings) + 1)
        self._strings[text] = str_id
        self._string_text[str_id] = text
        return str_id

    def intern_package(self, name: str) -> PkgId:
        existing = self._packages.get(name)
        if existing is not None:
            return existing
        pkg_id = PkgId(len(self._packages) + 1)
        self._packages[name] = pkg_id
        self._package_name[pkg_id] = name
        return pkg_id

    def intern_template(self, pattern: str) -> TemplateId:
        existing = self._templates.get(pattern)
        if existing is not None:
            return existing
        template_id = TemplateId(len(self._templates) + 1)
        self._templates[pattern] = template_id
        self._template_pattern[template_id] = pattern
        return template_id

    def string_text(self, str_id: StrId) -> str | None:
        return self._string_text.get(str_id)

    def package_name(self, pkg_id: PkgId) -> str | None:
        return self._package_name.get(pkg_id)

    def template_pattern(self, template_id: TemplateId) -> str | None:
        return self._template_pattern.get(template_id)

    def document_frequencies(self) -> dict[TemplateId, int]:
        """Always empty: with no run table there are no documents to count."""
        return {}

    def document_count(self) -> int:
        """Always zero, for the same reason."""
        return 0
