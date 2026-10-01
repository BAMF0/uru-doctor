"""Global interning of strings, package names and log-line templates.

Three tables, one purpose: turn repeated text into small integers once, so that
every record downstream holds ids instead of strings.

The win is not subtle. A single ``apt.log`` from a failing LTS-to-LTS upgrade
mentions ``python3`` in forty ``Broken`` lines; a corpus of three hundred bugs
mentions ``libglib2.0-0t64`` in most of them. Interning collapses that to one
row per distinct string plus a four-byte reference at each use, which is what
brings a multi-megabyte log set down to a few kilobytes of record.

Templates earn their own table because they also carry a *document frequency*.
Without it, similarity scoring is dominated by boilerplate -- ``Setting up X``
appears in every report ever filed and tells you nothing. With it, the rare
templates that actually characterise a failure dominate, and the scoring needs
no hand-tuned stop list.

Interning is append-only and ids are stable for the lifetime of a store, so a
packed blob written today still resolves next month. Deleting the store is
always safe; re-ingesting rebuilds it.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Protocol

from uru_doctor.models import ABSENT, PkgId, StrId, TemplateId

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable


class InternBackend(Protocol):
    """What :class:`Interner` needs from a persistence layer.

    Declared as a protocol so the interner can be exercised against a plain
    dictionary in tests, and so :mod:`uru_doctor.store` is not imported here --
    it imports this module.

    Note what is *absent*: nothing here records which report contained which
    template. Document frequency is derived by the store from a
    ``run_templates`` table keyed on the run, because only the store knows the
    run key and only a keyed table makes re-ingesting a report idempotent. A
    counter bumped from here would double-count on every re-ingest.
    """

    def intern_string(self, text: str) -> StrId: ...
    def intern_package(self, name: str) -> PkgId: ...
    def intern_template(self, pattern: str) -> TemplateId: ...
    def string_text(self, str_id: StrId) -> str | None: ...
    def package_name(self, pkg_id: PkgId) -> str | None: ...
    def template_pattern(self, template_id: TemplateId) -> str | None: ...
    def document_frequencies(self) -> dict[TemplateId, int]: ...
    def document_count(self) -> int: ...


# ---------------------------------------------------------------------------
# Package name normalisation
# ---------------------------------------------------------------------------

#: A package reference as apt prints it in debug output: ``name:arch``, where
#: arch may itself be ``any`` or a wildcard. Names may contain ``+``, ``.``,
#: ``-`` and (for some upstreams) ``~``.
_PKG_REF = re.compile(
    r"""
    ^
    (?P<name>[a-z0-9][a-z0-9+.~-]*)
    (?: : (?P<arch>[a-z0-9]+(?::any)?) )?
    $
    """,
    re.VERBOSE,
)


def split_package_ref(ref: str) -> tuple[str, str]:
    """Split ``"libfoo1:amd64"`` into ``("libfoo1", "amd64")``.

    An absent architecture becomes ``""`` rather than a guess. apt omits the
    architecture for ``Architecture: all`` packages in some debug lines and
    includes it in others, and conflating ``libfoo1`` with ``libfoo1:amd64``
    would silently merge two graph nodes.
    """
    match = _PKG_REF.match(ref.strip())
    if match is None:
        return (ref.strip(), "")
    return (match.group("name"), match.group("arch") or "")


def canonical_package_key(ref: str) -> str:
    """Return the interning key for a package reference.

    Architecture is part of the key because it is part of the identity. In bug
    2169028, ``i965-va-driver:i386`` and ``intel-media-va-driver:i386`` depend
    on an i386 ABI package that has no provider, while their amd64 counterparts
    resolve fine. Merging the two architectures would erase the entire
    ``I386_ORPHAN`` cause class.
    """
    name, arch = split_package_ref(ref)
    return f"{name}:{arch}" if arch else name


def package_display(key: str) -> str:
    """Render an interning key for humans.

    Strips the ``:amd64`` that dominates every corpus and would make titles
    unreadable, while keeping any other architecture, where the architecture is
    usually the point.
    """
    if key.endswith(":amd64"):
        return key[: -len(":amd64")]
    return key


# ---------------------------------------------------------------------------
# Template masking
# ---------------------------------------------------------------------------

#: Architectures apt ever suffixes onto a package reference. Enumerated rather
#: than matched as ``\w+`` so that masking cannot swallow something that merely
#: looks like a package reference.
_ARCHES = "amd64|i386|arm64|armhf|ppc64el|s390x|riscv64|all|any"

#: A Debian package name. Deliberately not anchored on word boundaries at the
#: tail, because names legitimately end in digits and sonames.
_NAME = r"[a-z0-9][a-z0-9+.~-]*"

#: ``(group name, pattern, placeholder)`` in priority order.
#:
#: These are compiled into a *single* alternation and the line is scanned once,
#: left to right. That is not an optimisation, it is a correctness requirement:
#: applying masks one at a time over the whole line accumulates the captured
#: tokens in mask order while the placeholders end up in positional order, so
#: the two lists disagree and the line can no longer be reconstructed.
#:
#: Priority within the alternation matters where two patterns can match at the
#: same offset. Package references come before versions and bare numbers
#: because many names end in digits: ``gcc-15:amd64`` must not become
#: ``gcc-<N>:amd64``, and ``libpython3.14-minimal`` must keep its soname.
#: Because the scan is leftmost-first, an earlier-*starting* match always wins
#: regardless of listing order, so this only arbitrates genuine ties.
_MASK_SPECS: tuple[tuple[str, str, str], ...] = (
    # Timestamps first: they contain digits, colons and dashes that every later
    # pattern would otherwise chew on.
    ("ts", r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,.]\d+)?", "<TS>"),
    ("clock", r"\b\d{2}:\d{2}:\d{2}\b", "<TIME>"),
    # Architecture-qualified package references.
    ("pkg_arch", rf"\b{_NAME}:(?:{_ARCHES})(?::any)?\b", "<PKG>"),
    # dpkg's fixed phrasings, where the package name carries no architecture.
    # Lookbehind keeps each match to the name itself, so the captured token is
    # exactly what the placeholder stands for.
    ("pkg_overwrite", rf"(?<=which is also in package ){_NAME}", "<PKG>"),
    ("pkg_postinst", rf"(?<=installed ){_NAME}(?= package post-installation)", "<PKG>"),
    ("pkg_prerm", rf"(?<=installed ){_NAME}(?= package pre-removal)", "<PKG>"),
    ("pkg_proc", rf"(?<=error processing package ){_NAME}", "<PKG>"),
    ("pkg_securerm", rf"(?<=unable to securely remove ){_NAME}", "<PKG>"),
    # Absolute paths.
    ("path", r"/(?:[\w.+~@-]+/)+[\w.+~@-]*", "<PATH>"),
    # Debian versions: optional epoch, then a dotted upstream, then anything
    # version-ish. Before bare integers.
    ("ver_epoch", r"\b\d+:[0-9][A-Za-z0-9.+~:-]*", "<VER>"),
    ("ver_dotted", r"\b[0-9]+(?:\.[0-9]+)+[A-Za-z0-9.+~-]*", "<VER>"),
    # Sizes with units, before bare integers.
    ("size", r"\b\d+(?:\.\d+)?\s?(?:[kKMGT]i?B|bytes?)\b", "<SIZE>"),
    ("hexaddr", r"\b0x[0-9a-fA-F]+\b", "<HEX>"),
    ("digest", r"\b[0-9a-f]{12,}\b", "<HASH>"),
    ("num", r"\b\d+\b", "<N>"),
)

_COMBINED = re.compile("|".join(f"(?P<{name}>{pattern})" for name, pattern, _ in _MASK_SPECS))

_PLACEHOLDER_FOR: dict[str, str] = {name: ph for name, _, ph in _MASK_SPECS}

#: Every placeholder the masks can emit, for the inverse operation.
_PLACEHOLDER = re.compile(r"<(?:TS|TIME|PKG|PATH|VER|SIZE|HEX|HASH|N)>")

#: Collapse runs of whitespace so that indentation and alignment differences do
#: not fork a template.
_WS = re.compile(r"\s+")


def _masker(captured: list[str]) -> Callable[[re.Match[str]], str]:
    """Build an :func:`re.sub` replacement that records what it replaced."""

    def _replace(match: re.Match[str]) -> str:
        captured.append(match.group(0))
        return _PLACEHOLDER_FOR[match.lastgroup or ""]

    return _replace


def mask_line(line: str) -> tuple[str, tuple[str, ...]]:
    """Reduce a log line to a template and the tokens that were masked out.

    Returns the masked pattern and, **in positional order**, the substrings that
    were replaced. The arguments are what let the original line be reconstructed
    for display without retaining a copy of it, and they are interned
    separately so that the same package name appearing in two templates costs
    one row rather than two.

    Runs of whitespace are collapsed, so a reconstructed line matches the
    original up to whitespace normalisation. apt indents to encode recursion
    depth, which :mod:`uru_doctor.apt.lexer` captures structurally before this
    is ever called, so nothing of value is lost here.

    >>> mask_line("dpkg: error processing archive /tmp/042-libfoo_1.2-3.deb")
    ('dpkg: error processing archive <PATH>', ('/tmp/042-libfoo_1.2-3.deb',))
    """
    captured: list[str] = []
    text = _COMBINED.sub(_masker(captured), line.strip())
    return (_WS.sub(" ", text).strip(), tuple(captured))


def render_template(pattern: str, args: Iterable[str]) -> str:
    """Substitute ``args`` back into a masked ``pattern``, in order.

    The inverse of :func:`mask_line`, used to show a triager the original line
    without having kept a copy of it.
    """
    out: list[str] = []
    rest = pattern
    for arg in args:
        hit = _PLACEHOLDER.search(rest)
        if hit is None:
            break
        out.append(rest[: hit.start()])
        out.append(arg)
        rest = rest[hit.end() :]
    out.append(rest)
    return "".join(out)


# ---------------------------------------------------------------------------
# Interner
# ---------------------------------------------------------------------------


class Interner:
    """Caching front end over an :class:`InternBackend`.

    Ingest interns the same handful of strings thousands of times in a row --
    ``amd64``, ``@ii umU Ib``, the name of whichever package is at the centre of
    the failure. An in-process dictionary in front of the database turns almost
    all of that into a hash lookup, which matters because ingest is the only
    phase of this tool that is ever I/O bound.

    The cache is write-through and ids are append-only, so it can never go
    stale within a process.
    """

    def __init__(self, backend: InternBackend) -> None:
        self._backend = backend
        self._strings: dict[str, StrId] = {}
        self._packages: dict[str, PkgId] = {}
        self._templates: dict[str, TemplateId] = {}
        self._string_text: dict[StrId, str] = {}
        self._package_name: dict[PkgId, str] = {}
        self._by_bare_name: dict[str, list[PkgId]] = {}

    # -- strings ------------------------------------------------------------

    def string(self, text: str | None) -> StrId:
        """Intern ``text``, returning :data:`ABSENT` for None or empty.

        Empty and missing collapse to the same id deliberately: a packed array
        of ids can then represent optionality without a parallel presence mask.
        """
        if not text:
            return ABSENT
        cached = self._strings.get(text)
        if cached is not None:
            return cached
        str_id = self._backend.intern_string(text)
        self._strings[text] = str_id
        self._string_text[str_id] = text
        return str_id

    def text(self, str_id: StrId) -> str:
        """Resolve a :data:`StrId`. Unknown ids render as empty, never raise.

        Reports must not explode because a blob references an id that is
        missing from a half-written store.
        """
        if str_id == ABSENT:
            return ""
        cached = self._string_text.get(str_id)
        if cached is not None:
            return cached
        text = self._backend.string_text(str_id) or ""
        self._string_text[str_id] = text
        return text

    # -- packages -----------------------------------------------------------

    def package(self, ref: str | None) -> PkgId:
        """Intern a package reference, normalising ``name:arch`` first."""
        if not ref:
            return ABSENT
        key = canonical_package_key(ref)
        cached = self._packages.get(key)
        if cached is not None:
            return cached
        pkg_id = self._backend.intern_package(key)
        self._packages[key] = pkg_id
        self._package_name[pkg_id] = key
        bare, _ = split_package_ref(key)
        self._by_bare_name.setdefault(bare, []).append(pkg_id)
        return pkg_id

    def packages_named(self, name: str) -> tuple[PkgId, ...]:
        """Every interned id whose name is ``name``, across architectures.

        Needed because the upgrader and apt disagree about architecture
        suffixes. ``main.log``'s ``Foreign`` list uses python-apt's
        ``pkg.name``, which omits ``:arch`` for the native architecture, while
        the apt resolver trace writes ``libwacom9-surface:amd64`` in full.
        Looking the bare name up directly therefore misses, and the
        ``Conflicts`` reorientation that depends on it silently does nothing.

        If ``name`` already carries an architecture, only that exact package is
        returned -- an explicit architecture is a deliberate narrowing, as with
        the ``i386`` orphans in bug 2169028.
        """
        bare, arch = split_package_ref(name)
        if arch:
            existing = self._packages.get(f"{bare}:{arch}")
            return (existing,) if existing is not None else ()
        return tuple(self._by_bare_name.get(bare, ()))

    def package_key(self, pkg_id: PkgId) -> str:
        """Resolve a :data:`PkgId` to its ``name:arch`` key."""
        if pkg_id == ABSENT:
            return ""
        cached = self._package_name.get(pkg_id)
        if cached is not None:
            return cached
        name = self._backend.package_name(pkg_id) or ""
        self._package_name[pkg_id] = name
        return name

    def package_label(self, pkg_id: PkgId) -> str:
        """Resolve a :data:`PkgId` for display, dropping a bare ``:amd64``."""
        return package_display(self.package_key(pkg_id))

    def package_names(self, pkg_ids: Iterable[PkgId]) -> tuple[str, ...]:
        """Resolve many ids for display, in the order given."""
        return tuple(self.package_label(p) for p in pkg_ids)

    # -- templates ----------------------------------------------------------

    def template(self, line: str) -> tuple[TemplateId, tuple[StrId, ...]]:
        """Mask ``line``, intern the template and its masked-out arguments.

        Document frequency is not touched here. A template that occurs forty
        times in one log must count once for that report, and only the store
        knows which report is being written, so counting happens there.
        """
        pattern, args = mask_line(line)
        template_id = self._templates.get(pattern)
        if template_id is None:
            template_id = self._backend.intern_template(pattern)
            self._templates[pattern] = template_id
        return (template_id, tuple(self.string(a) for a in args))

    def pattern(self, template_id: TemplateId) -> str:
        """Resolve a :data:`TemplateId` to its masked pattern."""
        return self._backend.template_pattern(template_id) or ""

    def idf_weights(self) -> dict[TemplateId, float]:
        """Inverse document frequency per template, for similarity scoring.

        ``log(1 + N / df)``, so a template present in every report weighs about
        ``log(2)`` and a template unique to one report weighs ``log(1 + N)``.
        This is what stops similarity being dominated by the thousand lines of
        ``Setting up <PKG>`` that every successful and unsuccessful upgrade
        shares alike, and it needs no hand-maintained stop list: the corpus
        tells us what is boilerplate.
        """
        import math

        total = max(1, self._backend.document_count())
        return {
            template_id: math.log1p(total / df)
            for template_id, df in self._backend.document_frequencies().items()
            if df > 0
        }

    def render(self, template_id: TemplateId, args: Iterable[StrId]) -> str:
        """Reconstruct a log line for display from its template and arguments."""
        return render_template(self.pattern(template_id), (self.text(a) for a in args))
