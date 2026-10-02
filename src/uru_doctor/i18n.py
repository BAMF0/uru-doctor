# SPDX-License-Identifier: GPL-2.0-or-later
"""Recognising localised log messages.

Ubuntu's upgrade logs are not reliably English, and which parts are translated
is not a matter of taste -- it follows the code that produced them.

**Not translated.** apt's resolver trace. ``Investigating``, ``Broken``,
``Holding Back``, ``MarkKeep`` and the state blobs are raw C++ debug output
with no ``_()`` around them, so the whole of :mod:`uru_doctor.apt` works
unchanged on any locale. The upgrader's own ``logging.error`` calls are plain
Python strings and likewise untranslated -- ``failed to import AptClone`` and
``Package peazip has no priority set`` appear verbatim in an Italian log.

**Translated.** Anything apt or dpkg prints *at* the user. That includes the
error stack the upgrader embeds in ``Dist-upgrade failed:``, so a Catalan log
says::

    E:Error, pkgProblemResolver::Resolve ha trencat coses, potser a causa de
    paquets retinguts.

and the whole of ``apt-term.log``, where ``Setting up`` becomes
``Configurazione di`` and ``dpkg: warning:`` becomes ``dpkg: attenzione:``.

Three approaches were considered and two rejected.

*Matching English only* loses the apt error stack and the entirety of
``apt-term.log`` on any non-English report -- which is a large share of the
queue, and the share least likely to be triaged by someone who can read the
reporter's own description.

*Hand-written patterns per language* cannot be verified and cannot be kept up
to date. There are ninety-odd translations.

*Using the same catalogs the tools used* is what this module does. The ``.mo``
files are installed at ``/usr/share/locale/<lang>/LC_MESSAGES/``, the log
states its own locale (``main.log``'s ``locale: 'ca_ES' 'UTF-8'``), and
:mod:`gettext` will render any known message into that language. So the known
English message is translated *forward* and compared, rather than attempting to
translate the log backwards.

Where a catalog is unavailable, :data:`ANCHORS` provides a fallback: fragments
that survive translation because they are identifiers rather than prose.
``pkgProblemResolver::Resolve`` appears untranslated in Catalan, Italian,
German, Spanish, Portuguese, Chinese, Russian and Japanese. The fallback is
genuinely weaker -- some messages have no such fragment, and
``Unable to correct problems, you have held broken packages`` has not a single
Latin character in its Chinese or Japanese forms -- so it is a backstop, never
the primary route.
"""

from __future__ import annotations

import gettext
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Final

__all__ = [
    "ANCHORS",
    "APT_MESSAGES",
    "DEP_TYPE_NAMES",
    "DPKG_MESSAGES",
    "LOCALE_DIR",
    "MessageCatalogue",
    "catalogue_for",
    "dep_type_aliases",
    "language_of",
    "localise",
]

LOCALE_DIR: Final[Path] = Path("/usr/share/locale")

#: Catalog domains to try, in order. The apt library's domain carries its
#: soname, which changes between releases, so a log produced by apt 2.8 may
#: need ``libapt-pkg6.0`` while the local system only ships ``libapt-pkg7.0``.
#: Every candidate is tried and the first that actually translates wins.
_APT_DOMAINS: Final[tuple[str, ...]] = (
    "libapt-pkg7.0",
    "libapt-pkg6.0",
    "libapt-pkg5.0",
    "apt",
)

_DPKG_DOMAINS: Final[tuple[str, ...]] = ("dpkg",)

#: Canonical English messages from ``libapt-pkg`` that bear on diagnosis.
#:
#: Keys are stable identifiers used by the rules; values are the msgid exactly
#: as it appears in the catalog, because gettext matches on the msgid byte for
#: byte -- including the trailing space on the dpkg-interrupted message.
APT_MESSAGES: Final[dict[str, str]] = {
    "resolver_breaks": (
        "Error, pkgProblemResolver::Resolve generated breaks, this may be caused by held packages."
    ),
    "held_broken": "Unable to correct problems, you have held broken packages.",
    "dpkg_interrupted": (
        "dpkg was interrupted, you must manually run '%s' to correct the problem. "
    ),
    "unmet_deps": (
        "Unmet dependencies. Try 'apt --fix-broken install' with no packages "
        "(or specify a solution)."
    ),
}

#: Canonical English messages from ``dpkg`` that ``apt-term.log`` parsing needs.
DPKG_MESSAGES: Final[dict[str, str]] = {
    "setting_up": "Setting up %s (%s) ...\n",
    "unpacking": "Unpacking %s (%s) ...\n",
    "unpacking_over": "Unpacking %s (%s) over (%s) ...\n",
    "preparing": "Preparing to unpack %s ...\n",
    "removing": "Removing %s (%s) ...\n",
    "purging": "Purging configuration files for %s (%s) ...\n",
    "deconfiguring": "De-configuring %s (%s), to allow removal of %s ...\n",
    "errors_encountered": "Errors were encountered while processing:\n",
    "dep_unconfigured": "dependency problems - leaving unconfigured",
    "dep_triggers": "dependency problems - leaving triggers unprocessed",
    "warning_prefix": "dpkg: warning: ",
    "error_prefix": "dpkg: error: ",
}

#: Fragments that survive translation, used when no catalog is available.
#:
#: Identifiers, command lines and C++ symbol names, not prose. Note the French
#: catalog renders the resolver message with ``pkgProblem::Resolve`` rather than
#: ``pkgProblemResolver::Resolve``, so the anchor stops at ``pkgProblem``.
ANCHORS: Final[dict[str, tuple[str, ...]]] = {
    "resolver_breaks": ("pkgProblem", "::Resolve"),
    "dpkg_interrupted": ("dpkg --configure -a",),
    "unmet_deps": ("apt --fix-broken install",),
    # ``held_broken`` has no anchor. Every word of it is translated, and its
    # Chinese and Japanese forms contain no Latin text at all, so without a
    # catalog it is simply unrecognisable. Recorded here as an empty tuple so
    # that the omission is explicit rather than looking like an oversight.
    "held_broken": (),
}

_LOCALE_RE: Final = re.compile(r"^(?P<lang>[A-Za-z]{2,3})(?:[_-](?P<region>[A-Za-z]{2,}))?")


def language_of(locale: str | None) -> tuple[str, ...]:
    """Candidate gettext language codes for a locale string, most specific first.

    ``"ca_ES"`` yields ``("ca_ES", "ca")`` and ``"pt_BR"`` yields
    ``("pt_BR", "pt")``. Region-specific catalogs exist for a handful of
    languages -- Brazilian Portuguese most importantly -- and differ from the
    base language, so the specific form has to be tried first.

    ``"C"`` and ``"POSIX"`` yield nothing: they mean untranslated, and asking
    gettext for them would waste a filesystem lookup per message.
    """
    if not locale:
        return ()
    cleaned = locale.strip().split(".")[0].split("@")[0]
    if cleaned in ("C", "POSIX", ""):
        return ()
    match = _LOCALE_RE.match(cleaned)
    if match is None:
        return ()
    language = match["lang"].lower()
    region = (match["region"] or "").upper()
    if region:
        return (f"{language}_{region}", language)
    return (language,)


@lru_cache(maxsize=64)
def _translator(domain: str, language: str) -> gettext.NullTranslations | None:
    """Load one catalog, or ``None`` if it is not installed.

    Cached because a corpus run asks for the same handful of domains thousands
    of times, and each miss is a filesystem probe.
    """
    try:
        return gettext.translation(
            domain, localedir=str(LOCALE_DIR), languages=[language], fallback=False
        )
    except (OSError, ValueError):
        return None


def localise(message: str, locale: str | None, *, domains: tuple[str, ...]) -> str:
    """Render ``message`` as the given locale would, or return it unchanged.

    Unchanged is the honest answer when no catalog is installed or the
    translation is identical to the source, and callers treat it as such.
    """
    for language in language_of(locale):
        for domain in domains:
            translator = _translator(domain, language)
            if translator is None:
                continue
            translated = translator.gettext(message)
            if translated != message:
                return translated
    return message


@dataclass(frozen=True, slots=True)
class MessageCatalogue:
    """Localised forms of every message the rules need, for one locale."""

    locale: str = ""
    apt: dict[str, str] = field(default_factory=dict)
    """Key to the localised ``libapt-pkg`` message."""

    dpkg: dict[str, str] = field(default_factory=dict)
    """Key to the localised ``dpkg`` message."""

    available: bool = False
    """Whether any catalog was found. ``False`` means English-plus-anchors."""

    def matches(self, key: str, text: str) -> bool:
        """Whether ``text`` contains the message identified by ``key``.

        Three routes, tried in order of reliability: the localised form from
        the catalog apt itself used, then the English original -- which still
        appears when the reporter's locale is ``C`` or the catalog is
        incomplete -- then the translation-independent anchors.
        """
        localised = self.apt.get(key) or self.dpkg.get(key)
        if localised and _contains(text, localised):
            return True

        english = APT_MESSAGES.get(key) or DPKG_MESSAGES.get(key)
        if english and _contains(text, english):
            return True

        anchors = ANCHORS.get(key, ())
        return bool(anchors) and all(anchor in text for anchor in anchors)

    def first_match(self, text: str, keys: tuple[str, ...]) -> str | None:
        for key in keys:
            if self.matches(key, text):
                return key
        return None


def _contains(haystack: str, needle: str) -> bool:
    """Substring test that tolerates format placeholders and trailing space.

    The msgids carry ``%s`` and trailing newlines, neither of which survives
    into the log, so the needle is compared on its longest literal run. Below
    eight characters the run is too short to be evidence -- ``dpkg: `` would
    match almost anything in a dpkg log -- and the test refuses rather than
    guessing.
    """
    runs = [
        part.strip().rstrip(".:")
        for part in re.split(r"%[sd]|\\n|\n", needle)
        if len(part.strip()) >= 8
    ]
    if not runs:
        return False
    return all(run in haystack for run in runs[:3])


@lru_cache(maxsize=32)
def catalogue_for(locale: str | None) -> MessageCatalogue:
    """Build the message catalogue for one locale.

    Cached per locale: a corpus of hundreds of reports has a handful of
    distinct locales between them.
    """
    languages = language_of(locale)
    if not languages:
        return MessageCatalogue(locale=locale or "")

    apt = {
        key: localise(message, locale, domains=_APT_DOMAINS)
        for key, message in APT_MESSAGES.items()
    }
    dpkg = {
        key: localise(message, locale, domains=_DPKG_DOMAINS)
        for key, message in DPKG_MESSAGES.items()
    }
    available = any(apt[k] != APT_MESSAGES[k] for k in APT_MESSAGES) or any(
        dpkg[k] != DPKG_MESSAGES[k] for k in DPKG_MESSAGES
    )
    return MessageCatalogue(locale=locale or "", apt=apt, dpkg=dpkg, available=available)


def dpkg_verb_patterns(locale: str | None) -> dict[str, re.Pattern[str]]:
    """Patterns for dpkg's progress verbs in the log's language.

    ``apt-term.log`` is counted by these, and on an Italian log the English
    forms match nothing at all -- ``Setting up`` is ``Configurazione di`` --
    so every count comes out zero and every dpkg failure is missed.

    The verb is not always at the start of the line. German renders
    ``Setting up %s (%s) ...`` as ``%s (%s) wird eingerichtet ...``, putting
    the package first, so these are matched anywhere in the line rather than
    anchored. The *longest* literal run of each message is used for the same
    reason: taking the first run yields an empty string for any language that
    leads with the placeholder.
    """
    catalogue = catalogue_for(locale)
    out: dict[str, re.Pattern[str]] = {}
    for key in ("setting_up", "unpacking", "preparing", "removing", "purging"):
        literals: set[str] = set()
        for form in (DPKG_MESSAGES[key], catalogue.dpkg.get(key, "")):
            if not form:
                continue
            runs = [part.strip() for part in re.split(r"%[sd]|\\n|\n", form)]
            longest = max(runs, key=len, default="")
            if len(longest) >= 4:
                literals.add(longest)
        if literals:
            ordered = sorted(literals, key=len, reverse=True)
            out[key] = re.compile("|".join(re.escape(lit) for lit in ordered))
    return out


#: apt's nine dependency-type names, which it prints through ``_()``.
#:
#: This is the discovery that matters most for non-English logs. apt's resolver
#: trace is otherwise raw debug output, so it was reasonable to assume the whole
#: of it was untranslated -- but ``pkgCache::DepType()`` returns a translated
#: string, and it is interpolated straight into lines like
#: ``Installing X as Depends of Y``. A Catalan log therefore says ``Depèn`` and
#: an Italian one ``Dipende``, which took lexer coverage from 100% to 68.7%
#: and 78.6% respectively -- most of the conflict graph simply absent.
#:
#: Italian renders ``Conflicts`` as ``Va in conflitto``, with spaces, so no
#: single-word pattern can match these.
DEP_TYPE_NAMES: Final[tuple[str, ...]] = (
    "Depends",
    "PreDepends",
    "Suggests",
    "Recommends",
    "Conflicts",
    "Replaces",
    "Obsoletes",
    "Breaks",
    "Enhances",
)


@lru_cache(maxsize=1)
def dep_type_aliases() -> dict[str, str]:
    """Every installed translation of a dependency-type name, reversed.

    Maps a lowercased translated form to its canonical English name, across
    every locale installed on this machine. Built once and cached.

    Global rather than per-locale on purpose. The alternative is to thread the
    log's locale down into the lexer, which would mean a locale-parameterised
    grammar and a recompiled pattern table per report. These nine terms are
    specific enough that a collision between languages would be a curiosity,
    and the cost of one -- misreading ``Breaks`` as ``Depends`` on some
    hypothetical log -- is bounded and visible, whereas failing to resolve the
    name at all silently empties the graph.

    Degrades to the English names alone when no catalogs are installed, which
    is the correct behaviour in a container.
    """
    aliases: dict[str, str] = {}
    for name in DEP_TYPE_NAMES:
        aliases[name.lower()] = name
    aliases["pre-depends"] = "PreDepends"

    if not LOCALE_DIR.is_dir():
        return aliases

    for language_dir in sorted(LOCALE_DIR.iterdir()):
        messages = language_dir / "LC_MESSAGES"
        if not messages.is_dir():
            continue
        for domain in _APT_DOMAINS:
            if not (messages / f"{domain}.mo").is_file():
                continue
            translator = _translator(domain, language_dir.name)
            if translator is None:
                continue
            for name in DEP_TYPE_NAMES:
                translated = translator.gettext(name).strip().lower()
                # Only record a genuine translation, and never let one
                # language's rendering displace another's.
                if translated and translated != name.lower():
                    aliases.setdefault(translated, name)
            break
    return aliases
