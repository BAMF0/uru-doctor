# SPDX-License-Identifier: GPL-2.0-or-later
"""Decoding apt's package-state blob, conservatively.

Every package reference in ``apt.log`` carries a state expression:

.. code-block:: text

    < 3.12.3-0ubuntu2.1 -> 3.14.3-0ubuntu2 @ii umU Ib >
    < none | 1.23-2build2 @un uH >
    < none @un H >
    < 1.2.39-5build2 @ii mK Ib >

There are two parts. A version expression, whose *separator* is the single most
informative token in the whole log, and a flag blob beginning with ``@``.

**The separator.** ``->`` means apt selected the candidate; the package is
moving. ``|`` means a candidate exists and apt declined to take it. A bare
version means there is no candidate at all. The ``|`` form is what a stalled
LTS-to-LTS upgrade looks like from the inside: the package that would fix the
dependency is right there in the archive, and apt has decided not to install
it.

**The flag blob.** This is where caution is required.
``/usr/include/apt-pkg/prettyprinters.h`` states that the generated text is
"subject to change without prior notice and should NOT be used as part of a
general user interface". That warning is not theoretical. Observed vocabularies
across apt 2.8.3 and apt 3.2.0 include:

.. code-block:: text

    @ii umU Ib      @un uN          @ii gK          @ii mK Ib
    @ii umU NPb IPb @ii mR          @ii umH Ib      @ii ugH Ib
    @un uH          @un H           @un mH          @un pumN Ib
    @ii mP          @ii umR         @ii gK NPb IPb

``@un H`` has no mode-prefix group at all. ``@un pumN Ib`` has a four-character
one. A regular expression with fixed-width groups shatters on both, and the two
appear only in apt 2.8 output -- that is, only in exactly the 24.04-to-26.04
bugs this tool exists for.

So the strategy is:

1. **Keep the blob verbatim.** Interned whole, stored on every node. It is
   always comparable and always deduplicable even when it cannot be understood.
2. **Decode only what was verified.** The four broken markers, because
   ``Broken`` lines correlate with ``Ib``/``Nb`` presence and that pins their
   meaning. The mode letter, because the ``->`` versus ``|`` separator
   independently confirms which letters mean "moving" and which mean "staying".
3. **Report, never guess.** Unrecognised tokens go into
   :attr:`PackageState.unknown_tokens`, which ``uru-doctor templates
   --unclassified`` surfaces. A future apt that changes the format produces a
   loud "I don't recognise these" rather than a confident wrong answer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

from uru_doctor.models import Mode, NodeBits, VerSelect

# ---------------------------------------------------------------------------
# Grammar
# ---------------------------------------------------------------------------

#: The whole state expression, from ``<`` to ``>``.
#:
#: ``->`` is matched as an explicit alternative so that the ``>`` inside the
#: upgrade separator is not mistaken for the closing bracket. Without that
#: alternative, ``< 3.12.3 -> 3.14.3 @ii umU >`` terminates at the arrow, the
#: flag blob is never seen, and every package that is actually being upgraded
#: decodes as mode UNKNOWN -- which is to say, the common case silently fails.
#:
#: The body is captured whole and split on ``@`` afterwards rather than being
#: decomposed by the pattern. Debian versions contain epoch colons, ``~``
#: suffixes and hyphens, and a single pattern that tries to separate versions,
#: separator and flags in one pass is far easier to get subtly wrong than a
#: capture followed by two string splits. Versions never contain ``@``, so the
#: split is unambiguous.
STATE_RE = re.compile(r"<\s*(?P<body>(?:->|[^<>])*?)\s*>")

#: Flag tokens that denote brokenness, mapped to their bit.
#:
#: These four are decoded because they are independently checkable: a package
#: that appears as the subject of a ``Broken`` line carries ``Ib`` or ``Nb``,
#: which is what establishes that those letters mean what they appear to.
_BROKEN_TOKENS: dict[str, NodeBits] = {
    "Ib": NodeBits.INST_BROKEN,
    "Nb": NodeBits.NOW_BROKEN,
    "IPb": NodeBits.INST_POLICY_BROKEN,
    "NPb": NodeBits.NOW_POLICY_BROKEN,
}

#: Trailing letter of the mode group, mapped to the action apt settled on.
#:
#: Confirmed against the version separator: every observed ``R`` and ``H`` node
#: uses the ``|`` form (candidate available, not taken) while every ``U`` and
#: ``N`` node uses ``->`` (candidate selected). That correlation is what makes
#: this a reading rather than a guess.
_MODE_LETTERS: dict[str, Mode] = {
    "K": Mode.KEEP,
    "U": Mode.UPGRADE,
    "N": Mode.NEW_INSTALL,
    "R": Mode.REMOVE,
    "P": Mode.PURGE,
    "H": Mode.HOLD,
}

#: Leading letters of the mode group.
#:
#: ``g`` marks a package apt considers garbage, i.e. auto-installed and no
#: longer required; that one is used, because an auto-installed package makes a
#: poor root -- something else asked for it. The others are recorded but not
#: interpreted: ``u``, ``m`` and ``p`` appear in combinations
#: (``umU``, ``gK``, ``mR``, ``pumN``) whose individual meanings cannot be
#: established from the logs alone, and inventing an interpretation for them
#: would be exactly the silent-wrongness this module is built to avoid.
_MODE_PREFIXES: frozenset[str] = frozenset("umgp")


class InstallStatus(StrEnum):
    """The leading status field: is the package installed right now?"""

    INSTALLED = "installed"
    NOT_INSTALLED = "not_installed"
    HALF_CONFIGURED = "half_configured"
    UNKNOWN = "unknown"


#: The leading two-character field is dpkg's own status pair: a desired action
#: followed by a current state, as ``dpkg -l`` prints it.
#:
#: This started as an enumeration of the tokens seen in the logs and was wrong
#: within three files -- bug 2150319 produced ``pi`` (desire purge, state
#: installed), which no amount of staring at earlier logs would have predicted.
#: Decoding the two positions by rule covers the whole space instead, so the
#: only tokens that can still surprise us are ones dpkg does not define.
_DESIRED_ACTIONS: frozenset[str] = frozenset("ihrpu")

#: Second character: dpkg's current state. Mapped to the coarser question this
#: tool actually asks, which is whether the package is usable right now.
_CURRENT_STATES: dict[str, InstallStatus] = {
    "i": InstallStatus.INSTALLED,
    "n": InstallStatus.NOT_INSTALLED,
    "c": InstallStatus.NOT_INSTALLED,  # config files only
    "u": InstallStatus.HALF_CONFIGURED,  # unpacked
    "f": InstallStatus.HALF_CONFIGURED,  # half-configured
    "h": InstallStatus.HALF_CONFIGURED,  # half-installed
    "w": InstallStatus.INSTALLED,  # trigger-await
    "t": InstallStatus.INSTALLED,  # trigger-pending
}


def _decode_status(token: str) -> InstallStatus | None:
    """Decode a dpkg desired/current status pair, or None if it is not one."""
    if len(token) != 2:
        return None
    desired, current = token[0], token[1]
    if desired not in _DESIRED_ACTIONS:
        return None
    return _CURRENT_STATES.get(current)


# ---------------------------------------------------------------------------
# Parsed state
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PackageState:
    """What a ``< ... @... >`` expression said.

    A plain slotted dataclass rather than a Pydantic model: tens of thousands
    of these are built during a single ingest and immediately collapsed into
    packed arrays, so construction cost is the only thing that matters and no
    validation is wanted.
    """

    raw: str
    """The verbatim blob including the ``@``, e.g. ``"@ii umU Ib"``.

    Interned and stored on every graph node. The insurance policy against apt
    changing this format.
    """

    cur_version: str | None = None
    cand_version: str | None = None
    selection: VerSelect = VerSelect.NONE
    mode: Mode = Mode.UNKNOWN
    status: InstallStatus = InstallStatus.UNKNOWN
    bits: int = 0
    """Bitfield over :class:`~uru_doctor.models.NodeBits`."""

    unknown_tokens: tuple[str, ...] = ()
    """Flag tokens this build does not recognise.

    Non-empty means apt emitted something new. Surfaced rather than ignored.
    """

    @property
    def inst_broken(self) -> bool:
        return bool(self.bits & (1 << NodeBits.INST_BROKEN))

    @property
    def now_broken(self) -> bool:
        return bool(self.bits & (1 << NodeBits.NOW_BROKEN))

    @property
    def any_broken(self) -> bool:
        return self.inst_broken or self.now_broken

    @property
    def is_installed(self) -> bool:
        return self.status is InstallStatus.INSTALLED

    @property
    def has_unselected_candidate(self) -> bool:
        """A candidate exists and apt declined it.

        The holdback signature. Combined with :attr:`Mode.HOLD` and a
        ``Broken ... Depends on`` edge pointing at this node, it is the single
        most common root cause of a failed LTS-to-LTS upgrade: the package that
        would fix the dependency is available, and apt will not install it.
        """
        return self.selection is VerSelect.AVAILABLE_NOT_SELECTED

    @property
    def blocks_as_new_dependency(self) -> bool:
        """Not installed, a candidate exists, and apt settled on not installing.

        ``< none | 1.23-2build2 @un uH >``. Exactly the state of
        ``libfile-libmagic-perl`` in the lintian bug and of
        ``libpeas-1.0-1`` in the kubuntu one.
        """
        return (
            self.status is InstallStatus.NOT_INSTALLED
            and self.mode is Mode.HOLD
            and self.cand_version is not None
        )

    @property
    def is_unsatisfiable_virtual(self) -> bool:
        """Not installed, no candidate at all, and held.

        ``< none @un H >``. A dependency on a virtual or ABI package that
        nothing in the target release provides -- for instance
        ``libva-driver-abi-1.20:i386`` or ``python3-numpy-abi9``.
        """
        return (
            self.status is InstallStatus.NOT_INSTALLED
            and self.cur_version is None
            and self.cand_version is None
        )


@dataclass(slots=True)
class StateVocabulary:
    """Flag tokens encountered during a parse, for the unclassified report.

    Accumulated across a whole ingest so that an apt format change shows up as
    an aggregate ("4 831 lines carried tokens I don't know") rather than as a
    per-line warning nobody reads.
    """

    seen: dict[str, int] = field(default_factory=dict)
    unknown: dict[str, int] = field(default_factory=dict)

    def note(self, token: str, *, known: bool) -> None:
        self.seen[token] = self.seen.get(token, 0) + 1
        if not known:
            self.unknown[token] = self.unknown.get(token, 0) + 1

    @property
    def has_unknown(self) -> bool:
        return bool(self.unknown)

    def merge(self, other: StateVocabulary) -> None:
        for token, count in other.seen.items():
            self.seen[token] = self.seen.get(token, 0) + count
        for token, count in other.unknown.items():
            self.unknown[token] = self.unknown.get(token, 0) + count


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _split_versions(text: str) -> tuple[str | None, str | None, VerSelect]:
    """Split a version expression into current, candidate and separator kind.

    Handles the three observed forms, in order of how much they tell us:

    - ``"3.12.3-0ubuntu2.1 -> 3.14.3-0ubuntu2"`` -- candidate selected
    - ``"none | 1.23-2build2"`` -- candidate available, declined
    - ``"1.2.39-5build2"`` -- no candidate

    ``none`` is apt's spelling of "not installed" and becomes ``None`` so that
    callers never have to compare against a magic string.
    """
    body = text.strip()
    if not body:
        return (None, None, VerSelect.NONE)

    def norm(value: str) -> str | None:
        value = value.strip()
        return None if not value or value == "none" else value

    # "->" first: a Debian version can contain "-" but never "->".
    if "->" in body:
        left, _, right = body.partition("->")
        return (norm(left), norm(right), VerSelect.SELECTED)
    if "|" in body:
        left, _, right = body.partition("|")
        return (norm(left), norm(right), VerSelect.AVAILABLE_NOT_SELECTED)
    return (norm(body), None, VerSelect.NONE)


def _decode_flags(
    flags: str, vocabulary: StateVocabulary | None
) -> tuple[Mode, InstallStatus, int, tuple[str, ...]]:
    """Decode the whitespace-separated flag blob.

    Tokens are classified by shape rather than by position, which is what makes
    this tolerate ``@un H`` (status then a bare mode letter, no prefix group)
    and ``@un pumN Ib`` (a four-character mode group) with the same code path.
    """
    mode = Mode.UNKNOWN
    status = InstallStatus.UNKNOWN
    bits = 0
    unknown: list[str] = []

    for index, token in enumerate(flags.split()):
        known = False

        # dpkg's desired/current status pair, only ever first.
        if index == 0 and (decoded := _decode_status(token)) is not None:
            status = decoded
            known = True

        # A broken marker.
        elif token in _BROKEN_TOKENS:
            bits |= 1 << _BROKEN_TOKENS[token]
            known = True

        # A mode group: optional prefix letters then one action letter. Accepted
        # at any length, including zero prefix letters, which is what ``@un H``
        # requires and what a fixed-width pattern cannot express.
        elif token and token[-1] in _MODE_LETTERS:
            prefixes = token[:-1]
            if all(character in _MODE_PREFIXES for character in prefixes):
                mode = _MODE_LETTERS[token[-1]]
                if "g" in prefixes:
                    bits |= 1 << NodeBits.AUTO_INSTALLED
                known = True

        if vocabulary is not None:
            vocabulary.note(token, known=known)
        if not known:
            unknown.append(token)

    return (mode, status, bits, tuple(unknown))


def parse_state(text: str, vocabulary: StateVocabulary | None = None) -> PackageState | None:
    """Parse one ``< ... @... >`` expression out of ``text``.

    Returns None when ``text`` contains no state expression at all, which is
    normal: plenty of ``apt.log`` lines reference a package without one.
    """
    match = STATE_RE.search(text)
    if match is None:
        return None
    return _state_from_match(match, vocabulary)


def _state_from_match(match: re.Match[str], vocabulary: StateVocabulary | None) -> PackageState:
    body = match.group("body") or ""
    version_text, separator, flag_text = body.partition("@")
    flags = flag_text.strip() if separator else ""
    cur, cand, selection = _split_versions(version_text)
    mode, status, bits, unknown = _decode_flags(flags, vocabulary)
    return PackageState(
        raw=f"@{flags}" if flags else "",
        cur_version=cur,
        cand_version=cand,
        selection=selection,
        mode=mode,
        status=status,
        bits=bits,
        unknown_tokens=unknown,
    )


def parse_states(text: str, vocabulary: StateVocabulary | None = None) -> list[PackageState]:
    """Parse every state expression in ``text``, left to right.

    Needed because some lines carry two. ``Upgrading: A < ... > due to B
    Depends on C < ... > (= v)`` describes a subject and the dependency that
    forced it, and both states matter.
    """
    return [_state_from_match(m, vocabulary) for m in STATE_RE.finditer(text)]


def strip_states(text: str) -> str:
    """Remove state expressions, leaving the prose and package names.

    Used by the lexer: once the states are extracted, what remains is a short
    fixed phrase and one or two package references, which is far easier to
    match against than the original line.
    """
    return STATE_RE.sub(" ", text)
