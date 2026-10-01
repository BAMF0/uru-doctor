"""Detecting resolver livelock.

apt's problem resolver can get stuck alternating between two contradictory
decisions about the same package, never converging, until it exhausts its
iterations and reports a generic failure. The log that results is the most
confusing kind this tool handles: it contains hundreds of ``Broken`` lines, a
dozen plausible roots, and an error message -- ``Error, pkgProblemResolver::
Resolve generated breaks`` -- that names nothing at all.

LP#2150319 is the reference case. Its trace ends with this pair repeating, the
``Investigating`` counter climbing each time::

    Investigating (17) lintian:amd64 < ... @ii umU Ib >
    Broken lintian:amd64 Depends on libfile-libmagic-perl:amd64 < none | ... >
      Holding Back lintian:amd64 rather than change libfile-libmagic-perl:amd64
    Investigating (18) libyaml-libyaml-perl:amd64 < ... >
    Broken libyaml-libyaml-perl:amd64 Breaks on lintian:amd64 < ... > (< 2.119.0~)
      Upgrading lintian:amd64 due to Breaks field in libyaml-libyaml-perl:amd64
    Investigating (18) lintian:amd64 ...
      Holding Back lintian:amd64 rather than change libfile-libmagic-perl:amd64

``libyaml-libyaml-perl`` *requires* a newer ``lintian``; ``lintian`` requires a
package apt will not install; so apt upgrades and un-upgrades ``lintian`` for
ever. Upstream's eventual fix,
``DistUpgradeQuirks._fix_lintian_resolver_deadlock``, marks
``libfile-libmagic-perl`` for install to break the cycle, and its docstring
describes precisely this.

Why this needs its own detector rather than falling out of root analysis: a
livelocked package is not the root of anything. ``lintian`` has two victims and
loses every blast-radius comparison to roots that explain five or thirty-nine
packages, so ranking by consequence buries it. The thing that makes it the
cause is not how much it broke -- it is that apt was still arguing with itself
about it when it gave up.

The signature is cheap and, across the six real logs recorded here, exact: zero
oscillating packages in three logs that resolved or failed for other reasons,
one in LP#2150319 -- ``lintian``, with forty keeps against twenty upgrades --
and three in the bug whose log was truncated mid-run, which is itself the
likeliest explanation for why that run never finished.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from uru_doctor.apt.grammar import Verb
from uru_doctor.models import PkgId

if TYPE_CHECKING:
    from uru_doctor.apt.sections import Section
    from uru_doctor.intern import Interner

__all__ = [
    "MIN_REVERSALS",
    "Oscillation",
    "detect_oscillations",
]

#: Decisions that keep a package at its installed version *to resolve a
#: conflict*.
#:
#: Narrow on purpose. ``FIXING_VIA_KEEP`` and ``KEEPING_PACKAGE`` are ordinary
#: steps of a converging resolve, and including them made thirty-six packages
#: look oscillating in a log whose real problem was a third-party conflict.
#: What identifies a livelock is specifically the pairing of an explicit
#: hold-back against a forced upgrade of the same package.
_KEEP_VERBS: Final[frozenset[Verb]] = frozenset(
    {
        Verb.HOLDING_BACK,
        Verb.MARK_KEEP,
    }
)

#: Decisions that move a package forward *because something else demanded it*.
#:
#: ``MARK_INSTALL`` is excluded: apt emits it for every package it decides to
#: install, thousands of times in a full upgrade, so counting it as a reversal
#: makes the signature useless. The ``Upgrading X due to ...`` family is the
#: true opposite of a hold-back, because both are the resolver acting on a
#: conflict.
_UPGRADE_VERBS: Final[frozenset[Verb]] = frozenset(
    {
        Verb.UPGRADING_DUE_TO_FIELD,
        Verb.UPGRADING_DUE_TO_DEP,
        Verb.UPGRADING_DUE_TO,
    }
)

#: How many complete reversals before this is called a livelock.
#:
#: Chosen from the measured distribution rather than guessed. Across the six
#: real logs recorded here, reversal counts are sharply bimodal::
#:
#:     rev=1    23 packages     normal resolver exploration
#:     rev=2    15 packages     normal resolver exploration
#:     rev=17    1 package      genuine livelock
#:     rev=18    1 package      genuine livelock
#:     rev=20    1 package      genuine livelock  (LP#2150319's lintian)
#:
#: Nothing at all falls between 3 and 16, so any threshold in that range
#: separates the two populations. Five is used: comfortably clear of the noise,
#: far below the signal, and defensible without reference to these particular
#: logs -- a package reversed five times is not converging.
MIN_REVERSALS: Final[int] = 5


@dataclass(frozen=True, slots=True)
class Oscillation:
    """A package apt could not settle on."""

    pkg_id: PkgId
    keeps: int
    """Decisions holding it at the installed version."""

    upgrades: int
    """Decisions moving it forward."""

    blocked_by: PkgId = 0
    """The package apt refused to change, from ``Holding Back X rather than
    change Y``. This is the actionable one: installing it breaks the cycle, and
    it is what upstream's quirk marks for LP#2150319."""

    forced_by: PkgId = 0
    """The package whose ``Breaks`` forced the upgrade, from ``Upgrading X due
    to Breaks field in Z``. The other half of the contradiction."""

    last_line: int = 0
    """Line of the final decision, for ordering and evidence."""

    @property
    def reversals(self) -> int:
        """The number of complete flip-flops, which is the weaker count."""
        return min(self.keeps, self.upgrades)

    @property
    def is_terminal(self) -> bool:
        """Whether apt was still oscillating when the trace ended.

        Not currently used for filtering -- an oscillation anywhere in a trace
        that ends in failure is worth reporting -- but recorded because
        "stuck at the end" is stronger evidence than "stuck in the middle".
        """
        return self.last_line > 0


def detect_oscillations(
    section: Section, interner: Interner, *, min_reversals: int = MIN_REVERSALS
) -> tuple[Oscillation, ...]:
    """Find packages apt decided and un-decided repeatedly.

    Returns them worst-first. Operates on the already-lexed token stream rather
    than re-reading the log, so it costs one pass over tokens the caller has
    anyway and cannot disagree with the rest of the analysis about what the log
    says.
    """
    keeps: dict[PkgId, int] = {}
    upgrades: dict[PkgId, int] = {}
    blocked_by: dict[PkgId, PkgId] = {}
    forced_by: dict[PkgId, PkgId] = {}
    last_line: dict[PkgId, int] = {}

    for token in section.tokens:
        if not token.subject:
            continue
        subject = interner.package(token.subject)

        if token.verb in _KEEP_VERBS:
            keeps[subject] = keeps.get(subject, 0) + 1
            last_line[subject] = token.line_no
            # ``Holding Back X rather than change Y`` names Y as the object,
            # and Y is the package worth acting on.
            if token.verb is Verb.HOLDING_BACK and token.object:
                blocked_by.setdefault(subject, interner.package(token.object))
        elif token.verb in _UPGRADE_VERBS:
            upgrades[subject] = upgrades.get(subject, 0) + 1
            last_line[subject] = token.line_no
            if token.object:
                forced_by.setdefault(subject, interner.package(token.object))

    found = [
        Oscillation(
            pkg_id=pkg_id,
            keeps=keep_count,
            upgrades=upgrades.get(pkg_id, 0),
            blocked_by=blocked_by.get(pkg_id, 0),
            forced_by=forced_by.get(pkg_id, 0),
            last_line=last_line.get(pkg_id, 0),
        )
        for pkg_id, keep_count in keeps.items()
        if keep_count >= min_reversals and upgrades.get(pkg_id, 0) >= min_reversals
    ]
    found.sort(key=lambda o: (-o.reversals, -o.keeps, o.pkg_id))
    return tuple(found)


def worst(oscillations: Sequence[Oscillation]) -> Oscillation | None:
    """The most severely oscillating package, if any."""
    return oscillations[0] if oscillations else None
