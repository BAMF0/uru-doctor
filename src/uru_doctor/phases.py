"""Mapping ``main.log`` markers onto :class:`~uru_doctor.models.Phase`.

The upgrader does not announce its phases. It logs incidental progress
messages, and the phase has to be inferred from them. Every marker here was
taken from a ``logging.debug``/``logging.info`` call in
``/usr/lib/python3/dist-packages/DistUpgrade/`` rather than guessed at from
example logs, because a marker that only appears in the three logs we happen
to have is a marker that will silently stop working.

Two properties matter for the rest of the tool:

Monotonicity
    Phases only ever advance. The upgrader reopens the cache several times
    (``openCache()`` appears five times in a successful run), and a naive
    mapping would bounce the phase back to ``CACHE_OPEN`` late in the upgrade
    and make a ``COMMIT`` failure look like a planning failure. So a marker
    that would move the phase backwards is ignored.

Commit detection
    ``COMMIT`` is the boundary that decides whether the machine was modified.
    It is recognised from ``Quirks.StartUpgrade`` and ``cache.commit()``,
    either of which means dpkg is about to run.
"""

from __future__ import annotations

import re
from typing import Final, NamedTuple

from uru_doctor.models import Phase

__all__ = [
    "PHASE_MARKERS",
    "PhaseMarker",
    "PhaseTracker",
    "phase_for",
]


class PhaseMarker(NamedTuple):
    """A ``main.log`` message that reveals which phase the upgrader is in."""

    pattern: re.Pattern[str]
    phase: Phase
    enters: bool = True
    """``True`` when the marker means the phase has begun, ``False`` when it
    means the phase has just finished. ``/openCache()`` is the latter: it is
    logged on the way out, so it closes ``CACHE_OPEN`` rather than opening it.
    """


def _m(pattern: str, phase: Phase, *, enters: bool = True) -> PhaseMarker:
    return PhaseMarker(re.compile(pattern), phase, enters)


#: Ordered longest-intent-first; the first match wins.
#:
#: Several markers map to the same phase on purpose. The upgrader has more than
#: one route into some phases depending on frontend and configuration, and
#: missing a marker costs us the phase boundary entirely, whereas a redundant
#: one costs nothing because of monotonicity.
PHASE_MARKERS: Final[tuple[PhaseMarker, ...]] = (
    # -- startup ---------------------------------------------------------
    _m(r"^Using config files ", Phase.INIT),
    _m(r"^uname information:", Phase.INIT),
    _m(r"^release-upgrader version ", Phase.INIT),
    _m(r"^Using '\S+' view", Phase.INIT),
    # The screen re-exec restarts the whole upgrader inside screen, so a log
    # that ends here is not a failure -- it is a log that moved elsewhere.
    _m(r"^re-exec inside screen:", Phase.SCREEN_REEXEC),
    _m(r"^screen returned:", Phase.SCREEN_REEXEC),
    # -- cache -----------------------------------------------------------
    _m(r"^_pythonSymlinkCheck run", Phase.PRE_CACHE_OPEN),
    _m(r"^running Quirks\.PreCacheOpen", Phase.PRE_CACHE_OPEN),
    _m(r"^openCache\(\)", Phase.CACHE_OPEN),
    _m(r"^/openCache\(\), new cache size", Phase.CACHE_OPEN, enters=False),
    _m(r"^need_server_mode\(\)", Phase.CACHE_OPEN),
    _m(r"^checkViewDepends\(\)", Phase.VIEW_DEPENDS),
    # -- the two updates -------------------------------------------------
    # Distinguished only by showErrors: the first update is advisory and its
    # failures are swallowed, the second is authoritative.
    _m(r"^running doUpdate\(\) \(showErrors=False\)", Phase.INITIAL_UPDATE),
    _m(r"^doPostInitialUpdate", Phase.POST_INITIAL_UPDATE),
    _m(r"^running Quirks\.PostInitialUpdate", Phase.POST_INITIAL_UPDATE),
    _m(
        r"^(?:updateDeb822Sources|migrateToDeb822Sources|updateSourcesList)\(\)",
        Phase.SOURCES_REWRITE,
    ),
    _m(r"^verifySourcesListEntry:", Phase.SOURCES_REWRITE),
    _m(r"^running doUpdate\(\) \(showErrors=True\)", Phase.SECOND_UPDATE),
    # -- planning --------------------------------------------------------
    _m(r"^running Quirks\.PreDistUpgradeCache", Phase.PRE_DIST_UPGRADE),
    _m(r"^Running KeepInstalledSection rules", Phase.PRE_DIST_UPGRADE),
    _m(r"^Marking '\S+' for upgrade", Phase.CALCULATE),
    _m(r"^running Quirks\.PostDistUpgradeCache", Phase.CALCULATE),
    _m(r"^running installTasks", Phase.CALCULATE),
    _m(r"^About to apply the following changes", Phase.CALCULATE),
    # -- download --------------------------------------------------------
    _m(r"^Fetch: updateStatus", Phase.FETCH),
    # -- the point of no return ------------------------------------------
    # ``StartUpgrade`` is the reliable marker: ``doDistUpgrade`` calls
    # ``self.quirks.StartUpgrade()`` immediately before ``self.cache.commit()``.
    #
    # Bare ``cache.commit()`` is deliberately *not* a marker. It is logged at
    # INFO by ``MyCache.commit`` and therefore also appears when a quirk
    # commits -- ``_maybe_prevent_flatpak_auto_removal`` does exactly that
    # during PostInitialUpdate. Honouring it put LP#2150319 at ``COMMIT`` when
    # that run actually died in the resolver, turning a planning failure into
    # an apparent half-upgraded system. ``cache.commit() returned`` is safe
    # because only ``doDistUpgrade`` logs it.
    _m(r"^running Quirks\.StartUpgrade", Phase.COMMIT),
    _m(r"^writing dpkg progress log to", Phase.COMMIT),
    _m(r"^got a conffile-prompt from dpkg", Phase.COMMIT),
    _m(r"^cache\.commit\(\) returned", Phase.COMMIT, enters=False),
    # -- after dpkg ------------------------------------------------------
    _m(r"^running Quirks\.PostUpgrade", Phase.POST_UPGRADE),
    _m(r"^Start checking for obsolete pkgs", Phase.REMOVE_OBSOLETE),
    _m(r"^tryMarkObsoleteForRemoval\(\)", Phase.REMOVE_OBSOLETE),
    _m(r"^Finish checking for obsolete pkgs", Phase.REMOVE_OBSOLETE, enters=False),
    _m(r"^running Quirks\.PostCleanup", Phase.POST_CLEANUP),
    _m(r"^Running PostInstallScript:", Phase.POST_INSTALL_SCRIPTS),
    _m(r"^confirmRestart\(\) called", Phase.DONE),
)


def phase_for(message: str) -> PhaseMarker | None:
    """Return the marker matching ``message``, or ``None``.

    ``message`` is the log record with its timestamp and level already
    stripped.
    """
    for marker in PHASE_MARKERS:
        if marker.pattern.match(message):
            return marker
    return None


class PhaseTracker:
    """Advances through phases as markers arrive, never going backwards.

    Backward movement is the thing to guard against. ``openCache()`` is logged
    five times in a successful upgrade, the last of which is after dpkg has
    finished; honouring it would report a ``CACHE_OPEN`` failure for a run that
    actually died during cleanup, which inverts the severity of the bug.
    """

    __slots__ = ("_current", "_entered", "_regressions")

    def __init__(self) -> None:
        self._current = Phase.UNKNOWN
        self._entered: dict[Phase, int] = {}
        self._regressions = 0

    @property
    def current(self) -> Phase:
        return self._current

    @property
    def regressions(self) -> int:
        """Markers ignored for pointing backwards.

        Expected to be non-zero in any real log. Useful only as a sanity check
        that the tracker is doing its job.
        """
        return self._regressions

    def entered_at(self, phase: Phase) -> int | None:
        """The line number where ``phase`` was first entered."""
        return self._entered.get(phase)

    def feed(self, message: str, line_no: int) -> Phase:
        """Offer a log record, and return the phase in effect afterwards.

        The returned phase applies *to this record*: a record that enters a
        phase belongs to the phase it enters, while one that closes a phase
        still belongs to the phase it closes.
        """
        marker = phase_for(message)
        if marker is None:
            return self._current

        if marker.phase < self._current:
            self._regressions += 1
            return self._current

        if marker.phase > self._current:
            self._current = marker.phase
            self._entered.setdefault(marker.phase, line_no)
        return self._current
