# SPDX-License-Identifier: GPL-2.0-or-later
"""What a rule is allowed to see.

A single object rather than a pile of parameters, for two reasons.

Rules must not re-parse. Everything they need was computed during ingest, and
a rule that re-reads a log can disagree with the record, which is how two parts
of a tool end up telling a triager different stories.

Rules must be cheap to add. A new rule gets the whole context and returns
findings; it never has to know how the context was assembled or in what order
the parsers ran.

The context also owns :meth:`RuleContext.finding`, so every rule produces
findings with consistent provenance -- the rule name, the phase, and evidence
indices that really point into :attr:`UpgradeRun.events`.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from uru_doctor.apt.roots import RootReport, analyse
from uru_doctor.intern import Interner
from uru_doctor.models import (
    Cause,
    Confidence,
    Decision,
    Finding,
    Level,
    LogSource,
    Phase,
    PkgId,
    Severity,
    UpgradeRun,
)
from uru_doctor.parsers.apportmeta import ApportMeta
from uru_doctor.parsers.aptterm import TermLog
from uru_doctor.parsers.mainlog import BULK_LIST_PREFIXES

__all__ = ["RuleContext"]


@dataclass(slots=True)
class RuleContext:
    """The evidence available to rules for one run."""

    run: UpgradeRun
    interner: Interner
    meta: ApportMeta | None = None
    term: TermLog | None = None
    """Parsed ``apt-term.log``, when one was present."""

    # Lazy caches. Plain fields rather than ``functools.cached_property``,
    # which cannot work on a ``slots=True`` dataclass -- there is no instance
    # ``__dict__`` for it to write into.
    _root_reports: list[RootReport] = field(default_factory=list, repr=False)
    _analysed: bool = field(default=False, repr=False)
    _error_messages: tuple[str, ...] | None = field(default=None, repr=False)
    _all_messages: tuple[str, ...] | None = field(default=None, repr=False)
    _apt_errors: tuple[str, ...] | None = field(default=None, repr=False)

    # -- text evidence ------------------------------------------------------

    @property
    def error_messages(self) -> tuple[str, ...]:
        """``ERROR``-level messages from ``main.log``, in order.

        Rendered back from the interned templates so patterns match the text
        the upgrader actually wrote.
        """
        if self._error_messages is None:
            self._error_messages = tuple(
                self.interner.render(event.template_id, event.args)
                for event in self.run.events
                if event.level is Level.ERROR
            )
        return self._error_messages

    @property
    def all_messages(self) -> tuple[str, ...]:
        """Every ``main.log`` message, for rules that need warnings too."""
        if self._all_messages is None:
            self._all_messages = tuple(
                self.interner.render(event.template_id, event.args) for event in self.run.events
            )
        return self._all_messages

    @property
    def apt_errors(self) -> tuple[str, ...]:
        """The ``E:`` entries from apt's error stack.

        Only the errors. The ``W:`` entries are in
        :attr:`UpgradeRun.apt_warning_entries` and are never matched against,
        because a warning is not a cause -- the Chrome i386 warning in bug
        2150319 sat next to the real resolver error and misdirected the bug for
        weeks.
        """
        if self._apt_errors is None:
            self._apt_errors = tuple(
                self.interner.text(entry) for entry in self.run.apt_error_entries
            )
        return self._apt_errors

    def event_indices(self, needle: str, *, level: Level | None = None) -> tuple[int, ...]:
        """Indices of events whose rendered text contains ``needle``.

        These become :attr:`Finding.evidence`, so a reader can be pointed at
        the exact lines rather than being asked to take the verdict on trust.

        Bulk enumerations are skipped. The upgrader logs its whole working set
        on single lines -- ``Upgrade:`` followed by three thousand names, and
        nine more like it -- so a substring match finds the needle in all of
        them. Those lines are true but say nothing: a package appearing among
        three thousand others is evidence that it was in the upgrade, which is
        equally true of everything. Quoting one as the reason a package broke
        is a 54 kB non-sequitur, and it crowded out the handful of lines that
        did single the package out.

        The list below is every bulk ``logging`` call in the upgrader that
        joins a package set, taken from ``DistUpgradeCache.py`` and
        ``DistUpgradeController.py``. Filtering on size instead was tried and
        does not work: real evidence runs to 53 tokens
        (``Can't mark 'ubuntu-unity-desktop' for upgrade (...)``) while a short
        ``Obsolete:`` list can be 21, so the bands overlap and no threshold
        separates them.
        """
        out: list[int] = []
        for index, event in enumerate(self.run.events):
            if level is not None and event.level is not level:
                continue
            text = self.interner.render(event.template_id, event.args)
            if text.startswith(BULK_LIST_PREFIXES):
                continue
            if needle in text:
                out.append(index)
        return tuple(out)

    # -- resolver evidence --------------------------------------------------

    @property
    def root_reports(self) -> tuple[RootReport, ...]:
        """Root analysis of every conflict graph, computed once.

        The third-party overlay is applied here so that every rule sees the
        same blame orientation. Rules must not call :func:`analyse` themselves;
        doing so without the overlay reports the Ubuntu package that a PPA
        broke as the culprit.
        """
        if not self._analysed:
            self._root_reports = [
                analyse(
                    graph,
                    self.interner,
                    third_party=self.run.third_party,
                    evidence_complete=self.run.evidence_complete,
                )
                for graph in self.run.graphs
            ]
            self._analysed = True
        return tuple(self._root_reports)

    @property
    def primary_report(self) -> RootReport | None:
        """The root report for the graph the failure came from."""
        reports = self.root_reports
        return reports[0] if reports else None

    # -- convenience --------------------------------------------------------

    @property
    def phase(self) -> Phase:
        return self.run.terminal_phase

    @property
    def reached_dpkg(self) -> bool:
        return self.run.reached_dpkg

    def has_log(self, source: LogSource) -> bool:
        return source in self.run.logs_present

    def label(self, pkg_id: PkgId) -> str:
        return self.interner.package_label(pkg_id)

    def labels(self, pkg_ids: Iterable[PkgId]) -> tuple[str, ...]:
        return tuple(self.label(p) for p in pkg_ids)

    def package(self, name: str) -> PkgId:
        return self.interner.package(name)

    # -- finding construction ----------------------------------------------

    def finding(
        self,
        *,
        rule: str,
        cause: Cause,
        summary: str,
        severity: Severity = Severity.MEDIUM,
        confidence: Confidence = Confidence.MODERATE,
        root_pkgs: Sequence[PkgId] = (),
        victim_pkgs: Sequence[PkgId] = (),
        cascade_size: int | None = None,
        evidence: Sequence[int] = (),
        graph_index: int | None = None,
        remedy: Decision = Decision.UNKNOWN,
        score_margin: int | None = None,
        fragile: bool = False,
        detail: dict[str, str] | None = None,
        phase: Phase | None = None,
    ) -> Finding:
        """Build a finding with the shared provenance filled in.

        ``cascade_size`` defaults to the victim count rather than zero, so a
        rule cannot accidentally report a blast radius of nothing and sink to
        the bottom of the ranking.
        """
        return Finding(
            cause=cause,
            severity=severity,
            confidence=confidence,
            rule=rule,
            summary=summary,
            root_pkgs=tuple(root_pkgs),
            victim_pkgs=tuple(victim_pkgs),
            cascade_size=cascade_size if cascade_size is not None else len(victim_pkgs),
            evidence=tuple(evidence),
            graph_index=graph_index,
            remedy=remedy,
            score_margin=score_margin,
            fragile=fragile,
            detail=detail or {},
            phase=phase if phase is not None else self.run.terminal_phase,
        )
