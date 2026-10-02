# SPDX-License-Identifier: GPL-2.0-or-later
"""The rule registry.

A rule maps evidence to a :class:`~uru_doctor.models.Cause`. Rules are plain
functions registered by decorator, which keeps three properties that matter for
a triage tool:

**Rules are data, not control flow.** Every rule carries its own priority,
pattern and provenance, so ``uru-doctor rules`` can print the whole policy and
a reviewer can check it against the upgrader source without reading any code.

**Order is explicit.** Priority is a number on the rule, not the position of an
``elif``. Two rules can fire on one run -- a disk-space failure during ``COMMIT``
also leaves broken packages behind -- and the ranking has to be inspectable.

**Patterns come from upstream strings.** Every pattern here was taken from a
``logging.error`` or ``_()`` call in
``/usr/lib/python3/dist-packages/DistUpgrade/``, not from a sample log. A
pattern invented to fit three bugs is a pattern that breaks on the fourth.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

from uru_doctor.models import Cause, Confidence, Severity

if TYPE_CHECKING:
    from uru_doctor.models import Finding, UpgradeRun
    from uru_doctor.rules.context import RuleContext

__all__ = [
    "RULES",
    "Rule",
    "RuleFn",
    "all_rules",
    "rule",
    "rules_digest",
    "rules_for",
]

#: A rule returns zero or more findings. Returning none is the normal case:
#: most rules do not apply to most runs.
RuleFn = Callable[["RuleContext"], "Sequence[Finding]"]


@dataclass(frozen=True, slots=True)
class Rule:
    """One named diagnostic rule."""

    name: str
    """Stable identifier, used in :attr:`Finding.rule` and by ``--explain``."""

    cause: Cause
    """The cause this rule attributes. Documentation, not enforcement: a rule
    may return findings with a related cause when the evidence narrows it."""

    priority: int
    """Lower fires first. Ties broken by name, so ordering is deterministic."""

    fn: RuleFn
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MODERATE
    phase_hint: str = ""
    """Where in the upgrade this failure occurs, for the report."""

    provenance: str = ""
    """Where the pattern came from, e.g. the upstream function that logs it."""

    remedy: str = ""
    """What the reporter should do, if the rule can say."""

    requires_complete_evidence: bool = True
    """Whether the rule may fire on a truncated log.

    Most may not. A log that stops mid-run cannot support a claim about why the
    run ended, and inventing one is the worst thing this tool could do. Rules
    that only describe observed state -- "these packages are broken" -- are
    exempt, because they assert nothing about the ending.
    """

    def __call__(self, context: RuleContext) -> Sequence[Finding]:
        return self.fn(context)


#: Every registered rule, keyed by name.
RULES: Final[dict[str, Rule]] = {}


def rule(
    name: str,
    cause: Cause,
    *,
    priority: int,
    severity: Severity = Severity.MEDIUM,
    confidence: Confidence = Confidence.MODERATE,
    phase_hint: str = "",
    provenance: str = "",
    remedy: str = "",
    requires_complete_evidence: bool = True,
) -> Callable[[RuleFn], RuleFn]:
    """Register a rule.

    The decorated function is returned unchanged so it stays directly
    testable without going through the registry.
    """

    def decorate(fn: RuleFn) -> RuleFn:
        if name in RULES:
            msg = f"duplicate rule name {name!r}"
            raise ValueError(msg)
        RULES[name] = Rule(
            name=name,
            cause=cause,
            priority=priority,
            fn=fn,
            severity=severity,
            confidence=confidence,
            phase_hint=phase_hint,
            provenance=provenance,
            remedy=remedy,
            requires_complete_evidence=requires_complete_evidence,
        )
        return fn

    return decorate


def all_rules() -> tuple[Rule, ...]:
    """Every rule, in firing order."""
    return tuple(sorted(RULES.values(), key=lambda r: (r.priority, r.name)))


def rules_for(run: UpgradeRun) -> Iterator[Rule]:
    """Rules eligible for ``run``, in firing order.

    Truncated evidence filters the registry rather than being re-checked inside
    every rule, so a new rule is safe by default.
    """
    for candidate in all_rules():
        if candidate.requires_complete_evidence and not run.evidence_complete:
            continue
        yield candidate


def rules_digest() -> str:
    """A short digest over the registered rules and their ranking inputs.

    Recorded on every diagnosed run so that a verdict can be attributed to a
    policy rather than only to a release. A release number is too coarse: the
    changes that move a verdict are overwhelmingly rule changes between
    releases, and the question "did the tool change or did the logs?" is
    unanswerable without this.

    What goes in is exactly what can change a ranking without changing a log:
    the rule's name, the cause it attributes, its priority, severity,
    confidence, and whether it may fire on truncated evidence. Deliberately
    excluded are ``provenance``, ``remedy`` and ``phase_hint``, which are
    documentation -- rewording a remedy must not look like a policy change, or
    the digest becomes noise and gets ignored.

    Not a hash of the source. That would change on a comment, and the point is
    to be quiet when nothing a verdict depends on has moved.
    """
    material = "\n".join(
        "\t".join(
            (
                item.name,
                item.cause.value,
                str(item.priority),
                item.severity.name,
                item.confidence.name,
                "1" if item.requires_complete_evidence else "0",
            )
        )
        # all_rules() is already sorted by (priority, name), so this is stable
        # across interpreter runs and import orders.
        for item in all_rules()
    )
    return hashlib.blake2b(material.encode("utf-8"), digest_size=8).hexdigest()


# ---------------------------------------------------------------------------
# Shared matching helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ErrorPattern:
    """A compiled upgrader error string with its origin recorded."""

    pattern: re.Pattern[str]
    source: str
    """The upstream call this was taken from."""

    captures: tuple[str, ...] = ()
    """Named groups worth putting in :attr:`Finding.detail`."""


def upstream(text: str, source: str, *captures: str) -> ErrorPattern:
    """Compile an upstream message into a pattern.

    ``%s`` placeholders become captures. Written this way so the literal left
    in the source stays recognisably the upstream string, which is what makes
    the table auditable against the upgrader.

    A placeholder in the *final* position is greedy; earlier ones are not. The
    distinction is load-bearing: with everything non-greedy,
    ``Not enough free space: %s`` captured the empty string, because ``.*?`` is
    happiest matching nothing and no following literal forces it onward. The
    rule still fired, and reported "not enough free disk space:" with the
    requirement missing -- a summary that tells a triager nothing they did not
    already know.
    """
    parts = text.split("%s")
    escaped = [re.escape(part) for part in parts]
    slots = len(parts) - 1
    names: list[str | None] = [*captures, *[None] * max(0, slots - len(captures))]

    joined = escaped[0]
    for index in range(slots):
        # Greedy only for a trailing placeholder, where nothing follows to
        # bound the match.
        body = ".*" if index == slots - 1 and not parts[-1] else ".*?"
        name = names[index]
        joined += (f"(?P<{name}>{body})" if name else f"({body})") + escaped[index + 1]
    return ErrorPattern(re.compile(joined, re.DOTALL), source, captures)


@dataclass(slots=True)
class MatchSet:
    """Patterns tried in order, remembering which one matched."""

    patterns: list[ErrorPattern] = field(default_factory=list)

    def first(self, messages: Sequence[str]) -> tuple[ErrorPattern, re.Match[str]] | None:
        for pattern in self.patterns:
            for message in messages:
                if match := pattern.pattern.search(message):
                    return (pattern, match)
        return None
