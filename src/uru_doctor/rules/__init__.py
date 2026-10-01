"""Diagnostic rules.

Importing this package registers every rule, which is what
:func:`uru_doctor.diagnose.diagnose` relies on. The submodules are imported for
their side effects and re-exported so callers can reach the registry without
knowing which file a rule lives in.
"""

from __future__ import annotations

from uru_doctor.rules import resolver, upgrader
from uru_doctor.rules.context import RuleContext
from uru_doctor.rules.registry import (
    RULES,
    ErrorPattern,
    Rule,
    RuleFn,
    all_rules,
    rule,
    rules_for,
    upstream,
)

__all__ = [
    "RULES",
    "ErrorPattern",
    "Rule",
    "RuleContext",
    "RuleFn",
    "all_rules",
    "resolver",
    "rule",
    "rules_for",
    "upgrader",
    "upstream",
]
