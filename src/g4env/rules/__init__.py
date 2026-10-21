"""Deterministic, offline rules."""

from __future__ import annotations

from g4env.rules.assignments import Assignment, iter_assignments, parse_assignment
from g4env.rules.base import Rule, RuleHit
from g4env.rules.builtin import BUILTIN_RULES, get_rules
from g4env.rules.project import check_tracked_env_files

__all__ = [
    "BUILTIN_RULES",
    "Assignment",
    "Rule",
    "RuleHit",
    "check_tracked_env_files",
    "get_rules",
    "iter_assignments",
    "parse_assignment",
]
