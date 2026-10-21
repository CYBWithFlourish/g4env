"""Base types for deterministic rules."""

from __future__ import annotations

from dataclasses import dataclass

from g4env.models import Severity
from g4env.scanning.loader import SourceUnit

__all__ = ["Rule", "RuleHit"]


@dataclass(frozen=True)
class RuleHit:
    """A single match produced by a rule."""

    rule_id: str
    severity: Severity
    confidence: float
    line: int
    text: str
    description: str
    var_name: str | None = None
    generic: bool = False
    """Generic hits are suppressed when a more specific rule covers the line."""

    def sort_key(self) -> tuple[int, int]:
        """Return the ordering key used to sort hits inside a file."""
        return (self.line, -self.severity.rank)


class Rule:
    """Base class for all deterministic rules.

    Subclasses set the descriptive attributes and implement :meth:`scan`.
    """

    id: str = ""
    severity: Severity = Severity.LOW
    title: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    confidence: float = 0.5

    def scan(self, unit: SourceUnit) -> list[RuleHit]:
        """Return every hit of this rule inside ``unit``."""
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<Rule {self.id}>"
