"""Core data structures describing a g4env security report.

Everything in this module is deliberately plain: dataclasses with explicit
``to_dict`` methods so the JSON output is byte-for-byte predictable and can be
validated against the versioned report schema.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = [
    "SCHEMA_VERSION",
    "SEVERITY_ORDER",
    "TOOL_VERSION",
    "Evidence",
    "Finding",
    "Metadata",
    "Report",
    "Severity",
    "Threshold",
    "build_summary",
    "compute_risk_score",
]

TOOL_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"


class Severity(str, Enum):
    """Severity levels ordered from least to most serious."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Numeric ordering used for sorting and threshold comparisons."""
        return _SEVERITY_RANK[self.value]

    @property
    def weight(self) -> int:
        """Contribution of a single finding of this severity to the risk score."""
        return _SEVERITY_WEIGHT[self.value]

    @classmethod
    def coerce(cls, value: object) -> Severity:
        """Return the :class:`Severity` matching ``value`` (case insensitive)."""
        if isinstance(value, Severity):
            return value
        text = str(value).strip().upper()
        for member in cls:
            if member.value == text:
                return member
        raise ValueError(f"unknown severity: {value!r}")

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


_SEVERITY_RANK: dict[str, int] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
_SEVERITY_WEIGHT: dict[str, int] = {"LOW": 3, "MEDIUM": 7, "HIGH": 15, "CRITICAL": 35}

#: Severity levels in ascending order of seriousness.
SEVERITY_ORDER: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass(frozen=True)
class Threshold:
    """The ``--fail-on`` threshold.

    A ``severity`` of ``None`` means the policy never triggers, which is how
    the ``none`` option is represented.
    """

    severity: Severity | None = None

    @classmethod
    def parse(cls, raw: str) -> Threshold:
        """Parse a ``--fail-on`` value into a :class:`Threshold`."""
        text = str(raw).strip().lower()
        if text in {"none", "off", "never"}:
            return cls(None)
        try:
            return cls(Severity.coerce(text))
        except ValueError as exc:
            allowed = ", ".join((*SEVERITY_ORDER, "none"))
            raise ValueError(f"invalid failure threshold {raw!r}; expected one of: {allowed}") from exc

    def triggered(self, severity: Severity) -> bool:
        """Return ``True`` when ``severity`` meets or exceeds this threshold."""
        if self.severity is None:
            return False
        return severity.rank >= self.severity.rank


@dataclass(frozen=True)
class Evidence:
    """A single concrete piece of evidence backing a finding."""

    line: int | None
    text: str
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON representation used in reports."""
        return {"line": self.line, "text": self.text, "path": self.path}


@dataclass(frozen=True)
class Finding:
    """A single security finding."""

    id: str
    severity: Severity
    confidence: float
    title: str
    description: str
    impact: str
    remediation: str
    source: str = "rule"
    evidence: tuple[Evidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON representation used in reports."""
        return {
            "id": self.id,
            "severity": self.severity.value,
            "confidence": round(float(self.confidence), 2),
            "title": self.title,
            "description": self.description,
            "evidence": [item.to_dict() for item in self.evidence],
            "impact": self.impact,
            "remediation": self.remediation,
            "source": self.source,
        }

    @property
    def location(self) -> tuple[str | None, int | None]:
        """Return the ``(path, line)`` of the first evidence item."""
        if not self.evidence:
            return (None, None)
        first = self.evidence[0]
        return (first.path, first.line)


@dataclass(frozen=True)
class Metadata:
    """Provenance information describing how a report was produced."""

    tool_version: str = TOOL_VERSION
    provider: str = "rules"
    offline: bool = True
    model: str | None = None
    files_scanned: int = 0
    duration_ms: int = 0
    network_scope: str = "none"
    components: tuple[str, ...] = ("rules",)

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON representation used in reports."""
        return {
            "tool_version": self.tool_version,
            "provider": self.provider,
            "offline": self.offline,
            "model": self.model,
            "files_scanned": self.files_scanned,
            "duration_ms": self.duration_ms,
            "network_scope": self.network_scope,
            "components": list(self.components),
        }


@dataclass(frozen=True)
class Report:
    """The complete audit report."""

    schema_version: str
    target: str
    risk_score: int
    summary: str
    findings: tuple[Finding, ...]
    metadata: Metadata = field(default_factory=Metadata)

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON representation used in reports."""
        return {
            "schema_version": self.schema_version,
            "target": self.target,
            "risk_score": self.risk_score,
            "summary": self.summary,
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": self.metadata.to_dict(),
        }

    def counts(self) -> dict[str, int]:
        """Return the number of findings per severity level."""
        counts = dict.fromkeys(SEVERITY_ORDER, 0)
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def highest_severity(self) -> Severity | None:
        """Return the most serious severity present in the report."""
        if not self.findings:
            return None
        return max((finding.severity for finding in self.findings), key=lambda item: item.rank)


def compute_risk_score(findings: Iterable[Finding]) -> int:
    """Compute a 0-100 risk score from the weighted severity of all findings."""
    total = sum(finding.severity.weight for finding in findings)
    return max(0, min(100, total))


def build_summary(findings: Sequence[Finding]) -> str:
    """Build the human readable one line summary of a report."""
    total = len(findings)
    if total == 0:
        return "No findings."
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for finding in findings:
        counts[finding.severity.value] += 1
    parts = [f"{counts[level]} {level.lower()}" for level in reversed(SEVERITY_ORDER) if counts[level]]
    return f"{total} finding(s): {', '.join(parts)}."
