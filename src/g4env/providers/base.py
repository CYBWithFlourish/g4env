"""Provider interfaces shared by the deterministic and model based backends."""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from g4env.errors import ProviderError
from g4env.models import Evidence, Finding, Severity
from g4env.scanning.discovery import Candidate
from g4env.scanning.loader import SourceUnit
from g4env.scanning.redaction import redact_text

__all__ = [
    "MAX_CONTENT_CHARS",
    "MAX_MODEL_FINDINGS",
    "ModelInfo",
    "ModelProvider",
    "Provider",
    "extract_json_object",
]

#: Maximum number of characters of a file that is sent to a model.
MAX_CONTENT_CHARS = 12_000

#: Maximum number of findings accepted from a single model response.
MAX_MODEL_FINDINGS = 20

#: Identifiers a model is allowed to use for contextual findings.
ALLOWED_MODEL_IDS = frozenset(
    {
        "ctx.hardcoded-credential",
        "ctx.insecure-default",
        "ctx.secret-leak",
        "ctx.exposure-risk",
        "ctx.misconfiguration",
        "ctx.weak-credential",
        "ctx.over-permission",
        "ctx.model-finding",
    }
)

_ID_RE = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")

SYSTEM_PROMPT = """\
You are a senior application security auditor. You review configuration files,
CI/CD pipeline definitions and source code for hardcoded credentials, insecure
defaults and environment anti-patterns.

Rules you must follow:
1. Only report a problem that is supported by the content you were given.
2. Never invent, guess or complete a credential. Quote only what is present.
3. Prefer no finding over a weak finding. Empty output is a valid answer.
4. Every finding must reference a line of the supplied file.

Respond with a single JSON object and nothing else. Use exactly this shape:
{
  "findings": [
    {
      "id": "ctx.hardcoded-credential",
      "severity": "HIGH",
      "confidence": 0.8,
      "title": "short imperative title",
      "description": "what was found, where and why it matters",
      "line": 12,
      "evidence": "the exact line copied from the file"
    }
  ]
}

Use an id from this list: ctx.hardcoded-credential, ctx.insecure-default,
ctx.secret-leak, ctx.exposure-risk, ctx.misconfiguration, ctx.weak-credential,
ctx.over-permission. Severity must be one of LOW, MEDIUM, HIGH or CRITICAL.
Confidence must be a number between 0 and 1. If there is nothing to report,
return {"findings": []}.
"""


@dataclass(frozen=True)
class ModelInfo:
    """Metadata about a model that is available to a provider."""

    name: str
    size: int | None = None
    modified_at: str | None = None
    details: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON representation used by the CLI."""
        return {
            "name": self.name,
            "size": self.size,
            "modified_at": self.modified_at,
            "details": self.details,
        }


class Provider(ABC):
    """Base class for every analysis backend."""

    name: str = "provider"
    offline: bool = True
    network_scope: str = "none"
    model: str | None = None
    model_capable: bool = False
    attach_paths: bool = False

    def __init__(self) -> None:
        self._warnings: list[str] = []

    @property
    def warnings(self) -> list[str]:
        """Non fatal problems that should be surfaced to the user."""
        return self._warnings

    @property
    def components(self) -> tuple[str, ...]:
        """The backends that make up this provider."""
        return (self.name,)

    @abstractmethod
    def analyze_unit(self, unit: SourceUnit) -> list[Finding]:
        """Analyse a single file and return the findings it produced."""

    def analyze_project(
        self,
        root: Path,
        candidates: Sequence[Candidate],
    ) -> list[Finding]:
        """Analyse the project as a whole. Optional for providers."""
        return []

    def warn(self, message: str) -> None:
        """Record a non fatal problem that should be surfaced to the user."""
        self._warnings.append(message)

    def list_models(self) -> list[ModelInfo]:
        """Return the models this provider can use. Empty for offline providers."""
        return []

    def close(self) -> None:  # noqa: B027 - optional hook, not abstract
        """Release any resources held by the provider.

        Providers that hold no resources do not need to override this.
        """


def extract_json_object(text: str) -> dict[str, Any] | None:
    """Extract the first JSON object found in ``text``.

    Model output is untrusted: it may be wrapped in markdown fences or come
    with prose around it, so a tolerant scan is used.
    """
    if not text:
        return None
    candidate = text.strip()
    candidate = re.sub(r"^```[A-Za-z0-9_-]*\s*", "", candidate)
    candidate = re.sub(r"\s*```$", "", candidate).strip()
    try:
        parsed = json.loads(candidate)
    except (json.JSONDecodeError, ValueError):
        parsed = None
    if isinstance(parsed, dict):
        return parsed

    start = candidate.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(candidate)):
            char = candidate[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(candidate[start : index + 1])
                    except (json.JSONDecodeError, ValueError):
                        break
                    if isinstance(parsed, dict):
                        return parsed
                    break
        start = candidate.find("{", start + 1)
    return None


class ModelProvider(Provider):
    """Shared behaviour for providers backed by a language model.

    Model output is treated as untrusted: it is parsed defensively, every
    field is validated and evidence is checked against the actual file.
    """

    model_capable = True

    def analyze_unit(self, unit: SourceUnit) -> list[Finding]:
        """Send a redacted copy of ``unit`` to the model and parse the result."""
        if not unit.text.strip():
            return []
        content = self.prepare_content(unit)
        prompt = self.build_prompt(unit, content)
        try:
            raw = self.generate(prompt)
        except ProviderError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            raise ProviderError(f"model backend failed: {exc}") from exc
        if not raw or not raw.strip():
            return []
        payload = extract_json_object(raw)
        if payload is None:
            self.warn(f"{unit.rel_path}: model response could not be parsed as JSON")
            return []
        return self.build_findings(payload, unit, content)

    def prepare_content(self, unit: SourceUnit) -> str:
        """Redact and truncate the file content before it leaves the process."""
        redacted = redact_text(unit.text)
        if len(redacted) > MAX_CONTENT_CHARS:
            redacted = redacted[:MAX_CONTENT_CHARS] + "\n... [truncated]"
        return redacted

    def build_prompt(self, unit: SourceUnit, content: str) -> str:
        """Build the user prompt sent to the model."""
        return (
            "Audit the following file.\n\n"
            f"File: {unit.rel_path}\n"
            f"Kind: {unit.kind.value}\n"
            f"Template: {'yes' if unit.is_template else 'no'}\n"
            "---8<---\n"
            f"{content}\n"
            "--->8---\n\n"
            "Return the JSON object described in the instructions."
        )

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Run the model and return its raw text response."""

    def build_findings(
        self,
        payload: dict[str, Any],
        unit: SourceUnit,
        content: str,
    ) -> list[Finding]:
        """Convert a raw model payload into validated findings."""
        raw_findings = payload.get("findings")
        if not isinstance(raw_findings, list):
            return []

        findings: list[Finding] = []
        for item in raw_findings[:MAX_MODEL_FINDINGS]:
            if not isinstance(item, dict):
                continue
            finding = self._build_finding(item, unit, content)
            if finding is not None:
                findings.append(finding)
        return findings

    def _build_finding(
        self,
        item: dict[str, Any],
        unit: SourceUnit,
        content: str,
    ) -> Finding | None:
        title = self._text(item.get("title"), 200)
        description = self._text(item.get("description"), 2000)
        if not title and not description:
            return None

        severity = self._severity(item.get("severity"))
        confidence = self._confidence(item.get("confidence"))
        identifier = self._identifier(item.get("id"))

        evidence_text = self._text(item.get("evidence"), 500)
        line = self._line(item.get("line"))
        line, evidence_text = self._resolve_evidence(unit, content, evidence_text, line)

        impact = self._text(item.get("impact"), 1000) or (
            "Unverified configuration behaviour can expose credentials or weaken "
            "the security posture of the deployment."
        )
        remediation = self._text(item.get("remediation"), 1000) or (
            "Review the configuration, move secrets into a secret manager and "
            "document the intended value."
        )

        evidence: tuple[Evidence, ...] = ()
        if evidence_text:
            evidence = (
                Evidence(
                    line=line,
                    text=evidence_text,
                    path=unit.rel_path if self.attach_paths else None,
                ),
            )

        return Finding(
            id=identifier,
            severity=severity,
            confidence=confidence,
            title=title or "Contextual security observation",
            description=description or title,
            impact=impact,
            remediation=remediation,
            source="model",
            evidence=evidence,
        )

    def _resolve_evidence(
        self,
        unit: SourceUnit,
        content: str,
        evidence_text: str,
        line: int | None,
    ) -> tuple[int | None, str]:
        """Confirm that the claimed evidence exists in the file."""
        stripped = evidence_text.strip()
        if not stripped:
            if line is not None and 1 <= line <= len(unit.lines):
                return line, unit.lines[line - 1].strip()
            return line, ""

        if line is not None and 1 <= line <= len(unit.lines):
            actual = unit.lines[line - 1].strip()
            if actual == stripped or stripped in actual or actual in stripped:
                return line, actual

        for number, candidate_line in enumerate(unit.lines, start=1):
            if candidate_line.strip() == stripped:
                return number, stripped
        if stripped in content:
            return line, stripped

        self.warn(f"{unit.rel_path}: model evidence could not be verified in the file")
        return line, ""

    @staticmethod
    def _text(value: Any, limit: int) -> str:
        if not isinstance(value, str):
            return ""
        collapsed = " ".join(value.split())
        return collapsed[:limit]

    @staticmethod
    def _severity(value: Any) -> Severity:
        try:
            return Severity.coerce(value)
        except (ValueError, TypeError):
            return Severity.MEDIUM

    @staticmethod
    def _confidence(value: Any) -> float:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return 0.5
        if number != number:  # NaN
            return 0.5
        return max(0.0, min(1.0, number))

    @staticmethod
    def _identifier(value: Any) -> str:
        text = str(value).strip().lower() if value is not None else ""
        text = re.sub(r"[^a-z0-9.\-]", "-", text).strip("-")
        if text and text not in ALLOWED_MODEL_IDS:
            text = f"ctx.{text}" if text.startswith("ctx.") else "ctx.model-finding"
        if not text or not _ID_RE.match(text):
            return "ctx.model-finding"
        return text

    @staticmethod
    def _line(value: Any) -> int | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value if value > 0 else None
        if isinstance(value, str) and value.strip().isdigit():
            number = int(value.strip())
            return number if number > 0 else None
        return None
