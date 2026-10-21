"""The audit orchestrator.

This module ties discovery, loading, the analysis provider and the report
schema together. It is intentionally free of presentation logic so that it
can be reused by the CLI, the benchmark harness and the test-suite.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from g4env.errors import InputError, SchemaError
from g4env.models import (
    SCHEMA_VERSION,
    Evidence,
    Finding,
    Metadata,
    Report,
    Threshold,
    build_summary,
    compute_risk_score,
)
from g4env.providers.base import Provider
from g4env.scanning.discovery import Candidate, discover
from g4env.scanning.loader import (
    BinaryFileError,
    FileTooLargeError,
    load_source_unit,
)
from g4env.scanning.redaction import redact_text
from g4env.schema import load_schema, validate

__all__ = ["AuditOptions", "AuditResult", "run_audit"]


@dataclass
class AuditOptions:
    """Everything the orchestrator needs to run an audit."""

    target: Path
    provider: Provider
    fail_on: Threshold = field(default_factory=Threshold)
    redact: bool = True
    max_files: int = 5000
    max_depth: int = 20


@dataclass
class AuditResult:
    """The outcome of an audit."""

    report: Report
    warnings: list[str]


def _sort_key(finding: Finding) -> tuple[int, str, int, str]:
    path, line = finding.location
    return (-finding.severity.rank, path or "", line or 0, finding.id)


def _dedupe(findings: Sequence[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, int | None, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        path, line = finding.location
        key = (finding.id, path, line, finding.title)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _redact(finding: Finding) -> Finding:
    evidence = tuple(
        Evidence(line=item.line, text=redact_text(item.text), path=item.path)
        for item in finding.evidence
    )
    return replace(
        finding,
        description=redact_text(finding.description),
        evidence=evidence,
    )


def run_audit(options: AuditOptions) -> AuditResult:
    """Run an audit and return the validated report."""
    started = time.monotonic()
    target = options.target
    if not target.exists():
        raise InputError(f"audit target does not exist: {target}")

    provider = options.provider
    provider.attach_paths = target.is_dir()
    warnings: list[str] = []

    candidates: list[Candidate] = discover(
        target,
        max_files=options.max_files,
        max_depth=options.max_depth,
    )

    findings: list[Finding] = []
    scanned = 0
    for candidate in candidates:
        try:
            unit = load_source_unit(
                candidate.path,
                rel_path=candidate.rel_path,
                kind=candidate.kind,
                is_template=candidate.is_template,
            )
        except FileTooLargeError as exc:
            warnings.append(str(exc))
            continue
        except BinaryFileError as exc:
            warnings.append(str(exc))
            continue
        except InputError as exc:
            warnings.append(str(exc))
            continue
        scanned += 1
        findings.extend(provider.analyze_unit(unit))

    findings.extend(provider.analyze_project(target, candidates))
    warnings.extend(provider.warnings)

    findings = _dedupe(findings)
    if options.redact:
        findings = [_redact(finding) for finding in findings]
    findings.sort(key=_sort_key)

    duration_ms = int((time.monotonic() - started) * 1000)
    report = Report(
        schema_version=SCHEMA_VERSION,
        target=str(target),
        risk_score=compute_risk_score(findings),
        summary=build_summary(findings),
        findings=tuple(findings),
        metadata=Metadata(
            provider=provider.name,
            offline=provider.offline,
            model=provider.model,
            files_scanned=scanned,
            duration_ms=duration_ms,
            network_scope=provider.network_scope,
            components=provider.components,
        ),
    )

    errors = validate(report.to_dict(), load_schema(SCHEMA_VERSION))
    if errors:
        raise SchemaError(
            "the generated report does not match schema "
            f"{SCHEMA_VERSION}: {'; '.join(errors[:5])}"
        )

    return AuditResult(report=report, warnings=warnings)
