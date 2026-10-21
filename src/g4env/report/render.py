"""Rendering of reports in the supported output formats."""

from __future__ import annotations

import json
from collections.abc import Iterable

from g4env.models import SEVERITY_ORDER, Finding, Report, Severity

__all__ = ["render_json", "render_table", "render_text"]

_SEVERITY_MARK = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
}


def _location(finding: Finding) -> str:
    path, line = finding.location
    if path and line:
        return f"{path}:{line}"
    if path:
        return path
    if line:
        return f"line {line}"
    return "-"


def _truncate(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    if width <= 1:
        return text[:width]
    return text[: width - 1] + "\u2026"


def render_json(report: Report) -> str:
    """Render the report as pretty printed JSON."""
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def _header(report: Report) -> list[str]:
    metadata = report.metadata
    scope = "offline" if metadata.offline else metadata.network_scope
    return [
        f"g4env {metadata.tool_version}  |  target: {report.target}",
        f"provider: {metadata.provider} ({scope})  |  model: {metadata.model or '-'}  "
        f"|  schema: {report.schema_version}",
        f"files scanned: {metadata.files_scanned}  |  duration: {metadata.duration_ms} ms",
        f"risk score: {report.risk_score}/100",
        "",
    ]


def _details(report: Report) -> list[str]:
    lines: list[str] = []
    for finding in report.findings:
        lines.append(f"  [{_SEVERITY_MARK[finding.severity]}] {finding.id}  {_location(finding)}")
        lines.append(f"    {finding.title}")
        lines.append(f"    {finding.description}")
        for item in finding.evidence:
            lines.append(f"    evidence  {item.text}")
        lines.append(f"    impact    {finding.impact}")
        lines.append(f"    fix       {finding.remediation}")
        lines.append("")
    return lines


def _remediation_plan(report: Report) -> list[str]:
    """Group the findings per rule and explain how to fix each group."""
    groups: dict[str, list[Finding]] = {}
    for finding in report.findings:
        groups.setdefault(finding.id, []).append(finding)

    lines = ["Remediation plan", ""]
    ordered = sorted(
        groups.items(),
        key=lambda item: (-item[1][0].severity.rank, item[0]),
    )
    for rule_id, findings in ordered:
        locations = ", ".join(_location(finding) for finding in findings[:6])
        if len(findings) > 6:
            locations += f", +{len(findings) - 6} more"
        lines.append(
            f"  [{_SEVERITY_MARK[findings[0].severity]}] {rule_id}"
            f"  ({len(findings)} occurrence{'s' if len(findings) != 1 else ''})"
        )
        lines.append(f"    where    {locations}")
        lines.append(f"    fix      {findings[0].remediation}")
        lines.append("")
    return lines


def _next_steps(report: Report) -> list[str]:
    """Return the ordered next steps for the findings in the report."""
    identifiers = {finding.id for finding in report.findings}
    severities = [finding.severity for finding in report.findings]
    steps: list[str] = []

    if Severity.CRITICAL in severities:
        steps.append(
            "Treat the CRITICAL findings as an incident: rotate the exposed key"
            " material now, before anything else."
        )
    if any(severity is Severity.HIGH for severity in severities):
        steps.append(
            "Rotate every credential that is stored in plaintext; assume it has"
            " already leaked through version control history."
        )
    steps.append(
        "Move the values into a secret manager or your platform's encrypted"
        " environment store and reference them with a variable."
    )
    if "env.tracked-env-file" in identifiers:
        steps.append(
            "Add the .env files to .gitignore, remove them from the index and"
            " purge them from the git history."
        )
    if "env.secret-in-ci" in identifiers:
        steps.append(
            "Reference CI secrets through the pipeline secret store instead of"
            " literal values in the workflow file."
        )
    if "env.insecure-default" in identifiers:
        steps.append(
            "Replace the values in the template files with obvious placeholders"
            " so the next copy cannot leak."
        )
    steps.append(
        "Re-run `g4env audit .` to confirm that the remediation worked."
    )
    return steps


def render_text(report: Report) -> str:
    """Render the report as human readable text."""
    lines = _header(report)
    lines.append(report.summary)
    lines.append("")
    if not report.findings:
        lines.append("No findings.")
        lines.append("")
        lines.append("Next steps")
        lines.append("  1. Nothing to fix here, keep auditing on every change.")
        lines.append("  2. Wire `g4env audit . --fail-on high` into CI to catch regressions.")
        return "\n".join(lines).rstrip() + "\n"
    lines.extend(_details(report))
    lines.extend(_remediation_plan(report))
    lines.append("Next steps")
    for index, step in enumerate(_next_steps(report), start=1):
        lines.append(f"  {index}. {step}")
    return "\n".join(lines).rstrip() + "\n"


def _summary_counts(report: Report) -> str:
    counts = report.counts()
    parts = [f"{counts[level]} {level.lower()}" for level in reversed(SEVERITY_ORDER)]
    return ", ".join(parts)


def render_table(report: Report) -> str:
    """Render the report as an aligned table followed by the details."""
    lines = _header(report)
    lines.append(report.summary)
    lines.append("")

    if not report.findings:
        lines.append("No findings.")
        return "\n".join(lines).rstrip() + "\n"

    headers = ("SEVERITY", "RULE", "CONF", "LOCATION", "TITLE")
    rows = [
        (
            finding.severity.value,
            finding.id,
            f"{finding.confidence:.2f}",
            _location(finding),
            finding.title,
        )
        for finding in report.findings
    ]

    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def format_row(cells: Iterable[str]) -> str:
        return "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(cells)).rstrip()

    lines.append(format_row(headers))
    lines.append("  ".join("\u2500" * width for width in widths))
    for row in rows:
        lines.append(format_row(row))
    lines.append("")
    lines.append(f"severity breakdown: {_summary_counts(report)}")
    lines.append("")
    lines.extend(_details(report))
    lines.extend(_remediation_plan(report))
    lines.append("Next steps")
    for index, step in enumerate(_next_steps(report), start=1):
        lines.append(f"  {index}. {step}")
    return "\n".join(lines).rstrip() + "\n"
