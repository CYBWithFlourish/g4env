"""Tests for the audit orchestrator and the report renderers."""

from __future__ import annotations

import json
from pathlib import Path

from g4env.audit import AuditOptions, run_audit
from g4env.bench.tokens import STRIPE_KEY as FAKE_STRIPE_KEY
from g4env.models import SCHEMA_VERSION, Severity
from g4env.providers.rules import RulesProvider
from g4env.report.render import render_json, render_table, render_text
from g4env.schema import load_schema, validate

SECRET_LINE = "STRIPE_API_KEY=" + FAKE_STRIPE_KEY + "\n"


def _audit(target: Path):
    return run_audit(AuditOptions(target=target, provider=RulesProvider())).report


def test_audit_of_a_directory_scans_every_file(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(SECRET_LINE, encoding="utf-8")
    (tmp_path / "config.yaml").write_text(
        "database:\n  url: postgres://user:realpassword@db:5432/app\n", encoding="utf-8"
    )
    report = _audit(tmp_path)
    assert report.metadata.files_scanned == 2
    assert {finding.id for finding in report.findings} == {
        "env.raw-secret",
        "env.db-credentials",
        "env.tracked-env-file",
    }


def test_evidence_paths_are_relative_for_directory_audits(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(SECRET_LINE, encoding="utf-8")
    report = _audit(tmp_path)
    assert report.findings[0].evidence[0].path == ".env"


def test_evidence_paths_are_null_for_single_file_audits(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text(SECRET_LINE, encoding="utf-8")
    report = _audit(path)
    assert report.findings[0].evidence[0].path is None


def test_findings_are_sorted_by_severity(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text(
        "\n".join(
            [
                "DB_PASSWORD=admin",
                "STRIPE_API_KEY=" + FAKE_STRIPE_KEY,
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----END RSA PRIVATE KEY-----",
            ]
        ),
        encoding="utf-8",
    )
    report = _audit(path)
    severities = [finding.severity for finding in report.findings]
    assert severities == sorted(severities, key=lambda item: -item.rank)


def test_risk_score_matches_the_documented_weights(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text(SECRET_LINE, encoding="utf-8")
    report = _audit(path)
    assert report.risk_score == 15


def test_secrets_are_redacted_in_the_report(tmp_path: Path) -> None:
    secret = FAKE_STRIPE_KEY
    path = tmp_path / ".env"
    path.write_text(f"STRIPE_API_KEY={secret}\n", encoding="utf-8")
    report = _audit(path)
    assert secret not in json.dumps(report.to_dict())


def test_redaction_can_be_disabled(tmp_path: Path) -> None:
    secret = FAKE_STRIPE_KEY
    path = tmp_path / ".env"
    path.write_text(f"STRIPE_API_KEY={secret}\n", encoding="utf-8")
    report = run_audit(
        AuditOptions(target=path, provider=RulesProvider(), redact=False)
    ).report
    assert secret in json.dumps(report.to_dict())


def test_report_validates_against_the_schema(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("PORT=8000\n", encoding="utf-8")
    report = _audit(path)
    assert validate(report.to_dict(), load_schema(SCHEMA_VERSION)) == []


def test_metadata_records_the_provider(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("PORT=8000\n", encoding="utf-8")
    report = _audit(path)
    assert report.metadata.provider == "rules"
    assert report.metadata.offline is True
    assert report.metadata.network_scope == "none"
    assert report.metadata.components == ("rules",)


def test_text_output_contains_the_remediation_plan(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text(SECRET_LINE, encoding="utf-8")
    output = render_text(_audit(path))
    assert "Remediation plan" in output
    assert "Next steps" in output
    assert "secret manager" in output


def test_text_output_without_findings(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("PORT=8000\n", encoding="utf-8")
    output = render_text(_audit(path))
    assert "No findings." in output
    assert "Next steps" in output


def test_table_output_lists_every_finding(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text(SECRET_LINE, encoding="utf-8")
    output = render_table(_audit(path))
    assert "SEVERITY" in output
    assert "env.raw-secret" in output
    assert "Remediation plan" in output


def test_json_output_is_machine_readable(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text(SECRET_LINE, encoding="utf-8")
    payload = json.loads(render_json(_audit(path)))
    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["findings"][0]["severity"] == "HIGH"


def test_summary_counts_every_severity(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("DB_PASSWORD=admin\n", encoding="utf-8")
    report = _audit(path)
    assert report.counts()[Severity.MEDIUM] == 1
    assert "1 medium" in report.summary
