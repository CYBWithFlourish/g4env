"""Tests for the report schema and the in-tree validator."""

from __future__ import annotations

import json

import pytest

from g4env.audit import AuditOptions, run_audit
from g4env.bench.tokens import STRIPE_KEY as FAKE_STRIPE_KEY
from g4env.models import SCHEMA_VERSION
from g4env.providers.rules import RulesProvider
from g4env.schema import load_schema, validate
from g4env.schema.validator import SchemaValidationError, _resolve_ref


def test_schema_is_valid_json() -> None:
    schema = load_schema(SCHEMA_VERSION)
    assert schema["properties"]["schema_version"]["const"] == "1.0"


def test_validator_accepts_valid_report(tmp_path) -> None:
    path = tmp_path / ".env"
    path.write_text("STRIPE_API_KEY=" + FAKE_STRIPE_KEY + "\n", encoding="utf-8")
    result = run_audit(AuditOptions(target=path, provider=RulesProvider()))
    errors = validate(result.report.to_dict(), load_schema(SCHEMA_VERSION))
    assert errors == []


def test_validator_rejects_missing_property() -> None:
    errors = validate({"schema_version": "1.0"}, load_schema(SCHEMA_VERSION))
    assert any("missing required property" in error for error in errors)


def test_validator_rejects_wrong_type() -> None:
    payload = {
        "schema_version": "1.0",
        "target": ".env",
        "risk_score": "high",
        "summary": "x",
        "findings": [],
        "metadata": {"tool_version": "1.0.0", "provider": "rules", "offline": True},
    }
    errors = validate(payload, load_schema(SCHEMA_VERSION))
    assert any("expected type integer" in error for error in errors)


def test_validator_rejects_additional_properties() -> None:
    payload = {
        "schema_version": "1.0",
        "target": ".env",
        "risk_score": 0,
        "summary": "x",
        "findings": [],
        "metadata": {"tool_version": "1.0.0", "provider": "rules", "offline": True},
        "unexpected": True,
    }
    errors = validate(payload, load_schema(SCHEMA_VERSION))
    assert any("unexpected property" in error for error in errors)


def test_validator_rejects_bad_enum() -> None:
    payload = {
        "schema_version": "1.0",
        "target": ".env",
        "risk_score": 0,
        "summary": "x",
        "findings": [],
        "metadata": {"tool_version": "1.0.0", "provider": "nope", "offline": True},
    }
    errors = validate(payload, load_schema(SCHEMA_VERSION))
    assert any("is not one of" in error for error in errors)


def test_validator_rejects_bad_id_pattern() -> None:
    payload = {
        "schema_version": "1.0",
        "target": ".env",
        "risk_score": 0,
        "summary": "x",
        "findings": [
            {
                "id": "Not A Valid Id",
                "severity": "HIGH",
                "confidence": 0.5,
                "title": "t",
                "description": "d",
                "evidence": [],
                "impact": "i",
                "remediation": "r",
                "source": "rule",
            }
        ],
        "metadata": {"tool_version": "1.0.0", "provider": "rules", "offline": True},
    }
    errors = validate(payload, load_schema(SCHEMA_VERSION))
    assert any("does not match pattern" in error for error in errors)


def test_validator_handles_nullable_line() -> None:
    payload = {
        "schema_version": "1.0",
        "target": ".env",
        "risk_score": 0,
        "summary": "x",
        "findings": [
            {
                "id": "env.raw-secret",
                "severity": "HIGH",
                "confidence": 0.5,
                "title": "t",
                "description": "d",
                "evidence": [{"line": None, "text": "x", "path": None}],
                "impact": "i",
                "remediation": "r",
                "source": "rule",
            }
        ],
        "metadata": {"tool_version": "1.0.0", "provider": "rules", "offline": True},
    }
    assert validate(payload, load_schema(SCHEMA_VERSION)) == []


def test_resolve_ref_rejects_external_references() -> None:
    with pytest.raises(SchemaValidationError):
        _resolve_ref("https://example.com/schema.json", {})


def test_report_json_is_stable(tmp_path) -> None:
    path = tmp_path / ".env"
    path.write_text("PORT=8000\n", encoding="utf-8")
    result = run_audit(AuditOptions(target=path, provider=RulesProvider()))
    payload = json.loads(json.dumps(result.report.to_dict()))
    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["findings"] == []
    assert payload["summary"] == "No findings."
