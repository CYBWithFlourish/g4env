"""Tests for the deterministic rules."""

from __future__ import annotations

import pytest

from g4env.bench.tokens import (
    AWS_ACCESS_KEY_ID as FAKE_AWS_ACCESS_KEY_ID,
    GENERIC_PASSWORD as FAKE_GENERIC_PASSWORD,
    GITHUB_TOKEN as FAKE_GITHUB_TOKEN,
    GOOGLE_API_KEY as FAKE_GOOGLE_API_KEY,
    SENDGRID_API_KEY as FAKE_SENDGRID_API_KEY,
    STRIPE_KEY as FAKE_STRIPE_KEY,
)
from g4env.models import Severity
from g4env.providers.rules import RulesProvider
from g4env.rules.builtin import get_rules
from g4env.scanning.loader import FileKind

from .conftest import make_unit

PROVIDER = RulesProvider()


def rule_ids(text: str, **kwargs) -> set[str]:
    """Return the rule identifiers reported for ``text``."""
    unit = make_unit(text, **kwargs)
    return {finding.id for finding in PROVIDER.analyze_unit(unit)}


def test_raw_secret_detects_vendor_formats() -> None:
    assert "env.raw-secret" in rule_ids("STRIPE_API_KEY=" + FAKE_STRIPE_KEY + "\n")
    assert "env.raw-secret" in rule_ids("GITHUB_TOKEN=" + FAKE_GITHUB_TOKEN + "\n")
    assert "env.raw-secret" in rule_ids("AWS_ACCESS_KEY_ID=" + FAKE_AWS_ACCESS_KEY_ID + "\n")
    assert "env.raw-secret" in rule_ids("GOOGLE_API_KEY=" + FAKE_GOOGLE_API_KEY + "\n")
    assert "env.raw-secret" in rule_ids(
        "SENDGRID_API_KEY=" + FAKE_SENDGRID_API_KEY + "\n"
    )


def test_raw_secret_detects_generic_assignment() -> None:
    assert "env.raw-secret" in rule_ids("API_PASSWORD=" + FAKE_GENERIC_PASSWORD + "\n")


def test_raw_secret_ignores_placeholders() -> None:
    assert rule_ids("API_KEY=your-api-key-here\n") == set()
    assert rule_ids("API_KEY=changeme\n") == set()
    assert rule_ids("API_KEY=${OTHER_KEY}\n") == set()
    assert rule_ids("API_KEY=\n") == set()


def test_raw_secret_ignores_public_keys() -> None:
    text = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDdl4xJ2bVn8X9pC8Z3nQ1sT7vV0mK6wR8yL1uI5oP2aS4dF6gH8jK0lM2nO4qR6sT8vW0xY2zA4bC6dE8 user@example\n"
    assert rule_ids(text) == set()


def test_private_key_is_critical() -> None:
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAy8Dbv8prpJ0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    unit = make_unit(text)
    findings = PROVIDER.analyze_unit(unit)
    assert [finding.id for finding in findings] == ["env.private-key"]
    assert findings[0].severity is Severity.CRITICAL


def test_openssh_private_key_detected() -> None:
    text = "DEPLOY_KEY=-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"
    assert "env.private-key" in rule_ids(text)


def test_db_credentials_from_uri() -> None:
    text = "DATABASE_URL=postgres://user:realpassword@db.internal:5432/app\n"
    assert "env.db-credentials" in rule_ids(text)


def test_db_credentials_from_keyword_string() -> None:
    text = 'CONN="Server=db01;Database=app;User Id=appuser;Password=realpassword;"\n'
    assert "env.db-credentials" in rule_ids(text)


def test_db_credentials_ignores_placeholder_password() -> None:
    assert rule_ids("DATABASE_URL=postgres://user:password@localhost:5432/app\n") == set()


def test_insecure_default_only_for_templates() -> None:
    text = "API_KEY=" + FAKE_STRIPE_KEY + "\n"
    assert "env.insecure-default" not in rule_ids(text)
    assert "env.insecure-default" in rule_ids(text, name=".env.example", template=True)


def test_high_entropy_requires_unclassified_name() -> None:
    assert "env.high-entropy" in rule_ids("CONFIG_BLOB=k3J4h5G6f7D8s9A0b1C2d3E4f5G6h7J8\n")
    assert "env.high-entropy" not in rule_ids("BUILD_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
    assert "env.high-entropy" not in rule_ids("API_KEY=k3J4h5G6f7D8s9A0b1C2d3E4f5G6h7J8\n")


def test_weak_password() -> None:
    assert "env.weak-password" in rule_ids("DB_PASSWORD=admin\n")
    assert "env.weak-password" not in rule_ids("DB_PASSWORD=${DB_PASSWORD}\n")


def test_hardcoded_auth_header() -> None:
    text = 'session.headers.update({"Authorization": "Bearer abc123DEF456ghi789JKL012"})\n'
    assert "env.hardcoded-auth-header" in rule_ids(text, name="app.py", kind=FileKind.SOURCE)


def test_secret_in_ci_only_for_pipelines() -> None:
    text = "jobs:\n  build:\n    env:\n      API_TOKEN: literal-token-value\n"
    assert "env.secret-in-ci" in rule_ids(text, name="ci.yml", kind=FileKind.CI)
    assert "env.secret-in-ci" not in rule_ids(text, name="values.yaml", kind=FileKind.CONFIG)


def test_generic_hit_is_suppressed_by_specific_rule() -> None:
    text = "jobs:\n  build:\n    env:\n      API_TOKEN: literal-token-value\n"
    ids = rule_ids(text, name="ci.yml", kind=FileKind.CI)
    assert "env.secret-in-ci" in ids
    assert "env.raw-secret" not in ids


def test_rule_ids_are_unique_and_documented() -> None:
    ids = [rule.id for rule in get_rules()]
    assert len(ids) == len(set(ids))
    assert all(rule.id.startswith("env.") for rule in get_rules())


def test_every_rule_has_metadata() -> None:
    for rule in get_rules():
        assert rule.title
        assert rule.description
        assert rule.impact
        assert rule.remediation
        assert 0 < rule.confidence <= 1


@pytest.mark.parametrize(
    "text",
    [
        "PORT=8000\n",
        "DEBUG=false\n",
        "LOG_LEVEL=info\n",
        "# a comment\n",
        "",
    ],
)
def test_benign_content_is_silent(text: str) -> None:
    assert rule_ids(text) == set()
