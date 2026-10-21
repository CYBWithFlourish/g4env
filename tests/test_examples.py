"""Tests for the demo fixtures shipped in ``examples/``.

The fixtures are the quickest way to see the tool work, so they are locked
here: every rule must fire on the set, and the clean file must stay clean.
"""

from __future__ import annotations

from pathlib import Path

from g4env.audit import AuditOptions, run_audit
from g4env.providers.rules import RulesProvider

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"

#: Every rule the deterministic engine ships with.
ALL_RULES = {
    "env.raw-secret",
    "env.private-key",
    "env.db-credentials",
    "env.insecure-default",
    "env.high-entropy",
    "env.weak-password",
    "env.hardcoded-auth-header",
    "env.secret-in-ci",
    "env.tracked-env-file",
}


def _audit(target: Path):
    return run_audit(AuditOptions(target=target, provider=RulesProvider())).report


def test_the_demo_set_triggers_every_rule() -> None:
    report = _audit(EXAMPLES)
    assert {finding.id for finding in report.findings} >= ALL_RULES


def test_the_demo_set_covers_every_fixture_file() -> None:
    report = _audit(EXAMPLES)
    scanned = {finding.evidence[0].path for finding in report.findings}
    assert ".env" in scanned
    assert ".env.example" in scanned
    assert "app.env" in scanned
    assert "opaque.env" in scanned
    assert "config/app.yaml" in scanned
    assert "config/settings.json" in scanned
    assert ".github/workflows/deploy.yml" in scanned
    assert "source/client.py" in scanned
    assert "keys/deploy_key.txt" in scanned


def test_the_clean_fixture_reports_nothing() -> None:
    report = _audit(EXAMPLES / "clean.env")
    assert not report.findings
    assert report.risk_score == 0


def test_the_demo_values_are_not_real_provider_tokens() -> None:
    """The fixtures must not impersonate a provider.

    Provider secret scanners block commits that contain a well formed token,
    so the demo values deliberately carry no vendor prefix.
    """
    from g4env.patterns import VENDOR_SIGNATURES

    for path in sorted(EXAMPLES.rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for signature in VENDOR_SIGNATURES:
            assert not signature.regex.search(text), (
                f"{path.name} looks like a {signature.label}"
            )


def test_the_repository_self_scan_stays_clean() -> None:
    """The examples must not make the repository's own audit fail."""
    root = Path(__file__).resolve().parents[1]
    report = _audit(root)
    assert not report.findings
