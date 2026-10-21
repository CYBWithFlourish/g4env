"""Tests for the command line interface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from g4env.bench.tokens import STRIPE_KEY as FAKE_STRIPE_KEY
from g4env.cli import EXIT_ERROR, EXIT_OK, EXIT_POLICY, EXIT_USAGE, main


def run(argv: list[str], capsys) -> tuple[int, str, str]:
    """Run the CLI and return ``(exit code, stdout, stderr)``."""
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_version_prints_version_and_schema(capsys) -> None:
    code, out, _ = run(["version"], capsys)
    assert code == EXIT_OK
    assert out.strip() == "g4env 1.0.0 (report schema 1.0)"


def test_version_flag(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "g4env 1.0.0" in capsys.readouterr().out


def test_audit_text_output(capsys, sample_env: Path) -> None:
    code, out, _ = run(["audit", str(sample_env)], capsys)
    assert code == EXIT_POLICY
    assert "env.raw-secret" in out
    assert "sk_live_****" in out
    assert "STRIPE_API_KEY=" + FAKE_STRIPE_KEY not in out


def test_audit_json_output_is_valid_json(capsys, sample_env: Path) -> None:
    code, out, _ = run(["audit", str(sample_env), "--format", "json"], capsys)
    assert code == EXIT_POLICY
    payload = json.loads(out)
    assert payload["schema_version"] == "1.0"
    assert payload["metadata"]["provider"] == "rules"
    assert payload["metadata"]["offline"] is True
    assert payload["findings"][0]["id"] == "env.raw-secret"
    assert payload["findings"][0]["evidence"][0]["path"] is None


def test_audit_table_output(capsys, sample_env: Path) -> None:
    code, out, _ = run(["audit", str(sample_env), "--format", "table"], capsys)
    assert code == EXIT_POLICY
    assert "SEVERITY" in out
    assert "env.raw-secret" in out


def test_audit_clean_file_exits_zero(capsys, tmp_path: Path) -> None:
    clean = tmp_path / ".env"
    clean.write_text("PORT=8000\nDEBUG=false\n", encoding="utf-8")
    code, out, _ = run(["audit", str(clean)], capsys)
    assert code == EXIT_OK
    assert "No findings" in out


def test_fail_on_none_never_fails(capsys, sample_env: Path) -> None:
    code, _, _ = run(["audit", str(sample_env), "--fail-on", "none"], capsys)
    assert code == EXIT_OK


def test_fail_on_critical_ignores_high(capsys, sample_env: Path) -> None:
    code, _, _ = run(["audit", str(sample_env), "--fail-on", "critical"], capsys)
    assert code == EXIT_OK


def test_no_redact_shows_raw_secret(capsys, sample_env: Path) -> None:
    code, out, _ = run(["audit", str(sample_env), "--no-redact"], capsys)
    assert code == EXIT_POLICY
    assert FAKE_STRIPE_KEY in out


def test_missing_target_is_operational_error(capsys, tmp_path: Path) -> None:
    code, _, err = run(["audit", str(tmp_path / "nope.env")], capsys)
    assert code == EXIT_ERROR
    assert "does not exist" in err


def test_invalid_format_is_usage_error(capsys, sample_env: Path) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["audit", str(sample_env), "--format", "yaml"])
    assert excinfo.value.code == EXIT_USAGE


def test_invalid_provider_is_usage_error(capsys, sample_env: Path) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["audit", str(sample_env), "--provider", "openai"])
    assert excinfo.value.code == EXIT_USAGE


def test_missing_command_is_usage_error(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == EXIT_USAGE


def test_gemini_provider_requires_api_key(capsys, sample_env: Path, monkeypatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("G4ENV_GEMINI_API_KEY", raising=False)
    code, _, err = run(["audit", str(sample_env), "--provider", "gemini"], capsys)
    assert code == EXIT_USAGE
    assert "GEMINI_API_KEY" in err


def test_rules_listing(capsys) -> None:
    code, out, _ = run(["rules"], capsys)
    assert code == EXIT_OK
    assert "env.raw-secret" in out
    assert "env.private-key" in out


def test_rules_json_listing(capsys) -> None:
    code, out, _ = run(["rules", "--format", "json"], capsys)
    assert code == EXIT_OK
    payload = json.loads(out)
    assert any(rule["id"] == "env.db-credentials" for rule in payload)


def test_schema_command(capsys) -> None:
    code, out, _ = run(["schema"], capsys)
    assert code == EXIT_OK
    assert "report schema 1.0" in out


def test_schema_json_command(capsys) -> None:
    code, out, _ = run(["schema", "--format", "json"], capsys)
    assert code == EXIT_OK
    payload = json.loads(out)
    assert payload["properties"]["schema_version"]["const"] == "1.0"


def test_schema_validation_of_report(capsys, sample_env: Path, tmp_path: Path) -> None:
    _, out, _ = run(["audit", str(sample_env), "--format", "json"], capsys)
    report = tmp_path / "report.json"
    report.write_text(out, encoding="utf-8")
    code, _, _ = run(["schema", "--validate", str(report)], capsys)
    assert code == EXIT_OK


def test_schema_validation_rejects_bad_report(capsys, tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema_version": "9.9"}), encoding="utf-8")
    code, _, err = run(["schema", "--validate", str(bad)], capsys)
    assert code == EXIT_ERROR
    assert "does not match schema" in err


def test_audit_directory_reports_relative_paths(capsys, sample_tree: Path) -> None:
    code, out, _ = run(["audit", str(sample_tree), "--format", "json"], capsys)
    assert code == EXIT_POLICY
    payload = json.loads(out)
    paths = {item["path"] for finding in payload["findings"] for item in finding["evidence"]}
    assert "config/app.yaml" in paths


def test_audit_directory_skips_vendored_dependencies(capsys, sample_tree: Path) -> None:
    _, out, _ = run(["audit", str(sample_tree), "--format", "json"], capsys)
    payload = json.loads(out)
    paths = {item["path"] for finding in payload["findings"] for item in finding["evidence"]}
    assert not any(path and "node_modules" in path for path in paths)


def test_bench_command(capsys) -> None:
    code, out, _ = run(["bench"], capsys)
    assert code == EXIT_OK
    assert "precision" in out
    assert "f1" in out
