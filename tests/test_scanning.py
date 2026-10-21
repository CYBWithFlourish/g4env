"""Tests for safe loading and file discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from g4env.scanning.discovery import classify, discover, is_template_name
from g4env.scanning.ignore import IgnoreRules
from g4env.scanning.loader import (
    BinaryFileError,
    FileKind,
    FileTooLargeError,
    load_source_unit,
    max_file_bytes,
)


def test_loader_reads_text(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("A=1\nB=2\n", encoding="utf-8")
    unit = load_source_unit(
        path, rel_path=".env", kind=FileKind.ENV, is_template=False
    )
    assert unit.lines == ("A=1", "B=2")
    assert unit.line_text(2) == "B=2"
    assert unit.line_text(99) == ""


def test_loader_rejects_binary(tmp_path: Path) -> None:
    path = tmp_path / "blob.bin"
    path.write_bytes(b"\x00\x01\x02binary")
    with pytest.raises(BinaryFileError):
        load_source_unit(path, rel_path="blob.bin", kind=FileKind.OTHER, is_template=False)


def test_loader_rejects_oversized_files(tmp_path: Path) -> None:
    path = tmp_path / "big.env"
    path.write_text("A=1\n" * 1000, encoding="utf-8")
    with pytest.raises(FileTooLargeError):
        load_source_unit(
            path,
            rel_path="big.env",
            kind=FileKind.ENV,
            is_template=False,
            limit=10,
        )


def test_loader_tolerates_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "mixed.env"
    path.write_bytes(b"KEY=value\n" + b"\xff\xfe" + b"\n")
    unit = load_source_unit(
        path, rel_path="mixed.env", kind=FileKind.ENV, is_template=False
    )
    assert "KEY=value" in unit.text


def test_max_file_bytes_honours_environment(monkeypatch) -> None:
    monkeypatch.setenv("G4ENV_MAX_FILE_BYTES", "1234")
    assert max_file_bytes() == 1234
    monkeypatch.setenv("G4ENV_MAX_FILE_BYTES", "not-a-number")
    assert max_file_bytes() > 0


def test_discovery_finds_env_files(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("A=1\n", encoding="utf-8")
    (tmp_path / "config.yaml").write_text("a: 1\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    names = {candidate.rel_path for candidate in discover(tmp_path)}
    assert names == {".env", "config.yaml", "app.py"}


def test_discovery_skips_vendor_directories(tmp_path: Path) -> None:
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "index.js").write_text("x\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("x\n", encoding="utf-8")
    assert discover(tmp_path) == []


def test_discovery_skips_binary_suffixes(tmp_path: Path) -> None:
    (tmp_path / "logo.png").write_bytes(b"\x89PNG")
    assert discover(tmp_path) == []


def test_discovery_respects_gitignore(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("secrets/\n*.local.env\n", encoding="utf-8")
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "prod.env").write_text("A=1\n", encoding="utf-8")
    (tmp_path / "app.local.env").write_text("A=1\n", encoding="utf-8")
    (tmp_path / "keep.env").write_text("A=1\n", encoding="utf-8")
    names = {candidate.rel_path for candidate in discover(tmp_path)}
    assert names == {".gitignore", "keep.env"}


def test_discovery_of_single_file(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("A=1\n", encoding="utf-8")
    candidates = discover(path)
    assert len(candidates) == 1
    assert candidates[0].path == path


def test_classify_kinds() -> None:
    assert classify(Path(".env"), ".env")[0] is FileKind.ENV
    assert classify(Path(".env.example"), ".env.example")[0] is FileKind.ENV
    assert classify(Path("config.yaml"), "config.yaml")[0] is FileKind.CONFIG
    assert classify(Path("app.py"), "app.py")[0] is FileKind.SOURCE
    assert classify(Path("ci.yml"), ".github/workflows/ci.yml")[0] is FileKind.CI
    assert classify(Path("Jenkinsfile"), "Jenkinsfile")[0] is FileKind.CI


def test_template_detection() -> None:
    assert is_template_name(".env.example")
    assert is_template_name(".env.sample")
    assert is_template_name("docker-compose.template.yml")
    assert not is_template_name(".env")
    assert not is_template_name("config.yaml")


def test_ignore_rules_negation() -> None:
    rules = IgnoreRules()
    rules.extend("*.env\n!important.env\n")
    assert rules.is_ignored("secrets.env")
    assert not rules.is_ignored("important.env")


def test_ignore_rules_empty_is_noop() -> None:
    rules = IgnoreRules()
    assert not rules.is_ignored("anything.env")
