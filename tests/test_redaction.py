"""Tests for the redaction layer."""

from __future__ import annotations

import pytest

from g4env.bench.tokens import (
    AWS_ACCESS_KEY_ID as FAKE_AWS_ACCESS_KEY_ID,
    GITHUB_TOKEN as FAKE_GITHUB_TOKEN,
    GOOGLE_API_KEY as FAKE_GOOGLE_API_KEY,
    STRIPE_KEY as FAKE_STRIPE_KEY,
)
from g4env.scanning.redaction import MASK, redact_text, redact_value


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (FAKE_STRIPE_KEY, "sk_live_" + MASK),
        (FAKE_GITHUB_TOKEN, "ghp_" + MASK),
        (FAKE_AWS_ACCESS_KEY_ID, "AKIA" + MASK),
        (FAKE_GOOGLE_API_KEY, "AIza" + MASK),
        ("supersecretvalue", MASK),
    ],
)
def test_redact_value_keeps_vendor_prefix(value: str, expected: str) -> None:
    assert redact_value(value) == expected


def test_redact_value_keeps_references() -> None:
    assert redact_value("${MY_KEY}") == "${MY_KEY}"
    assert redact_value("$MY_KEY") == "$MY_KEY"


def test_redact_text_masks_assignment_values() -> None:
    assert redact_text("STRIPE_API_KEY=" + FAKE_STRIPE_KEY) == (
        "STRIPE_API_KEY=sk_live_" + MASK
    )


def test_redact_text_masks_url_credentials() -> None:
    redacted = redact_text("DATABASE_URL=postgres://user:realpassword@db:5432/app")
    assert "realpassword" not in redacted
    assert "postgres://user:" + MASK + "@db:5432/app" in redacted


def test_redact_text_masks_opaque_blobs() -> None:
    blob = "MIIEowIBAAKCAQEAy8Dbv8prpJ0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy"
    assert blob not in redact_text(blob)


def test_redact_text_keeps_benign_content() -> None:
    text = "PORT=8000\nLOG_LEVEL=info\nAPP_NAME=my-service\n"
    assert redact_text(text) == text


def test_redact_text_handles_authorization_header() -> None:
    redacted = redact_text('headers = {"Authorization": "Bearer abc123DEF456ghi789JKL"}')
    assert "abc123DEF456ghi789JKL" not in redacted


def test_redact_text_is_idempotent() -> None:
    once = redact_text("STRIPE_API_KEY=" + FAKE_STRIPE_KEY)
    assert redact_text(once) == once
