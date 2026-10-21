"""Tests for the shared value classification helpers."""

from __future__ import annotations

import pytest

from g4env.variables import (
    classify_name,
    is_placeholder_value,
    is_reference_value,
    is_secret_name,
)


@pytest.mark.parametrize(
    "value",
    [
        "${MY_KEY}",
        "$MY_KEY",
        "{{ my_key }}",
        "%MY_KEY%",
        "env('MY_KEY')",
        "secrets.NAME",
        "vault://secret/data/app",
        "awssm://app/key",
        "self.api_key",
        "config.token",
        "settings.SECRET_KEY",
    ],
)
def test_reference_values_are_recognised(value: str) -> None:
    assert is_reference_value(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "sk_live_51H8xYz2eZvKYlo2C",
        "postgres://user:password@host/db",
        "just-a-plain-value",
        "",
    ],
)
def test_literal_values_are_not_references(value: str) -> None:
    assert is_reference_value(value) is False


def test_trailing_separator_is_not_part_of_a_reference() -> None:
    assert is_reference_value("self.api_key,") is True
    assert is_reference_value("${MY_KEY},") is True


@pytest.mark.parametrize(
    "value",
    [
        "changeme",
        "your-api-key-here",
        "example",
        "<your-token>",
        "****",
    ],
)
def test_placeholder_values_are_recognised(value: str) -> None:
    assert is_placeholder_value(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "sk_live_51H8xYz2eZvKYlo2C",
        "SuperSecret123",
        "postgres://user:password@host/db",
    ],
)
def test_literal_values_are_not_placeholders(value: str) -> None:
    assert is_placeholder_value(value) is False


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("STRIPE_API_KEY", "secret"),
        ("DB_PASSWORD", "secret"),
        ("AWS_ACCESS_KEY_ID", "secret"),
        ("DATABASE_URL", "credential"),
        ("APP_NAME", "benign"),
        ("PUBLIC_KEY", "benign"),
        ("MONKEY", "benign"),
    ],
)
def test_classify_name(name: str, expected: str) -> None:
    assert classify_name(name) == expected


def test_is_secret_name() -> None:
    assert is_secret_name("CLIENT_SECRET")
    assert not is_secret_name("HOSTNAME")
