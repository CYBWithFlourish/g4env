"""Tests for the provider backends."""

from __future__ import annotations

import json
from typing import Any

import pytest

from g4env.bench.tokens import STRIPE_KEY as FAKE_STRIPE_KEY
from g4env.errors import ProviderError
from g4env.models import Severity
from g4env.providers.base import extract_json_object
from g4env.providers.composite import CompositeProvider
from g4env.providers.gemini import (
    GeminiProvider,
    GeminiRestTransport,
    resolve_api_key,
)
from g4env.providers.ollama import OllamaProvider, OllamaTransport
from g4env.providers.rules import RulesProvider

from .conftest import make_unit

SECRET = FAKE_STRIPE_KEY


def _ollama_handler(payload: str) -> Any:
    def handler(path: str, request: dict[str, Any]) -> dict[str, Any]:
        if path.endswith("/api/tags"):
            return {
                "models": [
                    {
                        "name": "gemma2:2b",
                        "size": 1600000000,
                        "modified_at": "2026-01-01T10:00:00Z",
                        "details": {"family": "gemma2"},
                    }
                ]
            }
        if path.endswith("/api/generate"):
            return {"response": payload, "done": True}
        return {}

    return handler


def _gemini_handler(payload: str) -> Any:
    def handler(path: str, request: dict[str, Any]) -> dict[str, Any]:
        if path.endswith("/models") and request == {}:
            return {"models": [{"name": "models/gemini-2.5-flash", "displayName": "Flash"}]}
        return {
            "candidates": [
                {"content": {"parts": [{"text": payload}], "role": "model"}}
            ]
        }

    return handler


# --------------------------------------------------------------------------- #
# JSON extraction
# --------------------------------------------------------------------------- #


def test_extract_json_object_from_plain_json() -> None:
    assert extract_json_object('{"findings": []}') == {"findings": []}


def test_extract_json_object_from_code_fence() -> None:
    assert extract_json_object('```json\n{"findings": []}\n```') == {"findings": []}


def test_extract_json_object_with_surrounding_prose() -> None:
    raw = 'Sure! Here is the result:\n{"findings": [{"id": "ctx.secret-leak"}]}\nHope that helps.'
    payload = extract_json_object(raw)
    assert payload is not None
    assert payload["findings"][0]["id"] == "ctx.secret-leak"


def test_extract_json_object_returns_none_for_garbage() -> None:
    assert extract_json_object("no json at all") is None
    assert extract_json_object("") is None


# --------------------------------------------------------------------------- #
# Ollama
# --------------------------------------------------------------------------- #


def test_ollama_provider_parses_findings(mock_server) -> None:
    payload = json.dumps(
        {
            "findings": [
                {
                    "id": "ctx.secret-leak",
                    "severity": "CRITICAL",
                    "confidence": 0.9,
                    "title": "Shared credential",
                    "description": "The staging environment reuses the production password.",
                    "line": 2,
                    "evidence": "password: reused-from-production",
                }
            ]
        }
    )
    server = mock_server(_ollama_handler(payload))
    provider = OllamaProvider(host=server.url, model="gemma2:2b")
    unit = make_unit("APP_NAME=demo\npassword: reused-from-production\n")
    findings = provider.analyze_unit(unit)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "ctx.secret-leak"
    assert finding.severity is Severity.CRITICAL
    assert finding.source == "model"
    assert finding.evidence[0].line == 2


def test_ollama_provider_redacts_before_prompting(mock_server) -> None:
    server = mock_server(_ollama_handler('{"findings": []}'))
    provider = OllamaProvider(host=server.url, model="gemma2:2b")
    unit = make_unit(f"STRIPE_API_KEY={SECRET}\n")
    provider.analyze_unit(unit)
    _, request = server.requests[0]
    assert SECRET not in request["prompt"]
    assert "sk_live_" in request["prompt"]


def test_ollama_provider_sends_the_system_prompt(mock_server) -> None:
    server = mock_server(_ollama_handler('{"findings": []}'))
    provider = OllamaProvider(host=server.url, model="gemma2:2b")
    provider.analyze_unit(make_unit("A=1\n"))
    _, request = server.requests[0]
    assert "security auditor" in request["prompt"]
    assert request["model"] == "gemma2:2b"
    assert request["format"] == "json"


def test_ollama_provider_handles_unparsable_output(mock_server) -> None:
    server = mock_server(_ollama_handler("I am not sure about this file."))
    provider = OllamaProvider(host=server.url, model="gemma2:2b")
    findings = provider.analyze_unit(make_unit("A=1\n"))
    assert findings == []
    assert provider.warnings


def test_ollama_provider_drops_hallucinated_evidence(mock_server) -> None:
    payload = json.dumps(
        {
            "findings": [
                {
                    "id": "ctx.secret-leak",
                    "severity": "HIGH",
                    "title": "Invented",
                    "description": "Made up",
                    "evidence": "THIS_LINE_DOES_NOT_EXIST=1",
                }
            ]
        }
    )
    server = mock_server(_ollama_handler(payload))
    provider = OllamaProvider(host=server.url, model="gemma2:2b")
    findings = provider.analyze_unit(make_unit("APP_NAME=demo\n"))
    assert len(findings) == 1
    assert findings[0].evidence == ()
    assert provider.warnings


def test_ollama_provider_rejects_out_of_range_confidence(mock_server) -> None:
    payload = json.dumps(
        {
            "findings": [
                {
                    "id": "ctx.secret-leak",
                    "severity": "HIGH",
                    "confidence": 42,
                    "title": "T",
                    "description": "D",
                }
            ]
        }
    )
    server = mock_server(_ollama_handler(payload))
    provider = OllamaProvider(host=server.url, model="gemma2:2b")
    findings = provider.analyze_unit(make_unit("APP_NAME=demo\n"))
    assert findings[0].confidence == 1.0


def test_ollama_provider_normalises_unknown_identifiers(mock_server) -> None:
    payload = json.dumps(
        {
            "findings": [
                {
                    "id": "totally made up!",
                    "severity": "HIGH",
                    "title": "T",
                    "description": "D",
                }
            ]
        }
    )
    server = mock_server(_ollama_handler(payload))
    provider = OllamaProvider(host=server.url, model="gemma2:2b")
    findings = provider.analyze_unit(make_unit("APP_NAME=demo\n"))
    assert findings[0].id == "ctx.model-finding"


def test_ollama_lists_models(mock_server) -> None:
    server = mock_server(_ollama_handler('{"findings": []}'))
    transport = OllamaTransport(host=server.url)
    models = transport.list_models()
    assert models[0].name == "gemma2:2b"
    assert models[0].size == 1600000000


def test_ollama_transport_reports_unreachable_server() -> None:
    transport = OllamaTransport(host="http://127.0.0.1:1", timeout=1.0)
    with pytest.raises(ProviderError) as excinfo:
        transport.list_models()
    assert "cannot reach" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# Gemini
# --------------------------------------------------------------------------- #


def test_gemini_provider_parses_findings(mock_server) -> None:
    payload = json.dumps(
        {
            "findings": [
                {
                    "id": "ctx.insecure-default",
                    "severity": "MEDIUM",
                    "confidence": 0.6,
                    "title": "Debug in production",
                    "description": "Debug output is enabled in a production profile.",
                    "line": 1,
                    "evidence": "DEBUG_MODE=enabled",
                }
            ]
        }
    )
    server = mock_server(_gemini_handler(payload))
    transport = GeminiRestTransport(api_key="test-key", base_url=f"{server.url}/v1beta")
    provider = GeminiProvider(api_key="test-key", transport=transport)
    findings = provider.analyze_unit(make_unit("DEBUG_MODE=enabled\n"))
    assert len(findings) == 1
    assert findings[0].id == "ctx.insecure-default"
    assert findings[0].severity is Severity.MEDIUM


def test_gemini_provider_redacts_before_sending(mock_server) -> None:
    server = mock_server(_gemini_handler('{"findings": []}'))
    transport = GeminiRestTransport(api_key="test-key", base_url=f"{server.url}/v1beta")
    provider = GeminiProvider(api_key="test-key", transport=transport)
    provider.analyze_unit(make_unit(f"STRIPE_API_KEY={SECRET}\n"))
    _, request = server.requests[0]
    body = json.dumps(request)
    assert SECRET not in body


def test_gemini_provider_sends_the_api_key_in_a_header(mock_server) -> None:
    server = mock_server(_gemini_handler('{"findings": []}'))
    transport = GeminiRestTransport(api_key="test-key", base_url=f"{server.url}/v1beta")
    provider = GeminiProvider(api_key="test-key", transport=transport)
    provider.analyze_unit(make_unit("A=1\n"))
    assert server.headers[0].get("x-goog-api-key") == "test-key"


def test_gemini_provider_reports_blocked_requests(mock_server) -> None:
    def handler(path: str, request: dict[str, Any]) -> dict[str, Any]:
        return {"promptFeedback": {"blockReason": "SAFETY"}}

    server = mock_server(handler)
    transport = GeminiRestTransport(api_key="test-key", base_url=f"{server.url}/v1beta")
    provider = GeminiProvider(api_key="test-key", transport=transport)
    with pytest.raises(ProviderError) as excinfo:
        provider.analyze_unit(make_unit("A=1\n"))
    assert "blocked" in str(excinfo.value)


def test_gemini_lists_models(mock_server) -> None:
    server = mock_server(_gemini_handler('{"findings": []}'))
    transport = GeminiRestTransport(api_key="test-key", base_url=f"{server.url}/v1beta")
    models = transport.list_models()
    assert models[0].name == "gemini-2.5-flash"


def test_resolve_api_key_prefers_gemini_variable(monkeypatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "primary")
    monkeypatch.setenv("GOOGLE_API_KEY", "secondary")
    assert resolve_api_key() == "primary"


def test_resolve_api_key_falls_back_to_google_variable(monkeypatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_API_KEY", "secondary")
    assert resolve_api_key() == "secondary"


def test_resolve_api_key_returns_none(monkeypatch) -> None:
    for name in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "G4ENV_GEMINI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    assert resolve_api_key() is None


# --------------------------------------------------------------------------- #
# Composite
# --------------------------------------------------------------------------- #


class _StubModelProvider(CompositeProvider):
    """A composite provider whose model backend always reports one finding."""

    def __init__(self) -> None:
        super().__init__(RulesProvider())
        self.name = "stub"
        self.model = "stub-model"
        self.model_capable = True
        self.offline = False
        self.network_scope = "remote"


def test_composite_provider_merges_rule_and_model_findings() -> None:
    from g4env.models import Evidence, Finding

    class Stub(CompositeProvider):
        def __init__(self) -> None:
            super().__init__(RulesProvider())
            self.name = "stub"
            self.model = "stub-model"
            self.model_capable = True

        def analyze_unit(self, unit):  # type: ignore[override]
            findings = super().analyze_unit(unit)
            findings.append(
                Finding(
                    id="ctx.secret-leak",
                    severity=Severity.HIGH,
                    confidence=0.5,
                    title="Contextual",
                    description="Something contextual",
                    impact="i",
                    remediation="r",
                    source="model",
                    evidence=(Evidence(line=1, text="x", path=None),),
                )
            )
            return findings

    provider = Stub()
    findings = provider.analyze_unit(make_unit("STRIPE_API_KEY=" + SECRET + "\n"))
    sources = {finding.source for finding in findings}
    assert sources == {"rule", "model"}
    assert provider.components == ("rules",)
    assert provider.model_capable is True


def test_composite_provider_reports_the_widest_network_scope() -> None:
    provider = CompositeProvider(RulesProvider())
    assert provider.network_scope == "none"
    assert provider.offline is True
