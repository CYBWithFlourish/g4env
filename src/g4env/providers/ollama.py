"""Provider backed by a local Ollama server."""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from typing import Any

from g4env.errors import ProviderError
from g4env.providers.base import SYSTEM_PROMPT, ModelInfo, ModelProvider

__all__ = ["DEFAULT_HOST", "DEFAULT_MODEL", "OllamaProvider", "OllamaTransport"]

#: Default Ollama model tag.
DEFAULT_MODEL = "gemma2:2b"

#: Default Ollama server address.
DEFAULT_HOST = "http://127.0.0.1:11434"


class OllamaTransport:
    """Minimal HTTP client for the Ollama REST API."""

    def __init__(self, host: str = DEFAULT_HOST, timeout: float = 120.0) -> None:
        self.host = host.rstrip("/")
        self.timeout = timeout

    def _request(
        self,
        path: str,
        payload: dict[str, Any] | None = None,
        method: str = "GET",
    ) -> dict[str, Any]:
        url = f"{self.host}{path}"
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            with exc:
                detail = exc.read().decode("utf-8", errors="replace")[:400]
            raise ProviderError(
                f"the Ollama server returned HTTP {exc.code} for {path}: {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, (TimeoutError, socket.timeout)):
                raise ProviderError(
                    f"the Ollama server at {self.host} timed out after {self.timeout}s"
                ) from exc
            raise ProviderError(
                f"cannot reach the Ollama server at {self.host}: {reason}. "
                "Start it with 'ollama serve' or pass --host."
            ) from exc
        except TimeoutError as exc:
            raise ProviderError(
                f"the Ollama server at {self.host} timed out after {self.timeout}s"
            ) from exc
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ProviderError(
                f"the Ollama server returned a non JSON response for {path}"
            ) from exc
        if not isinstance(parsed, dict):
            raise ProviderError(f"unexpected response shape from {path}")
        return parsed

    def generate(
        self,
        *,
        model: str,
        system: str,
        prompt: str,
        json_mode: bool = True,
    ) -> str:
        """Run a completion and return the model response text."""
        payload: dict[str, Any] = {
            "model": model,
            "prompt": f"{system}\n\n{prompt}",
            "stream": False,
            "options": {"temperature": 0},
        }
        if json_mode:
            payload["format"] = "json"
        try:
            data = self._request("/api/generate", payload, method="POST")
        except ProviderError as exc:
            if json_mode and "HTTP 400" in str(exc):
                payload.pop("format", None)
                data = self._request("/api/generate", payload, method="POST")
            else:
                raise
        response = data.get("response")
        if not isinstance(response, str):
            raise ProviderError("the Ollama server did not return a response body")
        return response

    def list_models(self) -> list[ModelInfo]:
        """Return the models installed in the local Ollama server."""
        data = self._request("/api/tags")
        models: list[ModelInfo] = []
        for item in data.get("models", []):
            if not isinstance(item, dict):
                continue
            details = item.get("details")
            family = details.get("family") if isinstance(details, dict) else None
            models.append(
                ModelInfo(
                    name=str(item.get("name", "")),
                    size=item.get("size") if isinstance(item.get("size"), int) else None,
                    modified_at=item.get("modified_at") if isinstance(item.get("modified_at"), str) else None,
                    details=family if isinstance(family, str) else None,
                )
            )
        return models

    def warm(self, model: str, keep_alive: str = "10m") -> None:
        """Preload ``model`` into memory."""
        self._request(
            "/api/generate",
            {"model": model, "prompt": "", "keep_alive": keep_alive, "stream": False},
            method="POST",
        )


class OllamaProvider(ModelProvider):
    """Adds local Gemma reasoning on top of the deterministic rules."""

    name = "ollama"
    offline = False
    network_scope = "localhost-only"

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        model: str = DEFAULT_MODEL,
        timeout: float = 120.0,
        transport: OllamaTransport | None = None,
    ) -> None:
        super().__init__()
        self.transport = transport or OllamaTransport(host=host, timeout=timeout)
        self.host = self.transport.host
        self.model = model

    def generate(self, prompt: str) -> str:
        """Run the local model and return its raw response."""
        return self.transport.generate(
            model=self.model or DEFAULT_MODEL,
            system=SYSTEM_PROMPT,
            prompt=prompt,
            json_mode=True,
        )

    def list_models(self) -> list[ModelInfo]:
        """Return the models available in the local Ollama server."""
        return self.transport.list_models()

    def warm(self) -> None:
        """Preload the configured model into memory."""
        self.transport.warm(self.model or DEFAULT_MODEL)
