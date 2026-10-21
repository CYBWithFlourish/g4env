"""Provider backed by the hosted Gemini API.

The Gemini provider is the only backend that leaves the machine. It is
therefore opt-in (``--provider gemini``), it always redacts content before
transmission and it is recorded as such in the report metadata
(``offline: false``, ``network_scope: "remote"``).
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from typing import Any

from g4env.errors import ProviderError
from g4env.providers.base import SYSTEM_PROMPT, ModelInfo, ModelProvider

__all__ = [
    "API_KEY_ENV_VARS",
    "DEFAULT_GEMINI_MODEL",
    "FALLBACK_MODELS",
    "GeminiApiError",
    "GeminiProvider",
    "GeminiRestTransport",
    "GeminiSdkTransport",
    "resolve_api_key",
]

#: Default Gemini model.
DEFAULT_GEMINI_MODEL = "gemini-3.8-flash"

#: Default Gemini REST endpoint.
DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

#: Environment variables inspected (in order) for the API key.
API_KEY_ENV_VARS = ("GEMINI_API_KEY", "GOOGLE_API_KEY", "G4ENV_GEMINI_API_KEY")

#: Models tried when the configured one is not available to the current key.
#:
#: Google retires models for newly created API keys, so a model that worked
#: yesterday can answer "no longer available to new users" today. When that
#: happens the provider continues with the first fallback that answers.
FALLBACK_MODELS: tuple[str, ...] = ("gemini-flash-latest", "gemma-4-26b-a4b-it")

#: HTTP statuses that mean the *model* is temporarily unavailable.
#:
#: These are worth retrying and, if that fails, worth switching to another
#: model for.
MODEL_TRANSIENT_STATUS_CODES: frozenset[int] = frozenset({500, 502, 503, 504})

#: HTTP status that means the *key* is being rate limited.
#:
#: The limit belongs to the account, not to a model, so another model would
#: hit it as well. It needs a longer wait instead of a switch.
RATE_LIMIT_STATUS = 429

#: How many times a transient failure is retried before giving up.
MAX_TRANSIENT_ATTEMPTS = 3

#: Base delay between retries, multiplied by the attempt number.
RETRY_BACKOFF_SECONDS = 2.0

#: Base delay for a rate limit, which needs a longer wait.
RATE_LIMIT_BACKOFF_SECONDS = 8.0

#: Markers that identify a "this model does not exist for you" answer.
_MODEL_UNAVAILABLE_MARKERS = (
    "no longer available",
    "is not found",
    "not found",
    "unknown model",
    "unsupported model",
    "invalid model",
)


class GeminiApiError(ProviderError):
    """An error returned by the Gemini API, with its HTTP status.

    The status code lets the provider tell a retired model (recoverable by
    switching models) apart from a bad key or a rate limit.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        body: str = "",
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


def _is_model_unavailable(exc: ProviderError) -> bool:
    """Return ``True`` when ``exc`` means the model cannot be used."""
    if getattr(exc, "status_code", None) != 404:
        return False
    detail = str(getattr(exc, "body", "") or "") + " " + str(exc)
    lowered = detail.lower()
    return any(marker in lowered for marker in _MODEL_UNAVAILABLE_MARKERS)


def resolve_api_key(environ: dict[str, str] | None = None) -> str | None:
    """Return the API key found in the environment, if any.

    The key is only ever read from the environment so that it never appears
    in a shell history, a process listing or a CI log.
    """
    env = environ if environ is not None else dict(os.environ)
    for name in API_KEY_ENV_VARS:
        value = env.get(name)
        if value and value.strip():
            return value.strip()
    return None


class GeminiRestTransport:
    """Talks to the Gemini REST API using the standard library."""

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 120.0,
    ) -> None:
        if not api_key:
            raise ProviderError("a Gemini API key is required")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(
        self,
        path: str,
        payload: dict[str, Any] | None = None,
        method: str = "GET",
    ) -> dict[str, Any]:
        url = f"{self.base_url}/{path.lstrip('/')}"
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "x-goog-api-key": self.api_key,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            with exc:
                detail = exc.read().decode("utf-8", errors="replace")[:400]
            raise GeminiApiError(
                f"the Gemini API returned HTTP {exc.code} for {path}: {detail}",
                status_code=exc.code,
                body=detail,
            ) from exc
        except urllib.error.URLError as exc:
            raise ProviderError(
                f"cannot reach the Gemini API: {exc.reason}"
            ) from exc
        except TimeoutError as exc:
            raise ProviderError(
                f"the Gemini API timed out after {self.timeout}s"
            ) from exc
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ProviderError("the Gemini API returned a non JSON response") from exc
        if not isinstance(parsed, dict):
            raise ProviderError("unexpected response shape from the Gemini API")
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
        generation_config: dict[str, Any] = {"temperature": 0}
        if json_mode:
            generation_config["responseMimeType"] = "application/json"
        payload = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": generation_config,
        }
        data = self._request(f"models/{model}:generateContent", payload, method="POST")

        feedback = data.get("promptFeedback")
        if isinstance(feedback, dict) and feedback.get("blockReason"):
            raise ProviderError(
                f"the Gemini API blocked the request: {feedback.get('blockReason')}"
            )
        candidates = data.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise ProviderError("the Gemini API returned no candidates")
        first = candidates[0]
        if not isinstance(first, dict):
            raise ProviderError("the Gemini API returned an unexpected candidate")
        content = first.get("content")
        if not isinstance(content, dict):
            raise ProviderError("the Gemini API returned an empty response")
        parts = content.get("parts")
        texts = [
            part.get("text", "")
            for part in parts or []
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        ]
        return "".join(texts)

    def list_models(self) -> list[ModelInfo]:
        """Return the models exposed by the Gemini API."""
        data = self._request("models")
        models: list[ModelInfo] = []
        for item in data.get("models", []):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", ""))
            if name.startswith("models/"):
                name = name[len("models/") :]
            if not name:
                continue
            details = item.get("description") or item.get("displayName")
            models.append(
                ModelInfo(
                    name=name,
                    size=None,
                    modified_at=None,
                    details=details if isinstance(details, str) else None,
                )
            )
        return models


class GeminiSdkTransport:
    """Talks to the Gemini API through the official ``google-genai`` SDK."""

    def __init__(self, api_key: str, timeout: float = 120.0) -> None:
        if not api_key:
            raise ProviderError("a Gemini API key is required")
        try:
            from google import genai  # type: ignore[import-not-found]
            from google.genai import types  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ProviderError(
                "the google-genai SDK is not installed; install the 'gemini' extra"
            ) from exc
        self._types = types
        try:
            self._client = genai.Client(api_key=api_key)
        except Exception as exc:  # pragma: no cover - SDK specific
            raise ProviderError(f"cannot initialise the Gemini client: {exc}") from exc
        self.timeout = timeout

    def generate(
        self,
        *,
        model: str,
        system: str,
        prompt: str,
        json_mode: bool = True,
    ) -> str:
        """Run a completion and return the model response text."""
        config_kwargs: dict[str, Any] = {
            "system_instruction": system,
            "temperature": 0.0,
            "max_output_tokens": 4096,
        }
        if json_mode:
            config_kwargs["response_mime_type"] = "application/json"
        try:
            config = self._types.GenerateContentConfig(**config_kwargs)
            response = self._client.models.generate_content(
                model=model,
                contents=prompt,
                config=config,
            )
        except Exception as exc:  # pragma: no cover - SDK specific
            status = getattr(exc, "code", None)
            raise GeminiApiError(
                f"the Gemini API request failed: {exc}",
                status_code=status if isinstance(status, int) else None,
                body=str(exc),
            ) from exc
        text = getattr(response, "text", None)
        if not isinstance(text, str):
            raise ProviderError("the Gemini API returned an empty response")
        return text

    def list_models(self) -> list[ModelInfo]:
        """Return the models exposed by the Gemini API."""
        try:
            pager = self._client.models.list()
        except Exception as exc:  # pragma: no cover - SDK specific
            raise ProviderError(f"cannot list Gemini models: {exc}") from exc
        models: list[ModelInfo] = []
        for item in pager:
            name = getattr(item, "name", None)
            if not isinstance(name, str) or not name:
                continue
            if name.startswith("models/"):
                name = name[len("models/") :]
            details = getattr(item, "display_name", None) or getattr(item, "description", None)
            models.append(
                ModelInfo(
                    name=name,
                    size=None,
                    modified_at=None,
                    details=details if isinstance(details, str) else None,
                )
            )
        return models


class GeminiProvider(ModelProvider):
    """Adds hosted Gemma/Gemini reasoning on top of the deterministic rules."""

    name = "gemini"
    offline = False
    network_scope = "remote"

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_GEMINI_MODEL,
        timeout: float = 120.0,
        transport: Any | None = None,
        *,
        retry_backoff: float = RETRY_BACKOFF_SECONDS,
        rate_limit_backoff: float = RATE_LIMIT_BACKOFF_SECONDS,
        fallbacks: Sequence[str] = FALLBACK_MODELS,
    ) -> None:
        super().__init__()
        self.transport = transport or _build_transport(api_key, timeout)
        self.model = model
        self.retry_backoff = retry_backoff
        self.rate_limit_backoff = rate_limit_backoff
        self.fallbacks = tuple(fallbacks)

    def generate(self, prompt: str) -> str:
        """Run the hosted model and return its raw response.

        The configured model is tried first. A model that the current key may
        not use any more (Google retires models for new keys) is replaced by
        the next candidate, as is a model that is temporarily unavailable. The
        switch is reported as a warning so the user always knows which model
        produced the findings.

        A rate limit is *not* a reason to switch: it belongs to the key, so
        every model would hit it. It is waited out on the same model instead.
        """
        model = self.model or DEFAULT_GEMINI_MODEL
        chain = [model, *(name for name in self.fallbacks if name != model)]
        for index, candidate in enumerate(chain):
            try:
                text = self._generate_with_retries(candidate, prompt)
            except ProviderError as exc:
                if index == len(chain) - 1:
                    raise
                replacement = chain[index + 1]
                if _is_model_unavailable(exc):
                    self.warn(
                        f"the model {candidate} is not available to this API key;"
                        f" continuing with {replacement}"
                    )
                    continue
                status = getattr(exc, "status_code", None)
                if status in MODEL_TRANSIENT_STATUS_CODES:
                    self.warn(
                        f"the model {candidate} is temporarily unavailable"
                        f" (HTTP {status}); continuing with {replacement}"
                    )
                    continue
                raise
            if candidate != model:
                self.model = candidate
            return text
        raise ProviderError(  # pragma: no cover - the loop always returns or raises
            "the Gemini API did not return a response"
        )

    def _generate_with_retries(self, model: str, prompt: str) -> str:
        """Call the model, retrying failures that are likely to be temporary.

        A rate limit belongs to the key rather than to the model, so it is
        waited out on the same model with a longer delay. A model that is
        temporarily unavailable is retried briefly; whether to switch to
        another model afterwards is up to the caller.
        """
        for attempt in range(1, MAX_TRANSIENT_ATTEMPTS + 1):
            try:
                return self.transport.generate(
                    model=model,
                    system=SYSTEM_PROMPT,
                    prompt=prompt,
                    json_mode=True,
                )
            except ProviderError as exc:
                status = getattr(exc, "status_code", None)
                if status == RATE_LIMIT_STATUS:
                    if attempt >= MAX_TRANSIENT_ATTEMPTS:
                        raise
                    self.warn(
                        "the Gemini API is rate limiting this key (HTTP 429);"
                        " waiting before the next attempt"
                    )
                    if self.rate_limit_backoff:
                        time.sleep(self.rate_limit_backoff * attempt)
                    continue
                if status not in MODEL_TRANSIENT_STATUS_CODES:
                    raise
                if attempt >= MAX_TRANSIENT_ATTEMPTS:
                    raise
                if self.retry_backoff:
                    time.sleep(self.retry_backoff * attempt)
        raise ProviderError(  # pragma: no cover - the loop always returns or raises
            "the Gemini API did not return a response"
        )

    def list_models(self) -> list[ModelInfo]:
        """Return the models exposed by the Gemini API."""
        return self.transport.list_models()


def _build_transport(api_key: str, timeout: float) -> Any:
    """Prefer the official SDK, fall back to the REST API."""
    try:
        import google.genai  # noqa: F401
    except ImportError:
        return GeminiRestTransport(api_key=api_key, timeout=timeout)
    return GeminiSdkTransport(api_key=api_key, timeout=timeout)
