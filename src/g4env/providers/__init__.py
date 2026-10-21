"""Analysis backends available to ``g4env audit``."""

from __future__ import annotations

from g4env.errors import UsageError
from g4env.providers.base import ModelInfo, ModelProvider, Provider
from g4env.providers.composite import CompositeProvider
from g4env.providers.gemini import (
    DEFAULT_GEMINI_MODEL,
    GeminiProvider,
    resolve_api_key,
)
from g4env.providers.ollama import DEFAULT_HOST, DEFAULT_MODEL, OllamaProvider
from g4env.providers.rules import RulesProvider

__all__ = [
    "DEFAULT_GEMINI_MODEL",
    "DEFAULT_HOST",
    "DEFAULT_MODEL",
    "PROVIDER_NAMES",
    "CompositeProvider",
    "GeminiProvider",
    "ModelInfo",
    "ModelProvider",
    "OllamaProvider",
    "Provider",
    "RulesProvider",
    "create_provider",
    "resolve_api_key",
]

#: The provider names accepted on the command line.
PROVIDER_NAMES = ("rules", "ollama", "gemini")


def create_provider(
    name: str,
    *,
    model: str | None = None,
    host: str | None = None,
    api_key: str | None = None,
    timeout: float = 120.0,
) -> Provider:
    """Create a provider by name.

    ``rules`` is fully offline. ``ollama`` combines the deterministic rules
    with a local model and ``gemini`` combines them with the hosted API,
    which requires an API key.
    """
    key = name.strip().lower()
    if key == "rules":
        return RulesProvider()
    if key == "ollama":
        return CompositeProvider(
            RulesProvider(),
            OllamaProvider(
                host=host or DEFAULT_HOST,
                model=model or DEFAULT_MODEL,
                timeout=timeout,
            ),
        )
    if key == "gemini":
        resolved = api_key or resolve_api_key()
        if not resolved:
            raise UsageError(
                "no Gemini API key found; set GEMINI_API_KEY (or GOOGLE_API_KEY) "
                "in the environment before using --provider gemini"
            )
        return CompositeProvider(
            RulesProvider(),
            GeminiProvider(
                api_key=resolved,
                model=model or DEFAULT_GEMINI_MODEL,
                timeout=timeout,
            ),
        )
    raise UsageError(
        f"unknown provider {name!r}; expected one of: {', '.join(PROVIDER_NAMES)}"
    )
