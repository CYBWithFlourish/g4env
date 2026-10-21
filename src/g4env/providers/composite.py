"""Combination of the deterministic rules with a model backend."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from g4env.errors import ProviderError
from g4env.models import Finding
from g4env.providers.base import ModelInfo, Provider
from g4env.scanning.discovery import Candidate
from g4env.scanning.loader import SourceUnit

__all__ = ["CompositeProvider"]


class CompositeProvider(Provider):
    """Runs the deterministic rules and a model backend side by side.

    The model backend adds contextual findings on top of the deterministic
    results; it never replaces them. Findings keep their ``source`` field so
    a report always shows where a finding came from.
    """

    def __init__(self, *providers: Provider) -> None:
        if not providers:
            raise ValueError("a composite provider needs at least one backend")
        super().__init__()
        self._providers = providers
        primary = providers[-1]
        self.name = primary.name
        self.model = primary.model
        self.offline = all(provider.offline for provider in providers)
        self.network_scope = self._network_scope()
        self.model_capable = any(provider.model_capable for provider in providers)

    def _network_scope(self) -> str:
        scopes = {provider.network_scope for provider in self._providers}
        if "remote" in scopes:
            return "remote"
        if "localhost-only" in scopes:
            return "localhost-only"
        return "none"

    @property
    def components(self) -> tuple[str, ...]:
        """The backends that make up this provider."""
        return tuple(provider.name for provider in self._providers)

    @property
    def warnings(self) -> list[str]:
        """Warnings raised by this provider and by its backends."""
        collected = list(self._warnings)
        for provider in self._providers:
            collected.extend(provider.warnings)
        return collected

    def analyze_unit(self, unit: SourceUnit) -> list[Finding]:
        """Analyse a file with every backend."""
        findings: list[Finding] = []
        for provider in self._providers:
            findings.extend(provider.analyze_unit(unit))
        return findings

    def analyze_project(
        self,
        root: Path,
        candidates: Sequence[Candidate],
    ) -> list[Finding]:
        """Analyse the project with every backend."""
        findings: list[Finding] = []
        for provider in self._providers:
            findings.extend(provider.analyze_project(root, candidates))
        return findings

    def list_models(self) -> list[ModelInfo]:
        """Return the models of the first backend that exposes any."""
        for provider in reversed(self._providers):
            models = provider.list_models()
            if models:
                return models
        return []

    def warm(self) -> None:
        """Warm up the first backend that supports it."""
        for provider in reversed(self._providers):
            warm = getattr(provider, "warm", None)
            if callable(warm):
                warm()
                return
        raise ProviderError(
            f"the {self.name} provider does not support warming up a model"
        )
