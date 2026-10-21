"""The labelled evaluation set used by ``g4env bench``.

The set contains both positive cases (content that must be reported) and
negative cases (content that must stay silent). It doubles as the
regression suite for the deterministic rules.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from g4env.bench.tokens import substitute

__all__ = ["DATASET_PATH", "BenchCase", "load_cases"]

DATASET_PATH = Path(__file__).resolve().parent / "dataset.json"


@dataclass(frozen=True)
class BenchCase:
    """A single labelled sample."""

    id: str
    filename: str
    kind: str
    template: bool
    text: str
    expect: tuple[str, ...]
    rationale: str
    mode: str = "rules"
    allow_any_model: bool = False

    @property
    def is_contextual(self) -> bool:
        """Return ``True`` when the case targets a model provider."""
        return self.mode == "contextual" or any(item.endswith("*") for item in self.expect)


def _case_from_dict(payload: dict[str, Any]) -> BenchCase:
    return BenchCase(
        id=str(payload.get("id", "")),
        filename=str(payload.get("filename", ".env")),
        kind=str(payload.get("kind", "env")),
        template=bool(payload.get("template", False)),
        text=substitute(str(payload.get("text", ""))),
        expect=tuple(str(item) for item in payload.get("expect", [])),
        rationale=str(payload.get("rationale", "")),
        mode=str(payload.get("mode", "rules")),
        allow_any_model=bool(payload.get("allow_any_model", False)),
    )


@lru_cache(maxsize=1)
def load_cases() -> tuple[BenchCase, ...]:
    """Load the labelled evaluation set."""
    with DATASET_PATH.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    cases = payload.get("cases", [])
    return tuple(_case_from_dict(item) for item in cases)
