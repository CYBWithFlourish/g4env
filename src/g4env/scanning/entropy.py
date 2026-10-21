"""Shannon entropy helpers used by the deterministic rules."""

from __future__ import annotations

import math
from collections import Counter

__all__ = ["looks_random", "shannon_entropy"]

#: Entropy (bits per character) above which a string is considered random.
ENTROPY_THRESHOLD = 3.5


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy of ``value`` in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def looks_random(value: str, *, threshold: float = ENTROPY_THRESHOLD) -> bool:
    """Return ``True`` when ``value`` has enough entropy to look machine generated."""
    return shannon_entropy(value) >= threshold
