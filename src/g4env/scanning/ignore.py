"""A small, conservative implementation of ``.gitignore`` style matching.

g4env uses it to skip build artefacts, virtual environments and vendored
dependencies when auditing a directory. Only the widely used subset of the
ignore format is supported; anything unrecognised is ignored rather than
treated as an exclusion, which keeps the tool from silently skipping files.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

__all__ = ["IgnoreRules", "parse_ignore_file"]


@dataclass(frozen=True)
class _Pattern:
    regex: re.Pattern[str]
    negated: bool
    directory_only: bool
    anchored: bool


def _compile(pattern: str) -> _Pattern | None:
    raw = pattern.strip()
    if not raw or raw.startswith("#"):
        return None
    negated = raw.startswith("!")
    if negated:
        raw = raw[1:]
    directory_only = raw.endswith("/")
    if directory_only:
        raw = raw[:-1]
    if not raw:
        return None

    anchored = "/" in raw
    if raw.startswith("/"):
        raw = raw[1:]
        anchored = True

    parts = []
    index = 0
    length = len(raw)
    while index < length:
        char = raw[index]
        if char == "*":
            if raw.startswith("**", index):
                parts.append(".*")
                index += 2
                if raw.startswith("/", index):
                    index += 1
                    parts.append("/?")
                continue
            parts.append("[^/]*")
            index += 1
            continue
        if char == "?":
            parts.append("[^/]")
            index += 1
            continue
        if char == "[":
            end = raw.find("]", index)
            if end == -1:
                parts.append(re.escape(char))
                index += 1
                continue
            body = raw[index + 1 : end]
            if body.startswith("!"):
                body = "^" + body[1:]
            parts.append(f"[{body}]")
            index = end + 1
            continue
        parts.append(re.escape(char))
        index += 1

    body = "".join(parts)
    if anchored:
        expression = f"^{body}$"
    else:
        expression = f"(?:^|/){body}$"
    try:
        regex = re.compile(expression)
    except re.error:  # pragma: no cover - defensive
        return None
    return _Pattern(regex=regex, negated=negated, directory_only=directory_only, anchored=anchored)


def parse_ignore_file(text: str) -> list[_Pattern]:
    """Parse the contents of an ignore file into compiled patterns."""
    patterns: list[_Pattern] = []
    for line in text.splitlines():
        compiled = _compile(line)
        if compiled is not None:
            patterns.append(compiled)
    return patterns


class IgnoreRules:
    """Evaluate paths against a set of ignore patterns."""

    def __init__(self, patterns: list[_Pattern] | None = None) -> None:
        self._patterns = list(patterns or [])

    def __bool__(self) -> bool:
        return bool(self._patterns)

    def extend(self, text: str) -> None:
        """Add the patterns contained in ``text`` to this rule set."""
        self._patterns.extend(parse_ignore_file(text))

    def is_ignored(self, relative_path: str, *, is_dir: bool = False) -> bool:
        """Return ``True`` when ``relative_path`` should be skipped."""
        if not self._patterns:
            return False
        candidate = PurePosixPath(relative_path)
        ignored = False
        for pattern in self._patterns:
            if pattern.directory_only and not is_dir:
                # A directory-only pattern still ignores everything below it.
                parts = candidate.parts
                for index in range(1, len(parts)):
                    prefix = "/".join(parts[:index])
                    if pattern.regex.search(prefix):
                        return True
            if pattern.regex.search(candidate.name):
                ignored = not pattern.negated
                continue
            if pattern.anchored and pattern.regex.search(candidate.as_posix()):
                ignored = not pattern.negated
                continue
            if not pattern.anchored:
                for index in range(1, len(candidate.parts)):
                    prefix = "/".join(candidate.parts[:index])
                    if pattern.regex.search(prefix):
                        ignored = not pattern.negated
                        break
        return ignored
