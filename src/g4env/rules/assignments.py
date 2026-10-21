"""Parsing of ``KEY=value`` style assignments across file formats.

The parser understands dotenv, YAML, JSON, TOML, INI and shell style
assignments well enough to reason about the *value* of a configuration key
without pulling in a parser for every format.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

__all__ = ["Assignment", "iter_assignments", "parse_assignment"]

_ASSIGNMENT_RE = re.compile(
    r"^[ \t]*(?:export[ \t]+)?(?:-[ \t]+)?"
    r"(?P<name>\"[^\"\n]+\"|'[^'\n]+'|[A-Za-z_][A-Za-z0-9_.\-]*)"
    r"[ \t]*(?P<sep>[:=])[ \t]*(?P<value>.*?)[ \t]*$"
)

#: Schemes that make a ``scheme:value`` line a URL rather than an assignment.
_URL_SCHEMES = frozenset(
    {
        "http",
        "https",
        "ftp",
        "ftps",
        "file",
        "ssh",
        "git",
        "mailto",
        "data",
        "postgres",
        "postgresql",
        "mysql",
        "mariadb",
        "mongodb",
        "mongodb+srv",
        "redis",
        "rediss",
        "amqp",
        "amqps",
        "mssql",
        "sqlserver",
        "jdbc",
        "ldap",
        "smtp",
        "s3",
        "gs",
        "azure",
    }
)


@dataclass(frozen=True)
class Assignment:
    """A single configuration assignment."""

    line: int
    name: str
    value: str
    raw: str

    @property
    def is_quoted(self) -> bool:
        """Return ``True`` when the raw value was quoted."""
        return len(self.raw) >= 2 and self.raw[0] == self.raw[-1] and self.raw[0] in "\"'"


def _strip_comment(value: str) -> str:
    """Remove a trailing inline comment from an unquoted value."""
    quote: str | None = None
    for index, char in enumerate(value):
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
            continue
        if char == "#" and (index == 0 or value[index - 1] in " \t"):
            return value[:index].rstrip()
    return value.rstrip()


def parse_assignment(line: str) -> Assignment | None:
    """Parse a single line into an :class:`Assignment`, or return ``None``."""
    match = _ASSIGNMENT_RE.match(line)
    if match is None:
        return None
    name = match.group("name").strip("\"'")
    value = match.group("value").strip()
    if not name:
        return None
    if value.startswith("//") and name.lower() in _URL_SCHEMES:
        return None
    if name.lower() in _URL_SCHEMES and value.startswith("//"):
        return None
    cleaned = _strip_comment(value)
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in "\"'":
        cleaned = cleaned[1:-1]
    return Assignment(
        line=0,
        name=name,
        value=cleaned,
        raw=value,
    )


def iter_assignments(text: str) -> Iterator[Assignment]:
    """Yield every assignment found in ``text``."""
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        assignment = parse_assignment(line)
        if assignment is None:
            continue
        yield Assignment(
            line=number,
            name=assignment.name,
            value=assignment.value,
            raw=assignment.raw,
        )
