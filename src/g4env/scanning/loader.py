"""Safe loading of audit targets.

The loader is the boundary between untrusted files on disk and the analysis
engine. It enforces size limits, refuses binary content and decodes text
without ever raising on malformed input.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from g4env.errors import InputError

__all__ = [
    "DEFAULT_MAX_FILE_BYTES",
    "BinaryFileError",
    "FileKind",
    "FileTooLargeError",
    "SourceUnit",
    "load_source_unit",
    "max_file_bytes",
]

#: Largest file g4env will read by default (2 MiB).
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024

#: Number of leading bytes inspected when sniffing for binary content.
_SNIFF_BYTES = 8192

#: Ratio of undecodable bytes above which a file is treated as binary.
_MAX_REPLACEMENT_RATIO = 0.3


class FileKind(str, Enum):
    """The broad category of a scanned file."""

    ENV = "env"
    CONFIG = "config"
    SOURCE = "source"
    CI = "ci"
    OTHER = "other"


class BinaryFileError(InputError):
    """Raised when a file contains binary content and cannot be audited."""


class FileTooLargeError(InputError):
    """Raised when a file exceeds the configured size limit."""


@dataclass(frozen=True)
class SourceUnit:
    """A text file that is ready to be analysed."""

    path: Path
    rel_path: str
    kind: FileKind
    text: str
    lines: tuple[str, ...]
    size: int
    is_template: bool

    def line_text(self, number: int) -> str:
        """Return the text of a 1-based line number, or an empty string."""
        if 1 <= number <= len(self.lines):
            return self.lines[number - 1]
        return ""


def max_file_bytes() -> int:
    """Return the effective per-file size limit.

    The limit can be raised or lowered with the ``G4ENV_MAX_FILE_BYTES``
    environment variable.
    """
    raw = os.environ.get("G4ENV_MAX_FILE_BYTES")
    if not raw:
        return DEFAULT_MAX_FILE_BYTES
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_FILE_BYTES
    return value if value > 0 else DEFAULT_MAX_FILE_BYTES


def looks_binary(data: bytes) -> bool:
    """Return ``True`` when the byte blob looks like binary content."""
    return b"\x00" in data[:_SNIFF_BYTES]


def decode_text(data: bytes) -> str | None:
    """Decode ``data`` as UTF-8 text, or return ``None`` if it is not text."""
    text = data.decode("utf-8", errors="replace")
    if not text:
        return ""
    replacements = text.count("\ufffd")
    if replacements > max(1, int(len(text) * _MAX_REPLACEMENT_RATIO)):
        return None
    return text


def load_source_unit(
    path: Path,
    *,
    rel_path: str,
    kind: FileKind,
    is_template: bool,
    limit: int | None = None,
) -> SourceUnit:
    """Read ``path`` and return a :class:`SourceUnit`.

    Raises :class:`FileTooLargeError` or :class:`BinaryFileError` when the
    file cannot be audited safely.
    """
    limit = max_file_bytes() if limit is None else limit
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise InputError(f"cannot stat {path}: {exc}") from exc

    if size > limit:
        raise FileTooLargeError(
            f"{path} is {size} bytes which exceeds the {limit} byte limit"
        )

    try:
        data = path.read_bytes()
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc

    if looks_binary(data):
        raise BinaryFileError(f"{path} contains binary content and was skipped")

    text = decode_text(data)
    if text is None:
        raise BinaryFileError(f"{path} is not valid UTF-8 text and was skipped")

    return SourceUnit(
        path=path,
        rel_path=rel_path,
        kind=kind,
        text=text,
        lines=tuple(text.splitlines()),
        size=size,
        is_template=is_template,
    )
