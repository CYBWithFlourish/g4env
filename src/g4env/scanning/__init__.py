"""File discovery, safe loading, redaction and entropy helpers."""

from __future__ import annotations

from g4env.scanning.discovery import Candidate, classify, discover, is_template_name
from g4env.scanning.entropy import looks_random, shannon_entropy
from g4env.scanning.loader import (
    BinaryFileError,
    FileKind,
    FileTooLargeError,
    SourceUnit,
    load_source_unit,
    max_file_bytes,
)
from g4env.scanning.redaction import MASK, redact_line, redact_text, redact_value

__all__ = [
    "MASK",
    "BinaryFileError",
    "Candidate",
    "FileKind",
    "FileTooLargeError",
    "SourceUnit",
    "classify",
    "discover",
    "is_template_name",
    "load_source_unit",
    "looks_random",
    "max_file_bytes",
    "redact_line",
    "redact_text",
    "redact_value",
    "shannon_entropy",
]
