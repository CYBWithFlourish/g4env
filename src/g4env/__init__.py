"""g4env - Gemma 4 Environment Security.

An offline-first CLI that audits environment files, configuration schemas,
CI/CD pipelines and codebases for hardcoded credentials, sensitive keys and
environment anti-patterns.
"""

from __future__ import annotations

__all__ = ["SCHEMA_VERSION", "TOOL_NAME", "__version__"]

TOOL_NAME = "g4env"
__version__ = "1.0.0"

#: Version of the machine readable report schema emitted by this release.
SCHEMA_VERSION = "1.0"
