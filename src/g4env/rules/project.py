"""Project level checks that look at the whole tree rather than a single file."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from g4env.models import Severity
from g4env.rules.base import RuleHit
from g4env.scanning.discovery import Candidate, load_ignore_rules
from g4env.scanning.loader import FileKind

__all__ = ["check_tracked_env_files"]


def check_tracked_env_files(root: Path, candidates: Sequence[Candidate]) -> list[RuleHit]:
    """Report ``.env`` files that are not excluded from version control.

    A ``.env`` file that is not ignored by ``.gitignore`` is almost certainly
    going to be committed, which is the single most common way secrets leak.
    """
    if not root.is_dir():
        return []
    rules = load_ignore_rules(root)
    hits: list[RuleHit] = []
    for candidate in candidates:
        if candidate.kind is not FileKind.ENV or candidate.is_template:
            continue
        if candidate.path.name != ".env" and not candidate.path.name.startswith(".env."):
            continue
        if rules.is_ignored(candidate.rel_path):
            continue
        hits.append(
            RuleHit(
                rule_id="env.tracked-env-file",
                severity=Severity.MEDIUM,
                confidence=0.7,
                line=1,
                text=candidate.rel_path,
                description=(
                    f"{candidate.rel_path} exists and is not excluded by .gitignore,"
                    " so it is likely to be committed to version control."
                ),
            )
        )
    return hits
