"""The deterministic, fully offline provider."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from g4env.models import Evidence, Finding
from g4env.providers.base import Provider
from g4env.rules.base import Rule, RuleHit
from g4env.rules.builtin import get_rules
from g4env.rules.project import check_tracked_env_files
from g4env.scanning.discovery import Candidate
from g4env.scanning.loader import SourceUnit

__all__ = ["RulesProvider"]

#: Rules that describe a secret more precisely than ``env.raw-secret``.
#: When one of them covers the same line, the generic raw secret hit is
#: dropped so that a single secret is never reported twice.
_RAW_SECRET_SUPPRESSORS = frozenset(
    {
        "env.private-key",
        "env.db-credentials",
        "env.secret-in-ci",
        "env.hardcoded-auth-header",
    }
)


class RulesProvider(Provider):
    """Runs the deterministic rule set. Makes no network calls."""

    name = "rules"
    offline = True
    network_scope = "none"
    model = None

    def __init__(self, rules: Sequence[Rule] | None = None) -> None:
        super().__init__()
        self._rules = tuple(rules) if rules is not None else get_rules()
        self._by_id = {rule.id: rule for rule in self._rules}

    @property
    def rules(self) -> tuple[Rule, ...]:
        """Return the rules this provider runs."""
        return self._rules

    def analyze_unit(self, unit: SourceUnit) -> list[Finding]:
        """Run every rule against ``unit``.

        Generic hits are dropped when a more specific rule already covers
        the same line, so a single secret is never reported twice under
        two different rule identifiers.
        """
        hits: list[RuleHit] = []
        for candidate_rule in self._rules:
            hits.extend(candidate_rule.scan(unit))

        specific_lines = {hit.line for hit in hits if not hit.generic}
        rules_on_line: dict[int, set[str]] = {}
        for hit in hits:
            rules_on_line.setdefault(hit.line, set()).add(hit.rule_id)

        findings: list[Finding] = []
        for hit in hits:
            if hit.generic and hit.line in specific_lines:
                continue
            if hit.rule_id == "env.raw-secret" and (
                rules_on_line.get(hit.line, set()) & _RAW_SECRET_SUPPRESSORS
            ):
                continue
            rule = self._by_id.get(hit.rule_id)
            if rule is None:  # pragma: no cover - defensive
                continue
            findings.append(self._to_finding(rule, hit, unit))
        return findings

    def analyze_project(
        self,
        root: Path,
        candidates: Sequence[Candidate],
    ) -> list[Finding]:
        """Run the project wide checks."""
        findings: list[Finding] = []
        for hit in check_tracked_env_files(root, candidates):
            findings.append(
                Finding(
                    id=hit.rule_id,
                    severity=hit.severity,
                    confidence=hit.confidence,
                    title="Environment file is not excluded from version control",
                    description=hit.description,
                    impact="A committed .env file publishes every secret it contains.",
                    remediation="Add the file to .gitignore and rotate the exposed values.",
                    source="rule",
                    evidence=(
                        Evidence(
                            line=hit.line,
                            text=hit.text,
                            path=hit.text if self.attach_paths else None,
                        ),
                    ),
                )
            )
        return findings

    def _to_finding(self, rule: Rule, hit: RuleHit, unit: SourceUnit) -> Finding:
        evidence = Evidence(
            line=hit.line,
            text=hit.text,
            path=unit.rel_path if self.attach_paths else None,
        )
        return Finding(
            id=hit.rule_id,
            severity=hit.severity,
            confidence=hit.confidence,
            title=rule.title,
            description=hit.description,
            impact=rule.impact,
            remediation=rule.remediation,
            source="rule",
            evidence=(evidence,),
        )
