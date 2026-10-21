"""The deterministic rule set shipped with g4env.

Every rule works offline, without a model and without network access. Rules
are intentionally conservative: they must be able to explain themselves with
a concrete piece of evidence.
"""

from __future__ import annotations

import re

from g4env.models import Severity
from g4env.patterns import VENDOR_SIGNATURES
from g4env.rules.assignments import Assignment, iter_assignments
from g4env.rules.base import Rule, RuleHit
from g4env.scanning.loader import FileKind, SourceUnit
from g4env.variables import (
    classify_name,
    is_placeholder_value,
    is_reference_value,
    is_secret_name,
)

__all__ = [
    "BUILTIN_RULES",
    "DatabaseCredentialsRule",
    "HardcodedAuthHeaderRule",
    "HighEntropyRule",
    "InsecureDefaultRule",
    "PrivateKeyRule",
    "RawSecretRule",
    "SecretInPipelineRule",
    "WeakPasswordRule",
    "get_rules",
]

#: Values that are never credentials even though they look opaque.
_BOOLEAN_LITERALS = frozenset({"true", "false", "yes", "no", "on", "off", "enabled", "disabled"})

_NUMERIC_RE = re.compile(r"^[\d.,\s%+-]+$")

#: A value that is worth reporting as a raw secret.
_SECRETISH_RE = re.compile(r"^[A-Za-z0-9!#$%^&*()\-_+=|{}\[\]:;<>?/,.~]{10,}$")

#: A call expression such as ``strip().lower()`` is source code, not a literal.
_CALL_EXPRESSION_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\s*\(")

#: Minimum length of an opaque value before it is considered a credential.
_MIN_SECRET_LENGTH = 12

#: Minimum length of an opaque value that is only classified by entropy.
_MIN_ENTROPY_LENGTH = 24


class RawSecretRule(Rule):
    """Detect well known credential formats and secret-shaped assignments."""

    id = "env.raw-secret"
    severity = Severity.HIGH
    title = "Raw API token detected"
    description = "A plaintext API secret was found in the configuration."
    impact = "Exposed credentials can lead to unauthorized service access."
    remediation = "Move secrets to a secure secret manager or environment store."
    confidence = 0.95

    def scan(self, unit: SourceUnit) -> list[RuleHit]:
        hits: list[RuleHit] = []
        seen: set[tuple[int, str]] = set()
        assignments = {item.line: item for item in iter_assignments(unit.text)}

        for number, line in enumerate(unit.lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            for signature in VENDOR_SIGNATURES:
                for match in signature.regex.finditer(line):
                    secret = match.group(1)
                    key = (number, secret)
                    if key in seen:
                        continue
                    seen.add(key)
                    hits.append(
                        RuleHit(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=self.confidence,
                            line=number,
                            text=stripped,
                            description=(
                                f"A plaintext {signature.label} was found"
                                f"{self._context(assignments.get(number), secret)}."
                            ),
                        )
                    )

        for assignment in assignments.values():
            if not is_secret_name(assignment.name):
                continue
            value = assignment.value
            if not self._is_credential_value(value):
                continue
            key = (assignment.line, value)
            if key in seen:
                continue
            seen.add(key)
            hits.append(
                RuleHit(
                    rule_id=self.id,
                    severity=self.severity,
                    confidence=0.85,
                    line=assignment.line,
                    text=unit.line_text(assignment.line).strip(),
                    description=(
                        f"A plaintext API secret was found assigned to {assignment.name}."
                    ),
                    var_name=assignment.name,
                    generic=True,
                )
            )
        return hits

    def _context(self, assignment: Assignment | None, secret: str) -> str:
        if assignment is not None and secret in assignment.raw:
            return f" assigned to {assignment.name}"
        return ""

    @staticmethod
    def _is_credential_value(value: str) -> bool:
        if len(value) < _MIN_SECRET_LENGTH:
            return False
        if is_placeholder_value(value) or is_reference_value(value):
            return False
        if value.lower() in _BOOLEAN_LITERALS:
            return False
        if _NUMERIC_RE.match(value):
            return False
        if _CALL_EXPRESSION_RE.search(value):
            # ``strip().lower()`` is an expression, not an embedded literal.
            return False
        return bool(_SECRETISH_RE.match(value))


class PrivateKeyRule(Rule):
    """Detect embedded private key material."""

    id = "env.private-key"
    severity = Severity.CRITICAL
    title = "Private key embedded in configuration"
    description = "A private key block was found inside a configuration file."
    impact = "A committed private key grants full access to the associated identities."
    remediation = "Revoke the key, generate a new one and store it outside the repository."
    confidence = 0.99

    _MARKER_RE = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----")
    _PUTTY_RE = re.compile(r"PuTTY-User-Key-File-\d")

    def scan(self, unit: SourceUnit) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for number, line in enumerate(unit.lines, start=1):
            stripped = line.strip()
            match = self._MARKER_RE.search(stripped) or self._PUTTY_RE.search(stripped)
            if match is None:
                continue
            label = match.group(0).strip("- ")
            hits.append(
                RuleHit(
                    rule_id=self.id,
                    severity=self.severity,
                    confidence=self.confidence,
                    line=number,
                    text=stripped,
                    description=(
                        f"An unencrypted private key ({label}) is embedded in"
                        f" {unit.rel_path}."
                    ),
                )
            )
        return hits


class DatabaseCredentialsRule(Rule):
    """Detect connection strings that embed a username and a password."""

    id = "env.db-credentials"
    severity = Severity.HIGH
    title = "Database credentials in plaintext"
    description = "A database connection string contains a username and a password."
    impact = "Leaked database credentials allow direct access to application data."
    remediation = "Store the connection string in a secret manager and inject it at runtime."
    confidence = 0.9

    _URI_RE = re.compile(
        r"(?P<scheme>(?:jdbc:)?(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?"
        r"|amqps?|mssql|sqlserver|cockroachdb|clickhouse|cassandra|elasticsearch))://"
        r"(?P<user>[^\s:/@]+):(?P<password>[^\s/@]+)@",
        re.IGNORECASE,
    )
    _PASSWORD_RE = re.compile(r"(?i)\b(?:password|pwd)\s*=\s*(?P<password>[^;\"'\s]{3,})")
    _HOST_RE = re.compile(
        r"(?i)\b(?:server|data source|host|initial catalog|database|dbname|database_name)\s*="
    )

    def scan(self, unit: SourceUnit) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for number, line in enumerate(unit.lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = self._URI_RE.search(stripped)
            if match is not None:
                password = match.group("password")
                if is_placeholder_value(password) or is_reference_value(password):
                    # The password is a placeholder or a runtime reference,
                    # so nothing is actually exposed.
                    continue
                hits.append(
                    RuleHit(
                        rule_id=self.id,
                        severity=self.severity,
                        confidence=self.confidence,
                        line=number,
                        text=stripped,
                        description=(
                            "A plaintext database connection string with an embedded"
                            f" username and password was found using the"
                            f" {match.group('scheme').lower()}:// scheme."
                        ),
                    )
                )
                continue
            password_match = self._PASSWORD_RE.search(stripped)
            if password_match is not None and self._HOST_RE.search(stripped):
                password = password_match.group("password")
                if is_placeholder_value(password) or is_reference_value(password):
                    continue
                hits.append(
                    RuleHit(
                        rule_id=self.id,
                        severity=self.severity,
                        confidence=0.85,
                        line=number,
                        text=stripped,
                        description=(
                            "A plaintext database connection string with an embedded"
                            " username and password was found."
                        ),
                    )
                )
        return hits


class InsecureDefaultRule(Rule):
    """Detect real secrets inside template or example files."""

    id = "env.insecure-default"
    severity = Severity.MEDIUM
    title = "Template file contains a real secret value"
    description = "A sensitive key in a template file holds a real value instead of a placeholder."
    impact = "Templates are copied by every developer, so one real key leaks to everyone."
    remediation = "Replace the value with a placeholder such as your-api-key-here."
    confidence = 0.8

    def scan(self, unit: SourceUnit) -> list[RuleHit]:
        if not unit.is_template:
            return []
        hits: list[RuleHit] = []
        for assignment in iter_assignments(unit.text):
            if not is_secret_name(assignment.name):
                continue
            value = assignment.value
            if not value or is_placeholder_value(value) or is_reference_value(value):
                continue
            if len(value) < 8:
                continue
            hits.append(
                RuleHit(
                    rule_id=self.id,
                    severity=self.severity,
                    confidence=self.confidence,
                    line=assignment.line,
                    text=unit.line_text(assignment.line).strip(),
                    description=(
                        f"The template key {assignment.name} carries a real secret"
                        " value instead of a placeholder."
                    ),
                    var_name=assignment.name,
                )
            )
        return hits


class HighEntropyRule(Rule):
    """Detect high entropy values assigned to unclassified variables."""

    id = "env.high-entropy"
    severity = Severity.MEDIUM
    title = "High entropy value in an unclassified variable"
    description = "A high entropy string is assigned to a variable whose name gives no clue."
    impact = "Unlabelled opaque values are frequently forgotten credentials."
    remediation = "Classify the variable explicitly and move the value to a secret store."
    confidence = 0.6

    _OPAQUE_RE = re.compile(r"^[A-Za-z0-9+/_\-=]+$")

    def scan(self, unit: SourceUnit) -> list[RuleHit]:
        from g4env.scanning.entropy import shannon_entropy

        hits: list[RuleHit] = []
        for assignment in iter_assignments(unit.text):
            if classify_name(assignment.name) != "benign":
                continue
            value = assignment.value
            if len(value) < _MIN_ENTROPY_LENGTH:
                continue
            if not self._OPAQUE_RE.match(value):
                continue
            if is_placeholder_value(value) or is_reference_value(value):
                continue
            if shannon_entropy(value) < 3.5:
                continue
            hits.append(
                RuleHit(
                    rule_id=self.id,
                    severity=self.severity,
                    confidence=self.confidence,
                    line=assignment.line,
                    text=unit.line_text(assignment.line).strip(),
                    description=(
                        f"The variable {assignment.name} holds a high entropy value"
                        " that is not classified by its name."
                    ),
                    var_name=assignment.name,
                )
            )
        return hits


class WeakPasswordRule(Rule):
    """Detect weak or trivial passwords."""

    id = "env.weak-password"
    severity = Severity.MEDIUM
    title = "Weak password committed to configuration"
    description = "A password variable is set to a weak, guessable value."
    impact = "Weak credentials are trivially brute forced."
    remediation = "Generate a long random password and store it in a secret manager."
    confidence = 0.75

    _WEAK_LITERALS = frozenset(
        {
            "admin",
            "root",
            "password",
            "passw0rd",
            "letmein",
            "welcome",
            "qwerty",
            "123456",
            "12345678",
            "1234567890",
            "abc123",
            "password1",
            "postgres",
            "mysql",
            "secret",
            "changeme",
            "default",
            "test",
        }
    )

    def scan(self, unit: SourceUnit) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for assignment in iter_assignments(unit.text):
            name = assignment.name.upper()
            if not any(token in name for token in ("PASSWORD", "PASSWD", "PWD")):
                continue
            value = assignment.value
            if not value or is_reference_value(value) or is_placeholder_value(value):
                continue
            if value.lower() in self._WEAK_LITERALS or len(value) < 12:
                hits.append(
                    RuleHit(
                        rule_id=self.id,
                        severity=self.severity,
                        confidence=self.confidence,
                        line=assignment.line,
                        text=unit.line_text(assignment.line).strip(),
                        description=(
                            f"The password variable {assignment.name} uses a weak,"
                            " guessable value."
                        ),
                        var_name=assignment.name,
                    )
                )
        return hits


class HardcodedAuthHeaderRule(Rule):
    """Detect authorization headers with a literal credential."""

    id = "env.hardcoded-auth-header"
    severity = Severity.HIGH
    title = "Hardcoded authorization header"
    description = "An Authorization header carries a literal credential."
    impact = "Hardcoded tokens leak through version control, logs and client bundles."
    remediation = "Read the credential from the environment at runtime."
    confidence = 0.85

    _HEADER_RE = re.compile(
        r"(?i)\bauthorization[\"']?\s*[:=]\s*[\"']?(?:bearer|basic|token)?\s*"
        r"(?P<value>[A-Za-z0-9._\-+/=]{10,})"
    )
    _API_KEY_HEADER_RE = re.compile(
        r"(?i)\b(?:x-api-key|x-auth-token|api-key)[\"']?\s*[:=]\s*[\"']?"
        r"(?P<value>[A-Za-z0-9._\-+/=]{12,})"
    )

    def scan(self, unit: SourceUnit) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for number, line in enumerate(unit.lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for regex in (self._HEADER_RE, self._API_KEY_HEADER_RE):
                match = regex.search(stripped)
                if match is None:
                    continue
                value = match.group("value")
                if is_reference_value(value) or is_placeholder_value(value):
                    continue
                hits.append(
                    RuleHit(
                        rule_id=self.id,
                        severity=self.severity,
                        confidence=self.confidence,
                        line=number,
                        text=stripped,
                        description=(
                            "An authorization header contains a literal credential"
                            " instead of a runtime reference."
                        ),
                    )
                )
                break
        return hits


class SecretInPipelineRule(Rule):
    """Detect literal secrets inside CI/CD pipeline definitions."""

    id = "env.secret-in-ci"
    severity = Severity.HIGH
    title = "Secret hardcoded in CI/CD pipeline"
    description = "A pipeline definition assigns a literal value to a sensitive key."
    impact = "Pipeline logs, artefacts and forks expose the credential to everyone."
    remediation = "Store the value in the CI secret store and reference it at runtime."
    confidence = 0.8

    def scan(self, unit: SourceUnit) -> list[RuleHit]:
        if unit.kind is not FileKind.CI:
            return []
        hits: list[RuleHit] = []
        for assignment in iter_assignments(unit.text):
            if not is_secret_name(assignment.name):
                continue
            value = assignment.value
            if not value or is_reference_value(value) or is_placeholder_value(value):
                continue
            if len(value) < 8:
                continue
            hits.append(
                RuleHit(
                    rule_id=self.id,
                    severity=self.severity,
                    confidence=self.confidence,
                    line=assignment.line,
                    text=unit.line_text(assignment.line).strip(),
                    description=(
                        f"The pipeline assigns a literal value to the sensitive key"
                        f" {assignment.name}."
                    ),
                    var_name=assignment.name,
                )
            )
        return hits


#: All deterministic rules, in the order they are documented.
BUILTIN_RULES: tuple[Rule, ...] = (
    RawSecretRule(),
    PrivateKeyRule(),
    DatabaseCredentialsRule(),
    InsecureDefaultRule(),
    HighEntropyRule(),
    WeakPasswordRule(),
    HardcodedAuthHeaderRule(),
    SecretInPipelineRule(),
)


def get_rules() -> tuple[Rule, ...]:
    """Return the deterministic rule set."""
    return BUILTIN_RULES
