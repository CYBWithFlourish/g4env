"""Shared knowledge about credential-shaped values.

The same classification logic is used by the deterministic rules (to decide
*what* is suspicious) and by the redaction layer (to decide *what* to mask),
so the two can never drift apart.
"""

from __future__ import annotations

import re

__all__ = [
    "SECRET_NAME_TOKENS",
    "classify_name",
    "is_credential_name",
    "is_placeholder_value",
    "is_reference_value",
    "is_secret_name",
    "tokenize_name",
]

#: Name fragments that mark a variable as carrying a secret.
SECRET_NAME_TOKENS = frozenset(
    {
        "APIKEY",
        "KEY",
        "SECRET",
        "SECRETKEY",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "PASS",
        "PASSPHRASE",
        "CREDENTIAL",
        "CREDENTIALS",
        "CRED",
        "AUTH",
        "AUTHORIZATION",
        "PRIVATEKEY",
        "ACCESSKEY",
        "ACCESSKEYID",
        "CLIENTSECRET",
        "SESSIONKEY",
        "SIGNINGKEY",
        "ENCRYPTIONKEY",
        "SALT",
        "SIGNATURE",
        "WEBHOOK",
        "PAT",
        "DSN",
        "CERT",
        "CERTIFICATE",
        "KEYFILE",
        "SSHKEY",
        "GPGKEY",
    }
)

#: Name fragments that suggest a connection string or user account.
CREDENTIAL_NAME_TOKENS = frozenset(
    {
        "USER",
        "USERNAME",
        "UID",
        "LOGIN",
        "ACCOUNT",
        "ACCOUNTID",
        "CONNECTION",
        "CONNECTIONSTRING",
        "URI",
        "URL",
        "DSN",
        "HOST",
        "SERVER",
        "ENDPOINT",
        "BUCKET",
        "PROJECT",
        "PROJECTID",
        "ORG",
        "TENANT",
        "TENANTID",
        "REGION",
    }
)

#: Names that contain a secret fragment but are perfectly safe.
_SECRET_NAME_ALLOWLIST = frozenset(
    {
        "MONKEY",
        "KEYBOARD",
        "KEYCHAIN",
        "HOTKEY",
        "KEYNOTE",
        "PASSKEY",
        "PASSWORDS_DIR",
        "TURKEY",
        "KEYSTORE",
        "KEYRING",
        "PUBLICKEY",
        "PUBLIC_KEY_PATH",
        "CERTBOT",
        "TOKENIZER",
        "PASSWORDLESS",
    }
)

_NAME_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")

#: Values that are clearly placeholders rather than real secrets.
_PLACEHOLDER_LITERALS = frozenset(
    {
        "",
        "-",
        "--",
        "n/a",
        "na",
        "none",
        "null",
        "nil",
        "undefined",
        "todo",
        "tbd",
        "changeme",
        "change_me",
        "change-me",
        "changethis",
        "replace_me",
        "replace-me",
        "replaceme",
        "placeholder",
        "example",
        "example.com",
        "sample",
        "dummy",
        "fake",
        "test",
        "testing",
        "secret",
        "password",
        "mypassword",
        "your_password_here",
        "your-password-here",
        "your_secret_here",
        "your-secret-here",
        "your_api_key_here",
        "your-api-key-here",
        "your_token_here",
        "your-token-here",
        "insert_key_here",
        "insert-key-here",
        "set_me",
        "setme",
        "unset",
        "empty",
        "redacted",
        "removed",
        "hidden",
        "***",
        "****",
        "xxxx",
        "xxxxxxxx",
        "xxxxxxxxxxxxxxxx",
        "0000000000000000",
        "1234567890123456",
    }
)

_PLACEHOLDER_PATTERNS = (
    re.compile(r"^x{3,}$", re.IGNORECASE),
    re.compile(r"^\*{3,}$"),
    re.compile(r"^\.{3,}$"),
    re.compile(r"^<[^>]*>$"),
    re.compile(r"^\[[^\]]*\]$"),
    re.compile(r"^_+$"),
    re.compile(r"^\?+$"),
    re.compile(r"^(?:todo|tbd|fixme)\b", re.IGNORECASE),
    re.compile(r"^(?:your|my|some|the)?[\s_-]*(?:api[\s_-]?)?(?:key|secret|token|password|passwd|pwd)[\s_-]*(?:here)?$", re.IGNORECASE),
    re.compile(r"^(?:replace|insert|enter|set)[\s_-]*(?:me|it|this|your)?[\s_-]*(?:key|secret|token|password)?$", re.IGNORECASE),
    re.compile(r"^(?:example|sample|dummy|fake|test|placeholder|redacted)[\w\-]*$", re.IGNORECASE),
    re.compile(r"^[A-Za-z0-9+/=_-]{0,4}\*+[A-Za-z0-9+/=_-]{0,4}$"),
)

#: Values that merely reference another variable or secret store.
_REFERENCE_PATTERNS = (
    re.compile(r"^\$\{[^}]*\}$"),
    re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$"),
    re.compile(r"^\{\{[^}]*\}\}$"),
    re.compile(r"^\$\{\{.*\}\}$"),
    re.compile(r"^\{%[^%]*%\}$"),
    re.compile(r"^%[A-Za-z_][A-Za-z0-9_]*%$"),
    re.compile(r"^env\(.+\)$"),
    re.compile(r"^secretref://", re.IGNORECASE),
    re.compile(r"^vault://", re.IGNORECASE),
    re.compile(r"^awssm://", re.IGNORECASE),
    re.compile(r"^gcpsecret://", re.IGNORECASE),
    re.compile(r"^azurekeyvault://", re.IGNORECASE),
    re.compile(r"^ssm://", re.IGNORECASE),
    re.compile(r"^op://", re.IGNORECASE),
    # CI/CD expression contexts such as ${{ secrets.NAME }} or ${{ vars.NAME }}
    re.compile(r"^\$\{\{\s*(?:secrets|vars|env|inputs|github|needs|steps|strategy|matrix)\b", re.IGNORECASE),
    re.compile(r"^(?:secrets|vars|env|inputs)\.[A-Za-z0-9_.\-]+$", re.IGNORECASE),
)

#: Substrings that mark a value as a placeholder rather than a real secret.
_PLACEHOLDER_SUBSTRINGS = (
    "changeme",
    "change-me",
    "change_me",
    "placeholder",
    "example",
    "dummy",
    "redacted",
    "your-",
    "your_",
    "replace-me",
    "replace_me",
    "replaceme",
    "insert-",
    "insert_",
    "todo",
    "fixme",
    "sample",
)


def tokenize_name(name: str) -> tuple[str, ...]:
    """Split a variable name into uppercase tokens."""
    return tuple(part.upper() for part in _NAME_SPLIT_RE.split(name) if part)


def classify_name(name: str) -> str:
    """Classify a variable name as ``secret``, ``credential`` or ``benign``.

    ``benign`` means the name carries no signal about the value, which is
    what the high entropy rule treats as an *unclassified* variable.
    """
    cleaned = name.strip().strip("\"'")
    if not cleaned:
        return "benign"
    upper = cleaned.upper()
    if upper in _SECRET_NAME_ALLOWLIST:
        return "benign"
    tokens = tokenize_name(cleaned)
    if tokens and tokens[-1] in _SECRET_NAME_ALLOWLIST:
        return "benign"
    if "PUBLIC" in tokens:
        # Public keys and public identifiers are not secrets.
        return "benign"
    if any(token in SECRET_NAME_TOKENS for token in tokens):
        return "secret"
    if any(token in CREDENTIAL_NAME_TOKENS for token in tokens):
        return "credential"
    return "benign"


def is_secret_name(name: str) -> bool:
    """Return ``True`` when the variable name indicates a secret value."""
    return classify_name(name) == "secret"


def is_credential_name(name: str) -> bool:
    """Return ``True`` when the variable name indicates credentials."""
    return classify_name(name) == "credential"


def is_reference_value(value: str) -> bool:
    """Return ``True`` when the value only points at another secret source."""
    text = value.strip()
    if not text:
        return False
    return any(pattern.match(text) for pattern in _REFERENCE_PATTERNS)


def is_placeholder_value(value: str) -> bool:
    """Return ``True`` when the value is an obvious placeholder."""
    text = value.strip().strip("\"'")
    if not text:
        return True
    lowered = text.lower()
    if lowered in _PLACEHOLDER_LITERALS:
        return True
    if any(marker in lowered for marker in _PLACEHOLDER_SUBSTRINGS):
        return True
    return any(pattern.match(text) for pattern in _PLACEHOLDER_PATTERNS)
