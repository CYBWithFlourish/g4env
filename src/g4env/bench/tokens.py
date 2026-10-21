"""Fake credentials used by the evaluation set and the test-suite.

The values in this module are **not** real credentials. They are assembled
from fragments on purpose: several providers' secret scanners block a push
when a file contains a well formed looking token, even when the token is a
documentation example. Splitting the values keeps the repository pushable
while the assembled result still exercises exactly the same detection and
redaction paths as a real credential would.

The evaluation set refers to these values with ``{{NAME}}`` placeholders;
:func:`substitute` expands them when the dataset is loaded.
"""

from __future__ import annotations

import re

__all__ = [
    "ANTHROPIC_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AZURE_ACCOUNT_KEY",
    "BEARER_TOKEN",
    "DO_TOKEN",
    "FAKE_TOKENS",
    "GENERIC_PASSWORD",
    "GITHUB_TOKEN",
    "GOOGLE_API_KEY",
    "HF_TOKEN",
    "JWT_SECRET",
    "NPM_TOKEN",
    "OPENAI_API_KEY",
    "SENDGRID_API_KEY",
    "SLACK_TOKEN",
    "STRIPE_KEY",
    "substitute",
]

AWS_ACCESS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/" + "K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
GOOGLE_API_KEY = "AIza" + "SyD-1234567890abcdefghijklmnopqrstuvw"
OPENAI_API_KEY = "sk-proj-" + "abc123DEF456ghi789JKL012mno345PQR678"
ANTHROPIC_API_KEY = "sk-ant-api03-" + "abc123DEF456ghi789JKL012mno345"
SENDGRID_API_KEY = "SG." + "abc123DEF456ghi789JKL." + "abc123DEF456ghi789JKL012"
STRIPE_KEY = "sk_live_" + "51H8xYz2eZvKYlo2C" + "abcdefghijklmno"
SLACK_TOKEN = (
    "xoxb-" + "123456789012-" + "1234567890123-" + "AbCdEfGhIjKlMnOpQrStUvWx"
)
JWT_SECRET = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    + "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    + "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)
NPM_TOKEN = "npm_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
HF_TOKEN = "hf_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
DO_TOKEN = "dop_v1_" + "0123456789abcdef" * 4
AZURE_ACCOUNT_KEY = (
    "abcdefghijklmnopqrstuvwxyz0123456789"
    + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    + "abcdefghij=="
)
GENERIC_PASSWORD = "SuperSecret" + "123"
BEARER_TOKEN = "Bearer " + "abc123DEF456ghi789JKL012"

#: Fake credentials keyed by the placeholder name used in the dataset.
FAKE_TOKENS: dict[str, str] = {
    "AWS_ACCESS_KEY_ID": AWS_ACCESS_KEY_ID,
    "AWS_SECRET_ACCESS_KEY": AWS_SECRET_ACCESS_KEY,
    "GITHUB_TOKEN": GITHUB_TOKEN,
    "GOOGLE_API_KEY": GOOGLE_API_KEY,
    "OPENAI_API_KEY": OPENAI_API_KEY,
    "ANTHROPIC_API_KEY": ANTHROPIC_API_KEY,
    "SENDGRID_API_KEY": SENDGRID_API_KEY,
    "STRIPE_KEY": STRIPE_KEY,
    "SLACK_TOKEN": SLACK_TOKEN,
    "JWT_SECRET": JWT_SECRET,
    "NPM_TOKEN": NPM_TOKEN,
    "HF_TOKEN": HF_TOKEN,
    "DO_TOKEN": DO_TOKEN,
    "AZURE_ACCOUNT_KEY": AZURE_ACCOUNT_KEY,
    "GENERIC_PASSWORD": GENERIC_PASSWORD,
    "BEARER_TOKEN": BEARER_TOKEN,
}

#: Placeholder syntax used in the evaluation set.
_PLACEHOLDER_RE = re.compile(r"\{\{([A-Z0-9_]+)\}\}")


def substitute(text: str) -> str:
    """Expand every ``{{NAME}}`` placeholder with its fake credential."""
    if "{{" not in text:
        return text

    def _replace(match: re.Match[str]) -> str:
        name = match.group(1)
        try:
            return FAKE_TOKENS[name]
        except KeyError as exc:  # pragma: no cover - authoring error
            raise KeyError(f"unknown fake token {name!r}") from exc

    return _PLACEHOLDER_RE.sub(_replace, text)
