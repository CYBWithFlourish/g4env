"""Vendor specific credential signatures.

These patterns are shared between the deterministic rules (which use them to
*detect* credentials) and the redaction layer (which uses them to *mask*
credentials). Every pattern captures the credential itself in group 1.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["VENDOR_SIGNATURES", "VendorSignature"]


@dataclass(frozen=True)
class VendorSignature:
    """A named pattern that matches a well known credential format."""

    name: str
    regex: re.Pattern[str]

    @property
    def label(self) -> str:
        """Human readable name of the credential family."""
        return self.name


def _sig(name: str, pattern: str, flags: int = 0) -> VendorSignature:
    return VendorSignature(name=name, regex=re.compile(pattern, flags))


#: Ordered list of known credential formats.
VENDOR_SIGNATURES: tuple[VendorSignature, ...] = (
    _sig("AWS access key id", r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
    _sig("Google API key", r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
    _sig("Google OAuth client secret", r"\b(GOCSPX-[A-Za-z0-9_\-]{28})\b"),
    _sig("GitHub token", r"\b((?:gh[pousr]_[A-Za-z0-9]{36,255})|(?:github_pat_[A-Za-z0-9_]{50,255}))\b"),
    _sig("GitLab token", r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"),
    _sig("Slack token", r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b"),
    _sig("Slack webhook", r"\b(https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]{20,})\b"),
    _sig("Stripe key", r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b"),
    _sig("Stripe webhook secret", r"\b(whsec_[A-Za-z0-9]{24,})\b"),
    _sig("OpenAI key", r"\b(sk-(?:proj|svcacct)-[A-Za-z0-9_\-]{20,})\b"),
    _sig("Anthropic key", r"\b(sk-ant-[A-Za-z0-9_\-]{24,})\b"),
    _sig("OpenRouter key", r"\b(sk-or-v1-[a-f0-9]{64})\b"),
    _sig("SendGrid key", r"\b(SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})\b"),
    _sig("Twilio key", r"\b(SK[0-9a-fA-F]{32})\b"),
    _sig("npm token", r"\b(npm_[A-Za-z0-9]{36})\b"),
    _sig("PyPI token", r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b"),
    _sig("Mailgun key", r"\b(key-[0-9a-f]{32})\b"),
    _sig("Square token", r"\b(sq0(?:idp|csp|atp)-[A-Za-z0-9_\-]{22,43})\b"),
    _sig("Shopify token", r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b"),
    _sig("DigitalOcean token", r"\b(dop_v1_[a-f0-9]{64})\b"),
    _sig("HuggingFace token", r"\b(hf_[A-Za-z0-9]{34,})\b"),
    _sig("Linear API key", r"\b(lin_api_[A-Za-z0-9]{40})\b"),
    _sig("Notion token", r"\b((?:ntn_[A-Za-z0-9]{46})|(?:secret_[A-Za-z0-9]{43}))\b"),
    _sig("Cloudflare API token", r"\b(v1\.0-[a-f0-9]{40}-[A-Za-z0-9_\-]{20,})\b"),
    _sig("Grafana service account token", r"\b(glsa_[A-Za-z0-9]{32}_[A-Za-z0-9]{8})\b"),
    _sig("New Relic key", r"\b(NRJS-[a-f0-9]{19})\b"),
    _sig("Sentry DSN", r"\b(https://[a-f0-9]{32}@[A-Za-z0-9.\-]+/[0-9]+)\b"),
    _sig("Age secret key", r"\b(AGE-SECRET-KEY-1[0-9A-Z]{58})\b"),
    _sig("PlanetScale password", r"\b(pscale_pw_[A-Za-z0-9_\-]{43})\b"),
    _sig("Discord bot token", r"\b([MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})\b"),
    _sig("Telegram bot token", r"\b(\d{8,10}:[A-Za-z0-9_\-]{35})\b"),
    _sig("Facebook access token", r"\b(EAACEdEose0cBA[0-9A-Za-z]{10,})\b"),
    _sig("Firebase database URL", r"\b(https://[a-z0-9\-]+\.firebaseio\.com)\b"),
    _sig("Azure storage key", r"\b(AccountKey=[A-Za-z0-9+/=]{60,})"),
    _sig("Azure AD client secret", r"\b(~[A-Za-z0-9_\-]{36}~)\b"),
    _sig("JSON Web Token", r"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b"),
    _sig("Basic auth credential", r"\b([A-Za-z0-9+/]{16,}={0,2})(?=\s*[@:]?\s*(?:basic|Authorization))", re.IGNORECASE),
)
