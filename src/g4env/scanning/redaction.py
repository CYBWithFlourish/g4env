"""Redaction of sensitive values.

Everything g4env shows to a human, writes to a log, or sends to a model
provider passes through this module first. The goal is that a secret never
reaches a terminal, a CI log or a remote API while still leaving enough
context to act on the finding.
"""

from __future__ import annotations

import re

from g4env.patterns import VENDOR_SIGNATURES
from g4env.variables import is_reference_value, is_secret_name

__all__ = [
    "MASK",
    "redact_line",
    "redact_text",
    "redact_value",
]

#: The replacement written in place of a secret.
MASK = "****"

#: Prefixes that identify the vendor of a credential and are safe to keep.
_VENDOR_PREFIXES = (
    "whsec_",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "rk_test_",
    "pk_live_",
    "pk_test_",
    "sk-proj-",
    "sk-or-v1-",
    "sk-ant-",
    "sk-",
    "github_pat_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "glpat-",
    "glptt-",
    "glrt-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "xoxs-",
    "npm_",
    "pypi-",
    "hf_",
    "dop_v1_",
    "lin_api_",
    "shpat_",
    "shpca_",
    "shppa_",
    "shpss_",
    "pscale_pw_",
    "sq0idp-",
    "sq0atp-",
    "sq0csp-",
    "nrsa-",
    "NRJS-",
    "glsa_",
    "ntn_",
    "secret_",
    "AGE-SECRET-KEY-1",
    "AKIA",
    "ASIA",
    "ABIA",
    "ACCA",
    "AIza",
    "GOCSPX-",
    "ya29.",
    "1//",
    "v1.0-",
)

#: ``AC``/``SK`` style prefixes (Twilio account identifiers and similar).
_SHORT_PREFIX_RE = re.compile(r"^([A-Z]{2,6})(?=[A-Za-z0-9+/=]{12,}$)")

#: Generic ``PREFIX_`` style secrets.
_GENERIC_PREFIX_RE = re.compile(r"^([A-Za-z][A-Za-z0-9]{1,12}[_-])")

#: Credentials embedded in a URL.
_URL_CREDENTIALS_RE = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*://)(?P<user>[^\s:/@]+):(?P<password>[^\s@/]+)@"
)

#: Assignment of a value to a name.
_ASSIGNMENT_RE = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_.\-]{0,80})\s*(?P<sep>[:=])\s*"
    r"(?P<value>\"[^\"\n]*\"|'[^'\n]*'|[^\s,;#]+)"
)

#: PEM encoded private key material.
_PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")

#: Long opaque blobs (base64, hex, certificates).
_OPAQUE_RUN_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{40,}(?![A-Za-z0-9+/=_-])")

#: Quoted or bare value that is definitely a credential in prose.
_PROSE_CREDENTIAL_RE = re.compile(
    r"(?i)\b(?:password|passwd|secret|token|api[\s_-]?key)\b\s*[:=]\s*"
    r"(?P<value>\"[^\"\n]*\"|'[^'\n]*'|[^\s,;#]+)"
)

#: Authorization and API key headers carrying a literal credential.
_AUTH_HEADER_RE = re.compile(
    r"(?i)(\b(?:authorization|x-api-key|x-auth-token)[\"']?\s*[:=]\s*[\"']?"
    r"(?:bearer|basic|token)?\s*)(?P<value>[A-Za-z0-9._\-+/=]{8,})"
)


def redact_value(value: str) -> str:
    """Return ``value`` with the secret part masked.

    Vendor prefixes such as ``sk_live_`` are preserved because they make the
    finding actionable without disclosing the credential.
    """
    text = value.strip()
    if not text:
        return value
    if is_reference_value(text):
        return value
    for prefix in _VENDOR_PREFIXES:
        if text.startswith(prefix):
            return f"{prefix}{MASK}"
    match = _SHORT_PREFIX_RE.match(text)
    if match:
        return f"{match.group(1)}{MASK}"
    match = _GENERIC_PREFIX_RE.match(text)
    if match:
        return f"{match.group(1)}{MASK}"
    return MASK


def _mask_assignment(match: re.Match[str]) -> str:
    name = match.group("name")
    raw_value = match.group("value")
    if not is_secret_name(name):
        return match.group(0)
    quote = ""
    body = raw_value
    if len(body) >= 2 and body[0] == body[-1] and body[0] in "\"'":
        quote = body[0]
        body = body[1:-1]
    if not body or is_reference_value(body):
        return match.group(0)
    masked = redact_value(body)
    return f"{name}{match.group('sep')}{quote}{masked}{quote}"


def redact_text(text: str) -> str:
    """Mask every credential that can be identified inside ``text``."""
    if not text:
        return text

    result = _URL_CREDENTIALS_RE.sub(
        lambda match: f"{match.group('scheme')}{match.group('user')}:{MASK}@", text
    )
    result = _AUTH_HEADER_RE.sub(
        lambda match: f"{match.group(1)}{MASK}", result
    )
    result = _ASSIGNMENT_RE.sub(_mask_assignment, result)
    result = _PROSE_CREDENTIAL_RE.sub(
        lambda match: f"{match.group(0).split(match.group('value'))[0]}{MASK}", result
    )
    for signature in VENDOR_SIGNATURES:
        result = signature.regex.sub(
            lambda match: redact_value(match.group(1)), result
        )
    result = _PEM_RE.sub("-----BEGIN PRIVATE KEY-----", result)
    return _OPAQUE_RUN_RE.sub(MASK, result)


def redact_line(line: str) -> str:
    """Redact a single line of source text."""
    return redact_text(line)
