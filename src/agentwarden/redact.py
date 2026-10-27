"""Strip secrets from anything sent to a model (spec 009, invariant 2).

Pattern-based and conservative: a false redaction costs the judge a little context, a missed
one leaks a secret. Every string the judge sends goes through `redact_obj`.
"""

from __future__ import annotations

import re
from typing import Any

# Bounded on both sides: unbounded `[...]*` around the keyword is quadratic on inputs like
# "keykeykey..." (an attacker-controlled file could stall the judge).
_SECRET_NAME = (
    r"[A-Za-z0-9_.-]{0,40}(?:key|token|secret|password|passwd|credential)[A-Za-z0-9_.-]{0,40}"
)

# (kind, pattern, replacement). Order matters: whole blocks and URL credentials first,
# then specific token shapes, then generic NAME=value assignments. Every quantifier that
# follows a word boundary is bounded or anchored on a literal so matching stays linear.
_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)",
            re.DOTALL,
        ),
        "[REDACTED:private_key]",
    ),
    (
        "url_credentials",
        re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]{0,30}://)[^\s/:@]+:[^\s/@]+@"),
        r"\1[REDACTED:url_credentials]@",
    ),
    ("aws_key_id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[REDACTED:aws_key_id]"),
    (
        "github_token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
        "[REDACTED:github_token]",
    ),
    ("api_key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}"), "[REDACTED:api_key]"),
    ("stripe_key", re.compile(r"\b[rsp]k_(?:live|test)_[A-Za-z0-9]{10,}"), "[REDACTED:stripe_key]"),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}"), "[REDACTED:google_key]"),
    ("hf_token", re.compile(r"\bhf_[A-Za-z0-9]{20,}"), "[REDACTED:hf_token]"),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}"), "[REDACTED:npm_token]"),
    ("slack_token", re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}"), "[REDACTED:slack_token]"),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]+"),
        "[REDACTED:jwt]",
    ),
    (
        "bearer",
        re.compile(r"\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
        r"\1[REDACTED:bearer]",
    ),
    ("basic_auth", re.compile(r"\b(Basic\s+)[A-Za-z0-9+/=]{8,}"), r"\1[REDACTED:basic_auth]"),
    # curl -u user:pass, --user user:pass
    (
        "cli_password",
        re.compile(r"((?:^|\s)(?:-u|--user)\s+[^\s:]+:)\S+"),
        r"\1[REDACTED:cli_password]",
    ),
    # --password secret, --password=secret
    ("cli_password", re.compile(r"(--password[= ])\S+"), r"\1[REDACTED:cli_password]"),
    # mysql -pSecret, mysqldump -u root -pSecret
    (
        "cli_password",
        re.compile(r"(\bmysql\w{0,10}\b[^\n]{0,200}?\s-p)(?!\s)\S+"),
        r"\1[REDACTED:cli_password]",
    ),
    (
        "json_assignment",
        # "name": "value"  (JSON; escaped quotes inside the value handled)
        re.compile(rf"(\"{_SECRET_NAME}\"\s*:\s*\")(?:[^\"\\]|\\.)+(\")", re.IGNORECASE),
        r"\1[REDACTED:assignment]\2",
    ),
    (
        "assignment",
        # NAME=value, NAME: value, NAME = 'value with spaces'  (env files, YAML, shell)
        re.compile(
            rf"(\b{_SECRET_NAME}\s*[:=]\s*)"
            r"(?:([\"'])(?!\[REDACTED)[^\"'\n]+\2|(?!\[REDACTED)[^\s'\"]{4,})",
            re.IGNORECASE,
        ),
        "",
    ),
]

# Values that are code, not secrets: `key = compute_key(x)`, `token: ${{ secrets.X }}`.
_CODE_VALUE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*[(\[]|^\$\{|^\$[A-Za-z_]")

# Dict keys whose scalar value is a secret whatever it looks like (MCP tool inputs, JSON).
_SECRET_KEY = re.compile(
    r"key|token|secret|password|passwd|credential|authorization|auth|cookie", re.IGNORECASE
)


def redact(text: str) -> str:
    for kind, pattern, replacement in _PATTERNS:
        if kind == "assignment":
            text = pattern.sub(_assignment, text)
        else:
            text = pattern.sub(replacement, text)
    return text


def _assignment(match: re.Match[str]) -> str:
    prefix = match.group(1)
    value = match.group(0)[len(prefix) :]
    if _CODE_VALUE.match(value.strip("'\"")):
        return match.group(0)
    quote = match.group(2) or ""
    return f"{prefix}{quote}[REDACTED:assignment]{quote}"


def redact_obj(obj: Any) -> Any:
    """Recursively redact every string in dicts/lists; other values unchanged."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            secret_key = isinstance(key, str) and _SECRET_KEY.search(key) is not None
            scalar = isinstance(value, str | int | float) and not isinstance(value, bool)
            if secret_key and scalar and value != "":
                out[redact(key)] = "[REDACTED:assignment]"
            else:
                out[redact(key) if isinstance(key, str) else key] = redact_obj(value)
        return out
    if isinstance(obj, list | tuple):
        return [redact_obj(v) for v in obj]
    return obj
