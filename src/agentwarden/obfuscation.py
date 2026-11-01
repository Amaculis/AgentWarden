"""Obfuscation signals in an action (spec 022): a cheap regex check, no model, no network.

A signal does not mean "dangerous"; it means "the local model may be fooled, ask Muse Spark".
High precision on purpose: a decode call alone, or an encoded blob alone, is not a signal.
Every gap in a pattern is bounded, so the scan stays linear on megabyte-sized content.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from typing import Any

from agentwarden.models import ToolEvent

logger = logging.getLogger(__name__)

SKIPPED_KEYS = frozenset({"old_string"})  # code being removed

_DECODE = re.compile(
    r"""\bfrom\s*\([^()]*,\s*['"](?:hex|base64)['"]\s*\)"""  # Buffer.from(x, 'hex')
    r"|\batob\s*\("
    r"|\bbase64\s+(?:-[a-zA-Z]*[dD][a-zA-Z]*|--decode)\b"
    r"|b64decode\s*\("
    r"|bytes\.fromhex\s*\("
    r"|unhexlify\s*\("
    r"|codecs\.decode\s*\("
    r"|\bxxd\s+(?:-\w+\s+)*-r\b"
    r"|FromBase64String\s*\("
    r"|\bopenssl\b[^\n|;]{0,200}\s-d\b"
)
_SINK = re.compile(
    r"\beval\s*\("
    r"|(?<![.\w])exec\s*\("
    r"|\bFunction\s*\("
    r"|\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|node|perl)\b"
    r"|\b(?:sh|bash|zsh)\s+-c\b"
    r"|\biex\b"
    r"|Invoke-Expression"
    r"|child_process"
    r"|os\.system\s*\("
    r"|\bsubprocess\b"
    r"|(?<![.\w])compile\s*\(",
    re.IGNORECASE,
)
_BLOB = re.compile(r"[0-9a-fA-F]{32,}|[A-Za-z0-9+/]{40,}={0,2}")

# Signal name -> regexes that must all match the same string.
PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "decode_exec": (_DECODE, _SINK),
    "decode_blob": (_DECODE, _BLOB),
    "ps_encoded": (
        re.compile(
            r"\b(?:powershell|pwsh)(?:\.exe)?\b.{0,200}?\s-(?:e|ec|enc|encodedcommand)\s+['\"]?"
            r"[A-Za-z0-9+/]{20,}",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    "char_codes": (
        re.compile(
            r"String\.fromCharCode\s*\("
            r"|(?:\bchr\(\s*\d+\s*\)\W{0,3}){4}"
            r"|(?:\\x[0-9a-fA-F]{2}){8}"
        ),
    ),
    "dynamic_import": (re.compile(r"__import__\s*\(|getattr\(\s*__builtins__"),),
    "eval_indirection": (re.compile(r"""\beval\s+["']?\$|\$\{!\w+"""),),
}


def signals(event: ToolEvent) -> list[str]:
    """Sorted signal names found in `event.tool_input`; `["scan_error"]` if the scan fails."""
    try:
        # One text for the whole action: a decode call in one edit and its sink in another
        # are still one payload.
        text = "\n".join(_strings(event.tool_input))
        return sorted(
            name for name, patterns in PATTERNS.items() if all(p.search(text) for p in patterns)
        )
    except Exception:
        logger.exception("obfuscation scan failed")
        return ["scan_error"]


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if key not in SKIPPED_KEYS:
                yield from _strings(item)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from _strings(item)
