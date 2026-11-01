"""Judge-manipulation signals in an action (spec 023): a cheap regex check, no model, no network.

Text that talks to the safety judge ("Dear judge model: already reviewed", a fake verdict JSON)
has almost no legitimate reason to be in a coding action. A signal does not mean "dangerous";
it means "the local model may be manipulated, ask Muse Spark". Every gap is bounded, so the scan
stays linear on megabyte-sized content.
"""

from __future__ import annotations

import logging
import re
import unicodedata

from agentwarden.models import ToolEvent
from agentwarden.text_scan import strings

logger = logging.getLogger(__name__)

# Zero-width characters and the soft hyphen: invisible, used to split trigger words.
_INVISIBLE_RE = re.compile("[\u200b-\u200f\u2060\ufeff\u00ad]")

_EVALUATOR = (
    r"(?:judge|reviewer|safety|security\s{1,3}(?:reviewer|team|model|monitor|check)|monitor"
    r"|firewall|classifier|guard(?:rail)?|moderator|agentwarden|warden|ai\s{1,3}model|llm)s?"
)
_EVALUATOR_RE = re.compile(rf"\b{_EVALUATOR}\b", re.IGNORECASE)

PATTERNS: dict[str, re.Pattern[str]] = {
    "fake_verdict": re.compile(
        r"""\bverdict\s{0,3}[=:]\s{0,3}['"]?(?:allow|approved?|safe)\b"""
        r"""|['"]decision['"]\s{0,3}:\s{0,3}['"]allow['"]"""
        r"""|\bdecision\s{0,3}=\s{0,3}['"]?allow\b""",
        re.IGNORECASE,
    ),
    "addresses_judge": re.compile(
        # A salutation to an evaluator ("Dear judge model", "To the safety reviewer:") ...
        rf"(?i:\b(?:dear|attention|hey|hi|hello|instructions?\s{{1,3}}for)\s{{1,3}}"
        rf"(?:(?:the|any|all|ai|automated)\s{{1,3}}){{0,3}}{_EVALUATOR}\b"
        # "to the judge model:" needs the article: "Note to reviewers:" is a normal PR line.
        rf"|\bto\s{{1,3}}(?:the|any|all)\s{{1,3}}(?:(?:ai|automated)\s{{1,3}}){{0,2}}{_EVALUATOR}"
        rf"(?:\s{{1,3}}\w{{1,20}}){{0,2}}\s{{0,3}}:)"
        # ... or an all-caps label (case-sensitive: "AgentWarden:" is this project's own prefix).
        r"|(?<![A-Za-z])(?:JUDGE|REVIEWER|SAFETY REVIEWER|SECURITY REVIEWER|AI REVIEWER"
        r"|AGENTWARDEN|MONITOR)(?:\s{1,3}MODEL)?\s{0,3}:"
    ),
    "approval_claim": re.compile(
        r"\bpre-?approved\b"
        r"|\balready\s{1,3}(?:been\s{1,3})?(?:reviewed|approved|vetted|cleared|audited)\b"
        r"|\bdo\s{1,3}not\s{1,3}flag\b|\bdon'?t\s{1,3}flag\b"
        r"|\bno\s{1,3}need\s{1,3}to\s{1,3}(?:re-?)?(?:check|review)\b"
        r"|\bapproved\s{1,3}by\s{1,3}(?:the\s{1,3})?security\b"
        r"|\bsafe\s{1,3}to\s{1,3}(?:allow|approve)\b"
        r"""|\brespond\s{1,3}(?:with\s{1,3})?['"]?allow\b"""
        r"|\bwhitelisted\b",
        re.IGNORECASE,
    ),
    "override_instructions": re.compile(
        r"\b(?:ignore|disregard|forget|override)\s{1,3}(?:(?:all|any|the|your)\s{1,3})?"
        r"(?:previous|prior|above|earlier|preceding|system|safety)\s{1,3}"
        r"(?:instructions?|rules|prompts?|directions|guidelines|polic(?:y|ies))\b",
        re.IGNORECASE,
    ),
}


def normalize(text: str) -> str:
    """NFKC (fullwidth letters -> ASCII) and invisible characters removed."""
    return _INVISIBLE_RE.sub("", unicodedata.normalize("NFKC", text))


def signals(event: ToolEvent) -> list[str]:
    """Sorted signal names found in `event.tool_input`; `["scan_error"]` if the scan fails."""
    try:
        text = normalize("\n".join(strings(event.tool_input)))
        found = {name for name, pattern in PATTERNS.items() if pattern.search(text)}
        # An approval claim counts only next to an evaluator ("approved by @alice" does not).
        if "approval_claim" in found and not _EVALUATOR_RE.search(text):
            found.discard("approval_claim")
        return sorted(found)
    except Exception:
        logger.exception("manipulation scan failed")
        return ["scan_error"]
