"""Decision pipeline (spec 003: rules wired in; judge not configured yet)."""

from __future__ import annotations

import os

from agentwarden.models import ToolEvent, Verdict
from agentwarden.rules import evaluate

_SOURCE_LABELS = {
    "rules": "rules",
    "policy": "policy",
    "judge": "local model",
    "failsafe": "fail-safe",
    "default": "default",
}


def _with_system_message(verdict: Verdict) -> Verdict:
    """Attach a `systemMessage`-style note for deny/ask verdicts, unless disabled."""
    if verdict.decision == "allow":
        return verdict
    if os.environ.get("WARDEN_NOTIFY", "").lower() == "off":
        return verdict
    label = _SOURCE_LABELS.get(verdict.source, verdict.source)
    verb = "blocked" if verdict.decision == "deny" else "needs confirmation for"
    return verdict.model_copy(
        update={"system_message": f"🛡 AgentWarden: {verb} this action ({label})"}
    )


def decide(event: ToolEvent) -> Verdict:
    """Decide what to do with a tool event.

    Runs the rules stage first. If no rule matches, falls back to `ask`.
    """
    verdict = evaluate(event)
    if verdict is None:
        verdict = Verdict(
            decision="ask",
            reason="No rule matched; judge not configured yet.",
            risk=None,
            source="default",
        )
    return _with_system_message(verdict)
