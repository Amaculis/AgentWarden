"""Decision pipeline (spec 003: rules wired in; judge not configured yet)."""

from __future__ import annotations

from agentwarden.models import ToolEvent, Verdict
from agentwarden.rules import evaluate


def decide(event: ToolEvent) -> Verdict:
    """Decide what to do with a tool event.

    Runs the rules stage first. If no rule matches, falls back to `ask`.
    """
    verdict = evaluate(event)
    if verdict is not None:
        return verdict
    return Verdict(
        decision="ask",
        reason="No rule matched; judge not configured yet.",
        risk=None,
        source="default",
    )
