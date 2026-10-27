"""Decision pipeline (spec 002: no rules or judge yet — always `ask`)."""

from __future__ import annotations

from agentwarden.models import ToolEvent, Verdict


def decide(event: ToolEvent) -> Verdict:
    """Decide what to do with a tool event.

    Spec 002 wires no policy yet: rules and the judge plug in later.
    Always returns `ask` with source `default`.
    """
    return Verdict(
        decision="ask",
        reason="No policy configured yet.",
        risk=None,
        source="default",
    )
