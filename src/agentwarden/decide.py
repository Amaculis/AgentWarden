"""Decision pipeline: rules (spec 003) -> model judge (spec 009) -> thresholds, fail-safe."""

from __future__ import annotations

import os

from agentwarden.judge import SessionContext, env_float, judge
from agentwarden.models import ToolEvent, Verdict, failsafe
from agentwarden.providers import Provider, get_provider
from agentwarden.rules import evaluate

_SOURCE_LABELS = {
    "rules": "rules",
    "policy": "policy",
    "judge": "judge",
    "failsafe": "fail-safe",
    "default": "default",
}


def with_system_message(verdict: Verdict) -> Verdict:
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


def apply_thresholds(verdict: Verdict) -> Verdict:
    """Downgrade a model `allow` to `ask` when risk is high or confidence is low."""
    if verdict.source != "judge" or verdict.decision != "allow":
        return verdict
    max_risk = env_float("WARDEN_ALLOW_MAX_RISK", 30) / 100.0
    min_confidence = env_float("WARDEN_MIN_CONFIDENCE", 0.6)
    if verdict.risk is None or verdict.risk > max_risk:
        return verdict.model_copy(update={"decision": "ask"})
    if verdict.confidence is not None and verdict.confidence < min_confidence:
        return verdict.model_copy(update={"decision": "ask"})
    return verdict


def decide(
    event: ToolEvent,
    context: SessionContext | None = None,
    provider: Provider | None = None,
) -> Verdict:
    """Decide what to do with a tool event.

    Rules first; an unsettled action goes to the judge when one is configured
    (`WARDEN_JUDGE`), otherwise it is `ask`.
    """
    verdict = evaluate(event)
    if verdict is None:
        try:
            if provider is None:
                provider = get_provider(os.environ.get("WARDEN_JUDGE"))
        except Exception:
            provider = None
            verdict = failsafe("AgentWarden: judge provider misconfigured")
        if verdict is None and provider is not None:
            verdict = apply_thresholds(judge(event, context, provider))
    if verdict is None:
        verdict = Verdict(
            decision="ask",
            reason="No rule matched; judge not configured yet.",
            risk=None,
            source="default",
        )
    return with_system_message(verdict)
