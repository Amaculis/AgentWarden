"""Decision pipeline: rules (003) -> judge (009) or cascade (010) -> thresholds, fail-safe."""

from __future__ import annotations

import os
import re

from agentwarden.cascade import decide_with_cascade
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


MAX_ALTERNATIVE = 200
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# The alternative is model text shaped by attacker-controlled content and is shown to the
# agent in AgentWarden's voice: anything that looks like a command or a URL is dropped.
_COMMAND_LIKE = re.compile(
    r"://|[|;>`]|&&|\$\(|\b(?:curl|wget|base64|eval|nc|ncat|powershell|iex)\b|\bsh\s+-c\b",
    re.IGNORECASE,
)


def usable_alternative(text: str | None) -> str | None:
    if not isinstance(text, str):
        return None
    if "\n" in text.strip() or "\r" in text.strip():
        return None
    line = " ".join(_CONTROL.sub(" ", text).split())
    if not line or len(line) > MAX_ALTERNATIVE or _COMMAND_LIKE.search(line):
        return None
    return line


def with_alternative(verdict: Verdict) -> Verdict:
    """On deny, append a vetted safer alternative to the reason the agent sees."""
    alternative = usable_alternative(verdict.safer_alternative)
    if verdict.decision != "deny" or alternative is None:
        return verdict.model_copy(update={"safer_alternative": alternative})
    reason = f"{verdict.reason} Safer alternative: {alternative}"
    return verdict.model_copy(update={"reason": reason, "safer_alternative": alternative})


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


CascadeProviders = tuple[Provider | None, Provider | None]  # (local, spark)


def _cascade_from_env() -> CascadeProviders:
    from agentwarden.providers import local, meta_api

    return local.from_env(), meta_api.from_env()


def _cached(
    provider: Provider | None, cascade: CascadeProviders | None, name: str | None
) -> tuple[Provider | None, CascadeProviders | None]:
    from agentwarden.providers.cache import CachedProvider

    def wrap(p: Provider | None, role: str) -> Provider | None:
        return None if p is None else CachedProvider(p, namespace=role)

    if cascade is not None:
        return provider, (wrap(cascade[0], "local"), wrap(cascade[1], "meta_api"))
    return wrap(provider, name or ""), cascade


def _model_verdict(
    event: ToolEvent,
    context: SessionContext | None,
    provider: Provider | None,
    cascade: CascadeProviders | None,
) -> Verdict | None:
    """Verdict for an action the rules did not settle; `None` when no judge is configured."""
    try:
        if cascade is None and provider is None:
            name = os.environ.get("WARDEN_JUDGE")
            if (name or "").strip().lower() == "cascade":
                cascade = _cascade_from_env()
            else:
                provider = get_provider(name)
            if os.environ.get("WARDEN_CACHE", "").lower() == "on":
                provider, cascade = _cached(provider, cascade, name)
    except Exception:
        return failsafe("AgentWarden: judge provider misconfigured")
    if cascade is not None:
        return apply_thresholds(decide_with_cascade(event, context, *cascade))
    if provider is not None:
        return apply_thresholds(judge(event, context, provider))
    return None


def decide(
    event: ToolEvent,
    context: SessionContext | None = None,
    provider: Provider | None = None,
    cascade: CascadeProviders | None = None,
) -> Verdict:
    """Decide what to do with a tool event.

    Rules first; an unsettled action goes to the cascade (`WARDEN_JUDGE=cascade` or
    `cascade=`) or a single judge provider (`WARDEN_JUDGE=<name>` or `provider=`),
    otherwise it is `ask`.
    """
    verdict = evaluate(event)
    if verdict is not None:
        verdict = verdict.model_copy(update={"decided_by": "rules"})
    else:
        verdict = _model_verdict(event, context, provider, cascade)
    if verdict is None:
        verdict = Verdict(
            decision="ask",
            reason="No rule matched; judge not configured yet.",
            risk=None,
            source="default",
        )
    return with_system_message(with_alternative(verdict))
