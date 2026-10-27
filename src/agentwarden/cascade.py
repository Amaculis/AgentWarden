"""Cascade judge (spec 010): local Meta model first, Muse Spark for the hard cases.

Never raises. Local trouble escalates; Spark trouble, a missing provider or an exhausted time
budget ends in the fail-safe `ask`.
"""

from __future__ import annotations

import logging
import os
import time

from agentwarden.judge import SessionContext, env_float, judge, judge_timeout
from agentwarden.models import ToolEvent, Verdict, failsafe
from agentwarden.providers.base import Provider

logger = logging.getLogger(__name__)

MIN_SPARK_BUDGET_S = 1.0


def decision_budget() -> float:
    return env_float("WARDEN_DECISION_BUDGET", 7.0)


def should_escalate(local: Verdict) -> bool:
    if local.source != "judge":  # fail-safe: provider error, timeout, unparsable
        return True
    if local.confidence is None or local.confidence < env_float("WARDEN_ESCALATE_CONFIDENCE", 0.7):
        return True
    low = env_float("WARDEN_ESCALATE_RISK_LOW", 30) / 100.0
    high = env_float("WARDEN_ESCALATE_RISK_HIGH", 70) / 100.0
    if local.risk is not None and low <= local.risk <= high:
        return True
    confirm_deny = os.environ.get("WARDEN_CONFIRM_DENY", "").lower() in ("1", "true", "yes")
    return local.decision == "deny" and confirm_deny


def decide_with_cascade(
    event: ToolEvent,
    context: SessionContext | None,
    local: Provider | None,
    spark: Provider | None,
    *,
    budget_s: float | None = None,
) -> Verdict:
    try:
        return _cascade(event, context, local, spark, budget_s or decision_budget())
    except Exception:
        logger.exception("cascade failed")
        return failsafe("AgentWarden: judge error")


def _cascade(
    event: ToolEvent,
    context: SessionContext | None,
    local: Provider | None,
    spark: Provider | None,
    budget_s: float,
) -> Verdict:
    start = time.monotonic()

    def remaining() -> float:
        return budget_s - (time.monotonic() - start)

    local_verdict: Verdict | None = None
    if local is not None:
        local_timeout = min(env_float("WARDEN_LOCAL_TIMEOUT", 3.0), remaining())
        local_verdict = judge(event, context, local, timeout=local_timeout)
        if not should_escalate(local_verdict):
            return local_verdict.model_copy(update={"decided_by": "local"})

    local_decision = (
        local_verdict.decision if local_verdict and local_verdict.source == "judge" else None
    )
    escalation = {"escalated": local is not None, "local_decision": local_decision}

    if os.environ.get("WARDEN_CASCADE", "").lower() == "local_only":
        return failsafe("AgentWarden: local judge unsure (offline mode)").model_copy(
            update=escalation
        )
    if spark is None:
        return failsafe("AgentWarden: judge unavailable").model_copy(update=escalation)
    left = remaining()
    if left < MIN_SPARK_BUDGET_S:
        return failsafe("AgentWarden: judge time budget exceeded").model_copy(update=escalation)

    spark_verdict = judge(event, context, spark, timeout=min(judge_timeout(), left))
    if spark_verdict.source != "judge":
        return spark_verdict.model_copy(update=escalation)
    if remaining() < 0:
        return failsafe("AgentWarden: judge time budget exceeded").model_copy(update=escalation)
    return spark_verdict.model_copy(update={"decided_by": "spark", **escalation})
