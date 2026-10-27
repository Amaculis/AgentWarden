"""Pydantic models for hook payloads and verdicts (spec 002)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

DecisionValue = Literal["allow", "deny", "ask"]
VerdictSource = Literal["rules", "policy", "judge", "failsafe", "default"]


class ToolEvent(BaseModel):
    """PreToolUse hook payload."""

    model_config = ConfigDict(extra="ignore")

    session_id: str
    prompt_id: str | None = None
    cwd: str
    permission_mode: str | None = None
    hook_event_name: Literal["PreToolUse"]
    tool_name: str
    tool_input: dict[str, Any]
    tool_use_id: str | None = None


class PromptEvent(BaseModel):
    """UserPromptSubmit hook payload."""

    model_config = ConfigDict(extra="ignore")

    session_id: str
    prompt_id: str | None = None
    cwd: str
    permission_mode: str | None = None
    hook_event_name: Literal["UserPromptSubmit"]
    prompt: str


class ReadEvent(BaseModel):
    """PostToolUse hook payload for Read/WebFetch (spec 013). `tool_response` shape: VERIFY."""

    model_config = ConfigDict(extra="ignore")

    session_id: str
    cwd: str
    hook_event_name: Literal["PostToolUse"]
    tool_name: str
    tool_input: dict[str, Any] = {}
    tool_response: Any = None


class Verdict(BaseModel):
    """A decision returned to the hook."""

    decision: DecisionValue
    reason: str
    risk: float | None = Field(default=None, ge=0.0, le=1.0)
    source: VerdictSource
    system_message: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    safer_alternative: str | None = None
    decided_by: Literal["rules", "local", "spark"] | None = None
    escalated: bool = False
    local_decision: DecisionValue | None = None


def failsafe(reason: str) -> Verdict:
    """The fail-closed verdict: always `ask`, never `allow`."""
    return Verdict(decision="ask", reason=reason, risk=None, source="failsafe")
