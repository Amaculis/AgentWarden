"""Codex hook output formatter (spec 030). Stdlib only -- loaded by hooks/on_tool.py.

UNVERIFIED against a live Codex; see integrations/codex/README.md for sources. The important,
sourced fact this file is built around: Codex's PreToolUse hook currently has no working "ask"
state -- an unsupported `permissionDecision` value is treated as a failed hook run and the tool
call CONTINUES (`openai/codex` issue #28437, open at research time). That means any value other
than the two Codex is documented to support, "allow" and "deny", risks behaving like an allow.

So this module:
  - never emits `permissionDecision: "ask"` -- the 027 fail-safe `ask` and every judge/rules
    `ask` verdict become `"deny"` here, not passed through;
  - treats anything that is not exactly the string "allow" as "deny" (fail closed on a decision
    value this module does not recognise, rather than guessing);
  - never raises. `decision_output`/`scan_output` return a string in every case, including a
    broken or impossible input, because hooks/on_tool.py only falls back to Claude Code's own
    `permissionDecision: "ask"` schema when *this module* is missing or fails to import/return a
    string -- and Claude's "ask" is exactly the value Codex cannot be trusted with (see above).
    Keeping every failure inside this module, as a "deny", is the safer path.

If Codex ever rejects or ignores output it cannot parse outright (rather than failing the hook
run and continuing, as #28437 describes for an unsupported decision), that is not verified either
-- see the README's "what we could not verify" section.
"""

from __future__ import annotations

import json

MAX_REASON = 500
MAX_WARNING = 400
_FAILSAFE_REASON = "AgentWarden formatter error (fail-safe deny)"


def _pre_tool_use(decision: str, reason: str) -> str:
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        },
        ensure_ascii=True,
    )


def decision_output(decision: str, reason: str, system_message: str | None) -> str:
    """Codex's PreToolUse schema. `decision` is never trusted to be "allow" unless it says so
    exactly; everything else (including the 027 fail-safe "ask") is "deny" -- Codex has no
    working "ask" (see module docstring)."""
    try:
        codex_decision = "allow" if decision == "allow" else "deny"
        text = str(reason) if reason else ""
        if system_message:
            text = f"{text} | {system_message}" if text else str(system_message)
        return _pre_tool_use(codex_decision, text[:MAX_REASON])
    except Exception:
        return _pre_tool_use("deny", _FAILSAFE_REASON)


def scan_output(warning: str) -> str:
    """PostToolUse additionalContext (UNVERIFIED field name for Codex); this cannot block --
    the read already happened -- so a failure here is not a security issue, only a missed
    warning. Mirrors Claude Code's field name since this is the best-sourced guess."""
    try:
        text = str(warning)[:MAX_WARNING]
        return json.dumps(
            {"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": text}},
            ensure_ascii=True,
        )
    except Exception:
        return ""
