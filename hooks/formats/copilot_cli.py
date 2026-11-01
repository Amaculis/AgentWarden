"""Copilot CLI hook output (spec 029). Stdlib only -- loaded by hooks/on_tool.py and on_read.py.

docs.github.com hooks-configuration reference: a command hook prints `permissionDecision`
(`allow` | `deny` | `ask`) and `permissionDecisionReason` at the top level of its stdout JSON,
and `additionalContext` at the top level for postToolUse. The Claude Code schema nests these in
`hookSpecificOutput`, which the CLI does not read -- our deny would be ignored.

The same `.github/hooks/*.json` is read by VS Code, which reads the Claude-style
`hookSpecificOutput`; both forms are printed so one config works for both surfaces. Anything
but the three known decisions becomes `deny`. UNVERIFIED against a live Copilot.
"""

from __future__ import annotations

import json

_DECISIONS = ("allow", "deny", "ask")


def decision_output(decision: str, reason: str, system_message: str | None) -> str:
    decision = decision if decision in _DECISIONS else "deny"
    out: dict = {
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        },
    }
    if system_message:
        out["systemMessage"] = system_message
    return json.dumps(out, ensure_ascii=True)


def scan_output(warning: str) -> str:
    out = {
        "additionalContext": warning,
        "hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": warning},
    }
    return json.dumps(out, ensure_ascii=True)
