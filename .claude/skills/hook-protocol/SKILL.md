---
name: hook-protocol
description: Exact Claude Code hook input/output formats for PreToolUse and UserPromptSubmit, exit codes, and the fail-closed rules AgentWarden must follow. Use whenever writing or changing anything in hooks/ or the daemon endpoints the hooks call.
---

# Claude Code hook protocol (for AgentWarden)

Source: Claude Code hooks reference (code.claude.com/docs/en/hooks), checked 2026-10-26. Real payloads below captured 2026-10-26 by enabling the hooks in this repo's `.claude/settings.local.json` (gitignored) and running Bash/Read/Write/Edit in a live session; raw lines are in `.agentwarden/events.jsonl` (gitignored, not committed).

## Input (stdin JSON for command hooks, POST body for HTTP hooks)

Common fields on every event: `session_id`, `transcript_path`, `cwd`, `scratchpad_dir`, `prompt_id`, `permission_mode`, `effort`, `hook_event_name`. (`scratchpad_dir` and `effort` were not in the public reference doc — this build's Claude Code sends them too; treat unknown extra fields as pass-through, don't rely on them.)

PreToolUse adds `tool_name`, `tool_input`, `tool_use_id`. Real example (Bash):

```json
{
  "session_id": "3d97e6f2-2818-4b71-955c-ff6310aeb5be",
  "transcript_path": "C:\\Users\\Artem\\.claude\\projects\\d--GITHUB-AgentWarden\\3d97e6f2-2818-4b71-955c-ff6310aeb5be.jsonl",
  "cwd": "D:\\GITHUB\\AgentWarden",
  "scratchpad_dir": "C:\\Users\\Artem\\AppData\\Local\\Temp\\claude\\d--GITHUB-AgentWarden\\3d97e6f2-2818-4b71-955c-ff6310aeb5be\\scratchpad",
  "prompt_id": "5daaca00-4922-43ca-80ec-def0e591efc6",
  "permission_mode": "auto",
  "effort": {"level": "medium"},
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {"command": "echo test-manual-capture", "description": "Run a sample Bash command to trigger PreToolUse hook"},
  "tool_use_id": "toolu_01FyVCvSNS9ZJkXzSUHKwhUh"
}
```

`tool_input` shape depends on the tool — real shapes captured:

- Bash → `{"command": "...", "description": "..."}`
- Read → `{"file_path": "...", "limit": 5}` (`limit`/`offset` only present when passed)
- Write → `{"file_path": "...", "content": "..."}`
- Edit → `{"file_path": "...", "old_string": "...", "new_string": "...", "replace_all": false}`

WebFetch not yet captured — expected `{"url": "...", ...}` per public docs, unconfirmed.

UserPromptSubmit payload not yet captured in this repo (fires on the *next* prompt after hooks are enabled, and this capture session enabled hooks mid-session). Expected shape per public docs: same common fields plus `prompt` (the user's text) — **unconfirmed field name, needs one real capture before relying on it.**

## Output

PreToolUse decision — exit 0 and print only this JSON to stdout:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Reads ~/.ssh/id_rsa; the task is a CSS fix."
  }
}
```

`permissionDecision`: `allow` | `deny` | `ask` | `defer`. The reason is shown to Claude on `deny`, so write it so the agent understands why.

UserPromptSubmit: cannot rewrite the prompt. It may add `hookSpecificOutput.additionalContext` or block with top-level `{"decision": "block", "reason": "..."}`. AgentWarden only records the prompt as the session task; it returns nothing.

## Exit codes (command hooks)

- `0` + no output → no decision, normal permission flow continues. Silence does not approve.
- `0` + JSON → JSON is applied.
- `2` → blocking error; for PreToolUse the tool call is blocked, stderr goes to Claude.
- Any other code → non-blocking error, **the action proceeds**.
- Stdout must contain only the JSON. No prints, no logging to stdout.

## Fail-closed rules — why hooks/ are command hooks, not HTTP hooks

Claude Code treats these as non-blocking, meaning **the tool call goes ahead**:

- HTTP hook: connection failure, non-2xx status, non-JSON body, invalid schema.
- Any hook type: a PreToolUse hook that times out.
- Command hook: crash or exit code other than 0/2.

A security hook must not fail open. So:

1. `hooks/on_tool.py` is a **command** hook that calls the daemon itself with its own timeout.
2. Its HTTP timeout to the daemon is shorter than the hook's `timeout` in settings (e.g. daemon call 8 s, hook timeout 15 s).
3. Daemon unreachable, timeout, bad response, any exception → print the `ask` JSON with reason "AgentWarden unavailable". Wrap `main()` in a top-level try/except that does this.
4. The daemon does the same internally: judge timeout or error → `ask`.
5. Tests cover each of these paths.

## Settings for the product hooks

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {"hooks": [{"type": "command", "command": "python3 \"${CLAUDE_PROJECT_DIR}/hooks/on_prompt.py\"", "timeout": 5}]}
    ],
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "python3 \"${CLAUDE_PROJECT_DIR}/hooks/on_tool.py\"", "timeout": 15}]}
    ]
  }
}
```

Keep these out of `.claude/settings.json` until dogfooding starts (29.10); put them in `examples/settings.agentwarden.json`.
