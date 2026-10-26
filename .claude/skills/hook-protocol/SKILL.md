---
name: hook-protocol
description: Exact Claude Code hook input/output formats for PreToolUse and UserPromptSubmit, exit codes, and the fail-closed rules AgentWarden must follow. Use whenever writing or changing anything in hooks/ or the daemon endpoints the hooks call.
---

# Claude Code hook protocol (for AgentWarden)

Source: Claude Code hooks reference (code.claude.com/docs/en/hooks), checked 2026-10-26. Replace the examples below with real payloads from `.agentwarden/events.jsonl` once spec 001 is done.

## Input (stdin JSON for command hooks, POST body for HTTP hooks)

Common fields on every event: `session_id`, `prompt_id`, `transcript_path`, `cwd`, `permission_mode`, `hook_event_name`.

PreToolUse adds `tool_name`, `tool_input`, `tool_use_id`:

```json
{
  "session_id": "abc123",
  "prompt_id": "550e8400-e29b-41d4-a716-446655440000",
  "transcript_path": "/home/user/.claude/projects/.../transcript.jsonl",
  "cwd": "/home/user/my-project",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {"command": "npm test", "description": "Run test suite"},
  "tool_use_id": "toolu_01ABC123"
}
```

`tool_input` shape depends on the tool: Bash → `command`; Read/Edit/Write → `file_path` (+ content fields); WebFetch → `url`. Record real examples for each tool we handle.

UserPromptSubmit carries the user's prompt text. Confirm the field name from a real payload (expected: `prompt`).

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
