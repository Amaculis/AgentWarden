# 001 — Hook passthrough and event capture

Size: small

## Context

Before deciding anything we need the exact payloads Claude Code sends. This spec adds two command hooks that record every UserPromptSubmit and PreToolUse event to a local file and make no decision. The recorded payloads become the real examples in the `hook-protocol` skill and the first dogfood eval candidates.

## Behaviour

- `hooks/on_prompt.py` reads the UserPromptSubmit JSON from stdin and appends it as one line to `.agentwarden/events.jsonl`. Prints nothing, exits 0.
- `hooks/on_tool.py` does the same for PreToolUse. Prints nothing, exits 0 (no decision: normal permission flow).
- Each line gets `received_at` (UTC ISO 8601) added.
- `examples/settings.agentwarden.json` contains the settings block that wires both hooks (see `hook-protocol` skill), so they can be enabled in any test project.

## Interface

- `hooks/on_prompt.py`, `hooks/on_tool.py` — standard library only, no project imports (they must run even when the package is broken).
- Shared helper may live in `hooks/_common.py` (stdlib only).
- Env `AGENTWARDEN_HOME` overrides the output directory (default: `<cwd>/.agentwarden`).

## Failure paths

- Invalid JSON on stdin → write nothing, exit 0.
- Output directory not writable → exit 0, nothing printed to stdout.
- Any exception → exit 0. (This spec makes no decisions. From spec 002 on, exceptions in `on_tool.py` must produce `ask`.)

## Acceptance criteria

- [ ] `test_on_tool_appends_event` — feeding a sample PreToolUse payload appends one valid JSON line with `received_at`.
- [ ] `test_on_prompt_appends_event` — same for UserPromptSubmit.
- [ ] `test_invalid_json_is_ignored` — garbage on stdin: exit 0, no file written, empty stdout.
- [ ] `test_hooks_print_nothing` — stdout is empty in all cases.
- [ ] Manual: enable the hooks in a scratch project, run a short Claude Code session (read a file, run a command, edit a file), confirm events for Read, Bash, Edit are captured.
- [ ] Real payloads for Read, Bash, Edit, Write and UserPromptSubmit pasted into the `hook-protocol` skill, replacing the doc examples.

## Out of scope

Daemon, rules, judge, any decision output.

## Demo impact

None.
