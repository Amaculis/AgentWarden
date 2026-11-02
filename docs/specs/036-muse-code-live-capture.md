# 036 — Muse Code adapter from the live capture

Size: small (adapter, one rules branch, tests, integration README)

## Context

Spec 028 guessed Muse Code's tool names. A live session on 2026-11-02 (Muse Code 1.4.14,
Windows, `C:\tmp\muse-capture`, AgentWarden off, `hook_logger.py`) captured the real hook
payloads. Facts:

- Hook config must use Claude-style matcher groups:
  `{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "..."}]}]}}` in
  `<project>/.muse/hooks.json` (honoured once the folder is trusted). A flat
  `[{"command": ...}]` list is rejected (`hook.admission outcome=rejected`). Quotes inside
  `command` are passed literally on Windows. A failing `UserPromptSubmit` hook blocks the prompt.
- Payloads use Claude field names (`hook_event_name`, `tool_name`, `tool_input`,
  `tool_use_id`, `tool_response`) with Muse's own tool names, plus `turn_id` (no `prompt_id`).
- Tools seen: `powershell {command, description, workdir}`, `read_file {path}`,
  `edit_file {path, find, replace}`, `search {pattern, paths: [..], output_mode}`, and the
  internal `submit_reminder_decision` (17 of 23 tool calls; skill-reminder bookkeeping).
- `PostToolUse.tool_response` is a string for `read_file`/`powershell`/`search`, an object
  for `edit_file`.
- From the binary's messages: `permissionDecision: allow` without `updatedInput` is rejected,
  so AgentWarden must stay silent on `allow` (the default `WARDEN_ALLOW_MODE`).

## Behaviour

- `powershell` → `PowerShell`; `edit_file` `find`/`replace` → `old_string`/`new_string`;
  `search` → `Grep` with `paths` of one entry → `path`, empty → dropped, several → `AdapterError`
  (→ `ask`). Old guesses (`exec_command`, `shell`, `write_file`, ...) stay mapped.
- `turn_id` → `prompt_id` (spec 035 binding works for Muse).
- Shell `workdir` (with or without the `\\?\` prefix) must be the session `cwd` or inside it;
  otherwise `AdapterError` (→ `ask`), since the rules check paths against `cwd`.
- `Adapter.internal_tools`: tools of the agent's own bookkeeping with no side effects.
  `muse_code:submit_reminder_decision` → `allow` from the rules, no model call. Every other
  unmapped tool still `ask`s.

## Failure paths

- Untranslatable `search.paths`, outside `workdir`, non-string entries → `AdapterError` → `ask`.
- Nothing new yields `allow` except the named internal tool.

## Acceptance criteria

- [x] `test_live_payloads_normalize` (all four captured tools)
- [x] `test_live_powershell_rm_is_denied`, `test_live_env_read_is_denied`
- [x] `test_turn_id_becomes_prompt_id`
- [x] `test_search_paths_mapping` (0, 1, several)
- [x] `test_workdir_outside_cwd_raises`, `test_workdir_inside_cwd_ok`
- [x] `test_internal_reminder_tool_is_allowed_without_model`, other unmapped tools still ask
- [x] `make lint` and `make test` green.

## Out of scope

- A live run with AgentWarden switched on (next step, by the human).
- `write_file`, web tools, MCP tools: not seen in the capture.
- Explicit-allow output for Muse (`updatedInput`).

## Demo impact

Muse Code can be shown with real tool names; README stops calling them guesses.
