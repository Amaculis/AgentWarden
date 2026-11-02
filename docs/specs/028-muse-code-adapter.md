# 028 — Muse Code adapter

Size: small (new files on top of 027; no changes to rules/decide/judge)

## Context

Muse Code (Meta's CLI coding agent) runs command hooks with Claude Code's wire schema
(snake_case payload in, camelCase `hookSpecificOutput` out) but its own tool names
(`exec_command` reported) and possibly Codex-style payloads. Hooks are said to live in
`<project>/.muse/hooks.json` or be registered as a plugin (`.muse-plugin/plugin.json`, installed
with `muse plugins install` / `approve`); public reports say the documented `muse hooks` CLI is
missing from the shipped binary. None of this is verified here. Builds on 027.

## Behaviour

- `src/agentwarden/agents/muse_code.py` defines `ADAPTER` (name `muse_code`) mapping every Muse
  Code tool that runs commands, writes/edits files, reads files, searches, or fetches URLs to the
  canonical Claude tool (`Bash`, `Write`, `Edit`, `Read`, `Grep`, `Glob`, `WebFetch`) and its
  input fields. Anything unmapped stays `ask` (027).
- `config_paths` covers every place Muse Code loads hooks or plugins from, project and home
  (`.muse/`, `.muse-plugin/`, and the user-level equivalents found in the research).
- If Muse Code's output schema differs from Claude Code's in any field AgentWarden emits, add
  `hooks/formats/muse_code.py`; otherwise no formatter.
- `integrations/muse_code/` — a sample hook config wiring `hooks/on_tool.py --agent muse_code`
  (PreToolUse), `on_read.py` (post-read, if Muse Code has it) and `on_prompt.py` (prompt submit,
  if it has it), plus `README.md` with install steps.
- `integrations/muse_code/hook_logger.py` + a 5-step check list in the README: the human runs ONE
  short Muse Code session (budget is limited) with a logger hook that appends raw payloads to a
  file, so the real tool names and fields can be confirmed. Fixtures are then replaced with real
  captures.

## Research (before code; record sources in the README)

Muse Code docs and public integrations (e.g. agenticcontrolplane.com Muse Code guide, Arcjet
"Secure Muse Code", `meta-models/muse-code-sdk` issues, destructive_command_guard issue #572):
hook locations, event names, payload fields, tool names and their input fields, output schema,
how `ask`/`deny` are handled, PostToolUse / UserPromptSubmit equivalents.

## Failure paths

- Unknown Muse Code tool → `ask` (027). Conflicting fields → fail-safe `ask` (027).
- Daemon down / slow / broken → fail-safe `ask` in the schema Muse Code reads.
- If Muse Code ignores `ask` or treats it as allow (to be checked), document it in the README
  and in `docs/CONTEXT.md` candidates; do not claim protection that is not there.

## Acceptance criteria

- [x] `tests/test_agent_muse_code.py` — fixture payloads (from docs; marked UNVERIFIED until the
      live capture) for each mapped tool normalize to the canonical event; `rm -rf /` deny,
      `.env` read deny, `ls` allow, unmapped tool `ask`.
- [x] Writes and shell commands touching each Muse Code config path are hard-denied.
- [x] Hook end-to-end: `on_tool.py --agent muse_code` against the stub daemon prints output in
      Muse Code's schema (formatter tests if a formatter exists). No formatter: research found
      Muse Code's `PreToolUse` schema already matches Claude Code's.
- [x] `integrations/muse_code/README.md` with install steps, sources and the live-check list.
- [x] `make test` green, `make lint` clean, `make eval-rules` delta 0.000.

## Out of scope

Changes to 027's layer (if one is needed, write it in the README as a proposal, do not edit
`agents/__init__.py`, `rules.py`, `daemon.py`, `decide.py`, hooks other than `formats/`).
Running Muse Code itself.

## Demo impact

Yes, if the live check passes: the same deny shown in Claude Code and in Muse Code.
