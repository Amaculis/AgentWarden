# 030 — OpenAI Codex adapter

Size: small if Codex has blocking pre-tool hooks; otherwise a research note only

## Context

Codex (OpenAI's coding agent: Codex CLI and the IDE extension) has its own extension points and
its own payload/output formats; whether it has a hook that runs before a tool call and can block
it is not verified. No live Codex is available to the team: everything is verified against docs
and source only. Builds on 027.

## Behaviour

First establish what exists (Research). Then one of:

A. **Codex has a blocking pre-tool hook.**
   - `src/agentwarden/agents/codex.py` defines `ADAPTER` (name `codex`), or a subclass with an
     overridden `normalize` if the payload is structurally different (e.g. no `tool_input` dict,
     command as an argv list — join it with `shlex.join` for the canonical `command`).
   - `hooks/formats/codex.py` with `decision_output` / `scan_output` in Codex's schema. A fail-safe
     `ask` must map to whatever Codex treats as "stop and ask the user"; if Codex has no ask, map
     it to its block/deny and say so in the README.
   - `config_paths`: Codex's config and hook locations (project `.codex/`, user `~/.codex/`,
     `config.toml`, any `AGENTS.md`-adjacent hook files found).
   - `integrations/codex/` — sample config and `README.md` (install, sources, unverified note).

B. **No blocking hook.** No adapter code. `integrations/codex/README.md` records what Codex
   offers (sandbox/approval modes, notify hooks, MCP), why AgentWarden cannot gate it today, and
   the smallest change that would make it possible (e.g. an MCP-proxy or wrapper approach) as a
   backlog draft in `docs/specs/backlog/codex-integration.md`.

## Research (before code; record sources in the README)

OpenAI Codex docs and the `openai/codex` repository (config reference, hooks, notify, approval
policy, sandbox, MCP): which events exist, payload fields, tool names (`shell`, `apply_patch`,
`exec_command`…) and their arguments, how a hook result can deny or require approval.

## Failure paths

- Unknown Codex tool → `ask` (027). Conflicting fields / unexpected shape → fail-safe `ask`.
- Formatter error → Claude-schema fail-safe (027); the README must state what Codex does with
  output it cannot parse (block, ignore, or allow) — if it would allow, say so prominently.
- `apply_patch`-style multi-file edits: every target path must reach the rules (one canonical
  event cannot carry several paths; if needed, propose the 027 change in the README and `ask`
  such patches until then).

## Acceptance criteria

Variant A:
- [x] `tests/test_agent_codex.py` — doc/source-derived fixtures (marked UNVERIFIED) normalize
      correctly; `rm -rf /` deny, `.env` read deny, `ls` allow, unmapped `ask`; a patch touching
      `.agentwarden/` or a Codex config path is denied or `ask`, never allow.
- [x] Formatter tests: every decision and the fail-safe render in Codex's schema; a broken
      formatter ends in the 027 fail-safe.
- [x] Hook end-to-end with `--agent codex` against the stub daemon.
- [x] `make test` green, `make lint` clean, `make eval-rules` delta 0.000.

Variant B:
- [ ] `integrations/codex/README.md` and the backlog draft, with sources.

## Out of scope

Changes to 027's layer (propose in the README). Codex cloud tasks.

## Demo impact

None until verified on a live Codex.
