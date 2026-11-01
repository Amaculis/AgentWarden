# 029 — GitHub Copilot adapter

Size: small (new files on top of 027; no changes to rules/decide/judge)

## Context

VS Code Copilot agent hooks (Preview, VS Code Insiders 1.110+) and Copilot CLI use the Claude
Code hook format: `preToolUse` decisions are read from `hookSpecificOutput.permissionDecision`
(`allow | ask | deny`); workspace hooks live in `.github/hooks/*.json`. Tool names differ from
Claude Code. Copilot CLI has a reported bug: a `preToolUse` `ask` does not work and the denial
text is not shown to the agent (github/copilot-cli#2647). No live Copilot is available to the
team: everything is verified against docs only. Builds on 027.

## Behaviour

- `src/agentwarden/agents/copilot.py` defines `ADAPTER` (name `copilot`) mapping VS Code agent
  mode and Copilot CLI tools that run commands, write/edit/create files, read files, search, or
  fetch URLs to the canonical Claude tools and fields. If the two differ too much to share one
  map, two adapters (`copilot_vscode`, `copilot_cli`) are fine. Anything unmapped stays `ask`.
- Field/event-name aliases if Copilot sends camelCase or other event names (`preToolUse` vs
  `PreToolUse`): use `field_aliases` / `event_names` from 027.
- `config_paths`: `.github/hooks`, plus any other place VS Code or Copilot CLI loads hooks from
  or that switches hooks off (user-level hooks dir, VS Code settings keys that point to hook
  files — if hooks can be disabled through `.vscode/settings.json`, include that file).
  Must not hard-deny ordinary `.github/workflows` work (027's parent-match rule already avoids
  sibling paths; add a test).
- `hooks/formats/copilot.py` only if the output schema differs.
- `integrations/copilot/` — sample `.github/hooks/agentwarden.json` wiring the three hooks with
  `--agent copilot`, `README.md` with install steps, sources, and a clear "unverified against a
  live Copilot" note and the CLI `ask` bug.

## Research (before code; record sources in the README)

code.visualstudio.com/docs/copilot/customization/hooks, docs.github.com Copilot hooks pages
(concepts/agents/hooks, copilot-sdk pre-tool-use), microsoft/vscode-copilot-chat
`assets/prompts/skills/agent-customization/references/hooks.md`, github/copilot-cli issues: hook
file locations and precedence, event names, payload fields, tool names and input fields for both
VS Code and CLI, output schema, PostToolUse/additionalContext and prompt-submit equivalents.

## Failure paths

- Unknown Copilot tool → `ask` (027). Conflicting fields → fail-safe `ask`.
- Daemon down / slow / broken → fail-safe `ask` in the schema Copilot reads.
- Copilot CLI `ask` bug: document what the CLI does with our `ask` (per the issue) and whether
  `deny` should be used instead there; do not change the fail-safe to `deny` without a spec.

## Acceptance criteria

- [x] `tests/test_agent_copilot.py` — doc-derived fixtures (marked UNVERIFIED) for each mapped
      tool normalize correctly; `rm -rf /` deny, `.env` read deny, `ls` allow, unmapped `ask`.
- [x] Writes and shell commands touching `.github/hooks` (and every other config path) are
      hard-denied; editing `.github/workflows/ci.yml` and `rm .github/workflows/old.yml` are not
      hard-denied by the config rule.
- [x] Hook end-to-end with `--agent copilot_cli` (and `copilot_vscode` at the unit level) against
      a real daemon.
- [x] `integrations/copilot/README.md` with install steps, sources, unverified note, CLI bug.
- [x] `make test` green, `make lint` clean, `make eval-rules` delta 0.000.

## Out of scope

Changes to 027's layer (propose in the README instead). A VS Code extension. Copilot coding agent
running in GitHub Actions.

## Demo impact

None until verified on a live Copilot.
