# GitHub Copilot integration (spec 029)

**Unverified against a live Copilot.** Nobody on the team has a working Copilot (VS Code agent
mode or Copilot CLI) to test against, so everything below comes from GitHub's and Microsoft's
published docs, cross-checked across several pages, plus three open `github/copilot-cli` issues.
Where two fetches of the same or related pages disagreed, or a detail appeared in only one
source, it is called out as a GUESS below instead of stated as fact. Do not trust the hard-deny
behaviour described here until it has been run against a real Copilot session.

Builds on spec 027 (`src/agentwarden/agents/__init__.py`) and adds two adapters because VS Code's
agent-mode hooks and Copilot CLI's native hooks disagree on event-name casing, payload field
names and tool names:

- `src/agentwarden/agents/copilot_vscode.py` -- VS Code Copilot agent mode.
- `src/agentwarden/agents/copilot_cli.py` -- Copilot CLI (and, as far as we can tell, the cloud /
  coding agent, which the docs describe as sharing the CLI's hook system).
- `src/agentwarden/agents/_copilot_common.py` -- config paths shared by both (leading underscore
  so `agents.discover()` does not try to register it as a third adapter).

No `hooks/formats/copilot*.py` was added: both surfaces' `preToolUse` output schema
(`{"permissionDecision": "allow"|"deny"|"ask", "permissionDecisionReason": "..."}`, optionally
wrapped in `hookSpecificOutput`) matches Claude Code's, so the hooks' default Claude-schema output
is used unchanged.

## Sources

- https://code.visualstudio.com/docs/copilot/customization/hooks -- VS Code agent-hook events,
  the `PreToolUse` "Claude-style" alias, hook config locations.
- https://docs.github.com/en/copilot/concepts/agents/hooks -- "About hooks for GitHub Copilot"
  overview, event list, config file precedence.
- https://docs.github.com/en/copilot/reference/hooks-reference -- field names and tool-name
  table (VS Code-compatible snake_case alias).
- https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference --
  native camelCase field names (`toolName`/`toolArgs`), output schema, hook config locations and
  `disableAllHooks`.
- https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-hooks -- hook
  config file shape (`version`, `hooks.preToolUse[].type/bash/powershell/cwd/env/timeoutSec`) and
  an example script reading `tool_name`/`tool_input` from stdin with `jq`.
- https://docs.github.com/en/copilot/concepts/agents/cloud-agent/about-hooks -- cloud/coding
  agent shares the CLI's hook mechanism (no extra detail beyond that).
- https://docs.github.com/en/copilot/concepts/agents/about-copilot-cli -- generic tool
  permission categories (`shell(...)`, `write`, `git`), not specific tool names.
- `microsoft/vscode-copilot-chat` `assets/prompts/skills/agent-customization/references/hooks.md`
  (raw.githubusercontent.com) -- event name list (`SessionStart`, `UserPromptSubmit`,
  `PreToolUse`, `PostToolUse`, `PreCompact`, `SubagentStart`, `SubagentStop`, `Stop`), confirms
  `hookSpecificOutput.permissionDecision`.
- https://github.com/github/copilot-cli/issues/2647 -- "preToolUse `ask` feedback is not shown to
  the agent" (the bug named in spec 029).
- https://github.com/github/copilot-cli/issues/4237 -- "Steering message in `preToolUse` `ask`
  denial is silently dropped" (same family of bug, more recent).
- https://github.com/github/copilot-cli/issues/3042 -- "`ask` permissionDecision does not
  suppress the native trust prompt, causing two confirmations per gated tool call".

## Verified vs. guessed

**Verified (stated the same way across two or more of the sources above, or quoted directly from
an official docs page):**

- Hook config files: `.github/hooks/*.json` at the repo root (both VS Code and CLI read this);
  CLI also reads a user-level `~/.copilot/hooks/*.json` (`%USERPROFILE%\.copilot\hooks\` on
  Windows), overridable via `$COPILOT_HOME`.
- Hook config file shape: `{"version": 1, "hooks": {"<event>": [{"type": "command", "bash":
  "...", "powershell": "...", "cwd": "...", "env": {...}, "timeoutSec": N}]}}`.
- Event names exist in two casings: native camelCase (`preToolUse`, `postToolUse`,
  `userPromptSubmitted`, `sessionStart`, `sessionEnd`, `agentStop`, `subagentStop`,
  `errorOccurred`) and a PascalCase, Claude Code-shaped alias (`PreToolUse`, `PostToolUse`,
  `UserPromptSubmit`, `SessionStart`, `PreCompact`, `SubagentStart`, `SubagentStop`, `Stop`).
- The PascalCase alias ("VS Code agent hooks" doc, quoted almost verbatim) carries snake_case
  fields (`tool_name`, `tool_input`) **and already uses Claude-style tool names** ("Read",
  "Write", "Edit" are named explicitly as examples). `copilot_vscode.py` assumes this alias is
  what VS Code sends and is therefore a near-identity map.
- The native camelCase event carries `toolName`/`toolArgs` fields. `bash`, `edit`, `view` are
  given as example native tool names in at least two separate official pages ("such as `bash`,
  `edit`, `view`").
- `preToolUse` output: `permissionDecision` is one of `allow` / `deny` / `ask`.
- The CLI bug: a `preToolUse` `ask` decision's reason/steering text is not shown to the agent
  (#2647, #4237); separately, `ask` does not suppress the CLI's own native trust prompt, so the
  user is asked twice for the one action (#3042). We found no evidence this drops the decision
  itself -- the action still stops for confirmation; the agent just never sees *why*.

**Guessed (plausible by analogy with Claude Code / Codex / Muse Code, or only ever appeared in a
single lower-confidence source) -- treat these as the first things to check against a real
Copilot:**

- Native CLI tool names beyond `bash`/`edit`/`view`: we assumed `create` (new file), `grep`,
  `glob`, `web_fetch`, `ask_user`, `task`, and mapped only the first four (`create` -> `Write`,
  `grep` -> `Grep`, `glob` -> `Glob`, `web_fetch` -> `WebFetch`); `ask_user` and `task` are left
  unmapped on purpose since even their existence is a guess.
- The inner field name inside `toolArgs`/`tool_input` for a file path (we used `path`, mapped to
  canonical `file_path`). No source we found quotes this field name directly for Copilot; one
  example script only showed `tool_input` passed through whole, not its inner keys.
- Whether `.github/hooks/*.json` uses the same event-name casing for both VS Code and CLI, or
  whether VS Code specifically expects the PascalCase keys in the config file itself. The sample
  config in this directory uses the native camelCase keys (`preToolUse`, ...) because that is the
  only config shape with a concrete documented example; if VS Code needs `PreToolUse` as the
  config key, duplicate the block under both keys.
- Whether `.vscode/settings.json` can point at or disable Copilot hooks. No page we found names
  a specific settings key for this. `copilot_vscode.py` hard-protects this file anyway (same
  aggressive stance as this repo's existing `.claude/settings*.json` rule), on the theory that
  being wrong in the direction of protecting an ordinary settings file too eagerly is the safe
  failure mode, not the unsafe one.
- `disableAllHooks: true` as a hook-config top-level key that turns off non-policy hooks (one
  source only).
- `$COPILOT_HOME` is an environment variable, so a custom location cannot be expressed as one of
  this adapter's `config_paths` path-component tuples (which match anywhere in the normalized
  absolute path, but only for a fixed directory name). Only the default `~/.copilot/...` layout
  is protected. **Gap, not fixed here** -- flagged for whoever verifies this against a live
  Copilot.
- `/etc/github-copilot/policy.d/*.json` (an org-wide policy hook location mentioned once) is
  outside any project tree and outside what this layer's `config_paths` mechanism can express;
  intentionally left uncovered.

## Tool map

| Copilot CLI tool (native) | Canonical | Confidence |
|---|---|---|
| `bash` / `powershell` | `Bash` / `PowerShell` | verified |
| `view` | `Read` | verified |
| `edit` | `Edit` | verified |
| `create` | `Write` | guessed |
| `grep` | `Grep` | guessed |
| `glob` | `Glob` | guessed |
| `web_fetch` | `WebFetch` | guessed |
| `ask_user`, `task`, anything else | *(unmapped -- `ask`)* | -- |

| VS Code `PreToolUse` alias tool | Canonical | Confidence |
|---|---|---|
| `Bash`, `PowerShell`, `Read`, `Write`, `Edit`, `MultiEdit`, `Grep`, `Glob`, `WebFetch` | itself (identity) | verified shape, guessed completeness |
| anything else | *(unmapped -- `ask`)* | -- |

An unmapped tool never reaches the judge: `rules.py`'s `_unknown_agent_tool_rule` (027) `ask`s on
`<agent>:<tool>` before any model call, for both adapters.

## Config paths (hard-denied for writes / shell mentions, whatever agent is running)

- `.github/hooks` (repo-level hook config, both surfaces)
- `.github/copilot/settings.json`, `.github/copilot/settings.local.json` (inline repo hooks)
- `.vscode/settings.json` (VS Code adapter only; guessed, see above)
- `.copilot/hooks`, `.copilot/settings.json`, `.copilot/settings.local.json` (CLI adapter only;
  user-level default layout, not `$COPILOT_HOME`-aware)

`.github/workflows/**` is a sibling of `.github/hooks`, not a parent or child of it, so ordinary
CI work there (editing `.github/workflows/ci.yml`, `rm .github/workflows/old.yml`) is not touched
by this rule -- covered by `tests/test_agent_copilot.py`.

## The Copilot CLI `ask` bug (github/copilot-cli#2647)

Per the issue (and the related #4237, #3042), a `preToolUse` hook returning `ask` does get
enforced as a stop-and-confirm, but: the `permissionDecisionReason` text AgentWarden sends is not
shown to the agent as steering context, and the CLI shows its own native trust prompt on top
(two prompts for one action). **This is a CLI display/UX bug, not AgentWarden returning the wrong
decision**, and spec 029 is explicit that the fail-safe should not be changed to `deny` without a
separate spec weighing that trade-off. We have not made that change here. Practical effect for a
CLI user today: when AgentWarden asks, expect two confirmations and no explanation from the
agent -- the reason is only visible wherever AgentWarden's own `systemMessage` surfaces (dashboard
/ audit log), not in the CLI's own prompt.

## Install steps (unverified)

1. Copy `.github/hooks/agentwarden.json` from this directory into your repository's own
   `.github/hooks/agentwarden.json` (keep the AgentWarden checkout's `hooks/` directory --
   `on_tool.py`, `on_read.py`, `on_prompt.py` -- reachable from the repo root, or adjust the
   `bash`/`powershell` command paths).
2. Start the daemon (`make run`, or your own `uvicorn agentwarden.daemon:app` invocation).
3. For **Copilot CLI**: the sample as written. For **VS Code agent mode**, change
   `--agent copilot_cli` to `--agent copilot_vscode` in every hook command (and see the
   config-key-casing guess above -- you may need a second copy of the block under the PascalCase
   event names if VS Code does not read the camelCase config the CLI uses).
4. Everything else (the daemon URL, `WARDEN_NOTIFY`, `WARDEN_ALLOW`, timeouts) is the same
   environment configuration as the Claude Code integration; see the top-level repo README /
   `docs/CONTEXT.md`.
5. Verify a deny actually blocks the action and an `ask` actually stops for confirmation before
   relying on this in a real session -- again, this whole integration is unverified against a
   live Copilot.

## Proposal for 027 (not implemented here, out of scope for 029)

`agents/__init__.py`'s `config_paths` matching is a fixed path-component tuple matched anywhere
in the normalized absolute path. It has no way to express an environment-variable-rooted
location (`$COPILOT_HOME`, and likely similar variables for other agents down the line). A future
027 change could let an adapter contribute a callable (`cwd, env -> tuple[tuple[str, ...], ...]`)
alongside the static tuples, resolved once per request from the hook's own environment, so a
custom `COPILOT_HOME` would be protected the same way the default path is. Not done here: it
would mean editing `agents/__init__.py`, which 029 is not allowed to touch.
