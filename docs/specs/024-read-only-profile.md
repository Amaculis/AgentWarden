# 024 — Read-only policy profile

Size: small (policy.py, one new field)

## Context

For reading unfamiliar or untrusted code, the user wants an agent that can look but not touch.
A prompt injection that reaches such an agent has nothing to act with. Claude Code's plan mode
does something similar but is not enforced by AgentWarden's audit log, hard denies or
dashboard. This profile is a policy-file switch handled by the existing policy stage (spec 004):
no model call, no new endpoint.

"Read-only" is deliberately narrow: only the `Read`, `Glob` and `Grep` tools. Shell commands
are not split into "reads" and "writes" (`cat f | curl ...` looks like a read, `make test`
runs project code), so every `Bash`/`PowerShell` call asks.

## Behaviour

`.agentwarden/policy.yaml` gains `mode: normal | read_only` (default `normal`: nothing changes).

With `mode: read_only`, `policy.match` decides in this order:

1. Built-in hard denies (secrets, self-protection) already ran before the policy stage —
   unchanged, still first.
2. `deny_paths` / `deny_commands` / `ask_paths` / `ask_commands` — unchanged.
3. `Read`, `Glob`, `Grep` whose every path field is inside the project → `allow`
   ("read-only profile: reading inside the project").
4. Anything else → `ask` ("read-only profile: <tool> is not a read tool"). That covers `Edit`,
   `Write`, `MultiEdit`, `NotebookEdit`, `Bash`, `PowerShell`, `WebFetch`, MCP tools, `Task`,
   a read outside the project, and a read with an unresolved `~`/`$VAR` path.
5. `allow_paths`, `allow_commands`, `allow_domains` are ignored in this mode (the dashboard's
   "always allow" still writes them, they take effect after switching back to `normal`).

Verdict source is `policy`. The verdict is final: the judge and the cascade are not called, so
a read-only session costs no API credits and the model cannot be talked into `allow`.

Example: `mode: read_only`, `Edit src/app.py` → `ask`, reason "AgentWarden: read-only profile:
Edit is not a read tool."; `Read src/app.py` → `allow`; `Read ~/.ssh/id_rsa` → `deny` (hard
deny, before the policy).

## Interface

- `policy.Policy.mode: Literal["normal", "read_only"] = "normal"`.
- `policy.match` gains the branch above, after the deny/ask checks and before the allow checks.
- `examples/policy.example.yaml` and the README policy section document `mode`.

## Failure paths

- Unknown `mode` value (typo like `readonly`) → schema mismatch → the existing rule applies:
  the whole file is ignored, defaults are used, one warning is logged. This falls back to
  `normal`, not to allow-all; the log line is the only signal, so the example file says so.
- Missing / unreadable policy → defaults (`normal`), as before.
- Path fields missing or not strings on a read tool → not provably inside the project → `ask`.
- Nothing in this spec can produce `allow` for a non-read tool.

## Acceptance criteria

- [x] `test_read_only_allows_read_inside_project` — `Read`, `Grep`, `Glob` in the project → `allow`.
- [x] `test_read_only_asks_for_write_tools` — `Edit`, `Write`, `MultiEdit`, `NotebookEdit` → `ask`.
- [x] `test_read_only_asks_for_shell_and_network` — `Bash` (even `ls`, `git status`),
      `PowerShell`, `WebFetch`, an MCP tool name → `ask`.
- [x] `test_read_only_asks_for_read_outside_project` — `/etc/hosts`, `../other`, `~/x` → `ask`.
- [x] `test_read_only_ignores_allow_lists` — `allow_commands: [make test]`,
      `allow_paths: [src/]`, `allow_domains: [pypi.org]` do not allow in read-only.
- [x] `test_read_only_deny_and_ask_paths_still_apply` — `deny_paths: [secrets/]` → `deny`,
      `ask_paths: [docs/]` → `ask` for a `Read`.
- [x] `test_read_only_cannot_weaken_hard_denies` — through `rules.evaluate`: `Read .env` and
      an edit of `.agentwarden/policy.yaml` stay `deny`.
- [x] `test_read_only_never_calls_judge` — `decide.decide` with a mock provider: provider has
      zero calls for a write tool in read-only mode.
- [x] `test_normal_mode_unchanged` — default policy behaves as before (existing tests green).
- [x] `test_invalid_mode_uses_defaults_and_warns`.
- [x] `make test` green, `make lint` clean (run ruff on `src tests eval redteam hooks`).

## Out of scope

- A shell-command whitelist for read-only (`ls`, `git status`): they ask for now.
- Switching the mode from the dashboard or an env var.
- Restricting what the agent can read inside the project beyond the existing hard denies.
- Enforcing the profile in the hooks themselves; it lives in the daemon's policy stage like
  every other policy rule.

## Demo impact

A short extra scene is possible ("untrusted repo: read-only mode, injected README tries to
edit a file → ask"). Nothing in the existing demo changes.
