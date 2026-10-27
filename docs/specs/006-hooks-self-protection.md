# 006 — Self-protection for `hooks/`

Size: small

## Context

Spec 003 added hard denies for `.agentwarden/` and `.claude/settings*.json` so the protected agent
cannot switch AgentWarden off. `hooks/on_tool.py` and `hooks/on_prompt.py` are just as load-bearing
(`settings.json` points straight at them) but live outside `.agentwarden/`, at the project root, so
nothing in `rules.py` protects them today — `rm -rf hooks/on_tool.py` or editing the hook script to
always print `{}` is not denied. This closes that gap, per `docs/SESSION.md` item 2.

## Behaviour

Any tool call that would read, write, edit, delete, move or shell out against something under the
project's top-level `hooks/` directory is denied, the same way `.agentwarden/` is: hard deny, stage
1, cannot be weakened by user policy.

Only the project's own `hooks/` directory at the project root counts — not an unrelated directory
named `hooks` deep in a dependency tree (e.g. `node_modules/some-pkg/hooks/`) and not the English
word "hooks" in a sentence. Scope follows `_is_inside_project` plus a top-level `hooks` component,
mirroring how `.claude/settings*.json` is scoped rather than how the broader `.agentwarden` mention
check works (that one intentionally over-blocks since the whole word is already rare and sensitive).

Example: `Write(file_path="hooks/on_tool.py", content="...")` → deny, reason
`AgentWarden: blocked -- touching AgentWarden's own hooks/ scripts is not allowed. Do not try
another way; ask the user.`

`Bash(command="rm -rf hooks")` → deny, same reason, matched via the existing shell-mention style
check used for `.agentwarden` and `.claude`.

`Read(file_path="C:/other-project/hooks/build.py")` (outside this project) → not matched, normal
rule stages apply.

## Interface

- `src/agentwarden/rules.py`: new `_hooks_rule(event) -> Verdict | None`, added to
  `_hard_deny_stage`'s rule tuple after `_claude_settings_rule`.
- `_is_project_hooks_path(raw_path, cwd) -> bool`: true when the path is inside the project
  (`_is_inside_project`) and its first component below the project root is `hooks`.
- `_shell_mentions_hooks(command) -> bool`: regex, same style as
  `_CLAUDE_SETTINGS_MENTION_RE` — matches `hooks/` or `hooks\` as a path-like token (e.g.
  `\bhooks[/\\]`), not the bare word "hooks".
- No new env vars, no endpoint changes.

## Failure paths

Not applicable — this is a pure rules-stage addition, no model call, no network, no new fallible
I/O. Existing invariant (any rules-stage error bubbles up through `decide.py`'s existing fail-safe)
is unchanged.

## Acceptance criteria

- [x] `test_write_to_hooks_file_is_denied` — `Write(file_path="hooks/on_tool.py")` from
  `cwd=<project root>` → deny.
- [x] `test_edit_hooks_file_is_denied` — same for `Edit`/`MultiEdit`.
- [x] `test_delete_hooks_via_bash_is_denied` — `Bash(command="rm -rf hooks")` and
  `PowerShell(command="Remove-Item hooks -Recurse -Force")` → deny.
- [x] `test_hooks_outside_project_not_matched` — a path under `hooks/` that resolves outside the
  project root (different drive/absolute path) is not denied by this rule.
- [x] `test_unrelated_hooks_word_not_matched` — `Bash(command="echo use git hooks for this")` is
  not denied by this rule (no path-like `hooks/` token).
- [x] `test_policy_cannot_override_hooks_protection` — `allow_paths: ["hooks/"]`,
  `allow_commands: ["rm -rf hooks"]` in `.agentwarden/policy.yaml` still deny.
- [x] `make test` green (303 passed), `make lint` clean.

## Out of scope

Protecting `hooks/` scripts once they are moved outside the project (e.g. `~/.agentwarden/hooks/`
as discussed in `docs/SESSION.md`) — if that move happens it is a separate spec and may make this
rule obsolete. Protecting arbitrary other entry points (`Makefile`, `pyproject.toml`) — not part of
the hook chain the agent could disable.

## Demo impact

Minor: one more "the agent tried to disable me and I said no" beat available for the demo, same
family as the existing `.agentwarden` self-protection shot.
