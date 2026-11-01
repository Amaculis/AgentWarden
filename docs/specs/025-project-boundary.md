# 025 — Project boundary and directory grants

Size: large (rules order, decide, daemon endpoint, store, dashboard)

## Context

Probing `rules.evaluate` (2026-11-01) showed the project boundary is applied unevenly:

| Action | Before |
| --- | --- |
| `Glob {"pattern": "C:/Users/**/*.docx"}` | `allow` (only `path` was checked, not the pattern) |
| `Bash: ls C:/Users` | `allow` (safe-command prefix, path ignored) |
| `Read` / `Grep` / `Edit` outside the project | no rule; goes to the model |
| `Bash: cat ../other/x.py` | no rule; goes to the model |

Searching outside the project is reconnaissance and almost never needed for a coding task; reading
or writing one file outside it sometimes is (`~/.gitconfig`, a sibling package). This spec makes
the boundary deterministic for every tool, and gives the user a way to widen it: permanently in
the policy file, or for one session from the dashboard. The agent can never widen it itself.

## Behaviour

**Roots.** Allowed roots = the event's `cwd` (project) + `extra_roots` from the policy file +
directories granted to this session. A path is inside when it is equal to or under a root
(lexical, same normalisation as today: `~`/`$HOME` expanded, `..` resolved, case-insensitive).

**Boundary stage** in `rules.evaluate`, after the hard denies:

1. `Grep` / `Glob`: any path field (`path`, `glob`, and for `Glob` the `pattern`) outside every
   root → `deny`: "searching outside the project (<path>) is not allowed". No path field → the
   project (unchanged).
2. `Read`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`: path outside every root → `ask`:
   "<tool> outside the project (<path>) needs confirmation".
3. `Bash` / `PowerShell`: path-like tokens (same tokenizer the policy uses, spec 008), except
   the command word of each simple command (`C:/Python312/python.exe x.py` is fine) and device
   files (`/dev/null`, `/dev/stdin|stdout|stderr`, `NUL`, `$null`). A token outside every root:
   - and the simple command is a search/listing command (`find`, `ls`, `dir`, `tree`, `du`,
     `grep`, `egrep`, `rg`, `ag`, `fd`, `locate`, `get-childitem`, `gci`, `select-string`,
     `sls`) → `deny`;
   - otherwise → `ask`.
   A path token that still contains `$` or `%NAME%` after the existing leading-`~`/`$HOME`
   expansion (`$FOO/x`, `/tmp/$X/y`, `%APPDATA%\x` when unset) counts as outside: the daemon
   cannot know the agent shell's variables.
4. Every boundary reason ends with: "To allow it, ask the user to grant <dir> for this session
   in the AgentWarden dashboard." `<dir>` is the path's directory (for a file tool), the path
   itself (for `Grep`/`Glob` `path`, or a Glob pattern's part before its first wildcard), or
   the token's directory (Bash). The same value is set on the verdict as `grant_dir`, stored
   in the audit log, and read by the dashboard — no parsing of the reason text. A path with an
   unresolved variable gets no `grant_dir` (nothing sensible to grant).

**Order.** hard denies → boundary `deny` (final) → policy `deny` (final) → built-in default
`deny` (`rm -rf /` stays a deny, not a boundary ask) → boundary `ask` → rest of the policy →
defaults. So a policy deny still beats a boundary ask, and no policy or
default `allow` (`allow_commands: [ls]`, the safe-read default) can allow a path outside the
roots.

**A boundary `ask` is a ceiling, not a final answer.** It carries `consult_judge: true`;
`decide` still runs the judge / cascade, and only a model `deny` replaces it. A model `allow`,
`ask`, timeout or error leaves the boundary `ask`. So `Edit ~/.bashrc` with a smuggled payload
is still denied by the model, and nothing outside the roots is ever allowed. A boundary `deny`
never calls the model.

**Policy file**: `extra_roots: list[str]` — absolute directories that count as inside the
project, permanently. Relative entries and filesystem roots (`/`, `C:\`) are dropped with one
warning; the rest of the file still loads.

**Session grants.**
- `POST /session/roots` `{session_id, path}` with header `x-warden-token` (UI token, as for
  `/policy/rules`) → stored per session. Same validation as `extra_roots`: absolute, not a
  filesystem root, ≤ 300 chars, one line. Response `{"ok": true, "added": bool}`.
- `GET /session/roots?session_id=…` → `{"roots": [...]}` (read-only, no token, like `/log`).
- Grants live in the SQLite store, table `session_roots (session_id, path, created_at)`. They
  are never shared between sessions. A new Claude Code session starts with none.
- The daemon's `/decide` reads the session's grants and passes them to `decide`.
- Dashboard: a feed row with a non-empty `grant_dir` gets a button "Allow folder for this
  session", which shows the directory and posts it after confirmation. No JS test harness
  exists; checked by hand.

Hard denies still apply inside every root: granting `C:\Users\me` does not make `.ssh/id_rsa`,
`.env` or `.agentwarden/` readable.

## Interface

- `rules.evaluate(event, extra_roots: Sequence[str] = ()) -> Verdict | None` (callers that pass
  nothing behave as before, plus the boundary).
- `rules.command_path_tokens(command) -> list[tuple[str, str]]` — `(command_word, token)` pairs;
  `policy._command_path_tokens` keeps working (reuses it).
- `policy.match` is split into `match_deny(policy, event)` and `match_rest(policy, event)`
  (ask, read-only profile, allow); `match()` stays as `match_deny(...) or match_rest(...)`.
- `models.Verdict.grant_dir: str | None = None`; store `decisions.grant_dir TEXT` (added by the
  existing missing-column migration); `/log` rows include it.
- Session grants are deduplicated by normalised path (case-insensitive, `\` → `/`, trailing
  slash dropped); the first spelling is the one stored and listed.
- `decide.decide(event, context=None, provider=None, cascade=None, *, extra_roots=())`.
- `policy.Policy.extra_roots: list[str] = []`.
- `store.Store.add_session_root(session_id, path) -> bool`, `session_roots(session_id) -> list[str]`.
- Daemon: `POST /session/roots`, `GET /session/roots`.

## Failure paths

- Store unavailable when reading grants → no session grants (stricter, never wider); `/decide`
  still answers. Audit-log failure keeps its existing behaviour (`ask`).
- `POST /session/roots` without / with a wrong token → 403, nothing stored. Invalid path → 400.
- Malformed `tool_input` (non-string paths) → field ignored as today; Bash tokenizer failure →
  falls back to whitespace split as today.
- Policy file invalid → defaults (no `extra_roots`), one warning, as today.
- Nothing in this spec can turn a hard deny into anything else, and nothing can produce
  `allow` for a path outside the roots.

## Acceptance criteria

- [x] `test_glob_absolute_pattern_outside_denied` — the `C:/Users/**/*.docx` case.
- [x] `test_grep_path_outside_denied`, `test_glob_relative_pattern_inside_allowed`.
- [x] `test_read_write_edit_outside_ask` (incl. `~/.gitconfig`, `../other/x`).
- [x] `test_bash_listing_outside_denied` — `ls C:/Users`, `find /etc -name x`,
      `Get-ChildItem C:\Users -Recurse`, `rg foo ../other`.
- [x] `test_bash_path_outside_ask` — `cat ../other/x.py`, `cp a.txt /tmp/a.txt`.
- [x] `test_bash_inside_and_device_tokens_unchanged` — `ls src`, `pytest tests/`,
      `cmd 2>/dev/null`, `git log origin/main`, `C:/Python312/python.exe x.py`.
- [x] `test_boundary_reason_names_dashboard_grant` — reason text and `grant_dir` agree;
      unresolved-variable path → no `grant_dir`.
- [x] `test_bash_unresolved_variable_path_outside` — `cat $FOO/x`, `cat /tmp/$X/y` → ask.
- [x] `test_policy_match_split_equivalent` — `match` == `match_deny or match_rest` on the
      existing policy test events.
- [x] Store/log: `grant_dir` round-trips through `add_decision` → `/log`.
- [x] `test_boundary_ask_judge_deny_wins`, `test_boundary_ask_judge_cannot_loosen` (allow,
      timeout, unparsable → ask), `test_boundary_ask_without_judge_stays_ask`,
      `test_boundary_deny_does_not_call_judge`, `test_bash_wildcard_grant_dir_has_no_wildcard`.
- [x] Existing `test_destructive_denied` (`rm -rf /`) stays `deny` (built-in default deny beats
      boundary ask).
- [x] `test_extra_roots_from_policy_allow_inside` and `test_extra_roots_rejects_relative_and_fs_root`.
- [x] `test_session_root_widens_boundary` — `evaluate(..., extra_roots=[...])`.
- [x] `test_granted_root_keeps_hard_denies` — `.ssh/id_rsa`, `.env` under a granted root → deny.
- [x] `test_policy_allow_cannot_cross_boundary` — `allow_commands: [ls]`, `ls C:/Users` → deny.
- [x] `test_policy_deny_beats_boundary_ask`.
- [x] `test_read_only_mode_outside_read` — read-only profile + outside read → `ask` (boundary).
- [x] Store: `test_session_roots_add_list_isolated_per_session`, duplicate → `added: false`.
- [x] Daemon: `test_session_roots_requires_token`, `test_session_roots_rejects_invalid_path`,
      `test_decide_uses_session_roots`, `test_decide_store_failure_no_grants`.
- [x] Existing tests green, or changed only where the old expectation was the bug (listed in
      the commit message).
- [x] `make eval-rules` run; every changed case listed in `eval/CHANGELOG.md`.
- [x] `make test` green, `make lint` clean.
- [x] Reviewer findings fixed: Glob/Grep pattern with `..` after a wildcard (was `allow`),
      PowerShell `-Path:value`, variables from the daemon env no longer trusted, unexpandable
      `$HOME` counts as outside (tests in `test_boundary.py`, 781 tests green).

## Out of scope

- Symlink / junction resolution (paths stay lexical). Separate spec: needs filesystem access in
  the rules, which today has none.
- Revoking a grant from the dashboard (grants end with the session).
- Making scanner taints force `ask` (separate small spec).
- Detecting the agent changing `cwd` to widen the boundary (`cd /` then relative paths): the hook
  payload's `cwd` is the only project root we have. VERIFY whether Claude Code reports a
  changed Bash cwd in the hook payload; if it does, this needs its own spec.

## Demo impact

Yes, if shown: the agent tries `Glob C:/Users/**/*.docx` → blocked with a reason that tells the
user how to grant access; the dashboard row has the grant button.
