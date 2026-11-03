# 037 — Easy install: `agentwarden init` and a self-contained package

Size: large

## Context

Today a user clones the repo, runs `make install`, starts the daemon with `make run` and
hand-merges hook settings that point at `${CLAUDE_PROJECT_DIR}/hooks/...`, which means the hook
scripts must be copied into every protected project. The judge and scanner prompts are read from
the repo root, so an installed wheel would fail-safe every judged action to `ask`. This spec makes
AgentWarden installable as one tool and wires a project in one command.

## Behaviour

```sh
uv tool install git+https://github.com/Amaculis/AgentWarden    # or: pipx install git+...
agentwarden serve                    # daemon on 127.0.0.1:8765 (same as `make run`)
cd my-project && agentwarden init    # adds the hooks to .claude/settings.local.json
```

`agentwarden init [PROJECT] [--shared]`:

- Writes AgentWarden's three hooks (`UserPromptSubmit`, `PreToolUse` `*`,
  `PostToolUse` `Read|WebFetch`) into `PROJECT/.claude/settings.local.json` (default; the paths are
  machine-specific) or `settings.json` with `--shared`.
- Each command is `"<python>" "<installed hooks dir>/on_tool.py"`, absolute, forward slashes:
  `<python>` is the interpreter running `agentwarden` (stdlib is all the hooks need), the hooks
  dir is the copy shipped inside the package.
- Merges: keeps every other key and every other hook; replaces earlier AgentWarden entries
  instead of duplicating them (running `init` twice gives the same file).
- Prints what it wrote and the next step (`agentwarden serve`, judge env vars).

`agentwarden uninstall [PROJECT] [--shared]` removes only AgentWarden's entries; empty event lists
and an empty `hooks` object are dropped.

`agentwarden status` prints the installed hooks dir, whether the daemon answers `/health`, and the
judge configuration (`WARDEN_JUDGE`, whether `META_API_KEY` and `WARDEN_LOCAL_BASE` are set; never
their values).

`python -m agentwarden ...` is the same CLI.

Packaging: the wheel ships `hooks/` as `agentwarden/hooks/` and `prompts/` as
`agentwarden/prompts/`. The judge and scanner use the packaged copy when present and the repo's
`prompts/*.md` otherwise (dev checkout); `WARDEN_JUDGE_PROMPT` / `WARDEN_SCANNER_PROMPT` still
override.

Self-protection (built-in hard denies, policy cannot override):

- A shell command that runs the AgentWarden CLI with `init`, `uninstall` or `serve`
  (`agentwarden …`, `agentwarden.exe …`, `python -m agentwarden …`) → `deny`.
  `status`, `--help`, `--version` are not matched.
- A shell command that uninstalls the package (`pip`/`pip3`/`uv pip`/`pipx`/`uv tool` +
  `uninstall` + `agentwarden`) → `deny`.
- A modifying file tool (`Write`, `Edit`, `MultiEdit`, `NotebookEdit`) on a path inside the
  installed `agentwarden` package directory (hooks, prompts, rules) → `deny`, on the lexical path
  and the resolved target. Not applied when the project is the AgentWarden checkout itself.
- A shell command naming an installed copy (`site-packages/agentwarden`,
  `dist-packages/agentwarden`, `uv/tools/agentwarden`, `pipx/venvs/agentwarden`) → `deny`.
- `uvicorn agentwarden.daemon:app` (a second daemon under the agent's control) → `deny`.
- Indirection outside the AgentWarden checkout → `deny`: Python imports of the package
  (`python -c "from agentwarden.cli import main; ..."`, `agentwarden.__file__`), aliases and
  functions wrapping `agentwarden`, variables holding the command.
- The CLI match needs command position (start, after a separator, `$(`, `bash -c`, `-Command`,
  `cmd /c`, behind `uv run`/`uvx`/`python -m`/`env`/`VAR=x`/PowerShell `&`), so mentions such as
  `grep 'agentwarden serve' README.md` are not hard-denied.
- `agentwarden status` only contacts `WARDEN_URL` when it is plain http on loopback (like the
  hooks); anything else falls back to the default URL.

## Interface

- `src/agentwarden/cli.py`: `main(argv: list[str] | None = None) -> int`; subcommands `init`,
  `uninstall`, `status`, `serve`.
- `src/agentwarden/__main__.py`: `raise SystemExit(cli.main())`.
- `src/agentwarden/resources.py`: `PACKAGE_DIR`, `hooks_dir() -> Path`,
  `prompt_path(name: str) -> Path`.
- `pyproject.toml`: `[project.scripts] agentwarden = "agentwarden.cli:main"`, hatch
  `force-include` for `hooks` and `prompts`, version `1.0.0`.
- `src/agentwarden/rules.py`: `_cli_rule` (new stage in the hard-deny list), package-dir check in
  the file-path self-protection.

## Failure paths

- `settings*.json` is not valid JSON or not an object → `init`/`uninstall` exit 1, file untouched.
- Hooks dir missing in the install (broken wheel) → `init` exits 1, nothing written.
- Project dir does not exist → exit 1.
- `status` with the daemon down → prints "daemon: not running", exit 0.
- Packaged prompt missing → existing judge/scanner fail-safe (`ask`).
- Hook behaviour is unchanged: daemon down, timeout or bad output → `ask`.

## Acceptance criteria

- [x] `test_init_creates_local_settings` — empty project → `.claude/settings.local.json` with the
  three hooks, absolute paths to `resources.hooks_dir()`.
- [x] `test_init_is_idempotent` — running twice gives byte-identical output.
- [x] `test_init_keeps_other_settings_and_hooks` — existing keys and foreign hooks survive.
- [x] `test_init_shared_writes_settings_json`
- [x] `test_init_invalid_json_untouched` — exit 1, file unchanged.
- [x] `test_uninstall_removes_only_agentwarden`
- [x] `test_status_daemon_down` — exit 0, no secret values printed.
- [x] `test_prompt_path_prefers_package_then_repo`
- [x] `test_cli_init_uninstall_serve_denied` (Bash and PowerShell, `python -m` form)
- [x] `test_cli_status_help_not_denied`
- [x] `test_pip_uninstall_agentwarden_denied`
- [x] `test_edit_installed_package_denied`
- [x] `test_cli_indirection_denied`, `test_mentions_of_cli_not_hard_denied`,
  `test_daemon_url_only_loopback`
- [x] wheel (`pip wheel .`) contains `agentwarden/hooks/on_tool.py` and `agentwarden/prompts/judge.md`
- [x] `make test` green, `make lint` clean
- [x] README Quick start shows the install + `init` path, including the no-cloud option

## Out of scope

- Publishing to PyPI.
- Running the daemon as a background service or at login.
- Installing Ollama or pulling a model.
- `init` for agents other than Claude Code.
- Changing the hook scripts themselves.
- Indirection the regexes cannot see (e.g. a script file written earlier and run later, a
  binary renamed on disk). Those actions still go through the judge, and the obfuscation and
  manipulation escalations.

## Review

Reviewer findings (applied): `python -c` / `__file__` / alias bypasses, false positives on
`grep 'agentwarden serve'`, `WARDEN_URL` side channel in `status`. Regex repeats are bounded;
100 KB worst cases stay under 0.5 s.

## Demo impact

None for the recorded demo. README Quick start gets shorter.
