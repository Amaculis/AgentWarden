# Session state — 2026-10-27

Done today:

- Spec 004 (30a7d73): user `policy.yaml`, policy stage in `rules.py`, `Verdict.system_message`,
  15 tamper candidates in `eval/candidates/tamper.jsonl` (pending human review).
- Spec 005 (spec 90b7ac1, tests 4b90b38, implementation in the next commit): `hooks/on_tool.py`
  now calls `/decide` and fails closed. Stdlib-only urllib, 8 s wall-clock deadline via a worker
  thread, proxies and redirects disabled, loopback-only `WARDEN_URL`, ASCII-only stdout,
  `allow` → passthrough by default (`WARDEN_ALLOW=explicit` opt-in, user decision). Daemon
  fail-safe `ask`s now carry a 🛡 `system_message`. Windows example settings added. 291 tests
  green, lint clean, reviewer found nothing.

In progress: nothing.

Next:

1. Manual check of spec 005 in real Claude Code on Windows (human): copy
   `examples/settings.agentwarden.windows.json` into a scratch project, `make run`, ask the agent to
   `cat ~/.ssh/id_rsa` → deny with 🛡 line; stop daemon → "AgentWarden unavailable" ask. Record
   how `systemMessage` renders (VS Code + CLI) in the `hook-protocol` skill. Also check in the hooks
   docs whether a hook `allow` overrides `deny` rules in `settings.json`.
2. Self-protection for `hooks/` (Small): hook scripts under `${CLAUDE_PROJECT_DIR}/hooks/` are
   agent-editable and no rule protects them; `rm -rf hooks/on_tool.py` is not denied. Either a rule
   in `rules.py` or move hooks to `~/.agentwarden/hooks/`.
3. Eval runner `eval/run.py` (Makefile targets reference it, file missing) — needed to run
   `eval/candidates/tamper.jsonl` and the future eval sets.

Open problems:

- Hook test suite takes ~34 s, mostly because many tests connect to a closed loopback port and
  Windows takes ~2 s to refuse. Acceptable for now.
- `on_prompt.py` still only records locally; wiring it to `/event` waits for the judge spec.
- Future judge/cascade must keep `/decide` under ~7 s so the hook's 8 s deadline holds.
- Meta API credits pending; `meta-api` skill VERIFY items unconfirmed.
