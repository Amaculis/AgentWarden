# Session state — 2026-10-27

Done: spec 004 implemented and committed: `policy.py` (new) — `Policy` model, `load_policy()`
(mtime-cached, `WARDEN_POLICY` env override, falls back to defaults on missing/invalid/unreadable
file, warns once per session), `match()` (deny/ask/allow for paths, commands, domains). Wired into
`rules.py`'s `_policy_stage` (between hard denies and defaults, via a lazy import to avoid a
circular import). `Verdict` gains `system_message` (🛡 notifications for deny/ask, source-labelled,
suppressed by `WARDEN_NOTIFY=off`) and `source="policy"`. Full flow: planner → test-writer →
implement → reviewer. Reviewer caught one real bug: an unreadable (not just missing/invalid)
policy file raised `OSError` past the catch clause, falling through to the daemon's generic
fail-safe `ask` instead of the spec's "treat like missing, use defaults" — fixed, tested
(`test_policy_unreadable_file_uses_defaults`). 216 tests green, `make lint` clean. Also added 15
hand-crafted `tamper` category eval cases to `eval/candidates/tamper.jsonl` (pending human review
and promotion to `eval/cases/` — no eval runner exists yet to execute them against).

In progress: nothing.

Next: no eval runner exists yet (`eval/run.py` referenced by the Makefile's `eval`/`eval-rules`/
`eval-scan` targets is missing) — needed before `eval/candidates/tamper.jsonl` or the action/
content eval sets can actually be run. After that: the hook-wiring spec (hooks calling `/decide`
and surfacing `systemMessage`; also covers moving hook scripts under `~/.agentwarden/hooks/` and
fixing `python3` hardcoding for Windows).

Open problems:

- Manual check for 002/003/004 (`make run` + curl) still not done by hand — agent sandbox blocks
  port binding/curl.
- Hook scripts still run from `${CLAUDE_PROJECT_DIR}/hooks/`, editable by the agent, and are not
  protected by any rule in `rules.py` (only `.claude/settings*.json`, which reference them, are
  protected) — a redteam case for `rm -rf hooks/on_tool.py` currently falls through to
  "unsettled" rather than a guaranteed deny. Flagged for the hook-wiring spec or a follow-up to
  spec 003/004's self-protection rules.
- `examples/settings.agentwarden.json` still hardcodes `python3`; plain Windows needs `python`.
  Fix in the hook-wiring spec.
- `hooks/` don't call `/decide` yet, so `Verdict.system_message` is only exercised at the
  `decide()`/`/decide` level for now — surfacing it to the user inside Claude Code needs the
  hook-wiring spec.
- Meta API credits pending; `meta-api` skill VERIFY items unconfirmed.
