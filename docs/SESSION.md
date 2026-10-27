# Session state — 2026-10-27

Done: spec 002 implemented and committed (af57fed): models, decide (always ask), SQLite store, daemon with fail-safe `/decide`. 51 tests, ruff clean.
Spec 003 written on Opus: `docs/specs/003-builtin-rules.md` (Size: large) — `rules.py` with secret + self-protection hard denies, built-in destructive/ask/allow defaults, policy stage left as an empty slot; `decide()` uses rules, falls back to ask/default. Self-protection moved out of `backlog/policy-and-notifications.md` into 003.

In progress: nothing.

Next: spec 003 implementation on Sonnet — planner → test-writer → implement → reviewer. Then the policy spec (from backlog, Size: large).

Open problems:

- Manual check for 002 and 003 (`make run` + curl) — the agent sandbox blocks port binding/curl; run by hand.
- Hook scripts run from `${CLAUDE_PROJECT_DIR}/hooks/`, editable by the agent. The hook-wiring spec must install them under `~/.agentwarden/hooks/` (covered by the 003 `.agentwarden` rule).
- `examples/settings.agentwarden.json` hardcodes `python3`; plain Windows needs `python`. Fix in the hook-wiring spec.
- Meta API credits pending; `meta-api` skill VERIFY items unconfirmed.
