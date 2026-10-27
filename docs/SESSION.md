# Session state — 2026-10-28

Done today:

- Spec 006 (98454af): self-protection for `hooks/`. `rules.py` gained `_hooks_rule`, denying
  read/write/edit and shell rm/mv/del against the project's top-level `hooks/` directory, same
  hard-deny tier as `.agentwarden/` and `.claude/settings*.json`; user policy allow rules can't
  override it. 12 new tests (303 total), lint clean. Closes SESSION.md item 2 from last session.

In progress: nothing.

Next:

1. Eval runner `eval/run.py` (Makefile's `eval`, `eval-rules`, `eval-scan` targets reference it,
   file still missing) — needed to run `eval/candidates/tamper.jsonl` (15 cases, spec 004) and any
   future eval sets. Touches multiple modes (rules/local/spark/cascade) and metrics — likely
   **Size: large**, so write the spec on Opus, then `planner` → `test-writer` → implement →
   `reviewer`. Read the `eval-case` skill first for the case schema and metrics before writing the
   spec.
2. After the eval runner exists: promote the reviewed `eval/candidates/tamper.jsonl` cases into
   `eval/cases/` and run `make eval-rules` to get a real baseline number.

Open problems:

- Hook test suite takes ~34 s total for the full suite, mostly because many tests connect to a
  closed loopback port and Windows takes ~2 s to refuse. Acceptable for now.
- `on_prompt.py` still only records locally; wiring it to `/event` waits for the judge spec.
- Future judge/cascade must keep `/decide` under ~7 s so the hook's 8 s deadline holds.
- Meta API credits pending; `meta-api` skill VERIFY items unconfirmed.
- Spec 005 has one unticked manual item left: confirm in the Claude Code hooks docs whether a hook
  `permissionDecision: "allow"` overrides `deny` rules in `settings.json` permissions (relevant to
  `WARDEN_ALLOW=explicit`). Also CLI (non-VS Code) rendering of `systemMessage` still unverified.
