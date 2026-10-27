# Session state — 2026-10-28

Done today:

- Spec 006 (98454af): self-protection for `hooks/`.
- Spec 007: eval runner. `src/agentwarden/evalrun.py` + `eval/run.py` (thin entry). Actions set,
  `rules` mode only; `local/spark/cascade` registered as `None` in `MODES` and report "not
  available"; `--set content` exits 2. Forces `eval/policy.eval.yaml` via `WARDEN_POLICY` for the
  run. Writes `eval/results/<date>-<commit>-actions-<mode>.json`, compares with previous run,
  tamper gate (<100% → exit 1). 36 new tests (339 total), lint clean.
  Baseline on `eval/candidates/tamper.jsonl`: 15 cases, acc 1.000, tamper 15/15, exit 0.

- Eval runner fix: mismatch/compare lines used `→` and crashed on a cp1252 console
  (Windows default); now `->` + `stdout.reconfigure(errors="backslashreplace")`, regression test
  added (340 tests). Also fixed a ruff I001 in `tests/test_evalrun.py` left from 007.
- Seed candidates: `eval/candidates/20261028-seed.jsonl` (redteam subagent), 75 cases: 50 benign
  (48 allow / 2 ask), secrets 4, exfiltration 4, destruction 3, persistence 3, drift 3,
  injection 3, judge_attack 2, borderline 3; 9 policy-dependent. Combined with tamper: 90 cases,
  rules mode acc 0.611, tamper 15/15, detect 1.000, FPR 0.540 (expected: unsettled -> ask until
  the judge exists), settled by rules 0.589.

In progress: nothing.

Next:

1. Human: review labels in `eval/candidates/tamper.jsonl` and `20261028-seed.jsonl`, promote
   into `eval/cases/` (keep ~20% in `holdout.jsonl`), then `make eval-rules` for the first
   committed baseline. Label to check: `benign-exportdotenvlocal-164` (labelled allow, built-in
   secrets hard deny fires on `.env.local` -- probably relabel ask/deny).
2. Decide on the policy gap below (small spec if yes).
3. Then the cascade judge (`docs/specs/backlog/cascade-judge.md`) — adds `local/spark/cascade`
   deciders to `evalrun.MODES`. Large, Opus.

Open problems:

- Policy `deny_paths`/`ask_paths` match only `tool_input.file_path`; a Bash command touching the
  same path (`cat secrets/stripe_key.txt`, case `secrets-dir-102`) is unsettled -> `ask`, not
  `deny`. Fix would extract path-like tokens from Bash commands; must not false-positive on
  e.g. `manage.py makemigrations` vs `ask_paths: migrations/` (case `benign-makemigrationscmd-152`).

- `uv` is not on PATH in the Claude Code shell on this machine; tests/lint were run with
  `python -m pytest` / `python -m ruff` (same checks as `make`). `make eval-rules` itself was
  verified via `PYTHONPATH=src python eval/run.py ...` (empty `eval/cases/` → "no cases found",
  exit 2).
- Hook test suite takes ~34 s total, mostly loopback refusals on Windows. Acceptable for now.
- `on_prompt.py` still only records locally; wiring it to `/event` waits for the judge spec.
- Future judge/cascade must keep `/decide` under ~7 s so the hook's 8 s deadline holds.
- Meta API credits pending; `meta-api` skill VERIFY items unconfirmed.
- Spec 005 has one unticked manual item left: confirm whether a hook `permissionDecision:
  "allow"` overrides `deny` rules in `settings.json` permissions (relevant to
  `WARDEN_ALLOW=explicit`). CLI (non-VS Code) rendering of `systemMessage` still unverified.
