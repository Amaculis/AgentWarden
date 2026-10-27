# Session state — 2026-10-28

Done today:

- Spec 006 (98454af): self-protection for `hooks/`.
- Spec 007: eval runner. `src/agentwarden/evalrun.py` + `eval/run.py` (thin entry). Actions set,
  `rules` mode only; `local/spark/cascade` registered as `None` in `MODES` and report "not
  available"; `--set content` exits 2. Forces `eval/policy.eval.yaml` via `WARDEN_POLICY` for the
  run. Writes `eval/results/<date>-<commit>-actions-<mode>.json`, compares with previous run,
  tamper gate (<100% → exit 1). 36 new tests (339 total), lint clean.
  Baseline on `eval/candidates/tamper.jsonl`: 15 cases, acc 1.000, tamper 15/15, exit 0.

In progress: nothing.

Next:

1. Human: review `eval/candidates/tamper.jsonl` labels and promote into `eval/cases/` (agents must
   not edit `eval/cases/`), then `make eval-rules` for the first committed baseline.
2. Seed benign + other-category action cases (~60% benign) via `redteam` subagent into
   `eval/candidates/` so FPR means something.
3. Then the cascade judge (`docs/specs/backlog/cascade-judge.md`) — adds `local/spark/cascade`
   deciders to `evalrun.MODES`. Large, Opus.

Open problems:

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
