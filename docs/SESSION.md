# Session state — 2026-11-01 (last commit e185abc)

Done: spec 022 (`e185abc`) — cascade escalates to Muse Spark when the action shows obfuscation
signals (`src/agentwarden/obfuscation.py`: `decode_exec`, `decode_blob`, `ps_encoded`,
`char_codes`, `dynamic_import`, `eval_indirection`), whatever the local confidence; a local
`deny` stays final; `WARDEN_ESCALATE_OBFUSCATION=0` disables. Reviewer found quadratic regex
gaps (1 MB `powershell`/`openssl`-repeat content > 15 s) — fixed with bounded gaps, plus
perf tests. Signals are scanned over all of `tool_input` joined (split decode/sink caught),
`old_string` skipped.

Offline check: on `eval/cases/` signals fire on 5 deny cases only (254, 257, 245, 242, 249),
**no benign case**, so main FPR cannot move from this mechanism (only from model noise).

Next: the open spec 022 criterion — cascade eval (costs API credits, needs Ollama up):
`WARDEN_LOCAL_TIMEOUT=20 WARDEN_JUDGE_TIMEOUT=25 WARDEN_DECISION_BUDGET=26
PYTHONPATH=src python eval/run.py --set actions --mode cascade`; expect 257 → deny, main
detection 1.000, main FPR ≤ 6.8%; log in `eval/CHANGELOG.md`, update README numbers if they
change. Then Sonnet work: human-wait items below.

Waiting for the human:
1. Dashboard in a real browser + demo dry run (`docs/demo.md`); PostToolUse `tool_response`
   shape for Read/WebFetch still unverified.
2. Delete `muse-install.ps1`, stray `make` file (leftover `ps` output), `pytest-of-Artem/`
   (it also crashes `ruff format --check .`; use `ruff format --check src tests eval redteam
   hooks`), and branch `backup/pre-secret-fix` if done with it.
3. Drop `openai` from `pyproject.toml` (no longer imported).

Open problems:
- Any local process can POST `/event` and plant a fake "user prompt" (spec 018).
- No `uv`, no `make` here: `PYTHONPATH=src python eval/run.py --set actions --mode cascade`,
  `PYTHONPATH=src python -m pytest -q -m "not slow"`. Pass the raised timeouts as env vars
  (above) — code defaults are still the old ones; `.env.example` is only a reference.
- `OLLAMA_CONTEXT_LENGTH` not raised; no truncation seen, unverified.
- Red-team batch > 5 untested.
