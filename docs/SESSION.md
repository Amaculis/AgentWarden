# Session state — 2026-10-30 23:40 (last commit 9d9d587)

Done since the night run: all three prompts written by the human and transferred
(`prompts/judge.md`, `prompts/scanner.md`, `prompts/redteam.md`, all `Version: 1`) · all 203
eval candidates reviewed and promoted (155 action cases in `eval/cases/*.jsonl` by category +
`holdout.jsonl`, 65 content cases in `eval/content/*.jsonl` + `holdout.jsonl`; only relabel was
`~/.ssh/config`, spec 021, which also fixed the rule) · `META_API_KEY` connected, `meta-api`
skill first-request checklist done · first real `make eval MODE=spark`: accuracy 0.953 main /
0.889 holdout, detection_rate 1.000, tamper 12/12, $0.215/100 actions
(`eval/results/2026-10-29-2b2522b-actions-spark.json`) · first real `make eval-scan`: recall
0.962 main / 1.000 holdout, precision 1.000 on both
(`eval/results/2026-10-29-eb9db41-content-scan.json`) · along the way, found and fixed that
Muse Spark is a reasoning model whose hidden reasoning tokens vary run-to-run even at
temperature=0 — raised `MAX_TOKENS` in `judge.py` (2000) and `scanner.py` (3000),
`WARDEN_SCAN_TIMEOUT` 5s→7s; details and numbers in the `meta-api` skill · red-team loop fixed
(generator token/timeout budget now scales with `--batch`, default batch 20→5; examples no
longer sampled from `holdout.jsonl`) and run for real: 4 rounds / 15 dangerous cases, 0
bypasses, 0 over-blocks, ~$0.19 total (`redteam/runs/2026-10-30*`) · dashboard page built by
Muse Code (`muse-spark-1.3`, Standard tier) per `docs/handoff/015-dashboard.md`, reviewed and
fixed (source filter matched nothing for judge/policy, rule editor reset every 2s poll,
unbounded row growth) — not yet opened in a real browser.

Waiting for the human (in this order):
1. Install Ollama + a ~3B model (Llama 3.2 3B first, 3.1 8B for comparison), raise
   `OLLAMA_CONTEXT_LENGTH` (default is too small for our prompt + document), set
   `WARDEN_LOCAL_BASE` / `WARDEN_LOCAL_MODEL`. Then: `make eval MODE=local`,
   `make eval MODE=cascade`, `make eval-scan` (local), record p50/p95/parse-failures in the
   `meta-api` skill. This is the critical path — cascade cannot run without it, and the
   four-mode comparison table is the main demo evidence.
2. Muse Code: README (`docs/handoff/018-readme.md`) — prompt already given to the human in
   this session, numbers above included.
3. Manual: open the dashboard in a real browser (`make run`, VS Code Simple Browser) and click
   through — only tested via TestClient and static review so far. Real PostToolUse
   `tool_response` shape for Read/WebFetch still unverified. Demo dry run (`docs/demo.md`).
4. Delete `muse-install.ps1` from repo root (untracked, harmless, just clutter) and the
   `backup/pre-secret-fix` branch if the user is done with it.
5. Review: drop `openai` from `pyproject.toml` (code no longer imports it; a subagent installed
   it into system Python earlier, not from this repo).

Open problems / limitations:
- Known: any local process can POST `/event` and plant a fake "user prompt" (spec 018).
- `uv` not on PATH in the Claude Code shell: use `python -m pytest` / `python -m ruff`.
- Git Bash heredocs turn `\\` into `\`: write edit scripts with the Write tool, or use Edit.
- Red-team default batch is 5; batches above 5 are untested against the real API's max output.
- Next for Claude after Ollama is up: judge tuning on real cascade numbers (`judge-tuning`
  skill) — architecture-level, likely wants Opus.
