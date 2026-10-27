# Session state — 2026-10-28 (night run, autonomous)

Done (commits on main, not pushed):

- 007 fix: eval runner survived cp1252 consoles; seed candidates
  `eval/candidates/20261028-seed.jsonl` (75 action cases) and
  `eval/candidates/content-20261028-seed.jsonl` (40 scanner docs, 20/20).
- 008: policy `deny_paths`/`ask_paths` also match paths inside Bash/PowerShell commands (never
  `allow_paths`).
- 009: judge v1 — `redact.py`, `providers/` (base, mock, openai_compat on plain httpx, meta_api,
  local), `judge.py`, thresholds in `decide.py`, session context in the daemon, eval modes
  `spark`/`local`. Reviewed (Opus reviewer); all findings fixed (redaction gaps, ReDoS, test env
  isolation in `tests/conftest.py`, total HTTP deadline, nan/inf env, conflicting verdict JSON).
- 010: cascade — `cascade.py` (local first, Spark on low confidence / mid risk / local failure,
  7 s budget, `WARDEN_LOCAL_TIMEOUT` 3 s), `WARDEN_JUDGE=cascade`, audit columns
  `decided_by/escalated/local_decision/confidence`, eval `local_share`/`escalation_rate`.
- 011: `on_prompt.py` POSTs the prompt to `/event` (loopback only, 2 s) so the judge has the task.
- 012: verdict cache (`providers/cache.py`; eval always, daemon with `WARDEN_CACHE=on`),
  `cost_per_100` in eval.
- 013: injection scanner — `hooks/on_read.py` (PostToolUse Read|WebFetch), daemon `/scan`,
  `scanner.py`, session taints shown to the judge, `make eval-scan` (`evalscan.py`). Reviewed;
  findings fixed (NUL bypass, unverified quote, redaction before cut, scan concurrency cap,
  bounded extraction, unique taints).
- chore: all files normalised to LF, `.gitattributes` pins `eol=lf`.

Waiting for the human:

1. Write `prompts/judge.md` and `prompts/scanner.md` — drafts in `docs/handoff/`. Until then the
   judge and scanner return fail-safe `ask` / no warning ("prompt not written").
2. Review labels in `eval/candidates/*.jsonl`, promote to `eval/cases/` and `eval/content/`
   (~20% to `holdout.jsonl`). Check `benign-exportdotenvlocal-164` (built-in secrets deny fires).
3. Meta API credits → set `META_API_KEY`, run the `meta-api` skill first-request checklist
   (base URL, model id `muse-spark-1.2`, JSON mode), then `make eval MODE=spark`.
4. Local-model spike (`docs/specs/backlog/local-model-spike.md`) → `WARDEN_LOCAL_BASE`/`MODEL`,
   then `make eval MODE=cascade` and `make eval-scan`.
5. Manual checks: real PostToolUse payload shape (`tool_response`) for Read and WebFetch;
   demo README warning in a real session; spec 005 leftover (hook `allow` vs settings deny).
6. Note: a subagent ran `pip install openai` into the system Python (C:\Python313) during the
   night; the code no longer imports `openai` (providers use httpx). Uninstall if unwanted.

Open problems:

- `uv` is not on PATH in the Claude Code shell; tests/lint run with `python -m pytest` /
  `python -m ruff`.
- Git Bash heredocs turn `\\` into `\` (corrupted `\n`/`\x00` in edits twice). Write Python edit
  scripts with the Write tool, or use Edit, when the text contains backslashes.
- Hook suite ~45 s (loopback refusals on Windows).
