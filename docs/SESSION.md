# Session state — 2026-10-28 02:10 (night run done; nothing pushed)

Done tonight (specs 008–020, all `make test`/`lint` green, 627 tests): 008 policy paths in shell
commands · 009 judge v1 (providers on httpx, redaction, fail-safe, thresholds) · 010 cascade ·
011 prompt → `/event` · 012 verdict cache + cost · 013 injection scanner (`on_read.py`,
`/scan`, taints) · 014 Meta red-team loop · 015 dashboard backend (page = Muse Code handoff) ·
016 safer alternative · 017 demo project + run sheet · 018 security hardening · 019 `~`/`$HOME`
paths · 020 browser/cloud secrets + 2 ReDoS fixes · LF normalisation. Large specs reviewed by
an Opus reviewer; all findings fixed. Candidates: 155 action + 65 content in `eval/candidates/`.

Waiting for the human (in this order):
1. Write `prompts/judge.md`, `prompts/scanner.md`, `prompts/redteam.md` (drafts in
   `docs/handoff/`). Until then judge/scanner/red-team return ask / no warning / "not available".
2. Review candidate labels, promote to `eval/cases/` + `eval/content/` (~20% holdout). Check:
   `benign-exportdotenvlocal-164`, `benign-readenvlocalgo-218`, `benign-readsshconfig-240`
   (built-in secrets deny fires on `.env.local`, `~/.ssh/config` — relabel or accept as FP).
3. Credits: `META_API_KEY`, `meta-api` skill first-request checklist, `make eval MODE=spark`.
4. Local-model spike (`docs/specs/backlog/local-model-spike.md`, steps updated), then
   `make eval MODE=cascade`, `make eval-scan`, `make redteam ROUNDS=1`.
5. Muse Code: `docs/handoff/015-dashboard.md` (page), `docs/handoff/018-readme.md` (README).
6. Manual: real PostToolUse `tool_response` shape (Read/WebFetch); demo dry run
   (`docs/demo.md`); spec 005 leftover (hook allow vs settings deny).
7. A subagent ran `pip install openai` into C:\Python313; code no longer imports `openai`
   (still listed in pyproject.toml — drop it with `uv remove openai` if you agree).

Open problems / limitations:
- Known: any local process can POST `/event` and plant a fake "user prompt" (spec 018).
- `uv` not on PATH in the Claude Code shell: use `python -m pytest` / `python -m ruff`.
- Git Bash heredocs turn `\\` into `\`: write edit scripts with the Write tool.
- Next for Claude after the human steps: judge tuning on real numbers (`judge-tuning` skill), Opus.
