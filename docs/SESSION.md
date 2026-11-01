# Session state — 2026-11-01 (last code commit e185abc)

Done: spec 022 (`e185abc`) — cascade escalates to Muse Spark when the action shows obfuscation
signals (`src/agentwarden/obfuscation.py`: `decode_exec`, `decode_blob`, `ps_encoded`,
`char_codes`, `dynamic_import`, `eval_indirection`), whatever the local confidence; a local
`deny` stays final; `WARDEN_ESCALATE_OBFUSCATION=0` disables. Reviewer found quadratic regex
gaps (1 MB `powershell`/`openssl`-repeat content > 15 s) — fixed with bounded gaps, plus
perf tests. Signals are scanned over all of `tool_input` joined (split decode/sink caught),
`old_string` skipped.

Offline check: on `eval/cases/` signals fire on 5 deny cases only (254, 257, 245, 242, 249),
**no benign case**, so main FPR cannot move from this mechanism (only from model noise).

Eval (cascade, v1 prompt, `36c2cff`): 257 allow → deny via Spark; main acc 0.953, detection
1.000, FPR 5.5% (was 11.0%, but that drop is 8B noise, not this change); holdout acc 0.926,
detection 1.000 (contaminated). Logged in `eval/CHANGELOG.md`, README and `meta-api` skill
updated. README cost column ($0.0055) is the 31 Oct figure: this run reported cost 0.0 (pricing
env not set), escalation rate is unchanged at 0.125.

Spec 024 (read-only policy profile, `mode: read_only` in policy.yaml): only Read/Glob/Grep inside
the project allowed, everything else `ask`, allow_* ignored, no model call. Idea not yet a spec
(023, Opus, Large): cascade escalates on prompt-injection phrases in the action (like 022 for
obfuscation: "ignore previous", "as the reviewer", fake verdict JSON) so a local `allow` is never
final for them; measure on `judge_attack`.

Spec 025 (project boundary): search/listing outside the project → deny; file or shell path
outside → ask that the judge may only tighten; `extra_roots` in policy and per-session grants
(`POST /session/roots` with UI token, dashboard button "Allow folder for this session").
Reviewer found `Glob **/../../x` → allow; fixed with tests. Dashboard button not checked in a
real browser yet. Cascade not re-run: expect `benign-readsshconfig-240` allow → ask.

Next (Sonnet): nothing queued; pick from "Waiting for the human" or the open problems.

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
