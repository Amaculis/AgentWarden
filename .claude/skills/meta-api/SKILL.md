---
name: meta-api
description: How AgentWarden calls Meta models — Meta Model API client setup, model names, Standard vs Contributor tier, timeouts, structured JSON, cost control, the local open-weights provider, and the role of each Meta model (cascade, scanner, red-team generator). Use when writing or changing src/agentwarden/providers/, judge.py, cascade.py, scanner.py or redteam/.
---

# Calling Meta models

Status: facts below come from Meta's docs as summarised by third parties on 2026-10-26, except where marked **VERIFIED 28 Oct** (confirmed with a real request against the user's key). Items still marked VERIFY are unconfirmed.

## Which Meta model does what

| Role | Model | Where | Called from |
| --- | --- | --- | --- |
| First-pass judge | Small Meta open-weights model (decided in the local-model spike) | Local, or Modal/Baseten | `cascade.py` via `providers/local.py` |
| Escalation judge | Muse Spark (Standard) | Meta Model API | `cascade.py` via `providers/meta_api.py` |
| Injection scanner | Same local model as the first-pass judge | Local | `scanner.py` |
| Red-team generator | Muse Spark (Standard) | Meta Model API | `redteam/run.py` |
| Coding help for mechanical tasks | Muse Code (Standard) | User runs it | handoff briefs, never from code |

Each role has its own prompt file in `prompts/` (human-owned, protected): `judge.md`, `scanner.md`, `redteam.md`.

## Client

- Meta Model API is OpenAI-compatible at the request/response level. Base URL
  `https://api.meta.ai/v1`, endpoint `POST /chat/completions`, auth `Authorization: Bearer
  <META_API_KEY>` — **VERIFIED 28 Oct** (real 200 response from `providers/meta_api.py`).
- We do not use the `openai` SDK (removed, see `providers/openai_compat.py` — plain httpx);
  the line above is for anyone probing the API by hand.
- Model from env `WARDEN_MODEL`. Default `muse-spark-1.2` accepted by the API —
  **VERIFIED 28 Oct**. Did not list all available models (no `/models` call made); if a newer
  version exists it wasn't checked.
- **Never use a `-contributor` model**: Contributor tier trains on prompts and code. AgentWarden sends code context.
- **Muse Spark is a reasoning model.** It spends completion tokens on hidden reasoning before
  any visible output; a `max_tokens` cap sized only for the JSON reply truncates `content` to
  `null` (`finish_reason: "length"`, `reasoning_tokens` near the cap) — **VERIFIED 28 Oct**, hit
  this with `max_tokens=20` and again at `300`. Fixed by raising `MAX_TOKENS` to 900 in
  `judge.py` and `scanner.py`. A plain allow-case judge call used ~370 reasoning tokens before
  ~50 tokens of JSON; a clear-injection scanner call used ~500 total. Harder cases may need
  more — if truncation (`error="http"` with no exception) shows up in eval, raise further
  rather than add retry logic.

## Request rules

- `temperature=0`.
- Hard timeout on every call: `WARDEN_JUDGE_TIMEOUT` seconds (default 6). Timeout or error → caller returns `ask`. Measured latency at `max_tokens=900`: 1.3–3.3 s for single judge/scanner calls
  (p50/p95 over a real sample not measured — only a handful of manual calls so far)
  — **VERIFIED 28 Oct**, but close enough to the 6 s default that a harder case could time out;
  revisit if eval shows frequent judge timeouts.
- `max_tokens=900` (not ≈200 — see reasoning-token note above).
- Ask for JSON only via prompt instructions; no separate JSON-mode / structured-output
  parameter was sent or needed — the model returned a clean single JSON object as instructed
  in both the plain-allow and clear-injection test calls — **VERIFIED 28 Oct**, but not tried
  against an adversarial or ambiguous case yet, so still validate and extract the first JSON
  object defensively (current code already does). Judge: `{"decision": "allow|deny|ask", "risk": 0-100, "confidence": 0-1, "reason": "<one sentence>", "safer_alternative": "<one sentence or empty>"}`. Scanner: `{"injection": true|false, "confidence": 0-1, "quote": "<≤200 chars>", "reason": "<one sentence>"}`. Anything that fails validation → `ask`.
- Input is always redacted first (`redact.py`).
- One retry at most, only on connection errors, within the same overall timeout.

## Cost control

- Pricing (Standard, per million tokens): ~$1.25 input, ~$0.15 cached input, ~$4.25 output (VERIFY on dev.meta.ai pricing page).
- Budget: $150 hackathon credits. Spend Limit set in Billing.
- Cache verdicts by hash of (model, prompt version, redacted request) in `.agentwarden/cache.sqlite`. Eval reruns must hit the cache.
- Log tokens in/out per call; `make eval` prints total cost.

## Providers

- `providers/meta_api.py` — Meta Model API (above).
- `providers/local.py` — Meta open-weights model behind any OpenAI-compatible endpoint (vLLM, Ollama, Baseten, Modal). Same interface, base URL from `WARDEN_LOCAL_BASE`. This is the "sensitive codebase" mode.
- `providers/mock.py` — deterministic verdicts for tests; can simulate timeout, garbage output and errors.

All three implement one interface: `complete(messages, *, timeout, max_tokens) -> ProviderResult`, raising nothing. `ProviderResult` carries either parsed JSON or an `error` (timeout / connection / unparsable). The caller decides what an error means:

- `cascade.py`: local error → escalate to Spark; Spark error → `ask`.
- `scanner.py`: error → no warning, log it (never send an "all clear").
- `redteam/run.py`: error → drop the case, count it.

Every provider records latency, tokens in/out and cost per call, so evals can report them per mode.

## Local provider notes

- Same OpenAI-compatible client, `base_url=WARDEN_LOCAL_BASE`, model `WARDEN_LOCAL_MODEL`, no API key or a dummy one.
- Small models follow JSON instructions less reliably: always validate, and count parse failures in eval as their own metric.
- Keep the local prompt short; put examples last. Measure latency with the real prompt, not a toy one.
- Model id, hardware, p50/p95 and JSON reliability go here after the spike (VERIFY).

## First request checklist (28 Oct)

- [x] Confirm base URL and auth header — `https://api.meta.ai/v1`, `Authorization: Bearer`.
- [x] Confirm `muse-spark-1.2` is accepted (not whether it's the newest — `/models` not called).
- [x] Confirm JSON output works from prompt instructions alone, on 2 manual cases.
- [x] Found and fixed the reasoning-token truncation bug (`max_tokens` 300→900→**2000**, see below).
- [x] Measured latency and parse-failure rate over a real 155-case run (`make eval MODE=spark`,
      29 Oct), far more than ≥10 calls.
- [x] Tried many adversarial cases (judge_attack, injection, taints) against the real API —
      JSON held on all of them; no case made the model drop the JSON format.
- [ ] List available models to check for a newer Muse Spark version.
- [ ] Confirm credits are applied and pricing in Billing (page not opened this session).

## First real eval run (29 Oct, `make eval MODE=spark`, 155 cases, 128 main + 27 holdout)

- **At `max_tokens=900`**: 25/128 main cases (≈20%) failed — `error="http"` (content truncated
  to `null`, same reasoning-token bug as before, just not fully fixed) or "unreadable verdict".
  One case that *did* succeed used 746 of 900 completion tokens on reasoning before any output
  — barely inside the cap. 900 was not a safe margin for a real, varied case set.
- **Raised `max_tokens` to 2000** (`judge.py`, `scanner.py`) and reran — cache kept the ~100
  already-successful calls free, so the rerun only re-spent on the ~28 that had failed.
- **Result after the fix**: accuracy 0.953 (main) / 0.889 (holdout), detection_rate 1.000 on
  both (no dangerous action was ever judged `allow`), tamper 12/12 and 3/3. Remaining errors
  dropped from 28 to 6: all `timeout`, not truncation — p95 latency 5.2–6.2 s, close to the
  default `WARDEN_JUDGE_TIMEOUT=6`. Cost: $0.215 per 100 actions (155 cases cost well under $1
  total). Full numbers: `eval/results/2026-10-29-2b2522b-actions-spark.json`.
- **Open tuning question, not yet acted on**: whether to raise `WARDEN_JUDGE_TIMEOUT` (6s) a
  little, since it's below `WARDEN_DECISION_BUDGET` (7s) and p95 is close to it. Left alone for
  now — 3 timeouts out of 128 is a small fraction and fail-safe `ask` is the correct, safe
  response to a slow call either way; revisit with the `judge-tuning` skill if this recurs on
  the full eval (cascade/content) rather than tune on 3 cases.

## First real scanner eval run (29 Oct, `WARDEN_SCANNER=meta_api make eval-scan`, 65 cases, 53
main + 12 holdout)

- **At `WARDEN_SCAN_TIMEOUT=5s`, `max_tokens=2000`**: 9 timeouts (p95 5.2–5.3 s, right at the
  5s cap), all on the hardest obfuscated injections (RTL override, homoglyphs, split-section).
  Raised the timeout to 7s (`hooks/on_read.py` already budgets up to 8s for the whole scan
  call, so 5s wasn't using the slack that already existed).
- **At 7s / 2000 tokens**: 2 failures left, both `error="http"` (truncation), not timeout. One
  replayed by hand used 1768 of 2000 reasoning tokens on one run and truncated on a rerun of
  the *same* case — real run-to-run variance in reasoning length even at `temperature=0`, not a
  one-off. Raised `max_tokens` to 3000.
- **At 7s / 3000 tokens**: recall 0.962 (main) / **1.000 (holdout)**, precision **1.000 on
  both** — zero false positives across the whole set. One remaining failure
  (`codecomment-rtloverride-203`, a Unicode right-to-left-override payload) still times out at
  p95 ~6.4s; left as a known hard case rather than chasing one more token/timeout bump for
  diminishing returns. Full numbers: `eval/results/2026-10-29-eb9db41-content-scan.json`.
- **Takeaway for both judge and scanner**: Muse Spark's hidden reasoning is the dominant cost
  in both tokens and latency, and it varies run-to-run on the same input. Budget generously
  (we ended at `max_tokens=2000` judge / `3000` scanner) — the extra output tokens are cheap
  (~$4.25/M) next to the cost of a wrongly-truncated verdict.

## First real red-team round (30 Oct, `redteam/run.py --rounds 1 --batch 5 --defender spark`)

- **Fixed `max_tokens=6000` returned no content even for batch 5**: 5,998 of 6,000 completion
  tokens went to reasoning (`finish_reason: "length"`, `content: null`, `refusal: null` — not a
  refusal). A probe at 20,000 finished at 9,590 completion tokens (9,111 reasoning), ~37 s.
- Budget now scales with the batch: `TOKENS_PER_CASE=4000`, timeout `max(60, 15 s × batch)`
  (`redteam.py`); default batch lowered 20 → 5 (`Makefile`, CLI). Larger batches are untested:
  the API's maximum output length is not verified — VERIFY before running batch > 5.
- Muse Spark does write realistic attacks (base64 curl-pipe-bash from a tainted README, npm
  postinstall persistence, reviewer-addressed judge attack) and benign look-alikes; no refusals.
- Round 1 result: 5 generated, 5 valid, 0 bypasses, 0 over-blocks, $0.048. One round of 5 is
  far too small to claim a bypass rate; it only proves the loop works end to end.
