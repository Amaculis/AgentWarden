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
- [x] Found and fixed the reasoning-token truncation bug (`max_tokens` 300→900).
- [ ] List available models to check for a newer Muse Spark version.
- [ ] Measure p50/p95 latency over ≥10 calls (only ~5 manual calls so far: 1.3–3.3 s).
- [ ] Confirm credits are applied and pricing in Billing (page not opened this session).
- [ ] Try an ambiguous/adversarial case against the real API to see if JSON still holds.
