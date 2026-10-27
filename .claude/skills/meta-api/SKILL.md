---
name: meta-api
description: How AgentWarden calls Meta models — Meta Model API client setup, model names, Standard vs Contributor tier, timeouts, structured JSON, cost control, the local open-weights provider, and the role of each Meta model (cascade, scanner, red-team generator). Use when writing or changing src/agentwarden/providers/, judge.py, cascade.py, scanner.py or redteam/.
---

# Calling Meta models

Status: facts below come from Meta's docs as summarised by third parties on 2026-10-26. Items marked VERIFY must be confirmed against dev.meta.ai docs and a real request, then this file updated.

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

- Meta Model API is OpenAI-SDK compatible. Base URL: `https://api.meta.ai/v1` (VERIFY).
- Use the `openai` Python client with `base_url` and `api_key` from env: `META_API_BASE`, `META_API_KEY`. Never hard-code or log the key.
- Model from env `WARDEN_MODEL`. Default: the Standard Muse Spark model, e.g. `muse-spark-1.2` (VERIFY the current name via the models list; a newer version may exist).
- **Never use a `-contributor` model**: Contributor tier trains on prompts and code. AgentWarden sends code context.

## Request rules

- `temperature=0`.
- Hard timeout on every call: `WARDEN_JUDGE_TIMEOUT` seconds (default 6). Timeout or error → caller returns `ask`.
- Cap `max_tokens` for the verdict (≈200 is enough).
- Ask for JSON only. Judge: `{"decision": "allow|deny|ask", "risk": 0-100, "confidence": 0-1, "reason": "<one sentence>", "safer_alternative": "<one sentence or empty>"}`. Scanner: `{"injection": true|false, "confidence": 0-1, "quote": "<≤200 chars>", "reason": "<one sentence>"}`. Use the API's JSON / structured output mode if supported (VERIFY); otherwise extract the first JSON object and validate with pydantic. Anything that fails validation → `ask`.
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

## First request checklist (do once, then update this file)

- [ ] List available models; record exact Standard Muse Spark id.
- [ ] Confirm base URL and auth header.
- [ ] Confirm JSON mode support and how to request it.
- [ ] Measure latency of a 1k-token judge request (p50 over 10 calls).
- [ ] Confirm credits are applied in Billing.
