---
name: meta-api
description: How AgentWarden calls Meta models — Meta Model API client setup, model names, Standard vs Contributor tier, timeouts, structured JSON, cost control, and the local open-weights provider. Use when writing or changing src/agentwarden/providers/ or judge.py.
---

# Calling Meta models

Status: facts below come from Meta's docs as summarised by third parties on 2026-10-26. Items marked VERIFY must be confirmed against dev.meta.ai docs and a real request, then this file updated.

## Client

- Meta Model API is OpenAI-SDK compatible. Base URL: `https://api.meta.ai/v1` (VERIFY).
- Use the `openai` Python client with `base_url` and `api_key` from env: `META_API_BASE`, `META_API_KEY`. Never hard-code or log the key.
- Model from env `WARDEN_MODEL`. Default: the Standard Muse Spark model, e.g. `muse-spark-1.2` (VERIFY the current name via the models list; a newer version may exist).
- **Never use a `-contributor` model**: Contributor tier trains on prompts and code. AgentWarden sends code context.

## Request rules

- `temperature=0`.
- Hard timeout on every call: `WARDEN_JUDGE_TIMEOUT` seconds (default 6). Timeout or error → caller returns `ask`.
- Cap `max_tokens` for the verdict (≈200 is enough).
- Ask for JSON only: `{"decision": "allow|deny|ask", "risk": 0-100, "reason": "<one sentence>"}`. Use the API's JSON / structured output mode if supported (VERIFY); otherwise extract the first JSON object and validate with pydantic. Anything that fails validation → `ask`.
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

All three implement one interface: `judge(request: JudgeRequest) -> Verdict`, raising nothing — errors become `Verdict(decision="ask", ...)`.

## First request checklist (do once, then update this file)

- [ ] List available models; record exact Standard Muse Spark id.
- [ ] Confirm base URL and auth header.
- [ ] Confirm JSON mode support and how to request it.
- [ ] Measure latency of a 1k-token judge request (p50 over 10 calls).
- [ ] Confirm credits are applied in Billing.
