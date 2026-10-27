# 012 — Verdict cache and per-call cost

Size: small (providers + evalrun; no change to the fail-safe path)

## Context

Every eval rerun of `spark`/`cascade` pays for the same requests again ($150 credits total).
The `meta-api` skill asks for a cache keyed by (model, prompt version, redacted request) and
for tokens/cost per call so `make eval` can print cost per 100 actions.

## Behaviour

- `CachedProvider(provider, path, cacheable=None)` wraps any `Provider`.
  - Key: sha256 of JSON `{namespace, model, max_tokens, messages}`; namespace = role
    (`local` / `meta_api`) + the provider base URL, so two judges never share entries. `messages` already hold the prompt
    text and the redacted request, so a prompt change or a different request misses.
    `model` = the wrapped provider's `model` attribute, else its class name.
  - Hit → `ProviderResult(text, tokens_in, tokens_out, cached=True, latency_ms=0)`, wrapped
    provider not called.
  - Miss → call through. Stored only when `error is None`, `text` is a string and
    `cacheable(text)` is true (eval passes "parses as a verdict"). Errors are never cached.
  - Totals for cost: `calls`, `hits`, `tokens_in`, `tokens_out` (misses only).
  - Any SQLite error → behave as a miss / skip the write; never raise.
- Path: `WARDEN_CACHE_PATH`, default `~/.agentwarden/cache.sqlite` (next to the audit DB).
- Eval: model modes always wrap their providers. `cost_per_100` = USD of non-cached tokens
  / cases run × 100, priced with `WARDEN_PRICE_IN` / `WARDEN_PRICE_OUT` (USD per million
  tokens, defaults 1.25 / 4.25 from the `meta-api` skill, VERIFY). Local provider tokens are
  free (price 0). Table gets a `$/100` column.
- Daemon: wraps the judge provider(s) only when `WARDEN_CACHE=on` (default off: a live
  session should re-judge, since the same command can mean different things over time).

## Interface

- `src/agentwarden/providers/cache.py`: `CachedProvider`, `cache_path() -> Path`.
- `ProviderResult.cached: bool = False`.
- `evalrun`: `_resolve_mode` deciders carry `.meters: list[tuple[CachedProvider, float, float]]`
  (provider, price_in, price_out); `cost_per_100` filled for model modes.

## Failure paths

- Cache DB unreadable / locked / corrupt → miss, call the provider, no write. Never raises.
- Provider error → returned as is, not cached.

## Acceptance criteria

- [x] `test_second_identical_call_is_cached` — provider called once, `cached=True` second.
- [x] `test_errors_not_cached`
- [x] `test_uncacheable_text_not_cached`
- [x] `test_prompt_change_misses`
- [x] `test_broken_cache_file_is_a_miss`
- [x] `test_eval_cost_per_100` — mock usage tokens priced; rerun hits cache, cost 0.
- [x] `make test` green, `make lint` clean.

## Out of scope

Cache expiry/size limits. Real price lookup.

## Demo impact

`make eval` shows `$/100`; reruns are free.
