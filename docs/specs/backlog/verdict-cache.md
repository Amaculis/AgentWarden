# NNN — Verdict cache and per-call cost

Size: small

## Context

Every eval rerun of `spark`/`cascade` pays for the same requests again ($150 credits total).
The `meta-api` skill asks for a cache keyed by (model, prompt version, redacted request) and
for tokens/cost per call so `make eval` can print cost per 100 actions.

## Behaviour

- `.agentwarden/cache.sqlite`: key = sha256(model id + prompt text + redacted messages JSON),
  value = provider text + tokens. Only successful, parsable results are cached; errors never.
- Wrap any `Provider` in `CachedProvider(provider, path)`; eval always uses it, the daemon
  uses it when `WARDEN_CACHE=on`.
- `ProviderResult` gains `cached: bool`; evalrun sums tokens and prices them with
  `WARDEN_PRICE_IN` / `WARDEN_PRICE_OUT` (USD per million tokens, defaults from the
  `meta-api` skill, VERIFY), filling `cost_per_100` in the results JSON.

## Acceptance criteria

- [ ] Second identical call is served from cache, provider not called.
- [ ] Error results are not cached.
- [ ] Changing the prompt text misses the cache.
- [ ] `cost_per_100` filled for model modes; cache hits cost 0.
- [ ] `make test` green, `make lint` clean.
