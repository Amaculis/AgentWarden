# NNN — Spike: choose and run the local Meta open-weights model

Size: small
Planned: Wed 28 Oct. Time box: 2 hours. Output is a decision, not product code.

## Context

The cascade and the scanner both depend on a local Meta model that is fast enough. Decide early which model and where it runs, before building on it.

## Steps

1. On dev.meta.ai, list Meta open-weights models usable for this (third-party guides mention Muse Glimmer for local hardware and Muse Spark Open via hosted providers — VERIFY names, sizes, licence).
2. Try the smallest suitable one locally through an OpenAI-compatible server (Ollama or vLLM). Record hardware used.
3. If local is too slow (p50 > 1 s for a ~1k-token judge request), host it on Modal or Baseten with partner credits.
4. Run 20 eval cases through it with the judge prompt v1 via a throwaway script; compare verdicts with Muse Spark on the same cases.

## Acceptance criteria

- [ ] Decision written to `docs/CONTEXT.md` (model id, where it runs, why).
- [ ] `meta-api` skill updated: local model id, base URL pattern, latency p50/p95, JSON reliability (how many of 20 parsed).
- [ ] `.env.example` updated with `WARDEN_LOCAL_BASE` / `WARDEN_LOCAL_MODEL` examples.
- [ ] Agreement with Spark on the 20 cases recorded (e.g. 16/20).

## Out of scope

Provider code, cascade logic.

## Demo impact

None directly; decides whether the demo can say "runs fully on your machine".
