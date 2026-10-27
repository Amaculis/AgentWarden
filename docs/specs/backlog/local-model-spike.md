# NNN — Spike: choose and run the local Meta open-weights model

Size: small
Time box: 2 hours. Output is a decision, not product code. Human-driven (downloads, hardware).

## Context

The cascade (010) and the scanner (013) both use a local Meta model behind an
OpenAI-compatible endpoint. All code is in place and tested with mocks; this spike picks the
model and measures it.

## Steps

1. On dev.meta.ai, list Meta open-weights models usable for this (VERIFY names, sizes, licence).
2. Serve the smallest suitable one through an OpenAI-compatible server, e.g. Ollama
   (`ollama serve`, base `http://127.0.0.1:11434/v1`) or vLLM. Record hardware.
3. Point AgentWarden at it (no code change):
   `WARDEN_LOCAL_BASE=http://127.0.0.1:11434/v1`, `WARDEN_LOCAL_MODEL=<model id>`.
   Write `prompts/judge.md` and `prompts/scanner.md` first (drafts in `docs/handoff/`).
4. Judge quality and latency — the eval already reports p50/p95, errors and parse failures:
   `python eval/run.py --set actions --mode local --cases eval/candidates/*.jsonl`
   and, with `META_API_KEY`, the same with `--mode spark`. Compare the two
   `eval/results/*-actions-{local,spark}.json` files (per-case `decision` fields) for agreement.
   Reruns are free (verdict cache, spec 012).
5. Scanner: `WARDEN_SCANNER=local python eval/run.py --set content --cases eval/candidates/content-*.jsonl`.
6. If p50 > 1 s for the judge, try a smaller model or host it on Modal/Baseten (partner
   credits) and set `WARDEN_LOCAL_BASE` to that endpoint; raise `WARDEN_LOCAL_TIMEOUT` only if
   the 7 s decision budget still holds.

## Acceptance criteria

- [ ] Decision written to `docs/CONTEXT.md` (model id, where it runs, why).
- [ ] `meta-api` skill updated: local model id, base URL, p50/p95, JSON reliability.
- [ ] `.env.example` updated with the real `WARDEN_LOCAL_BASE` / `WARDEN_LOCAL_MODEL`.
- [ ] Agreement with Spark on the candidate set recorded (e.g. 70/90).

## Out of scope

Provider code, cascade logic (done in 009/010).

## Demo impact

Decides whether the demo can say "runs fully on your machine".
