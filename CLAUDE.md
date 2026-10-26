# AgentWarden

Semantic firewall for AI coding agents. It intercepts Claude Code actions through hooks, checks them with deterministic rules, and asks a Meta model (Muse Spark via Meta Model API, or Meta open-weights models running locally) whether the action fits the task the user gave. Every action gets `allow`, `deny` or `ask`.

Built for the Meta Global AI Developer Hackathon (Oct 26 – Nov 4, 2026). Only code written during the event goes in this repo.

## Architecture

- `hooks/` — command hooks that Claude Code runs. They forward events to the daemon and **fail closed**: daemon down, slow or broken → `ask`.
- `src/agentwarden/daemon.py` — FastAPI service: `/event`, `/decide`, `/log`, dashboard page.
- `src/agentwarden/rules.py` — deterministic allow/deny, no model.
- `src/agentwarden/judge.py` + `providers/` — model call, JSON verdict `{decision, risk, reason}`. Providers: `meta_api`, `local`, `mock`.
- `src/agentwarden/redact.py` — strips secrets before anything is sent to a model.
- `src/agentwarden/decide.py` — combines rules + judge, applies risk thresholds and the fail-safe.
- `src/agentwarden/store.py` — SQLite audit log.
- `eval/` — labelled cases and `make eval` metrics.

## Commands

- `make install` — install dependencies (uv)
- `make lint` — ruff check + format check
- `make test` — fast tests, no network
- `make eval` — full eval with the real model (costs API credits)
- `make eval-rules` — eval with rules only, free
- `make run` — start the daemon on 127.0.0.1:8765

## Invariants — never break these

1. Any error, timeout or unparsable model output → `ask`. Never `allow`.
2. Secrets never leave the machine: everything sent to a model goes through `redact.py`.
3. The only outbound network calls are to the configured model provider.
4. Do not edit `prompts/judge.md` or `eval/cases/` unless the task explicitly asks for it. Proposed eval cases go to `eval/candidates/`.
5. Tests never call the real API. Use `providers/mock.py`. Tests that need the real model are marked `@pytest.mark.slow`.
6. Never read or print `.env`. Configuration comes from environment variables.

## Workflow

- Every task starts from a spec in `docs/specs/NNN-name.md` (skill: `warden-spec`).
- Tests first, then implementation until `make test` is green.
- Small commits; the message starts with the spec number, e.g. `001: hook passthrough`.
- Definition of done: `make lint` and `make test` green, every acceptance criterion in the spec checked off.

## Stack

Python 3.12, uv, FastAPI, pydantic, httpx, OpenAI-compatible client for Meta Model API, SQLite, pytest, ruff.
