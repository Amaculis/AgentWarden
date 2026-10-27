# NNN — Send user prompts to the daemon (session task for the judge)

Size: small (but touches hooks/ — follow the hook-protocol skill)

## Context

`hooks/on_prompt.py` only appends to `.agentwarden/events.jsonl`. The judge (009) reads the
session task from the daemon store (`prompts` table), which stays empty in real sessions.

## Behaviour

`on_prompt.py` also POSTs the event to `<WARDEN_URL base>/event` with a ≤ 2 s deadline,
best-effort. It must never block or alter the prompt: exit 0, print nothing, swallow errors.

## Acceptance criteria

- [ ] Prompt reaches `/event` (stub daemon test).
- [ ] Daemon down / slow → hook still exits 0 within the deadline, prints nothing.
- [ ] `make test` green, `make lint` clean.
