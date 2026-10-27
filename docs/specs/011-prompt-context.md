# 011 — Send user prompts to the daemon (session task for the judge)

Size: small (but touches hooks/ — follow the hook-protocol skill)

## Context

`hooks/on_prompt.py` only appends to `.agentwarden/events.jsonl`. The judge (009) reads the
session task from the daemon store (`prompts` table), which stays empty in real sessions.

## Behaviour

`on_prompt.py` also POSTs the event to `<WARDEN_URL base>/event` with a ≤ 2 s deadline,
best-effort. It must never block or alter the prompt: exit 0, print nothing, swallow errors.

- URL: `on_tool.decide_url()` (loopback-only `WARDEN_URL` validation) with `/decide` replaced
  by `/event`; invalid or non-loopback `WARDEN_URL` → no request.
- Transport: `on_tool.call_daemon` (no proxies, no redirects, wall-clock deadline).
- Deadline: `min(WARDEN_HOOK_TIMEOUT, 2)` seconds.
- The local `events.jsonl` record is written first, as before.

## Failure paths

- Daemon down / slow / 4xx / 5xx → exit 0, nothing printed, prompt untouched.
- `on_tool` import fails → recording only, exit 0.

## Acceptance criteria

- [x] `test_on_prompt_posts_to_event` — prompt reaches `/event` (stub daemon test).
- [x] `test_on_prompt_slow_daemon_bounded` — slow daemon → exit 0 within ~2 s, prints nothing.
- [x] `test_on_prompt_non_loopback_url_not_called` — non-loopback `WARDEN_URL` → no request.
- [x] `make test` green, `make lint` clean.
