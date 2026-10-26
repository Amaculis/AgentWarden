# NNN — <short name>

Size: small | large

## Context

Why this change, in 2–3 sentences. Link the previous spec if it builds on one.

## Behaviour

What the system does after this change. Inputs → outputs. Include an example request/response or command and its output.

## Interface

Functions, endpoints, files, env vars added or changed, with signatures.

## Failure paths

Each one and its outcome. For hooks, daemon, judge and providers every path must end in `ask`.

- Daemon unreachable → …
- Timeout → …
- Malformed input / model output → …

## Acceptance criteria

- [ ] `test_...` — …
- [ ] `make test` green, `make lint` clean
- [ ] …

## Out of scope

What this spec deliberately does not do.

## Demo impact

Does this change anything a judge sees in the demo video? If yes, what.
