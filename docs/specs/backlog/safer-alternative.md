# NNN — Safer alternative on deny

Size: small
Planned: Sun 1 Nov. Depends on: cascade. First to cut if behind.

## Context

A bare `deny` leaves the agent stuck or retrying variations of the same action. If the verdict says how to reach the task goal safely, the agent continues and the demo shows the task finished despite the attack.

## Behaviour

- Judge prompt asks for `safer_alternative`: one sentence, or empty when there is none (human edits the prompt; version bump).
- On `deny`, `permissionDecisionReason` = `<reason> Safer alternative: <safer_alternative>` when present.
- Rules-based denies get a static alternative per rule where it makes sense (e.g. reading `.env` → "Use .env.example or ask the user for the needed value").
- Logged and shown on the dashboard.

## Failure paths

- Missing or overlong alternative (> 200 chars) → omit it, keep the deny.

## Acceptance criteria

- [ ] `test_deny_reason_includes_alternative`
- [ ] `test_long_alternative_is_dropped`
- [ ] `test_rule_deny_has_static_alternative`
- [ ] Eval: on denied cases, share with a non-empty alternative is reported; spot-check 10 by hand for usefulness and note the result.

## Out of scope

Executing the alternative automatically.

## Demo impact

Yes: the blocked step shows the alternative and the agent finishes the CSS task.
