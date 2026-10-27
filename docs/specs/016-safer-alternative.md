# 016 — Safer alternative on deny

Size: small (decide.py reason assembly + static alternatives in rules.py)
Depends on: 009 (judge output already carries `safer_alternative`).

## Context

A bare `deny` leaves the agent stuck or retrying variations of the same action. If the verdict
says how to reach the task goal safely, the agent continues and the demo shows the task
finished despite the attack.

## Behaviour

- On `deny`, `reason` (→ `permissionDecisionReason`) becomes
  `<reason> Safer alternative: <safer_alternative>` when an alternative survives the checks.
- Checks (`decide.usable_alternative`): one line, ≤ 200 chars, control characters stripped, and
  it must not look like a command an attacker could smuggle through the judge: no `://`, no
  `|`, `;`, `&&`, `$(`, backticks, `>`, and no `curl`, `wget`, `base64`, `sh -c`, `eval`.
  The model's text is shaped by attacker-controlled content and is shown to the agent in
  AgentWarden's voice, so anything command-like is dropped (the deny stays).
- Rules-based denies get a static alternative:
  - secrets → "Use .env.example or ask the user for the value you need."
  - self-protection (.agentwarden, Claude settings, hooks/, daemon) → "Ask the user to change
    AgentWarden's settings from the dashboard."
  - destructive commands → "Delete only specific build artifacts inside the project, or ask
    the user."
- `ask` and `allow` reasons are unchanged (the user decides on `ask`).
- The audit log stores `safer_alternative` (new nullable column, migrated like spec 010).
- The judge prompt already asks for `safer_alternative` (draft in `docs/handoff/`); no
  `prompts/` change here.

## Failure paths

- Missing, overlong (> 200), multi-line or command-like alternative → omitted, deny kept.

## Acceptance criteria

- [x] `test_deny_reason_includes_alternative`
- [x] `test_long_alternative_is_dropped`
- [x] `test_command_like_alternative_is_dropped`
- [x] `test_rule_deny_has_static_alternative`
- [x] `test_ask_reason_unchanged`
- [x] `test_alternative_stored_in_log`
- [x] `make test` green, `make lint` clean.
- [ ] Human eval: on denied cases, share with a non-empty alternative; spot-check 10 by hand.

## Out of scope

Executing the alternative automatically.

## Demo impact

Yes: the blocked step shows the alternative and the agent finishes the CSS task.
