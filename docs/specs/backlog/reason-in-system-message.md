# NNN — Show the reason in the visible AgentWarden message

Size: small (decide.py message text + tests; no change to decisions or fail-safe paths)
Status: draft, waiting for the human's answers (see Open questions). Next free number at start: 033.

## Context

When AgentWarden answers `ask` or `deny`, the user mostly sees the command itself. The hook already
sends the verdict reason as `permissionDecisionReason` (`hooks/on_tool.py`), but it is not verified
what Claude Code's permission dialog renders from it. The only line the user is sure to see is the
`systemMessage`, and it carries the source only: "🛡 AgentWarden: needs confirmation for this
action (rules)" (`decide.with_system_message`). For the demo and for daily use the user should see
*why*.

## Behaviour

- `systemMessage` for `ask` and `deny` gets a short reason after the source, one line, at most
  ~200 characters, cut at a word boundary with "…":
  `🛡 AgentWarden: needs confirmation (rules): uploads data or rewrites git history`
  `🛡 AgentWarden: blocked (rules): reads a secret file. Safer: use .env.example`
- The reason text goes through `redact.py` first (a model reason may quote a secret from the
  command), has newlines and control characters collapsed to spaces, and stays ASCII-safe in the
  hook JSON (already `ensure_ascii`).
- `allow` and `WARDEN_NOTIFY=off` unchanged (no message).
- Fail-safe messages from the hook (daemon down, formatter broken) already name the cause; unchanged.

## Interface

- `decide.with_system_message(verdict)`: builds `"🛡 AgentWarden: {verb} ({label}): {short_reason}"`.
- New helper `short_reason(text, limit=200)` in `decide.py` (or `redact.py` if it reads better).
- Optional env `WARDEN_NOTIFY_REASON=off` to go back to the source-only message (decide in the
  open questions).

## Failure paths

- Empty or missing reason → source-only message as today.
- `redact` or truncation raises → source-only message; the decision itself is never changed.

## Acceptance criteria

- [ ] `test_system_message_contains_reason` for a rules `ask` and a rules `deny`.
- [ ] `test_system_message_reason_is_redacted` — a secret in a model reason does not appear.
- [ ] `test_system_message_reason_truncated_single_line` — newlines collapsed, ≤ the limit.
- [ ] `test_system_message_without_reason_unchanged`.
- [ ] Existing exact-string assertions in `tests/hooks/test_on_tool.py` updated, not deleted.
- [ ] `make test` green, `make lint` clean, eval-rules +0.000.

## Out of scope

- Rewriting the rule reasons themselves (separate pass over `rules.py` strings if some are vague).
- A dashboard change (the dashboard already shows the full reason).
- Other agents' output formats (`hooks/formats/`): they receive the same message string.

## Demo impact

Yes, positive: each stop shows its reason on screen, so the viewer sees why without opening the
dashboard.

## Open questions (ask the human when they join)

1. What exactly do you see now when AgentWarden asks: only the command in Claude Code's dialog, or
   also the 🛡 line? Which verdict source was it (rules / local model / Muse Spark)? A screenshot
   settles whether `permissionDecisionReason` is rendered at all.
2. Where should the reason appear: only in the 🛡 line (this draft), or also stay in
   `permissionDecisionReason` as today? (Keeping both is the default.)
3. For `deny`, add the safer alternative to the line, or keep it only in what the agent sees?
4. Language: reasons are English like the rest of the product. Is that fine for the demo video, or
   should the 🛡 line be Russian?
5. Length: 200 characters one line, or allow a second line for long model explanations?
6. Do you want the `WARDEN_NOTIFY_REASON=off` switch, or is `WARDEN_NOTIFY=off` enough?
7. Are some rule reasons too vague today ("confirm before continuing")? If yes, list the ones you
   remember and I fold a wording pass into this spec.
