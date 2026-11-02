# 033 — Show the reason in the visible AgentWarden message

Size: small (decide.py message text + tests; no change to decisions or fail-safe paths)
Decisions (human unavailable, defaults chosen 2026-11-02): English text; one line, 200 characters; reason also stays in
`permissionDecisionReason`; no extra env switch (`WARDEN_NOTIFY=off` covers it); the deny line shows
the reason as the daemon built it (it already carries the safer alternative, so it is part of the
truncated text).

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
- New helper `short_reason(text) -> str | None` in `decide.py`: clean (NFKC, control/format chars
  dropped), collapse whitespace, drop a leading "AgentWarden:", redact, truncate at a word boundary.
- `decide.MAX_MESSAGE_REASON = 200`.

## Failure paths

- Empty or missing reason (or only the "AgentWarden:" prefix) → source-only message as today.
- `redact` or truncation raises → source-only message; the decision itself is never changed.

## Acceptance criteria

- [x] `test_system_message_contains_reason_for_ask` and `..._for_deny`.
- [x] `test_system_message_reason_is_redacted` — a secret in a model reason does not appear.
- [x] `test_system_message_reason_is_single_line_and_truncated` — newlines collapsed, ≤ the limit, cut at a word boundary.
- [x] `test_system_message_without_reason_unchanged`, `test_failure_in_short_reason_falls_back_to_source_only`.
- [x] Existing `endswith("(rules)")` / `endswith("(policy)")` assertions in `tests/test_decide.py` updated, not deleted (the hook tests use stub messages and are unchanged).
- [x] `make test` green, `make lint` clean, eval-rules +0.000.

## Out of scope

- Rewriting the rule reasons themselves (separate pass over `rules.py` strings if some are vague).
- A dashboard change (the dashboard already shows the full reason).
- Other agents' output formats (`hooks/formats/`): they receive the same message string.

## Demo impact

Yes, positive: each stop shows its reason on screen, so the viewer sees why without opening the
dashboard.
