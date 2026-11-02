# 034 — Oversized shell commands: linear lexing and an `ask`

Size: small (rules.py + input_capture.py guard, tests; no change for normal commands)

## Context

`shlex` is quadratic on one huge token (spec 032 found it): a 200 KB word took ~1 s per lexing
pass, 1 MB took over 30 s in the hard-deny stage. A hook that hangs is cut off by its timeout and
turns into `ask` (fail-closed), but a command that large cannot be checked in any case.

## Behaviour

- `input_capture.MAX_LEXED_CHARS = 50_000`. Above it, `input_capture._tokens` and
  `rules.split_command` use the linear regex tokenizer (`input_capture.fallback_tokens`, the same
  one used for unbalanced quotes) instead of `shlex`.
- `rules.evaluate`: after the hard-deny stage, a `Bash`/`PowerShell` command longer than
  `rules.MAX_CHECKED_COMMAND_CHARS` (= `MAX_LEXED_CHARS`) returns `ask`
  ("this command is too long for AgentWarden to check") — no policy match, no model call.
- Hard denies still run first on oversized commands, so a secret read or input injection stays
  `deny`; the coarser tokenizer can only lose a hard deny to this `ask`, never to `allow`.
- Commands up to the limit behave exactly as before.

## Failure paths

- Oversized command → `ask`. Tokenizer never raises on oversized input. Nothing here yields `allow`.

## Acceptance criteria

- [x] `test_command_over_limit_asks_without_tokenizing`: 800 KB command → `ask`, source `rules`, under 1 s.
- [x] `test_command_at_limit_is_still_checked`, `test_command_one_over_limit_asks`: boundary exact.
- [x] `test_limit_applies_to_both_shell_tools`: Bash and PowerShell.
- [x] `test_hard_deny_still_wins_over_the_length_ask`, `test_secret_read_still_denied_when_oversized`.
- [x] `test_input_capture_is_linear_on_one_huge_token`: 1 MB token, with and without tool hints, under 2 s.
- [x] `test_input_capture_still_finds_tool_after_huge_token`.
- [x] `make lint` and `make test` green (1284 passed).

## Out of scope

- Non-shell tools (Write/Edit content is not lexed as a command).
- Raising or making the limit configurable.
- A linear replacement for `shlex` for normal-sized commands.

## Demo impact

None.
