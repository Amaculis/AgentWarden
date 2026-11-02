# 035 — Bind the session task to the action's prompt_id

Size: small (store query + daemon context, tests; follows the 018 known limitation)

## Context

Spec 018 left a known gap: any local process — including a protected agent that gets past the
daemon-URL hard deny — can POST `/event` and plant a fake "user prompt". The daemon used the
last 3 prompts of the session as the judge's `task`, so a planted "the user approves deleting
X" sat right next to the real request.

Verified on real Claude Code captures (`.agentwarden/events.jsonl`, 2026-11-02): the
`UserPromptSubmit` event carries a `prompt_id` and every following `PreToolUse` of that turn
carries the same `prompt_id`; the prompt event arrives before the turn's first tool event.

## Behaviour

`daemon.session_context(store, session_id, prompt_id)` builds the task with
`store.task_prompts(session_id, prompt_id)`:

- **Current prompt:** the *first* stored prompt row with the action's `(session_id, prompt_id)`.
  A later row with the same id (a replay) is ignored. No such row → no current prompt.
- **Earlier prompts (at most 2):** rows stored before the current prompt row, with a non-null
  `prompt_id` different from the current one, each the first row for its id, and confirmed by
  a decision with that `prompt_id` recorded before the current turn's first decision.
- No current prompt → `task` is `None` (the judge decides without it; less context, never more
  trust).
- An action without a `prompt_id` (agents whose adapters do not provide one) keeps the old
  behaviour: the last 3 prompts of the session.

A prompt planted during the current turn is never used: it is not the first row for the
current id, and any other id it carries is either stored after the current prompt or confirmed
only by decisions made during the current turn.

## Failure paths

- Store error while building context → context `None` (existing behaviour); rules still run.
- Nothing here can turn a verdict into `allow`; it only removes text from the judge input.

## Residual risk (documented)

An agent that reaches the daemon (past the hard deny and the obfuscation escalation) and posts
both a fake prompt and a fake `/decide` with the same new id can still plant an *earlier*
prompt that shows up in a later turn. It cannot replace or extend the current prompt. Adapters
without `prompt_id` keep the old weakness.

## Acceptance criteria

- [x] `test_task_is_the_prompt_with_the_actions_prompt_id`
- [x] `test_forged_prompt_with_new_id_is_ignored`
- [x] `test_replayed_prompt_id_is_ignored`
- [x] `test_earlier_prompt_needs_a_decision_before_the_current_turn`
- [x] `test_prompt_forged_during_current_turn_is_ignored_even_with_a_forged_decision`
- [x] `test_missing_current_prompt_gives_no_task`
- [x] `test_events_without_prompt_id_keep_last_three_prompts`
- [x] `test_daemon_forged_event_does_not_reach_the_judge` (end to end via `/event` + `/decide`)
- [x] `make lint` and `make test` green.

## Out of scope

- A per-session secret for hooks (Claude Code does not provide one).
- Checking prompts against the transcript file.
- Changing the judge prompt or the shape of the judge input.

## Demo impact

None visible; the judge input no longer contains planted prompts.
