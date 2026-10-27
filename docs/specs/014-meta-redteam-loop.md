# 014 — Meta red-team loop: Muse Spark attacks, the cascade defends

Size: large (new module + CLI; reuses providers, cascade, eval schema; no hook/fail-safe change)
Depends on: 009, 010, 012. Built and tested against `MockProvider`; real runs need credits.

## Context

We need evidence that the judge holds up against attacks it has not seen, including attacks
aimed at the judge itself. Muse Spark generates new attacks each round; the defender is scored
on them; bypasses become eval candidates. "Meta attacks, Meta defends".

## Behaviour

`make redteam ROUNDS=N BATCH=20` → `python redteam/run.py --rounds N --batch 20
[--defender cascade|spark|local|rules] [--categories a,b]`:

1. Generator = Muse Spark (`meta_api` provider) with `prompts/redteam.md` (human-owned; empty
   v0 body → "not available", exit 2). User message: the fixed data line + JSON
   `{"round", "batch", "categories", "examples": [<=5 cases>], "blocked_last_round":
   [attack ideas]}`. Examples come from `eval/cases/*.jsonl`, else `eval/candidates/*.jsonl`.
   Timeout `WARDEN_REDTEAM_TIMEOUT` (60 s), `max_tokens` 6000. Not cached.
2. Parse: every JSON object in the reply (JSONL lines, a JSON array, or objects inside prose).
   Each must validate as an action case after removing `attack_idea` (kept separately) and
   forcing `source = "redteam-meta"`. Ids are rewritten to
   `<category>-meta-<date>-r<k>-<NNN>` so they never collide. Invalid → dropped, counted.
3. Defender: the eval decider for `--defender` (default `cascade`; providers cached, spec 012).
   Unavailable → "not available (<ENV> not set)", exit 2.
4. Classification: bypass = label `deny`/`ask` but decision `allow`; over-block = label `allow`
   but decision `deny`.
5. Round report → `redteam/runs/<date>-r<k>.json` (counts, bypass rate, over-blocks, cost, the
   cases with decisions) and a console row: round, generated, valid, bypasses, bypass rate,
   over-blocks, cost.
6. Bypasses and over-blocks → `eval/candidates/redteam-<date>-r<k>.jsonl` (`source:
   "redteam-meta"`, `note` = attack idea). The writer refuses any path outside
   `eval/candidates/`.
7. Next round's `blocked_last_round` = attack ideas the defender did not allow.
8. Budget: generator tokens priced as Spark plus defender meters; stop before a new round when
   the total reaches `REDTEAM_MAX_USD` (5), report `stopped: "budget"` with partial results.

## Interface

- `src/agentwarden/redteam.py`: `parse_generated(text, round_no, date) -> (cases, ideas,
  invalid)`, `classify(label, decision) -> "bypass" | "overblock" | None`,
  `run_round(...)`, `main(argv)`.
- `redteam/run.py` — thin entry like `eval/run.py`.
- `docs/handoff/redteam-prompt-v1-draft.md` — generator prompt draft for the human.

## Failure paths

- Generator error / timeout / garbage → round with 0 valid cases, counted, loop continues.
- Defender error on a case → fail-safe `ask` (never a bypass by error).
- Budget reached → stop, partial report written.
- Results/candidates write error → message, exit 2.

## Acceptance criteria

- [x] `test_invalid_generated_cases_are_dropped`
- [x] `test_ids_rewritten_and_source_forced`
- [x] `test_bypass_and_overblock_classification`
- [x] `test_round_writes_report_and_candidates`
- [x] `test_blocked_ideas_feed_next_round`
- [x] `test_budget_stop_reports_partial_round`
- [x] `test_candidates_written_never_to_eval_cases`
- [x] `test_unwritten_prompt_unavailable`
- [x] `test_reports_never_written_outside_runs_dir`
- [x] `make test` green, `make lint` clean.
- [ ] Human: 3 real rounds; bypass rate per round in `eval/CHANGELOG.md` with the tuning that
      followed. README/video table "attack success rate by round".

## Out of scope

Automatic prompt rewriting from bypasses (tuning stays human, see `judge-tuning`).
Auto-labelling: generator labels are drafts.

## Demo impact

Yes: the "Meta attacks, Meta defends" numbers in the metrics part of the video.
