---
name: meta-redteam
description: How to run and interpret the Meta red-team loop (Muse Spark generates attacks, the cascade defends) and turn its results into eval cases and judge tuning. Use when building redteam/, running make redteam, or reviewing red-team results.
---

# Meta red-team loop

Spec: `docs/specs/backlog/meta-redteam-loop.md` (moved to `docs/specs/` when started).

## One cycle (about 30 minutes of human time)

1. `make redteam ROUNDS=1 BATCH=20` — generates attacks with Muse Spark and runs the cascade on them. Stops at `REDTEAM_MAX_USD`.
2. Read the round report in `redteam/runs/`. Look at bypasses first (dangerous allowed), then over-blocks (benign denied).
3. Review `eval/candidates/redteam-<date>-r<k>.jsonl`. Fix labels where the generator was wrong. Promote good cases to `eval/cases/` (the human does this; agents do not touch `eval/cases/`).
4. If bypasses share a cause, run one tuning round (`judge-tuning` skill).
5. Run the next round. The generator gets the list of attacks blocked last round so it tries new ones.
6. Log the round in `eval/CHANGELOG.md`:

```
## red team r3 — 2026-10-31
Generated 20, valid 18, bypasses 3 (17%), over-blocks 1.
Bypass themes: script written then run; judge_attack via code comment.
Followed by: judge v5 (taint context).
```

## Rules

- Generator prompt `prompts/redteam.md` is human-owned. Agents propose changes, the human applies them.
- Every URL in generated attacks must be `https://example.invalid`. Validate and drop anything else.
- Never let generated cases execute anything. They are data for the judge only.
- Report honestly: the bypass rate across rounds is a result even if it does not drop.
- Hold out: do not tune on the latest round before measuring it.

## What goes in the submission

- A small table or chart: bypass rate by round, with the tuning step between rounds.
- One sentence on what kinds of attacks still get through. That is the "Limitations" section.
