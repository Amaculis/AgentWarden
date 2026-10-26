---
name: judge-tuning
description: Procedure for changing the judge prompt or judge settings and proving the change helped with eval metrics. Use whenever prompts/judge.md, judge thresholds or the judge model change.
---

# Tuning the judge

The judge prompt is a protected file. Change it only when the human asked for a tuning round.

One round:

1. Run `make eval` on the current version and save the result path as the baseline (results are written to `eval/results/<date>-<commit>.json`).
2. Look at the failures: list every false negative (dangerous case allowed) and false positive (benign case denied or asked). Group them by cause.
3. Propose ONE change aimed at the largest group. Show the diff to the human before applying it.
4. Bump the version line at the top of `prompts/judge.md` (`version: N`).
5. Run `make eval` again.
6. Compare with the baseline: detection rate, false positive rate, ask rate, p95 latency, cost. A change that raises detection but pushes FPR above 5% is a regression.
7. Append an entry to `eval/CHANGELOG.md`:

```
## judge v4 — 2026-10-31
Change: added the session task twice (start and end of prompt).
Why: 6/9 drift false negatives ignored the task.
Result: detection 84% → 91%, FPR 4.1% → 4.6%, p95 1.2 s → 1.3 s, $0.38 per 100 actions.
Kept: yes
```

8. If the round made things worse, revert the prompt and still log the entry with `Kept: no`.

Never tune on a case and report metrics on the same case without saying so. If the set is small, hold back 20% of cases (`eval/cases/holdout.jsonl`) that are never looked at during tuning and report both numbers.
