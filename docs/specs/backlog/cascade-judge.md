# NNN — Cascade judge: local Meta model first, Muse Spark for hard cases

Size: large
Planned: Fri 30 Oct. Depends on: judge v1 on Muse Spark, eval harness v1, the local-model spike.

## Context

Judge v1 sends every unsettled action to Muse Spark. The cascade puts a small Meta open-weights model in front of it. Most actions are decided locally (private, fast, free); only uncertain ones escalate. This is the main "use of Meta tooling" story: two Meta models with distinct roles.

## Behaviour

1. Rules settle what they can (unchanged).
2. The rest goes to the local provider with the same judge prompt. It returns `{decision, risk, confidence, reason}`.
3. Escalate to Muse Spark when any of:
   - `confidence < WARDEN_ESCALATE_CONFIDENCE` (default 0.7);
   - `WARDEN_ESCALATE_RISK_LOW <= risk <= WARDEN_ESCALATE_RISK_HIGH` (default 30–70);
   - local verdict is `deny` and `WARDEN_CONFIRM_DENY=true` (default false; trades cost for fewer false positives).
4. The final verdict records `decided_by: rules | local | spark` and, when escalated, the local verdict too.
5. `WARDEN_CASCADE=off` keeps v1 behaviour (Spark only); `local_only` never escalates (offline mode).

## Interface

- `src/agentwarden/cascade.py`: `decide_with_cascade(request) -> Verdict`.
- `Verdict` gains `confidence: float`, `decided_by: str`, `escalated_from: Verdict | None`.
- Env: `WARDEN_LOCAL_BASE`, `WARDEN_LOCAL_MODEL`, `WARDEN_CASCADE`, thresholds above.
- Judge prompt asks for `confidence`; prompt version bumped (human edits the prompt).

## Failure paths

- Local provider down or times out → escalate to Spark (not `ask` directly), within the overall time budget.
- Spark also fails → `ask`.
- Local output unparsable → treated as low confidence → escalate.
- Overall budget `WARDEN_DECISION_BUDGET` (default 8 s) exceeded → `ask`.

## Acceptance criteria

- [ ] `test_confident_local_verdict_is_final`
- [ ] `test_low_confidence_escalates_to_spark`
- [ ] `test_mid_risk_escalates_to_spark`
- [ ] `test_local_down_escalates_to_spark`
- [ ] `test_both_down_returns_ask`
- [ ] `test_budget_exceeded_returns_ask`
- [ ] `test_decided_by_recorded_in_log`
- [ ] Eval: `make eval` reports four modes — rules / local / spark / cascade — with detection, FPR, % decided locally, p50/p95 latency, cost per 100 actions.
- [ ] Eval: cascade detection within 3 points of spark-only, with ≥ 70% decided locally (target; record the real numbers either way).

## Out of scope

Training or fine-tuning the local model. Choosing thresholds by grid search (one manual pass is enough; note it in `eval/CHANGELOG.md`).

## Demo impact

Yes: the dashboard and video show `decided by: local` vs `escalated to Muse Spark`, and the four-mode table.
