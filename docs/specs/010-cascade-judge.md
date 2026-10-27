# 010 — Cascade judge: local Meta model first, Muse Spark for hard cases

Size: large (decide fail-safe path, judge, eval)
Depends on: 009 (judge v1, providers, redaction). The local-model spike (backlog) picks the
real model; this spec is built and tested against `MockProvider` only.

## Context

Judge v1 (009) sends every unsettled action to one provider. The cascade puts a small Meta
open-weights model in front of Muse Spark. Most actions are decided locally (private, fast,
free); only uncertain ones escalate. This is the main "use of Meta tooling" story: two Meta
models with distinct roles.

## Behaviour

`WARDEN_JUDGE=cascade` (new value) enables it in the daemon; eval mode `cascade` runs it.

1. Rules settle what they can (unchanged).
2. The rest goes to the local provider with the same judge prompt (`judge.judge`).
3. Escalate to Muse Spark when any of:
   - the local verdict is a fail-safe (provider error, timeout, unparsable output);
   - `confidence` is missing or `< WARDEN_ESCALATE_CONFIDENCE` (default 0.7);
   - `WARDEN_ESCALATE_RISK_LOW <= risk*100 <= WARDEN_ESCALATE_RISK_HIGH` (default 30–70);
   - the local verdict is `deny` and `WARDEN_CONFIRM_DENY=true` (default false).
4. The final verdict records `decided_by: local | spark` and, when escalated, `escalated: true`
   plus the local decision (`local_decision`).
5. Thresholds of 009 (`apply_thresholds`) apply to the final verdict.
6. `WARDEN_CASCADE=local_only` never escalates (offline mode): an escalation trigger becomes
   `ask` instead of a Spark call.

## Interface

- `src/agentwarden/cascade.py`:
  `decide_with_cascade(event, context, local: Provider | None, spark: Provider | None, *,
  budget_s: float | None = None) -> Verdict`. Never raises.
- `models.Verdict` gains `decided_by: Literal["rules","local","spark"] | None = None`,
  `escalated: bool = False`, `local_decision: DecisionValue | None = None`.
- `providers.get_provider("cascade")` is not a provider; `decide.decide` handles
  `WARDEN_JUDGE=cascade` by building `local.from_env()` and `meta_api.from_env()`.
- Env: `WARDEN_CASCADE` (`on` default | `local_only`), `WARDEN_ESCALATE_CONFIDENCE`,
  `WARDEN_ESCALATE_RISK_LOW`, `WARDEN_ESCALATE_RISK_HIGH`, `WARDEN_CONFIRM_DENY`,
  `WARDEN_DECISION_BUDGET` (default 7 s, keeps `/decide` under the hook's 8 s deadline).
- Store: `decisions` table gains nullable `decided_by TEXT`, `escalated INTEGER`
  (migration: `ALTER TABLE ... ADD COLUMN` when missing).
- `evalrun`: mode `cascade` available when both `WARDEN_LOCAL_BASE` and `META_API_KEY` are set;
  results JSON fills `local_share` (decided locally / judged) and `escalation_rate`.

## Failure paths

- Local provider missing → straight to Spark (if configured), else `ask`.
- Local down, times out, or unparsable → escalate to Spark within the remaining budget.
- Spark missing, down, times out or unparsable → `ask`.
- Remaining budget < 1 s before the Spark call → `ask` without calling.
- Overall budget exceeded → `ask`. Local timeout = min(`WARDEN_LOCAL_TIMEOUT` (3 s),
  remaining), so a hung local model still leaves Spark time; Spark timeout =
  min(`WARDEN_JUDGE_TIMEOUT`, remaining).

## Acceptance criteria

- [x] `test_confident_local_verdict_is_final`
- [x] `test_low_confidence_escalates_to_spark`
- [x] `test_missing_confidence_escalates`
- [x] `test_mid_risk_escalates_to_spark`
- [x] `test_confirm_deny_escalates_deny`
- [x] `test_local_down_escalates_to_spark`
- [x] `test_local_unparsable_escalates`
- [x] `test_both_down_returns_ask`
- [x] `test_local_only_never_calls_spark`
- [x] `test_budget_exceeded_returns_ask`
- [x] `test_decided_by_recorded_in_log`
- [x] `test_eval_cascade_mode_with_mocks` — reports `local_share` and `escalation_rate`.
- [ ] Eval with real models (human, needs credits): `make eval` reports four modes; cascade
      detection within 3 points of spark-only with ≥ 70% decided locally (target; record the
      real numbers either way in `eval/CHANGELOG.md`).
- [x] `make test` green, `make lint` clean.

## Out of scope

Training or fine-tuning the local model. Grid search over thresholds (one manual pass is
enough; note it in `eval/CHANGELOG.md`). Verdict cache and per-call cost (backlog
`verdict-cache.md`).

## Demo impact

Yes: the dashboard and video show `decided by: local` vs `escalated to Muse Spark`, and the
four-mode table.
