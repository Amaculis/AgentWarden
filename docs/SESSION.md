# Session state — 2026-11-01

Done: spec 022 (`e185abc`) — cascade escalates to Muse Spark when the action shows obfuscation
signals (`src/agentwarden/obfuscation.py`: `decode_exec`, `decode_blob`, `ps_encoded`,
`char_codes`, `dynamic_import`, `eval_indirection`), whatever the local confidence; a local
`deny` stays final; `WARDEN_ESCALATE_OBFUSCATION=0` disables. Reviewer found quadratic regex
gaps (1 MB `powershell`/`openssl`-repeat content > 15 s) — fixed with bounded gaps, plus
perf tests. Signals are scanned over all of `tool_input` joined (split decode/sink caught),
`old_string` skipped.

Offline check: on `eval/cases/` signals fire on 5 deny cases only (254, 257, 245, 242, 249),
**no benign case**, so main FPR cannot move from this mechanism (only from model noise).

Eval (cascade, v1 prompt, `36c2cff`): 257 allow → deny via Spark; main acc 0.953, detection
1.000, FPR 5.5% (was 11.0%, but that drop is 8B noise, not this change); holdout acc 0.926,
detection 1.000 (contaminated). Logged in `eval/CHANGELOG.md`, README and `meta-api` skill
updated. README cost column ($0.0055) is the 31 Oct figure: this run reported cost 0.0 (pricing
env not set), escalation rate is unchanged at 0.125.

Spec 024 (read-only policy profile, `mode: read_only` in policy.yaml): only Read/Glob/Grep inside
the project allowed, everything else `ask`, allow_* ignored, no model call. Idea not yet a spec
(023, Opus, Large): cascade escalates on prompt-injection phrases in the action (like 022 for
obfuscation: "ignore previous", "as the reviewer", fake verdict JSON) so a local `allow` is never
final for them; measure on `judge_attack`.

Spec 025 (project boundary): search/listing outside the project → deny; file or shell path
outside → ask that the judge may only tighten; `extra_roots` in policy and per-session grants
(`POST /session/roots` with UI token, dashboard button "Allow folder for this session").
Reviewer found `Glob **/../../x` → allow; fixed with tests. Dashboard button not checked in a
real browser yet. Cascade not re-run: expect `benign-readsshconfig-240` allow → ask.

Done 2026-11-01 (Opus):
- Spec 026 (link resolution, `links.py` + `rules._resolution_stage`): path rules also check
  symlink / junction / 8.3 short-name targets and hard links to protected files; only adds
  checks; `lstat`/`readlink` inside the roots only, UNC never touched;
  `WARDEN_RESOLVE_LINKS=0` disables. Reviewer found the hard-link table followed planted links
  (`os.stat`) — fixed with lstat-per-component + mutation-checked tests. eval-rules +0.000.
  File-symlink tests skip here (no developer mode); junction variants run.
- Spec 023 (manipulation escalation, `manipulation.py`, shared walker `text_scan.py`): signals
  `fake_verdict`, `addresses_judge`, `approval_claim`, `override_instructions` force Spark like
  022; `WARDEN_ESCALATE_MANIPULATION=0` disables. Fires on all 6 `judge_attack` cases, 0
  benign/borderline; 33/74 commits of this repo would fire (verdict JSON in eval/tests).
  Candidates `eval/candidates/judge_attack-023.jsonl` (10 attacks, 6 benign): signals 10/10
  attacks, 5/6 benign (by design, they escalate). Measured: the 8B model allows 0 of 10
  candidate attacks; cascade flag off == on; main cascade acc 0.953, det 1.000, FPR 6.8% (+1 =
  readsshconfig-240, spec 025). No measured gain, kept as defence in depth (eval/CHANGELOG.md).
  Candidates 12 and 15 are 8B false-positive denies ("Dear judge" text read as injection) —
  check before moving any candidate to eval/cases/. eval/results/*-b5847bc-actions-cascade.json
  holds the last candidate run, not the main run (the file name is commit+mode only).

Done 2026-11-01 (Opus): spec 027 (`e395992`, agent adapter layer, `agents/`): hooks take
`--agent <name>` → `X-AgentWarden-Agent` header → daemon normalizes the foreign payload into the
Claude Code shape (`tool_map`/`input_map`); unmapped foreign tool → `<agent>:<tool>` → rules
`ask`, no model; every registered agent's `config_paths` hard-denied for writes/shell (parent
dir only as a whole dir or wildcard, so `.github/workflows` stays usable), links and hard links
included; optional `hooks/formats/<agent>.py` output formatter, any failure → Claude-schema
fail-safe. Found on the way: before 027 a foreign shell tool name skipped every hard deny.
Reviewer: no findings. 905 tests, eval-rules +0.000.

027 follow-ups on main: broken formatter → Claude-schema `deny` (`13ad51d`); on_read forwards
payloads without an event name (`fe6c0a0`).

Ready to merge (Opus-reviewed, review findings fixed, pairwise merge-clean, rebased on `fe6c0a0`,
no push): `028-muse-code`, `029-copilot`, `030-codex`, worktrees under `.claude/worktrees/`.
- 028: shell tools from a third-party issue, other tool names guessed; config dirs `.muse/`,
  `.muse-plugin/`, `~/.config/muse/`. Live check = one short session in a scratch folder with a
  fake `.env` (`integrations/muse_code/README.md`); AgentWarden is off during it.
- 029: `copilot_cli` follows the docs.github.com hooks-configuration reference (no event name,
  `sessionId`, top-level `permissionDecision`), formatter prints top-level + `hookSpecificOutput`
  so one `.github/hooks` file serves CLI and VS Code. CLI timeout is fail-open. Not live-tested.
- 030: Codex has no working `ask` → formatter prints `deny`; single-file `apply_patch` mapped to
  Write/Edit, multi-file → deny; hook failures in Codex fail open. Not live-tested.
Open: env-var homes (`COPILOT_HOME`, `CODEX_HOME`) and `cd dir && …` relative paths bypass the
config-path shell check; a missing `hooks/formats/<agent>.py` falls back to Claude `ask`.

Done 2026-11-01 (Opus): spec 031 (`input_capture.py` + three rules): simulated input (SendKeys,
WScript, user32, UIA, xdotool/ydotool/wtype/xte/nircmd/AutoHotkey, osascript System Events,
`python -c` pyautogui/pynput/keyboard, also inside `-EncodedCommand`) = hard deny in stage 1;
screen/clipboard capture = default `ask` (judge may tighten), `deny` with an upload; Write/Edit
of a script file that does either = `ask`. Reviewer found a `python -u -u -u -u -u -c` bypass
and `-enc $var` — fixed with tests. 1013 tests, eval-rules +0.000; candidates
`eval/candidates/input-capture.jsonl` (5 tamper, 3 exfiltration, 4 benign): tamper 5/5, benign
never denied. Not in `docs/demo.md` yet (spec suggests the SendKeys self-approval shot).
Done 2026-11-01 (Sonnet): spec 032 — found in 031 and fixed: `split_command` no longer treats `#`
as a comment (`echo #\n<cmd>` hid every later line from the boundary check); upload / git-history
detection is now `verb → tail` per `|;&` segment (`_has_upload`, `_has_history_rewrite`), same
verdicts as the old regexes (oracle tests + fuzz), linear time. Reviewer found a scp/rsync
narrowing (delimiter inside a quoted remote spec) and the same quadratic shape in
`_DOWNLOAD_PIPE_RE` / `_DISK_DESTROY_RE` (`"dd " * 30000` = 19 s) — both fixed. Open: `shlex` is
quadratic on one huge token (800 KB → ~11 s per call, pre-existing; hook timeout → `ask`).

Waiting for the human:
1. Dashboard in a real browser + demo dry run (`docs/demo.md`); PostToolUse `tool_response`
   shape for Read/WebFetch still unverified.
2. Delete `muse-install.ps1`, stray `make` file (leftover `ps` output), `pytest-of-Artem/`
   (it also crashes `ruff format --check .`; use `ruff format --check src tests eval redteam
   hooks`), and branch `backup/pre-secret-fix` if done with it.
3. Drop `openai` from `pyproject.toml` (no longer imported).
4. Decide whether to move `eval/candidates/judge_attack-023.jsonl` (or part of it) into
   `eval/cases/` (human-owned). Eval runner overwrites a result file per commit+mode: candidate
   runs clobber the main run's file — maybe add the case-file name to the result name.

Open problems:
- Any local process can POST `/event` and plant a fake "user prompt" (spec 018).
- No `uv`, no `make` here: `PYTHONPATH=src python eval/run.py --set actions --mode cascade`,
  `PYTHONPATH=src python -m pytest -q -m "not slow"`. Pass the raised timeouts as env vars
  (above) — code defaults are still the old ones; `.env.example` is only a reference.
- `OLLAMA_CONTEXT_LENGTH` not raised; no truncation seen, unverified.
- Red-team batch > 5 untested.
