# 005 — Hook wiring: `on_tool.py` calls `/decide` and fails closed

Size: large

## Context

Specs 002–004 built `/decide` (rules, policy, `system_message`), but `hooks/on_tool.py` still only records events (spec 001) and makes no decision, so nothing AgentWarden decides reaches Claude Code. This spec makes the PreToolUse hook call the daemon, translate the `Verdict` into hook output, and fail closed to `ask` on every error, following the `hook-protocol` skill. It also fixes the `python3` hardcoding in the example settings for Windows.

## Behaviour

`hooks/on_tool.py` (PreToolUse command hook):

1. Reads raw stdin bytes and decodes them as UTF-8 (strict). It does not use `sys.stdin.read()`, because on Windows that decodes with the console code page and garbles non-ASCII paths.
2. Parses the JSON object. Records it to `events.jsonl` as before (spec 001, best-effort: a recording failure is ignored and never changes the decision).
3. POSTs the **original bytes** to `${WARDEN_URL}/decide` (default `http://127.0.0.1:8765`) with `Content-Type: application/json`, under a hard 8 s wall-clock deadline.
4. Validates the response (see "Verdict validation") and maps it to hook output.
5. Writes exactly one JSON document to stdout, **ASCII-only** (`json.dumps(..., ensure_ascii=True)`). The 🛡 is sent as the escape `🛡`, which Claude Code's JSON parser decodes. This way a cp1252 Windows stdout can never raise `UnicodeEncodeError` halfway through the output.
6. Always exits 0.

### Verdict → hook output mapping

| Verdict `decision` | stdout |
|---|---|
| `deny` | `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": <reason>}, "systemMessage": <system_message>}` |
| `ask` | same shape with `"ask"` |
| `allow`, `WARDEN_ALLOW` unset or `passthrough` (default) | **nothing** (empty stdout, exit 0): Claude Code's own permission flow continues |
| `allow`, `WARDEN_ALLOW=explicit` | `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow", "permissionDecisionReason": <reason>}}` |

- `systemMessage` appears only when the verdict's `system_message` is a non-empty string. If it is `null`, missing or `""`, the key is **omitted**, never sent as `null`.
- The hook never writes its own `systemMessage` for a daemon-supplied verdict. The daemon owns the wording (see the daemon change below). The hook writes its own text only on its own fail-closed path.
- Extra Verdict fields (`risk`, `source`, unknown keys) are ignored by the hook.

Why `allow` defaults to passthrough: a hook `permissionDecision: "allow"` skips Claude Code's own permission prompt. If AgentWarden emitted it by default, any false allow (a policy typo now, a judge mistake later) would turn into silent execution where the user would otherwise have been asked. That makes AgentWarden a single point of failure instead of an extra layer. With passthrough, AgentWarden only adds friction and never removes the user's existing protection. `WARDEN_ALLOW=explicit` is the opt-in for users who want AgentWarden to replace their allowlists, and is what the demo can use once eval numbers justify it. Any value other than `explicit` means passthrough.

Example: deny from rules (stdout, shown here un-escaped for readability):

```json
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
  "permissionDecisionReason": "Reading secret files is not allowed (~/.ssh/id_rsa)."},
 "systemMessage": "🛡 AgentWarden: blocked this action (rules)"}
```

Example: daemon down:

```json
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
  "permissionDecisionReason": "AgentWarden unavailable"},
 "systemMessage": "🛡 AgentWarden: unavailable, needs confirmation for this action (fail-safe)"}
```

(`systemMessage` is omitted when `WARDEN_NOTIFY=off` in the hook's environment.)

### Verdict validation (in the hook, stdlib only)

The response is accepted only if **all** of these hold. Otherwise the hook takes the fail-closed path:

- HTTP status is exactly 200.
- Body is at most 64 KiB (the hook reads at most 64 KiB + 1 byte; a larger body means fail closed).
- Body decodes as UTF-8 and parses as a JSON **object**.
- `decision` is exactly one of `"allow"`, `"deny"`, `"ask"` (case-sensitive, no stripping).
- `reason` is a `str`.
- `system_message`, if present, is `str` or `null`. Any other type means fail closed.

The hook deliberately does **not** import `agentwarden.models.Verdict` (see Decision 1). The contract test below generates its canned bodies with `Verdict(...).model_dump_json()`, so if the model changes shape, the hook tests catch it.

### Daemon change: every `/decide` deny/ask carries `system_message`

Today `daemon.py`'s error branches return a bare `failsafe(...)`, so they have no `system_message`, and the user would see an `ask` prompt with no 🛡 line explaining it. This spec makes the notification contract uniform:

- `decide.py`'s `_with_system_message` becomes public: `with_system_message(verdict: Verdict) -> Verdict` (same behaviour, still honours `WARDEN_NOTIFY=off`).
- Every `failsafe(...)` that `daemon.py`'s `/decide` returns goes through `with_system_message`. Example text: `🛡 AgentWarden: needs confirmation for this action (fail-safe)`.
- The audit row stored by `/decide` is unchanged in meaning.

Contract after this spec: every `/decide` response with decision `deny` or `ask` has a non-empty `system_message`, unless `WARDEN_NOTIFY=off` in the daemon's environment.

### Example settings

- `examples/settings.agentwarden.json`: macOS/Linux, `python3` (unchanged command form, kept for POSIX where `python` is often absent).
- `examples/settings.agentwarden.windows.json` **(new)**: identical except that the interpreter is `python`. Plain Windows installs (python.org installer, `uv python install`) put `python` on PATH, not `python3`, and `python3` on Windows may be the Microsoft Store stub that opens the Store.
- Both: PreToolUse `on_tool.py` with `"timeout": 15`; UserPromptSubmit `on_prompt.py` with `"timeout": 5`. No PostToolUse entry (`on_read.py` does not exist yet).
- `hook-protocol` skill: the "Settings for the product hooks" section points to both files and states the timeout budget (8 s daemon call < 15 s hook timeout).

Two files rather than one "portable" command: there is no single interpreter name that works on stock Windows and stock Debian/Ubuntu/macOS, and wrapping the hook in `uv run` adds ~300 ms+ per tool call plus a dependency on the project venv (see Decision 1).

## Interface

- `hooks/on_tool.py`, rewritten. Stdlib only, no `agentwarden`/`httpx` imports. Importable from tests (no side effects at import time; `_common` is imported inside functions, as today). Pure, unit-testable functions (names are binding for tests, bodies left to the planner):
  - `parse_verdict(status: int, body: bytes) -> dict | None`: the validation above; `None` means invalid.
  - `build_output(verdict: dict, allow_mode: str) -> str`: returns the stdout string (`""` for passthrough allow).
  - `failsafe_output(notify: bool) -> str`: the "AgentWarden unavailable" ask JSON.
  - `decide_url() -> str | None`: reads `WARDEN_URL`, validates it, returns `<base>/decide` or `None`.
  - `call_daemon(url: str, body: bytes, deadline_s: float) -> tuple[int, bytes] | None`: `None` on any transport error or deadline.
  - `run(stdin_bytes: bytes, env: Mapping[str, str]) -> str`: the whole pipeline, never raises; `__main__` writes its result and exits 0.
- `src/agentwarden/decide.py`: `_with_system_message` renamed to `with_system_message` (public).
- `src/agentwarden/daemon.py`: `/decide` failsafe returns wrapped with `with_system_message`.
- `examples/settings.agentwarden.windows.json`: new.
- `.claude/skills/hook-protocol/SKILL.md`: settings section and the systemMessage VERIFY note updated (manual criterion below).

Env vars read by the hook (from Claude Code's environment, which the agent's Bash tool cannot change):

| Var | Default | Meaning |
|---|---|---|
| `WARDEN_URL` | `http://127.0.0.1:8765` | Same var `rules.daemon_port()` uses. Must be `http://` with host `127.0.0.1`, `localhost` or `[::1]`; anything else means fail closed. |
| `WARDEN_HOOK_TIMEOUT` | `8` | Seconds, float. Clamped to `(0, 10]`; unparsable or `<= 0` means 8. Exists so tests can exercise the timeout path in < 1 s; the clamp keeps it below the 15 s settings timeout. |
| `WARDEN_ALLOW` | `passthrough` | `explicit` makes `allow` verdicts print `permissionDecision: "allow"`. |
| `WARDEN_NOTIFY` | on | `off` suppresses the hook's own fail-closed `systemMessage`. |
| `AGENTWARDEN_HOME` | `<cwd>/.agentwarden` | Unchanged (event recording). |

## Decisions

1. **Stdlib `urllib.request`, not `httpx`/`agentwarden`.** Spec 001's "standard library only" was framed around event capture, but the actual reason holds even more strongly for the decision hook. Claude Code runs `python3 ".../hooks/on_tool.py"` with whatever interpreter is on PATH, not the project venv, so `httpx` is usually **not importable** there. A failed import inside `try` would make every single tool call `ask` (unusable). A failed import outside `try` would crash the hook with exit 1, which Claude Code treats as non-blocking, so the tool runs (**fail open**, a direct breach of invariant 1). Stdlib removes that whole class of failure, and it also avoids ~100–200 ms of `httpx`/`pydantic` import time on every tool call. The cost is duplicating a small shape check of `Verdict`, which the model-generated contract test covers.
2. **Hard wall-clock deadline via a worker thread.** `urllib`'s `timeout=` applies per socket operation, not to the whole request: a daemon that trickles one byte every 7 s would never time out, and the hook would hit Claude Code's 15 s timeout, which is **fail open**. So `call_daemon` runs the request in a daemon thread and `join(deadline_s)`s it. If the thread is still alive, the result is `None` and we take the fail-closed path. The process then exits, and the daemon thread dies with it. Socket `timeout=` is also set to `deadline_s` as a second guard. Budget: Python start + record (< 0.5 s) + 8 s call < 15 s settings timeout, a margin of over 6 s.
3. **Proxies disabled.** `urllib` honours `HTTP_PROXY`/`HTTPS_PROXY` from the environment. A proxy would receive the full tool event, including file contents of a `Write`, which breaks invariants 2 and 3. The hook builds its opener with `ProxyHandler({})`. No redirects are followed: a 3xx response is not 200, so the hook fails closed.
4. **Loopback-only `WARDEN_URL`.** The event is not redacted before it reaches the daemon (redaction happens daemon-side before any model call). Sending it to a non-loopback host would make AgentWarden itself an exfiltration path. A misconfigured URL fails closed instead of sending.
5. **Forward original bytes.** The hook POSTs the stdin bytes unchanged rather than re-serialising, so the daemon sees exactly what Claude Code sent. The hook parses the JSON only to check that it is an object (and for recording).
6. **`allow` defaults to passthrough** (see Behaviour). `explicit` is opt-in.
7. **ASCII-only stdout, UTF-8 stdin** (see Behaviour steps 1 and 5): both are Windows-specific traps that would otherwise produce mojibake or a crash.
8. **Daemon-side `system_message` for failsafes** instead of the hook inventing text for daemon verdicts. One owner for the wording, and `/decide`'s contract becomes "deny/ask always carries a message".

## Failure paths

Every path ends in the fail-closed `ask` output (`permissionDecisionReason: "AgentWarden unavailable"`, `systemMessage` unless `WARDEN_NOTIFY=off`), exit 0, nothing else on stdout:

- Daemon unreachable (connection refused, DNS, network unreachable) → fail-closed `ask`.
- Daemon too slow: no full response within `WARDEN_HOOK_TIMEOUT` (default 8 s), including slow-drip bodies → fail-closed `ask`.
- Non-200 status (4xx, 5xx, 3xx redirect) → fail-closed `ask`.
- Body > 64 KiB, not UTF-8, not JSON, JSON but not an object → fail-closed `ask`.
- Verdict shape invalid: missing/unknown `decision`, `"Allow"`/`" allow"`, non-string `reason`, non-string non-null `system_message` → fail-closed `ask`.
- `WARDEN_URL` not loopback `http://`, or unparsable → fail-closed `ask`, no request sent.
- Stdin empty, not UTF-8, not JSON, or JSON but not an object → fail-closed `ask`, no request sent. (This changes spec 001's behaviour, where invalid stdin printed nothing. From now on silence would mean "no opinion" and let Claude Code's normal flow decide, so we fail closed instead.)
- Event recording fails (unwritable `AGENTWARDEN_HOME`) → ignored; the decision proceeds normally.
- Any other exception anywhere in `run()` → caught at the top level → fail-closed `ask`.
- Daemon itself errors (invalid event, `decide()` raises, audit log down) → the daemon returns 200 + `ask` (spec 002), now with `system_message` → the hook passes it through as a normal `ask`.

Known residual paths the script **cannot** close, documented here so nobody assumes otherwise:

- Interpreter missing or not on PATH (`python3`/`python` not found) → the shell exits 127/9009, which Claude Code treats as a non-blocking error, so the tool **runs**. Mitigation: the manual install check below, and choosing the right example file. Detecting this from inside the hook is impossible by construction.
- Writing to stdout itself fails (closed pipe) → no output, so Claude Code's normal permission flow runs (not an explicit allow).
- The hook script file is edited or deleted by the agent → out of scope (see below).

## Acceptance criteria

Tests run `on_tool.py` as a real subprocess (house style, `tests/hooks/_support.py`) against a **stub daemon**: a `http.server.ThreadingHTTPServer` on `127.0.0.1:0` in a pytest fixture, with configurable status, body, delay and slow-drip, recording the request it received. `WARDEN_URL` points the hook at it. That URL override is what makes the tests possible: the real hook code path (urllib, threading, encoding, exit code) runs end to end, and no test can accidentally hit a real daemon on 8765. `run_hook` gains `env` overrides and **defaults `WARDEN_URL` to a closed loopback port**, so legacy tests never reach a developer's running daemon. Pure functions are additionally unit-tested in-process (import `hooks/on_tool.py` with `hooks/` on `sys.path`). Tests that bind a port need loopback binding: if the agent sandbox blocks it, run `make test` outside the sandbox. These tests must **fail, not skip**, when they cannot bind.

Hook, happy paths:
- [ ] `test_deny_verdict_maps_to_deny_output`: stub returns `Verdict(decision="deny", reason=..., source="rules", system_message="🛡 ...").model_dump_json()`; stdout parses to the exact deny shape, `systemMessage` equals the message, exit 0.
- [ ] `test_ask_verdict_maps_to_ask_output`
- [ ] `test_system_message_omitted_when_null`: stub returns `system_message: null`; the `systemMessage` key is absent (not `null`).
- [ ] `test_allow_passthrough_prints_nothing`: default env, allow verdict, stdout `""`, exit 0.
- [ ] `test_allow_explicit_mode`: `WARDEN_ALLOW=explicit`, stdout has `permissionDecision: "allow"` and no `systemMessage`.
- [ ] `test_stdout_is_ascii_only`: deny with 🛡 and a non-ASCII reason; `result.stdout` (bytes) is pure ASCII and round-trips through `json.loads` to the original text.
- [ ] `test_forwards_original_bytes`: the stub records the request body; it equals the stdin bytes; the path is `/decide`; the method is POST.
- [ ] `test_non_ascii_stdin_forwarded_intact`: a `file_path` containing `é`/`ж` arrives at the stub unchanged.
- [ ] `test_still_records_event`: the spec 001 recording still happens alongside a decision.

Hook, fail-closed paths (each asserts: exit 0, stdout is exactly the fail-closed ask JSON, `permissionDecisionReason == "AgentWarden unavailable"`):
- [ ] `test_daemon_unreachable_asks`: `WARDEN_URL` at a closed port.
- [ ] `test_daemon_timeout_asks`: stub delays 2 s, `WARDEN_HOOK_TIMEOUT=0.5`; the hook finishes in < 1.5 s.
- [ ] `test_slow_drip_body_asks`: stub sends headers and then one byte every 0.2 s for 3 s, `WARDEN_HOOK_TIMEOUT=0.5`; the hook finishes in < 1.5 s (proves the wall-clock deadline, Decision 2).
- [ ] `test_non_200_asks`: parametrised 302, 404, 500.
- [ ] `test_non_json_body_asks`
- [ ] `test_oversized_body_asks`: > 64 KiB.
- [ ] `test_invalid_verdict_shape_asks`: parametrised: no `decision`; `"Allow"`; `"maybe"`; `reason` is int; `system_message` is a list; body is a JSON array.
- [ ] `test_non_loopback_url_asks_without_request`: `WARDEN_URL=http://example.com:8765`; the stub receives nothing.
- [ ] `test_proxy_env_ignored`: `HTTP_PROXY` points to a second stub; the decision still comes from the real stub, and the proxy stub receives nothing.
- [ ] `test_invalid_stdin_asks`: parametrised: garbage, empty, `[1,2]`, invalid UTF-8 bytes. No request reaches the stub.
- [ ] `test_unwritable_home_still_decides`: unwritable `AGENTWARDEN_HOME` plus a stub deny gives the deny output.
- [ ] `test_failsafe_respects_notify_off`: `WARDEN_NOTIFY=off`, daemon down; there is no `systemMessage` key.
- [ ] `test_hook_timeout_env_clamped`: unit-level: `"0"`, `"-1"`, `"abc"` give 8; `"99"` gives 10.

End to end (real daemon, no network beyond loopback, not `slow`):
- [ ] `test_e2e_real_daemon_denies_ssh_key`: uvicorn serves `create_app(tmp_db)` on a free loopback port in a thread; the hook gets a `Read ~/.ssh/id_rsa` event; stdout is a deny with a 🛡 `systemMessage`; the audit row exists.

Daemon:
- [ ] `test_decide_failsafe_has_system_message`: invalid body to `/decide` gives `ask` with `system_message` starting with `🛡 AgentWarden`.
- [ ] `test_decide_failsafe_notify_off`: same with `WARDEN_NOTIFY=off` gives `system_message is None`.
- [ ] Existing `decide()` notification tests still pass after the rename.

Settings and housekeeping:
- [ ] `test_example_settings_files`: both example files are valid JSON; POSIX uses `python3`, Windows uses `python`; PreToolUse `timeout` is 15 and greater than the hook's maximum deadline of 10.
- [ ] Spec 001 tests updated where behaviour intentionally changed (`test_on_tool_makes_no_decision`, `test_invalid_json_is_ignored` and `test_hooks_print_nothing` for `on_tool`). `on_prompt.py` tests stay unchanged.
- [ ] `make test` green, `make lint` clean.
- [ ] Manual (human, real Claude Code on Windows): copy the Windows example into a scratch project, `make run`, ask the agent to `cat ~/.ssh/id_rsa` and confirm a deny with the 🛡 line. Stop the daemon, run any Bash command, and confirm an `ask` with "AgentWarden unavailable". Record how `systemMessage` renders in the VS Code extension and the CLI in the `hook-protocol` skill (closes its VERIFY note).
- [ ] Manual: confirm in the hooks docs whether a hook `permissionDecision: "allow"` overrides `deny` rules in `settings.json` permissions, and note the answer in `hook-protocol` (relevant to `WARDEN_ALLOW=explicit`).

## Out of scope

- **Protecting the hook scripts themselves** (`hooks/` under `${CLAUDE_PROJECT_DIR}` is agent-editable; moving them to `~/.agentwarden/hooks/` and adding self-protection rules). This is a separate self-protection follow-up already tracked in `docs/SESSION.md`; it is not folded in here.
- `on_prompt.py` → `/event` (recording the session task in the daemon). It stays a stdlib recorder; it will be wired when the judge spec needs the task.
- `on_read.py` / PostToolUse scanner wiring.
- Judge/cascade latency budget inside the daemon (the future judge spec must fit `/decide` under ~7 s so the 8 s hook deadline holds).
- Any change to `rules.py`, `policy.py`, `Verdict` fields, or the wording of decide's `system_message`.
- Richer `systemMessage` text (naming the file/category, e.g. "blocked reading .env — secrets"). The current generic wording from spec 004 stays.
- Installing the hooks into this repo's own `.claude/settings.json` (dogfooding starts 29.10, separate step).
- A daemon auto-start or health-check step in the hook.

## Demo impact

Yes, this is the first spec where the viewer sees AgentWarden act inside Claude Code: the agent's `cat ~/.ssh/id_rsa` is blocked with the `🛡 AgentWarden: blocked this action (rules)` line, and stopping the daemon produces an "AgentWarden unavailable" confirmation instead of silently letting actions through (the fail-closed shot). With the default `WARDEN_ALLOW=passthrough`, safe actions look exactly as they do without AgentWarden. If the demo wants to show "fewer prompts", record it with `WARDEN_ALLOW=explicit`.
