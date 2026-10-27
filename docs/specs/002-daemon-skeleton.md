# 002 — Daemon skeleton, models, SQLite audit log

Size: large

## Context

Spec 001 captured the real hook payloads (see `hook-protocol` skill). This spec adds the long-running daemon the hooks will call: typed models for those payloads, the `/event`, `/decide`, `/log` endpoints, and a SQLite audit log. There is no policy yet — `/decide` always answers `ask` — so rules (next spec) and the judge plug into a working, tested pipe. Hooks are not wired to the daemon here.

## Behaviour

- `POST /event` takes a UserPromptSubmit payload, stores the prompt, returns `204`.
- `POST /decide` takes a PreToolUse payload, runs `decide()`, writes one audit row, returns the verdict. In this spec `decide()` always returns `ask` with source `default`.
- `GET /log` returns recent audit rows, newest first.
- `GET /health` returns `{"status": "ok"}`.
- Unknown extra fields in payloads (`scratchpad_dir`, `effort`, `transcript_path`, future ones) are accepted and ignored.

Example:

```
POST /decide
{"session_id": "s1", "prompt_id": "p1", "cwd": "D:\\proj", "permission_mode": "auto",
 "effort": {"level": "medium"}, "hook_event_name": "PreToolUse", "tool_name": "Bash",
 "tool_input": {"command": "ls", "description": "List files"}, "tool_use_id": "toolu_1"}

200 {"decision": "ask", "reason": "No policy configured yet.", "risk": null, "source": "default"}
```

```
GET /log?limit=2&session_id=s1
200 [{"id": 7, "created_at": "2026-10-27T09:00:00+00:00", "session_id": "s1", "prompt_id": "p1",
      "tool_use_id": "toolu_1", "tool_name": "Bash", "tool_input": {"command": "ls", ...},
      "cwd": "D:\\proj", "decision": "ask", "reason": "No policy configured yet.",
      "risk": null, "source": "default", "latency_ms": 1}, ...]
```

## Interface

`src/agentwarden/models.py` (pydantic v2, `extra="ignore"` on event models):

```python
DecisionValue = Literal["allow", "deny", "ask"]
VerdictSource = Literal["rules", "judge", "failsafe", "default"]

class ToolEvent(BaseModel):          # PreToolUse
    session_id: str
    prompt_id: str | None = None
    cwd: str
    permission_mode: str | None = None
    hook_event_name: Literal["PreToolUse"]
    tool_name: str
    tool_input: dict[str, Any]
    tool_use_id: str | None = None

class PromptEvent(BaseModel):        # UserPromptSubmit
    session_id: str
    prompt_id: str | None = None
    cwd: str
    permission_mode: str | None = None
    hook_event_name: Literal["UserPromptSubmit"]
    prompt: str

class Verdict(BaseModel):
    decision: DecisionValue
    reason: str
    risk: float | None = None        # 0.0–1.0 when set; validated
    source: VerdictSource

def failsafe(reason: str) -> Verdict   # decision="ask", source="failsafe"
```

`src/agentwarden/decide.py`:

```python
def decide(event: ToolEvent) -> Verdict   # 002: always ask, source="default"
```

`src/agentwarden/store.py`:

```python
class Store:
    def __init__(self, db_path: Path): ...      # creates parent dir + schema, WAL mode
    def add_prompt(self, event: PromptEvent) -> None
    def add_decision(self, event: ToolEvent, verdict: Verdict, latency_ms: int) -> int
    def recent_decisions(self, limit: int = 50, session_id: str | None = None) -> list[dict]
    def session_prompts(self, session_id: str) -> list[str]   # oldest first; for the judge later
```

- One `sqlite3` connection per call (endpoints run in a thread pool; no shared connection).
- Tables `prompts(id, created_at, session_id, prompt_id, cwd, prompt)` and `decisions(id, created_at, session_id, prompt_id, tool_use_id, tool_name, tool_input_json, cwd, decision, reason, risk, source, latency_ms)`. `created_at` is UTC ISO 8601.

`src/agentwarden/daemon.py`:

```python
def create_app(db_path: Path | None = None) -> FastAPI
app = create_app()        # for `make run`; must not open the DB at import time
```

- DB path: argument, else env `AGENTWARDEN_DB`, else `~/.agentwarden/audit.db`. Opened on startup (lifespan), not at import.
- `GET /log` params: `limit` (1–500, default 50), `session_id` (optional).

## Failure paths

Every `/decide` failure returns `200` with a `failsafe` verdict (`decision: "ask"`), never `allow`:

- Body is not JSON, or fails `ToolEvent` validation (missing `tool_name`, wrong `hook_event_name`, `tool_input` not an object) → `ask`, reason `"AgentWarden: invalid event"`. Nothing written to `decisions` (no valid event to record).
- `decide()` raises → `ask`, reason `"AgentWarden: internal error"`; the row is still written with source `failsafe`.
- Writing the audit row fails (DB locked, unwritable, disk full) → `ask`, reason `"AgentWarden: audit log unavailable"`, even if `decide()` returned something else. An action we can't record is not allowed silently.
- Any other unexpected exception in the handler → `ask`, reason `"AgentWarden: internal error"`.
- Error details go to stderr/logging only, never into `reason` (reason is shown to the agent).

`/event` (no decision involved): invalid payload → `422`; store failure → `500`. The prompt hook ignores the response, so neither blocks the user.

## Acceptance criteria

- [x] `test_tool_event_accepts_real_payloads` — the captured Bash/Read/Write/Edit payloads from the `hook-protocol` skill parse into `ToolEvent`; extras ignored.
- [x] `test_prompt_event_accepts_real_payload` — captured UserPromptSubmit payload parses into `PromptEvent`.
- [x] `test_verdict_risk_bounds` — `risk` outside 0–1 is rejected.
- [x] `test_decide_default_is_ask` — `decide()` returns `ask`, source `default`, for any tool.
- [x] `test_store_roundtrip` — `add_decision` then `recent_decisions` returns the row with `tool_input` decoded back to a dict; newest first; `limit` and `session_id` filter work.
- [x] `test_store_session_prompts` — prompts returned oldest first, only for the given session.
- [x] `test_decide_endpoint_returns_ask_and_logs` — `POST /decide` with a real payload → `200`, `decision == "ask"`, one row in `/log`.
- [x] `test_decide_invalid_json_is_ask` — garbage body → `200`, `ask`, source `failsafe`, nothing logged.
- [x] `test_decide_invalid_event_is_ask` — valid JSON missing `tool_name` → `200`, `ask`, source `failsafe`.
- [x] `test_decide_exception_is_ask` — `decide()` monkeypatched to raise → `200`, `ask`, source `failsafe`, row logged with source `failsafe`; reason contains no exception text.
- [x] `test_store_failure_is_ask` — `Store.add_decision` monkeypatched to raise, with `decide()` patched to return `allow` → response is `ask`, source `failsafe`.
- [x] `test_event_endpoint_stores_prompt` — `POST /event` → `204`; prompt visible via `session_prompts`.
- [x] `test_event_invalid_is_422`.
- [x] `test_log_limit_bounds` — `limit=0` and `limit=501` → `422`.
- [x] `test_health`.
- [x] `test_app_import_has_no_side_effects` — importing `agentwarden.daemon` with `AGENTWARDEN_DB` pointing into `tmp_path` creates no file until the app starts.
- [x] All tests use `tmp_path` DBs; none touch `~/.agentwarden` or the network.
- [x] `make test` green, `make lint` clean.
- [ ] Manual: `make run`, `curl` a captured payload to `/decide`, see it in `/log`. (Sandbox blocks binding a port/curl in this session — needs to be run by hand.)

## Out of scope

- Wiring `hooks/on_tool.py` / `on_prompt.py` to the daemon and the fail-closed hook wrapper (separate spec; spec 001's note "from 002 on, exceptions in on_tool.py must produce ask" moves there).
- Rules, judge, providers, redaction, risk thresholds.
- Dashboard HTML page.
- Auth between hook and daemon, Host-header / DNS-rebinding protection, log retention and rotation, redacting secrets stored in the local DB.
- `PostToolUse` or any other hook event.

## Demo impact

None visible yet. `/log` is the data source for the dashboard and the metrics table later.
