# Handoff 015 — dashboard page (for Muse Code, Standard tier)

Goal: one self-contained HTML page that shows AgentWarden's live decision feed and lets the
user add "always allow / always deny" rules, served by the existing daemon at `GET /`.

Read first: CLAUDE.md, docs/specs/015-dashboard.md, src/agentwarden/daemon.py (endpoints
only), src/agentwarden/store.py (`decisions` and `scans` columns).

May change: `src/agentwarden/dashboard/index.html` (create it; it is the only file).

Must not change: everything else, especially src/agentwarden/daemon.py, policy.py, decide.py,
redact.py, hooks/, prompts/, eval/cases/, tests/.

Contract (all JSON, same origin, daemon on 127.0.0.1):

- `GET /log?limit=100&since_id=<id>&decision=<allow|deny|ask>&source=<rules|policy|judge|failsafe|default|local|spark>`
  → array, newest first, rows: `id, created_at, session_id, tool_name, tool_input (object),
  cwd, decision, reason, risk (0-1 or null), source, latency_ms, confidence, decided_by
  (rules|local|spark|null), escalated (0/1), local_decision`.
- `GET /scans?limit=50` → rows: `id, created_at, session_id, tool_name, source (file/URL),
  flagged (0/1), confidence, error, latency_ms`. Show flagged ones as warning rows in the feed.
- `GET /policy?cwd=<row.cwd>` → `{"path", "exists", "policy": {deny_paths, ask_paths,
  allow_paths, deny_commands, ask_commands, allow_commands, allow_domains}}`.
- `POST /policy/rules` with header `X-Warden-Token: <token>` and body
  `{"cwd": <row.cwd>, "kind": <one of the 7 list names>, "value": <string>}` →
  `200 {"ok": true, "added": bool, "path"}`, `400 {"detail"}` invalid rule, `403` bad token.
- Token: read it once from `location.hash` (`#token=...`), keep it in memory, then
  `history.replaceState` to drop the hash from the URL bar. Never put it in localStorage,
  query strings or logs. No token → buttons disabled with a hint "open the URL from
  ~/.agentwarden/ui_url".

Page behaviour:

- Feed: poll `/log?since_id=<max id seen>` every 2 s, prepend new rows. Columns: time, tool,
  short action (`tool_input.command` for Bash/PowerShell, `file_path`/`url`/`pattern`
  otherwise; truncate to ~80 chars, full text in a `title` tooltip), decision badge
  (allow green / ask amber / deny red), decided by (`decided_by` or `source`; show
  "escalated → spark" when `escalated` is 1), risk %, reason.
- Filters: decision (all/deny/ask/allow), decided by.
- Counters for the selected session (default: newest session): actions, allowed, asked,
  denied, % decided locally (`decided_by == "local"` / judged), % escalated.
- On deny/ask rows: buttons "Always allow" / "Always deny". Clicking opens a small inline
  confirm showing the exact rule (`allow_commands: "<command>"` for shell tools,
  `allow_paths: "<file_path>"` for file tools; same for deny), editable before saving.
  On save POST `/policy/rules`; show the result or the `detail` error.
- Policy panel: read-only lists from `/policy` for the selected row's `cwd`.
- Banner "AgentWarden daemon not reachable" when a poll fails; clear it on success.

Security in the page:

- Insert all data with `textContent` / `createElement` only — never `innerHTML` with row
  data (tool inputs and reasons are attacker-influenced text).
- No external scripts, fonts, CDNs or network calls other than the same-origin endpoints
  above. Inline `<style>` and `<script>` only.

Done when:

- `python -m pytest -q` still green (no test changes needed; the page is not tested by
  pytest).
- `make run`, open the URL from `~/.agentwarden/ui_url` in VS Code `Simple Browser: Show`:
  the feed lists events from `/log`, a new decision appears within 2 s, and "Always deny" on
  an ask row writes the rule (visible in the policy panel).

Style: one HTML file, no frameworks, no build step, no Streamlit; readable in both light and
dark VS Code themes (`prefers-color-scheme`); works at ~500 px width (side panel).
