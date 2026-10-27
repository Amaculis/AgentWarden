# 015 — Dashboard in the IDE: decision feed and "always allow / always deny"

Size: large. Backend (token, policy writes, endpoints) by Claude — it is security-relevant.
The page itself (`dashboard/index.html`) by Muse Code from `docs/handoff/015-dashboard.md`,
reviewed by Sonnet, commit marked `(Muse Code)`.

## Context

The user needs to see what the agent is doing and correct AgentWarden in one click. Opened in
VS Code with `Simple Browser: Show`, next to the agent, without a VS Code extension. Kept
secondary on purpose: the organisers list "dashboards as the main feature" as overdone.

## Behaviour

- `GET /` serves `src/agentwarden/dashboard/index.html` (no secrets in it). Until Muse Code
  delivers the page, a minimal placeholder is served.
- `GET /log?limit=&session_id=&decision=&source=&since_id=` — decision feed, newest first;
  `since_id` returns only rows with `id > since_id` (for 2 s polling).
- `GET /scans?limit=&session_id=` — scanner log rows (no content is ever stored).
- `GET /policy?cwd=<project root>` — `{"path", "policy": {...lists}, "exists"}`.
- `POST /policy/rules` with header `X-Warden-Token` and body
  `{"cwd", "kind", "value"}` → appends `value` to list `kind` in that project's policy file.
  - `kind` ∈ `deny_commands ask_commands allow_commands deny_paths ask_paths allow_paths
    allow_domains`.
  - `value`: non-empty, one line, ≤ 200 chars, no control characters.
  - Already present → `200 {"ok": true, "added": false}`.
  - Missing/invalid token → `403`, logged, nothing written. Invalid body → `400`/`422`.
- UI token: random (`secrets.token_urlsafe(32)`) per daemon start, compared with
  `hmac.compare_digest`. The daemon writes the dashboard URL
  `http://127.0.0.1:<port>/#token=<token>` to `<AGENTWARDEN_HOME or ~/.agentwarden>/ui_url`
  and logs it at startup. The `#fragment` is never sent to the server; the page reads it and
  sends it as `X-Warden-Token`. The protected agent cannot read `.agentwarden/` nor call the
  daemon (built-in hard denies, invariant 7) — the token is the second layer.
- `policy.append_rule(path, kind, value)`: loads the YAML (missing file → new policy with
  `version: 1`), appends, validates the result as a `Policy`, writes atomically (temp file +
  replace). Leading `#` comment lines are kept; other comments are lost (documented trade-off,
  no ruamel dependency). Built-in hard denies are unaffected: they run before the policy stage.

Superseded by 018: the token URL is printed to the daemon console only (no `ui_url` file),
requests need a loopback `Host`/`Origin`, and `cwd` must be a local path already in the audit
log.

## Failure paths

- Unreadable/invalid existing policy YAML → `400`, file left untouched (never overwrite a
  file we could not parse).
- Write error → `500` with a short message, original file intact (atomic replace).
- Daemon down → the page shows a "daemon not reachable" banner (page's job).

## Acceptance criteria

- [x] `test_policy_rules_endpoint_requires_token` (missing, wrong → 403, file untouched)
- [x] `test_policy_rules_appends_and_dedups`
- [x] `test_append_rule_validates_and_preserves_file` (bad kind/value → error; leading comments
      kept; invalid existing YAML → error, untouched)
- [x] `test_log_filter_by_decision_and_source` and `since_id`
- [x] `test_ui_url_written_with_token`
- [x] `test_root_serves_html_without_token`
- [x] `make test` green, `make lint` clean.
- [ ] Muse Code: page per handoff; Sonnet review; commit `(Muse Code)`.
- [ ] Manual: Simple Browser next to Claude Code; a blocked action appears within 2 s;
      "Always deny" on an ask row makes the same action deny on retry.

## Out of scope

VS Code extension, status bar, auth beyond the local token, charts.

## Demo impact

Yes, 20–30 s at most: the feed next to the agent, and one "Always deny" click.
