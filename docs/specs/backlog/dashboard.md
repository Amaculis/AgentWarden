# NNN — Dashboard in the IDE: decision feed and "always allow / always deny"

Size: large
Planned: Sun 1 Nov. Implementation by Muse Code (handoff), review by Sonnet. Depends on: policy file, audit log.

## Context

The user needs to see what the agent is doing and correct AgentWarden in one click. Opened in VS Code with the built-in `Simple Browser: Show` command, so it sits next to the agent without a VS Code extension. Kept secondary on purpose: the organisers list "dashboards as the main feature" as overdone.

## Behaviour

`GET /` on the daemon serves one HTML page (no framework, no Streamlit, no build step):

- **Feed**: newest first, auto-refresh every 2 s. Each row: time, tool, short action (path or command), decision, decided by (rules / policy / local / Muse Spark), risk, reason, safer alternative. Scanner warnings appear as their own rows.
- **Filters**: decision (all / deny / ask / allow), decided by.
- **Counters** for the session: actions, allowed, asked, denied, % decided locally, % escalated.
- **Buttons** on each deny/ask row: "Always allow this" / "Always deny this". Opens a small confirm with the exact rule that will be added (e.g. `deny_commands: "terraform apply"`), which the user can edit before saving. On save, the daemon appends it to `.agentwarden/policy.yaml`.
- **Policy view**: read-only current policy, link to open the file.

## Security of the buttons

The agent must not be able to press them (self-protection already denies the agent any call to the daemon URL; this is the second layer):

- Policy-changing endpoint `POST /policy/rules` requires a one-time token. The daemon creates a random token at start, writes it to `.agentwarden/ui_token` (agent cannot read `.agentwarden/`), and the page gets it only from that file via a `GET /` that checks `Sec-Fetch-Site: none` / same-origin.
- Without a valid token → 403, logged.
- Daemon binds to 127.0.0.1 only.

## Interface

- `src/agentwarden/dashboard/index.html` (+ inline JS/CSS).
- Daemon: `GET /`, `GET /log?since=<id>&decision=&source=`, `GET /policy`, `POST /policy/rules`.
- `policy.py`: `append_rule(kind, value)` — validates, appends, keeps comments.

## Failure paths

- Daemon down → page shows "AgentWarden daemon not reachable" banner.
- Invalid rule from the form → 400 with message, nothing written.

## Acceptance criteria

- [ ] `test_policy_rules_endpoint_requires_token`
- [ ] `test_append_rule_validates_and_preserves_file`
- [ ] `test_log_filter_by_decision_and_source`
- [ ] Manual: open in VS Code Simple Browser next to a Claude Code session; a blocked action appears within 2 s; "Always deny" on an ask row makes the same action deny on retry.
- [ ] Handoff brief `docs/handoff/NNN-dashboard.md` used for Muse Code; commit marked `(Muse Code)`.

## Out of scope

VS Code extension, status bar, auth beyond the local token, charts.

## Demo impact

Yes, 20–30 s at most: the feed next to the agent, and one "Always deny" click.
