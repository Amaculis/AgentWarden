# 027 — agent adapter layer

Size: large

## Context

AgentWarden only understands Claude Code payloads: rules, policy, judge, eval and the dashboard
key on Claude tool names (`Bash`, `Write`, `Read`…). A foreign agent's shell tool (Muse Code
`exec_command`, for example) matches no rule, skips every hard deny and goes straight to the
judge, which may `allow` it. Three integrations (028 Muse Code, 029 Copilot, 030 Codex) will be
built in parallel branches; this spec adds the shared layer they plug into so each branch only
adds new files.

## Behaviour

The canonical event stays the Claude Code shape. An adapter translates a foreign event into it
at the daemon's entry; everything after that is unchanged.

- Each hook takes an optional `--agent <name>` argument (default `claude_code`) and sends it as
  the `X-AgentWarden-Agent` header on `/decide`, `/scan` and `/event`. The payload bytes are
  forwarded unchanged, so the agent name cannot be planted through the payload.
- The daemon picks the adapter by that header (missing → `claude_code`) and calls
  `adapter.normalize(kind, body)` before model validation. `claude_code` is the identity.
- A foreign tool the adapter maps (`exec_command` → `Bash`, its `cmd` → `command`) is decided
  exactly like the Claude tool: `rm -rf /` from Muse Code is the same hard deny.
- A foreign tool the adapter does not map → rules `ask` ("unknown <agent> tool <name>"), no
  model call. For `claude_code` unknown tools keep today's path (judge).
- Self-protection covers every registered agent's config, whatever agent is running: each
  adapter lists `config_paths` (e.g. `(".muse", "hooks.json")`, `(".github", "hooks")`), and a new
  hard-deny rule blocks writes/edits to them and shell commands that mention them. Reads stay
  allowed but are not auto-allowed by the safe-read rule (same as `.claude/settings.json`
  today). Link resolution (026) checks them too.
- Adapters are discovered: every module in `agentwarden/agents/` that defines `ADAPTER` is
  registered. A branch adds `agents/muse_code.py` and nothing else in the registry.
- Hook output: hooks keep the Claude Code output schema. An agent that needs another schema adds
  `hooks/formats/<agent>.py` (stdlib only) with `decision_output(decision, reason,
  system_message) -> str` and `scan_output(warning) -> str`; the hook imports it when present.

Example (Muse Code, after 028 adds its adapter):

```
stdin  {"hook_event_name":"PreToolUse","tool_name":"exec_command","tool_input":{"cmd":"rm -rf /"},...}
hook   POST /decide  X-AgentWarden-Agent: muse_code
daemon normalize → {"tool_name":"Bash","tool_input":{"command":"rm -rf /"},...} → rules deny
stdout {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",...}}
```

## Interface

- `src/agentwarden/agents/__init__.py`
  - `@dataclass(frozen=True) class Adapter`: `name: str`, `tool_map: Mapping[str, str]`
    (foreign tool → canonical tool), `input_map: Mapping[str, Mapping[str, str]]` (canonical
    tool → {foreign field: canonical field}), `config_paths: tuple[tuple[str, ...], ...]`,
    `passthrough: bool = False` (identity; unknown tools go to the judge).
  - `Adapter.normalize(kind: Literal["tool", "read", "prompt"], body: dict) -> dict` — returns a
    new dict; `tool_name`/`tool_input` translated for `tool` and `read`; a mapped tool keeps the
    original name in `agent_tool_name`. Unmapped tool in a non-passthrough adapter →
    `tool_name = "<agent>:<foreign name>"` (rules `ask` it, see below). Never raises on
    shape problems the models already reject; raises `AdapterError` on a non-dict `tool_input`.
  - `get_adapter(name: str | None) -> Adapter` — `None`/empty → `claude_code`; unknown or not
    matching `^[a-z][a-z0-9_]{0,31}$` → `AdapterError`.
  - `all_config_paths() -> tuple[tuple[str, ...], ...]` — union over all adapters.
- `src/agentwarden/agents/claude_code.py` — `ADAPTER = Adapter("claude_code", {}, {}, (),
  passthrough=True)`; `.claude/settings*.json` keeps its existing dedicated rule.
- `daemon.py` — `/decide`, `/scan`, `/event` read `X-AgentWarden-Agent` and normalize before
  `model_validate`. `/event` and `/scan` change from typed bodies to `Request` parsing; an
  invalid JSON or payload stays `422` as before.
- `rules.py`
  - new stage-1 rule `_agent_config_rule` after `_claude_settings_rule`;
  - `_target_verdict` and `_safe_read_rule` treat agent config paths like Claude settings;
  - stage-1 `_unknown_agent_tool_rule`: `tool_name` containing `:` → `ask`, before the model.
- `hooks/on_tool.py`, `hooks/on_read.py`, `hooks/on_prompt.py` — parse `--agent` from
  `sys.argv`, add the header; `on_tool.run(stdin_bytes, env, agent="claude_code")`.
  `call_daemon(url, body, deadline_s, headers=None)`.
- `hooks/formats/` — empty package (`__init__.py`) for branch formatters.

## Failure paths

- Unknown or malformed `--agent` in a hook → fail-safe `ask` (Claude output schema), no call.
- Unknown agent header at the daemon → `/decide` returns the fail-safe `ask`; `/scan` returns
  `{"warning": null}` and logs; `/event` returns 400 (the hook ignores it).
- `normalize` raises → fail-safe `ask` (`/decide`), no scan (`/scan`), 400 (`/event`).
- Unmapped foreign tool → rules `ask`, never the judge, never `allow`.
- Adapter module fails to import → logged, that adapter is missing → its header is unknown →
  `ask`. Other adapters still load.
- Formatter module in `hooks/formats/` fails to import or raises → Claude-schema fail-safe `ask`.

## Acceptance criteria

- [x] `test_agents.py::test_claude_code_is_identity` — Claude payloads normalize to themselves.
- [x] `test_agents.py::test_get_adapter_rejects_unknown_and_malformed_names`
- [x] `test_agents.py::test_discovery_registers_modules_with_adapter` (test adapter via
      monkeypatched registry)
- [x] `test_agents.py::test_mapped_shell_tool_hits_hard_deny` — fake adapter `exec_command`/`cmd`
      → `rm -rf /` deny, `cat .agentwarden/policy.yaml` deny, `ls` allow.
- [x] `test_agents.py::test_mapped_file_tool_hits_secret_and_boundary_rules`
- [x] `test_agents.py::test_unmapped_foreign_tool_asks_without_model` (mock provider not called)
- [x] `test_agents.py::test_agent_config_paths_are_hard_denied_for_every_agent` — write and shell
      mention of a fake adapter's config path denied even when the running agent is `claude_code`;
      read is `ask`/judge, not auto-allowed.
- [x] `test_agents.py::test_agent_config_link_is_denied` — junction to a config dir (026 path).
- [x] `test_daemon.py` — header selects adapter on `/decide`, `/scan`, `/event`; unknown header →
      fail-safe / null warning / 400; normalize error → fail-safe.
- [x] `tests/hooks/test_on_tool.py` — `--agent` sends the header; malformed `--agent` → fail-safe
      without a call; formatter module used when present, broken formatter → fail-safe.
- [x] `tests/hooks/test_on_read.py`, `test_on_prompt.py` — header forwarded.
- [x] Existing tests unchanged and green; `make eval-rules` delta 0.000.
- [x] `make test` green, `make lint` clean.

## Out of scope

- The Muse Code, Copilot and Codex adapters themselves (028, 029, 030).
- Storing the agent name in the audit log / showing it on the dashboard.
- Installers that write each agent's hook config.

## Demo impact

None by itself. It is what lets the demo show the same deny in Claude Code and Muse Code.
