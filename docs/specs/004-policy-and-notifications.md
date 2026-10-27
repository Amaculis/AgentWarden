# 004 — User policy file, self-protection and visible notifications

Size: large

## Context

The user needs to control what the agent may do without editing code, and to see what AgentWarden did without opening a dashboard. A policy file the agent can edit, or a daemon the agent can call, would let the agent switch the protection off, so self-protection is part of this spec. Self-protection hard denies were already implemented in `docs/specs/003-builtin-rules.md`; this spec fills the `_policy_stage` hook point `rules.py` left empty and adds notifications.

## Behaviour

### Policy file

`.agentwarden/policy.yaml` in the protected project, user-edited (or via dashboard buttons later). Loaded on every decision if its mtime changed.

```yaml
version: 1
deny_paths: ["secrets/", "*.pem", "*.key"]
ask_paths: ["migrations/", "infra/"]
allow_paths: ["docs/"]
deny_commands: ["terraform apply", "kubectl delete", "git push --force"]
ask_commands: ["npm publish"]
allow_commands: ["make test", "uv run pytest"]
allow_domains: ["pypi.org", "github.com"]
```

Precedence, strongest first:
1. Built-in hard denies (secrets, self-protection — spec 003). Policy can never weaken these.
2. Policy `deny_*` → `deny`.
3. Policy `ask_*` → `ask`.
4. Policy `allow_*` → `allow`.
5. Built-in defaults, then the cascade.

Matching: paths by glob relative to the project root; commands by prefix after whitespace normalisation; domains by exact host or subdomain.

### Self-protection (built-in hard denies)

Already implemented in spec 003. This spec only inserts the policy stage between 003's hard denies and built-in defaults, and must test that no policy entry can weaken them.

### Notifications

Hook output adds `systemMessage` (shown to the user, not the agent) for `deny` and `ask`:
`🛡 AgentWarden: blocked reading .env — secrets (rules)` / `… (local model)` / `… (Muse Spark)`.
Allows stay silent. `WARDEN_NOTIFY=off` disables it.

## Interface

- `src/agentwarden/policy.py`: `load_policy(project_root) -> Policy`, `match(policy, action) -> Decision | None`.
- `rules.py` calls built-in hard denies first, then policy, then built-in defaults.
- Env: `WARDEN_POLICY` (path override), `WARDEN_NOTIFY`.
- Verdict gains `source: "builtin" | "policy" | "local" | "spark"` (used in `systemMessage` and the log).

## Failure paths

- Policy file missing → built-in defaults only.
- Policy file invalid YAML or schema → ignore the file, log an error, add a `systemMessage` once per session: "AgentWarden: policy.yaml is invalid, using defaults". Never fall back to allow-all.
- Policy file unreadable (permissions, race during write) → treat like missing, built-in defaults only, never allow-all.

## Acceptance criteria

- [x] `test_policy_deny_path_blocks`
- [x] `test_policy_allow_cannot_override_builtin_secret_deny`
- [x] `test_policy_reload_on_change`
- [x] `test_invalid_policy_uses_defaults_and_warns`
- [x] `test_policy_allow_cannot_override_self_protection` — `allow_paths: [".agentwarden/"]`, `allow_commands: ["curl"]` still deny editing the policy file and calling the daemon.
- [x] `test_deny_and_ask_include_system_message`
- [x] `make test` green, `make lint` clean
- [x] Eval: `tamper` category cases (≥ 10) all end in `deny` — 15 hand-crafted cases in `eval/candidates/tamper.jsonl`, pending human review before promotion to `eval/cases/` (no eval runner exists yet to execute them against).
- [x] Eval runs use a fixed policy `eval/policy.eval.yaml` so results are reproducible — file already present.

## Decisions (resolved during planning)

- `VerdictSource` gains `"policy"` only. The existing `"rules"` value stays as-is for hard-deny/
  default verdicts (no rename to `"builtin"`); `"local"`/`"spark"` are added by the judge/cascade
  specs, not here.
- `Verdict` gains `system_message: str | None = None`, built by a small helper called from
  `decide.py` (checks `WARDEN_NOTIFY`). Wiring that message into `hooks/on_tool.py`'s actual
  hook output is out of scope here — the hooks don't call `/decide` yet (separate hook-wiring
  spec); this spec proves the message at the `decide()`/`/decide` level.
- `policy.py` reuses `rules.py`'s path/command normalisation helpers (`_path_parts`,
  `_is_inside_project`, etc.) rather than duplicating that logic — spec 003 already found a real
  bug in ad hoc path handling, so one implementation of path matching is safer.
- `allow_domains`/`deny_domains` style matching applies only to `WebFetch`'s `url` field. Command
  policy (`deny_commands`/`ask_commands`/`allow_commands`) is a plain prefix match on the
  normalised command string; it does not parse URLs out of `curl`/`wget` arguments.

## Out of scope

Dashboard buttons (dashboard spec). Per-user or org-wide policies. Wiring `systemMessage` into
`hooks/on_tool.py` (needs the hooks to call `/decide`, which is a separate spec).

## Demo impact

Yes: the 🛡 line in Claude Code is what the viewer sees; the policy file is shown in the "you stay in control" part.
