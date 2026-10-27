# NNN — User policy file, self-protection and visible notifications

Size: large
Planned: Tue 27 Oct together with rules (fold into the rules spec if it is not written yet, otherwise do right after it).

## Context

The user needs to control what the agent may do without editing code, and to see what AgentWarden did without opening a dashboard. A policy file the agent can edit, or a daemon the agent can call, would let the agent switch the protection off, so self-protection is part of this spec.

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
1. Built-in hard denies (secrets, self-protection below). Policy can never weaken these.
2. Policy `deny_*` → `deny`.
3. Policy `ask_*` → `ask`.
4. Policy `allow_*` → `allow`.
5. Built-in defaults, then the cascade.

Matching: paths by glob relative to the project root; commands by prefix after whitespace normalisation; domains by exact host or subdomain.

### Self-protection (built-in hard denies)

Moved to spec 003 (`docs/specs/003-builtin-rules.md`), already implemented there. This spec only inserts the policy stage between 003's hard denies and built-in defaults, and must test that no policy entry can weaken them.

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

## Acceptance criteria

- [ ] `test_policy_deny_path_blocks`
- [ ] `test_policy_allow_cannot_override_builtin_secret_deny`
- [ ] `test_policy_reload_on_change`
- [ ] `test_invalid_policy_uses_defaults_and_warns`
- [ ] `test_policy_allow_cannot_override_self_protection` — `allow_paths: [".agentwarden/"]`, `allow_commands: ["curl"]` still deny editing the policy file and calling the daemon.
- [ ] `test_deny_and_ask_include_system_message`
- [ ] Eval: `tamper` category cases (≥ 10) all end in `deny`.
- [ ] Eval runs use a fixed policy `eval/policy.eval.yaml` so results are reproducible.

## Out of scope

Dashboard buttons (dashboard spec). Per-user or org-wide policies.

## Demo impact

Yes: the 🛡 line in Claude Code is what the viewer sees; the policy file is shown in the "you stay in control" part.
