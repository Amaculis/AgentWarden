---
name: warden-spec
description: Template and rules for writing a task spec in docs/specs/ before any implementation. Use when starting a new feature, fix or refactor in AgentWarden.
---

# Writing a spec

Every task starts with `docs/specs/NNN-short-name.md`. NNN is the next free three-digit number. Copy `docs/specs/000-template.md`.

Rules:

- One spec = one reviewable change, ideally one evening of work.
- Acceptance criteria are checkable: a test name, a command and its output, or a metric threshold. "Works well" is not a criterion.
- Every spec that touches hooks, the daemon, the judge or providers lists its failure paths explicitly, and each must end in `ask`.
- "Out of scope" is mandatory. It stops the agent from gold-plating.
- If the spec changes behaviour a judge could see in the demo, say so under "Demo impact".

When the spec is done:

1. Run the `planner` subagent on it.
2. Run the `test-writer` subagent.
3. Implement until `make test` is green.
4. Run the `reviewer` subagent, fix findings.
5. Tick the acceptance criteria in the spec and commit with the `NNN:` prefix.
