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

Mark the size at the top of the spec: `Size: small` or `Size: large` (rules in `CLAUDE.md`).

When the spec is done:

- **Small:** write the tests, implement until `make test` is green, tick the criteria, commit.
- **Large:** `planner` → `test-writer` → implement → `reviewer` → fix findings → tick the criteria → commit.

Commit messages start with the `NNN:` prefix.
