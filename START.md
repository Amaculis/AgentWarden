# AgentWarden — how to start development

Scaffolding for agentic development: agents immediately follow project rules, format code themselves, and can't finish with failing tests. There's no product code here yet — you write that with agents starting from spec 001.

## What's inside

| File | Purpose |
| --- | --- |
| `CLAUDE.md` | Project rules for agents: architecture, commands, 6 invariants, process |
| `.claude/settings.json` | Permissions (make/uv/git without prompts; `.env`, `~/.ssh`, `curl`, `git push` forbidden) and 3 dev hooks |
| `.claude/hooks/protect_core.py` | Agent edits `prompts/` or `eval/cases/` → Claude Code asks you |
| `.claude/hooks/format_py.py` | After every .py edit: ruff format + fix; errors remain → agent fixes right away |
| `.claude/hooks/stop_tests.py` | Agent can't finish while fast tests are red |
| `.claude/agents/` | `planner`, `test-writer`, `reviewer`, `redteam` |
| `.claude/skills/` | `hook-protocol`, `meta-api`, `warden-spec`, `eval-case`, `judge-tuning` |
| `docs/specs/000-template.md` | Spec template |
| `docs/specs/001-hook-passthrough.md` | First task — ready to work on |
| `prompts/judge.md` | Judge prompt scaffold — you write it yourself on 10/28 |
| `Makefile`, `pyproject.toml`, `.github/workflows/ci.yml` | uv, ruff, pytest, CI |

## Tonight (≈1.5 hours)

1. **Credits:** form from the mailing list → card on dev.meta.ai → Billing → Spend Limit → Standard mode.
2. **Repository:** unpack the archive, then:
   ```
   git init && git add . && git commit -m "000: project scaffold"
   gh repo create agentwarden --public --source . --push
   ```
   First commit — today, after the hackathon starts: this is proof everything was done during the event.
3. **Environment:** `uv sync`, then `make test` (no tests yet — that's normal).
4. **`.env`:** copy `.env.example` → `.env`, paste in the key. The agent doesn't read `.env` — that's forbidden in settings.
5. **First request to the model — by hand, not by agent:** go through the checklist at the end of `.claude/skills/meta-api/SKILL.md` and fix anything marked VERIFY. It takes 20 minutes, and afterward agents won't be guessing at the API.
6. **Start Claude Code in the project folder** and give the first task:
   ```
   Implement docs/specs/001-hook-passthrough.md. Run the planner subagent first,
   then test-writer, then implement, then the reviewer subagent.
   ```

## How to work every day

One cycle per task:

1. "Write spec 002 for <what's needed> using the warden-spec skill" → you edit the spec (5 minutes, this is the most important part).
2. "Implement docs/specs/002-....md" — planner, tests, implementation, review follow the process from `CLAUDE.md`.
3. You read the diff and the reviewer's notes, then commit.

In parallel: while one session implements, write the next spec in a second one. If tasks don't overlap on files, run the second implementation in a separate git worktree.

## Important finding about hooks

Per the Claude Code docs, a hook that **fails, doesn't respond in time, or can't be connected to does not block the action** — the agent just continues. For protection purposes this is fail-open. That's why AgentWarden's product hooks are command scripts that themselves call the daemon with their own timeout and return `ask` on any error. Details are in the `hook-protocol` skill. Worth mentioning in the submission as a deliberate design decision.

## Meta models for development

- **Muse Code** — Meta's CLI agent, free itself, tokens billed at the Muse Spark rate. Credits most likely come from the same Meta Model API balance as the judge: check Billing after your first session.
- **Use Standard only.** Contributor is ~12x cheaper, but trains models on your code.
- **Recommendation:** main development — in Claude Code (your subscription limits). Muse Code — for separate tasks (dashboard, some tests, eval script), so you can honestly state in the submission that Meta models also wrote code. The same `CLAUDE.md` works as instructions for Muse Code too.

## Windows

Hooks are invoked as `python3`. If on Windows the command is called `python` or `py`, change it in `.claude/settings.json`. For `make`, install it via `winget install GnuWin32.Make` or run the commands from the `Makefile` directly.
