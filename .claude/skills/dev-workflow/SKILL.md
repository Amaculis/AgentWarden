---
name: dev-workflow
description: How to run AgentWarden development cheaply and keep sessions continuous — which work goes to Sonnet, Opus or Meta models (Muse Code), how to hand work to Muse Code, when to tell the user to /clear, and what to save to which .md file before ending a session. Use at the start of every task, when choosing a model or delegating to a subagent, when a task is finished, and when the session is getting long.
---

# Development workflow

Goal: spend the Claude subscription only where it pays off, push mechanical work to Meta credits, and never lose context between sessions.

You cannot switch your own model. When a task needs a different model, say so in one line and the user switches with `/model`. For subagents, set the model yourself through the subagent's `model` field or the delegation call.

## 1. Pick the model

| Work | Model | Why |
| --- | --- | --- |
| Implementing a `Size: small` spec, tests, fixtures, refactors, rules, eval script, CI, docs edits | **Sonnet** (default) | Well-specified work; Opus adds cost, not quality |
| Read-only searching across the repo, finding where something is used | Sonnet subagent (or Haiku) | Keeps file dumps out of the main context |
| Architecture changes, new module boundaries | **Opus** | Wrong decisions here cost days |
| `decide.py`, fail-safe paths, `redact.py`, hook wrappers | **Opus** for design and review, Sonnet may implement | Security-critical; this is what judges and attackers probe |
| Judge prompt design, analysing eval failures between tuning rounds | **Opus** | Reasoning about why the model misjudges |
| Debugging after 2 failed fix attempts on Sonnet | **Opus** | Stop the loop; a stronger model with a clean context is cheaper than a 3rd–5th attempt |
| Writing a `Size: large` spec | **Opus**, user edits | The spec drives everything after it |
| Dashboard HTML/CSS/JS, README draft, demo repo scaffolding, docstrings, eval report formatting, bulk eval case drafts | **Meta — Muse Code** (user runs it, on Meta credits, Standard tier) | Mechanical work; also counts as using Meta tools in judging |
| The judge inside the product | **Meta Model API** (Muse Spark) or Meta open weights | Product requirement |

Never send to Muse Code: the judge prompt, `decide.py`, `redact.py`, hook wrappers, `.env` or anything with secrets, labelling of `eval/cases/`.

When the current task fits a different row than the model in use, say at the start: "Эта задача для Opus — переключи `/model opus`, или продолжу на Sonnet." Then continue as the user decides.

## 2. Handing work to Muse Code

You cannot run Muse Code. Prepare a brief the user pastes into it, saved as `docs/handoff/NNN-<topic>.md`:

```markdown
# Handoff NNN — <topic> (for Muse Code, Standard tier)

Goal: <one sentence>
Read first: CLAUDE.md, <the 2–4 files it needs>
May change: <exact files or folders>
Must not change: everything else, especially src/agentwarden/decide.py, redact.py, hooks/, prompts/, eval/cases/
Contract: <endpoint / function signatures / data shape it must use>
Done when: <command(s) and expected result, e.g. `make test` green, page loads at /dashboard and lists events from /log>
Style: <constraints, e.g. one HTML file, no frameworks, no Streamlit>
```

When the user returns, review the diff (Sonnet) against the brief before committing. Note in the commit message `(Muse Code)` so it can be cited in the submission.

## 3. Where knowledge goes

| File | What goes there | Update when |
| --- | --- | --- |
| `CLAUDE.md` | Stable rules, commands, invariants | Rarely; only when a rule changes |
| `docs/CONTEXT.md` | Decisions, scope, plan changes, positioning | The user decides something, or the plan shifts |
| `docs/SESSION.md` | Current state, next step, open problems | End of every session and before every `/clear`. Overwrite, keep it under 30 lines |
| `.claude/skills/*` | Repeated procedures, verified facts about APIs and hooks | A fact is verified (e.g. a `VERIFY` item in `meta-api`), a real payload is captured, or the same explanation was needed twice |
| `docs/specs/NNN-*.md` | Tick acceptance criteria | When each criterion passes |

## 4. Prompt the user to save knowledge

Say it in one line, right when it happens, and offer to write it:

- The user made a decision ("делаем без MCP", "дашборд режем") → "Записать в `docs/CONTEXT.md`?"
- You verified a fact about Meta API or hooks → update the skill and say so.
- You explained the same thing twice, or found a non-obvious workaround → "Это стоит записать в скилл `<name>` — добавить?"
- A rule in `CLAUDE.md` turned out wrong or missing → propose the exact edit.

Do not write to `CLAUDE.md` or `docs/CONTEXT.md` without the user's yes. `docs/SESSION.md` you update yourself.

## 5. When to tell the user to /clear

Recommend `/clear` when any of these happens:

- A spec is finished and committed.
- The next task is in a different area than the last one.
- The session is long: roughly 30+ tool calls, or many large files read, or context was compacted.
- You notice yourself re-reading files or forgetting earlier decisions.
- A debugging loop hit 3 attempts without progress.

Before recommending it:

1. Overwrite `docs/SESSION.md`:
   ```markdown
   # Session state — <date time>
   Done: <specs/commits this session>
   In progress: <what, and exactly where it stopped>
   Next: <next spec or step, and which model>
   Open problems: <bugs, unknowns, VERIFY items>
   ```
2. List any pending knowledge to save (section 4) and ask.
3. Then say, in the user's language, in this shape:

```
✅ 003 готова и закоммичена. SESSION.md обновлён.
Предлагаю записать в CONTEXT.md: <одна строка> — да?
Пора /clear. Следующая: 004 (Sonnet) — начни новую сессию с «Read docs/SESSION.md and continue».
```

Keep it to these lines. Do not recommend `/clear` in the middle of a change that is not committed or noted in `SESSION.md`.

## 6. Starting a session

Read `docs/SESSION.md` if it exists. Read `docs/CONTEXT.md` only when the task needs background. Do not scan the repo; open only the files the task names.
