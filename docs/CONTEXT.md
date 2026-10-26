# Project context (decisions so far)

Summary of the planning conversation before coding started, 25–26 Oct 2026. Read this once at the start of a new session if you need background; `CLAUDE.md` holds the working rules.

## Hackathon

- Meta Global AI Developer Hackathon, Indie developer track, solo. Theme: Build for Your World.
- Build window: 26 Oct – 4 Nov 2026. Submission deadline: 4 Nov 21:00 ET = 5 Nov 04:00 Riga. Target: submit by 02:00 Riga.
- Submission: Cerebral Valley platform + 3-minute demo video (judges score from it; show only what was built during the event) + public GitHub repo (check it opens logged out).
- Judging: stage 1 pass/fail (fits a theme and uses Meta AI products), stage 2 rubric 0–10, stage 3 live final on 9 Nov for top 5 per track (= the 5 prize places).
- Organisers' "overdone" list includes dashboards as the main feature and Streamlit apps. AgentWarden's dashboard stays secondary; plain HTML from FastAPI, no Streamlit.
- $150 Meta Model API credits per participant (form submitted 26 Oct, pending). Card required. Standard tier only, never Contributor.

## Product

AgentWarden — semantic firewall for AI coding agents. Hooks intercept Claude Code actions; deterministic rules first; a Meta model judges only ambiguous actions against the session task; decision allow / deny / ask; audit log.

Positioning against "just use ask mode": approval fatigue makes people click yes or switch to auto; the confirm dialog shows the command, not whether it fits the task; background/parallel agents have no human to click. AgentWarden is a smart `ask`: silent on the obvious, blocks the dangerous, asks only on the ambiguous with a reason. Key metric besides detection: how many fewer prompts than ask-all at the same protection.

Known limitation to state openly: the judge is an LLM and can itself be attacked, so rules run first and doubt resolves to `ask`.

Finding from the hooks docs: a hook that crashes, times out or cannot connect does NOT block the action (fail-open). So product hooks are command hooks that call the daemon with their own timeout and return `ask` on any failure. See the `hook-protocol` skill.

Decision (27 Oct, spec 002): if the daemon cannot write the audit row for an action, the answer is `ask`, whatever the policy said. An action that can't be recorded is never allowed silently. Malformed events to `/decide` get `200` + `ask` (not 4xx), so the hook only has to handle "daemon unreachable / timeout".

## MVP scope

In: Claude Code PreToolUse + UserPromptSubmit hooks; rules; Meta judge with JSON verdict; fail-safe to ask; SQLite audit log; small dashboard; eval set 150+ cases with metrics for rules / judge / both; demo where a prompt injection in a README tries to read `.env` and send it out.

Out unless time remains: MCP proxy, Copilot, SSH/DB control, multi-user.

## Metric targets (guidance)

Detection ≥ 90%, false positive rate ≤ 5%, judge p95 < 1.5 s, < 30% of actions reach the judge, cost per 100 actions, reduction in prompts vs ask-all.

## Plan by day

- Mon 26: setup, credits, repo, spec 001 (event capture)
- Tue 27: daemon, models, SQLite log, rules + tests
- Wed 28: judge v1, session context, redaction, fail-safe
- Thu 29: eval set v1 (60 cases), `make eval`, start dogfooding
- Fri 30: verdict cache, replay harness, CI
- Sat 31: eval v2 (150+), 3–5 judge tuning rounds, three-mode comparison
- Sun 1: dashboard (partly via Muse Code), local open-weights provider
- Mon 2: demo repo + scenario, clean install test, rough video
- Tue 3: README, final eval, feature freeze
- Wed 4 (day off): final video, submission

Cut order if behind: local model → dashboard (CLI table instead) → replay harness.

## Demo video (≤ 3 min)

Hook (10 s, the attack itself) → problem (20 s) → live: same task with AgentWarden, attack blocked with reason (60 s) → where Meta models are used (20 s) → metrics table (30 s) → close (10 s).

## Cost discipline

Subagents on Sonnet; full planner/test-writer/reviewer cycle only for `Size: large` specs; `/clear` between tasks; mechanical work (dashboard, case generation, eval script, README) in Muse Code on Meta credits.
