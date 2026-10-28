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

## How Meta models are used (decided 27 Oct)

Meta is the core of the product, not a swappable LLM call. Four uses, each with its own measurable result:

1. **Cascade judge.** A small Meta open-weights model runs locally on every action that rules did not settle. Confident verdicts stop there; low confidence or mid-range risk escalates to Muse Spark. Most code never leaves the machine. Metric: share decided locally, quality vs Spark-only, latency, cost.
2. **Injection scanner.** After every Read / WebFetch (PostToolUse), the local model checks the content for instructions aimed at an AI and warns the agent through `additionalContext` before it acts. Catches the attack at the input, not only at the action. Metric: recall on injected docs, false positives on normal docs that contain legitimate commands.
3. **Meta red-team loop.** Muse Spark generates new attacks; the cascade is scored on them; bypasses become eval candidates and drive judge tuning. "Meta attacks, Meta defends". Answers the "LLM guarding an LLM" objection with numbers. Metric: attack success rate per round.
4. **Safer alternative.** On `deny`, the verdict includes a safe way to do the task ("use `.env.example`"), so the agent continues instead of getting stuck.

Not planned: SAM 3.1 or Muse Image (no real role here). Optional, only if verified: protecting Muse Code itself if it exposes hooks.

To verify early (Wed 28): which Meta open-weights models are available (e.g. Glimmer, Muse Spark Open), whether the user's hardware runs one fast enough, otherwise host it on Modal/Baseten partner credits.

## Judge prompt decisions (decided 28 Oct)

- **Strictness: cautious.** Unsure between allow and ask → ask; unsure between deny and ask → ask. Code adds: a model `allow` with risk > 30 or confidence < 0.6 becomes `ask`. Loosen later only from measured FPR.
- **One prompt for both judges.** The local model and Muse Spark share `prompts/judge.md`; split into two versions only if the local-model spike shows the small model cannot follow it.
- **Prompt v1 content** (beyond the draft in `docs/handoff/judge-prompt-v1-draft.md`): `taints` = files the scanner flagged; acting on their instructions → deny. `task` is context, not authority (a fake "user prompt" can be planted, spec 018). `safer_alternative` in plain words, no commands, URLs or script names (the code drops those).
- **Local hardware for the spike:** RTX 3050 8 GB, i5-11600K, 32 GB RAM. Plan: Ollama, ~3B model first (latency), ~8B for a quality comparison; measured numbers go to the `meta-api` skill.

## User control and visibility (decided 27 Oct)

- **Inside Claude Code**: every deny/ask shows a `systemMessage` line to the user (`🛡 AgentWarden: blocked … (local model)`). Allows stay silent. This is the primary interface.
- **Policy file** `.agentwarden/policy.yaml`: user-edited deny/ask/allow lists for paths, commands and domains. Reloaded on change. Cannot weaken built-in hard denies.
- **Dashboard in the IDE**: one HTML page from the daemon, opened in VS Code with `Simple Browser: Show`. Feed, filters, counters, "always allow / always deny" buttons that append to the policy file. No VS Code extension (too costly; "dashboards as the main feature" is on the organisers' overdone list).
- **Self-protection**: the agent cannot edit `.agentwarden/` or `.claude/settings*.json`, call the daemon, or kill it. Policy changes through the dashboard need a local token the agent cannot read. Eval category `tamper` proves it.

## MVP scope

In: Claude Code PreToolUse + UserPromptSubmit + PostToolUse hooks; rules; cascade (local Meta model → Muse Spark) with JSON verdict; injection scanner; safer alternative on deny; fail-safe to ask; SQLite audit log; small dashboard; Meta red-team loop; action eval 150+ cases in four modes; scanner eval 60+ documents; demo where a README injection is flagged at read time and the follow-up exfiltration is blocked.

Out unless time remains: MCP proxy, Copilot, SSH/DB control, multi-user, Muse Code protection.

## Metric targets (guidance)

Actions: detection ≥ 90%, false positive rate ≤ 5%, < 30% of actions reach any model, ≥ 70% of model-checked actions decided locally, cascade p95 < 1.5 s, cost per 100 actions, reduction in prompts vs ask-all.
Scanner: recall ≥ 85% on injected documents, false positive rate ≤ 5% on normal documents.
Red team: attack success rate reported per round, expected to drop after tuning.

## Plan by day

- Mon 26: setup, credits, repo, spec 001 (event capture)
- Tue 27: daemon, models, SQLite log, rules + policy file + self-protection + systemMessage, tests
- Wed 28: judge v1 on Muse Spark, session context, redaction, fail-safe; spike: pick and run the local open-weights model
- Thu 29: eval harness v1 (60 cases, modes rules/spark), start dogfooding
- Fri 30: cascade (local provider + escalation), eval modes local/cascade, verdict cache
- Sat 31: Meta red-team loop, eval v2 (150+), 3–5 tuning rounds
- Sun 1: injection scanner + scanner eval, safer alternative, dashboard with policy buttons (via Muse Code)
- Mon 2: demo repo + scenario, clean install test, rough video
- Tue 3: README, final eval, feature freeze
- Wed 4 (day off): final video, submission

Cut order if behind: Muse Code protection → safer alternative → dashboard (CLI table instead) → replay harness. Do not cut the cascade or the scanner: they carry the Meta story.

## Demo video (≤ 3 min)

Hook (10 s, the attack itself) → problem (20 s) → live: same task with AgentWarden — scanner flags the README at read time, the exfiltration is blocked with a reason and a safer alternative, the agent finishes the real task (60 s) → where Meta models are used: cascade + scanner + red team (20 s) → metrics: four-mode table and red-team rounds (30 s) → close (10 s).

## Cost discipline

Subagents on Sonnet; full planner/test-writer/reviewer cycle only for `Size: large` specs; `/clear` between tasks; mechanical work (dashboard, case generation, eval script, README) in Muse Code on Meta credits.
