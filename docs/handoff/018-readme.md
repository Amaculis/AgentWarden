# Handoff 018 — README for the submission (for Muse Code, Standard tier)

Goal: rewrite `README.md` so a hackathon judge understands AgentWarden in 2 minutes and can
install and run it in 10.

Read first: CLAUDE.md, docs/CONTEXT.md (positioning, Meta models' roles), docs/demo.md,
docs/specs/ (titles only: 001–017), Makefile, .env.example, examples/settings.agentwarden*.json.

May change: `README.md` only.

Must not change: everything else, especially src/, hooks/, prompts/, eval/, tests/,
CLAUDE.md, docs/CONTEXT.md.

Contract (sections, in this order):

1. One-paragraph pitch: semantic firewall for AI coding agents; every Claude Code action is
   checked rules → local Meta open-weights model → Muse Spark; what the agent reads is scanned
   for injected instructions; every action gets allow / deny / ask; fails closed.
2. Demo GIF/video link placeholder (`<!-- video link -->`).
3. How it works: a small ASCII or Mermaid diagram of hooks → daemon → rules → cascade (local →
   Spark) → verdict, plus the PostToolUse scanner and session taints. Name the Meta models and
   their roles (first-pass judge, escalation judge, scanner, red-team generator).
4. Safety properties, as a short list: fail-closed to `ask`, secrets redacted before any model
   call, only outbound call is the configured model provider, the agent cannot switch
   AgentWarden off (built-in hard denies + UI token), Standard tier only (never Contributor).
5. Quick start: `make install`, write the two prompts, env vars (`WARDEN_JUDGE`,
   `META_API_KEY`, `WARDEN_LOCAL_BASE`, `WARDEN_LOCAL_MODEL`), `make run`, copy the hooks from
   `examples/` into `.claude/settings.json`, open the dashboard URL from `~/.agentwarden/ui_url`.
6. Try the demo: `python demo/setup_demo.py ../northwind-demo` and the prompt from docs/demo.md.
7. Evaluation: `make eval`, `make eval-scan`, `make redteam`; leave a results table
   placeholder (`<!-- results: four-mode table -->`, `<!-- red-team rounds -->`) — numbers are
   filled in by the human after real runs. Do not invent numbers.
8. Policy file: example from `examples/policy.example.yaml`; note that the policy can never
   weaken built-in hard denies.
9. Project layout (one line per top-level folder) and "Built during the Meta Global AI
   Developer Hackathon, Oct 26 – Nov 4, 2026".

Done when: `README.md` renders on GitHub (headings, code blocks, diagram), every command in it
exists in the Makefile or repo, no invented metrics, no secrets or real hostnames
(`example.invalid` only), under ~250 lines.

Style: plain, factual English; short sentences; no marketing superlatives; code blocks for
every command.
