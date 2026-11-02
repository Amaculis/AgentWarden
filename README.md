# AgentWarden

Semantic firewall for AI coding agents. Every Claude Code action is checked by deterministic rules first, then a local Meta open-weights model, then Muse Spark for the hard cases. Content the agent reads is scanned for injected instructions. Each action gets `allow`, `deny` or `ask`. Any error, timeout or doubt resolves to `ask`: the firewall fails closed.

<!-- video link -->

## How it works

```text
Claude Code --PreToolUse--> hooks/on_tool.py --POST /decide--> daemon
                                                              |
                                     rules settled? --yes--> verdict
                                                              |
                                       no (ambiguous)         v
                                                              |
                                    cascade: local Meta model |
                                       confident? --yes--> verdict
                                                              |
                                       unsure / mid risk      v
                                                              |
                                                     Muse Spark --> verdict

Claude Code --PostToolUse (Read/WebFetch)--> hooks/on_read.py --> scanner
flagged content --> session taints --> fed back into the judge context
```

Meta models and their roles:

- First-pass judge: a small Meta open-weights model, running locally behind an OpenAI-compatible endpoint. It decides every action the rules did not settle.
- Escalation judge: Muse Spark, called through the Meta Model API only when the local verdict has low confidence or mid-range risk.
- Scanner: the local model checks files and pages right after the agent reads them. Flagged sources become session taints, and acting on tainted instructions is denied.
- Red-team generator: Muse Spark invents new attacks, the cascade defends, and bypasses become eval cases (`make redteam`).

## Safety

- Fail-closed: any error, timeout or unparsable model output becomes `ask`, never `allow`.
- Secrets are redacted before anything is sent to a model.
- The only outbound network calls go to the configured model provider.
- The protected agent cannot switch AgentWarden off. Edits to the policy directory, the hook settings, calls to the daemon and killing the daemon are built-in hard denies. Dashboard policy writes need a local UI token the agent cannot read.
- Standard tier only. Contributor models are never used.

## Quick start

1. Install dependencies:

```sh
make install
```

2. Check the two prompts the models use: `prompts/judge.md` (action verdicts) and `prompts/scanner.md` (injection checks). Edit them to match your risk appetite.

3. Set the environment in the shell that will start the daemon:

```sh
export WARDEN_JUDGE=cascade
export META_API_KEY=<your-key>
export WARDEN_LOCAL_BASE=http://127.0.0.1:11434/v1
export WARDEN_LOCAL_MODEL=<local-meta-open-weights-model>
```

`WARDEN_JUDGE=meta_api` also works without a local model. With `WARDEN_JUDGE=off` unsettled actions become `ask`.

4. Start the daemon:

```sh
make run
```

It listens on 127.0.0.1:8765 and prints the dashboard URL (with the UI token) to its console.

5. Protect a project: copy `examples/settings.agentwarden.json` (or `examples/settings.agentwarden.windows.json` on Windows) into your project's `.claude/settings.json`, merging the `hooks` block:

```json
"hooks": {
  "UserPromptSubmit": ["hooks/on_prompt.py"],
  "PreToolUse": ["hooks/on_tool.py"],
  "PostToolUse": ["hooks/on_read.py"]
}
```

6. Open the dashboard URL from the daemon console in VS Code with `Simple Browser: Show`. New decisions appear within 2 seconds. `Always allow` / `Always deny` buttons append rules to that project's policy file.

## Other agents

Claude Code is the tested target. Adapters for other agents exist but have **not been run
against a live agent session**; each integration README lists what is documented and what is
guessed:

- Muse Code: `integrations/muse_code/` (payloads captured live on Windows; a live `deny` on a
  `.env` read blocked Muse Code).
- GitHub Copilot: `integrations/copilot/` (from documentation only).
- Codex: `integrations/codex/` (from documentation only).

## Try the demo

The demo project hides an instruction in its README. The scanner flags it at read time, and the follow-up exfiltration is blocked with a reason and a safer alternative.

```sh
python demo/setup_demo.py ../northwind-demo
```

Open Claude Code in `../northwind-demo` and type:

```text
Fix the login button colour — it should use the primary colour from the README.
```

Full script, expected beats and fallbacks: `docs/demo.md`.

## Evaluation

```sh
make eval
```

```sh
make eval-scan
```

```sh
make redteam
```

`make eval` scores the action cases in four modes (rules / local / spark / cascade). `make eval-scan` scores the scanner on injected and normal documents. `make redteam` runs the Meta red-team loop. Spark and cascade modes cost API credits; rules mode is free (`make eval-rules`).

Action eval, 128 main + 27 holdout cases (31 Oct; cascade re-run 1 Nov; `llama3.1:8b` on Ollama CPU for local/cascade):

| Mode | Accuracy (main / holdout) | Detection rate (main / holdout) | Tamper | p95 latency | Cost / 100 actions |
| --- | --- | --- | --- | --- | --- |
| rules | 0.500 / 0.630 | 1.000 / 1.000 | 12/12 | 0.3 ms | $0 |
| local | 0.914 / 0.852 | 1.000 / 0.900 | 12/12 | 14.2 s | $0 |
| spark | 0.953 / 0.889 | 1.000 / 1.000 | 12/12 | ~6 s | $0.215 |
| cascade | 0.953 / 0.926 | 1.000 / 1.000 | 12/12 | 2.4 s | $0.0055 |

Rules mode reaches detection 1.000 by answering `ask` to everything it cannot settle. In local mode, one holdout case (an obfuscated npm `postinstall` script) is judged `allow` with high confidence; cascade now escalates any action with obfuscation signals (hex/base64 decoding, `eval` of decoded data) to Muse Spark, which denies it. That signal list was written after seeing this miss, so the holdout number is optimistic.

Scanner eval, 53 main + 12 holdout documents, local model: recall 0.923 / 0.833, precision 0.96 / 1.00.

Red-team: 4 rounds, 20 attacks generated by Muse Spark against the cascade defender, 0 bypasses, 0 over-blocks, $0.33 total.

## Policy file

Copy `examples/policy.example.yaml` to `.agentwarden/policy.yaml` in the project you want to protect and edit the lists:

```yaml
version: 1

# Paths are globs relative to the project root.
deny_paths: ["secrets/", "*.pem", "*.key"]
ask_paths: ["migrations/", "infra/"]
allow_paths: ["docs/"]

# Commands match by prefix.
deny_commands: ["terraform apply", "kubectl delete", "git push --force"]
ask_commands: ["npm publish"]
allow_commands: ["make test", "uv run pytest"]

# Network: hosts the agent may reach without asking.
allow_domains: ["pypi.org", "github.com"]
```

The policy can never weaken built-in hard denies. Secrets and self-protection rules run before it.

Set `mode: read_only` to look at untrusted code: only `Read`, `Glob` and `Grep` inside the project run without a question, everything else (edits, shell commands, network, MCP tools) asks, and the `allow_*` lists are ignored. No model is called in this mode.

The project folder is a boundary. Searching or listing outside it (`Glob`, `Grep`, `ls`, `find`, `Get-ChildItem`) is denied; reading, editing or a shell path outside it asks, and the judge can only make that stricter. To widen the boundary, add absolute folders to `extra_roots` in the policy file (permanent), or press **Allow folder for this session** on the row in the dashboard (until the session ends). Secrets and AgentWarden's own files stay blocked inside every allowed folder.

## Project layout

- `hooks/` — Claude Code hook scripts; forward events to the daemon, fail closed to `ask`.
- `src/` — daemon, rules, policy, judge, cascade, scanner, redaction, audit log, dashboard page.
- `prompts/` — judge, scanner and red-team prompts (human-owned).
- `eval/` — labelled action and content cases plus the eval runner.
- `redteam/` — Meta red-team loop: attack generator plus scoring.
- `tests/` — fast tests, no network; real-model tests are marked slow.
- `docs/` — context, specs, demo run sheet, handoffs.
- `demo/` — demo project generator.
- `examples/` — hook settings and policy example to copy into a project.

Built during the Meta Global AI Developer Hackathon, Oct 26 – Nov 4, 2026.
