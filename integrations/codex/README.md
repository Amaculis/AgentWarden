# Codex adapter (spec 030)

**Status: UNVERIFIED against a live Codex.** Nobody on the team has Codex (CLI or IDE extension)
installed; every claim below comes from OpenAI's published docs and the `openai/codex` GitHub
repository (docs, issues, PRs, linked source), fetched during this task. Treat anything marked
"UNVERIFIED" as a best-effort reading of secondary sources, not a confirmed fact about Codex's
actual runtime behaviour. The adapter is written defensively precisely because of that: see
"Design decisions driven by unverified facts" below.

## Variant chosen: A (Codex has a blocking pre-tool hook)

Research found that Codex has a `PreToolUse` hook that runs before a tool executes and can
return a `deny` decision that stops the call. That is the condition the spec sets for variant A.

## Sources

Primary / official:
- `openai/codex` GitHub issue #28437 ("Support PreToolUse permissionDecision: ask for native
  approval prompts"), open at research time (created per the issue, dated after this repo's
  cutoff; fetched 2026-11-01) — https://github.com/openai/codex/issues/28437
- `openai/codex` GitHub PR #17563 ("PermissionRequest hooks support"), merged, 43 files /
  1,821 additions — https://github.com/openai/codex/pull/17563 and
  https://github.com/openai/codex/pull/17563/files
- `openai/codex` GitHub issue #20875 (shell tool's `command` argv quoting) —
  https://github.com/openai/codex/issues/20875
- OpenAI developer docs, which redirect (HTTP 308, `developers.openai.com` -> `learn.chatgpt.com`,
  both OpenAI-controlled):
  - Hooks: https://developers.openai.com/codex/hooks (-> https://learn.chatgpt.com/docs/hooks)
  - Config reference: https://developers.openai.com/codex/config-reference
    (-> https://learn.chatgpt.com/docs/config-file/config-reference)
  - Agent approvals & security: https://developers.openai.com/codex/agent-approvals-security

Secondary (used only to corroborate the primary sources above, never as the sole basis for a
behaviour this adapter relies on):
- Community write-ups on Codex CLI hooks/config found via web search (dev.to, third-party blogs,
  third-party "hooks reference" sites). Tool-name details that only these secondary sources
  support are flagged UNVERIFIED in the code and not load-bearing for any `deny`/`allow` logic.

All of the above were read through an automated fetch-and-summarize step, not by a human on the
team opening the pages directly — a further reason to keep this adapter's failure behaviour
biased toward `deny`/`ask` rather than trusting any single detail.

## What the research found

- **`PreToolUse` hook, runs before the tool, can block.** `hookSpecificOutput.permissionDecision`
  is one of `"allow"` or `"deny"`; `"deny"` stops the call. (learn.chatgpt.com/docs/hooks, PR
  #17563.) Output schema otherwise mirrors Claude Code's: `hookSpecificOutput.hookEventName`,
  `.permissionDecision`, `.permissionDecisionReason`, and (for `allow`) an optional
  `updatedInput` to rewrite the call.
- **`"ask"` is currently broken, not just missing.** Per issue #28437 (open), when a `PreToolUse`
  hook returns `permissionDecision: "ask"`, Codex "marks the hook run as failed, reports the
  error, and **continues the tool call**" -- i.e. an unsupported decision value behaves like an
  `allow`, not like a safe default. This is the single most important fact driving this
  adapter's design (see below). UNVERIFIED beyond the issue text itself -- we could not run
  Codex to confirm.
- **Tool names.** The hooks doc says the canonical shell tool name is `Bash` with
  `tool_input.command`; `apply_patch` is the file-edit tool (also said to "match" `Edit`/`Write`
  in one summary, UNVERIFIED). Community/source-level discussion (issue #20875, and general
  Codex architecture writeups) also uses `shell`, `exec_command` and `unified_exec` for what
  appears to be the same or a closely related shell surface across Codex versions. Because we
  cannot verify which name a given Codex build actually sends, the adapter maps **all four**
  (`Bash`, `shell`, `exec_command`, `unified_exec`) to the canonical `Bash` tool -- mapping an
  extra, never-sent name costs nothing; missing the real one would silently skip every hard deny.
- **`command` can be a string or an argv list.** Issue #20875 and PR #17563's context describe
  Codex itself shell-quoting an argv list (Rust equivalent of `shlex.join`) before running it.
  `CodexAdapter.normalize` does the same so rules.py and the judge see one canonical string.
- **`apply_patch`'s payload is a unified-diff envelope, possibly multi-file.** (`***** Begin
  Patch` / one or more `*** Update File:` / `*** Add File:` / `*** Delete File:` blocks per call,
  per community writeups and the `prompt_with_apply_patch_instructions.md` file in the
  `openai/codex` repo.) UNVERIFIED in exact field name (`tool_input.command` vs `.patch` vs
  `.diff` -- sources disagree, see "27's layer" below).
- **Config/hook file locations.** `~/.codex/config.toml` (user) and `<project>/.codex/config.toml`
  (project, loaded only in trusted projects; cannot override `notify`/`profile`/`profiles`/
  telemetry keys). Hooks are either a `[hooks]` table inline in `config.toml` or a separate
  `hooks.json` file in the same directory (`~/.codex/hooks.json`, `<project>/.codex/hooks.json`).
  Supported event names found across sources: `PreToolUse`, `PermissionRequest`, `PostToolUse`,
  `PreCompact`, `PostCompact`, `SessionStart`, `SessionEnd`, `SubagentStart`, `SubagentStop`,
  `UserPromptSubmit`, `Stop`, `Interrupt`. No hook-config file living next to `AGENTS.md` was
  found anywhere in the research (the spec asked us to check for one); `AGENTS.md` itself appears
  to be plain instructions text, not a hook mechanism.
- **`sandbox_mode`** (`read-only | workspace-write | danger-full-access`) and **`approval_policy`**
  (`on-request | never | { granular = {...} }`) are Codex's own, separate approval/sandbox layer;
  AgentWarden's hook sits in front of/alongside that, it does not replace it.

## Design decisions driven by unverified facts

1. **The formatter (`hooks/formats/codex.py`) never emits `permissionDecision: "ask"`.** Codex
   has no working "stop and ask the user" state today (issue #28437); an unsupported value is
   treated as a failed hook and the tool call *continues* -- the opposite of fail-safe. So every
   `ask` verdict from rules/judge/cascade, and the 027 universal fail-safe (daemon down, timeout,
   bad JSON), is rendered as `deny` for Codex. This is a deliberate, documented narrowing of
   AgentWarden's three-way decision to Codex's two-way one, biased toward the safer side.
2. **`decision_output` treats anything that is not exactly `"allow"` as `"deny"`,** not just the
   three known decision strings. If a future code path somehow passed something else through,
   this formatter still fails closed rather than guessing.
3. **`decision_output`/`scan_output` never raise.** They wrap their own body in `try/except` and
   return a valid `deny` JSON string on any internal error. This matters because
   `hooks/on_tool.py`'s *own* fallback, when a formatter is missing or itself fails to import or
   return a string, is Claude Code's schema with `permissionDecision: "ask"` -- exactly the value
   Codex cannot be trusted with (point 1). Keeping every failure inside this module avoids ever
   reaching that fallback path. (That fallback itself is 027's, out of scope to change here; see
   "027 gaps" below.)
4. **`apply_patch` is left unmapped on purpose.** Codex's patch payload can touch several files
   in one call; the 027 canonical event (`tool_input.file_path`, one target) cannot carry that
   losslessly, and the exact field holding the diff text is itself unverified (see above). Rather
   than guess and risk silently missing a target inside `.agentwarden/` or `.codex/`, `apply_patch`
   is not in `tool_map`. 027's own unmapped-tool rule (`_unknown_agent_tool_rule`) then `ask`s
   before any model call, with no path inspection at all -- which trivially satisfies "never
   `allow`" for every `apply_patch` call, including ones that target protected paths, at the cost
   of asking about benign patches too.
5. **`config_paths = ((".codex",),)`** -- the whole project `.codex/` directory, one path
   component, so it matches wherever it appears under the project root (same pattern as the
   existing `.fakedir` test fixture in `tests/test_agents.py`). This covers `config.toml`,
   `hooks.json` and anything else Codex might keep there, rather than enumerating exact
   filenames we are not fully sure of.
6. **`scan_output`'s `additionalContext` field name is a guess** (mirrors Claude Code's own
   PostToolUse schema, the best-sourced option found). `PostToolUse` cannot block -- the read
   already happened -- so if Codex ignores or rejects this field, the only effect is a missed
   warning, not a security gap.

## What we could not verify

- Whether Codex's hook runner does anything other than "mark the hook failed and continue the
  tool call" for output it cannot parse at all (as opposed to a recognized-but-unsupported
  `permissionDecision` value, which issue #28437 does describe). If malformed/unparsable JSON is
  instead treated as a deny or an ignore, we don't know; we assumed the worse case (continues =
  allow) throughout.
- The exact wire format of `apply_patch`'s payload (field name, whether it is always a full
  unified-diff envelope or sometimes a single-file patch) -- hence leaving it unmapped rather than
  parsing it.
- Whether the shell tool is actually named `Bash`, `shell`, `exec_command`, `unified_exec`, or
  varies by Codex version/surface (CLI vs IDE extension) -- hence mapping all four.
- Whether `scan_output`'s `additionalContext` is honoured on `PostToolUse` for Codex at all.
- Any of this for the Codex **IDE extension** specifically, as opposed to the CLI; the research
  did not find IDE-extension-specific hook documentation distinct from the CLI's.

## 027 layer gaps this adapter ran into

- **No per-formatter fail-safe decision.** 027's `hooks/on_tool.py` hardcodes `"ask"` as the
  universal fail-safe decision and only lets a formatter *render* that string, not replace the
  decision value itself for its own fallback path (formatter missing, or raising/returning a
  non-string). For an agent with no `ask` state, like Codex, that fallback is unsafe in spirit
  (see point 3 above). This adapter works around it by making its own `decision_output`/
  `scan_output` bullet-proof so that fallback is never reached in practice, but the underlying
  27 behaviour is unchanged. Proposal: let `hooks/formats/<agent>.py` optionally export a
  `FAILSAFE_DECISION` constant (default `"ask"`) that `failsafe_output` uses instead of the
  hardcoded string.
- **One canonical event, one path.** `apply_patch`'s potentially multi-file payload cannot be
  represented. Proposal: a `tool_input.file_paths: list[str]` canonical shape (or a list of
  canonical events per adapter call) that rules.py's path-checking functions iterate over,
  denying/asking if *any* target matches a hard rule.

## Installing (UNVERIFIED, for a Codex user to validate)

1. Copy `hooks.sample.json` in this directory to `.codex/hooks.json` (project-trusted) or
   `~/.codex/hooks.json` (user), editing the `command` paths to point at this repo's
   `hooks/on_tool.py` / `hooks/on_read.py` with `--agent codex`.
2. Run `make run` to start the AgentWarden daemon on `127.0.0.1:8765` as usual.
3. Nothing else in this repo changes: the daemon picks the `codex` adapter from the
   `X-AgentWarden-Agent` header the hook sends, same mechanism as every other agent (spec 027).

No demo impact until this is verified against a real Codex (per the spec).
