# Muse Code integration (specs 028, 036)

Wires AgentWarden's hooks into Muse Code (Meta's CLI coding agent) via the adapter in
`src/agentwarden/agents/muse_code.py`.

## Live capture (2026-11-02, Muse Code 1.4.14, Windows)

One session in `C:\tmp\muse-capture` with `hook_logger.py` (AgentWarden off) confirmed:

- **Hook config:** `<project>/.muse/hooks.json` is honoured once the folder is trusted, but only
  in Claude-style matcher groups: `{"hooks": {"PreToolUse": [{"hooks": [{"type": "command",
  "command": "..."}]}]}}`. A flat `[{"command": ...}]` list (the old sample here) is rejected
  (`hook.admission outcome=rejected` in Muse's session log). No `schema_version` needed.
- **Quotes** inside `command` reach the program literally on Windows: use absolute paths without
  spaces and without quotes.
- **A failing `UserPromptSubmit` hook blocks the prompt** (seen: Python could not open the
  script, Muse showed "Prompt blocked by hook").
- **Payloads** use Claude field names (`hook_event_name`, `tool_name`, `tool_input`,
  `tool_use_id`, `tool_response`, `session_id`, `cwd`) plus `turn_id` (no `prompt_id`),
  `model`, `model_provider`.
- **Tools seen:** `powershell {command, description, workdir}` (workdir with a `\\?\` prefix),
  `read_file {path}`, `edit_file {path, find, replace}`, `search {pattern, paths, output_mode}`,
  and the internal `submit_reminder_decision` (17 of 23 calls). `tool_response` is a string for
  `read_file` / `powershell` / `search`, an object for `edit_file`.
- **Output rules** (from Muse's own error messages in the binary): `permissionDecision: allow`
  without `updatedInput` is rejected, so AgentWarden stays silent on `allow` (the default; do
  not set `WARDEN_ALLOW_MODE=explicit` for Muse); `deny` needs a non-empty
  `permissionDecisionReason`; `hookSpecificOutput.hookEventName` is required.

Still **not** checked live: AgentWarden switched on (that a `deny` blocks and an `ask` prompts),
`write_file`, web and MCP tools, Linux/macOS tool names. The research below predates the
capture; where it disagrees, the capture wins.

## Sources (fetched/searched 2026-11-01)

1. <https://agenticcontrolplane.com/blog/muse-code-acp-integration> — "Muse Code's hooks
   aren't where the docs say — we found where they actually live." States that a project
   `.muse/hooks.json` is **silently ignored** as of the version tested, and hooks actually
   register through a plugin manifest, `.muse-plugin/plugin.json` (behind
   `MUSE_EXPERIMENTAL_PLUGINS=1`). Lists `PreToolUse`, `PermissionRequest`, `PostToolUse`,
   `Stop` as hook events. Confirms the `hookSpecificOutput` / `permissionDecision`
   (`deny`/`ask`/`allow`) output shape for `PreToolUse`, a different
   `{"decision": {"behavior": ..., "message": ...}}` shape for `PermissionRequest`, and a
   `{"decision": "block", "reason": ...}` shape for `UserPromptSubmit`.
2. <https://docs.arcjet.com/coding-agents/muse-code> — "Secure Muse Code." States hooks
   load from three sources: project `.muse/hooks.json` (committed, active only once the
   project folder is trusted), the `hooks` block in `~/.config/muse/settings.json`
   (user-level, XDG-style path), and a file named by a `managed_hooks_path` setting. Lists
   many more hook events (`PostToolUseFailure`, `SubagentStart/Stop`, `SessionStart/End`,
   `Notification`, `PreCompact`/`PostCompact`). Gives the same `PreToolUse` output shape as
   source 1. This directly **contradicts** source 1 on whether `.muse/hooks.json` works —
   unresolved; see the live check.
3. <https://github.com/Dicklesworthstone/destructive_command_guard/issues/572> — confirms
   an `exec_command` tool (alongside `shell` and `write_stdin`) exists in the shipped
   Muse 1.4.7-R6101.1 binary, but the reporter could not actually capture an `exec_command`
   payload, so whether it uses a `cmd` field (guessed, by analogy to Codex's unified exec
   tool) or `command` is **unconfirmed**. Confirms the three hook-source list (project file,
   `~/.config/muse/settings.json`, `managed_hooks_path`) and a required `"schema_version": 1`
   field in user settings.
4. <https://innfactory.ai/en/ai-harness/muse/> — "Muse Code: Meta's Coding Agent Harness
   Explained." Confirms `PreToolUse`/`SessionStart` hooks via `.muse/hooks.json`, project
   instructions from `AGENTS.md` (falling back to `CLAUDE.md`), and that hooks "run outside
   the sandbox with a cleared environment." Only describes tools by category (file ops,
   shell, web search), no individual tool names.
5. <https://github.com/jmagly/aiwg/pull/265> — a real-world `.muse/hooks.json` consumer:
   confirms a `SessionStart` hook entry is written to that file by a provider installer,
   and that a managed hook can be removed by deleting its "matcher group" from the file —
   implying matcher-style grouping similar to Claude Code's `hooks.json`, though the PR
   diff does not show the literal JSON.
6. Found via search but not fetched in full (lower confidence, listed for the next pass):
   <https://github.com/agentic-control-plane/muse-code-acp-plugin>,
   <https://github.com/Safa675/meta-hackathon-project/issues/11>,
   <https://github.com/hypery11/oh-my-musecode>,
   <https://pypi.org/project/muse-code-openrouter/0.3.0/>.

## Verified vs. guessed

**Verified by at least one source above:**
- Wire schema for `PreToolUse` input (snake_case `hook_event_name`/`tool_name`/`tool_input`/
  `session_id`/`permission_mode`/`cwd`) and output (`hookSpecificOutput.permissionDecision`,
  `permissionDecisionReason`) matches Claude Code's — this is why **no**
  `hooks/formats/muse_code.py` was added; `on_tool.py --agent muse_code` prints the same
  schema it already does for Claude Code.
- `exec_command` and `shell` tools exist in the shipped binary.
- Three hook config sources: `<project>/.muse/hooks.json`, `~/.config/muse/settings.json`
  (`hooks` block), a `managed_hooks_path` file.
- A plugin path, `.muse-plugin/plugin.json`, is also a real place hooks can register from.

**Guessed (not observed anywhere), pending the live capture:**
- `exec_command`'s actual command field (`cmd` vs `command`) — the adapter maps `cmd` ->
  `command` defensively; if it turns out to already be `command`, the mapping is a no-op.
- Every other tool name: `write_file`, `edit_file`, `read_file`, `search_files`,
  `glob_files`, `fetch_url`, and their field names (`path`, `content`, `old_str`/`new_str`,
  `query`, `url`). These follow a generic Codex/Claude-style naming convention and are not
  attested by any source found.
- Whether `.muse/hooks.json` is honoured at all (sources 1 and 2 disagree) — the sample
  `hooks.json` in this directory is provided for both paths; if the live check shows
  `.muse/hooks.json` is ignored, install via `.muse-plugin/plugin.json` instead (not drafted
  here — write that file from the plugin manifest shape once confirmed).
- The Windows-home equivalent of `~/.config/muse/settings.json`. The adapter's third
  `config_paths` entry (`.config/muse/settings.json`) matches the POSIX path component
  sequence; a Windows install may use a different root (e.g. `%APPDATA%`), which is not
  covered yet. Flagged here rather than guessed into the adapter.
- `PostToolUse`'s advisory (non-blocking) output shape when used for the injection scanner's
  `additionalContext` warning (as opposed to the blocking shapes sources 1-2 describe for
  `PermissionRequest`/`UserPromptSubmit`). Assumed to match Claude Code's
  `hookSpecificOutput.additionalContext` since no source contradicts it, but not confirmed.

## Install steps

1. Start the AgentWarden daemon: `make run` (or `uv run agentwarden-daemon`).
2. Copy `integrations/muse_code/hooks.json` to `<project>/.muse/hooks.json` and replace
   `C:/Python313/python.exe` and `C:/path/to/AgentWarden` with your absolute paths (no spaces,
   no quotes).
3. Trust the project folder when Muse Code asks (project hooks load only in a trusted folder).
4. Set `WARDEN_URL` if the daemon is not on the default `http://127.0.0.1:8765`.
5. Run Muse Code in the project; a denied action should show the same deny Claude Code
   shows for the same command.

## Live check (ONE short Muse Code session — budget is limited)

AgentWarden is **off** during this session (the logger never blocks), and the logger writes
every payload in full, including PostToolUse results — i.e. the contents of files Muse Code
reads. So:

0. Make an empty scratch folder outside any real project, e.g. `C:\tmp\muse-capture`, with
   only a `README.md` and a **fake** `.env` (`API_KEY=fake-value-for-capture`). Never run the
   capture in a real project or with real secrets on disk next to it.
1. Swap in the capture config: copy `integrations/muse_code/logger_hooks.json` to
   `.muse/hooks.json` in that scratch folder (and, if step 3 shows it is ignored, also try it
   as `.muse-plugin/plugin.json`'s hook declaration). Point the `command` paths at this
   repo's `integrations/muse_code/hook_logger.py`.
2. Run one short session there: a plain `ls`-equivalent command, one file read, one file
   write/edit, one search, and one attempted read of the fake `.env` (expect Muse Code's own
   behaviour, not AgentWarden's).
3. Stop the session, open `integrations/muse_code/muse_code_capture.jsonl`, and for each
   line note: did `.muse/hooks.json` actually fire (file has entries at all)? What is
   `tool_name` for the shell command — `exec_command`, `shell`, or something else — and
   which field holds the command (`cmd`/`command`)? What are the real write/edit/read/search
   tool names and field names?
4. Update `tool_map`/`input_map`/`config_paths` in `src/agentwarden/agents/muse_code.py` and
   the fixtures in `tests/test_agent_muse_code.py` to match; remove the "UNVERIFIED" framing
   for whatever was confirmed, and correct whatever was wrong.
5. Re-run `python -m pytest tests/test_agent_muse_code.py` and confirm the same deny now
   shows up for a real `rm -rf`-equivalent command in that captured shape, then delete
   `muse_code_capture.jsonl` (it may contain real file contents / paths from the scratch
   project) before committing.

## Open gap for 027 (do not fix here)

None found. The adapter layer from spec 027 covers everything this integration needed:
tool/field mapping, config-path self-protection, and per-agent output formatters (unused
here since the wire schema already matches).

## If Muse Code ignores or misreads `ask`

Not yet checked live. If the live check shows Muse Code treats an unrecognized
`permissionDecision` value, a missing `hookSpecificOutput`, or `ask` itself as an implicit
allow, record that here and add it to `docs/CONTEXT.md` as a known gap — do not claim this
integration blocks anything until that is confirmed.
