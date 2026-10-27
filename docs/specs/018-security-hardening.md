# 018 — Security hardening after the 011/015/016 review

Size: small-to-medium (daemon middleware + endpoint checks, policy matching, decide filter,
one hook line). Follows an Opus review of commits 0fccf01, b05f7a1, 7741940.

## Context

The review found that the dashboard endpoints widened the attack surface: an unvalidated `cwd`
let `GET /policy` touch any path (UNC paths make the daemon open SMB connections — a network
call that breaks invariant 3), there was no Host/Origin check against DNS rebinding, the UI
token sat in a file protected only by the shell regexes, a one-click "Always allow" on a
command allowed every chained command with that prefix, and the safer-alternative filter missed
Unicode tricks and plain-language instructions.

## Behaviour

1. **No token on disk.** The daemon prints the dashboard URL (`http://127.0.0.1:<port>/#token=…`)
   once to its own stderr at startup and writes nothing. The port comes from `WARDEN_URL`
   (same source as the hooks). The user copies the URL into Simple Browser.
2. **Host and Origin checks** (middleware on every request): `Host` must be a loopback name
   (`127.0.0.1`, `localhost`, `[::1]`, with any port) or one listed in
   `WARDEN_TRUSTED_HOSTS` (tests add `testserver`); an `Origin` header, when present, must be
   `http://<loopback name>[:port]`. Otherwise `403`. Defeats DNS rebinding.
3. **`cwd` validation** for `GET /policy` and `POST /policy/rules`: absolute, not UNC
   (`\\` / `//` / `\\?\`), and already present in the audit log (`decisions.cwd`). Otherwise
   `400` and no filesystem access.
4. **`allow_commands` exact-ish:** an allow prefix matches only if the rest of the command has
   no shell operators (`&&`, `||`, `;`, `|`, `>`, `<`, `` ` ``, `$(`, newline). Deny/ask keep
   plain prefix matching (stricter is fine).
5. **Safer alternative filter:** NFKC-normalise and drop Unicode format/control characters
   (category `Cf`/`Cc`) first; additionally reject domain-like tokens, script file extensions
   (`.sh .ps1 .bat .exe .py .js`) and the verbs `install|download|fetch|execute|paste|run`.
   Model alternatives are dropped entirely when the session has taints. Static rule
   alternatives are unaffected. The judge `reason` gets the same Unicode clean-up (it stays,
   because the user needs it; its content risk is accepted and documented).
6. **`on_prompt.py`** reads stdin as bytes and decodes UTF-8 with `errors="replace"` (a
   Cyrillic prompt on a cp1252 console was silently dropped).
7. `append_rule` removes its temp file when the write fails.

## Known limitation (documented, not fixed)

Any local process — including a protected agent that obfuscates the daemon port past the
built-in rule — can POST `/event` and plant a fake "user prompt" that the judge reads as the
session task. Hooks cannot authenticate without a secret the agent could also read. The judge
prompt draft treats the task as context, not authority; a stronger fix needs Claude Code to
pass a per-session secret to hooks.

## Acceptance criteria

- [x] `test_no_ui_url_file_and_url_printed`
- [x] `test_untrusted_host_rejected`, `test_foreign_origin_rejected`, `test_loopback_origin_ok`
- [x] `test_policy_cwd_must_be_known_local_path` (UNC, relative, unknown → 400, no fs access)
- [x] `test_allow_prefix_does_not_cover_chained_commands`
- [x] `test_alternative_unicode_and_instruction_filter`, `test_alternative_dropped_when_tainted`
- [x] `test_on_prompt_utf8_on_cp1252_console`
- [x] `make test` green, `make lint` clean.
