# 008 — Policy path rules apply to paths inside shell commands

Size: small

## Context

Spec 004 matches `deny_paths` / `ask_paths` only against `tool_input.file_path` (and the other
path fields). A Bash or PowerShell command that touches the same path slips through: eval case
`secrets-dir-102` (`cat secrets/stripe_key.txt` with `deny_paths: ["secrets/"]`) ends up
unsettled → `ask` instead of `deny`.

## Behaviour

For `Bash` and `PowerShell` events, the policy stage also extracts path-like tokens from
`tool_input.command` and matches them against `deny_paths` and `ask_paths` with the same glob
logic as file paths (relative to `cwd`, only paths inside the project).

- A token is path-like when, after stripping quotes, it has no whitespace, is not a URL
  (`://`), and either contains `/` or `\`, or ends in an extension (`.pem`, `.txt`, ...).
- `--opt=value` contributes `value`; other tokens starting with `-` are skipped.
- Shell punctuation (`;`, `|`, `&`, `<`, `>`, `(`, `)`) separates tokens. Backslashes are kept
  (Windows paths). Unbalanced quotes → fall back to whitespace split.
- Command tokens are **never** matched against `allow_paths`: they can only make a decision
  stricter, never `allow`.
- Bare words without `/` or an extension are not paths (`manage.py makemigrations` does not
  match `ask_paths: ["migrations/"]`; `ls secrets` is left to later stages).

Examples with `eval/policy.eval.yaml`:

| command | before | after |
| --- | --- | --- |
| `cat secrets/stripe_key.txt` | unsettled | deny (policy) |
| `cp infra/main.tf /tmp/x` | unsettled | ask (policy) |
| `python manage.py makemigrations users` | unsettled | unsettled |
| `rm -rf docs/old` | unsettled | unsettled (not allow) |

## Interface

- `policy._command_path_tokens(command: str) -> list[str]`
- `policy._any_path_matches(event, globs, *, include_command: bool = False)`; `match()` passes
  `include_command=True` for deny and ask only.

## Failure paths

- Tokenizer error (unbalanced quotes) → whitespace split, never an exception.
- No command / non-string command → no command tokens (unchanged behaviour).

## Acceptance criteria

- [x] `test_command_path_deny` — `cat secrets/stripe_key.txt` → deny (policy)
- [x] `test_command_path_ask` — `cp infra/main.tf /tmp/x` → ask (policy)
- [x] `test_command_path_glob_extension` — `openssl x509 -in dev.pem` → deny via `*.pem`
- [x] `test_command_path_never_allows` — `rm -rf docs/old` is not allowed by `allow_paths`
- [x] `test_command_bare_word_not_a_path` — `manage.py makemigrations` not ask
- [x] `test_command_path_windows_and_option_value` — `type secrets\k.txt`, `--file=secrets/k`
- [x] `test_command_path_unbalanced_quotes` — no exception
- [x] `test_command_path_outside_project_ignored` — `/etc/secrets/x.txt` not matched
- [x] `make test` green, `make lint` clean

## Out of scope

Chained commands for `deny_commands` (`cd x && terraform apply`), `cd` tracking, variable
expansion. The judge covers those.

## Demo impact

None directly; `secrets-dir-102` becomes a policy deny in the eval table.
