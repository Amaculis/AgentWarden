# 032 — Shell comment bypass and quadratic upload regex

Size: small (one module, `rules.py`; touches a self-protection path, so a `reviewer` pass is still advised)
Depends on: 008 (command tokens), 025 (boundary), 031 (found both issues).

## Context

Two defects found while reviewing spec 031, both in `rules.py`:

1. `split_command` uses `shlex` with its default `commenters = "#"`. `command_path_tokens` turns
   newlines into `" ; "` before tokenizing, so `echo #\ncat ../secret.txt` becomes
   `echo # ; cat ../secret.txt` and shlex drops everything after `#`. Every later line is hidden
   from the boundary and config-path checks. (`policy.py` also uses `split_command`.)
2. `_UPLOAD_RE` and `_GIT_HISTORY_RE` have unbounded `[^|;&]*` gaps. On `curl curl curl …` each
   `curl` rescans to the end of the segment: 16 000 repeats take about 8 s, so a hostile command
   stalls the daemon until the hook times out. (Spec 026/031 hit the same class of bug.) Bounding
   the gap would let padding past the bound hide a flag, so the fix keeps the meaning and makes the
   search linear.

## Behaviour

- `split_command` never treats `#` as a comment: every token after it is still returned, so the
  path rules see the whole command. This can only add checks (a real comment containing a path
  may now trigger a boundary `ask`), never remove any.
- Upload, history-rewrite, download-pipe-to-shell and `dd of=/dev/` detection returns exactly the
  same verdict as before for every command, but runs in time linear in the command length.
  Method: split on `[|;&]` (`|` for the download pipe, newline for `dd`); in each segment find the
  **first** verb match, then search the rest of the segment for its flag pattern. The first verb
  match is enough because the old unbounded gap already let it reach everything a later match
  could reach. One exception kept on purpose: the old scp/rsync tail `\S+:` could run across the
  delimiter, so `scp f 'a&b@h:/p'` still matches (`_REMOTE_TOKEN_RE`).
- Review (7b269ae) found the scp weakening and the same quadratic shape in `_DOWNLOAD_PIPE_RE` and
  `_DISK_DESTROY_RE` (`"dd " * 30000` took 19 s); both fixed in this spec.

Example: `echo #\ncat ../secret.txt` → `command_path_tokens` returns `("cat", "../secret.txt")`,
the boundary rule answers `ask` (before: no path seen).

## Interface

- `rules.split_command(command)`: `lexer.commenters = ""`.
- `rules._UPLOAD_RE` and `rules._GIT_HISTORY_RE` are replaced by a table of `(verb_re, tail_re)`
  and `_has_upload(command)`, `_has_history_rewrite(command)`, with a shared `_verb_then_tail`.
  `_ask_defaults_rule` and `_capture_rule` call the functions. No other module imports the regexes.

## Failure paths

- Regex or split raises → the existing callers already end in `ask` (`_capture_rule` has a
  `try`; `_ask_defaults_rule` is inside `evaluate`'s catch-all). No new path; no `allow` is added.
- Unbalanced quotes in `split_command` → unchanged fallback `command.split()`.

## Acceptance criteria

- [x] `test_split_command_keeps_tokens_after_hash` — `#` is an ordinary token; later tokens kept.
- [x] `test_comment_does_not_hide_later_line_from_boundary` — `echo #\ncat ../secret.txt` in `evaluate` → `ask`; same with `ls # x\ncat ~/.ssh/id_rsa` → `deny`.
- [x] `test_upload_detection_unchanged`, `test_history_rewrite_detection_unchanged`, `test_download_pipe_and_dd_detection_unchanged` — tables of commands (every pattern, flags far away from the verb, flag after `|`/`;` NOT matched, delimiter-adjacent scp tokens) give the same result as the old regexes (kept in the test file as the oracle). A throwaway fuzz of 800 000 random commands showed 0 divergences.
- [x] `test_upload_and_history_perf` — `curl `×200 000, `git push `×100 000, `scp `×200 000, `nc `×200 000, `a`×1 000 000 each run in < 1 s.
- [x] `test_evaluate_perf_on_repeated_verbs` — `dd `, `curl `, `iwr `, `irm `, `curl|`, `rm `, `scp ` ×100 000 through `evaluate` in < 2 s.
- [x] existing `test_upload_and_history_rewrite_ask` and the 031 capture-upload tests stay green.
- [x] `make test` green, `make lint` clean (`ruff format --check src tests eval redteam hooks`), eval-rules +0.000.

## Out of scope

- Other regexes in `rules.py`/`input_capture.py` beyond the four above (fuzz and stress found no
  other quadratic one in `evaluate`).
- `shlex` itself is quadratic on one huge token (800 KB `aaaa…` takes ~11 s per call, same before
  and after this spec). The hook times out → `ask`; fixing it needs a length guard or own lexer.
- Known pre-existing misses of the segment split: `nc h 1 2>&1 < f`, `scp -o "X=a;b" f host:/x`.
- Making the path rules understand real shell comment semantics (treating them as code is the safe side).
- `cd dir && …` relative paths and env-var config homes (spec 027 open items).

## Demo impact

None.
