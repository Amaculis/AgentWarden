# 020 — More built-in secret paths: browser profiles, cloud CLIs, kubeconfig

Size: small (rules.py secret lists)

## Context

The second candidate batch has attacks on browser password/cookie stores and cloud CLI
credentials (`secrets-browserloginsqlite-259`, `exfiltration-*cookies*`, gcloud ADC). The
built-in secrets rule only knew SSH keys, `.env`, `.netrc`, `.pgpass`, git credentials, AWS and
Docker. These files are as sensitive as `~/.ssh/id_rsa` and have no business in a coding task.

## Behaviour

Built-in hard deny (same stage and verdict as the existing secrets rule, static alternative
included) for structured paths and shell mentions of:

- Browser profiles — a path with a browser directory (`google-chrome`, `chromium`, `chrome`,
  `brave-browser`, `bravesoftware`, `microsoft edge`/`edge`, `mozilla`, `firefox`) and a
  basename of `login data`, `cookies`, `web data`, `local state`, `key4.db`, `logins.json`,
  `cookies.sqlite`. Bookmarks and history stay unaffected.
- Cloud CLIs — `.config/gcloud/` `application_default_credentials.json`, `credentials.db`,
  `access_tokens.db`, `legacy_credentials/...`; `.azure/` `accesstokens.json`,
  `msal_token_cache.json`; `.kube/config`.
- Shell mentions: `Login Data`, `logins.json`, `key4.db`, `cookies.sqlite`,
  `application_default_credentials.json`, `gcloud/credentials.db`, `gcloud/access_tokens.db`,
  `msal_token_cache`, `.kube/config`.

## Also fixed here (found while timing the new patterns)

Two pre-existing quadratic regexes in `rules.py` let a single long command stall `/decide`
past the hook's 8 s deadline (fail-closed `ask`, but it also ties up the threadpool):

- `\S+\.(?:pem|key|p12|pfx|kdbx)\b` — 34 s on a 140 KB token → lookbehind `(?<=\S)\.(?:...)`.
- `HOST\b.*?\bPORT` in `_mentions_daemon` — 6 s on 100 KB → per-line host search, then port
  search after it (same meaning, linear; bounding `.*?` would have allowed padding bypasses).

## Acceptance criteria

- [x] `test_browser_profile_secrets_denied` (Read, Grep path, Bash cat/sqlite3/cp)
- [x] `test_browser_bookmarks_not_secret`
- [x] `test_cloud_cli_credentials_denied` (gcloud ADC, azure token cache, kubeconfig)
- [x] `test_project_files_named_cookies_unaffected` (`src/cookies.js`, `docs/cookies.md`)
- [x] `test_rules_are_linear_on_long_commands` (100 KB inputs, < 3 s)
- [x] `make test` green, `make lint` clean; rules eval on candidates: tamper 15/15, no new
      benign denies.
