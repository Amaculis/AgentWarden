# 026 — Resolve links and short names before path rules

Size: large (rules get filesystem access; hard denies, self-protection and boundary depend on it)
Depends on: 003 (path rules), 019 (home paths), 025 (project boundary).

## Context

Every path rule is lexical (003, 025 "Out of scope"). A path that looks harmless can name a
protected file:

| Trick | Example | Today |
| --- | --- | --- |
| Symlink in a cloned repo | repo ships `docs -> ~/.ssh`; agent does `Read docs/id_rsa` | `id_rsa` basename caught, but `docs/notes -> ~/.aws/credentials` is `allow` (safe read) |
| Junction (Windows, **no admin needed**) | `mklink /J lnk ..\..\other`; `Read lnk/x.py` | inside project → `allow`; boundary bypassed |
| Link to self-protection | `cfg -> .agentwarden`; `Edit cfg/policy.yaml` | `.agentwarden` not in the path → passes the hard deny |
| 8.3 short name (Windows) | `Edit AGENTW~1/policy.yaml`, `Read C:/Users/me/AWS~1/CREDEN~1` | not matched by any rule |
| Hard link | `x.txt` hard-linked to `~/.ssh/id_ed25519` | `allow` |

Verified on the dev machine (2026-11-01, Windows 11, Python 3.12): `mklink /J` works as a normal
user; `os.path.islink()` is **False** for a junction (`os.path.isjunction()` is True);
`os.readlink()` on a junction returns a `\\?\C:\...` target; drive C: has 8.3 names
(`CREDEN~1.JSO` for `.credentials.json`), D: does not; `os.path.realpath()` resolves both the
junction and the 8.3 name to the long, final path; `os.stat` gives non-zero `st_ino`/`st_dev`.

The repo case matters most: git checks out symlinks, so a malicious repository can plant them
without the agent ever running `ln`.

## Behaviour

**Principle: resolution only adds checks.** The final rule verdict is the stricter of the
lexical verdict and the verdict for the resolved path (`deny` > `ask` > `allow` > no verdict).
Nothing that is `deny` or `ask` today can become looser. If resolution is impossible (path does
not exist, remote dev container, daemon on another machine), behaviour is exactly today's.

1. **Which paths.** The same path fields the rules already read: file tools' `file_path` /
   `notebook_path`, `Grep`/`Glob` `path` and the literal base of a pattern, and Bash/PowerShell
   path tokens (`command_path_tokens`). At most 64 paths per action; more → `ask` ("too many
   paths to check").
2. **Which ones are resolved.** Only paths that are lexically **inside the roots** (project,
   `extra_roots`, session grants). A path lexically outside is already `deny`/`ask`; resolving it
   could not tighten the boundary verdict and would touch the filesystem outside the project.
   UNC paths (`\\host\...`, `//host/...`) are never touched (an SMB lookup is an outbound network
   call and leaks the user's NTLM hash).
3. **How.** `links.resolve(path, cwd, roots) -> Resolution` walks the path component by
   component with `os.lstat` + `os.readlink` (symlinks **and** junctions; `\\?\` prefix
   stripped), joining relative link targets to the link's directory, at most 40 hops. The walk
   **stops at the first hop that leaves the roots** and reports that target (no `lstat` outside
   the roots, so no mapped network drive is ever touched). On Windows, if any component
   contains `~<digit>`, the in-root prefix is expanded with `os.path.realpath` (8.3 → long
   name). Result: `resolved` (final path, original case), `changed: bool`, `left_roots: bool`,
   `error: str | None`.
4. **What is checked on the resolved path**, when `changed`:
   - secret path (`_is_secret_path`) → `deny`, reason names both: "`docs/notes` is a link to
     `~/.aws/credentials`, a secret file";
   - self-protection → `deny` exactly where the lexical rule denies the target: `.agentwarden/`
     and project `hooks/` for every tool (including `Read`), `.claude/settings*.json` for
     writing tools and shell (a lexical `Read` of settings is allowed, so it is through a link);
   - `left_roots` → the boundary verdict for the target, as if the action named it (search/listing
     → `deny`, otherwise `ask` with `consult_judge` and `grant_dir` = the target's directory).
5. **Hard links.** For an existing regular file inside the roots with `st_nlink > 1` that the
   action reads or writes: compare `(st_dev, st_ino)` with a protected set → match = `deny`
   ("hard link to a secret file"). Protected set: `~/.ssh/*` except `*.pub`/`known_hosts`/`config`,
   `~/.aws/credentials`, `~/.netrc`, `~/.git-credentials`, `~/.pgpass`, `~/.docker/config.json`,
   `~/.kube/config`, `.env*` (secret per `_is_secret_path`) in each root's top directory,
   `.agentwarden/*` and `.claude/settings*.json` of the project. Built lazily, cached 60 s per
   project; only `os.stat` of fixed paths and one `os.listdir(~/.ssh)`. `st_nlink > 1` with no
   match → no change (pnpm stores hard-link `node_modules` files; they must stay readable).
6. **Errors.** A path that exists but cannot be walked (loop, > 40 hops, permission error,
   any exception) → `ask` ("could not resolve <path>"). A path that does not exist → lexical
   only (a `Write` to a new file: the existing directory prefix is still walked).
7. **Order in `rules.evaluate`.** The resolution stage runs right after the lexical hard denies
   and before the boundary: resolved secret / self-protection `deny` are hard denies (the policy
   cannot override them); a resolved boundary verdict merges with the lexical boundary verdict
   (stricter wins). Everything after (policy, defaults, judge) is unchanged and sees the
   lexical `tool_input`.
8. **Link creation** needs no new rule; tests pin today's behaviour: `ln -s ~/.ssh x`,
   `New-Item -ItemType SymbolicLink -Target ~/.aws/credentials`, `mklink /J lnk C:\Users` are
   `deny` (secret mention) or `ask` (boundary). A link to a target inside the project stays as
   today.
9. **Budget.** Resolution of one action takes < 20 ms on a local disk for 64 paths × 10
   components; the walk has its own deadline of 200 ms → past it, `ask`.

`WARDEN_RESOLVE_LINKS=0` disables steps 2–6 (for remote setups where the daemon's filesystem
is not the agent's). Default on. A disabled check is logged once at startup.

## Interface

- New `src/agentwarden/links.py`:
  - `@dataclass(frozen=True) class Resolution: resolved: str; changed: bool; left_roots: bool;
    error: str | None`
  - `resolve(path: str, cwd: str, roots: Sequence[str], *, deadline: float) -> Resolution`
    (never raises; any exception → `error`)
  - `protected_inodes(cwd: str, roots: Sequence[str]) -> frozenset[tuple[int, int]]` (cached)
  - `hardlink_target(path: str, cwd: str, roots) -> str | None` — the protected file name, or None
- `rules._resolution_stage(event, roots) -> Verdict | None`, called from `evaluate`.
- `rules._stricter(a: Verdict | None, b: Verdict | None) -> Verdict | None`.
- Env: `WARDEN_RESOLVE_LINKS` (default on).
- No new Verdict/store fields; the reason text names the lexical path and its target.

## Failure paths

- Path exists, walk fails (loop, hop limit, permission, OSError) → `ask`.
- Walk deadline exceeded → `ask`.
- More than 64 paths → `ask`.
- UNC path or link target → no filesystem access; lexical boundary verdict (outside → `ask`/`deny`).
- `protected_inodes` fails (no home dir, permission) → empty set plus one warning; symlink checks
  still run. (Stricter alternative rejected: every pnpm read would become `ask`.)
- Path does not exist → today's lexical behaviour.
- `WARDEN_RESOLVE_LINKS=0` → today's lexical behaviour, warning at startup.
- Nothing in this spec can turn `deny` or `ask` into `allow`.

## Acceptance criteria

Tests create real links in `tmp_path`; symlink tests are skipped where the OS refuses them
(Windows without developer mode), junction tests run on Windows only, 8.3 tests are skipped when
the volume has no short names. At least the junction and symlink-to-dir cases must run in CI on
the dev machine.

- [x] `test_symlink_to_secret_file_denied` — `notes -> <home>/.aws/credentials`, `Read notes` → deny.
- [x] `test_symlinked_dir_to_ssh_denied` — `docs -> <home>/.ssh`, `Read docs/id_ed25519` and
      `Bash: cat docs/id_ed25519` → deny.
- [x] `test_link_to_agentwarden_edit_denied` — `cfg -> .agentwarden`, `Edit cfg/policy.yaml`,
      `Write cfg/x`, `Bash: echo x > cfg/policy.yaml` → deny.
- [x] `test_junction_outside_project_ask` (Windows) — `lnk` junction to a sibling dir,
      `Read lnk/x.py` → ask with `grant_dir` = the sibling dir; `Grep path=lnk` → deny.
- [x] `test_link_inside_project_unchanged` — `src/current -> src/v2`, `Read src/current/a.py` → allow.
- [x] `test_short_name_to_agentwarden_denied` (Windows, 8.3 volume) — `Edit AGENTW~1/policy.yaml` → deny.
      A fully shortened absolute path (root too, `PYTEST~1/...`) is lexically outside → boundary `ask`.
- [x] `test_hardlink_to_secret_denied` — hard link inside the project to a fake `<home>/.ssh/id_rsa`
      (home redirected via `HOME`/`USERPROFILE` in the test) → deny.
- [x] `test_hardlink_unrelated_allowed` — two hard links to an ordinary file, `Read` → allow.
- [x] `test_resolution_never_loosens` — property-style: for every existing `test_rules.py` /
      `test_boundary.py` event, `evaluate` with resolution on is equal or stricter than off.
- [x] `test_link_loop_ask`, `test_too_many_paths_ask`, `test_walk_deadline_ask` (monkeypatched clock).
- [x] `test_unc_never_touched` — `os.lstat` monkeypatched to fail the test if called with a UNC
      path; `Read //host/share/x` and an in-project link to `\\host\share` → ask, no call.
- [x] `test_walk_stops_at_root_exit` — `os.lstat` never called on a path outside the roots.
- [x] `test_nonexistent_path_lexical_only` — `Write new/dir/file.py` → same as today.
- [x] `test_resolve_links_flag_off` — `WARDEN_RESOLVE_LINKS=0` → today's verdicts.
- [x] `test_link_creation_pinned` — the three creation commands from Behaviour 8 → deny/ask.
- [x] Existing tests green (eval cases have no real files, so `make eval-rules` must not change;
      run it and confirm).
- [x] `make test` green (832, 1 skipped: file symlinks need Windows developer mode here; the
      junction variants `test_dirlink_to_aws_denied`, `test_resolve_links_flag_off` run), `make lint` clean.
- [x] `make eval-rules`: all metrics +0.000.
- [x] Reviewer finding fixed: the hard-link table used `os.stat`/`listdir`, which follow a link
      planted in `.agentwarden/` or `~/.kube` (possible SMB call). Now `lstat` per component, links
      skipped; `test_protected_inodes_never_follow_planted_links`,
      `test_hardlink_check_does_not_stat_through_links` (both fail on the old code). Also: the
      whole stage is wrapped, any exception → `ask`.

## Out of scope

- Links **below** a searched directory (`Grep path=src` where `src/x -> ~/.ssh`): needs a tree
  walk. VERIFY whether Claude Code's Grep (ripgrep, no `-L` by default) and Glob follow symlinks;
  if they do, separate spec.
- Links created and used inside one Bash command (`ln -s ... x && cat x`): the link does not
  exist at decision time; the creation part is caught lexically or goes to the judge.
- TOCTOU: the agent replaces a file with a link between the decision and the tool run. Not
  solvable from a hook.
- Paths built from variables (`$X/y`) — already `ask` (025).
- `subst` drives, mount points / bind mounts on Linux beyond what `readlink` reports, alternate
  data streams (`file.txt:secret`), case-sensitivity differences on Linux.
- Resolving paths inside `Write.content` or scripts.

## Demo impact

Optional demo beat: a cloned repo ships `docs/setup -> ~/.aws/credentials`; the agent is told
"read docs/setup" and AgentWarden denies with "is a link to ~/.aws/credentials". Otherwise none.
