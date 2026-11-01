"""Link and short-name resolution for the path rules (spec 026).

The only filesystem access in the rules. A path that is lexically inside the allowed roots is
walked component by component with `os.lstat` + `os.readlink` (symlinks and Windows
junctions). The walk never touches anything outside the roots: it stops at the first hop that
leaves them and reports that target. UNC paths are never touched (an SMB lookup is an
outbound network call and leaks the user's NTLM hash).
"""

from __future__ import annotations

import errno
import logging
import os
import posixpath
import re
import stat
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass

logger = logging.getLogger(__name__)

MAX_HOPS = 40
MAX_PATH_LEN = 32_767  # the longest path Windows or Linux can open
CACHE_TTL_S = 60.0

_SHORT_NAME_RE = re.compile(r"~\d")
# "does not exist" in any spelling: missing, a file used as a directory, an invalid name
# (a wildcard or `:` in a shell token on Windows), a name too long.
_MISSING_ERRNOS = {errno.ENOENT, errno.ENOTDIR, errno.EINVAL, errno.ENAMETOOLONG}
_MISSING_WINERRORS = {2, 3, 21, 53, 67, 123, 161, 206}


@dataclass(frozen=True)
class Resolution:
    resolved: str  # absolute, forward slashes, original case
    changed: bool  # a link was followed or a short name expanded
    left_roots: bool  # the target is outside every root (the walk stopped there)
    error: str | None = None


def enabled() -> bool:
    return os.environ.get("WARDEN_RESOLVE_LINKS", "1").lower() not in ("0", "false", "no")


def is_unc(path: str) -> bool:
    return path.replace("\\", "/").startswith("//")


def _slash(path: str) -> str:
    p = path.replace("\\", "/")
    if p.startswith("//?/unc/") or p.startswith("//?/UNC/"):
        return "//" + p[8:]
    if p.startswith("//?/"):
        return p[4:]
    return p


def _key(path: str) -> str:
    return posixpath.normpath(_slash(path)).lower().rstrip("/")


def _split(path: str) -> tuple[str, list[str]]:
    """Anchor (`C:/`, `/`) and components of an absolute path."""
    p = _slash(path)
    if len(p) >= 2 and p[1] == ":":
        anchor, rest = p[:2] + "/", p[2:]
    else:
        anchor, rest = "/", p
    return anchor, [c for c in rest.split("/") if c]


def _join(base: str, parts: Sequence[str]) -> str:
    if not parts:
        return base
    return base.rstrip("/") + "/" + "/".join(parts)


def _find_root(path: str, roots: Sequence[str]) -> str | None:
    """The longest root containing `path` (lexically), in its original spelling."""
    key = _key(path)
    best: str | None = None
    for root in roots:
        rkey = _key(root)
        if (key == rkey or key.startswith(rkey + "/")) and (
            best is None or len(rkey) > len(_key(best))
        ):
            best = root
    return best


def _is_missing(exc: OSError) -> bool:
    if isinstance(exc, FileNotFoundError | NotADirectoryError):
        return True
    return exc.errno in _MISSING_ERRNOS or getattr(exc, "winerror", None) in _MISSING_WINERRORS


def _is_link(st: os.stat_result) -> bool:
    if stat.S_ISLNK(st.st_mode):
        return True
    return getattr(st, "st_reparse_tag", 0) == getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", -1)


def resolve(path: str, roots: Sequence[str], *, deadline: float) -> Resolution:
    """Follow links in `path` (absolute) while it stays inside `roots` (absolute). Never raises."""
    try:
        clean = [posixpath.normpath(_slash(r)) for r in roots if not is_unc(r)]
        return _resolve(path, clean, deadline)
    except Exception as exc:  # noqa: BLE001 -- any surprise must end in `ask`, not a crash
        logger.exception("link resolution failed for %s", path)
        return Resolution(_slash(path), False, False, f"resolution failed: {exc}")


def _resolve(path: str, roots: list[str], deadline: float) -> Resolution:
    start = _slash(path)
    if is_unc(start):
        return Resolution(start, False, True)
    changed = False
    hops = 0

    def restart(target: str, rest: deque[str]) -> tuple[str | None, deque[str]]:
        """Continue the walk at `target`; `None` when it is outside every root."""
        target = posixpath.normpath(_slash(target))
        root = _find_root(target, roots)
        if root is None:
            rest.appendleft(target)
            return None, rest
        root_parts = _split(root)[1]
        rest.extendleft(reversed(_split(target)[1][len(root_parts) :]))
        return root, rest

    if len(start) > MAX_PATH_LEN:  # cannot exist on any filesystem
        return Resolution(start, False, False)
    current, remaining = restart(start, deque())
    if current is None:  # lexically outside: the boundary rules handle it
        return Resolution(start, False, True)
    while remaining:
        if time.monotonic() > deadline:
            return Resolution(start, changed, False, "resolution took too long")
        part = remaining.popleft()
        if part == ".":
            continue
        if part == "..":
            current, remaining = restart(posixpath.dirname(current.rstrip("/")), remaining)
            if current is None:
                return _outside(remaining)
            continue
        candidate = _join(current, [part])
        try:
            st = os.lstat(candidate)
        except ValueError:  # embedded NUL, too long: such a file cannot exist
            return _finish(_join(candidate, list(remaining)), roots, changed)
        except OSError as exc:
            if _is_missing(exc):  # the rest does not exist yet (a new file): nothing to follow
                return _finish(_join(candidate, list(remaining)), roots, changed)
            return Resolution(start, changed, False, f"cannot check {candidate}: {exc}")
        if not _is_link(st):
            current = candidate
            continue
        hops += 1
        if hops > MAX_HOPS:
            return Resolution(start, changed, False, "too many links (loop?)")
        target = _slash(os.readlink(candidate))
        changed = True
        if is_unc(target):
            return Resolution(_join(target, list(remaining)), True, True)
        if not (target.startswith("/") or (len(target) >= 2 and target[1] == ":")):
            target = posixpath.join(current, target)
        current, remaining = restart(target, remaining)
        if current is None:
            return _outside(remaining)
    return _finish(current, roots, changed)


def _outside(remaining: deque[str]) -> Resolution:
    """The walk left the roots: `remaining` is the target followed by the unwalked rest."""
    target = remaining.popleft()
    return Resolution(_join(target, list(remaining)), True, True)


def _finish(path: str, roots: list[str], changed: bool) -> Resolution:
    """Expand Windows 8.3 short names (`AGENTW~1`) inside the root."""
    if os.name != "nt" or not _SHORT_NAME_RE.search(path):
        return Resolution(path, changed, False)
    root = _find_root(path, roots)
    if root is None:
        return Resolution(path, changed, False)
    rel = _key(path)[len(_key(root)) :].lstrip("/")
    real_root = _slash(os.path.realpath(root))
    real = _slash(os.path.realpath(path))
    real_rel = real[len(real_root) :].lstrip("/") if _key(real).startswith(_key(real_root)) else ""
    if not real_rel or real_rel.lower() == rel:
        return Resolution(path, changed, False)
    return Resolution(_join(_slash(root), real_rel.split("/")), True, False)


# ---------------------------------------------------------------------------
# Hard links
# ---------------------------------------------------------------------------

_cache: dict[tuple, tuple[float, dict[tuple[int, int], tuple[str, str]]]] = {}

_HOME_SECRETS = (
    ".aws/credentials",
    ".netrc",
    ".git-credentials",
    ".pgpass",
    ".docker/config.json",
    ".kube/config",
)


def clear_cache() -> None:
    _cache.clear()


def _plain(base: str, rel: Sequence[str]) -> tuple[str, os.stat_result] | None:
    """`base/rel...` and its `lstat`, when no component is a link (never followed: a planted
    link to `//host/share` would be an SMB call). `None` if missing or a link."""
    if is_unc(base):
        return None
    path = _slash(base)
    st: os.stat_result | None = None
    for part in rel:
        path = _join(path, [part])
        try:
            st = os.lstat(path)
        except (OSError, ValueError):
            return None
        if _is_link(st):
            return None
    return (path, st) if st is not None else None


def _plain_files(base: str, rel: Sequence[str]) -> list[str]:
    """Names of the regular, non-link files directly in `base/rel` (itself not a link)."""
    if rel:
        found = _plain(base, rel)
        if found is None or not stat.S_ISDIR(found[1].st_mode):
            return []
        directory = found[0]
    elif is_unc(base):
        return []
    else:
        directory = _slash(base)
    try:
        return sorted(os.listdir(directory))
    except (OSError, ValueError):
        return []


def protected_inodes(
    cwd: str, roots: Sequence[str], is_secret_name: Callable[[str], bool]
) -> dict[tuple[int, int], tuple[str, str]]:
    """`(st_dev, st_ino)` -> `(path, kind)` for protected files; kind is `secret`,
    `agentwarden` or `claude_settings`. Cached for a minute. Never raises.

    Only `lstat`/`listdir` of fixed local paths; a link anywhere on the way is skipped, not
    followed."""
    home = os.path.expanduser("~")
    key = (home, cwd, tuple(roots))
    hit = _cache.get(key)
    if hit is not None and time.monotonic() - hit[0] < CACHE_TTL_S:
        return hit[1]
    wanted: list[tuple[str, list[str], str]] = []  # (base, relative parts, kind)
    for name in _plain_files(home, [".ssh"]):
        low = name.lower()
        if not (low.endswith(".pub") or low.startswith("known_hosts") or low == "config"):
            wanted.append((home, [".ssh", name], "secret"))
    wanted += [(home, rel.split("/"), "secret") for rel in _HOME_SECRETS]
    for root in dict.fromkeys([cwd, *roots]):
        wanted += [(root, [n], "secret") for n in _plain_files(root, []) if is_secret_name(n)]
    wanted += [
        (cwd, [".agentwarden", n], "agentwarden") for n in _plain_files(cwd, [".agentwarden"])
    ]
    for name in ("settings.json", "settings.local.json"):
        wanted.append((cwd, [".claude", name], "claude_settings"))
    table: dict[tuple[int, int], tuple[str, str]] = {}
    for base, rel, kind in wanted:
        found = _plain(base, rel)
        if found is not None and stat.S_ISREG(found[1].st_mode) and found[1].st_ino:
            table[(found[1].st_dev, found[1].st_ino)] = (found[0], kind)
    if is_unc(home) or home == "~":
        logger.warning("home directory %s not checked for hard-linked secrets", home)
    _cache[key] = (time.monotonic(), table)
    return table


def hardlink_target(
    path: str, cwd: str, roots: Sequence[str], is_secret_name: Callable[[str], bool]
) -> tuple[str, str] | None:
    """`(protected path, kind)` when `path` is a hard link to a protected file, else None."""
    if is_unc(path):
        return None
    try:
        st = os.lstat(path)  # `path` is already resolved: a link left here is not followed
    except (OSError, ValueError):
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_nlink < 2 or not st.st_ino:
        return None
    match = protected_inodes(cwd, roots, is_secret_name).get((st.st_dev, st.st_ino))
    if match is None or _key(match[0]) == _key(path):
        return None  # the protected file itself: the lexical rules already decided
    return match
