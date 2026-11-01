"""User policy stage (spec 004): `.agentwarden/policy.yaml`, loaded and matched.

No model call. Runs between `rules.py`'s hard-deny stage and its built-in defaults --
policy can never weaken a hard deny (the hard-deny stage runs first and `rules.evaluate`
never reaches this stage for those cases).
"""

from __future__ import annotations

import fnmatch
import logging
import os
import posixpath
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ValidationError, field_validator

from agentwarden.models import ToolEvent, Verdict
from agentwarden.rules import (
    _collect_path_fields,
    _expand_home,
    _get_str,
    _is_abs_path,
    _is_inside_project,
    _normalize_full,
    is_inside_roots,
    path_token,
    split_command,
)

logger = logging.getLogger(__name__)

_DEFAULT_RELATIVE_PATH = Path(".agentwarden") / "policy.yaml"

MAX_ROOT_CHARS = 300
_FS_ROOT_RE = re.compile(r"^(?:[A-Za-z]:)?/*$")
_ROOT_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def valid_root(path: object) -> str | None:
    """A directory usable as an extra root (spec 025), or `None`.

    Absolute after `~` expansion, one line, at most 300 characters, not a filesystem root.
    """
    if not isinstance(path, str):
        return None
    path = path.strip()
    if not path or len(path) > MAX_ROOT_CHARS or _ROOT_CONTROL_RE.search(path):
        return None
    expanded = _expand_home(path).replace("\\", "/")
    if not _is_abs_path(expanded) or "$" in expanded or "%" in expanded:
        return None
    if _FS_ROOT_RE.match(posixpath.normpath(expanded)):
        return None
    return path


class Policy(BaseModel):
    version: int = 1
    mode: Literal["normal", "read_only"] = "normal"  # spec 024
    extra_roots: list[str] = []  # spec 025: absolute directories that count as the project
    deny_paths: list[str] = []
    ask_paths: list[str] = []
    allow_paths: list[str] = []
    deny_commands: list[str] = []
    ask_commands: list[str] = []
    allow_commands: list[str] = []
    allow_domains: list[str] = []

    @field_validator("extra_roots")
    @classmethod
    def _keep_valid_roots(cls, roots: list[str]) -> list[str]:
        kept = [r for r in (valid_root(root) for root in roots) if r is not None]
        if len(kept) != len(roots):
            logger.warning(
                "AgentWarden: dropped %d extra_roots entries (relative, filesystem root or "
                "too long)",
                len(roots) - len(kept),
            )
        return kept


_DEFAULT_POLICY = Policy()

# path -> (mtime or None for "missing", loaded Policy)
_cache: dict[str, tuple[float | None, Policy]] = {}
_warned_invalid = False


def _policy_path(project_root: str, path_override: str | None) -> str:
    if path_override:
        return path_override
    env_override = os.environ.get("WARDEN_POLICY")
    if env_override:
        return env_override
    return str(Path(project_root) / _DEFAULT_RELATIVE_PATH)


def load_policy(project_root: str, path_override: str | None = None) -> Policy:
    """Load the policy file, caching by its mtime.

    Missing file, invalid YAML or a schema mismatch all fall back to the default
    (empty) policy -- never raises, never falls back to allow-all.
    """
    global _warned_invalid
    path = _policy_path(project_root, path_override)

    try:
        mtime = os.path.getmtime(path)
    except OSError:
        policy = _DEFAULT_POLICY
        _cache[path] = (None, policy)
        return policy

    cached = _cache.get(path)
    if cached is not None and cached[0] == mtime:
        return cached[1]

    try:
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        if raw is None:
            raw = {}
        if not isinstance(raw, dict):
            raise ValueError("policy.yaml must be a mapping")
        policy = Policy.model_validate(raw)
    except (yaml.YAMLError, ValidationError, ValueError, OSError, UnicodeDecodeError):
        if not _warned_invalid:
            logger.warning("AgentWarden: policy.yaml is invalid, using defaults")
            _warned_invalid = True
        policy = _DEFAULT_POLICY

    _cache[path] = (mtime, policy)
    return policy


# ---------------------------------------------------------------------------
# Verdict builders -- every policy verdict has source "policy".
# ---------------------------------------------------------------------------


def _deny(detail: str) -> Verdict:
    return Verdict(
        decision="deny",
        risk=1.0,
        source="policy",
        reason=f"AgentWarden: blocked by policy -- {detail}.",
    )


def _ask(detail: str) -> Verdict:
    return Verdict(decision="ask", risk=None, source="policy", reason=f"AgentWarden: {detail}.")


def _allow(detail: str) -> Verdict:
    return Verdict(decision="allow", risk=0.0, source="policy", reason=f"AgentWarden: {detail}.")


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def _path_matches_glob(raw_path: str, cwd: str, glob: str) -> bool:
    full = _normalize_full(raw_path, cwd)
    root = _normalize_full(cwd, cwd)
    if not (full == root or full.startswith(root + "/")):
        return False
    rel = full[len(root) :].lstrip("/")
    pattern = glob.replace("\\", "/").strip().rstrip("/").lower()
    if fnmatch.fnmatch(rel, pattern):
        return True
    return fnmatch.fnmatch(rel, pattern + "/*")


def _command_path_tokens(command: str) -> list[str]:
    """Path-like tokens of a shell command (spec 008). Bare words are not paths."""
    return [p for p in (path_token(tok) for tok in split_command(command)) if p is not None]


def _any_path_matches(event: ToolEvent, globs: list[str], *, include_command: bool = False) -> bool:
    if not globs:
        return False
    fields = list(_collect_path_fields(event) or [])
    if include_command and event.tool_name in ("Bash", "PowerShell"):
        command = _get_str(event.tool_input, "command")
        if command is not None:
            fields.extend(_command_path_tokens(command))
    if not fields:
        return False
    return any(
        _is_inside_project(field, event.cwd) and _path_matches_glob(field, event.cwd, glob)
        for field in fields
        for glob in globs
    )


_SHELL_OPERATORS = re.compile(r"&&|\|\||[;|<>`\n]|\$\(")


def _command_matches(command: str, prefixes: list[str], *, exact_tail: bool = False) -> bool:
    """Prefix match. With `exact_tail` (allow rules) the rest may not chain other commands:
    `allow_commands: [npm test]` must not allow `npm test && curl ... | sh`."""
    if exact_tail and _SHELL_OPERATORS.search(command):
        return False
    collapsed = " ".join(command.split()).lower()
    return any(
        collapsed == prefix.lower() or collapsed.startswith(prefix.lower() + " ")
        for prefix in prefixes
    )


def _any_command_matches(
    event: ToolEvent, prefixes: list[str], *, exact_tail: bool = False
) -> bool:
    if not prefixes:
        return False
    if event.tool_name not in ("Bash", "PowerShell"):
        return False
    command = _get_str(event.tool_input, "command")
    if command is None:
        return False
    return _command_matches(command, prefixes, exact_tail=exact_tail)


def _host_matches_domain(host: str, domain: str) -> bool:
    host = host.lower()
    domain = domain.lower()
    return host == domain or host.endswith("." + domain)


def _any_domain_matches(event: ToolEvent, domains: list[str]) -> bool:
    if not domains or event.tool_name != "WebFetch":
        return False
    url = _get_str(event.tool_input, "url")
    if url is None:
        return False
    host = urlparse(url).hostname
    if not host:
        return False
    return any(_host_matches_domain(host, domain) for domain in domains)


# ---------------------------------------------------------------------------
# Writing (spec 015: dashboard "always allow / always deny")
# ---------------------------------------------------------------------------

RULE_KINDS = (
    "deny_commands",
    "ask_commands",
    "allow_commands",
    "deny_paths",
    "ask_paths",
    "allow_paths",
    "allow_domains",
)
MAX_RULE_CHARS = 200
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class PolicyWriteError(ValueError):
    """The rule or the existing policy file is invalid; nothing was written."""


def policy_file(project_root: str) -> Path:
    return Path(_policy_path(project_root, None))


def append_rule(path: Path | str, kind: str, value: str) -> bool:
    """Append `value` to list `kind`; `False` if already present. Atomic; never half-writes.

    Leading `#` comment lines are kept; other comments are lost (no ruamel dependency).
    Built-in hard denies run before the policy stage, so no rule written here can weaken them.
    """
    if kind not in RULE_KINDS:
        raise PolicyWriteError(f"unknown rule kind: {kind!r}")
    if not isinstance(value, str) or not value.strip():
        raise PolicyWriteError("rule value is empty")
    value = value.strip()
    if len(value) > MAX_RULE_CHARS or _CONTROL_CHARS.search(value):
        raise PolicyWriteError("rule value must be one line of at most 200 characters")
    path = Path(path)
    header: list[str] = []
    data: dict = {"version": 1}
    if path.exists():
        try:
            text = path.read_text(encoding="utf-8")
            loaded = yaml.safe_load(text)
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            raise PolicyWriteError(f"existing policy is unreadable: {exc}") from exc
        if loaded is None:
            loaded = {"version": 1}
        if not isinstance(loaded, dict):
            raise PolicyWriteError("existing policy is not a mapping")
        try:
            Policy.model_validate(loaded)
        except ValidationError as exc:
            raise PolicyWriteError(f"existing policy is invalid: {exc}") from exc
        data = loaded
        for line in text.splitlines():
            if not line.startswith("#"):
                break
            header.append(line)
    rules = list(data.get(kind) or [])
    if value in rules:
        return False
    rules.append(value)
    data[kind] = rules
    Policy.model_validate(data)
    body = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    content = "\n".join([*header, body]) if header else body
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(content, encoding="utf-8", newline="\n")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    _cache.pop(str(path), None)
    return True


_READ_TOOLS = ("Read", "Glob", "Grep")


def _is_project_read(event: ToolEvent, roots: Sequence[str] = ()) -> bool:
    """A Read/Glob/Grep call whose every path is provably inside the roots (spec 024/025)."""
    if event.tool_name not in _READ_TOOLS:
        return False
    for key in ("file_path", "path"):
        value = event.tool_input.get(key)
        if value is not None and not isinstance(value, str):
            return False
    fields = _collect_path_fields(event) or []
    if event.tool_name == "Read" and not fields:
        return False
    return all(is_inside_roots(field, event.cwd, roots or (event.cwd,)) for field in fields)


def _read_only_verdict(event: ToolEvent, roots: Sequence[str] = ()) -> Verdict:
    if _is_project_read(event, roots):
        return _allow("read-only profile: reading inside the project")
    if event.tool_name in _READ_TOOLS:
        return _ask("read-only profile: this read is not provably inside the project")
    return _ask(f"read-only profile: {event.tool_name} is not a read tool")


def match_deny(policy: Policy, event: ToolEvent) -> Verdict | None:
    """The policy's deny lists only (spec 025 runs the boundary ask between deny and the rest)."""
    if _any_path_matches(event, policy.deny_paths, include_command=True) or _any_command_matches(
        event, policy.deny_commands
    ):
        return _deny("this path or command is denied by policy")
    return None


def match_rest(policy: Policy, event: ToolEvent, *, roots: Sequence[str] = ()) -> Verdict | None:
    """Ask lists, the read-only profile, then allow lists. `roots` widen read-only reads."""
    if _any_path_matches(event, policy.ask_paths, include_command=True) or _any_command_matches(
        event, policy.ask_commands
    ):
        return _ask("this path or command needs confirmation by policy")
    if policy.mode == "read_only":  # allow_* lists are ignored in this mode
        return _read_only_verdict(event, roots)
    if (
        _any_path_matches(event, policy.allow_paths)
        or _any_command_matches(event, policy.allow_commands, exact_tail=True)
        or _any_domain_matches(event, policy.allow_domains)
    ):
        return _allow("this path, command or domain is allowed by policy")
    return None


def match(policy: Policy, event: ToolEvent) -> Verdict | None:
    """Match an event against the policy. Precedence: deny > ask > allow."""
    return match_deny(policy, event) or match_rest(policy, event)
