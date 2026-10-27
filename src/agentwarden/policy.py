"""User policy stage (spec 004): `.agentwarden/policy.yaml`, loaded and matched.

No model call. Runs between `rules.py`'s hard-deny stage and its built-in defaults --
policy can never weaken a hard deny (the hard-deny stage runs first and `rules.evaluate`
never reaches this stage for those cases).
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
import shlex
from pathlib import Path
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ValidationError

from agentwarden.models import ToolEvent, Verdict
from agentwarden.rules import _collect_path_fields, _get_str, _is_inside_project, _normalize_full

logger = logging.getLogger(__name__)

_DEFAULT_RELATIVE_PATH = Path(".agentwarden") / "policy.yaml"


class Policy(BaseModel):
    version: int = 1
    deny_paths: list[str] = []
    ask_paths: list[str] = []
    allow_paths: list[str] = []
    deny_commands: list[str] = []
    ask_commands: list[str] = []
    allow_commands: list[str] = []
    allow_domains: list[str] = []


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


_EXTENSION_RE = re.compile(r"\.[A-Za-z0-9_]+$")


def _split_command(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.escape = ""  # keep backslashes: Windows paths
        return list(lexer)
    except ValueError:
        return [tok.strip("\"'") for tok in command.split()]


def _command_path_tokens(command: str) -> list[str]:
    """Path-like tokens of a shell command (spec 008). Bare words are not paths."""
    paths = []
    for tok in _split_command(command):
        if tok.startswith("-"):
            if "=" not in tok:
                continue
            tok = tok.split("=", 1)[1]
        tok = tok.strip("\"'")
        if not tok or any(c.isspace() for c in tok) or "://" in tok:
            continue
        if "/" in tok or "\\" in tok or _EXTENSION_RE.search(tok):
            paths.append(tok)
    return paths


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


def _command_matches(command: str, prefixes: list[str]) -> bool:
    collapsed = " ".join(command.split()).lower()
    return any(
        collapsed == prefix.lower() or collapsed.startswith(prefix.lower() + " ")
        for prefix in prefixes
    )


def _any_command_matches(event: ToolEvent, prefixes: list[str]) -> bool:
    if not prefixes:
        return False
    if event.tool_name not in ("Bash", "PowerShell"):
        return False
    command = _get_str(event.tool_input, "command")
    if command is None:
        return False
    return _command_matches(command, prefixes)


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
    tmp.write_text(content, encoding="utf-8", newline="\n")
    os.replace(tmp, path)
    _cache.pop(str(path), None)
    return True


def match(policy: Policy, event: ToolEvent) -> Verdict | None:
    """Match an event against the policy. Precedence: deny > ask > allow."""
    if _any_path_matches(event, policy.deny_paths, include_command=True) or _any_command_matches(
        event, policy.deny_commands
    ):
        return _deny("this path or command is denied by policy")
    if _any_path_matches(event, policy.ask_paths, include_command=True) or _any_command_matches(
        event, policy.ask_commands
    ):
        return _ask("this path or command needs confirmation by policy")
    if (
        _any_path_matches(event, policy.allow_paths)
        or _any_command_matches(event, policy.allow_commands)
        or _any_domain_matches(event, policy.allow_domains)
    ):
        return _allow("this path, command or domain is allowed by policy")
    return None
