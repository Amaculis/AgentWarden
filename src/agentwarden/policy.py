"""User policy stage (spec 004): `.agentwarden/policy.yaml`, loaded and matched.

No model call. Runs between `rules.py`'s hard-deny stage and its built-in defaults --
policy can never weaken a hard deny (the hard-deny stage runs first and `rules.evaluate`
never reaches this stage for those cases).
"""

from __future__ import annotations

import fnmatch
import logging
import os
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


def _any_path_matches(event: ToolEvent, globs: list[str]) -> bool:
    if not globs:
        return False
    fields = _collect_path_fields(event)
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


def match(policy: Policy, event: ToolEvent) -> Verdict | None:
    """Match an event against the policy. Precedence: deny > ask > allow."""
    if _any_path_matches(event, policy.deny_paths) or _any_command_matches(
        event, policy.deny_commands
    ):
        return _deny("this path or command is denied by policy")
    if _any_path_matches(event, policy.ask_paths) or _any_command_matches(
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
