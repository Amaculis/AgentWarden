"""Deterministic rules stage (spec 003): hard denies, then built-in defaults.

No model call, no filesystem access, no network. `evaluate()` runs:

1. Hard denies (secrets, self-protection) -- nothing can weaken these.
2. Project boundary (spec 025) interleaved with the user policy (spec 004): boundary deny,
   policy deny, boundary ask, the rest of the policy.
3. Built-in defaults (destructive deny, risky ask, safe-read/safe-command allow).

Returns the first verdict that matches, or `None` if nothing matched.
"""

from __future__ import annotations

import os
import posixpath
import re
import shlex
from collections.abc import Sequence
from urllib.parse import urlparse

from agentwarden.models import ToolEvent, Verdict

# ---------------------------------------------------------------------------
# Verdict builders -- every rule verdict has source "rules" and an
# "AgentWarden:" reason prefix.
# ---------------------------------------------------------------------------


ALT_SECRETS = "Use .env.example or ask the user for the value you need."
ALT_SELF_PROTECTION = "Ask the user to change AgentWarden's settings from the dashboard."
ALT_DESTRUCTION = "Delete only specific build artifacts inside the project, or ask the user."


def _deny(detail: str, alternative: str | None = None) -> Verdict:
    return Verdict(
        decision="deny",
        risk=1.0,
        source="rules",
        reason=f"AgentWarden: blocked -- {detail}. Do not try another way; ask the user.",
        safer_alternative=alternative,
    )


def _ask(detail: str) -> Verdict:
    return Verdict(decision="ask", risk=None, source="rules", reason=f"AgentWarden: {detail}.")


def _allow(detail: str) -> Verdict:
    return Verdict(decision="allow", risk=0.0, source="rules", reason=f"AgentWarden: {detail}.")


# ---------------------------------------------------------------------------
# Field extraction -- missing / non-string fields are treated as absent.
# ---------------------------------------------------------------------------


def _get_str(tool_input: dict, key: str) -> str | None:
    val = tool_input.get(key)
    return val if isinstance(val, str) and val else None


PATH_FIELD_BY_TOOL = {
    "Read": "file_path",
    "Write": "file_path",
    "Edit": "file_path",
    "MultiEdit": "file_path",
    "NotebookEdit": "notebook_path",
}


def _collect_path_fields(event: ToolEvent) -> list[str] | None:
    """Target path-like strings for this tool, or `None` if the tool has none."""
    tool = event.tool_name
    ti = event.tool_input
    if tool in PATH_FIELD_BY_TOOL:
        val = _get_str(ti, PATH_FIELD_BY_TOOL[tool])
        return [val] if val else []
    if tool == "Grep":
        return [v for field in ("path", "glob") if (v := _get_str(ti, field))]
    if tool == "Glob":
        return [v for field in ("path", "pattern") if (v := _get_str(ti, field))]
    return None


# ---------------------------------------------------------------------------
# Path normalisation and component matching
# ---------------------------------------------------------------------------


def _is_abs_path(p: str) -> bool:
    if p.startswith("/"):
        return True
    return len(p) >= 2 and p[1] == ":" and p[0].isalpha()


def _expand_home(path: str) -> str:
    """Expand `~`, `$HOME`, `%USERPROFILE%`-style prefixes (spec 019).

    The daemon runs as the same user as the agent, so this is the file the tool would open.
    """
    stripped = path.strip()
    if stripped[:1] in ("~", "$", "%"):
        return os.path.expandvars(os.path.expanduser(stripped))
    return path


def _unresolved_home(path: str) -> bool:
    return path.strip()[:1] in ("~", "$", "%")


def _normalize_full(path: str, cwd: str) -> str:
    p = _expand_home(path).replace("\\", "/")
    if not _is_abs_path(p):
        p = posixpath.join(cwd.replace("\\", "/"), p)
    return posixpath.normpath(p).lower()


def _is_inside_project(path: str, cwd: str) -> bool:
    if _unresolved_home(_expand_home(path)):
        return False  # unknown variable: never treat it as a project file
    p = _normalize_full(path, cwd)
    c = _normalize_full(cwd, cwd)
    return p == c or p.startswith(c + "/")


def _path_parts(raw_path: str) -> list[str]:
    slash = raw_path.replace("\\", "/").lower()
    return [p for p in slash.split("/") if p not in ("", ".")]


def _has_component(raw_path: str, component: str) -> bool:
    return component in _path_parts(raw_path)


# ---------------------------------------------------------------------------
# Stage 1a -- secrets, structured paths
# ---------------------------------------------------------------------------

SECRET_EXACT_BASENAMES = {
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".netrc",
    ".pgpass",
    ".git-credentials",
}
SECRET_EXTENSIONS = (".pem", ".key", ".p12", ".pfx", ".kdbx")
ENV_SAFE_BASENAMES = {".env.example", ".env.sample", ".env.template"}

# Spec 020: browser credential/cookie stores and cloud CLI tokens.
BROWSER_DIRS = {
    "google-chrome",
    "chromium",
    "chrome",
    "brave-browser",
    "bravesoftware",
    "microsoft edge",
    "edge",
    "mozilla",
    "firefox",
}
BROWSER_SECRET_BASENAMES = {
    "login data",
    "cookies",
    "web data",
    "local state",
    "key4.db",
    "logins.json",
    "cookies.sqlite",
}
GCLOUD_SECRET_BASENAMES = {
    "application_default_credentials.json",
    "credentials.db",
    "access_tokens.db",
}
AZURE_SECRET_BASENAMES = {"accesstokens.json", "msal_token_cache.json", "msal_token_cache.bin"}


def _is_cloud_or_browser_secret(parts: list[str]) -> bool:
    basename, dirs = parts[-1], parts[:-1]
    if basename in BROWSER_SECRET_BASENAMES and BROWSER_DIRS.intersection(dirs):
        return True
    if "gcloud" in dirs and (basename in GCLOUD_SECRET_BASENAMES or "legacy_credentials" in dirs):
        return True
    if ".azure" in dirs and basename in AZURE_SECRET_BASENAMES:
        return True
    return ".kube" in dirs and basename == "config"


def _is_secret_path(raw_path: str) -> bool:
    parts = _path_parts(raw_path)
    if not parts:
        return False
    basename = parts[-1]
    if basename in SECRET_EXACT_BASENAMES:
        return True
    if basename.endswith(SECRET_EXTENSIONS):
        return True
    if basename == ".env" or (basename.startswith(".env.") and basename not in ENV_SAFE_BASENAMES):
        return True
    if ".ssh" in parts[:-1]:
        # config holds only host aliases and key file paths (fixed format), never key
        # material, unlike id_rsa etc. — safe to read, same as known_hosts.
        return not (basename.endswith(".pub") or basename in ("known_hosts", "config"))
    if ".aws" in parts[:-1] and basename == "credentials":
        return True
    if _is_cloud_or_browser_secret(parts):
        return True
    return bool(".docker" in parts[:-1] and basename == "config.json")


def _is_secret_glob(glob_str: str) -> bool:
    base = glob_str.strip().lower().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if base in ENV_SAFE_BASENAMES:
        return False
    if base.startswith(".env"):
        return True
    if base.endswith(SECRET_EXTENSIONS):
        return True
    return base in SECRET_EXACT_BASENAMES


# ---------------------------------------------------------------------------
# Stage 1b -- secrets, shell mentions
# ---------------------------------------------------------------------------

_DOTENV_RE = re.compile(r"\.env(\.[A-Za-z0-9_-]+)?\b", re.IGNORECASE)

_SECRET_MENTION_PATTERNS = (
    re.compile(r"\.ssh/(?![^\s'\"]*\.pub\b)(?!known_hosts\b)(?!config\b)\S+", re.IGNORECASE),
    re.compile(r"\bid_rsa\b(?!\.pub)", re.IGNORECASE),
    re.compile(r"\bid_ed25519\b(?!\.pub)", re.IGNORECASE),
    re.compile(r"\bid_ecdsa\b(?!\.pub)", re.IGNORECASE),
    re.compile(r"\bid_dsa\b(?!\.pub)", re.IGNORECASE),
    re.compile(r"\.netrc\b", re.IGNORECASE),
    re.compile(r"\.pgpass\b", re.IGNORECASE),
    re.compile(r"\.git-credentials\b", re.IGNORECASE),
    re.compile(r"\.aws/credentials\b", re.IGNORECASE),
    re.compile(r"\.docker/config\.json\b", re.IGNORECASE),
    # Spec 020: browser stores and cloud CLI tokens.
    # Only as a path segment or quoted name: "validate login data" in code is not a secret.
    re.compile(r"(?:[/\\]|[\"'])login(?:\\ | )data\b", re.IGNORECASE),
    re.compile(r"\blogins\.json\b|\bkey4\.db\b|\bcookies\.sqlite\b", re.IGNORECASE),
    # Bounded gap: an unbounded [^\n]* here is quadratic on "chrome/chrome/...".
    re.compile(
        r"\b(?:google-chrome|chromium|brave[\w-]*|edge|chrome)[/\\][^\n]{0,200}?\bcookies\b",
        re.IGNORECASE,
    ),
    re.compile(r"application_default_credentials\.json\b", re.IGNORECASE),
    re.compile(r"gcloud[/\\](?:credentials|access_tokens)\.db\b", re.IGNORECASE),
    re.compile(r"\bmsal_token_cache\b|\.azure[/\\]accesstokens\.json\b", re.IGNORECASE),
    re.compile(r"\.kube[/\\]config\b", re.IGNORECASE),
    # Lookbehind instead of `\S+`: same meaning, linear (`\S+` was quadratic on long tokens).
    re.compile(r"(?<=\S)\.(?:pem|key|p12|pfx|kdbx)\b", re.IGNORECASE),
)


def _shell_mentions_secret_path(command: str) -> bool:
    for match in _DOTENV_RE.finditer(command):
        if match.group(0).lower() not in ENV_SAFE_BASENAMES:
            return True
    return any(p.search(command) for p in _SECRET_MENTION_PATTERNS)


_ENV_LISTING_RE = re.compile(
    r"\b(?:gci|get-childitem|dir|ls)\s+env:|\[environment\]::getenvironmentvariables",
    re.IGNORECASE,
)
_SENSITIVE_NAME_RE = re.compile(r"(key|token|secret|password|credential)", re.IGNORECASE)
_VAR_REF_RE = re.compile(
    r"\$env:([A-Za-z_][A-Za-z0-9_]*)"
    r"|\$\{([A-Za-z_][A-Za-z0-9_]*)\}"
    r"|\$([A-Za-z_][A-Za-z0-9_]*)"
    r"|%([A-Za-z_][A-Za-z0-9_]*)%"
)


def _mentions_sensitive_var(command: str) -> bool:
    for match in _VAR_REF_RE.finditer(command):
        name = next((g for g in match.groups() if g), None)
        if name and _SENSITIVE_NAME_RE.search(name):
            return True
    return False


def _env_dump_rule(command: str) -> bool:
    if command.strip().lower() in ("env", "printenv", "set"):
        return True
    return bool(_ENV_LISTING_RE.search(command)) or _mentions_sensitive_var(command)


def _secret_verdict_for_tool(tool: str) -> Verdict:
    if tool == "Write":
        return _ask("writing to what looks like a secret file (e.g. .env) needs confirmation")
    return _deny(
        "reading or modifying secret files (like .env, private keys, credentials) is not allowed",
        ALT_SECRETS,
    )


def _secret_rule(event: ToolEvent) -> Verdict | None:
    tool = event.tool_name
    if tool in ("Bash", "PowerShell"):
        command = _get_str(event.tool_input, "command")
        if command is None:
            return None
        if _shell_mentions_secret_path(command) or _env_dump_rule(command):
            return _deny(
                "reading secret files or dumping environment variables is not allowed", ALT_SECRETS
            )
        return None
    fields = _collect_path_fields(event)
    if not fields:
        return None
    for field in fields:
        if tool in ("Grep", "Glob"):
            if _is_secret_glob(field) or _is_secret_path(field):
                return _secret_verdict_for_tool(tool)
        elif _is_secret_path(field):
            return _secret_verdict_for_tool(tool)
    return None


# ---------------------------------------------------------------------------
# Stage 1c -- self-protection: .agentwarden
# ---------------------------------------------------------------------------

_AGENTWARDEN_MENTION_RE = re.compile(r"\.agentwarden\b", re.IGNORECASE)


def _agentwarden_rule(event: ToolEvent) -> Verdict | None:
    tool = event.tool_name
    if tool in ("Bash", "PowerShell"):
        command = _get_str(event.tool_input, "command")
        if command and _AGENTWARDEN_MENTION_RE.search(command):
            return _deny(
                "touching .agentwarden (policy, audit log, hooks) is not allowed",
                ALT_SELF_PROTECTION,
            )
        return None
    for field in _collect_path_fields(event) or []:
        if _has_component(field, ".agentwarden"):
            return _deny(
                "touching .agentwarden (policy, audit log, hooks) is not allowed",
                ALT_SELF_PROTECTION,
            )
    return None


# ---------------------------------------------------------------------------
# Stage 1d -- self-protection: .claude settings
# ---------------------------------------------------------------------------

_CLAUDE_SETTINGS_MENTION_RE = re.compile(r"\.claude[/\\]settings", re.IGNORECASE)
_CLAUDE_WHOLE_DIR_RE = re.compile(r"(?:^|[\s'\"/\\~])\.claude(?=$|[\s'\"])", re.IGNORECASE)


def _is_claude_settings_path(raw_path: str) -> bool:
    parts = _path_parts(raw_path)
    if not parts:
        return False
    basename = parts[-1]
    if basename not in ("settings.json", "settings.local.json"):
        return False
    return ".claude" in parts[:-1]


def _shell_mentions_claude_protected(command: str) -> bool:
    return bool(_CLAUDE_SETTINGS_MENTION_RE.search(command)) or bool(
        _CLAUDE_WHOLE_DIR_RE.search(command)
    )


def _claude_settings_rule(event: ToolEvent) -> Verdict | None:
    tool = event.tool_name
    if tool in ("Bash", "PowerShell"):
        command = _get_str(event.tool_input, "command")
        if command and _shell_mentions_claude_protected(command):
            return _deny(
                "touching .agentwarden's own .claude settings/config is not allowed",
                ALT_SELF_PROTECTION,
            )
        return None
    if tool in ("Write", "Edit", "MultiEdit"):
        for field in _collect_path_fields(event) or []:
            if _is_claude_settings_path(field):
                return _deny("editing Claude Code settings is not allowed", ALT_SELF_PROTECTION)
    return None


# ---------------------------------------------------------------------------
# Stage 1e -- self-protection: hooks/ directory
# ---------------------------------------------------------------------------

_HOOKS_PATH_TOKEN_RE = re.compile(r"\bhooks[/\\]", re.IGNORECASE)
_HOOKS_REMOVE_VERBS_RE = re.compile(
    r"\b(?:rm|del|erase|remove-item|ri|mv|move-item|ren|rename-item)\b", re.IGNORECASE
)


def _is_project_hooks_path(raw_path: str, cwd: str) -> bool:
    if not _is_inside_project(raw_path, cwd):
        return False
    full = _normalize_full(raw_path, cwd)
    root = _normalize_full(cwd, cwd)
    rel = full[len(root) :].lstrip("/")
    first = rel.split("/", 1)[0] if rel else ""
    return first == "hooks"


def _shell_mentions_hooks(command: str) -> bool:
    if _HOOKS_PATH_TOKEN_RE.search(command):
        return True
    return bool(_HOOKS_REMOVE_VERBS_RE.search(command)) and bool(
        re.search(r"\bhooks\b", command, re.IGNORECASE)
    )


def _hooks_rule(event: ToolEvent) -> Verdict | None:
    tool = event.tool_name
    if tool in ("Bash", "PowerShell"):
        command = _get_str(event.tool_input, "command")
        if command and _shell_mentions_hooks(command):
            return _deny(
                "touching AgentWarden's own hooks/ scripts is not allowed", ALT_SELF_PROTECTION
            )
        return None
    for field in _collect_path_fields(event) or []:
        if _is_project_hooks_path(field, event.cwd):
            return _deny(
                "touching AgentWarden's own hooks/ scripts is not allowed", ALT_SELF_PROTECTION
            )
    return None


# ---------------------------------------------------------------------------
# Stage 1f -- self-protection: daemon call and kill
# ---------------------------------------------------------------------------

_WARDEN_URL_DEFAULT = "http://127.0.0.1:8765"


def daemon_port() -> int:
    """Port AgentWarden's daemon listens on, from `WARDEN_URL` (default 8765)."""
    url = os.environ.get("WARDEN_URL", _WARDEN_URL_DEFAULT)
    try:
        port = urlparse(url).port
    except ValueError:
        port = None
    return port if port is not None else 8765


_LOOPBACK_HOST_RE = re.compile(
    r"\b(?:localhost|127\.\d+\.\d+\.\d+|::1|0\.0\.0\.0)\b", re.IGNORECASE
)


def _mentions_daemon(text: str) -> bool:
    port = daemon_port()
    if re.search(rf":{port}\b", text):
        return True
    # Same meaning as `\bHOST\b.*?\bPORT\b` (on one line), but linear: the regex form was
    # quadratic on inputs repeating the host, and bounding `.*?` would allow padding bypasses.
    port_re = re.compile(rf"\b{port}\b")
    for line in text.splitlines():
        host = _LOOPBACK_HOST_RE.search(line)
        if host and port_re.search(line, host.end()):
            return True
    return False


_KILL_VERBS_RE = re.compile(r"\b(?:kill|pkill|killall|taskkill|stop-process|spps)\b", re.IGNORECASE)
_PROCESS_NAMES_RE = re.compile(
    r"\b(?:agentwarden|uvicorn|python3?|pythonw|py)(?:\.exe)?\b", re.IGNORECASE
)


def _kill_daemon_rule(command: str) -> Verdict | None:
    verb_match = _KILL_VERBS_RE.search(command)
    if not verb_match:
        return None
    if _PROCESS_NAMES_RE.search(command):
        return _deny(
            "killing a process that may be the AgentWarden daemon is not allowed",
            ALT_SELF_PROTECTION,
        )
    rest = command[verb_match.end() :]
    if re.fullmatch(r"[\s\-/A-Za-z]*\d[\d\s\-/A-Za-z]*", rest):
        return _ask("killing a process that may be AgentWarden")
    return None


def _daemon_protection_rule(event: ToolEvent) -> Verdict | None:
    tool = event.tool_name
    if tool in ("Bash", "PowerShell"):
        text = _get_str(event.tool_input, "command")
    elif tool == "WebFetch":
        text = _get_str(event.tool_input, "url")
    else:
        text = None
    if text is None:
        return None
    if _mentions_daemon(text):
        return _deny("calling the AgentWarden daemon directly is not allowed", ALT_SELF_PROTECTION)
    if tool in ("Bash", "PowerShell"):
        kill_verdict = _kill_daemon_rule(text)
        if kill_verdict is not None:
            return kill_verdict
    return None


# ---------------------------------------------------------------------------
# Stage 1 composition
# ---------------------------------------------------------------------------


def _hard_deny_stage(event: ToolEvent) -> Verdict | None:
    for rule in (
        _secret_rule,
        _agentwarden_rule,
        _claude_settings_rule,
        _hooks_rule,
        _daemon_protection_rule,
    ):
        verdict = rule(event)
        if verdict is not None:
            return verdict
    return None


# ---------------------------------------------------------------------------
# Stage 3a -- destructive deny
# ---------------------------------------------------------------------------


def _is_dangerous_target(tok: str) -> bool:
    t = tok.strip().rstrip("\\").rstrip("/")
    low = t.lower()
    if low in ("", "/", "~", "$home", "*", ".", ".."):
        return True
    return bool(re.fullmatch(r"[a-z]:", low))


def _destructive_rm_rule(command: str) -> bool:
    rm_match = re.search(r"\brm\b(.*)", command, re.IGNORECASE)
    if rm_match:
        tokens = rm_match.group(1).split()
        short_flags = ""
        long_recursive = long_force = False
        targets: list[str] = []
        for tok in tokens:
            if tok.startswith("--recursive"):
                long_recursive = True
            elif tok.startswith("--force"):
                long_force = True
            elif tok.startswith("-") and len(tok) > 1:
                short_flags += tok[1:].lower()
            else:
                targets.append(tok)
        has_rf = (long_recursive or "r" in short_flags) and (long_force or "f" in short_flags)
        if has_rf and any(_is_dangerous_target(t) for t in targets):
            return True

    ri_match = re.search(r"\bremove-item\b(.*)", command, re.IGNORECASE)
    if ri_match:
        rest = ri_match.group(1)
        has_recurse = bool(re.search(r"-recurse\b", rest, re.IGNORECASE))
        has_force = bool(re.search(r"-force\b", rest, re.IGNORECASE))
        targets = [t for t in rest.split() if not t.startswith("-")]
        if has_recurse and has_force and any(_is_dangerous_target(t) for t in targets):
            return True
    return False


_DOWNLOAD_PIPE_RE = re.compile(
    r"\b(?:curl|wget|iwr|invoke-webrequest|irm)\b[^|]*\|\s*"
    r"(?:sh|bash|zsh|python3?|iex|invoke-expression)\b",
    re.IGNORECASE,
)
_DISK_DESTROY_RE = re.compile(
    r"\bmkfs(?:\.\w+)?\b|\bdd\b.*\bof=/dev/|\bformat\s+[a-z]:|\bdiskpart\b",
    re.IGNORECASE,
)


def _destructive_rule(command: str) -> bool:
    return (
        _destructive_rm_rule(command)
        or bool(_DOWNLOAD_PIPE_RE.search(command))
        or bool(_DISK_DESTROY_RE.search(command))
    )


# ---------------------------------------------------------------------------
# Stage 3b -- risky ask
# ---------------------------------------------------------------------------

_UPLOAD_RE = re.compile(
    r"\bcurl\b[^|;&]*\s(?:-d\b|--data\b|--data-raw\b|--data-binary\b|-F\b|--form\b|-T\b|--upload-file\b)"
    r"|\bcurl\b[^|;&]*-X\s*(?:POST|PUT)\b"
    r"|\bwget\b[^|;&]*--post-(?:data|file)\b"
    r"|\b(?:nc|ncat)\b[^|;&]*<"
    r"|\b(?:scp|rsync)\b[^|;&]*\S+:\S*"
    r"|\b(?:Invoke-WebRequest|Invoke-RestMethod)\b[^|;&]*-Method\s+(?:Post|Put)\b"
    r"|\b(?:Invoke-WebRequest|Invoke-RestMethod)\b[^|;&]*-InFile\b",
    re.IGNORECASE,
)
_GIT_HISTORY_RE = re.compile(
    r"\bgit\s+push\b[^|;&]*(?:--force-with-lease|--force\b|(?<!-)-f\b)"
    r"|\bgit\s+reset\s+--hard\b"
    r"|\bgit\s+clean\b[^|;&]*-f\b",
    re.IGNORECASE,
)


def _ask_defaults_rule(command: str) -> bool:
    return bool(_UPLOAD_RE.search(command)) or bool(_GIT_HISTORY_RE.search(command))


# ---------------------------------------------------------------------------
# Stage 3c -- safe allow
# ---------------------------------------------------------------------------


def _safe_read_rule(event: ToolEvent, roots: Sequence[str] = ()) -> Verdict | None:
    tool = event.tool_name
    ti = event.tool_input
    roots = roots or (event.cwd,)
    if tool == "Read":
        path = _get_str(ti, "file_path")
        if path is None:
            return None
        if _is_claude_settings_path(path):
            return None
        if is_inside_roots(path, event.cwd, roots):
            return _allow("reading a file inside the project")
        return None
    # Grep / Glob
    if "path" not in ti or ti.get("path") is None:
        return _allow("searching inside the project (no path given)")
    path = _get_str(ti, "path")
    if path is None:
        return None
    if is_inside_roots(path, event.cwd, roots):
        return _allow("searching inside the project")
    return None


_METACHAR_RE = re.compile(r"[;|&><$`\n]")
_SAFE_COMMAND_PREFIXES = (
    "ls",
    "dir",
    "pwd",
    "git status",
    "git diff",
    "git log",
    "git show",
    "make test",
    "make lint",
    "pytest",
    "python -m pytest",
    "uv run pytest",
    "ruff check",
    "ruff format --check",
)
_GIT_BRANCH_ALLOWED_FLAGS = {"--list", "-a", "-v", "-vv"}


def _is_safe_command(command: str) -> bool:
    if _METACHAR_RE.search(command):
        return False
    collapsed = " ".join(command.split())
    if any(tok.startswith("--output") for tok in collapsed.split(" ")):
        return False
    low = collapsed.lower()
    if low == "git branch":
        return True
    if low.startswith("git branch "):
        rest = low[len("git branch ") :].split()
        return all(tok in _GIT_BRANCH_ALLOWED_FLAGS for tok in rest)
    return any(low == prefix or low.startswith(prefix + " ") for prefix in _SAFE_COMMAND_PREFIXES)


def _default_stage(event: ToolEvent, roots: Sequence[str] = ()) -> Verdict | None:
    tool = event.tool_name
    if tool in ("Bash", "PowerShell"):
        command = _get_str(event.tool_input, "command")
        if command is None:
            return None
        if _destructive_rule(command):
            return _deny("this command destroys data or the filesystem", ALT_DESTRUCTION)
        if _ask_defaults_rule(command):
            return _ask(
                "this command uploads data or rewrites git history; confirm before continuing"
            )
        if _is_safe_command(command):
            return _allow("read-only command with no shell metacharacters")
        return None
    if tool in ("Read", "Grep", "Glob"):
        return _safe_read_rule(event, roots)
    return None


# ---------------------------------------------------------------------------
# Project boundary (spec 025): roots = project + policy extra_roots + session grants
# ---------------------------------------------------------------------------

_SHELL_TOOLS = ("Bash", "PowerShell")
_FILE_TOOLS = ("Read", "Write", "Edit", "MultiEdit", "NotebookEdit")
_SEARCH_TOOLS = ("Grep", "Glob")
_LISTING_COMMANDS = frozenset(
    {
        "find", "ls", "dir", "tree", "du", "grep", "egrep", "rg", "ag", "fd", "locate",
        "get-childitem", "gci", "select-string", "sls",
    }
)  # fmt: skip
_DEVICE_TOKENS = frozenset(
    {"/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr", "nul", "$null"}
)
_UNRESOLVED_VAR_RE = re.compile(r"\$|%[A-Za-z_]\w*%")
_HOME_PREFIX_RE = re.compile(
    r"^(?:\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE)(?=[/\\]|$)", re.IGNORECASE
)
_FLAG_VALUE_RE = re.compile(r"^-{1,2}[A-Za-z][\w-]*[=:]")
_WILDCARD_RE = re.compile(r"[*?\[{]")
_CHAIN_TOKENS = frozenset({"&&", "||", "|", ";", "&", "(", ")", "|&", ";;"})
_PATH_EXTENSION_RE = re.compile(r"\.[A-Za-z0-9_]+$")


def split_command(command: str) -> list[str]:
    """Shell-ish tokens; operators come out as their own tokens (spec 008)."""
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.escape = ""  # keep backslashes: Windows paths
        return list(lexer)
    except ValueError:
        return [tok.strip("\"'") for tok in command.split()]


def path_token(tok: str) -> str | None:
    """The path in a shell token, or `None` when it does not look like one."""
    if tok.startswith("-"):
        flag = _FLAG_VALUE_RE.match(tok)  # --out=x, PowerShell -Path:x
        if flag is None:
            return None
        tok = tok[flag.end() :]
    tok = tok.strip("\"'")
    if not tok or any(c.isspace() for c in tok) or "://" in tok:
        return None
    if "/" in tok or "\\" in tok or _PATH_EXTENSION_RE.search(tok):
        return tok
    return None


def command_path_tokens(command: str) -> list[tuple[str, str]]:
    """`(command_word, path)` for each path argument; the command word itself is skipped."""
    pairs: list[tuple[str, str]] = []
    word: str | None = None
    for tok in split_command(command.replace("\n", " ; ")):
        if tok in _CHAIN_TOKENS:
            word = None
            continue
        if word is None:
            word = tok
            continue
        path = path_token(tok)
        if path is not None:
            pairs.append((word, path))
    return pairs


def _is_unresolved(path: str) -> bool:
    """Any variable other than a leading home reference (the agent's shell may define it
    differently from the daemon's environment), or a home reference the daemon can't expand."""
    if _unresolved_home(_expand_home(path)):
        return True
    return bool(_UNRESOLVED_VAR_RE.search(_HOME_PREFIX_RE.sub("", path.strip(), count=1)))


def _wildcard_escapes(path: str) -> bool:
    """A `..` after the first wildcard component (`**/../../x`) can climb anywhere."""
    parts = re.split(r"[/\\]", path)
    first = next((i for i, part in enumerate(parts) if _WILDCARD_RE.search(part)), None)
    return first is not None and ".." in parts[first:]


def _literal_base(path: str) -> str:
    """The part of `path` before its first wildcard (the whole path if it has none)."""
    match = _WILDCARD_RE.search(path)
    if match is None:
        return path
    return path[: match.start()].rstrip("/\\") or "."


def is_inside_roots(path: str, cwd: str, roots: Sequence[str]) -> bool:
    """`path` is equal to or under one of `roots` (lexical; unresolved variables never are).

    Wildcards are judged by their literal prefix; a `..` after a wildcard is never inside.
    """
    if _is_unresolved(path) or _wildcard_escapes(path):
        return False
    full = _normalize_full(_literal_base(path), cwd)
    for root in roots:
        base = _normalize_full(root, cwd)
        if full == base or full.startswith(base.rstrip("/") + "/"):
            return True
    return False


def _display_full(path: str, cwd: str) -> str:
    """Absolute, normalised path in its original case (shown to the user, stored as grant)."""
    p = _expand_home(path).replace("\\", "/")
    if not _is_abs_path(p):
        p = posixpath.join(cwd.replace("\\", "/"), p)
    return posixpath.normpath(p)


def _grant_dir(path: str, cwd: str, *, is_file: bool) -> str | None:
    if _is_unresolved(path):
        return None
    full = _display_full(path, cwd)
    return posixpath.dirname(full) if is_file else full


def _grant_hint(grant: str | None) -> str:
    if not grant:
        return ""
    return (
        f"; to allow it, ask the user to grant {grant} for this session in the "
        "AgentWarden dashboard"
    )


def _boundary_deny(what: str, path: str, grant: str | None) -> Verdict:
    verdict = _deny(f"{what} outside the project ({path}) is not allowed{_grant_hint(grant)}")
    return verdict.model_copy(update={"grant_dir": grant})


def _boundary_ask(what: str, path: str, grant: str | None) -> Verdict:
    verdict = _ask(f"{what} outside the project ({path}) needs confirmation{_grant_hint(grant)}")
    return verdict.model_copy(update={"grant_dir": grant, "consult_judge": True})


def _boundary_stage(event: ToolEvent, roots: Sequence[str]) -> Verdict | None:
    tool, ti, cwd = event.tool_name, event.tool_input, event.cwd
    if tool in _SEARCH_TOOLS:
        keys = ("path", "pattern") if tool == "Glob" else ("path", "glob")
        for key in keys:
            value = _get_str(ti, key)
            if value is None:
                continue
            if not is_inside_roots(value, cwd, roots):
                grant = None if _wildcard_escapes(value) else _literal_base(value)
                grant = _grant_dir(grant, cwd, is_file=False) if grant else None
                return _boundary_deny("searching", value, grant)
        return None
    if tool in _FILE_TOOLS:
        for path in _collect_path_fields(event) or []:
            if not is_inside_roots(path, cwd, roots):
                return _boundary_ask(tool, path, _grant_dir(path, cwd, is_file=True))
        return None
    if tool in _SHELL_TOOLS:
        command = _get_str(ti, "command")
        if command is None:
            return None
        first_ask: Verdict | None = None
        for word, path in command_path_tokens(command):
            if path.lower() in _DEVICE_TOKENS or is_inside_roots(path, cwd, roots):
                continue
            name = posixpath.basename(word.replace("\\", "/")).lower().removesuffix(".exe")
            wildcard = _WILDCARD_RE.search(path) is not None
            is_file = not wildcard and bool(_PATH_EXTENSION_RE.search(path))
            grant = (
                None
                if _wildcard_escapes(path)
                else _grant_dir(_literal_base(path), cwd, is_file=is_file)
            )
            if name in _LISTING_COMMANDS:
                return _boundary_deny(f"listing or searching ({name})", path, grant)
            if first_ask is None:
                first_ask = _boundary_ask("a command path", path, grant)
        return first_ask
    return None


def policy_roots(event: ToolEvent, policy_extra: Sequence[str], extra: Sequence[str]) -> list[str]:
    return [event.cwd, *policy_extra, *extra]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def evaluate(event: ToolEvent, extra_roots: Sequence[str] = ()) -> Verdict | None:
    """Run the rule stages in order; return the first verdict, or `None`.

    hard denies -> boundary deny -> policy deny -> built-in default deny -> boundary ask ->
    rest of policy -> defaults.
    """
    from agentwarden import policy as policy_module

    verdict = _hard_deny_stage(event)
    if verdict is not None:
        return verdict
    loaded = policy_module.load_policy(event.cwd)
    roots = policy_roots(event, loaded.extra_roots, extra_roots)
    boundary = _boundary_stage(event, roots)
    if boundary is not None and boundary.decision == "deny":
        return boundary
    verdict = policy_module.match_deny(loaded, event)
    if verdict is not None:
        return verdict
    if boundary is not None:
        default = _default_stage(event, roots)  # `rm -rf /` stays a deny, not a boundary ask
        return default if default is not None and default.decision == "deny" else boundary
    verdict = policy_module.match_rest(loaded, event, roots=roots)
    if verdict is not None:
        return verdict
    return _default_stage(event, roots)
