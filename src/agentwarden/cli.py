"""`agentwarden` command line: wire a project, start the daemon, check the setup (spec 037)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agentwarden import resources

DEFAULT_URL = "http://127.0.0.1:8765"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
HOOK_SCRIPTS = ("on_prompt.py", "on_tool.py", "on_read.py")
# (event, matcher or None, script, timeout seconds); mirrors examples/settings.agentwarden.json.
HOOKS: tuple[tuple[str, str | None, str, int], ...] = (
    ("UserPromptSubmit", None, "on_prompt.py", 5),
    ("PreToolUse", "*", "on_tool.py", 15),
    ("PostToolUse", "Read|WebFetch", "on_read.py", 15),
)


class CliError(Exception):
    pass


def settings_path(project: Path, shared: bool) -> Path:
    name = "settings.json" if shared else "settings.local.json"
    return project / ".claude" / name


def hook_command(script: str, hooks: Path | None = None, python: str | None = None) -> str:
    hooks = hooks or resources.hooks_dir()
    python = python or sys.executable
    return f'"{Path(python).as_posix()}" "{(hooks / script).as_posix()}"'


def _is_ours(entry: Any) -> bool:
    """A hook group whose commands run one of AgentWarden's hook scripts."""
    if not isinstance(entry, dict):
        return False
    for hook in entry.get("hooks") or []:
        command = hook.get("command", "") if isinstance(hook, dict) else ""
        if not isinstance(command, str):
            continue
        normalized = command.replace("\\", "/")
        if any(f"/{script}" in normalized for script in HOOK_SCRIPTS) and "hooks/" in normalized:
            return True
    return False


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CliError(f"{path} is not valid JSON ({exc}); left unchanged") from None
    if not isinstance(data, dict):
        raise CliError(f"{path} does not hold a JSON object; left unchanged")
    if not isinstance(data.get("hooks", {}), dict):
        raise CliError(f"{path}: 'hooks' is not an object; left unchanged")
    return data


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")


def _without_ours(hooks: dict) -> dict:
    cleaned: dict = {}
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            cleaned[event] = groups
            continue
        kept = [g for g in groups if not _is_ours(g)]
        if kept:
            cleaned[event] = kept
    return cleaned


def install_hooks(project: Path, shared: bool = False) -> Path:
    if not project.is_dir():
        raise CliError(f"{project} is not a directory")
    hooks = resources.hooks_dir()
    missing = [s for s in HOOK_SCRIPTS if not (hooks / s).is_file()]
    if missing:
        raise CliError(f"hook scripts missing in {hooks}: {', '.join(missing)}")
    path = settings_path(project, shared)
    data = _load(path)
    merged = _without_ours(data.get("hooks", {}))
    for event, matcher, script, timeout in HOOKS:
        group: dict = {}
        if matcher is not None:
            group["matcher"] = matcher
        group["hooks"] = [
            {"type": "command", "command": hook_command(script, hooks), "timeout": timeout}
        ]
        merged.setdefault(event, []).append(group)
    data["hooks"] = merged
    _write(path, data)
    return path


def uninstall_hooks(project: Path, shared: bool = False) -> Path:
    path = settings_path(project, shared)
    if not path.exists():
        return path
    data = _load(path)
    cleaned = _without_ours(data.get("hooks", {}))
    if cleaned:
        data["hooks"] = cleaned
    else:
        data.pop("hooks", None)
    _write(path, data)
    return path


def daemon_url() -> str:
    """`WARDEN_URL` when it is plain http on loopback (as the hooks require), else the default."""
    raw = (os.environ.get("WARDEN_URL") or DEFAULT_URL).rstrip("/")
    try:
        parts = urlsplit(raw)
        loopback = parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS
        clean = loopback and parts.path in ("", "/") and not parts.query and not parts.fragment
    except ValueError:
        clean = False
    return raw if clean else DEFAULT_URL


def daemon_running(url: str, timeout: float = 1.0) -> bool:
    try:
        with urllib.request.urlopen(f"{url}/health", timeout=timeout) as response:
            return response.status == 200
    except Exception:
        return False


def judge_summary() -> list[str]:
    judge = os.environ.get("WARDEN_JUDGE") or "off"
    lines = [f"judge: {judge}"]
    lines.append(f"META_API_KEY: {'set' if os.environ.get('META_API_KEY') else 'not set'}")
    local = "set" if os.environ.get("WARDEN_LOCAL_BASE") else "not set"
    lines.append(f"WARDEN_LOCAL_BASE: {local}")
    if judge == "off":
        lines.append("  rules only: anything the rules don't settle becomes ask")
    elif judge == "cascade" and not os.environ.get("META_API_KEY"):
        lines.append("  no Muse Spark key: unsure local verdicts become ask")
    return lines


NEXT_STEPS = """\
Next:
  1. Start the daemon in a terminal that has the judge settings:
       export WARDEN_JUDGE=cascade                          # or: local, meta_api, off
       export WARDEN_LOCAL_BASE=http://127.0.0.1:11434/v1   # Ollama
       export WARDEN_LOCAL_MODEL=llama3.1:8b
       export META_API_KEY=...                              # optional: Muse Spark escalation
       agentwarden serve
  2. Restart Claude Code in the project. Check with: agentwarden status"""


def cmd_init(args: argparse.Namespace) -> int:
    project = Path(args.project).resolve()
    path = install_hooks(project, shared=args.shared)
    print(f"AgentWarden hooks written to {path}")
    print(f"Hook scripts: {resources.hooks_dir()}")
    print(NEXT_STEPS)
    return 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    path = uninstall_hooks(Path(args.project).resolve(), shared=args.shared)
    print(f"AgentWarden hooks removed from {path}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    url = daemon_url()
    print(f"hook scripts: {resources.hooks_dir()}")
    state = "running" if daemon_running(url) else "not running (start it: agentwarden serve)"
    print(f"daemon {url}: {state}")
    for line in judge_summary():
        print(line)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from agentwarden.daemon import daemon_port

    uvicorn.run("agentwarden.daemon:app", host="127.0.0.1", port=daemon_port())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentwarden", description="Semantic firewall for AI coding agents."
    )
    parser.add_argument("--version", action="version", version=f"agentwarden {_version()}")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, handler, text in (
        ("init", cmd_init, "add AgentWarden's hooks to a project's Claude Code settings"),
        ("uninstall", cmd_uninstall, "remove AgentWarden's hooks from a project"),
    ):
        p = sub.add_parser(name, help=text)
        p.add_argument("project", nargs="?", default=".", help="project directory (default: .)")
        p.add_argument(
            "--shared",
            action="store_true",
            help="use .claude/settings.json instead of settings.local.json",
        )
        p.set_defaults(func=handler)

    sub.add_parser("status", help="show hooks, daemon and judge setup").set_defaults(
        func=cmd_status
    )
    sub.add_parser("serve", help="start the daemon on 127.0.0.1").set_defaults(func=cmd_serve)
    return parser


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("agentwarden")
    except Exception:
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CliError as exc:
        print(f"agentwarden: {exc}", file=sys.stderr)
        return 1
