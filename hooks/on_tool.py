#!/usr/bin/env python3
"""PreToolUse command hook: asks the daemon's /decide and fails closed (spec 005).

Stdlib only -- Claude Code runs this with whatever Python is on PATH, not the
project venv. Every error ends in the fail-closed `ask`; the script always
exits 0 and prints at most one ASCII-only JSON document.
"""

from __future__ import annotations

import importlib.util
import json
import math
import os
import re
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import ModuleType
from urllib.parse import urlsplit

DEFAULT_URL = "http://127.0.0.1:8765"
DEFAULT_TIMEOUT_S = 8.0
MAX_TIMEOUT_S = 25.0
MAX_BODY_BYTES = 64 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
DECISIONS = {"allow", "deny", "ask"}
FAILSAFE_REASON = "AgentWarden unavailable"
FAILSAFE_MESSAGE = (
    "\U0001f6e1 AgentWarden: unavailable, needs confirmation for this action (fail-safe)"
)
# Spec 027: `--agent <name>` picks the daemon's adapter and, if present, hooks/formats/<name>.py.
DEFAULT_AGENT = "claude_code"
AGENT_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
AGENT_HEADER = "X-AgentWarden-Agent"
FORMATS_DIR = Path(__file__).resolve().parent / "formats"
FORMATTER_FAILED_REASON = "AgentWarden hook output formatter failed"
FORMATTER_FAILED_MESSAGE = (
    "\U0001f6e1 AgentWarden: output formatter broken, blocked this action (fail-safe)"
)


def _dump(obj: dict) -> str:
    return json.dumps(obj, ensure_ascii=True)


def _decision_output(decision: str, reason: str, system_message: str | None) -> str:
    out: dict = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }
    if system_message:
        out["systemMessage"] = system_message
    return _dump(out)


def parse_agent(argv: Sequence[str]) -> str | None:
    """The agent named by `--agent NAME` / `--agent=NAME` (default Claude Code); `None` if the
    arguments are anything else."""
    if not argv:
        return DEFAULT_AGENT
    if len(argv) == 1 and argv[0].startswith("--agent="):
        name = argv[0][len("--agent=") :]
    elif len(argv) == 2 and argv[0] == "--agent":
        name = argv[1]
    else:
        return None
    return name if AGENT_RE.match(name) else None


def load_formatter(agent: str) -> ModuleType | None:
    """hooks/formats/<agent>.py, or `None` when the agent uses the Claude Code schema.

    Raises when the module exists but cannot be loaded."""
    if not AGENT_RE.match(agent):
        raise ValueError("malformed agent name")
    path = FORMATS_DIR / f"{agent}.py"
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(f"agentwarden_format_{agent}", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _render(formatter: ModuleType | None, decision: str, reason: str, message: str | None) -> str:
    if formatter is None:
        return _decision_output(decision, reason, message)
    out = formatter.decision_output(decision, reason, message)
    if not isinstance(out, str):
        raise TypeError("formatter returned a non-string")
    return out


def formatter_failure_output(notify: bool) -> str:
    """The agent has its own output schema but its formatter failed: print a Claude-schema
    `deny`. Some agents treat an `ask` they cannot use as "continue" (Codex), so the one
    decision we can still print must be the one that stops the call."""
    message = FORMATTER_FAILED_MESSAGE if notify else None
    return _decision_output("deny", FORMATTER_FAILED_REASON, message)


def failsafe_output(notify: bool, formatter: ModuleType | None = None) -> str:
    message = FAILSAFE_MESSAGE if notify else None
    if formatter is None:
        return _decision_output("ask", FAILSAFE_REASON, message)
    try:
        return _render(formatter, "ask", FAILSAFE_REASON, message)
    except Exception:
        return formatter_failure_output(notify)


def parse_verdict(status: int, body: bytes) -> dict | None:
    if status != 200 or len(body) > MAX_BODY_BYTES:
        return None
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    decision = data.get("decision")
    if not isinstance(decision, str) or decision not in DECISIONS:
        return None
    if not isinstance(data.get("reason"), str):
        return None
    system_message = data.get("system_message")
    if system_message is not None and not isinstance(system_message, str):
        return None
    return data


def build_output(verdict: dict, allow_mode: str, formatter: ModuleType | None = None) -> str:
    decision = verdict["decision"]
    if decision == "allow":
        if allow_mode != "explicit":
            return ""
        return _render(formatter, "allow", verdict["reason"], None)
    return _render(formatter, decision, verdict["reason"], verdict.get("system_message"))


def decide_url(env: Mapping[str, str] | None = None) -> str | None:
    env = os.environ if env is None else env
    raw = env.get("WARDEN_URL")
    if raw is None:
        raw = DEFAULT_URL
    try:
        parts = urlsplit(raw)
        parts.port  # noqa: B018 -- raises ValueError on a malformed port
    except ValueError:
        return None
    if parts.scheme != "http" or parts.hostname not in LOOPBACK_HOSTS:
        return None
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return None
    return raw.rstrip("/") + "/decide"


def hook_timeout_seconds(env: Mapping[str, str] | None = None) -> float:
    env = os.environ if env is None else env
    try:
        value = float(env.get("WARDEN_HOOK_TIMEOUT", ""))
    except ValueError:
        return DEFAULT_TIMEOUT_S
    if not math.isfinite(value) or value <= 0:
        return DEFAULT_TIMEOUT_S
    return min(value, MAX_TIMEOUT_S)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener() -> urllib.request.OpenerDirector:
    # ProxyHandler({}) ignores HTTP(S)_PROXY: the unredacted event must stay on loopback.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def call_daemon(
    url: str, body: bytes, deadline_s: float, headers: Mapping[str, str] | None = None
) -> tuple[int, bytes] | None:
    """POST `body` to `url`; `None` on any error or if the whole call exceeds `deadline_s`."""
    result: list[tuple[int, bytes]] = []
    all_headers = {"Content-Type": "application/json", **(headers or {})}

    def worker() -> None:
        request = urllib.request.Request(url, data=body, method="POST", headers=all_headers)
        try:
            with _opener().open(request, timeout=deadline_s) as response:
                result.append((response.status, response.read(MAX_BODY_BYTES + 1)))
        except urllib.error.HTTPError as e:
            result.append((e.code, b""))
        except Exception:
            pass

    # urllib's timeout is per socket operation; a slow-drip response would outlive it.
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(deadline_s)
    if thread.is_alive() or not result:
        return None
    return result[0]


def _record(event: dict) -> None:
    try:
        import _common

        _common.append_event(event)
    except Exception:
        pass


def run(stdin_bytes: bytes, env: Mapping[str, str], agent: str | None = DEFAULT_AGENT) -> str:
    """The whole hook pipeline. Never raises; returns what to print."""
    notify = True
    formatter: ModuleType | None = None
    try:
        notify = env.get("WARDEN_NOTIFY", "").lower() != "off"
        if agent is None or not AGENT_RE.match(agent):
            return failsafe_output(notify)
        try:
            formatter = load_formatter(agent)
        except Exception:
            return formatter_failure_output(notify)
        try:
            event = json.loads(stdin_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return failsafe_output(notify, formatter)
        if not isinstance(event, dict):
            return failsafe_output(notify, formatter)
        _record(event)
        url = decide_url(env)
        if url is None:
            return failsafe_output(notify, formatter)
        headers = {AGENT_HEADER: agent}
        response = call_daemon(url, stdin_bytes, hook_timeout_seconds(env), headers)
        if response is None:
            return failsafe_output(notify, formatter)
        verdict = parse_verdict(*response)
        if verdict is None:
            return failsafe_output(notify, formatter)
        return build_output(verdict, env.get("WARDEN_ALLOW", "passthrough"), formatter)
    except Exception:
        if formatter is not None:
            return formatter_failure_output(notify)
        return failsafe_output(notify)


def main() -> None:
    try:
        stdin_bytes = sys.stdin.buffer.read()
    except Exception:
        stdin_bytes = b""
    output = run(stdin_bytes, os.environ, parse_agent(sys.argv[1:]))
    if output:
        sys.stdout.write(output)
    sys.stdout.flush()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        try:
            sys.stdout.write(failsafe_output(True))
            sys.stdout.flush()
        except Exception:
            pass
    # os._exit: do not wait on a worker thread still stuck in a slow socket read.
    os._exit(0)
