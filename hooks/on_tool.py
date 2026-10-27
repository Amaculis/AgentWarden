#!/usr/bin/env python3
"""PreToolUse command hook: asks the daemon's /decide and fails closed (spec 005).

Stdlib only -- Claude Code runs this with whatever Python is on PATH, not the
project venv. Every error ends in the fail-closed `ask`; the script always
exits 0 and prints at most one ASCII-only JSON document.
"""

from __future__ import annotations

import json
import math
import os
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Mapping
from urllib.parse import urlsplit

DEFAULT_URL = "http://127.0.0.1:8765"
DEFAULT_TIMEOUT_S = 8.0
MAX_TIMEOUT_S = 10.0
MAX_BODY_BYTES = 64 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
DECISIONS = {"allow", "deny", "ask"}
FAILSAFE_REASON = "AgentWarden unavailable"
FAILSAFE_MESSAGE = (
    "\U0001f6e1 AgentWarden: unavailable, needs confirmation for this action (fail-safe)"
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


def failsafe_output(notify: bool) -> str:
    return _decision_output("ask", FAILSAFE_REASON, FAILSAFE_MESSAGE if notify else None)


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


def build_output(verdict: dict, allow_mode: str) -> str:
    decision = verdict["decision"]
    if decision == "allow":
        if allow_mode != "explicit":
            return ""
        return _decision_output("allow", verdict["reason"], None)
    return _decision_output(decision, verdict["reason"], verdict.get("system_message"))


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


def call_daemon(url: str, body: bytes, deadline_s: float) -> tuple[int, bytes] | None:
    """POST `body` to `url`; `None` on any error or if the whole call exceeds `deadline_s`."""
    result: list[tuple[int, bytes]] = []

    def worker() -> None:
        request = urllib.request.Request(
            url, data=body, method="POST", headers={"Content-Type": "application/json"}
        )
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


def run(stdin_bytes: bytes, env: Mapping[str, str]) -> str:
    """The whole hook pipeline. Never raises; returns what to print."""
    notify = True
    try:
        notify = env.get("WARDEN_NOTIFY", "").lower() != "off"
        try:
            event = json.loads(stdin_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return failsafe_output(notify)
        if not isinstance(event, dict):
            return failsafe_output(notify)
        _record(event)
        url = decide_url(env)
        if url is None:
            return failsafe_output(notify)
        response = call_daemon(url, stdin_bytes, hook_timeout_seconds(env))
        if response is None:
            return failsafe_output(notify)
        verdict = parse_verdict(*response)
        if verdict is None:
            return failsafe_output(notify)
        return build_output(verdict, env.get("WARDEN_ALLOW", "passthrough"))
    except Exception:
        return failsafe_output(notify)


def main() -> None:
    try:
        stdin_bytes = sys.stdin.buffer.read()
    except Exception:
        stdin_bytes = b""
    output = run(stdin_bytes, os.environ)
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
