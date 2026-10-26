"""Shared stdlib-only helpers for AgentWarden command hooks.

No project imports here: this must keep working even when the
src/agentwarden package is broken or not installed.
"""

import json
import os
from datetime import UTC, datetime
from pathlib import Path


def resolve_output_dir() -> Path:
    home = os.environ.get("AGENTWARDEN_HOME")
    if home:
        return Path(home)
    return Path.cwd() / ".agentwarden"


def append_event(event: dict) -> None:
    try:
        output_dir = resolve_output_dir()
        output_dir.mkdir(parents=True, exist_ok=True)
        record = dict(event)
        record["received_at"] = datetime.now(UTC).isoformat()
        with open(output_dir / "events.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        pass


def read_stdin_json(raw: str) -> dict | None:
    try:
        data = json.loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return data
