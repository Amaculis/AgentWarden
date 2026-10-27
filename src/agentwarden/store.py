"""SQLite audit log (spec 002).

One `sqlite3` connection per call — endpoints run in a thread pool, so no
connection is shared across calls.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from agentwarden.models import PromptEvent, ToolEvent, Verdict

_SCHEMA = """
CREATE TABLE IF NOT EXISTS prompts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    session_id TEXT NOT NULL,
    prompt_id TEXT,
    cwd TEXT NOT NULL,
    prompt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    session_id TEXT NOT NULL,
    prompt_id TEXT,
    tool_use_id TEXT,
    tool_name TEXT NOT NULL,
    tool_input_json TEXT NOT NULL,
    cwd TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    risk REAL,
    source TEXT NOT NULL,
    latency_ms INTEGER NOT NULL
);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat()


class Store:
    """SQLite-backed audit log, opened at `db_path`."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        return conn

    def add_prompt(self, event: PromptEvent) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO prompts (created_at, session_id, prompt_id, cwd, prompt)
                VALUES (?, ?, ?, ?, ?)
                """,
                (_now(), event.session_id, event.prompt_id, event.cwd, event.prompt),
            )
            conn.commit()
        finally:
            conn.close()

    def add_decision(self, event: ToolEvent, verdict: Verdict, latency_ms: int) -> int:
        conn = self._connect()
        try:
            cursor = conn.execute(
                """
                INSERT INTO decisions (
                    created_at, session_id, prompt_id, tool_use_id, tool_name,
                    tool_input_json, cwd, decision, reason, risk, source, latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _now(),
                    event.session_id,
                    event.prompt_id,
                    event.tool_use_id,
                    event.tool_name,
                    json.dumps(event.tool_input),
                    event.cwd,
                    verdict.decision,
                    verdict.reason,
                    verdict.risk,
                    verdict.source,
                    latency_ms,
                ),
            )
            conn.commit()
            return int(cursor.lastrowid)
        finally:
            conn.close()

    def recent_decisions(self, limit: int = 50, session_id: str | None = None) -> list[dict]:
        conn = self._connect()
        try:
            if session_id is not None:
                rows = conn.execute(
                    """
                    SELECT * FROM decisions WHERE session_id = ?
                    ORDER BY id DESC LIMIT ?
                    """,
                    (session_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM decisions ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        finally:
            conn.close()

        results = []
        for row in rows:
            record = dict(row)
            record["tool_input"] = json.loads(record.pop("tool_input_json"))
            results.append(record)
        return results

    def session_prompts(self, session_id: str) -> list[str]:
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT prompt FROM prompts WHERE session_id = ?
                ORDER BY id ASC
                """,
                (session_id,),
            ).fetchall()
        finally:
            conn.close()

        return [row["prompt"] for row in rows]
