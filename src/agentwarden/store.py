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

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    session_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    source TEXT NOT NULL,
    flagged INTEGER NOT NULL,
    confidence REAL,
    error TEXT,
    latency_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS taints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    session_id TEXT NOT NULL,
    source TEXT NOT NULL,
    UNIQUE (session_id, source)
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


# Columns added after spec 002; existing databases get them via ALTER TABLE (spec 010).
_ADDED_DECISION_COLUMNS = {
    "confidence": "REAL",
    "decided_by": "TEXT",
    "escalated": "INTEGER",
    "local_decision": "TEXT",
}


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
            existing = {row["name"] for row in conn.execute("PRAGMA table_info(decisions)")}
            for name, sql_type in _ADDED_DECISION_COLUMNS.items():
                if name not in existing:
                    conn.execute(f"ALTER TABLE decisions ADD COLUMN {name} {sql_type}")
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
                    tool_input_json, cwd, decision, reason, risk, source, latency_ms,
                    confidence, decided_by, escalated, local_decision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    verdict.confidence,
                    verdict.decided_by,
                    int(verdict.escalated),
                    verdict.local_decision,
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

    def add_scan(
        self,
        session_id: str,
        tool_name: str,
        source: str,
        flagged: bool,
        confidence: float | None,
        error: str | None,
        latency_ms: int,
    ) -> None:
        """Log a scan. The scanned content itself is never stored."""
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO scans (
                    created_at, session_id, tool_name, source, flagged, confidence, error,
                    latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _now(),
                    session_id,
                    tool_name,
                    source,
                    int(flagged),
                    confidence,
                    error,
                    latency_ms,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def add_taint(self, session_id: str, source: str) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO taints (created_at, session_id, source) VALUES (?, ?, ?)",
                (_now(), session_id, source),
            )
            conn.commit()
        finally:
            conn.close()

    def session_taints(self, session_id: str) -> list[str]:
        """Distinct flagged sources of the session, in first-flagged order."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT source FROM taints WHERE session_id = ? ORDER BY id ASC", (session_id,)
            ).fetchall()
        finally:
            conn.close()
        return list(dict.fromkeys(row["source"] for row in rows))

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
