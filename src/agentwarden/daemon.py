"""FastAPI daemon: /event, /decide, /log, /health (spec 002).

Fail-closed: any error on /decide returns `200` with an `ask` verdict,
never `allow`. Errors never leak into the `reason` field shown to the agent.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response

from agentwarden import scanner
from agentwarden.decide import decide, with_system_message
from agentwarden.judge import SessionContext
from agentwarden.models import PromptEvent, ReadEvent, ToolEvent, Verdict
from agentwarden.models import failsafe as _bare_failsafe
from agentwarden.providers import get_provider
from agentwarden.redact import redact
from agentwarden.scanner import ScanResult
from agentwarden.store import Store

logger = logging.getLogger("agentwarden.daemon")


def failsafe(reason: str) -> Verdict:
    """Fail-closed `ask` carrying the user-facing notification."""
    return with_system_message(_bare_failsafe(reason))


def session_context(store: Store, session_id: str) -> SessionContext:
    """Task (last 3 prompts) and last 5 actions of the session, oldest first."""
    prompts = store.session_prompts(session_id)[-3:]
    rows = store.recent_decisions(limit=5, session_id=session_id)
    actions = [{"tool_name": r["tool_name"], "tool_input": r["tool_input"]} for r in reversed(rows)]
    task = "\n---\n".join(prompts) or None
    taints = store.session_taints(session_id)
    return SessionContext(task=task, recent_actions=actions, taints=taints)


MAX_CONCURRENT_SCANS = 3
MAX_SOURCE_CHARS = 300


def scan_source(event: ReadEvent) -> str:
    """Redacted, bounded file path or URL: used for logs, the store, taints and the warning."""
    return redact(scanner.scan_source(event.tool_name, event.tool_input))[:MAX_SOURCE_CHARS]


def run_scan(event: ReadEvent, source: str) -> ScanResult:
    provider = get_provider(os.environ.get("WARDEN_SCANNER") or "local")
    return scanner.scan(scanner.extract_text(event.tool_response), source, provider)


def _default_db_path() -> Path:
    env = os.environ.get("AGENTWARDEN_DB")
    if env:
        return Path(env)
    return Path.home() / ".agentwarden" / "audit.db"


def create_app(db_path: Path | None = None) -> FastAPI:
    """Build the daemon app. Does not touch the filesystem: the store is
    opened on startup (lifespan), not here."""
    resolved_db_path = db_path if db_path is not None else _default_db_path()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.store = Store(resolved_db_path)
        app.state.scan_slots = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
        yield

    app = FastAPI(lifespan=lifespan)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/event", status_code=204)
    async def event(payload: PromptEvent, request: Request) -> Response:
        store: Store = request.app.state.store
        try:
            store.add_prompt(payload)
        except Exception:
            logger.exception("Failed to store prompt event")
            raise HTTPException(
                status_code=500, detail="AgentWarden: audit log unavailable"
            ) from None
        return Response(status_code=204)

    @app.post("/decide")
    async def decide_endpoint(request: Request) -> Verdict:
        store: Store = request.app.state.store
        start = time.monotonic()

        try:
            body = await request.json()
        except Exception:
            logger.exception("Invalid JSON body for /decide")
            return failsafe("AgentWarden: invalid event")

        try:
            tool_event = ToolEvent.model_validate(body)
        except Exception:
            logger.exception("Invalid ToolEvent payload for /decide")
            return failsafe("AgentWarden: invalid event")

        # Context only feeds the judge; failing to build it must not stop the rules from
        # running (a hard deny must stay a deny).
        try:
            context = session_context(store, tool_event.session_id)
        except Exception:
            logger.exception("session context unavailable")
            context = None

        try:
            verdict = await run_in_threadpool(decide, tool_event, context)
        except Exception:
            logger.exception("decide() raised")
            verdict = failsafe("AgentWarden: internal error")

        latency_ms = int((time.monotonic() - start) * 1000)

        try:
            store.add_decision(tool_event, verdict, latency_ms)
        except Exception:
            logger.exception("Failed to write audit row")
            return failsafe("AgentWarden: audit log unavailable")

        return verdict

    @app.post("/scan")
    async def scan_endpoint(payload: ReadEvent, request: Request) -> dict[str, str | None]:
        """Scan content the agent just read; `{"warning": null}` unless it was flagged."""
        store: Store = request.app.state.store
        source = scan_source(payload)
        slots: asyncio.Semaphore = request.app.state.scan_slots
        if slots.locked():
            # Scans share the threadpool with /decide; never let them starve it.
            result = ScanResult(error="busy")
        else:
            async with slots:
                try:
                    result = await run_in_threadpool(run_scan, payload, source)
                except Exception:
                    logger.exception("scan raised")
                    result = ScanResult(error="internal")
        try:
            store.add_scan(
                payload.session_id,
                payload.tool_name,
                source,
                result.flagged,
                result.confidence,
                result.error,
                result.latency_ms,
            )
            if result.flagged:
                store.add_taint(payload.session_id, source)
        except Exception:
            logger.exception("Failed to log scan")  # the warning matters more than the log
        if result.error:
            logger.warning("scan of %s failed: %s", source, result.error)
        if not result.flagged:
            return {"warning": None}
        return {"warning": scanner.warning_text(source, result)}

    @app.get("/log")
    async def log(
        request: Request,
        limit: int = Query(50, ge=1, le=500),
        session_id: str | None = None,
    ) -> list[dict]:
        store: Store = request.app.state.store
        return store.recent_decisions(limit=limit, session_id=session_id)

    return app


app = create_app()
