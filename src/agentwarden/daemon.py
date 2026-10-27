"""FastAPI daemon: /event, /decide, /log, /health (spec 002).

Fail-closed: any error on /decide returns `200` with an `ask` verdict,
never `allow`. Errors never leak into the `reason` field shown to the agent.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import Response

from agentwarden.decide import decide
from agentwarden.models import PromptEvent, ToolEvent, Verdict, failsafe
from agentwarden.store import Store

logger = logging.getLogger("agentwarden.daemon")


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

        try:
            verdict = decide(tool_event)
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
