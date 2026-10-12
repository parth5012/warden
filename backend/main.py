"""Warden application server uniting backend REST API and frontend Jinja/HTMX views."""

from __future__ import annotations

import sys
import asyncio
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

if sys.platform == "win32":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

from backend.api.health import router as health_router
from backend.api.inbox import router as inbox_router
from backend.api.runs import router as runs_router
from backend.api.audit import router as audit_router
from backend.api.telemetry import router as telemetry_router
from backend.api.policies import router as policies_router
from frontend.views import router as frontend_router

_ROOT_DIR = Path(__file__).resolve().parent.parent
_STATIC_DIR = _ROOT_DIR / "frontend" / "static"


def create_app() -> FastAPI:
    """Create and configure the unified Warden FastAPI application."""
    app = FastAPI(
        title="Warden — AI Agent Governance",
        description="Unified server for AI agent governance, HITL approvals, telemetry, and audit logs.",
        version="0.1.0",
    )

    # Mount static assets from frontend
    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # Mount backend API routes under /api
    app.include_router(health_router, prefix="/api")
    app.include_router(inbox_router, prefix="/api")
    app.include_router(runs_router, prefix="/api")
    app.include_router(audit_router, prefix="/api")
    app.include_router(telemetry_router, prefix="/api")
    app.include_router(policies_router, prefix="/api")

    # Also mount health/ready at root per standard Kubernetes/container probes
    app.include_router(health_router)

    # Mount frontend HTML page routes at root
    app.include_router(frontend_router)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
