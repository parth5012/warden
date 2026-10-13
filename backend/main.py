"""Warden application server uniting backend REST API and frontend Jinja/HTMX views."""

from __future__ import annotations

import sys
import asyncio
import os
from pathlib import Path
from typing import Any
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

if sys.platform == "win32":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

_ROOT_DIR = Path(__file__).resolve().parent.parent
_SRC_DIR = _ROOT_DIR / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from backend.api.health import router as health_router
from backend.api.inbox import router as inbox_router
from backend.api.runs import router as runs_router
from backend.api.audit import router as audit_router
from backend.api.telemetry import router as telemetry_router
from backend.api.policies import router as policies_router
from backend.api.auth import router as auth_router
from frontend.views import router as frontend_router

from app.agents import router as agents_router
from app.audit import router as aegis_audit_router
from app.chat import router as chat_router
from app.grants import router as grants_router
from app.leases import router as leases_router
from app.main import get_approvals, get_blast_radius
from app.policies import router as aegis_policies_router
from app.sandbox import router as sandbox_router
from app.traces import router as traces_router

_FRONTEND_STATIC_DIR = _ROOT_DIR / "frontend" / "static"
_APP_STATIC_DIR = _ROOT_DIR / "app" / "static"


class MultiDirStaticFiles(StaticFiles):
    """StaticFiles mount searching multiple directories in priority order."""

    def __init__(self, directories: list[Path], **kwargs: Any) -> None:
        valid_dirs: list[str | os.PathLike[str]] = [str(d.resolve()) for d in directories if d.exists()]
        super().__init__(directory=valid_dirs[0] if valid_dirs else None, **kwargs)
        self.all_directories = valid_dirs


def create_app() -> FastAPI:
    """Create and configure the unified Warden FastAPI application."""
    app = FastAPI(
        title="Aegis — AI Agent Governance",
        description="Unified server for AI agent governance, HITL approvals, telemetry, and audit logs.",
        version="0.1.0",
    )

    # Mount static assets from frontend and app
    static_dirs = [d for d in (_FRONTEND_STATIC_DIR, _APP_STATIC_DIR) if d.exists()]
    if static_dirs:
        app.mount("/static", MultiDirStaticFiles(directories=static_dirs), name="static")

    # Mount backend API routes under /api
    app.include_router(health_router, prefix="/api")
    app.include_router(inbox_router, prefix="/api")
    app.include_router(runs_router, prefix="/api")
    app.include_router(audit_router, prefix="/api")
    app.include_router(telemetry_router, prefix="/api")
    app.include_router(policies_router, prefix="/api")
    app.include_router(auth_router, prefix="/api")
    app.include_router(grants_router, prefix="/api")

    # Also mount health/ready at root per standard Kubernetes/container probes
    app.include_router(health_router)

    # Mount frontend HTML page routes at root
    app.include_router(frontend_router)

    # Mount Aegis interactive chat and governance views
    app.include_router(chat_router)
    app.include_router(grants_router)
    app.include_router(agents_router)
    app.include_router(leases_router)
    app.include_router(traces_router)
    app.include_router(sandbox_router)
    app.include_router(aegis_audit_router)
    app.include_router(aegis_policies_router)

    # Mount Aegis action review endpoints
    @app.get("/approvals")
    def approvals_page(request: Request) -> Any:
        return get_approvals(request)

    @app.get("/actions/{action_id}")
    def blast_radius_page(request: Request, action_id: str) -> Any:
        return get_blast_radius(request, action_id)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
