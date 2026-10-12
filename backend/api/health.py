"""Health and readiness probes."""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from warden.config import settings
from warden.checkpoint import CheckpointManager

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Basic liveness probe."""
    return {"status": "ok"}


@router.get("/ready")
async def readiness_check() -> JSONResponse:
    """Readiness probe checking database connectivity."""
    checkpoint_status = "unavailable"
    if settings.postgres_uri:
        try:
            async with CheckpointManager.create(settings.postgres_uri) as mgr:
                if await mgr.health_check():
                    checkpoint_status = "ok"
        except Exception:
            checkpoint_status = "error"

    is_ready = checkpoint_status == "ok"
    content: dict[str, Any] = {
        "ready": is_ready,
        "checkpoint_store": checkpoint_status,
        "journal": "ok" if is_ready else "pending_db",
    }
    status_code = 200 if is_ready else 503
    return JSONResponse(status_code=status_code, content=content)
