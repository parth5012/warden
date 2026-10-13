"""Tool registration for GuardedExecutor in Aegis.

Wires all Phase 1 Step 2 tools into GuardedExecutor's HandlerRegistry:
- get_system_metrics
- read_service_logs
- query_db_readonly
- exec_db_mutation
- read_file_sensitive
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING

from warden.models import Action, ActionKind
from warden.tools.database import exec_db_mutation, query_db_readonly
from warden.tools.filesystem import read_file_sensitive
from warden.tools.logs import read_service_logs
from warden.tools.metrics import get_system_metrics
from warden.tools.hitl_tools import validate_restart_service, validate_send_email

if TYPE_CHECKING:
    from warden.executor import GuardedExecutor


def register_tools(
    executor: GuardedExecutor,
    *,
    db_conn: sqlite3.Connection | None = None,
    log_root_dir: Path | None = None,
    file_root_dir: Path | None = None,
) -> None:
    """Register all 5 operational tools on the GuardedExecutor."""
    executor.register_handler(
        "get_system_metrics",
        get_system_metrics,
        kind=ActionKind.TOOL,
    )
    executor.register_handler(
        "read_service_logs",
        lambda action: read_service_logs(action, log_root_dir=log_root_dir),
        kind=ActionKind.TOOL,
    )
    executor.register_handler(
        "query_db_readonly",
        lambda action: query_db_readonly(action, db_conn=db_conn),
        kind=ActionKind.TOOL,
    )
    executor.register_handler(
        "exec_db_mutation",
        lambda action: exec_db_mutation(action, db_conn=db_conn),
        kind=ActionKind.TOOL,
    )
    executor.register_handler(
        "read_file_sensitive",
        lambda action: read_file_sensitive(action, safe_root_dir=file_root_dir),
        kind=ActionKind.TOOL,
    )
    executor.register_handler(
        "read_file",
        _simulate_workspace_read,
        kind=ActionKind.TOOL,
    )
    executor.register_handler(
        "send_email",
        _simulate_approved_email,
        kind=ActionKind.TOOL,
    )
    executor.register_handler(
        "restart_service",
        _simulate_approved_restart,
        kind=ActionKind.TOOL,
    )


async def _simulate_approved_email(action: Action) -> dict[str, object]:
    """Validate an approved email action without sending external mail."""
    validate_send_email(action.payload)
    return {
        "status": "sent-after-approval",
        "simulation": True,
        "recipient": action.payload["recipient"],
        "note": "No external email was sent.",
    }


async def _simulate_approved_restart(action: Action) -> dict[str, object]:
    """Validate an approved restart action without mutating a real service."""
    validate_restart_service(action.payload)
    return {
        "status": "approved",
        "simulation": True,
        "service": action.payload["service_name"],
        "note": "No real service was restarted.",
    }


async def _simulate_workspace_read(action: Action) -> dict[str, object]:
    """Return a deterministic read-only workspace preview without host access."""
    target = str(
        action.payload.get("target_resource")
        or action.payload.get("path")
        or "workspace"
    )
    if target.replace("\\", "/").startswith("/") and ".." in target.split("/"):
        raise ValueError("workspace path traversal is not allowed")
    return {
        "status": "completed",
        "path": target,
        "simulation": True,
        "note": "No host file was read.",
    }
