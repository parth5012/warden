"""Tool registration for GuardedExecutor in Warden.

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

from warden.models import ActionKind
from warden.tools.database import exec_db_mutation, query_db_readonly
from warden.tools.filesystem import read_file_sensitive
from warden.tools.logs import read_service_logs
from warden.tools.metrics import get_system_metrics

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
