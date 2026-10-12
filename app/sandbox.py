"""Sandbox Runs Management Router for Aegis.

Implements:
- SandboxPort execution telemetry (cgroups v2, docker, in-process adapters).
- Resource utilization metrics (CPU time, peak memory, timeout tracking).
- Environment secret scrubbing validation.
- Tactical terminal log viewer for stdout/stderr inspection.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
templates = Jinja2Templates(directory=TEMPLATES_DIR)

router = APIRouter(tags=["Sandbox Runs"])

# ==============================================================================
# SANDBOX RUNS DATA STORE (SandboxPort Execution Records)
# ==============================================================================

SANDBOX_RUNS_STORE: List[Dict[str, Any]] = [
    {
        "id": "sb_run_941a",
        "action_id": "act_8812c4",
        "agent": "DBAgent",
        "tool_name": "sql_query",
        "adapter": "Docker Container (Isolated Read-Replica)",
        "adapter_short": "docker_isolated",
        "command": "SELECT relname, n_live_tup FROM pg_stat_user_tables WHERE schemaname = 'public' ORDER BY n_live_tup DESC LIMIT 10;",
        "exit_code": 0,
        "status": "SUCCESS",
        "duration_ms": 890,
        "cpu_ms": 142,
        "peak_memory_mb": 42.6,
        "scrubbed_secrets_count": 2,
        "scrubbed_secrets": ["PGPASSWORD", "DB_CONNECTION_STRING"],
        "executed_at": (datetime.now(timezone.utc) - timedelta(minutes=23)).isoformat(),
        "stdout": (
            "+----------------------------+------------+\n"
            "| relname                    | n_live_tup |\n"
            "+----------------------------+------------+\n"
            "| billing_ledger_2026_q4     |    4521000 |\n"
            "| customer_accounts          |     891200 |\n"
            "| audit_journal_events       |     112450 |\n"
            "| auth_session_tokens        |      45120 |\n"
            "| telemetry_points           |      21890 |\n"
            "+----------------------------+------------+\n"
            "(5 rows returned in 890ms)\n"
            "[AEGIS-SANDBOX] Execution sealed. Container destroyed cleanly."
        ),
        "stderr": "",
    },
    {
        "id": "sb_run_829c",
        "action_id": "act_7021e1",
        "agent": "OpsAssistant",
        "tool_name": "run_shell",
        "adapter": "Subprocess (cgroups v2 restricted)",
        "adapter_short": "cgroups_v2",
        "command": "df -h /workspace /var/log",
        "exit_code": 0,
        "status": "SUCCESS",
        "duration_ms": 220,
        "cpu_ms": 45,
        "peak_memory_mb": 14.2,
        "scrubbed_secrets_count": 4,
        "scrubbed_secrets": ["AWS_SECRET_ACCESS_KEY", "SLACK_WEBHOOK_URL", "WARDEN_KEY", "JWT_SECRET"],
        "executed_at": (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat(),
        "stdout": (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/nvme0n1p2  120G   42G   73G  37% /workspace\n"
            "/dev/nvme0n1p3   50G   18G   30G  38% /var/log\n"
            "[AEGIS-SANDBOX] Cgroup limits enforced: max_memory=256MB, cpu_quota=50000/100000"
        ),
        "stderr": "",
    },
    {
        "id": "sb_run_704b",
        "action_id": "act_6104f2",
        "agent": "CodeAgent",
        "tool_name": "run_code",
        "adapter": "Subprocess (cgroups v2 restricted)",
        "adapter_short": "cgroups_v2",
        "command": "python -c 'import urllib.request; urllib.request.urlopen(\"http://169.254.169.254/latest/meta-data/\")'",
        "exit_code": 1,
        "status": "FAILED",
        "duration_ms": 110,
        "cpu_ms": 32,
        "peak_memory_mb": 18.5,
        "scrubbed_secrets_count": 3,
        "scrubbed_secrets": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"],
        "executed_at": (datetime.now(timezone.utc) - timedelta(minutes=45)).isoformat(),
        "stdout": "",
        "stderr": (
            "Traceback (most recent call last):\n"
            "  File \"<string>\", line 1, in <module>\n"
            "  File \"urllib/request.py\", line 215, in urlopen\n"
            "urllib.error.URLError: <urlopen error [Errno 101] Network unreachable: 169.254.169.254>\n"
            "[AEGIS-SANDBOX] Network egress filter BLOCKED cloud metadata endpoint IP (169.254.169.254)."
        ),
    },
    {
        "id": "sb_run_611e",
        "action_id": "act_5521a0",
        "agent": "KubeAgent",
        "tool_name": "write_file",
        "adapter": "In-Process Safe FS Adapter",
        "adapter_short": "in_process",
        "command": "write_file('/workspace/src/generated_manifest.yaml', content_len=1420)",
        "exit_code": 0,
        "status": "SUCCESS",
        "duration_ms": 48,
        "cpu_ms": 12,
        "peak_memory_mb": 8.1,
        "scrubbed_secrets_count": 1,
        "scrubbed_secrets": ["KUBECONFIG_TOKEN"],
        "executed_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        "stdout": "[AEGIS-SANDBOX] Wrote 1,420 bytes to /workspace/src/generated_manifest.yaml safely with POSIX permissions 0640.",
        "stderr": "",
    },
]


@router.get("/sandbox", response_class=HTMLResponse)
async def get_sandbox_page(
    request: Request,
    status: Optional[str] = Query("all", description="Status filter: all, SUCCESS, FAILED, TIMEOUT"),
    tool: Optional[str] = Query("all", description="Tool filter: all, sql_query, run_shell, run_code, write_file"),
    q: Optional[str] = Query(None, description="Search query"),
):
    """Render Sandbox Runs execution console."""
    filtered = list(SANDBOX_RUNS_STORE)

    if status and status.lower() != "all":
        filtered = [r for r in filtered if r["status"].lower() == status.lower()]

    if tool and tool.lower() != "all":
        filtered = [r for r in filtered if r["tool_name"].lower() == tool.lower()]

    if q:
        query = q.strip().lower()
        filtered = [
            r for r in filtered
            if query in r["id"].lower()
            or query in r["agent"].lower()
            or query in r["tool_name"].lower()
            or query in r["command"].lower()
            or query in r["adapter"].lower()
        ]

    metrics = {
        "total_runs": len(SANDBOX_RUNS_STORE),
        "success_count": sum(r["status"] == "SUCCESS" for r in SANDBOX_RUNS_STORE),
        "failed_count": sum(r["status"] == "FAILED" for r in SANDBOX_RUNS_STORE),
        "total_secrets_scrubbed": sum(r["scrubbed_secrets_count"] for r in SANDBOX_RUNS_STORE),
        "avg_duration": int(sum(r["duration_ms"] for r in SANDBOX_RUNS_STORE) / max(1, len(SANDBOX_RUNS_STORE))),
        "peak_memory_max": max(r["peak_memory_mb"] for r in SANDBOX_RUNS_STORE),
    }

    context = {
        "request": request,
        "active_page": "sandbox",
        "runs": filtered,
        "metrics": metrics,
        "selected_status": status or "all",
        "selected_tool": tool or "all",
        "q": q or "",
        "demo_mode": True,
    }

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request=request,
            name="components/sandbox_table_fragment.html",
            context=context,
        )

    return templates.TemplateResponse(
        request=request,
        name="sandbox.html",
        context=context,
    )


@router.get("/sandbox/{run_id}/logs", response_class=HTMLResponse)
async def get_sandbox_logs(request: Request, run_id: str):
    """Return tactical terminal drawer with stdout/stderr logs."""
    run = next((r for r in SANDBOX_RUNS_STORE if r["id"] == run_id), None)
    if not run:
        raise HTTPException(status_code=404, detail="Sandbox run not found")

    return templates.TemplateResponse(
        request=request,
        name="components/sandbox_log_drawer.html",
        context={"request": request, "run": run},
    )
