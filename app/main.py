import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, Any, List

# Ensure src/ is in sys.path so 'warden.*' imports resolve in all runtimes
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from app.agents import router as agents_router
from app.audit import router as audit_router
from app.policies import router as policies_router
from app.leases import router as leases_router
from app.traces import router as traces_router
from app.sandbox import router as sandbox_router
from app.chat import router as chat_router
from backend.api.auth import router as auth_router

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="Warden AI Governance Console", version="2.0.0")
app.include_router(agents_router)
app.include_router(chat_router)
app.include_router(audit_router)
app.include_router(policies_router)
app.include_router(leases_router)
app.include_router(traces_router)
app.include_router(sandbox_router)
app.include_router(auth_router, prefix="/api")
app.include_router(auth_router)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)


# ==============================================================================
# CANONICAL HASHING ENGINE (Security Contract)
# ==============================================================================
def canonical_action_bytes(action: Dict[str, Any]) -> bytes:
    """Serializes action descriptor to canonical sorted JSON bytes."""
    return json.dumps(
        action,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def calculate_action_hash(action: Dict[str, Any]) -> str:
    """Computes SHA-256 digest of canonical action bytes."""
    return hashlib.sha256(canonical_action_bytes(action)).hexdigest()


# ==============================================================================
# TACTICAL MOCK ACTIONS DATA STORE WITH MULTI-RESOURCE DIFFS
# ==============================================================================
RAW_ACTIONS: List[Dict[str, Any]] = [
    {
        "id": "act_7129e3",
        "version": 1,
        "title": "Batch delete temporary workspace files",
        "agent": "CodeAgent",
        "agent_model": "claude-3-5-sonnet",
        "operation": "FILE_BATCH_DELETE",
        "target_resource": "/workspace/tmp/",
        "files_count": 5,
        "diff_summary": "-5 files (-48.3 MB)",
        "risk": "Critical",
        "status": "Escalated",
        "time_ago": "2 min ago",
        "policy_id": "SEC-FS-04",
        "policy_reason": "Destructive mass deletion threshold exceeded (>3 files in root directory)",
        "requested_by": "agent-01 (autonomous loop #419)",
        "impact_vectors": {
            "filesystem": "Critical (-48.3 MB reclaimed)",
            "database": "None",
            "network": "None",
            "privilege": "Standard Sandbox",
        },
        "affected_files": [
            {
                "path": "tmp/logs/debug.log",
                "type": "Text / Log",
                "size": "2.4 MB",
                "diff_badge": "-2.4 MB",
                "diff_type": "text",
                "lines_deleted": 128,
                "lines_added": 0,
                "preview_content": [
                    {"type": "del", "num": 1, "text": "2024-01-15 10:23:45 DEBUG Starting autonomous loop runner"},
                    {"type": "del", "num": 2, "text": "2024-01-15 10:23:46 DEBUG Connecting to memory cache socket"},
                    {"type": "del", "num": 3, "text": "2024-01-15 10:23:50 INFO Cache sync complete (PID 4012)"},
                    {"type": "del", "num": 4, "text": "2024-01-15 10:24:01 DEBUG Storing serialized checkpoint v4"},
                    {"type": "del", "num": 5, "text": "2024-01-15 10:24:05 INFO Syncing filesystem buffer to disk"},
                ],
            },
            {
                "path": "tmp/cache.db",
                "type": "SQLite DB / Cache",
                "size": "48.3 MB",
                "diff_badge": "-48.3 MB",
                "diff_type": "binary",
                "lines_deleted": 0,
                "lines_added": 0,
                "binary_warning": "Binary SQLite database containing 142,500 cached embeddings and intermediate agent vector states. Irreversible on delete.",
            },
            {
                "path": "tmp/temp_data.csv",
                "type": "CSV Dataset",
                "size": "1.1 MB",
                "diff_badge": "-1.1 MB",
                "diff_type": "text",
                "lines_deleted": 4500,
                "lines_added": 0,
                "preview_content": [
                    {"type": "del", "num": 1, "text": "id,timestamp,embedding_cluster,score"},
                    {"type": "del", "num": 2, "text": "1001,2024-01-15T10:15:22,cluster_alpha,0.982"},
                    {"type": "del", "num": 3, "text": "1002,2024-01-15T10:15:24,cluster_beta,0.741"},
                    {"type": "del", "num": 4, "text": "1003,2024-01-15T10:15:28,cluster_gamma,0.884"},
                ],
            },
            {
                "path": "tmp/old_model.pkl",
                "type": "Pickle Binary",
                "size": "12.1 MB",
                "diff_badge": "-12.1 MB",
                "diff_type": "binary",
                "binary_warning": "Serialized PyTorch model weights checkpoint. Verify no active inference thread is reading this path.",
            },
            {
                "path": "tmp/output.json",
                "type": "JSON Result",
                "size": "53 KB",
                "diff_badge": "-53 KB",
                "diff_type": "text",
                "lines_deleted": 340,
                "lines_added": 0,
                "preview_content": [
                    {"type": "del", "num": 1, "text": "{\n  \"status\": \"completed\",\n  \"session_id\": \"sess_9801\","},
                    {"type": "del", "num": 2, "text": "  \"artifacts\": [\"model_eval.png\", \"metrics.parquet\"],"},
                    {"type": "del", "num": 3, "text": "  \"execution_time_seconds\": 42.1\n}"},
                ],
            },
        ],
    },
    {
        "id": "act_8491c2",
        "version": 1,
        "title": "Alter production database schema",
        "agent": "DBAgent",
        "agent_model": "gpt-4o",
        "operation": "SQL_SCHEMA_MIGRATION",
        "target_resource": "db.prod.users",
        "files_count": 1,
        "diff_summary": "+12 -4 lines",
        "risk": "High",
        "status": "Escalated",
        "time_ago": "12 min ago",
        "policy_id": "SEC-DB-02",
        "policy_reason": "Production table ALTER without prior staging dry-run approval",
        "requested_by": "db-optimizer (agent run #104)",
        "impact_vectors": {
            "filesystem": "None",
            "database": "High (Locks table 'users')",
            "network": "None",
            "privilege": "Database DDL Admin",
        },
        "affected_files": [
            {
                "path": "migrations/20240115_add_login_ip.sql",
                "type": "SQL Migration",
                "size": "1.2 KB",
                "diff_badge": "+12 -4",
                "diff_type": "text",
                "lines_deleted": 4,
                "lines_added": 12,
                "preview_content": [
                    {"type": "del", "num": 14, "text": "-- Deprecated old session column tracking"},
                    {"type": "del", "num": 15, "text": "ALTER TABLE users DROP COLUMN IF EXISTS legacy_session_key;"},
                    {"type": "add", "num": 16, "text": "ALTER TABLE users ADD COLUMN last_login_ip VARCHAR(45);"},
                    {"type": "add", "num": 17, "text": "CREATE INDEX idx_users_login_ip ON users(last_login_ip);"},
                ],
            }
        ],
    },
    {
        "id": "act_3920e8",
        "version": 1,
        "title": "Install unapproved Python package",
        "agent": "DevAgent",
        "agent_model": "claude-3-haiku",
        "operation": "PACKAGE_INSTALL",
        "target_resource": "requirements.txt",
        "files_count": 1,
        "diff_summary": "+1 dependency",
        "risk": "Medium",
        "status": "Pending",
        "time_ago": "28 min ago",
        "policy_id": "SEC-DEP-01",
        "policy_reason": "Requested package 'pandas-profiling==3.6.6' is not on the corporate approved security whitelist",
        "requested_by": "dev-assistant (agent run #88)",
        "impact_vectors": {
            "filesystem": "Low (Virtualenv modification)",
            "database": "None",
            "network": "PyPI index egress",
            "privilege": "Package manager sandbox",
        },
        "affected_files": [
            {
                "path": "requirements.txt",
                "type": "Dependency Manifest",
                "size": "840 B",
                "diff_badge": "+1 line",
                "diff_type": "text",
                "lines_deleted": 0,
                "lines_added": 1,
                "preview_content": [
                    {"type": "same", "num": 18, "text": "numpy>=1.26.0"},
                    {"type": "same", "num": 19, "text": "pandas>=2.1.0"},
                    {"type": "add", "num": 20, "text": "+ pandas-profiling==3.6.6"},
                ],
            }
        ],
    },
    {
        "id": "act_5510f4",
        "version": 1,
        "title": "Outbound HTTP egress to external metrics endpoint",
        "agent": "OpsAgent",
        "agent_model": "llama-3-70b",
        "operation": "NETWORK_EGRESS",
        "target_resource": "api.datadoghq.com:443",
        "files_count": 1,
        "diff_summary": "1 endpoint egress",
        "risk": "Medium",
        "status": "Pending",
        "time_ago": "1 hour ago",
        "policy_id": "SEC-NET-03",
        "policy_reason": "Unregistered egress destination outside VPC security boundary",
        "requested_by": "ops-telemetry-collector",
        "impact_vectors": {
            "filesystem": "None",
            "database": "None",
            "network": "Medium (Outbound HTTPS socket)",
            "privilege": "Socket Egress",
        },
        "affected_files": [
            {
                "path": "config/telemetry_endpoints.json",
                "type": "JSON Config",
                "size": "420 B",
                "diff_badge": "+1 endpoint",
                "diff_type": "text",
                "lines_deleted": 0,
                "lines_added": 3,
                "preview_content": [
                    {"type": "same", "num": 8, "text": "  \"primary_collector\": \"internal.telemetry.local\","},
                    {"type": "add", "num": 9, "text": "  \"external_mirror\": \"https://api.datadoghq.com/v1/series\","},
                    {"type": "add", "num": 10, "text": "  \"api_key_env\": \"DD_API_KEY\""},
                ],
            }
        ],
    },
]

ACTIONS_STORE: Dict[str, Dict[str, Any]] = {}
for act in RAW_ACTIONS:
    act_enriched = dict(act)
    act_enriched["hash"] = calculate_action_hash(act)
    ACTIONS_STORE[act["id"]] = act_enriched


RECENT_AUDIT_ACTIONS = [
    {"title": "Read configuration (.env)", "agent": "CodeAgent", "status": "Allowed", "risk": "Low", "time_ago": "1 min ago", "hash": "a1b2c3d4"},
    {"title": "List workspace files", "agent": "OpsAgent", "status": "Allowed", "risk": "Low", "time_ago": "4 min ago", "hash": "e5f6a7b8"},
    {"title": "Unlink /etc/shadow attempt", "agent": "RogueAgent", "status": "Denied", "risk": "Critical", "time_ago": "12 min ago", "hash": "9c8b7a6f"},
    {"title": "Query database (read-only)", "agent": "DBAgent", "status": "Allowed", "risk": "Low", "time_ago": "18 min ago", "hash": "3d2e1f0a"},
    {"title": "Run embedding calculation", "agent": "ResearchAgent", "status": "Allowed", "risk": "Medium", "time_ago": "25 min ago", "hash": "5b4c3d2e"},
]

ACTIVITY_BARS = [
    {"time": "12AM", "allowed": 4, "escalated": 1, "denied": 0, "total": 5},
    {"time": "3AM",  "allowed": 2, "escalated": 0, "denied": 1, "total": 3},
    {"time": "6AM",  "allowed": 6, "escalated": 2, "denied": 0, "total": 8},
    {"time": "9AM",  "allowed": 10, "escalated": 3, "denied": 1, "total": 14},
    {"time": "12PM", "allowed": 15, "escalated": 4, "denied": 2, "total": 21},
    {"time": "3PM",  "allowed": 12, "escalated": 4, "denied": 2, "total": 18},
    {"time": "6PM",  "allowed": 8, "escalated": 2, "denied": 1, "total": 11},
    {"time": "9PM",  "allowed": 5, "escalated": 1, "denied": 0, "total": 6},
]


# ==============================================================================
# ROUTE HANDLERS
# ==============================================================================
def build_dashboard_context(request: Request, active_page: str):
    """Build dashboard projections from the single illustrative demo dataset.

    Proposed actions and recent audit records are both included in the overview,
    so the headline count and risk distribution share the same nine-record scope.
    Replace these in-memory projections with event-store/database queries when
    the team's integrations are connected.
    """
    actions = list(ACTIONS_STORE.values())
    recent = list(RECENT_AUDIT_ACTIONS)
    review_actions = [
        action for action in actions
        if action.get("status", "").lower() in {"pending", "escalated"}
    ]

    dashboard_records = actions + recent
    status_counts = {
        "allowed": sum(item.get("status", "").lower() in {"allowed", "approved"} for item in dashboard_records),
        "escalated": sum(item.get("status", "").lower() == "escalated" for item in dashboard_records),
        "denied": sum(item.get("status", "").lower() == "denied" for item in dashboard_records),
    }
    risk_order = ["Low", "Medium", "High", "Critical"]
    risk_colors = {
        "Low": "var(--color-cyan)",
        "Medium": "var(--color-amber)",
        "High": "#F97316",
        "Critical": "var(--color-ruby)",
    }
    risk_counts = {risk: sum(item.get("risk", "").title() == risk for item in dashboard_records) for risk in risk_order}
    record_total = len(dashboard_records)
    risk_distribution = []
    offset = 0.0
    for risk in risk_order:
        count = risk_counts[risk]
        percentage = round((count / record_total) * 100, 1) if record_total else 0
        risk_distribution.append({
            "risk": risk,
            "count": count,
            "percentage": percentage,
            "dasharray": f"{percentage} {100 - percentage}",
            "dashoffset": round(-offset, 1),
            "color": risk_colors[risk],
        })
        offset += percentage

    return {
        "request": request,
        "active_page": active_page,
        "demo_mode": True,
        "stats": {
            "total": record_total,
            **status_counts,
            "escalated": status_counts["escalated"],
            "active_agents": len({action.get("agent") for action in actions}),
        },
        "activity_data": ACTIVITY_BARS,
        "risk_distribution": risk_distribution,
        "pending_actions": review_actions,
        "review_actions": review_actions,
        "pending_count": len(review_actions),
        "recent_actions": recent,
    }


@app.get("/")
def get_dashboard(request: Request):
    """Render the command center using the currently loaded demo records."""
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context=build_dashboard_context(request, "dashboard"),
    )


@app.get("/approvals")
def get_approvals(request: Request):
    """Render a dedicated approval triage queue."""
    return templates.TemplateResponse(
        request=request,
        name="approvals.html",
        context=build_dashboard_context(request, "approvals"),
    )


@app.get("/actions/{action_id}")
def get_blast_radius(request: Request, action_id: str):
    """Renders the comprehensive Blast Radius analysis for a specific action."""
    action = ACTIONS_STORE.get(action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    return templates.TemplateResponse(
        request=request,
        name="blast_radius.html",
        context={
            "active_page": "approvals",
            "action": action,
            "pending_count": len(ACTIONS_STORE),
        },
    )

