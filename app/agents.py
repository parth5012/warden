"""AI Agents page for the Aegis dashboard.

This route intentionally uses illustrative demo data until the agent registry
is connected to the team's runtime/policy services.
"""
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")
router = APIRouter(tags=["dashboard-pages"])

# Demo-only inventory. Replace this list with the team's real agent registry
# when that integration is available.
DEMO_AGENTS = [
    {
        "id": "agent-code-01",
        "name": "CodeAgent",
        "model": "Claude 3.5 Sonnet",
        "status": "Executing",
        "risk_tier": "High",
        "risk": "High",
        "task": "Workspace maintenance",
        "permissions": ["Workspace read", "Temporary-file write"],
        "last_seen": "2 min ago",
        "actions_today": 18,
        "policy": "SEC-FS-04",
        "description": "Handles code and workspace operations within the assigned sandbox.",
    },
    {
        "id": "agent-db-02",
        "name": "DBAgent",
        "model": "GPT-4o",
        "status": "Needs review",
        "risk_tier": "Critical",
        "risk": "Critical",
        "task": "Proposed production schema migration",
        "permissions": ["Read schema", "Propose DDL"],
        "last_seen": "12 min ago",
        "actions_today": 7,
        "policy": "SEC-DB-02",
        "description": "Prepares database operations; production changes require elevated review.",
    },
    {
        "id": "agent-dev-03",
        "name": "DevAgent",
        "model": "Claude 3 Haiku",
        "status": "Idle",
        "risk_tier": "Medium",
        "risk": "Medium",
        "task": "Dependency review",
        "permissions": ["Read manifests", "Propose package installs"],
        "last_seen": "28 min ago",
        "actions_today": 11,
        "policy": "SEC-DEP-01",
        "description": "Assists with development dependencies and environment configuration.",
    },
    {
        "id": "agent-ops-04",
        "name": "OpsAgent",
        "model": "Llama 3 70B",
        "status": "Restricted",
        "risk_tier": "Medium",
        "risk": "Medium",
        "task": "External telemetry endpoint request",
        "permissions": ["Read telemetry config", "Propose network egress"],
        "last_seen": "1 hour ago",
        "actions_today": 5,
        "policy": "SEC-NET-03",
        "description": "Supports operations and telemetry under network egress policy controls.",
    },
]


@router.get("/agents", name="agents")
async def agents_page(request: Request):
    active_count = sum(agent["status"] == "Executing" for agent in DEMO_AGENTS)
    review_count = sum(agent["status"] == "Needs review" for agent in DEMO_AGENTS)
    restricted_count = sum(agent["status"] == "Restricted" for agent in DEMO_AGENTS)
    stats = {
        "total": len(DEMO_AGENTS),
        "executing": active_count,
        "review": review_count,
        "restricted": restricted_count,
    }
    agent_stats = {
        "total": len(DEMO_AGENTS),
        "active": active_count,
        "review": review_count,
        "restricted": restricted_count,
    }
    return templates.TemplateResponse(
        request=request,
        name="agents.html",
        context={
            "active_page": "agents",
            "demo_mode": True,
            "agents": DEMO_AGENTS,
            "stats": stats,
            "agent_stats": agent_stats,
        },
    )
    
