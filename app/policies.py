"""L1/L2 Policies Management Router for Aegis.

Implements:
- L1 Deterministic Structural Rules (Regex, AST, Path patterns, Mass delete thresholds).
- L2 Semantic Rules (Intent embedding matching, Prompt injection heuristics, Exfiltration).
- Dynamic rule search, filter tabs, active/inactive toggling, and rule simulation tester.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
templates = Jinja2Templates(directory=TEMPLATES_DIR)

router = APIRouter(tags=["L1/L2 Policies"])

# ==============================================================================
# POLICIES REPOSITORY (L1 Structural & L2 Semantic Rules)
# ==============================================================================

POLICIES_STORE: List[Dict[str, Any]] = [
    {
        "id": "SEC-FS-04",
        "tier": "L1",
        "name": "Mass Destructive File Deletion",
        "category": "Filesystem",
        "action": "escalate",
        "verdict_label": "ESCALATE (HITL)",
        "risk": "Critical",
        "description": "Destructive mass deletion threshold exceeded (>3 files in root or working directory). Requires explicit operator approval.",
        "target_pattern": "/workspace/tmp/**",
        "engine": "Structural Path & Count Matcher",
        "rule_text": "DENY_AUTO if file_count > 3 and operation == 'FILE_BATCH_DELETE'; ESCALATE to human reviewer.",
        "version": "v2.4",
        "active": True,
        "author": "Raghav (Policy Lead)",
        "updated_at": "2026-10-10T14:20:00Z",
        "triggered_count": 14,
    },
    {
        "id": "SEC-HOST-00",
        "tier": "L1",
        "name": "Root System Integrity Violation",
        "category": "Host Security",
        "action": "deny",
        "verdict_label": "DENY (Terminal)",
        "risk": "Critical",
        "description": "Direct mutation of host system security files (/etc/shadow, /etc/passwd, /boot, systemd) is strictly prohibited. Terminal verdict; no human override.",
        "target_pattern": "/etc/**, /boot/**, /sys/**",
        "engine": "POSIX Invariant Sandbox Gate",
        "rule_text": "DENY unconditionally on path match. Terminal Lock 5.",
        "version": "v1.0",
        "active": True,
        "author": "Raghav (Policy Lead)",
        "updated_at": "2026-10-08T09:00:00Z",
        "triggered_count": 3,
    },
    {
        "id": "SEC-DB-02",
        "tier": "L1",
        "name": "Production Database DDL Alteration",
        "category": "Database",
        "action": "escalate",
        "verdict_label": "ESCALATE (HITL)",
        "risk": "High",
        "description": "Production table ALTER, DROP, or TRUNCATE statements require staging dry-run validation and dual operator sign-off.",
        "target_pattern": "db.prod.*",
        "engine": "SQL DDL AST Parser",
        "rule_text": "MATCH sql.statement IN ('ALTER', 'DROP', 'TRUNCATE') -> ESCALATE with dry_run_check requirement.",
        "version": "v3.1",
        "active": True,
        "author": "Raghav (Policy Lead)",
        "updated_at": "2026-10-11T16:45:00Z",
        "triggered_count": 8,
    },
    {
        "id": "SEC-DEP-01",
        "tier": "L1",
        "name": "Unapproved Package Manifest Dependency",
        "category": "Supply Chain",
        "action": "escalate",
        "verdict_label": "ESCALATE (HITL)",
        "risk": "Medium",
        "description": "Python or Node package installations not present on the enterprise security allowlist must undergo static vulnerability scanning.",
        "target_pattern": "requirements.txt, package.json, pyproject.toml",
        "engine": "Package Whitelist Inspector",
        "rule_text": "IF requested_package NOT IN corporate_whitelist -> ESCALATE.",
        "version": "v1.8",
        "active": True,
        "author": "Raghav (Policy Lead)",
        "updated_at": "2026-10-09T11:15:00Z",
        "triggered_count": 22,
    },
    {
        "id": "SEC-NET-03",
        "tier": "L1",
        "name": "External VPC Egress Guard",
        "category": "Network",
        "action": "escalate",
        "verdict_label": "ESCALATE (HITL)",
        "risk": "Medium",
        "description": "Outbound socket connections outside the configured VPC boundary or approved telemetry endpoints require explicit authorization.",
        "target_pattern": "*:443, *:80 (External Non-VPC)",
        "engine": "CIDR & DNS Filter Port",
        "rule_text": "CHECK destination_ip AGAINST allowed_cidrs; ESCALATE if unlisted public IP.",
        "version": "v2.0",
        "active": True,
        "author": "Raghav (Policy Lead)",
        "updated_at": "2026-10-10T18:00:00Z",
        "triggered_count": 19,
    },
    {
        "id": "SEC-FS-01",
        "tier": "L1",
        "name": "Sandbox Workspace Read Permitted",
        "category": "Filesystem",
        "action": "allow",
        "verdict_label": "ALLOW",
        "risk": "Low",
        "description": "Read-only access to files located strictly within the agent's designated workspace subtree is permitted automatically.",
        "target_pattern": "/workspace/** (Read Only)",
        "engine": "Filesystem Subtree Sandbox",
        "rule_text": "IF operation == 'FILE_READ' and path.startswith('/workspace') -> ALLOW.",
        "version": "v1.2",
        "active": True,
        "author": "Raghav (Policy Lead)",
        "updated_at": "2026-10-07T12:00:00Z",
        "triggered_count": 184,
    },
    # L2 Semantic / Vector Embedding Policies
    {
        "id": "SEM-PROMPT-01",
        "tier": "L2",
        "name": "Prompt Injection & Jailbreak Heuristic",
        "category": "Semantic Guard",
        "action": "deny",
        "verdict_label": "DENY (Terminal)",
        "risk": "Critical",
        "description": "Evaluates agent system instructions and tool arguments against vector similarity index of known adversarial jailbreak patterns (cosine sim > 0.88).",
        "target_pattern": "LLM Messages & Tool Prompt Args",
        "engine": "pgvector 1536d Cosine Embeddings",
        "rule_text": "SIMILARITY(embedding(payload), jailbreak_cluster) > 0.88 -> DENY.",
        "version": "v2.1",
        "active": True,
        "author": "Raghav (Policy Lead)",
        "updated_at": "2026-10-11T20:10:00Z",
        "triggered_count": 6,
    },
    {
        "id": "SEM-DATA-02",
        "tier": "L2",
        "name": "PII & Secret Exfiltration Filter",
        "category": "Data Loss Prevention",
        "action": "escalate",
        "verdict_label": "ESCALATE (HITL)",
        "risk": "High",
        "description": "Detects high-entropy strings, private API keys, credit cards, and credential patterns before network or filesystem write dispatch.",
        "target_pattern": "Outbound Payload Payloads",
        "engine": "Shannon Entropy + Named Entity Regex",
        "rule_text": "IF entropy(text) > 4.5 or regex_match(api_key_patterns) -> ESCALATE with masked redaction.",
        "version": "v3.0",
        "active": True,
        "author": "Raghav (Policy Lead)",
        "updated_at": "2026-10-12T08:30:00Z",
        "triggered_count": 11,
    },
]


@router.get("/policies", response_class=HTMLResponse)
async def get_policies_page(
    request: Request,
    tier: Optional[str] = Query("all", description="Tier filter: all, L1, L2"),
    action: Optional[str] = Query("all", description="Action filter: all, deny, escalate, allow"),
    q: Optional[str] = Query(None, description="Search query"),
):
    """Render L1/L2 Policies governance console."""
    filtered = list(POLICIES_STORE)

    if tier and tier.lower() != "all":
        filtered = [p for p in filtered if p["tier"].lower() == tier.lower()]

    if action and action.lower() != "all":
        filtered = [p for p in filtered if p["action"].lower() == action.lower()]

    if q:
        query = q.strip().lower()
        filtered = [
            p for p in filtered
            if query in p["id"].lower()
            or query in p["name"].lower()
            or query in p["description"].lower()
            or query in p["target_pattern"].lower()
        ]

    metrics = {
        "total": len(POLICIES_STORE),
        "l1_count": sum(p["tier"] == "L1" for p in POLICIES_STORE),
        "l2_count": sum(p["tier"] == "L2" for p in POLICIES_STORE),
        "deny_count": sum(p["action"] == "deny" for p in POLICIES_STORE),
        "escalate_count": sum(p["action"] == "escalate" for p in POLICIES_STORE),
        "active_count": sum(p["active"] for p in POLICIES_STORE),
    }

    context = {
        "request": request,
        "active_page": "policies",
        "policies": filtered,
        "metrics": metrics,
        "selected_tier": tier or "all",
        "selected_action": action or "all",
        "q": q or "",
        "demo_mode": True,
    }

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request=request,
            name="components/policies_table_fragment.html",
            context=context,
        )

    return templates.TemplateResponse(
        request=request,
        name="policies.html",
        context=context,
    )


@router.post("/policies/{policy_id}/toggle", response_class=HTMLResponse)
async def toggle_policy_status(request: Request, policy_id: str):
    """Toggle a policy's active state via HTMX."""
    policy = next((p for p in POLICIES_STORE if p["id"] == policy_id), None)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    policy["active"] = not policy["active"]
    return templates.TemplateResponse(
        request=request,
        name="components/policy_status_badge.html",
        context={"policy": policy},
    )
