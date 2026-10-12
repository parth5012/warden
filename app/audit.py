"""Audit Log and Write-Ahead Journal (WAL) Engine for Aegis.

Implements the application-level append-only event journal per DATA_MODEL.md
and API_CONTRACT.md. Distinguishes:
1. PostgreSQL internal WAL (database engine crash recovery, 8KB page writes).
2. Aegis application-level append-only event journal (domain state transitions).
3. Transactional outbox (reliable handoff to execution workers).
4. Operator-facing audit dashboard (/audit).
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
templates = Jinja2Templates(directory=TEMPLATES_DIR)

router = APIRouter(tags=["WAL & Audit Log"])


# ==============================================================================
# 1. CANONICAL EVENT MODEL & HASHING (Imported from warden.journal kernel)
# ==============================================================================

from warden.journal import (
    AuditJournal,
    EventKind,
    InMemoryJournal,
    JournalEvent,
    VerificationStatus,
    calculate_event_hash,
    canonical_event_bytes,
    get_journal,
    verify_hash_chain,
)

__all__ = [
    "EventKind",
    "VerificationStatus",
    "JournalEvent",
    "canonical_event_bytes",
    "calculate_event_hash",
    "verify_hash_chain",
    "sanitize_csv_cell",
    "JournalRepository",
    "InMemoryDemoJournal",
    "JOURNAL_STORE",
    "router",
]


# ==============================================================================
# 3. CSV FORMULA INJECTION SANITIZER
# ==============================================================================

def sanitize_csv_cell(value: Any) -> str:
    """Prevents CSV formula injection (OWASP guideline).

    Cells beginning with '=', '+', '-', '@', tab, or carriage return
    are prefixed with a single quote to neutralize spreadsheet execution.
    """
    if value is None:
        return ""
    val_str = str(value)
    if val_str and val_str[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{val_str}"
    return val_str


# ==============================================================================
# 4. JOURNAL REPOSITORY INTERFACE & PERSISTENCE ADAPTER
# ==============================================================================

class JournalRepository:
    """Abstract journal storage interface supporting append-only events and query projections."""

    def is_persistent(self) -> bool:
        raise NotImplementedError

    def append(self, event: JournalEvent) -> JournalEvent:
        raise NotImplementedError

    def list_events(
        self,
        q: Optional[str] = None,
        kind: Optional[str] = None,
        action_id: Optional[str] = None,
        run_id: Optional[str] = None,
        actor: Optional[str] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        limit: int = 15,
        offset: int = 0,
    ) -> Tuple[List[JournalEvent], int]:
        raise NotImplementedError

    def get_event(self, event_id: str) -> Optional[JournalEvent]:
        raise NotImplementedError

    def get_related_events(self, action_id: Optional[str], run_id: Optional[str], exclude_id: str) -> List[JournalEvent]:
        raise NotImplementedError

    def get_summary_metrics(self) -> Dict[str, int]:
        raise NotImplementedError


class InMemoryDemoJournal(AuditJournal, JournalRepository):
    """Deterministic in-memory journal pre-seeded with representative demo events.

    Integrates seamlessly with the actions from Command Center and Interception Gate.
    """

    def __init__(self) -> None:
        self._events: List[JournalEvent] = []
        self._init_demo_dataset()

    def is_persistent(self) -> bool:
        return False

    def _init_demo_dataset(self) -> None:
        """Seeds demo events reflecting the full lifecycle of actions in Aegis."""
        raw_seed = [
            # Event 1: Startup checkpoint
            {
                "id": "ev_001_chk_boot",
                "run_id": "run_sys_boot",
                "thread_id": "thread_init_0",
                "action_id": None,
                "checkpoint_step": 0,
                "kind": EventKind.CHECKPOINT_CREATED.value,
                "actor": "System Kernel",
                "status": "System",
                "description": "Kernel initialized governance checkpoint v2.0",
                "payload": {"version": "2.0.0", "engine": "LangGraph+FastAPI", "active_nodes": 4},
                "ts": "2026-10-12T09:00:00Z",
            },
            # Event 2: Action proposed for batch file delete (act_7129e3)
            {
                "id": "ev_002_req_7129",
                "run_id": "run_agent_419",
                "thread_id": "thread_code_419",
                "action_id": "act_7129e3",
                "checkpoint_step": 1,
                "kind": EventKind.ACTION_REQUESTED.value,
                "actor": "CodeAgent",
                "status": "Proposed",
                "description": "Batch delete temporary workspace files (5 files, -48.3 MB)",
                "payload": {
                    "operation": "FILE_BATCH_DELETE",
                    "target_resource": "/workspace/tmp/",
                    "files_count": 5,
                    "target_files": ["tmp/logs/debug.log", "tmp/cache.db", "tmp/temp_data.csv", "tmp/old_model.pkl", "tmp/output.json"],
                    "model": "claude-3-5-sonnet",
                },
                "ts": "2026-10-12T09:12:10Z",
            },
            # Event 3: Policy evaluation for act_7129e3
            {
                "id": "ev_003_pol_7129",
                "run_id": "run_agent_419",
                "thread_id": "thread_code_419",
                "action_id": "act_7129e3",
                "checkpoint_step": 1,
                "kind": EventKind.POLICY_EVALUATED.value,
                "actor": "PolicyEngine",
                "status": "Escalated",
                "description": "Triggered Rule SEC-FS-04: Mass deletion threshold exceeded (>3 files in root)",
                "payload": {
                    "policy_id": "SEC-FS-04",
                    "verdict": "escalate",
                    "reason": "Destructive mass deletion threshold exceeded (>3 files in root directory)",
                    "risk": "Critical",
                },
                "ts": "2026-10-12T09:12:12Z",
            },
            # Event 4: Gate requested (HITL) for act_7129e3
            {
                "id": "ev_004_gate_7129",
                "run_id": "run_agent_419",
                "thread_id": "thread_code_419",
                "action_id": "act_7129e3",
                "checkpoint_step": 1,
                "kind": EventKind.GATE_REQUESTED.value,
                "actor": "GuardedExecutor",
                "status": "Pending",
                "description": "Human review gate parked for operator triage",
                "payload": {
                    "gate_id": "gate_7129_hitl",
                    "action_id": "act_7129e3",
                    "requires": "Operator signature with named approver key",
                    "timeout_seconds": 3600,
                },
                "ts": "2026-10-12T09:12:13Z",
            },
            # Event 5: Safe read action
            {
                "id": "ev_005_req_env",
                "run_id": "run_agent_420",
                "thread_id": "thread_code_420",
                "action_id": "act_read_env_01",
                "checkpoint_step": 1,
                "kind": EventKind.ACTION_REQUESTED.value,
                "actor": "CodeAgent",
                "status": "Proposed",
                "description": "Read configuration (.env) for environment inspection",
                "payload": {"operation": "FILE_READ", "target_resource": ".env"},
                "ts": "2026-10-12T09:15:00Z",
            },
            # Event 6: Safe read allowed
            {
                "id": "ev_006_pol_env",
                "run_id": "run_agent_420",
                "thread_id": "thread_code_420",
                "action_id": "act_read_env_01",
                "checkpoint_step": 1,
                "kind": EventKind.POLICY_EVALUATED.value,
                "actor": "PolicyEngine",
                "status": "Allowed",
                "description": "Rule SEC-FS-01: Read-only access within sandbox boundary granted",
                "payload": {"policy_id": "SEC-FS-01", "verdict": "allow"},
                "ts": "2026-10-12T09:15:01Z",
            },
            # Event 7: Safe read completed
            {
                "id": "ev_007_exec_env",
                "run_id": "run_agent_420",
                "thread_id": "thread_code_420",
                "action_id": "act_read_env_01",
                "checkpoint_step": 2,
                "kind": EventKind.ACTION_COMPLETED.value,
                "actor": "SandboxRunner",
                "status": "Succeeded",
                "description": "Executed read in isolated subprocess sandbox; returned 28 lines",
                "payload": {"bytes_read": 1420, "lines": 28, "duration_ms": 14},
                "ts": "2026-10-12T09:15:02Z",
            },
            # Event 8: Malicious attempt blocked
            {
                "id": "ev_008_req_shadow",
                "run_id": "run_rogue_99",
                "thread_id": "thread_rogue_99",
                "action_id": "act_unlink_shadow",
                "checkpoint_step": 1,
                "kind": EventKind.ACTION_REQUESTED.value,
                "actor": "RogueAgent",
                "status": "Proposed",
                "description": "Attempt to unlink sensitive host security file /etc/shadow",
                "payload": {"operation": "FILE_UNLINK", "target_resource": "/etc/shadow", "flags": "-rf"},
                "ts": "2026-10-12T09:20:00Z",
            },
            # Event 9: Deny is terminal (Lock 5)
            {
                "id": "ev_009_den_shadow",
                "run_id": "run_rogue_99",
                "thread_id": "thread_rogue_99",
                "action_id": "act_unlink_shadow",
                "checkpoint_step": 1,
                "kind": EventKind.ACTION_DENIED.value,
                "actor": "PolicyEngine",
                "status": "Denied",
                "description": "DENIED (Terminal): Root security file tampering prohibited by SEC-HOST-00",
                "payload": {
                    "policy_id": "SEC-HOST-00",
                    "verdict": "deny",
                    "reason": "Host integrity violation. Root file modification blocked unconditionally.",
                    "terminal": True,
                },
                "ts": "2026-10-12T09:20:01Z",
            },
            # Event 10: Database DDL proposed (act_8491c2)
            {
                "id": "ev_010_req_8491",
                "run_id": "run_agent_104",
                "thread_id": "thread_db_104",
                "action_id": "act_8491c2",
                "checkpoint_step": 1,
                "kind": EventKind.ACTION_REQUESTED.value,
                "actor": "DBAgent",
                "status": "Proposed",
                "description": "Alter production database schema (ALTER TABLE users ADD last_login_ip)",
                "payload": {
                    "operation": "SQL_SCHEMA_MIGRATION",
                    "target_resource": "db.prod.users",
                    "statement": "ALTER TABLE users ADD COLUMN last_login_ip VARCHAR(45);",
                    "model": "gpt-4o",
                },
                "ts": "2026-10-12T09:30:10Z",
            },
            # Event 11: Policy escalated for act_8491c2
            {
                "id": "ev_011_pol_8491",
                "run_id": "run_agent_104",
                "thread_id": "thread_db_104",
                "action_id": "act_8491c2",
                "checkpoint_step": 1,
                "kind": EventKind.POLICY_EVALUATED.value,
                "actor": "PolicyEngine",
                "status": "Escalated",
                "description": "Rule SEC-DB-02: Production table ALTER requires operator sign-off",
                "payload": {
                    "policy_id": "SEC-DB-02",
                    "verdict": "escalate",
                    "risk": "High",
                    "reason": "Production table ALTER without prior staging dry-run approval",
                },
                "ts": "2026-10-12T09:30:11Z",
            },
            # Event 12: Ephemeral Lease evaluation
            {
                "id": "ev_012_lse_eval",
                "run_id": "run_agent_104",
                "thread_id": "thread_db_104",
                "action_id": "act_8491c2",
                "checkpoint_step": 1,
                "kind": EventKind.LEASE_EVALUATED.value,
                "actor": "PolicyEngine",
                "status": "Evaluated",
                "description": "Lease #LSE-901 checked: insufficient scope for DDL operation",
                "payload": {
                    "lease_id": "LSE-901",
                    "granted_scopes": ["db:read", "db:select"],
                    "required_scope": "db:ddl_admin",
                    "verdict": "scope_insufficient",
                },
                "ts": "2026-10-12T09:30:12Z",
            },
            # Event 13: Unapproved package install proposed (act_3920e8)
            {
                "id": "ev_013_req_3920",
                "run_id": "run_agent_88",
                "thread_id": "thread_dev_88",
                "action_id": "act_3920e8",
                "checkpoint_step": 1,
                "kind": EventKind.ACTION_REQUESTED.value,
                "actor": "DevAgent",
                "status": "Proposed",
                "description": "Install unapproved Python package: pandas-profiling==3.6.6",
                "payload": {
                    "operation": "PACKAGE_INSTALL",
                    "target_resource": "requirements.txt",
                    "package": "pandas-profiling==3.6.6",
                    "model": "claude-3-haiku",
                },
                "ts": "2026-10-12T09:40:00Z",
            },
            # Event 14: Network egress proposed (act_5510f4)
            {
                "id": "ev_014_req_5510",
                "run_id": "run_agent_70",
                "thread_id": "thread_ops_70",
                "action_id": "act_5510f4",
                "checkpoint_step": 1,
                "kind": EventKind.ACTION_REQUESTED.value,
                "actor": "OpsAgent",
                "status": "Proposed",
                "description": "Outbound HTTP egress to external metrics endpoint api.datadoghq.com:443",
                "payload": {
                    "operation": "NETWORK_EGRESS",
                    "target_resource": "api.datadoghq.com:443",
                    "model": "llama-3-70b",
                },
                "ts": "2026-10-12T09:55:00Z",
            },
            # Event 15: Execution failure event
            {
                "id": "ev_015_fail_sync",
                "run_id": "run_agent_65",
                "thread_id": "thread_ops_65",
                "action_id": "act_sync_failed_01",
                "checkpoint_step": 3,
                "kind": EventKind.ACTION_FAILED.value,
                "actor": "SandboxRunner",
                "status": "Failed",
                "description": "Subprocess execution failed: connection reset by peer during sync",
                "payload": {
                    "exit_code": 111,
                    "error": "ECONNREFUSED: Connection refused to remote mirror socket",
                    "duration_ms": 1250,
                },
                "ts": "2026-10-12T10:10:00Z",
            },
            # Event 16: Email dispatched
            {
                "id": "ev_016_email_sent",
                "run_id": "run_agent_425",
                "thread_id": "test-run-thread-live",
                "action_id": "act_email_ops_01",
                "checkpoint_step": 2,
                "kind": EventKind.ACTION_COMPLETED.value,
                "actor": "ops_assistant",
                "status": "Allowed",
                "description": "Executed send_email for weekly operations report",
                "payload": {"action_name": "send_email", "status": "sent", "recipient": "team@example.com"},
                "ts": "2026-10-12T10:15:00Z",
            },
        ]

        # Build cryptographic hash chain
        prev_hash: Optional[str] = None
        for raw in raw_seed:
            ev_dict = dict(raw)
            ev_dict["prev_hash"] = prev_hash
            ev_hash = calculate_event_hash(ev_dict)
            ev_dict["event_hash"] = ev_hash
            # In demo mode, mark as "Verification unavailable" because the underlying
            # persistent PostgreSQL hash table from Yashit/Gourav is not yet connected.
            ev_dict["verification_status"] = VerificationStatus.UNAVAILABLE
            prev_hash = ev_hash

            event = JournalEvent(**ev_dict)
            self._events.append(event)

    @property
    def events(self) -> List[JournalEvent]:
        return list(self._events)

    def verify(self) -> Tuple[VerificationStatus, Optional[str]]:
        return verify_hash_chain(self._events)

    def append(  # type: ignore[override]
        self,
        kind: Any,
        *,
        run_id: str = "",
        thread_id: str = "",
        actor: str = "",
        action_id: Optional[str] = None,
        checkpoint_step: Optional[int] = None,
        status: str = "",
        description: str = "",
        payload: Optional[Dict[str, Any]] = None,
    ) -> JournalEvent:
        """Appends an event to the in-memory journal, computing the chain hash.
        Supports both append(event: JournalEvent) and AuditJournal.append(kind, run_id=..., ...).
        """
        if isinstance(kind, JournalEvent):
            event = kind
        else:
            kind_str = kind.value if isinstance(kind, EventKind) else str(kind)
            event = JournalEvent(
                id=f"ev_{uuid.uuid4().hex[:12]}",
                run_id=run_id,
                thread_id=thread_id,
                action_id=action_id,
                checkpoint_step=checkpoint_step,
                kind=kind_str,
                actor=actor,
                status=status,
                description=description,
                payload=payload or {},
                ts=datetime.now(timezone.utc).isoformat(),
            )

        prev = self._events[-1].event_hash if self._events else None
        ev_dict = event.to_dict()
        ev_dict["prev_hash"] = prev
        ev_hash = calculate_event_hash(ev_dict)
        ev_dict["event_hash"] = ev_hash
        ev_dict["verification_status"] = VerificationStatus.UNAVAILABLE
        new_event = JournalEvent(**ev_dict)
        self._events.append(new_event)

        try:
            gj = get_journal()
            if gj is not self and isinstance(gj, InMemoryJournal):
                with gj._lock:
                    if not any(e.id == new_event.id for e in gj._events):
                        gj._events.append(new_event)
        except Exception:
            pass

        return new_event

    def list_events(  # type: ignore[override]
        self,
        q: Optional[str] = None,
        kind: Optional[str] = None,
        action_id: Optional[str] = None,
        run_id: Optional[str] = None,
        actor: Optional[str] = None,
        date_from: Optional[Union[str, int]] = None,
        date_to: Optional[Union[str, int]] = None,
        limit: int = 15,
        offset: int = 0,
    ) -> Tuple[List[JournalEvent], int]:
        actual_date_from: Optional[str] = None
        actual_date_to: Optional[str] = None

        if isinstance(date_from, int):
            limit = date_from
            if isinstance(date_to, int):
                offset = date_to
        else:
            actual_date_from = date_from
            if isinstance(date_to, str):
                actual_date_to = date_to

        filtered = list(self._events)

        if q:
            query = q.lower()
            filtered = [
                e for e in filtered
                if (
                    query in e.id.lower()
                    or query in (e.action_id or "").lower()
                    or query in e.run_id.lower()
                    or query in e.actor.lower()
                    or query in e.description.lower()
                    or query in json.dumps(e.payload).lower()
                )
            ]

        if kind and kind.lower() != "all":
            filtered = [e for e in filtered if e.kind == kind]

        if action_id:
            aid = action_id.strip().lower()
            filtered = [e for e in filtered if e.action_id and aid in e.action_id.lower()]

        if run_id:
            rid = run_id.strip().lower()
            filtered = [e for e in filtered if rid in e.run_id.lower() or rid in e.thread_id.lower()]

        if actor and actor.lower() != "all":
            act = actor.strip().lower()
            filtered = [e for e in filtered if act in e.actor.lower()]

        if actual_date_from:
            bound_from = actual_date_from.strip()
            filtered = [e for e in filtered if e.ts >= bound_from]

        if actual_date_to:
            bound_to = actual_date_to.strip()
            if len(bound_to) == 10:
                # Date-only bound is inclusive of the whole day.
                filtered = [e for e in filtered if e.ts[:10] <= bound_to]
            else:
                filtered = [e for e in filtered if e.ts <= bound_to]

        # Order descending by timestamp (newest first for the operator)
        filtered.sort(key=lambda e: e.ts, reverse=True)

        total_count = len(filtered)
        paginated = filtered[offset : offset + limit]
        return paginated, total_count

    def get_event(self, event_id: str) -> Optional[JournalEvent]:
        for e in self._events:
            if e.id == event_id:
                return e
        return None

    def get_related_events(self, action_id: Optional[str], run_id: Optional[str], exclude_id: str) -> List[JournalEvent]:
        related = []
        for e in self._events:
            if e.id == exclude_id:
                continue
            if action_id and e.action_id == action_id:
                related.append(e)
            elif run_id and e.run_id == run_id:
                related.append(e)
        related.sort(key=lambda e: e.ts)
        return related

    def get_summary_metrics(self) -> Dict[str, int]:
        total = len(self._events)
        proposals = sum(e.kind in ("action_requested", "action_proposed") for e in self._events)
        policy_decisions = sum(e.kind in ("policy_evaluated", "action_denied", "lease_evaluated") for e in self._events)
        approvals = sum(e.kind in ("gate_decided", "gate_requested") for e in self._events)
        executions = sum(
            e.kind in ("execution_queued", "execution_started", "action_completed", "action_failed")
            for e in self._events
        )
        failed = sum(
            e.kind in ("action_failed", "execution_failed")
            or e.status.lower() in ("failed", "denied", "error")
            for e in self._events
        )
        return {
            "total": total,
            "proposals": proposals,
            "policy_decisions": policy_decisions,
            "approval_decisions": approvals,
            "execution_events": executions,
            "failed_operations": failed,
        }


# Global repository instance (defaults to in-memory demo store, with connection hook for PostgreSQL)
JOURNAL_STORE = InMemoryDemoJournal()


# ==============================================================================
# 5. CONTROLLER HELPERS & VIEW MODELS
# ==============================================================================

def get_kind_badge_class(kind: str) -> str:
    """Returns CSS badge class based on event kind."""
    if "requested" in kind or "proposed" in kind:
        return "badge-proposed"
    if "denied" in kind or "failed" in kind:
        return "badge-denied"
    if "gate" in kind or "escalate" in kind:
        return "badge-escalated"
    if "completed" in kind or "succeeded" in kind:
        return "badge-succeeded"
    if "policy" in kind or "lease" in kind:
        return "badge-policy"
    if "checkpoint" in kind:
        return "badge-checkpoint"
    return "badge-default"


def format_utc_ts(iso_str: str) -> str:
    """Formats ISO string into readable UTC display."""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return iso_str


# ==============================================================================
# 6. ROUTE HANDLERS
# ==============================================================================

@router.get("/audit", response_class=HTMLResponse)
async def get_audit_page(
    request: Request,
    q: Optional[str] = Query(None, description="Free text query"),
    kind: Optional[str] = Query("all", description="Event kind filter"),
    action_id: Optional[str] = Query(None, description="Action ID filter"),
    run_id: Optional[str] = Query(None, description="Run or thread ID filter"),
    actor: Optional[str] = Query("all", description="Actor filter"),
    date_from: Optional[str] = Query(None, description="Start date (ISO)"),
    date_to: Optional[str] = Query(None, description="End date (ISO)"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(15, ge=1, le=100, description="Items per page"),
):
    """Main audit log dashboard and HTMX partial renderer."""
    offset = (page - 1) * limit
    events, total_count = JOURNAL_STORE.list_events(
        q=q,
        kind=kind,
        action_id=action_id,
        run_id=run_id,
        actor=actor,
        date_from=date_from,
        date_to=date_to,
        limit=limit,
        offset=offset,
    )

    total_pages = max(1, (total_count + limit - 1) // limit)
    metrics = JOURNAL_STORE.get_summary_metrics()

    # Pre-render badges & readable timestamps for template display
    enriched_events = []
    for ev in events:
        ev_dict = ev.to_dict()
        ev_dict["badge_class"] = get_kind_badge_class(ev.kind)
        ev_dict["formatted_ts"] = format_utc_ts(ev.ts)
        enriched_events.append(ev_dict)

    available_actors = sorted(list({e.actor for e in JOURNAL_STORE._events}))
    available_kinds = [k.value for k in EventKind]

    context = {
        "request": request,
        "active_page": "audit",
        "demo_mode": not JOURNAL_STORE.is_persistent(),
        "metrics": metrics,
        "events": enriched_events,
        "total_count": total_count,
        "current_page": page,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "prev_page": page - 1,
        "next_page": page + 1,
        "limit": limit,
        "q": q or "",
        "selected_kind": kind or "all",
        "action_id": action_id or "",
        "run_id": run_id or "",
        "selected_actor": actor or "all",
        "date_from": date_from or "",
        "date_to": date_to or "",
        "available_actors": available_actors,
        "available_kinds": available_kinds,
    }

    # HTMX Partial Swap: Return only the table & pagination if triggered by HTMX filter
    if request.headers.get("HX-Request") and not request.headers.get("HX-Boosted"):
        return templates.TemplateResponse(
            request=request,
            name="components/audit_table_fragment.html",
            context=context,
        )

    return templates.TemplateResponse(
        request=request,
        name="audit.html",
        context=context,
    )


@router.get("/audit/events/{event_id}", response_class=HTMLResponse)
async def get_audit_event_detail(request: Request, event_id: str):
    """Returns the event detail drawer/card fragment via HTMX or full inspection."""
    event = JOURNAL_STORE.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Audit event '{event_id}' not found")

    related = JOURNAL_STORE.get_related_events(
        action_id=event.action_id,
        run_id=event.run_id,
        exclude_id=event.id,
    )

    enriched_related = []
    for r in related:
        r_dict = r.to_dict()
        r_dict["badge_class"] = get_kind_badge_class(r.kind)
        r_dict["formatted_ts"] = format_utc_ts(r.ts)
        enriched_related.append(r_dict)

    ev_dict = event.to_dict()
    ev_dict["badge_class"] = get_kind_badge_class(event.kind)
    ev_dict["formatted_ts"] = format_utc_ts(event.ts)
    # Safely formatted JSON string for display in pre/code
    ev_dict["payload_json"] = json.dumps(event.payload, indent=2, ensure_ascii=False)

    context = {
        "request": request,
        "event": ev_dict,
        "related_events": enriched_related,
        "demo_mode": not JOURNAL_STORE.is_persistent(),
    }

    return templates.TemplateResponse(
        request=request,
        name="components/audit_event_detail.html",
        context=context,
    )


@router.get("/audit/export")
async def export_audit_csv(
    q: Optional[str] = Query(None),
    kind: Optional[str] = Query("all"),
    action_id: Optional[str] = Query(None),
    run_id: Optional[str] = Query(None),
    actor: Optional[str] = Query("all"),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
):
    """Exports filtered audit events to CSV with formula injection defense."""
    events, _ = JOURNAL_STORE.list_events(
        q=q,
        kind=kind,
        action_id=action_id,
        run_id=run_id,
        actor=actor,
        date_from=date_from,
        date_to=date_to,
        limit=10000,
        offset=0,
    )

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    # Header row
    writer.writerow([
        "Timestamp_UTC",
        "Event_ID",
        "Kind",
        "Action_ID",
        "Run_ID",
        "Thread_ID",
        "Checkpoint_Step",
        "Actor",
        "Status",
        "Description",
        "Event_Hash",
        "Prev_Hash",
        "Verification_Status",
        "Payload_JSON",
    ])

    # Data rows with sanitization
    for ev in events:
        writer.writerow([
            sanitize_csv_cell(ev.ts),
            sanitize_csv_cell(ev.id),
            sanitize_csv_cell(ev.kind),
            sanitize_csv_cell(ev.action_id or ""),
            sanitize_csv_cell(ev.run_id),
            sanitize_csv_cell(ev.thread_id),
            sanitize_csv_cell(ev.checkpoint_step if ev.checkpoint_step is not None else ""),
            sanitize_csv_cell(ev.actor),
            sanitize_csv_cell(ev.status),
            sanitize_csv_cell(ev.description),
            sanitize_csv_cell(ev.event_hash or ""),
            sanitize_csv_cell(ev.prev_hash or ""),
            sanitize_csv_cell(ev.verification_status.value),
            sanitize_csv_cell(json.dumps(ev.payload, ensure_ascii=False)),
        ])

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"aegis_audit_log_{timestamp}.csv"

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
