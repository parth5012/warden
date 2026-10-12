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
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

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
    "PostgresJournal",
    "JOURNAL_STORE",
    "get_journal_store",
    "set_journal_store",
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

    def get_available_actors(self) -> List[str]:
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

    def get_available_actors(self) -> List[str]:
        return sorted(list({e.actor for e in self._events}))

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
                    or query in (e.actor or "").lower()
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
            filtered = [e for e in filtered if act in (e.actor or "").lower()]

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


class PostgresJournal(AuditJournal, JournalRepository):
    """PostgreSQL-backed append-only Write-Ahead Journal & Audit Log repository.

    Provides durable, tamper-evident persistence for domain events, cryptographic
    hash chaining, and query projections over the `journal_events` and `audit_logs` tables.
    """

    def __init__(self, conn_string: str) -> None:
        self.conn_string = conn_string
        self._pool = ConnectionPool(conninfo=conn_string, min_size=1, max_size=5, open=True)

    def is_persistent(self) -> bool:
        return True

    def ensure_schema_and_seed(self, demo_events: Optional[List[JournalEvent]] = None) -> None:
        """Creates tables if not exists and seeds baseline events if empty."""
        ddl = """
        CREATE TABLE IF NOT EXISTS journal_events (
            id                  TEXT PRIMARY KEY,
            run_id              TEXT NOT NULL,
            thread_id           TEXT NOT NULL,
            action_id           TEXT,
            checkpoint_step     INTEGER,
            kind                TEXT NOT NULL,
            actor               TEXT NOT NULL,
            status              TEXT NOT NULL DEFAULT 'Proposed',
            description         TEXT NOT NULL DEFAULT '',
            payload             JSONB NOT NULL DEFAULT '{}',
            ts                  TIMESTAMPTZ NOT NULL DEFAULT now(),
            prev_hash           TEXT,
            event_hash          TEXT,
            verification_status TEXT NOT NULL DEFAULT 'Verified'
        );

        CREATE UNIQUE INDEX IF NOT EXISTS journal_events_idempotency
            ON journal_events (run_id, action_id, kind)
            WHERE kind IN ('action_requested', 'gate_requested');

        CREATE INDEX IF NOT EXISTS idx_journal_events_ts ON journal_events (ts DESC);
        CREATE INDEX IF NOT EXISTS idx_journal_events_run_thread ON journal_events (run_id, thread_id);
        CREATE INDEX IF NOT EXISTS idx_journal_events_action ON journal_events (action_id);
        CREATE INDEX IF NOT EXISTS idx_journal_events_kind ON journal_events (kind);
        CREATE INDEX IF NOT EXISTS idx_journal_events_actor ON journal_events (actor);

        CREATE TABLE IF NOT EXISTS audit_logs (
            id                  TEXT PRIMARY KEY,
            ts                  TIMESTAMPTZ NOT NULL DEFAULT now(),
            event_type          TEXT NOT NULL,
            actor               TEXT NOT NULL,
            resource            TEXT,
            action              TEXT NOT NULL,
            status              TEXT NOT NULL,
            metadata            JSONB NOT NULL DEFAULT '{}',
            ip_address          TEXT,
            event_hash          TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_audit_logs_ts ON audit_logs (ts DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs (actor);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_type ON audit_logs (event_type);

        CREATE TABLE IF NOT EXISTS login_audit (
            id                  TEXT PRIMARY KEY,
            ts                  TIMESTAMPTZ NOT NULL DEFAULT now(),
            username            TEXT NOT NULL,
            actor               TEXT NOT NULL,
            auth_method         TEXT NOT NULL DEFAULT 'password',
            status              TEXT NOT NULL,
            ip_address          TEXT,
            user_agent          TEXT,
            failure_reason      TEXT,
            metadata            JSONB NOT NULL DEFAULT '{}',
            event_id            TEXT REFERENCES journal_events(id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_login_audit_ts ON login_audit (ts DESC);
        CREATE INDEX IF NOT EXISTS idx_login_audit_user ON login_audit (username);
        CREATE INDEX IF NOT EXISTS idx_login_audit_status ON login_audit (status);
        """
        with self._pool.connection() as conn:
            conn.execute(ddl)
            conn.commit()

            count = conn.execute("SELECT count(*) FROM journal_events;").fetchone()[0]
            if count == 0 and demo_events:
                prev_hash: Optional[str] = None
                for ev in demo_events:
                    ev_dict = ev.to_dict()
                    ev_dict["prev_hash"] = prev_hash
                    ev_hash = calculate_event_hash(ev_dict)
                    ev_dict["event_hash"] = ev_hash
                    ev_dict["verification_status"] = VerificationStatus.VERIFIED.value
                    prev_hash = ev_hash

                    conn.execute("""
                        INSERT INTO journal_events (
                            id, run_id, thread_id, action_id, checkpoint_step, kind, actor,
                            status, description, payload, ts, prev_hash, event_hash, verification_status
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                        ) ON CONFLICT (id) DO NOTHING;
                    """, (
                        ev_dict["id"], ev_dict["run_id"], ev_dict["thread_id"], ev_dict["action_id"],
                        ev_dict["checkpoint_step"], ev_dict["kind"], ev_dict["actor"], ev_dict["status"],
                        ev_dict["description"], json.dumps(ev_dict["payload"]), ev_dict["ts"],
                        ev_dict["prev_hash"], ev_dict["event_hash"], ev_dict["verification_status"]
                    ))

                    conn.execute("""
                        INSERT INTO audit_logs (
                            id, ts, event_type, actor, resource, action, status, metadata, event_hash
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO NOTHING;
                    """, (
                        ev_dict["id"], ev_dict["ts"], ev_dict["kind"], ev_dict["actor"],
                        ev_dict["action_id"], ev_dict["description"], ev_dict["status"],
                        json.dumps(ev_dict["payload"]), ev_dict["event_hash"]
                    ))
                conn.commit()

    def _row_to_event(self, r: Dict[str, Any]) -> JournalEvent:
        ts_val = r["ts"].isoformat().replace("+00:00", "Z") if hasattr(r["ts"], "isoformat") else str(r["ts"])
        payload = r["payload"] if isinstance(r["payload"], dict) else json.loads(r["payload"])
        try:
            ver_status = VerificationStatus(r.get("verification_status", VerificationStatus.VERIFIED.value))
        except Exception:
            ver_status = VerificationStatus.VERIFIED

        return JournalEvent(
            id=r["id"],
            run_id=r["run_id"],
            thread_id=r["thread_id"],
            action_id=r["action_id"],
            checkpoint_step=r["checkpoint_step"],
            kind=r["kind"],
            actor=r["actor"],
            status=r["status"],
            description=r["description"],
            payload=payload,
            ts=ts_val,
            prev_hash=r["prev_hash"],
            event_hash=r["event_hash"],
            verification_status=ver_status,
        )

    @property
    def events(self) -> List[JournalEvent]:
        evs, _ = self.list_events(limit=10000)
        return list(reversed(evs))

    def verify(self) -> Tuple[VerificationStatus, Optional[str]]:
        return verify_hash_chain(self.events)

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
        """Appends an event to the persistent PostgreSQL journal, computing the chain hash.
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

        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                # Fetch latest event for hash chaining
                cur.execute("SELECT event_hash FROM journal_events ORDER BY ts DESC, id DESC LIMIT 1;")
                last_row = cur.fetchone()
                prev_hash = last_row["event_hash"] if last_row else None

                ev_dict = event.to_dict()
                ev_dict["prev_hash"] = prev_hash
                ev_hash = calculate_event_hash(ev_dict)
                ev_dict["event_hash"] = ev_hash
                ev_dict["verification_status"] = VerificationStatus.VERIFIED.value

                cur.execute("""
                    INSERT INTO journal_events (
                        id, run_id, thread_id, action_id, checkpoint_step, kind, actor,
                        status, description, payload, ts, prev_hash, event_hash, verification_status
                    ) VALUES (
                        %(id)s, %(run_id)s, %(thread_id)s, %(action_id)s, %(checkpoint_step)s,
                        %(kind)s, %(actor)s, %(status)s, %(description)s, %(payload)s,
                        %(ts)s, %(prev_hash)s, %(event_hash)s, %(verification_status)s
                    )
                    ON CONFLICT (run_id, action_id, kind) WHERE kind IN ('action_requested', 'gate_requested')
                    DO NOTHING
                    RETURNING id;
                """, {
                    "id": ev_dict["id"],
                    "run_id": ev_dict["run_id"],
                    "thread_id": ev_dict["thread_id"],
                    "action_id": ev_dict["action_id"],
                    "checkpoint_step": ev_dict["checkpoint_step"],
                    "kind": ev_dict["kind"],
                    "actor": ev_dict["actor"],
                    "status": ev_dict["status"],
                    "description": ev_dict["description"],
                    "payload": json.dumps(ev_dict["payload"]),
                    "ts": ev_dict["ts"],
                    "prev_hash": ev_dict["prev_hash"],
                    "event_hash": ev_dict["event_hash"],
                    "verification_status": ev_dict["verification_status"],
                })

                cur.execute("""
                    INSERT INTO audit_logs (
                        id, ts, event_type, actor, resource, action, status, metadata, event_hash
                    ) VALUES (
                        %(id)s, %(ts)s, %(kind)s, %(actor)s, %(resource)s, %(action)s,
                        %(status)s, %(metadata)s, %(event_hash)s
                    ) ON CONFLICT (id) DO NOTHING;
                """, {
                    "id": ev_dict["id"],
                    "ts": ev_dict["ts"],
                    "kind": ev_dict["kind"],
                    "actor": ev_dict["actor"],
                    "resource": ev_dict.get("action_id"),
                    "action": ev_dict.get("description", ""),
                    "status": ev_dict["status"],
                    "metadata": json.dumps(ev_dict["payload"]),
                    "event_hash": ev_dict["event_hash"],
                })

            conn.commit()

        return JournalEvent(**ev_dict)

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

        where_clauses: List[str] = []
        params: Dict[str, Any] = {}

        if q:
            where_clauses.append("""(
                id ILIKE %(q)s
                OR COALESCE(action_id, '') ILIKE %(q)s
                OR run_id ILIKE %(q)s
                OR actor ILIKE %(q)s
                OR description ILIKE %(q)s
                OR payload::text ILIKE %(q)s
            )""")
            params["q"] = f"%{q.strip()}%"

        if kind and kind.lower() != "all":
            where_clauses.append("kind = %(kind)s")
            params["kind"] = kind

        if action_id:
            where_clauses.append("action_id ILIKE %(action_id)s")
            params["action_id"] = f"%{action_id.strip()}%"

        if run_id:
            where_clauses.append("(run_id ILIKE %(run_id)s OR thread_id ILIKE %(run_id)s)")
            params["run_id"] = f"%{run_id.strip()}%"

        if actor and actor.lower() != "all":
            where_clauses.append("actor ILIKE %(actor)s")
            params["actor"] = f"%{actor.strip()}%"

        if actual_date_from:
            where_clauses.append("ts >= %(date_from)s::timestamptz")
            params["date_from"] = actual_date_from.strip()

        if actual_date_to:
            bound_to = actual_date_to.strip()
            if len(bound_to) == 10:
                where_clauses.append("ts < (%(date_to)s::date + interval '1 day')")
            else:
                where_clauses.append("ts <= %(date_to)s::timestamptz")
            params["date_to"] = bound_to

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                count_query = f"SELECT count(*) AS total FROM journal_events {where_sql};"
                cur.execute(count_query, params)
                total_count = cur.fetchone()["total"]

                query = f"""
                    SELECT id, run_id, thread_id, action_id, checkpoint_step, kind, actor,
                           status, description, payload, ts, prev_hash, event_hash, verification_status
                    FROM journal_events
                    {where_sql}
                    ORDER BY ts DESC, id DESC
                    LIMIT %(limit)s OFFSET %(offset)s;
                """
                query_params = dict(params)
                query_params["limit"] = limit
                query_params["offset"] = offset

                cur.execute(query, query_params)
                rows = cur.fetchall()

        events = [self._row_to_event(r) for r in rows]
        return events, total_count

    def get_event(self, event_id: str) -> Optional[JournalEvent]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("""
                    SELECT id, run_id, thread_id, action_id, checkpoint_step, kind, actor,
                           status, description, payload, ts, prev_hash, event_hash, verification_status
                    FROM journal_events
                    WHERE id = %s;
                """, (event_id,))
                row = cur.fetchone()
                if row:
                    return self._row_to_event(row)
        return None

    def get_related_events(self, action_id: Optional[str], run_id: Optional[str], exclude_id: str) -> List[JournalEvent]:
        if not action_id and not run_id:
            return []

        where_parts = []
        params: Dict[str, Any] = {"exclude_id": exclude_id}

        if action_id and run_id:
            where_parts.append("(action_id = %(action_id)s OR run_id = %(run_id)s)")
            params["action_id"] = action_id
            params["run_id"] = run_id
        elif action_id:
            where_parts.append("action_id = %(action_id)s")
            params["action_id"] = action_id
        elif run_id:
            where_parts.append("run_id = %(run_id)s")
            params["run_id"] = run_id

        where_sql = "WHERE id != %(exclude_id)s AND " + " AND ".join(where_parts)

        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(f"""
                    SELECT id, run_id, thread_id, action_id, checkpoint_step, kind, actor,
                           status, description, payload, ts, prev_hash, event_hash, verification_status
                    FROM journal_events
                    {where_sql}
                    ORDER BY ts ASC, id ASC;
                """, params)
                rows = cur.fetchall()

        return [self._row_to_event(r) for r in rows]

    def get_summary_metrics(self) -> Dict[str, int]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("""
                    SELECT
                        count(*) AS total,
                        count(*) FILTER (WHERE kind IN ('action_requested', 'action_proposed')) AS proposals,
                        count(*) FILTER (WHERE kind IN ('policy_evaluated', 'action_denied', 'lease_evaluated')) AS policy_decisions,
                        count(*) FILTER (WHERE kind IN ('gate_decided', 'gate_requested')) AS approval_decisions,
                        count(*) FILTER (WHERE kind IN ('execution_queued', 'execution_started', 'action_completed', 'action_failed')) AS execution_events,
                        count(*) FILTER (WHERE kind IN ('action_failed', 'execution_failed') OR lower(status) IN ('failed', 'denied', 'error')) AS failed_operations
                    FROM journal_events;
                """)
                row = cur.fetchone()
                return {
                    "total": row["total"],
                    "proposals": row["proposals"],
                    "policy_decisions": row["policy_decisions"],
                    "approval_decisions": row["approval_decisions"],
                    "execution_events": row["execution_events"],
                    "failed_operations": row["failed_operations"],
                }

    def get_available_actors(self) -> List[str]:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT DISTINCT actor FROM journal_events WHERE actor IS NOT NULL AND actor != '' ORDER BY actor;")
                rows = cur.fetchall()
                return [r[0] for r in rows]

    @property
    def _events(self) -> List[JournalEvent]:
        # Return all events sorted oldest-first for index slicing like _events[-1]
        events, _ = self.list_events(limit=1000, offset=0)
        events.reverse()
        return events


def create_journal_store() -> JournalRepository:
    """Initializes persistent PostgresJournal if connection string is configured, else InMemoryDemoJournal."""
    import os
    try:
        from warden.config import settings
        uri = settings.postgres_uri
    except Exception:
        uri = None
    if not uri:
        uri = os.getenv("CONNECTION_STRING") or os.getenv("POSTGRES_URI")

    if uri:
        try:
            demo_seed = InMemoryDemoJournal()._events
            pg_store = PostgresJournal(uri)
            pg_store.ensure_schema_and_seed(demo_events=demo_seed)
            return pg_store
        except Exception as exc:
            logging.getLogger("aegis.audit").warning(
                f"Could not connect to Postgres WAL journal: {exc}. Using InMemoryDemoJournal fallback."
            )
    return InMemoryDemoJournal()


# Global repository instance (auto-binds to PostgreSQL WAL when CONNECTION_STRING is available)
JOURNAL_STORE: Any = create_journal_store()


def get_journal_store() -> Any:
    global JOURNAL_STORE
    return JOURNAL_STORE


def set_journal_store(store: Any) -> None:
    global JOURNAL_STORE
    JOURNAL_STORE = store


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

    available_actors = (
        JOURNAL_STORE.get_available_actors()
        if hasattr(JOURNAL_STORE, "get_available_actors")
        else sorted(list({e.actor for e in getattr(JOURNAL_STORE, "_events", [])}))
    )
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
