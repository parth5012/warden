"""FastAPI surface — JSON-clean endpoints (lock 12), SSE live feed.

Warden's HTTP layer per ARCHITECTURE.md §6. Yash's live-SSE slice adds:

    GET /stream          live journal feed (Server-Sent Events)
    GET /stream/health   liveness for the feed (plain JSON probe)

The bus is wired as the GuardedExecutor's journal, so every seam event
(action_requested / action_denied / gate_requested / action_completed /
action_failed / gate_decided) streams live — one path, lock 1. Run startup
creates the graph + checkpointer; POST /runs drives the multi-agent graph.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph.state import CompiledStateGraph
from typing_extensions import TypeAlias

from warden.leases import Lease, LeasePolicy
from warden.multi_agent import build_multi_agent_graph
from warden.checkpoint import CheckpointManager
from warden.app.dashboard import render_dashboard
from warden.hitl.gates import (ApproverError, GateRegistry, NamedKeys, normalize_verdict)
from warden.multi_agent import build_multi_agent_graph
from warden.seam import GuardedExecutor
from warden.streaming import WardenJournalBus

CompiledGraph: TypeAlias = CompiledStateGraph[Any, Any, Any, Any]

# Named keys (lock 8): WARDEN_APPROVER_KEYS='alice=s3cret,bob=hunter2'.
# A tiny default keeps the dev/demo path working; production overrides env.
import os as _os

try:
    _approver_keys = NamedKeys.from_env(_os.environ.get("WARDEN_APPROVER_KEYS", "alice=warden-alice,bob=warden-bob"))
except ApproverError:  # pragma: no cover — defensive
    _approver_keys = NamedKeys(pairs={"alice": "warden-alice"})

# ---------------------------------------------------------------------------
# App state (populated on startup)
# ---------------------------------------------------------------------------


class _State:
    """Cross-request holders. Populated by the lifespan on startup."""

    def __init__(self, pg_uri: str = "") -> None:
        self.bus = WardenJournalBus()
        self.executor: GuardedExecutor | None = None
        self.graph: CompiledGraph | None = None
        self.manager: CheckpointManager | None = None
        self.pg_uri: str = pg_uri
        # THE lease toggle: shared mutable policy, read live by the graph.
        self.lease_policy = LeasePolicy()
        # The approvals inbox: a pure projection over the journal bus.
        self.registry = GateRegistry()
        self.approver_keys = _approver_keys


state = _State()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Wire the checkpointer + executor + graph once per app lifetime.

    PG URI resolution reuses the CLI's helper (env > bundled pgserver) so
    the app boots locally with zero config; startup fails closed if the
    checkpointer store is unreachable (there is no park/resume without it).
    """
    import asyncio
    import sys

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    from tests.cli_chat import _resolve_pg_uri

    state.pg_uri = _resolve_pg_uri(None)
    # The inbox starts from whatever the bus already journaled.
    state.registry = GateRegistry.from_bus(state.bus)
    async with CheckpointManager.create(state.pg_uri) as mgr:
        state.manager = mgr
        state.executor = GuardedExecutor(journal=state.bus)
        state.graph = build_multi_agent_graph(
            state.executor, checkpointer=mgr.checkpointer
        )
        yield
    state.manager = None
    state.graph = None
    state.executor = None


app = FastAPI(title="Warden", version="0.1.0", lifespan=lifespan)

# Testability note: handlers read the module-level `state` (single source).
# httpx ASGITransport does NOT run the lifespan, so tests swap `state.bus /
# executor / graph / lease_policy` for fixtures and hit the real routes
# without spawning Postgres — the toggle endpoints below are the contract.


# ---------------------------------------------------------------------------
# Live feed (the SSE slice)
# ---------------------------------------------------------------------------


@app.get("/stream")
async def stream(with_history: bool = True) -> StreamingResponse:
    """Live journal feed as Server-Sent Events.

    Query params:
      with_history: replay recent journaled events before streaming live.
    """
    sub_id = await state.bus.subscribe(with_history=with_history)

    async def running_feed() -> AsyncIterator[bytes]:
        try:
            async for frame in state.bus.sse_stream(sub_id):
                yield frame
        finally:
            with_cancel = state.bus.unsubscribe(sub_id) if state.bus is not None else None
            if with_cancel is not None:
                # A cancelled feed (client disconnect mid-frame) must still
                # release the subscriber slot — unsubscribe is safe to run
                # even if the sub was already popped.
                try:
                    await with_cancel
                except Exception:  # noqa: BLE001 — teardown must not raise
                    pass

    return StreamingResponse(
        running_feed(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # don't buffer at the proxy
        },
    )


@app.get("/stream/health")
async def stream_health() -> dict[str, Any]:
    """Feed liveness + subscriber count (plain JSON probe)."""
    ok = state.manager is not None and state.executor is not None
    return {
        "ok": ok,
        "subscribers": len(state.bus._subscribers),  # noqa: SLF001 — internal probe
        "history": len(state.bus.history()),
    }


# ---------------------------------------------------------------------------
# Run surface (drives the multi-agent graph through the seam)
# ---------------------------------------------------------------------------


@app.post("/runs")
async def start_run(body: dict[str, Any]) -> dict[str, Any]:
    """Start a governed run: {'task': '...'} -> thread_id + final state.

    Deliberately synchronous-with-the-request for the hackathon scope
    (long-running attach is a later phase — the SSE feed is the show).
    """
    if state.graph is None:
        return {"error": "governance_unavailable"}
    thread_id = f"run-{uuid.uuid4().hex[:12]}"
    config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
    result = await state.graph.ainvoke({"task": str(body.get("task", ""))}, config)
    return {
        "thread_id": thread_id,
        "messages": result.get("messages", []),
        "dispatched": result.get("dispatched", []),
        "approvals": result.get("approvals", []),
    }


# ---------------------------------------------------------------------------
# Lease toggles (Yash's task): runtime enforcement knob + per-run card
# ---------------------------------------------------------------------------


@app.get("/toggles/lease")
async def get_lease_toggle() -> dict[str, Any]:
    """Current lease-enforcement policy (the toggle's read side)."""
    return state.lease_policy.to_state()


@app.post("/toggles/lease")
async def set_lease_toggle(body: dict[str, Any]) -> dict[str, Any]:
    """Flip lease enforcement / set TTL for the NEXT route.

    Body: {'enabled': bool, 'ttl_seconds': float?} — both optional; only
    provided keys change. TTL applies per-grant (supervisor reads it live);
    in-flight handoffs are NOT re-timed (by design: shrinking TTL must not
    strand an approved, mid-flight action).
    """
    policy = state.lease_policy
    if "enabled" in body:
        policy.enabled = bool(body["enabled"])
    if "ttl_seconds" in body:
        ttl = float(body["ttl_seconds"])
        if ttl <= 0.0:
            raise HTTPException(status_code=422, detail="ttl_seconds must be > 0")
        policy.ttl_seconds = ttl
    return policy.to_state()


def _esc(s: Any) -> str:
    """Minimal HTML escaping for the server-rendered partial."""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _lease_card_html(lease: Lease | None, policy: LeasePolicy) -> str:
    """Server-rendered HTMX partial: one run's live lease card."""
    if lease is None:
        return '<div class="lease-card lease-none">no lease in state</div>'
    enabled = "ON" if policy.enabled else "OFF"
    return (
        f'<div class="lease-card lease-{_esc("on" if policy.enabled else "off")}">'
        f'<span class="holder">{_esc(lease.holder)}</span> '
        f'<span class="purpose">{_esc(lease.purpose or "handoff")}</span> '
        f'<span class="ttl">ttl {_esc(lease.ttl_seconds)}s</span> '
        f'<span class="toggle">enforcement {_esc(enabled)}</span>'
        f'</div>'
    )


@app.get("/runs/{thread_id}/lease")
async def run_lease_card(thread_id: str, request: Request) -> Response:
    """Per-run live lease state.

    Accept: application/json (default) -> JSON; text/html -> HTMX partial
    (the dashboard card, pollable via hx-get + hx-trigger="every 2s").
    """
    accept = request.headers.get("accept", "").lower()
    wants_html = "text/html" in accept

    # Lease + policy + verdict, straight from the graph's persisted state.
    if state.graph is None:
        detail: dict[str, Any] = {"error": "governance_unavailable"}
        return (
            HTMLResponse(_lease_card_html(None, state.lease_policy), status_code=503)
            if wants_html
            else _json_response(detail, 503)
        )
    config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
    snap = await state.graph.aget_state(config)
    raw: dict[str, Any] = dict(getattr(snap, "values", None) or {})
    lease = Lease.from_state(raw.get("lease"))
    remaining = 0.0
    if lease is not None:
        from warden.leases import remaining as lease_remaining

        remaining = lease_remaining(lease)
    verdict = state.lease_policy.check(raw.get("lease"), lease.holder if lease else "", thread_id)
    if wants_html:
        html = _lease_card_html(lease, state.lease_policy) + (
            f'<span class="remaining">{remaining:.1f}s left</span>' if lease is not None else ""
        )
        return HTMLResponse(html)
    return _json_response(
        {
            "thread_id": thread_id,
            "lease": lease.to_state() if lease else None,
            "remains_seconds": remaining,
            "verdict": verdict.value,
            "policy": state.lease_policy.to_state(),
        }
    )


def _json_response(payload: dict[str, Any], status_code: int = 200) -> Response:
    import json as _json

    return Response(
        content=_json.dumps(payload),
        status_code=status_code,
        media_type="application/json",
    )


# ---------------------------------------------------------------------------
# Approvals inbox + gate decisions (lock 8 named-key flow)
# ---------------------------------------------------------------------------


def _inbox_html(registry: GateRegistry) -> str:
    """Server-rendered HTMX inbox partial (pending first, decided strip)."""
    pending = registry.pending()
    decided = registry.decided()
    rows: list[str] = []
    for v in pending:
        rows.append(
            f'<div class="gate-card pending" id="gate-{_esc(v.gate_id)}">'
            f"<b>{_esc(v.action)}</b> on {_esc(v.thread_id)} "
            f'(payload: {_esc(v.payload)}) <i>asked {_esc(v.requested_at)}</i>'
            "</div>"
        )
    if not rows:
        rows.append('<div class="gate-card empty">inbox empty — no pending approvals</div>')
    strip: list[str] = []
    for v in decided:
        who = _esc(v.decided_by or "")
        strip.append(
            '<div class="gate-card decided">' + _esc(v.action) + " -> "
            + str(v.verdict) + " by " + who
            + " <i>" + _esc(v.decided_reason) + "</i></div>"
        )
    decided_html = "".join(strip)
    return (
        '<div class="inbox">'
        + "".join(rows)
        + '<div class="decided-strip">'
        + decided_html
        + "</div></div>"
    )


@app.get("/inbox")
async def inbox(request: Request) -> Response:
    """The approvals inbox. JSON (default) or HTMX partial (`Accept: text/html`)."""
    accept = request.headers.get("accept", "").lower()
    refresh = GateRegistry.from_bus(state.bus)  # always current with the journal
    state.registry = refresh
    if "text/html" in accept:
        return HTMLResponse(_inbox_html(refresh))
    return _json_response(
        {
            "pending": [v.to_dict() for v in refresh.pending()],
            "decided": [v.to_dict() for v in refresh.decided()],
        }
    )


@app.post("/gates/{gate_id}/decision")
async def decide_gate(
    gate_id: str,
    request: Request,
) -> Response:
    """Human verdict on a gate (lock 5/8 flow).

    Headers: `Warden-Key: <key>` — the approver's named key (identity = the
    key; client-supplied names are IGNORED for attribution).
    Body JSON: {"verdict": "approve"|"deny", "reason": "..."}

    Semantics: journal-first — the decision is journaled (gate_decided)
    BEFORE the parked run is resumed, and the resume uses `Command(resume=...)`
    per the caller contract. Re-deciding a decided gate is a 409. DENY is
    terminal (the parked run aborts with a Denied outcome, no dispatch).
    """
    import json as _json

    registry = GateRegistry.from_bus(state.bus)
    body_raw = await request.body()
    try:
        body: dict[str, Any] = _json.loads(body_raw or b"{}")
    except ValueError:
        return _json_response({"error": "invalid json"}, 400)

    try:
        decided_by = state.approver_keys.principal_for_header(request.headers.get("Warden-Key"))
    except ApproverError as exc:
        return _json_response({"error": str(exc)}, 401)

    try:
        verdict = normalize_verdict(body.get("verdict", ""))
    except ApproverError as exc:
        return _json_response({"error": str(exc)}, 422)
    reason = str(body.get("reason", ""))

    # Single decision per gate (409 on double-decide).
    view = registry.get(gate_id)
    if view is None:
        return _json_response({"error": "unknown gate_id"}, 404)
    if view.verdict is not None:
        return _json_response(
            {"error": "gate already decided", "verdict": view.verdict, "by": view.decided_by},
            409,
        )

    # Journal FIRST (the evidence), then resume the parked run.
    await state.bus.append(
        "gate_decided",
        {
            "gate_id": gate_id,
            "verdict": verdict,
            "decided_by": decided_by,
            "reason": reason,
        },
    )

    resume = GateRegistry.resume_value(gate_id, verdict, decided_by, reason)
    resumed: dict[str, Any] | None = None
    if state.graph is not None and view.thread_id:
        from langgraph.types import Command

        config: RunnableConfig = {"configurable": {"thread_id": view.thread_id}}
        result = await state.graph.ainvoke(Command(resume=resume), config)
        resumed = {
            "messages": result.get("messages", []),
            "dispatched": result.get("dispatched", []),
            "approvals": result.get("approvals", []),
        }

    return _json_response(
        {
            "gate_id": gate_id,
            "verdict": verdict,
            "decided_by": decided_by,
            "resumed": resumed,
        }
    )


# ---------------------------------------------------------------------------
# Operator console (server-rendered dashboard, lock 12)
# ---------------------------------------------------------------------------


@app.get("/dashboard")
async def dashboard() -> HTMLResponse:
    """The one operator page: live feed + inbox + lease toggle + run launcher."""
    return HTMLResponse(render_dashboard(state.lease_policy))


@app.post("/run-web")
async def run_web(task: str = "") -> Response:
    """Plain-form bridge for the dashboard launcher (no-JS degradation).

    Delegates to the same governed path as POST /runs; redirects back to
    the console — the SSE feed and inbox show what happened.
    """
    if state.graph is None:
        return HTMLResponse('<p>governance unavailable — checkpointer down', status_code=503)
    thread_id = f"run-{uuid.uuid4().hex[:12]}"
    config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
    await state.graph.ainvoke({"task": task}, config)
    return HTMLResponse(
        f'<p>Run <code>{_esc(thread_id)}</code> finished — see the feed.</p>'
        '<p><a href="/dashboard">back to console</a></p>'
    )
