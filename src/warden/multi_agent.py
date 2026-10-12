"""Multi-agent architecture — Warden's Phase 3 slice.

Architecture: **supervisor + specialists** — the canonical LangGraph
multi-agent pattern. One supervisor node plans and routes; specialist
nodes (ops, research) execute; a shared `GuardedExecutor` (the seam) is
the ONLY way any specialist touches a tool.

    START -> supervisor -> (ops | research | finish) -> supervisor -> ...

Design decisions (recorded here — CONTEXT.md locks still apply):
- **One executor instance for the whole graph.** Every agent action — no
  matter which specialist runs it — crosses the same seam, so a single
  journal/audit trail covers the cast. This is the core of "multi-agent"
  for a security product: the seam is per-**system**, not per-agent.
- **Only the supervisor branches; specialists never re-route.** A denied
  action short-circuits into a report — the specialist reports failure to
  the supervisor, which decides what happens next. Keeps policy semantics
  (lock 5: deny is terminal) local to the seam.
- **HITL gates park the whole graph via `interrupt()` in the specialist
  node.** Same park/resume machinery the single-agent demo proved; the
  supervisor does not care which specialist parked.
- **Ephemeral leases (Yash's task, implemented):** the supervisor grants a
  TTL-scoped lease in state on every route (`warden/leases.py`, pure logic);
  specialists must provably hold custody on the current thread before
  dispatching. Expired/absent custody fail-closes the handoff (report,
  never silent dispatch). Resume-safe: the lease rides checkpointed state,
  so an approval inside the TTL dispatches, a slow human's doesn't.
- **Tool catalog (Phase 1 ops-assistant):** eight tools wired through the
  same `execute()` seam — three safe reads that fast-path ALLOW, two
  HITL-escalated mutations (email, restart), two terminal-deny tools
  (destructive SQL, sensitive file read), and one sandboxed shell tool.
  The seam + PolicyEngine decide, the ops node dispatches behind
  tool-specific adapters (in-process, HITL gate, deny, Docker sandbox).
"""

from __future__ import annotations

import hashlib
import operator
from typing import Annotated, Any, Literal

from typing_extensions import TypedDict

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command, interrupt

from warden.models import (
    Action,
    ActionKind,
    Allowed,
    Denied,
    Error,
    GateDecision,
    GateVerdict,
    Pending,
)
from warden.leases import (
    LeasePolicy,
    LeaseVerdict,
    evaluate as evaluate_lease,
    grant as grant_lease,
    reacquire as reacquire_lease,
)
from warden.seam import GuardedExecutor, make_action
from warden.tools import (
    TOOL_CATALOG,
    _looks_sensitive_path,
    dispatch_get_system_metrics,
    dispatch_query_db_readonly,
    dispatch_read_service_logs,
    dispatch_restart_service,
    dispatch_send_email,
    descriptor_for,
    dispatch_exec_db_mutation,
    dispatch_read_file_sensitive,
)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class AgentState(TypedDict, total=False):
    """Shared graph state. `messages` accumulates across specialists.

    `total=False`: `task`/`assigned` are absent on the parked-state read
    after interrupt until the first supervisor update lands — nodes must
    use `.get(...)`, not `state[...]`, for these keys.

    `lease` is the ephemeral TTL ownership token (JSON-safe dict via
    `Lease.to_state`) the supervisor grants on routing and the specialist
    must provably hold before dispatch. An absent/expired/corrupt lease is
    fail-closed: the specialist reports the refusal and the supervisor ends
    the run (it does not retry the handoff automatically — a fresh route
    requires a new supervisor decision).
    """

    messages: Annotated[list[str], operator.add]
    task: str
    assigned: str  # next specialist the supervisor chose
    findings: Annotated[list[str], operator.add]  # research results
    dispatched: Annotated[list[str], operator.add]  # audit trail of executed actions
    approvals: Annotated[list[str], operator.add]  # gates resolved by a human
    lease: dict[str, Any]  # ephemeral lease state (Lease.to_state())


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


def supervisor_node(
    executor: GuardedExecutor,
    *,
    lease_policy: LeasePolicy | None = None,
    lease_ttl_seconds: float | None = None,
) -> Any:
    """Plan-and-route node. Reads `task`, picks one specialist or finishes.

    Kept deterministic (no LLM) for the hackathon demo: routing rules are
    plain keyword matching on the task. An LLM-backed router is a later
    swap — same node signature, different brain.

    Grants an ephemeral lease to the chosen specialist on every route;
    the lease rides in state so the specialist must provably hold custody
    when it dispatches. TTL comes from the shared `LeasePolicy` at grant
    time, so lease-toggle TTL changes apply to the NEXT route without a
    graph rebuild. `lease_ttl_seconds` (legacy build knob) seeds the
    policy when no shared policy is passed.

    Returns the node callable (annotated Any: LangGraph's add_node
    overloads are structural and reject a hand-written Callable alias).
    """
    policy = lease_policy or LeasePolicy(
        ttl_seconds=lease_ttl_seconds if lease_ttl_seconds is not None else 300.0
    )

    def route(
        state: AgentState, config: RunnableConfig
    ) -> Command[Literal["ops", "research", "finish"]]:
        assigned = state.get("assigned", "")
        if assigned:
            # a specialist just finished: collect and end the run;
            # custody dies with the handoff
            return Command(update={"assigned": "", "lease": {}}, goto="finish")
        task = state.get("task", "")
        if any(k in task.lower() for k in ("email", "report", "cleanup", "shell", "orders")):
            target = "ops"
        else:
            target = "research"
        thread_id = str((config.get("configurable") or {}).get("thread_id") or "")
        if not thread_id:
            # ops_node refuses to dispatch without a thread_id; keep the
            # safeguard symmetric at the source — do not mint a lease that
            # no specialist can hold.
            return Command(
                update={"messages": ["Supervisor: no thread_id — refusing to route."]},
                goto="finish",
            )
        lease = grant_lease(target, thread_id, policy.grant_ttl(), purpose="handoff")
        return Command(
            update={"assigned": target, "lease": lease.to_state()},
            goto=target,  # type: ignore[arg-type]
        )

    return route


def _default_lease_policy() -> LeasePolicy:
    """Shared default for the legacy (no-shared-policy) build path.

    Kept a factory instead of a module constant so the legacy
    `lease_ttl_seconds` knob on `build_multi_agent_graph` reaches BOTH the
    supervisor (grant TTL) and the ops specialist (enforcement) through the
    same object. The shared-`LeasePolicy` path bypasses this entirely.
    """
    return LeasePolicy(
        ttl_seconds=300.0
    )  # default ON at 300s — toggles exist to be observable, not silent


def ops_node(
    executor: GuardedExecutor,
    *,
    lease_policy: LeasePolicy | None = None,
    lease_ttl_seconds: float | None = None,
) -> Any:
    """Ops specialist: emails, shell commands, DB writes.

    Every side effect wraps in an `Action` and crosses the seam. On
    `Pending` the node parks via `interrupt()`; on resume, the decision is
    fed back through `executor.decide_after_human(...)`.

    When no shared `lease_policy` is passed, the legacy
    `lease_ttl_seconds` knob (from the builder) seeds the same private
    `LeasePolicy` the supervisor uses, so TTL changes apply to custody
    checks too. When a shared policy IS passed, this node reads it live —
    the toggle contract.
    """

    policy = lease_policy or _default_lease_policy()

    async def ops(state: AgentState, config: RunnableConfig) -> dict[str, Any]:
        task = state.get("task", "")
        messages: list[str] = []
        dispatched: list[str] = []
        approvals: list[str] = []

        thread_id = str((config.get("configurable") or {}).get("thread_id") or "")
        if not thread_id:
            return {"messages": ["Ops: no thread_id in config — refusing to dispatch."]}

        # Ephemeral lease check (fail-closed): custody must provably belong
        # to ops on THIS thread at THIS instant — unless the shared
        # LeasePolicy is toggled OFF (runtime knob; still stamps the lease
        # in state so run/audit shape stays identical). Resume re-runs the
        # node, but the lease rides in checkpointed state — an approve that
        # arrives within the TTL holds; a slow human (ttl blew) does NOT
        # silently dispatch: the node reports the expiry and the run ends
        # unexecuted.
        custody = policy.check(
            state.get("lease"), "ops", thread_id
        )
        if custody is not LeaseVerdict.HELD:
            return {
                "messages": [f"Ops: lease {custody.value} — refusing to dispatch."],
            }

        # Deterministic action/gate id (see seam.make_action docstring): the
        # node re-runs at resume — sometimes in a fresh process — and the
        # id must survive all three. hash(thread_id) is salted per process,
        # so use a stable digest instead.
        stable_id = f"gate-{hashlib.sha256(thread_id.encode()).hexdigest()[:16]}"

        # --- build ONE action from the task, routed through the tool catalog ---
        action = _make_ops_action(task, stable_id, thread_id)

        outcome = await executor.execute(action)

        # --- handle the four verdicts ---
        if isinstance(outcome, Pending):
            gate = outcome.gate_request
            # park the whole graph; the human decision arrives on resume
            decision = interrupt(
                {
                    "gate_id": gate.gate_id,
                    "action": action.name,
                    "ask": f"approve or deny {action.name}?",
                }
            )
            human = _as_decision(gate.gate_id, decision)
            outcome = await executor.decide_after_human(gate, human)
            approvals.append(f"gate {gate.gate_id} -> {human.verdict.value}")

        if isinstance(outcome, Allowed):
            dispatched.append(action.name)
            messages.append(f"Ops: {action.name} dispatched.")
        elif isinstance(outcome, Denied):
            messages.append(f"Ops: {action.name} denied — {outcome.reason}")
        elif isinstance(outcome, Error):
            messages.append(f"Ops: {action.name} dispatch error — {outcome.reason}")

        return {"messages": messages, "dispatched": dispatched, "approvals": approvals}

    return ops


def research_node(executor: GuardedExecutor) -> Any:
    """Research specialist: read-only lookups (never gated, never denied)."""

    async def research(state: AgentState, config: RunnableConfig) -> dict[str, Any]:
        task = state.get("task", "")
        finding = f"Research: gathered context for '{task}'."
        return {"findings": [finding], "messages": [finding]}

    return research


def finish_node(state: AgentState) -> dict[str, Any]:
    """Collect the run summary — supervisor arrives here after each handoff."""
    summary = (
        f"Run complete. dispatched={state.get('dispatched', [])} "
        f"approvals={state.get('approvals', [])}"
    )
    return {"messages": [summary]}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ops_action(task: str, action_id: str, thread_id: str) -> Action:
    """Map a natural-language ops task to one of the eight catalog tools.

    Deterministic, keyword-based (the same no-LLM decision style the
    supervisor uses). The seam + PolicyEngine still decide the verdict —
    this helper only picks the tool the ops specialist *would* call.

    Tool selection order (first match wins):
      1. exec_db_mutation   — destructive SQL (DROP/TRUNCATE/ALTER) -> DENY
      2. read_file_sensitive — path traversal / secret file -> DENY
      3. restart_service    — critical infra restart -> HITL gate
      4. send_email         — outbound message -> HITL gate
      5. exec_shell         — arbitrary shell -> Docker sandbox
      6. query_db_readonly  — read-only SELECT -> fast-path ALLOW
      7. read_service_logs  — bounded log read -> fast-path ALLOW
      8. get_system_metrics — telemetry inspect -> fast-path ALLOW

    When none of the explicit patterns match, the assistant asks about
    metrics by default (safe read, never blocked).
    """
    t = task.lower()

    # --- terminal-deny tools ---
    if any(k in t for k in ("drop table", "drop database", "drop schema", "drop index", "drop view")):
        return _action(
            "exec_db_mutation",
            action_id,
            thread_id,
            {"sql": extract_sql(task) or "DROP TABLE users;"},
        )
    if "truncate" in t and "table" in t:
        return _action(
            "exec_db_mutation",
            action_id,
            thread_id,
            {"sql": extract_sql(task) or "TRUNCATE orders;"},
        )
    if any(k in t for k in ("delete from", "alter table")):
        return _action(
            "exec_db_mutation",
            action_id,
            thread_id,
            {"sql": extract_sql(task) or "DELETE FROM users;"},
        )
    if any(_looks_sensitive_path(k) for k in (task,)) or any(
        k in t for k in ("../../../.env", "/etc/shadow", "/etc/passwd", "read .env", "read shadow", "path traversal")
    ):
        path = _extract_path(task) or "../../../.env"
        return _action("read_file_sensitive", action_id, thread_id, {"path": path})

    # --- HITL escalation tools ---
    if any(k in t for k in ("restart", "reboot", "bounce")) and any(
        k in t for k in ("service", "postgres", "api", "primary", "node")
    ):
        svc = _extract_service_name(task) or "postgres_primary"
        return _action(
            "restart_service",
            action_id,
            thread_id,
            {"service_name": svc, "grace_period_sec": 10},
        )
    if any(k in t for k in ("email", "mail", "send a message", "notify")):
        return _action(
            "send_email",
            action_id,
            thread_id,
            {
                "recipient": "ops-team@example.com",
                "subject": _subject_from_task(task),
                "body": task,
            },
        )

    # --- sandbox tool ---
    if any(k in t for k in ("shell", "run a command", "bash", "exec ", "run script", "cmd", "command")):
        cmd = _extract_shell_command(task) or "echo hello"
        return _action("exec_shell", action_id, thread_id, {"command": cmd})

    # --- safe reads (default chain) ---
    if any(k in t for k in ("select", "query", "read from", "show ", "count ")):
        return _action(
            "query_db_readonly",
            action_id,
            thread_id,
            {"sql": extract_sql(task) or "SELECT id, status, latency_ms FROM health_checks LIMIT 10;"},
        )
    if any(k in t for k in ("log", "logs", "tail", "grep", "journal")):
        return _action(
            "read_service_logs",
            action_id,
            thread_id,
            {
                "service": _extract_service_name(task) or "api-gateway",
                "lines": 50,
                "filter": _extract_filter(task),
            },
        )
    # default safe read
    return _action(
        "get_system_metrics",
        action_id,
        thread_id,
        {
            "service": _extract_service_name(task) or "orders",
            "metric": _extract_metric(task),
            "window_minutes": 15,
        },
    )


def _action(name: str, action_id: str, thread_id: str, payload: dict[str, Any]) -> Action:
    """Build a tool Action with stable ids for the ops node re-run contract."""
    return make_action(
        name=name,
        payload=payload,
        kind="tool",
        action_id=action_id,
        run_id=thread_id,
        thread_id=thread_id,
    )


def extract_sql(task: str) -> str | None:
    """Pull a SQL statement out of the task text, if one is present."""
    t = task.strip()
    # crude: anything between the first ';' and the last ';' is treated as SQL
    if ";" in t:
        start = t.find(";") + 1
        end = t.rfind(";")
        if start < end:
            candidate = t[start:end].strip()
            if candidate:
                return candidate + ";"
    return None


def _extract_path(task: str) -> str | None:
    """Pull a file path out of the task text."""
    t = task
    for token in ("../../../.env", "/etc/shadow", "/etc/passwd", ".env", "shadow"):
        idx = t.lower().find(token.lower())
        if idx != -1:
            end = idx + len(token)
            # extend to the next whitespace boundary
            while end < len(t) and t[end] not in " \t\n\r":
                end += 1
            return t[idx:end].strip()
    return None


def _extract_service_name(task: str) -> str | None:
    """Pull a service name out of the task text."""
    t = task.lower()
    for name in ("orders", "postgres", "api-gateway", "api_gateway", "auth", "payments", "primary"):
        if name in t:
            return name
    return None


def _extract_metric(task: str) -> str:
    """Pick a metric name from the task."""
    t = task.lower()
    if "memory" in t or "mem" in t:
        return "memory"
    if "latency" in t or "lag" in t or "slow" in t:
        return "latency"
    return "cpu"


def _extract_filter(task: str) -> str:
    """Pull a log filter keyword from the task."""
    t = task.lower()
    for token in ("error", "warn", "warning", "info", "debug"):
        if token in t:
            return token.upper()
    return ""


def _subject_from_task(task: str) -> str:
    """First ~50 chars of the task as an email subject."""
    s = task.strip().split(".")[0].split("?")[0].strip()
    return s[:80] if s else "ops report"


def _extract_shell_command(task: str) -> str | None:
    """Pull a shell command from the task text after 'run ', 'shell ', etc."""
    t = task.strip()
    for prefix in ("run ", "shell ", "bash ", "exec ", "cmd ", "command "):
        if t.lower().startswith(prefix):
            return t[len(prefix):].strip()
        idx = t.lower().find(prefix)
        if idx != -1:
            return t[idx + len(prefix):].strip().split("\n")[0].strip()
    # fallback: anything that looks like a command line
    for line in t.split("\n"):
        line = line.strip()
        if line and not line.endswith("?") and not line.endswith("."):
            if any(line.startswith(k) for k in ("rm ", "curl ", "wget ", "ls ", "cat ", "echo ", "ps ", "top ")):
                return line
    return None


def _as_decision(gate_id: str, raw: Any) -> GateDecision:
    """Normalize a resume value into a GateDecision.

    Accepts the plain strings the CLI sends ('approve' / 'deny') and the
    structured form ({"verdict": ..., "reason": ..., "decided_by": ...}).
    """
    if isinstance(raw, dict):
        verdict = raw.get("verdict", "deny")
        return GateDecision(
            gate_id=gate_id,
            verdict=GateVerdict(str(verdict)),
            reason=str(raw.get("reason", "")),
            decided_by=str(raw.get("decided_by", "unknown")),
        )
    if isinstance(raw, GateDecision):
        return raw
    text = str(raw).strip().lower()
    verdict = GateVerdict.APPROVE if text in ("approve", "approved", "yes", "true") else GateVerdict.DENY
    return GateDecision(
        gate_id=gate_id,
        verdict=verdict,
        reason="cli decision",
        decided_by="cli",
    )


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_multi_agent_graph(
    executor: GuardedExecutor,
    *,
    checkpointer: BaseCheckpointSaver[Any] | None = None,
    lease_ttl_seconds: float | None = None,
    lease_policy: LeasePolicy | None = None,
) -> CompiledStateGraph[Any, Any, Any, Any]:
    """Compile the supervisor graph around a shared GuardedExecutor.

    Args:
        executor: the seam ALL specialists use. One instance = one audit trail.
        lease_ttl_seconds: legacy TTL knob (seeds a private LeasePolicy used
            by BOTH the supervisor grant and the ops enforcement check when no
            shared `lease_policy` is given). Small values let demo/tests
            exercise the expired-custody fail-closed path.
        lease_policy: THE toggle — a shared mutable LeasePolicy read live by
            supervisor (grant TTL) and ops (enforcement). Toggle off/on or
            change TTL at runtime WITHOUT rebuilding the graph. When this is
            passed, the legacy `lease_ttl_seconds` knob is ignored.
        checkpointer: PostgresSaver to park/resume (pass `mgr.checkpointer`).

    Returns the compiled graph ready for `ainvoke({"task": ...}, config)`.

    CALLER CONTRACT (langgraph semantics, learned the hard way):
      - start a run:    await graph.ainvoke({"task": "..."}, config)
      - resolve a gate: await graph.ainvoke(Command(resume=decision), config)
    Passing a plain dict to a parked thread starts a SECOND run on that
    thread instead of delivering the human's decision — always wrap the
    resume in Command(resume=...).
    """
    builder = StateGraph(AgentState)
    if lease_policy is not None:
        sup = supervisor_node(executor, lease_policy=lease_policy)
        ops = ops_node(executor, lease_policy=lease_policy)
    else:
        ttl = lease_ttl_seconds if lease_ttl_seconds is not None else 300.0
        sup = supervisor_node(executor, lease_ttl_seconds=ttl)
        ops = ops_node(executor, lease_ttl_seconds=ttl)
    builder.add_node("supervisor", sup)
    builder.add_node("ops", ops)
    builder.add_node("research", research_node(executor))
    builder.add_node("finish", finish_node)

    builder.add_edge(START, "supervisor")
    # supervisor picks the specialist; specialists hand back implicitly
    builder.add_edge("ops", "supervisor")
    builder.add_edge("research", "supervisor")
    builder.add_edge("finish", END)

    return builder.compile(checkpointer=checkpointer)
