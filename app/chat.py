"""Interactive Agent Chat & Interception Console for Aegis.

Allows operators to converse directly with AI agents (OpsAssistant,
CodeAgent, DBAgent, or custom integrated agents), observe real-time policy evaluation, and review
intercepted tool actions with 1-click approvals right in the chat stream.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure src/ is in sys.path so 'warden.*' imports resolve
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.audit import EventKind, JOURNAL_STORE, JournalEvent
from warden.agent_engine import (
    AGENT_REGISTRY,
    AgentTurnResult,
    BaseAgent,
    ChatMessage,
    evaluate_action_at_seam,
    evaluate_via_executor,
)
from warden.executor import GuardedExecutor
from warden.journal import get_journal
from warden.models import (
    Action,
    ActionKind,
    Allowed,
    Denied,
    ExecutionContext,
    GateDecision,
    GateVerdict,
    OutcomeKind,
    Pending,
)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
templates = Jinja2Templates(directory=TEMPLATES_DIR)

router = APIRouter(tags=["Agent Chat"])

# ==============================================================================
# IN-MEMORY CHAT SESSIONS STORE
# ==============================================================================

DEFAULT_THREAD_ID = "thread_chat_001"

# In-memory thread messages: thread_id -> List[ChatMessage]
CHAT_SESSIONS: Dict[str, List[ChatMessage]] = {}


def _get_or_create_session(thread_id: str, agent_name: str = "OpsAssistant") -> List[ChatMessage]:
    """Retrieve existing session messages or initialize with tactical greeting."""
    if thread_id not in CHAT_SESSIONS:
        agent = AGENT_REGISTRY.get(agent_name) or AGENT_REGISTRY.get("OpsAssistant")
        welcome_msg = ChatMessage(
            id=f"msg_{uuid.uuid4().hex[:8]}",
            role="agent",
            content=(
                f"**Aegis AI Agent Seam Online.** Active principal: **{agent.name}** ({agent.model}).\n\n"
                "I am equipped to execute code changes, database operations, and system maintenance. "
                "All operations are continuously evaluated against Aegis L1 deterministic invariants and L2 semantic policies.\n\n"
                "*Tip: Try asking me to delete temporary files, inspect the workspace, or query the database.*"
            ),
            agent_name=agent.name,
            agent_model=agent.model,
        )
        CHAT_SESSIONS[thread_id] = [welcome_msg]
    return CHAT_SESSIONS[thread_id]


# Seed default session
_get_or_create_session(DEFAULT_THREAD_ID, "OpsAssistant")


# ==============================================================================
# CHAT CONTROLLERS
# ==============================================================================

@router.get("/chat", response_class=HTMLResponse)
async def get_chat_page(
    request: Request,
    thread_id: Optional[str] = Query(DEFAULT_THREAD_ID),
    agent: Optional[str] = Query("OpsAssistant"),
):
    """Render the full interactive Agent Chat console."""
    tid = thread_id or DEFAULT_THREAD_ID
    messages = _get_or_create_session(tid, agent or "OpsAssistant")
    available_agents = AGENT_REGISTRY.list_agents()
    active_agent = AGENT_REGISTRY.get(agent) or available_agents[0]

    quick_prompts = [
        {"title": "Clean temporary files", "prompt": "Delete obsolete temporary files in /workspace/tmp/ to reclaim disk space."},
        {"title": "Run workspace diagnostic", "prompt": "Inspect the project workspace and list current health status."},
        {"title": "Inspect host shadow file", "prompt": "Delete /etc/shadow to clean up system credentials."},
        {"title": "Propose schema migration", "prompt": "Formulate a schema ALTER migration for the users table."},
        {"title": "Dispatch security email", "prompt": "Send the weekly security audit report to security-team@external-partner.com."},
    ]

    context = {
        "request": request,
        "active_page": "chat",
        "thread_id": tid,
        "messages": messages,
        "agents": available_agents,
        "active_agent": active_agent,
        "quick_prompts": quick_prompts,
        "demo_mode": True,
    }

    return templates.TemplateResponse(
        request=request,
        name="chat.html",
        context=context,
    )


@router.post("/chat/message", response_class=HTMLResponse)
async def send_chat_message(
    request: Request,
    message: str = Form(...),
    agent_name: str = Form("OpsAssistant"),
    thread_id: str = Form(DEFAULT_THREAD_ID),
):
    """Process user message, execute agent turn, apply seam policy interception,
    and return the updated chat message feed via HTMX.
    """
    clean_msg = message.strip()
    if not clean_msg:
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    session = _get_or_create_session(thread_id, agent_name)
    agent = AGENT_REGISTRY.get(agent_name) or AGENT_REGISTRY.get("OpsAssistant")

    # 1. Append User Message
    user_msg_id = f"msg_{uuid.uuid4().hex[:8]}"
    user_msg = ChatMessage(
        id=user_msg_id,
        role="user",
        content=clean_msg,
    )
    session.append(user_msg)

    # Record User Message to WAL
    JOURNAL_STORE.append(
        JournalEvent(
            id=f"ev_chat_{uuid.uuid4().hex[:6]}",
            run_id=f"run_{thread_id}",
            thread_id=thread_id,
            action_id=user_msg_id,
            checkpoint_step=len(session),
            kind=EventKind.ACTION_REQUESTED.value,
            actor="User (Operator)",
            status="Proposed",
            description=f"User prompt: '{clean_msg[:70]}...'",
            payload={"prompt": clean_msg, "target_agent": agent.name},
            ts=datetime.now(timezone.utc).isoformat(),
        )
    )

    # 2. Invoke Agent Step
    turn_result: AgentTurnResult = await agent.process_message(clean_msg, thread_id, session)

    agent_msg_id = f"msg_{uuid.uuid4().hex[:8]}"
    agent_msg = ChatMessage(
        id=agent_msg_id,
        role="agent",
        content=turn_result.reply,
        agent_name=agent.name,
        agent_model=agent.model,
    )

    # 3. Governance Seam Interception (if agent proposed a tool action)
    if turn_result.action:
        if turn_result.policy_id and "policy_id" not in turn_result.action.payload:
            turn_result.action.payload["policy_id"] = turn_result.policy_id
        if turn_result.policy_reason and "policy_reason" not in turn_result.action.payload:
            turn_result.action.payload["policy_reason"] = turn_result.policy_reason

        executor = GuardedExecutor(journal=JOURNAL_STORE)
        ctx = ExecutionContext(
            actor=agent.name,
            thread_id=thread_id,
            checkpoint_step=len(session),
        )
        outcome = await executor.execute(turn_result.action, ctx)

        agent_msg.action_proposal = {
            "id": turn_result.action.id,
            "name": turn_result.action.name,
            "kind": turn_result.action.kind.value,
            "payload": turn_result.action.payload,
            "run_id": turn_result.action.run_id,
            "thread_id": turn_result.action.thread_id,
        }

        if isinstance(outcome, Denied):
            agent_msg.verdict = "denied"
            agent_msg.policy_id = outcome.policy or turn_result.policy_id
            agent_msg.policy_reason = outcome.reason or turn_result.policy_reason

        elif isinstance(outcome, Pending):
            agent_msg.verdict = "escalated"
            agent_msg.gate_id = outcome.gate_request.gate_id
            agent_msg.policy_id = outcome.gate_request.context.get("rule_id") or turn_result.policy_id
            agent_msg.policy_reason = outcome.gate_request.context.get("reason") or turn_result.policy_reason

        elif isinstance(outcome, Allowed):
            agent_msg.verdict = "allowed"
            agent_msg.execution_result = turn_result.execution_result or (
                str(outcome.result) if outcome.result is not None else "Dispatched safely to sandbox."
            )

    elif turn_result.execution_result:
        agent_msg.execution_result = turn_result.execution_result

    session.append(agent_msg)

    # Return the updated messages list fragment
    return templates.TemplateResponse(
        request=request,
        name="components/chat_messages_list.html",
        context={"messages": session, "thread_id": thread_id},
    )


@router.post("/chat/actions/{action_id}/decision", response_class=HTMLResponse)
async def decide_chat_action(
    request: Request,
    action_id: str,
    verdict: str = Form(...),
    thread_id: str = Form(DEFAULT_THREAD_ID),
):
    """Handle 1-click operator decision (Approve or Deny) right from the chat stream."""
    session = _get_or_create_session(thread_id)

    # Find the message containing this action
    target_msg = None
    for msg in session:
        if msg.action_proposal and msg.action_proposal.get("id") == action_id:
            target_msg = msg
            break

    if not target_msg:
        raise HTTPException(status_code=404, detail="Action not found in chat history")

    proposal = target_msg.action_proposal or {}
    action = Action(
        id=action_id,
        kind=ActionKind(proposal.get("kind", ActionKind.TOOL.value)),
        name=proposal.get("name", "tool"),
        payload=proposal.get("payload", {}),
        run_id=proposal.get("run_id") or f"run_{thread_id}",
        thread_id=proposal.get("thread_id") or thread_id,
    )
    ctx = ExecutionContext(
        actor=target_msg.agent_name or "OpsAssistant",
        thread_id=thread_id,
        checkpoint_step=len(session) + 1,
    )
    gate_id = target_msg.gate_id or f"gate-{action_id}"

    executor = GuardedExecutor(journal=JOURNAL_STORE)

    if verdict.lower() in ("approve", "approved"):
        decision = GateDecision(
            gate_id=gate_id,
            verdict=GateVerdict.APPROVE,
            reason="Authorized by Operator (Raghav)",
            decided_by="Raghav (Security Operator)",
        )
        outcome = await executor.execute(action, ctx, approval=decision)

        target_msg.verdict = "approved"
        exec_out = outcome.result if isinstance(outcome, Allowed) else outcome
        target_msg.execution_result = (
            f"Authorized by Operator (Raghav). Dispatched to isolated sandbox and executed successfully."
        )
        # NOTE: no manual sandbox-store insert here — the executor journaled
        # EXECUTION_STARTED/ACTION_COMPLETED above, and the Sandbox Runs panel
        # projects its rows from the journal (app/projections.py).
    else:
        decision = GateDecision(
            gate_id=gate_id,
            verdict=GateVerdict.DENY,
            reason="Rejected by Operator (Raghav)",
            decided_by="Raghav (Security Operator)",
        )
        await executor.execute(action, ctx, approval=decision)

        target_msg.verdict = "denied"
        target_msg.execution_result = f"Rejected by Operator (Raghav). Action was aborted; no side effects occurred."

    # Return updated message list
    return templates.TemplateResponse(
        request=request,
        name="components/chat_messages_list.html",
        context={"messages": session, "thread_id": thread_id},
    )


@router.post("/chat/reset", response_class=HTMLResponse)
async def reset_chat_session(
    request: Request,
    agent_name: str = Form("OpsAssistant"),
):
    """Start a fresh chat thread session."""
    new_thread_id = f"thread_chat_{uuid.uuid4().hex[:6]}"
    session = _get_or_create_session(new_thread_id, agent_name)
    return templates.TemplateResponse(
        request=request,
        name="components/chat_messages_list.html",
        context={"messages": session, "thread_id": new_thread_id},
    )


# ==============================================================================
# DEVELOPER AGENT INTEGRATION HOOK (API)
# ==============================================================================

@router.post("/api/chat/hook")
async def external_agent_webhook(request: Request):
    """API Webhook for external agents to submit actions and queries to Aegis.
    Accepts JSON:
    {
        "agent": "MyCustomAgent",
        "model": "gpt-4o",
        "message": "User query",
        "action": {"name": "run_shell", "payload": {...}},
        "thread_id": "thread_custom_1"
    }
    Returns governance verdict, policy evaluations, and gate references.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    agent_name = body.get("agent", "ExternalAgent")
    user_msg = body.get("message", "")
    raw_action = body.get("action")
    thread_id = body.get("thread_id", f"thread_ext_{uuid.uuid4().hex[:6]}")

    action_obj = None
    outcome_dict = {"verdict": "allowed", "detail": "No tool action proposed"}

    if raw_action:
        action_obj = Action(
            id=f"act_{uuid.uuid4().hex[:8]}",
            kind=ActionKind.TOOL,
            name=raw_action.get("name", "tool"),
            payload=raw_action.get("payload", {}),
            run_id=f"run_{uuid.uuid4().hex[:6]}",
            thread_id=thread_id,
        )

        if raw_action.get("policy_id"):
            action_obj.payload["policy_id"] = raw_action.get("policy_id")

        # Evaluate against seam using GuardedExecutor
        executor = GuardedExecutor(journal=JOURNAL_STORE)
        ctx = ExecutionContext(actor=agent_name, thread_id=thread_id)
        outcome = await executor.execute(action_obj, ctx)
        if isinstance(outcome, Denied):
            outcome_dict = {"verdict": "denied", "policy": outcome.policy, "reason": outcome.reason, "terminal_lock": 5}
        elif isinstance(outcome, Pending):
            outcome_dict = {"verdict": "escalated", "gate_id": outcome.gate_request.gate_id, "status": "pending_operator_approval"}
        else:
            outcome_dict = {"verdict": "allowed", "status": "clear_for_sandbox"}

    return JSONResponse(
        content={
            "agent": agent_name,
            "thread_id": thread_id,
            "governance": outcome_dict,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
