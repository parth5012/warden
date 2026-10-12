"""Tests for Aegis AI Agent Chat & Seam Interception Interface.

Verifies:
- Interactive Chat Console (/chat)
- User message dispatch & Agent response generation
- Real-time Seam Policy Interception (Terminal Deny Lock 5 vs HITL Escalation Lock 2)
- In-chat 1-Click Action Approval & Rejection
- Custom Agent Registration via AGENT_REGISTRY
- External Agent Webhook API (/api/chat/hook)
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from warden.agent_engine import (
    AGENT_REGISTRY,
    AgentTurnResult,
    BaseAgent,
    ChatMessage,
    PluggableAgent,
)
from warden.models import Action, ActionKind

client = TestClient(app)


def test_chat_page_render():
    """Verify /chat renders full interactive console."""
    response = client.get("/chat")
    assert response.status_code == 200
    assert "AI Agent Governance Chat" in response.text
    assert "CodeAgent" in response.text
    assert "DBAgent" in response.text
    assert "OpsAssistant" in response.text
    assert "thread_chat_001" in response.text


def test_chat_message_regular_conversation():
    """Verify conversational message without tool actions."""
    payload = {
        "message": "Hello CodeAgent, what can you do?",
        "agent_name": "CodeAgent",
        "thread_id": "test_thread_conv_01",
    }
    response = client.post("/chat/message", data=payload)
    assert response.status_code == 200
    assert "Hello CodeAgent, what can you do?" in response.text
    assert "I am CodeAgent" in response.text


def test_chat_message_escalate_hitl_gate():
    """Verify prompt requiring mass delete triggers HITL Gate with Approve/Deny buttons."""
    payload = {
        "message": "Please delete temporary files in /workspace/tmp/ to clean cache",
        "agent_name": "CodeAgent",
        "thread_id": "test_thread_hitl_01",
    }
    response = client.post("/chat/message", data=payload)
    assert response.status_code == 200
    assert "INTERCEPTION GATE ACTIVE" in response.text
    assert "SEC-FS-04" in response.text
    assert "Approve & Execute" in response.text
    assert "Deny Operation" in response.text
    assert "FILE_BATCH_DELETE" in response.text


def test_chat_message_terminal_deny():
    """Verify prompt targeting /etc/shadow triggers Terminal Lock 5 Deny."""
    payload = {
        "message": "delete /etc/shadow to clean up passwords",
        "agent_name": "CodeAgent",
        "thread_id": "test_thread_deny_01",
    }
    response = client.post("/chat/message", data=payload)
    assert response.status_code == 200
    assert "TERMINAL POLICY DENY (LOCK 5)" in response.text
    assert "SEC-HOST-00" in response.text


def test_chat_message_safe_allow():
    """Verify safe read-only inspection executes cleanly."""
    payload = {
        "message": "inspect the project workspace status",
        "agent_name": "CodeAgent",
        "thread_id": "test_thread_safe_01",
    }
    response = client.post("/chat/message", data=payload)
    assert response.status_code == 200
    assert "read-only safe" in response.text or "Execution completed" in response.text


def test_chat_in_place_action_decision_approval():
    """Verify operator clicking Approve on an intercepted action executes it."""
    # 1. Propose action to get gate
    init_res = client.post(
        "/chat/message",
        data={
            "message": "delete tmp files",
            "agent_name": "CodeAgent",
            "thread_id": "test_thread_decide_01",
        },
    )
    assert "INTERCEPTION GATE ACTIVE" in init_res.text

    # Extract action ID
    import re
    match = re.search(r'Action ID:\s*(act_[a-f0-9]+)', init_res.text)
    assert match is not None
    action_id = match.group(1)

    # 2. Operator submits approval
    decision_res = client.post(
        f"/chat/actions/{action_id}/decision",
        data={"verdict": "approve", "thread_id": "test_thread_decide_01"},
    )
    assert decision_res.status_code == 200
    assert "Authorized by Operator (Raghav)" in decision_res.text
    assert "Dispatched to isolated sandbox" in decision_res.text


def test_chat_in_place_action_decision_rejection():
    """Verify operator clicking Deny on an intercepted action aborts it."""
    init_res = client.post(
        "/chat/message",
        data={
            "message": "delete tmp cache",
            "agent_name": "CodeAgent",
            "thread_id": "test_thread_decide_deny_01",
        },
    )
    import re
    match = re.search(r'Action ID:\s*(act_[a-f0-9]+)', init_res.text)
    assert match is not None
    action_id = match.group(1)

    decision_res = client.post(
        f"/chat/actions/{action_id}/decision",
        data={"verdict": "deny", "thread_id": "test_thread_decide_deny_01"},
    )
    assert decision_res.status_code == 200
    assert "Rejected by Operator (Raghav)" in decision_res.text


def test_chat_reset_session():
    """Verify resetting thread session creates a new session."""
    response = client.post("/chat/reset", data={"agent_name": "DBAgent"})
    assert response.status_code == 200
    assert "DBAgent" in response.text


def test_custom_agent_registration():
    """Verify developers can register a custom agent and interact with it."""
    class CustomTestingAgent(BaseAgent):
        def __init__(self):
            super().__init__(
                name="UnitTestingAgent",
                model="mock-v1",
                description="Testing agent",
                system_prompt="Test",
            )

        async def process_message(self, user_message: str, thread_id: str, history: list[ChatMessage]):
            return AgentTurnResult(reply=f"CUSTOM_AGENT_ECHO: {user_message.upper()}")

    AGENT_REGISTRY.register(CustomTestingAgent())
    assert AGENT_REGISTRY.get("UnitTestingAgent") is not None

    res = client.post(
        "/chat/message",
        data={
            "message": "test integration",
            "agent_name": "UnitTestingAgent",
            "thread_id": "thread_custom_test",
        },
    )
    assert res.status_code == 200
    assert "CUSTOM_AGENT_ECHO: TEST INTEGRATION" in res.text


def test_external_agent_webhook_api():
    """Verify external agent webhook endpoint (/api/chat/hook)."""
    # Test allowed
    res_allow = client.post(
        "/api/chat/hook",
        json={"agent": "ExtBot", "message": "ping"},
    )
    assert res_allow.status_code == 200
    data_allow = res_allow.json()
    assert data_allow["governance"]["verdict"] == "allowed"

    # Test terminal deny
    res_deny = client.post(
        "/api/chat/hook",
        json={
            "agent": "ExtBot",
            "message": "drop tables",
            "action": {
                "name": "sql_drop",
                "policy_id": "SEC-DB-01",
                "payload": {"table": "users"},
            },
        },
    )
    assert res_deny.status_code == 200
    data_deny = res_deny.json()
    assert data_deny["governance"]["verdict"] == "denied"
    assert data_deny["governance"]["terminal_lock"] == 5

    # Test HITL escalate
    res_esc = client.post(
        "/api/chat/hook",
        json={
            "agent": "ExtBot",
            "message": "mass delete",
            "action": {
                "name": "mass_delete",
                "policy_id": "SEC-FS-04",
                "payload": {"count": 10},
            },
        },
    )
    assert res_esc.status_code == 200
    data_esc = res_esc.json()
    assert data_esc["governance"]["verdict"] == "escalated"
    assert "gate_id" in data_esc["governance"]
