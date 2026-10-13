"""Chat escalations must surface in the Interception Gate (lock 3).

A `gate_requested` journal event feeds the approvals inbox, which is a pure
`events -> view` projection. Chat-tool escalations never touch the legacy
in-memory `PENDING_GATES` dict, so `/api/inbox`, `/inbox`, and the dashboard
pending panel must read the journal projection.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from app.main import app
from backend.api import llm as llm_api
from warden.llm.types import LLMRequest

client = TestClient(app)


@pytest.fixture(autouse=True)
def fake_guarded_llm_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    async def provider(request: LLMRequest) -> dict[str, object]:
        return {
            "id": "inbox-test-response",
            "choices": [{"message": {"content": "Inbox test assistant reply."}}],
            "usage": {"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12},
        }

    monkeypatch.setattr(llm_api._client, "provider_caller", provider)


def test_chat_escalation_appears_in_interception_gate() -> None:
    thread = "thr_inbox_gate_01"
    res = client.post(
        "/chat/message",
        data={
            "message": "send the weekly report to ops-team@example.com",
            "agent_name": "OpsAssistant",
            "thread_id": thread,
        },
    )
    assert res.status_code == 200
    match = re.search(r"Action ID:\s*(act_[a-f0-9]+)", res.text)
    assert match is not None
    action_id = match.group(1)

    inbox = client.get("/api/inbox")
    assert inbox.status_code == 200
    gates = inbox.json().get("pending_gates", [])
    journal_hits = [g for g in gates if g.get("action_id") == action_id]
    assert journal_hits, "chat escalation missing from /api/inbox journal projection"
    assert journal_hits[0]["thread_id"] == thread

    page = client.get("/inbox")
    assert page.status_code == 200
    assert action_id in page.text
    assert "Pending tool approvals" in page.text

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert action_id in dashboard.text or "send_email" in dashboard.text


def test_resolved_chat_gate_leaves_interception_gate() -> None:
    thread = "thr_inbox_gate_02"
    res = client.post(
        "/chat/message",
        data={
            "message": "send the weekly report to ops-team@example.com",
            "agent_name": "OpsAssistant",
            "thread_id": thread,
        },
    )
    assert res.status_code == 200
    match = re.search(r"Action ID:\s*(act_[a-f0-9]+)", res.text)
    assert match is not None
    action_id = match.group(1)

    decision = client.post(
        f"/chat/actions/{action_id}/decision",
        data={"verdict": "approve", "thread_id": thread},
    )
    assert decision.status_code == 200

    inbox = client.get("/api/inbox")
    assert inbox.status_code == 200
    gates = inbox.json().get("pending_gates", [])
    assert all(g.get("action_id") != action_id for g in gates)


def test_journal_gate_resolves_from_api() -> None:
    thread = "thr_inbox_gate_03"
    res = client.post(
        "/chat/message",
        data={
            "message": "send the weekly report to ops-team@example.com",
            "agent_name": "OpsAssistant",
            "thread_id": thread,
        },
    )
    assert res.status_code == 200
    match = re.search(r"Action ID:\s*(act_[a-f0-9]+)", res.text)
    assert match is not None
    action_id = match.group(1)

    inbox = client.get("/api/inbox")
    gates = inbox.json().get("pending_gates", [])
    hit = next(g for g in gates if g.get("action_id") == action_id)
    resolve = client.post(
        f"/api/inbox/{hit['id']}/resolve", json={"decision": "deny"}
    )
    assert resolve.status_code == 200
    body = resolve.json()
    assert body["status"] == "resolved"
    assert body["outcome"] == "denied"

    inbox = client.get("/api/inbox")
    gates = inbox.json().get("pending_gates", [])
    assert all(g.get("action_id") != action_id for g in gates)


def test_tool_gate_resolves_from_inbox_page() -> None:
    thread = "thr_inbox_gate_04"
    res = client.post(
        "/chat/message",
        data={
            "message": "send the weekly report to ops-team@example.com",
            "agent_name": "OpsAssistant",
            "thread_id": thread,
        },
    )
    assert res.status_code == 200
    match = re.search(r"Action ID:\s*(act_[a-f0-9]+)", res.text)
    assert match is not None
    action_id = match.group(1)

    inbox = client.get("/api/inbox")
    gates = inbox.json().get("pending_gates", [])
    hit = next(g for g in gates if g.get("action_id") == action_id)

    page = client.post(
        f"/inbox/tool/{hit['id']}/resolve",
        data={"decision": "deny", "approver": "alice"},
    )
    assert page.status_code == 200
    assert "DENIED" in page.text

    inbox = client.get("/api/inbox")
    gates = inbox.json().get("pending_gates", [])
    assert all(g.get("action_id") != action_id for g in gates)

    bad = client.post(
        f"/inbox/tool/{hit['id']}/resolve",
        data={"decision": "approve", "approver": "alice"},
    )
    assert bad.status_code == 404
