"""Checkpoint system tests against real PostgreSQL.

Covers: setup idempotency, park/resume, crash-restart recovery,
state inspection, history, fail-closed behaviour, health checks.
"""

from __future__ import annotations

import uuid

import pytest
from langchain_core.runnables import RunnableConfig

from warden.checkpoint import CheckpointManager
from warden.demo_graph import build_demo_graph
from warden.models import CheckpointInfo, Error


def _config(thread_id: str) -> RunnableConfig:
    return {"configurable": {"thread_id": thread_id}}


def _fresh_thread() -> str:
    return f"test-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


async def test_create_setup_is_idempotent(pg_uri: str) -> None:
    """setup() runs on every boot — running it twice must not fail."""
    async with CheckpointManager.create(pg_uri) as mgr:
        assert mgr.is_healthy
    async with CheckpointManager.create(pg_uri) as mgr2:
        assert mgr2.is_healthy


async def test_checkpointer_unavailable_outside_context(pg_uri: str) -> None:
    """Accessing .checkpointer outside `async with` raises (programming error)."""
    mgr = CheckpointManager(pg_uri)
    with pytest.raises(RuntimeError, match="not initialised"):
        _ = mgr.checkpointer


async def test_health_check_true_when_open(pg_uri: str) -> None:
    async with CheckpointManager.create(pg_uri) as mgr:
        assert await mgr.health_check() is True


async def test_create_raises_on_bad_connection() -> None:
    """Startup fail-closed: no Postgres -> raise, do not run the graph."""
    with pytest.raises(Exception):
        async with CheckpointManager.create(
            "postgresql://postgres:@/postgres?host=/nonexistent-warden-dir"
        ):
            pass


# ---------------------------------------------------------------------------
# Park / resume (the HITL core)
# ---------------------------------------------------------------------------


async def test_interrupt_parks_then_resume_completes(pg_uri: str) -> None:
    thread_id = _fresh_thread()
    config = _config(thread_id)

    async with CheckpointManager.create(pg_uri) as mgr:
        graph = build_demo_graph(mgr.checkpointer)

        # 1. Start -> parks at approval interrupt
        result = await graph.ainvoke({"messages": []}, config)
        assert "__interrupt__" in result, "graph must park at interrupt()"
        interrupt_value = result["__interrupt__"][0].value
        assert interrupt_value["action"] == "send_email"

        # 2. Inspection sees the parked state
        info = await mgr.get_state_info(graph, config)
        assert isinstance(info, CheckpointInfo)
        assert info.thread_id == thread_id
        assert info.has_pending_interrupts is True
        assert info.pending_interrupt_values == [interrupt_value]

        # 3. Resume with human decision -> graph completes
        resumed = await mgr.resume(graph, config, "approve")
        assert not isinstance(resumed, Error)
        assert resumed["approved"] is True
        assert any("sent" in m for m in resumed["messages"])

        # 4. No interrupts left
        info2 = await mgr.get_state_info(graph, config)
        assert isinstance(info2, CheckpointInfo)
        assert info2.has_pending_interrupts is False


async def test_resume_with_deny_aborts(pg_uri: str) -> None:
    thread_id = _fresh_thread()
    config = _config(thread_id)

    async with CheckpointManager.create(pg_uri) as mgr:
        graph = build_demo_graph(mgr.checkpointer)
        result = await graph.ainvoke({"messages": []}, config)
        assert "__interrupt__" in result

        resumed = await mgr.resume(graph, config, "deny")
        assert not isinstance(resumed, Error)
        assert resumed["approved"] is False
        assert any("NOT sent" in m for m in resumed["messages"])


async def test_resume_is_idempotent_per_decision(pg_uri: str) -> None:
    """Re-running the parked node on resume must not duplicate prior output.

    draft_node ran BEFORE the interrupt; its message must appear exactly
    once after resume (LangGraph resumes from the checkpoint, it does not
    re-execute completed nodes).
    """
    thread_id = _fresh_thread()
    config = _config(thread_id)

    async with CheckpointManager.create(pg_uri) as mgr:
        graph = build_demo_graph(mgr.checkpointer)
        await graph.ainvoke({"messages": []}, config)
        resumed = await mgr.resume(graph, config, "approve")
        assert not isinstance(resumed, Error)
        drafts = [m for m in resumed["messages"] if m.startswith("Drafted")]
        assert len(drafts) == 1


# ---------------------------------------------------------------------------
# Crash / restart recovery (kill -9 mid-park)
# ---------------------------------------------------------------------------


async def test_state_survives_manager_restart(pg_uri: str) -> None:
    """Park, close everything (simulated kill), reopen, resume — must work."""
    thread_id = _fresh_thread()
    config = _config(thread_id)

    # Phase 1: park, then tear down completely
    async with CheckpointManager.create(pg_uri) as mgr:
        graph = build_demo_graph(mgr.checkpointer)
        result = await graph.ainvoke({"messages": []}, config)
        assert "__interrupt__" in result

    # Phase 2: fresh manager + freshly compiled graph, same thread_id
    async with CheckpointManager.create(pg_uri) as mgr2:
        graph2 = build_demo_graph(mgr2.checkpointer)

        info = await mgr2.get_state_info(graph2, config)
        assert isinstance(info, CheckpointInfo)
        assert info.has_pending_interrupts is True, (
            "parked state must survive process restart"
        )

        resumed = await mgr2.resume(graph2, config, "approve")
        assert not isinstance(resumed, Error)
        assert resumed["approved"] is True


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------


async def test_state_history_walk(pg_uri: str) -> None:
    thread_id = _fresh_thread()
    config = _config(thread_id)

    async with CheckpointManager.create(pg_uri) as mgr:
        graph = build_demo_graph(mgr.checkpointer)
        await graph.ainvoke({"messages": []}, config)
        await mgr.resume(graph, config, "approve")

        history = await mgr.get_state_history(graph, config)
        assert isinstance(history, list)
        assert len(history) >= 2, "history must contain park + post-resume steps"
        # Contract: oldest first — steps must be non-decreasing
        steps = [info.step for info in history]
        assert steps == sorted(steps), f"history not oldest-first: {steps}"
        # Newest (last) checkpoint has no pending interrupts
        assert history[-1].has_pending_interrupts is False


# ---------------------------------------------------------------------------
# Fail-closed (lock 4): environmental failures return Error, never raise
# ---------------------------------------------------------------------------


async def test_state_info_fail_closed_after_close(pg_uri: str) -> None:
    """With the connection pool closed, inspection returns Error — no raise."""
    thread_id = _fresh_thread()
    config = _config(thread_id)

    async with CheckpointManager.create(pg_uri) as mgr:
        graph = build_demo_graph(mgr.checkpointer)
        await graph.ainvoke({"messages": []}, config)

    # Manager closed -> underlying connection dead
    err = await mgr.get_state_info(graph, config)
    assert isinstance(err, Error)
    assert err.reason == "governance_unavailable"


async def test_resume_fail_closed_after_close(pg_uri: str) -> None:
    thread_id = _fresh_thread()
    config = _config(thread_id)

    async with CheckpointManager.create(pg_uri) as mgr:
        graph = build_demo_graph(mgr.checkpointer)
        await graph.ainvoke({"messages": []}, config)

    err = await mgr.resume(graph, config, "approve")
    assert isinstance(err, Error)
    assert err.reason == "governance_unavailable"


async def test_history_fail_closed_after_close(pg_uri: str) -> None:
    thread_id = _fresh_thread()
    config = _config(thread_id)

    async with CheckpointManager.create(pg_uri) as mgr:
        graph = build_demo_graph(mgr.checkpointer)
        await graph.ainvoke({"messages": []}, config)

    err = await mgr.get_state_history(graph, config)
    assert isinstance(err, Error)
    assert err.reason == "governance_unavailable"


# ---------------------------------------------------------------------------
# Redaction (checkpoint.py)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("conn_string", "expected"),
    [
        # normal URI: userinfo fully masked
        (
            "postgresql://alice:s3cret@host:5432/db",
            "postgresql://***@host:5432/db",
        ),
        # malformed password containing '@' — whole userinfo must vanish
        ("postgresql://user:p@ss@host/db", "postgresql://***@host/db"),
        # keyword DSN: password masked
        (
            "host=db.example.com port=5432 password=secret user=app",
            "host=db.example.com port=5432 password=*** user=app",
        ),
        # quoted keyword password
        (
            "host=/tmp/sock password='my pass' dbname=app",
            "host=/tmp/sock password=*** dbname=app",
        ),
        # '@' in query string, no userinfo — untouched
        ("postgresql://host/db?opt=a@b", "postgresql://host/db?opt=a@b"),
        # userinfo without password
        ("postgresql://user@host/db", "postgresql://***@host/db"),
    ],
)
def test_redact_masks_credentials(conn_string: str, expected: str) -> None:
    from warden.checkpoint import _redact

    assert _redact(conn_string) == expected
