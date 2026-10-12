"""Live SSE streaming tests.

Layers covered:
- Pure SSE formatter: keepalive, id/event/data folding, retry frame, parse-back
- Bus as JournalSink: fan-out to subscribers, tag/monotonic ids, history
  catch-up for late subscribers, bounded-queue drop policy, unsubscribe sentinel
- Endpoint (FastAPI) via SAME-LOOP httpx ASGITransport: real frames on the
  wire during a live run driven through the GuardedExecutor seam
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from langgraph.types import Command

from warden.seam import GuardedExecutor
from warden.streaming import (
    WardenJournalBus,
    parse_sse_frame,
    sse_format,
    sse_frame_retry,
)

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def _fresh() -> str:
    return uuid.uuid4().hex[:8]


# ---------------------------------------------------------------------------
# Pure SSE formatting
# ---------------------------------------------------------------------------


def test_keepalive_form() -> None:
    assert sse_format(None) == b": keepalive\n\n"


def test_frame_shape_and_roundtrip() -> None:
    frame = sse_format({"k": "v"}, event="journal", id_=7)
    text = frame.decode()
    assert text.startswith("event: journal\n")
    assert "id: 7\n" in text
    assert text.endswith('data: {"k":"v"}\n\n')
    parsed = parse_sse_frame(frame)
    assert parsed == {"event": "journal", "id": 7, "data": {"k": "v"}}


def test_multi_line_json_folded_to_single_data_line() -> None:
    frame = sse_format({"text": "line1\nline2"}, event="journal")
    lines = frame.decode().split("\n")
    data_lines = [ln for ln in lines if ln.startswith("data: ")]
    assert len(data_lines) == 1
    assert "line1\\nline2" in data_lines[0]  # folded inside JSON, not SSE framing


def test_retry_frame() -> None:
    assert parse_sse_frame(sse_frame_retry(5000)) == {"retry": 5000}


# ---------------------------------------------------------------------------
# Bus: JournalSink + fan-out + history + bounds
# ---------------------------------------------------------------------------


async def test_bus_is_a_valid_journal_sink_for_the_seam() -> None:
    bus = WardenJournalBus()
    executor = GuardedExecutor(journal=bus)
    from warden.models import Action, ActionKind

    action = Action(
        id="a1", kind=ActionKind.TOOL, name="list", payload={}, run_id="r1", thread_id="t"
    )
    await executor.execute(action)
    events = [e.event for e in bus.history()]
    assert events == ["action_requested", "action_completed"]
    ids = [e.id for e in bus.history()]
    assert ids == sorted(ids)  # monotonic


async def test_subscriber_receives_live_events() -> None:
    bus = WardenJournalBus()
    sub = await bus.subscribe(with_history=False)
    stream = bus.sse_stream(sub)
    await bus.append("gate_requested", {"gate_id": "g1"})
    first = await asyncio.wait_for(stream.__anext__(), timeout=2.0)
    parsed = parse_sse_frame(first)
    assert parsed["event"] == "journal"
    assert parsed["data"]["payload"] == {"gate_id": "g1"}
    await bus.unsubscribe(sub)


async def test_late_subscriber_catches_up_from_history_then_live() -> None:
    bus = WardenJournalBus()
    await bus.append("action_requested", {"n": 1})
    await bus.append("action_completed", {"n": 1})
    sub = await bus.subscribe(with_history=True)
    stream = bus.sse_stream(sub)
    seen = parse_sse_frame(await stream.__anext__())
    assert seen["data"]["payload"] == {"n": 1}
    second = parse_sse_frame(await stream.__anext__())
    assert second["data"]["event"] == "action_completed"
    await bus.unsubscribe(sub)


async def test_bounded_queue_drops_oldest_not_sentinel() -> None:
    bus = WardenJournalBus(queue_size=2)
    sub = await bus.subscribe(with_history=False)
    for i in range(5):
        await bus.append("e", {"i": i})
    # Drain everything the subscriber got.
    stream = bus.sse_stream(sub)
    got: list[int] = []
    while True:
        try:
            frame = await asyncio.wait_for(stream.__anext__(), timeout=0.5)
        except asyncio.TimeoutError:
            break
        data = parse_sse_frame(frame)["data"]
        got.append(data["payload"]["i"])
    assert got == [3, 4], f"drop-oldest must keep newest, got {got}"
    await bus.unsubscribe(sub)


async def test_unsubscribe_ends_stream_with_retry_frame() -> None:
    bus = WardenJournalBus()
    sub = await bus.subscribe(with_history=False)
    # Subscribe BEFORE unsubscribing so the sentinel is queued: unsubscribe
    # removes the subscriber map entry first, so the stream must grab its
    # queue reference up front (it does, at generator start) like a live
    # client that is connected when the server tears the feed down.
    stream = bus.sse_stream(sub)
    started: asyncio.Task[bytes] = asyncio.create_task(
        stream.__anext__()  # type: ignore[arg-type]  # generator-asend coroutine
    )  # generator entered
    await asyncio.sleep(0.01)  # let the generator start and register
    await bus.unsubscribe(sub)
    frame = await asyncio.wait_for(started, timeout=2.0)
    parsed = parse_sse_frame(frame)
    assert parsed.get("retry") == 3000


async def test_keepalive_on_idle_timeout() -> None:
    bus = WardenJournalBus()
    sub = await bus.subscribe(with_history=False)
    stream = bus.sse_stream(sub, keepalive_interval=0.05)
    started: asyncio.Task[bytes] = asyncio.create_task(
        stream.__anext__()  # type: ignore[arg-type]  # generator-asend coroutine
    )
    frame = await asyncio.wait_for(started, timeout=2.0)
    assert frame == b": keepalive\n\n"
    await bus.unsubscribe(sub)


# ---------------------------------------------------------------------------
# Endpoint: same-loop ASGITransport (asyncio queues are loop-bound)
# ---------------------------------------------------------------------------


def _build_test_app(bus: WardenJournalBus) -> Any:
    """The real /stream route over a test bus — no PG lifespan attached.

    The production app's lifespan spins pgserver; the FEED contract is
    bus-backed, so the endpoint test binds the same route to a plain bus.
    """
    from fastapi import FastAPI
    from fastapi.responses import StreamingResponse

    test_app = FastAPI()

    @test_app.get("/stream")
    async def stream(with_history: bool = True) -> StreamingResponse:
        sub_id = await bus.subscribe(with_history=with_history)

        async def running_feed() -> AsyncIterator[bytes]:
            try:
                async for frame in bus.sse_stream(sub_id):
                    yield frame
            finally:
                await bus.unsubscribe(sub_id)

        return StreamingResponse(
            running_feed(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    return test_app


async def test_stream_endpoint_yields_frames_for_seam_events_via_asgi() -> None:
    """Real HTTP framing without a socket: httpx ASGITransport, same loop.

    Deterministic protocol: publish the two events first, THEN connect —
    the feed replays... no, with_history=False would miss them, so instead:
    connect, wait for the first live frame, unsubscribe via close_all from
    the writer task, and ensure the HTTP stream terminates cleanly.
    """
    bus = WardenJournalBus()
    test_app = _build_test_app(bus)

    async def live(bus: WardenJournalBus = bus) -> None:
        await asyncio.sleep(0.05)
        await bus.append("action_requested", {"actor": "ops"})
        await bus.append("action_completed", {"actor": "ops"})
        await asyncio.sleep(0.05)  # let the client consume both frames
        await bus.close_all()  # ends the running feed -> HTTP stream closes

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=test_app), base_url="http://test"
    ) as client:
        task = asyncio.create_task(live())
        chunks: list[bytes] = []
        async with client.stream("GET", "/stream?with_history=false") as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            async for chunk in resp.aiter_bytes():
                if chunk:
                    chunks.append(chunk)
        await task
    joined = b"".join(chunks)
    assert b"event: journal" in joined
    assert b"action_requested" in joined
    assert b"action_completed" in joined
    assert b"retry: 3000" in joined  # clean end-of-stream from the sentinel


# ---------------------------------------------------------------------------
# E2E: a governed run's journal flows to a wire subscriber (real bus only)
# ---------------------------------------------------------------------------


async def test_full_run_events_flow_to_subscriber() -> None:
    """Run the governed demo actions through the seam; subscriber sees each."""
    bus = WardenJournalBus()
    executor = GuardedExecutor(journal=bus)

    sub = await bus.subscribe(with_history=False)
    stream = bus.sse_stream(sub)
    # Pull frames in a bounded way: consume exactly N frames via anext tasks
    # (the generator starts on first anext, grabbing its queue reference).

    from warden.models import Action, ActionKind

    # deny path: terminal, journals requested+denied
    from warden.seam import SequencingPolicy

    executor._policy = SequencingPolicy(deny_names=frozenset({"db_write"}))  # noqa: SLF001
    action = Action(
        id="a2", kind=ActionKind.TOOL, name="db_write",
        payload={"query": "DROP TABLE"}, run_id="r2", thread_id="t",
    )
    await executor.execute(action)
    got: list[str] = []
    for _ in range(2):
        frame = await asyncio.wait_for(stream.__anext__(), timeout=2.0)
        got.append(parse_sse_frame(frame)["data"]["event"])
    assert got == ["action_requested", "action_denied"]
    await bus.unsubscribe(sub)
