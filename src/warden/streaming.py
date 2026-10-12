"""Live streaming — the journal bus feeding the dashboard over SSE.

Yash's "live SSE streaming" task. Design, honoring the locked architecture
(ARCHITECTURE.md §3, lock 3 — the journal is the source of truth):

- **One seam, one feed.** `WardenJournalBus.append(event, payload)` is a
  `JournalSink` (the exact interface `GuardedExecutor` already journals
  through). Pass the bus as the seam's journal and every write-ahead
  intent / decision / completion instantly becomes a live dashboard feed —
  no second telemetry path (lock 1).
- **Fan-out, never blocking the run.** `append` mirrors events into each
  subscriber's bounded queue; a slow dashboard client drops its own oldest
  events (overflow policy) rather than stalling the agent.
- **SSE formatting is pure** (`sse_format`, `sse_stream`): bytes-in,
  LINES-out, testable without a server. Multi-line payloads are folded to
  single-line JSON, `id:` carries the monotonic event id, and a
  `: keepalive` every `keepalive_interval` seconds keeps proxies from
  closing idle connections.
- **Same-loop rule.** asyncio queues are loop-bound; the FastAPI test
  path uses httpx `ASGITransport` (same event loop as the app), never the
  threaded TestClient.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import deque
from dataclasses import dataclass
from typing import Any, AsyncIterator

from warden.seam import JournalSink

logger = logging.getLogger("warden.streaming")


# ---------------------------------------------------------------------------
# The bus — a JournalSink with fan-out
# ---------------------------------------------------------------------------


@dataclass
class WardenEvent:
    """One journal event, bus-id-tagged and JSON-safe."""

    id: int
    event: str
    payload: dict[str, Any]
    ts: str

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "event": self.event, "payload": self.payload, "ts": self.ts}


class WardenJournalBus(JournalSink):
    """In-process event bus that IS a journal sink.

    Wire it as `GuardedExecutor(journal=bus)` and live streaming comes for
    free on every action the seam journals. History keeps the last
    `history_size` events so late subscribers can catch up (bounded —
    telemetry, not evidence; the durable journal is Parth's DB table).
    """

    def __init__(self, *, history_size: int = 256, queue_size: int = 64) -> None:
        self._seq = 0
        self._history: deque[WardenEvent] = deque(maxlen=history_size)
        self._queue_size = queue_size
        self._subscribers: dict[int, asyncio.Queue[WardenEvent | None]] = {}
        self._lock = asyncio.Lock()

    # -- JournalSink -----------------------------------------------------

    async def append(self, event: str, payload: dict[str, Any], /) -> None:
        """Seam sink interface: tag, remember, fan out. Never raises."""
        self._seq += 1
        from datetime import datetime, timezone

        evt = WardenEvent(
            id=self._seq,
            event=event,
            payload=payload,
            ts=datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        )
        self._history.append(evt)
        await self._fan_out(evt)

    # -- Replaying history (late dashboards catch up) ---------------------

    def history(self) -> list[WardenEvent]:
        """Past events, oldest first (bounded by history_size)."""
        return list(self._history)

    # -- Subscription lifecycle -------------------------------------------

    async def subscribe(self, *, with_history: bool = True) -> int:
        """Register a subscriber; returns a subscription id."""
        async with self._lock:
            self._seq += 1
            sub_id = self._seq
            queue: asyncio.Queue[WardenEvent | None] = asyncio.Queue(maxsize=self._queue_size)
            if with_history:
                for evt in self._history:
                    self._offer(queue, evt, context="history")
            self._subscribers[sub_id] = queue
            return sub_id

    async def unsubscribe(self, sub_id: int) -> None:
        """Remove a subscriber and signal its stream to end (None sentinel)."""
        async with self._lock:
            queue = self._subscribers.pop(sub_id, None)
        if queue is not None:
            self._offer(queue, None, context="unsubscribe")

    async def close_all(self) -> None:
        """End every subscriber's stream (app shutdown / test teardown)."""
        async with self._lock:
            queues = list(self._subscribers.values())
            self._subscribers.clear()
        for queue in queues:
            self._offer(queue, None, context="close_all")

    # -- Internals ---------------------------------------------------------

    @staticmethod
    def _offer(
        queue: asyncio.Queue[WardenEvent | None],
        item: WardenEvent | None,
        *,
        context: str,
    ) -> None:
        """Bounded-queue put_nowait with drop-oldest (the client's own loss)."""
        while True:
            try:
                queue.put_nowait(item)
                return
            except asyncio.QueueFull:
                dropped = queue.get_nowait()
                if dropped is None:
                    # Never drop the end-of-stream sentinel.
                    queue.put_nowait(None)
                    # ...the item offered just before it was lost; acceptable:
                    # a closing subscriber is leaving anyway.
                    return
                logger.debug("stream.drop_oldest", extra={"subscriber_ctx": context})

    async def _fan_out(self, evt: WardenEvent) -> None:
        for queue in list(self._subscribers.values()):
            self._offer(queue, evt, context="fanout")

    # -- SSE stream --------------------------------------------------------

    async def sse_stream(
        self,
        sub_id: int,
        *,
        keepalive_interval: float = 15.0,
    ) -> AsyncIterator[bytes]:
        """Yield SSE frames for one subscription until it ends.

        Keepalive comments (`: keepalive`) on idle intervals; a final
        `retry:` frame tells clients how to reconnect.
        """
        queue = self._subscribers.get(sub_id)
        if queue is None:
            return
        while True:
            try:
                evt = await asyncio.wait_for(queue.get(), timeout=keepalive_interval)
            except asyncio.TimeoutError:
                yield sse_format(None)
                continue
            if evt is None:  # unsubscribe() end-of-stream sentinel
                yield sse_frame_retry()
                return
            yield sse_format(evt.to_dict())


# ---------------------------------------------------------------------------
# SSE formatting (pure, server-independent)
# ---------------------------------------------------------------------------


def _sse_escape(text: str) -> str:
    """Per SSE spec: line breaks inside a data field use CRLF split framing."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def sse_format(data: dict[str, Any] | None, *, event: str = "journal", id_: int | None = None) -> bytes:
    """Format one SSE frame. `data=None` yields a keepalive comment."""
    if data is None:
        return b": keepalive\n\n"
    lines = []
    if event:
        lines.append(f"event: {event}")
    if id_ is not None:
        lines.append(f"id: {id_}")
    # Fold the JSON to a single data line (SSE data is line-delimited).
    folded = _sse_escape(json.dumps(data, separators=(",", ":"), default=str))
    lines.append(f"data: {folded}")
    lines.append("")
    lines.append("")
    return ("\n".join(lines)).encode("utf-8")


def sse_frame_retry(millis: int = 3000) -> bytes:
    """Tell reconnecting clients to retry after `millis`."""
    return f"retry: {millis}\n\n".encode("utf-8")


def parse_sse_frame(frame: bytes) -> dict[str, Any]:
    """Parse a formatted frame back (test-side reading convenience)."""
    fields: dict[str, Any] = {}
    for raw_line in frame.decode("utf-8").split("\n"):
        if raw_line.startswith(":"):  # comment/keepalive
            continue
        if ":" in raw_line:
            key, _, value = raw_line.partition(":")
            value = value.lstrip(" ")
            match key:
                case "event":
                    fields["event"] = value
                case "id":
                    fields["id"] = int(value)
                case "data":
                    fields["data"] = json.loads(value)
                case "retry":
                    fields["retry"] = int(value)
    return fields
