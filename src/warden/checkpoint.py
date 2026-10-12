"""CheckpointManager — Postgres checkpoint lifecycle with fail-closed behaviour.

This is the deep module for checkpoint infrastructure. It owns:
- PostgresSaver lifecycle (creation, setup, teardown)
- Connection health checks
- Fail-closed semantics: Postgres down -> Error("governance_unavailable")
- State inspection with structured logging
- Context manager for clean resource management

Graph nodes and external callers use LangGraph primitives directly
(interrupt(), Command(resume=...), graph.get_state()). This class does NOT
wrap those — it manages the infrastructure they depend on.
"""

from __future__ import annotations

import asyncio
import logging
import re
import sys
from typing import TYPE_CHECKING, Any, TypeAlias

if sys.platform == "win32":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.types import Command
from psycopg_pool import AsyncConnectionPool

from warden.models import CheckpointInfo, Error

if TYPE_CHECKING:
    from langchain_core.runnables import RunnableConfig
    from langgraph.graph.state import CompiledStateGraph
    from langgraph.types import StateSnapshot

    # CompiledStateGraph[StateT, ContextT, InputT, OutputT] — fully-erased alias
    CompiledGraph: TypeAlias = CompiledStateGraph[Any, Any, Any, Any]

logger = logging.getLogger("warden.checkpoint")


def _redact(conn_string: str) -> str:
    """Redact secrets from connection strings (URI and keyword DSN forms)."""
    from urllib.parse import urlsplit, urlunsplit

    try:
        parts = urlsplit(conn_string)
    except ValueError:
        # Unparseable (e.g. invalid IPv6): over-redact the authority —
        # losing host detail beats leaking credentials.
        return re.sub(r"(://).*?(?=/|$)", r"://***", conn_string, count=1)

    if parts.scheme and "@" in parts.netloc:
        # Mask the COMPLETE userinfo — it may contain unencoded '@'
        # (malformed but possible: postgresql://user:p@ss@host). rsplit on
        # the last '@' keeps the host intact; query data is untouched.
        host = parts.netloc.rsplit("@", 1)[-1]
        redacted = urlunsplit(
            (parts.scheme, f"***@{host}", parts.path, parts.query, parts.fragment)
        )
    else:
        redacted = conn_string

    # keyword/value DSN form: password=secret | password='my pass' | password="my pass"
    redacted = re.sub(
        r"(\bpassword\s*=\s*)(?:'[^']*'|\"[^\"]*\"|\S+)",
        r"\1***",
        redacted,
        flags=re.IGNORECASE,
    )
    return redacted


def _snapshot_to_info(thread_id: str, state: StateSnapshot) -> CheckpointInfo:
    """Convert a LangGraph StateSnapshot into our CheckpointInfo view."""
    meta = state.metadata
    # metadata arrives as a dict (serde) or a CheckpointMetadata object
    if isinstance(meta, dict):
        step = int(meta.get("step", -1))
    else:
        step = int(getattr(meta, "step", -1)) if meta is not None else -1
    interrupts = [i.value for i in state.interrupts]
    return CheckpointInfo(
        thread_id=thread_id,
        checkpoint_id=state.config.get("configurable", {}).get("checkpoint_id", ""),
        parent_checkpoint_id=state.parent_config.get("configurable", {}).get(
            "checkpoint_id"
        )
        if state.parent_config
        else None,
        created_at=state.created_at,
        step=step,
        has_pending_interrupts=bool(state.interrupts),
        pending_interrupt_values=interrupts,
    )


class CheckpointManager:
    """Manages the AsyncPostgresSaver lifecycle with fail-closed behaviour.

    Usage:
        async with CheckpointManager.create(conn_string) as mgr:
            graph = builder.compile(checkpointer=mgr.checkpointer)
            info = await mgr.get_state_info(graph, config)

    Invariants:
        - If Postgres is unreachable, inspection methods return
          Error("governance_unavailable") instead of raising.
        - .setup() runs on entry and is idempotent (safe every boot).
        - The checkpointer is only valid inside the context manager.
        - The connection string is never logged unredacted.
    """

    def __init__(self, conn_string: str) -> None:
        self._conn_string = conn_string
        self._ctx: Any = None
        self._saver: AsyncPostgresSaver | None = None
        self._healthy = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @classmethod
    def create(cls, conn_string: str) -> _CheckpointManagerCtx:
        """Open a managed CheckpointManager (async context manager).

        Creates the checkpointer tables on first use (idempotent).
        Raises if Postgres is unreachable at startup — fail-closed:
        there is no point running the graph without a park/resume store.

            async with CheckpointManager.create(conn_string) as mgr:
                graph = builder.compile(checkpointer=mgr.checkpointer)
        """
        return _CheckpointManagerCtx(conn_string)

    @property
    def checkpointer(self) -> AsyncPostgresSaver:
        """Return the underlying saver. Raises if not inside `async with create()`."""
        if self._saver is None:
            raise RuntimeError(
                "CheckpointManager not initialised — use "
                "'async with CheckpointManager.create(...)'"
            )
        return self._saver

    @property
    def is_healthy(self) -> bool:
        return self._healthy

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def health_check(self) -> bool:
        """Probe the Postgres connection. Returns True if healthy."""
        if self._saver is None:
            self._healthy = False
            return False
        try:
            conn = self._saver.conn
            if isinstance(conn, AsyncConnectionPool):
                async with conn.connection() as pooled:
                    await pooled.execute("SELECT 1")
            else:
                await conn.execute("SELECT 1")
            self._healthy = True
            logger.debug("checkpoint_manager.health_ok")
            return True
        except Exception as exc:
            self._healthy = False
            logger.warning(
                "checkpoint_manager.health_fail", extra={"error": str(exc)}
            )
            return False

    # ------------------------------------------------------------------
    # State inspection (logging + fail-closed)
    # ------------------------------------------------------------------

    async def get_state_info(
        self,
        graph: CompiledGraph,
        config: RunnableConfig,
    ) -> CheckpointInfo | Error:
        """Inspect the current checkpoint state for a thread.

        Returns CheckpointInfo on success, Error("governance_unavailable") on
        failure. Never raises for environmental reasons (lock 4).
        """
        thread_id = (config.get("configurable") or {}).get("thread_id", "unknown")
        try:
            state = await graph.aget_state(config)
            info = _snapshot_to_info(thread_id, state)
            logger.info(
                "checkpoint.state_inspected",
                extra={
                    "thread_id": info.thread_id,
                    "checkpoint_id": info.checkpoint_id,
                    "step": info.step,
                    "has_interrupts": info.has_pending_interrupts,
                },
            )
            return info
        except Exception as exc:
            logger.error(
                "checkpoint.state_inspect_failed",
                extra={"thread_id": thread_id, "error": str(exc)},
            )
            return Error(reason="governance_unavailable")

    async def get_state_history(
        self,
        graph: CompiledGraph,
        config: RunnableConfig,
    ) -> list[CheckpointInfo] | Error:
        """Return the checkpoint history for a thread, oldest first.

        Returns list of CheckpointInfo on success, Error("governance_unavailable")
        on failure. Never raises for environmental reasons (lock 4).
        """
        thread_id = (config.get("configurable") or {}).get("thread_id", "unknown")
        try:
            history: list[CheckpointInfo] = []
            async for state in graph.aget_state_history(config):
                history.append(_snapshot_to_info(thread_id, state))
            # aget_state_history yields newest-first; contract is oldest-first
            history.reverse()
            logger.info(
                "checkpoint.history_inspected",
                extra={"thread_id": thread_id, "checkpoint_count": len(history)},
            )
            return history
        except Exception as exc:
            logger.error(
                "checkpoint.history_inspect_failed",
                extra={"thread_id": thread_id, "error": str(exc)},
            )
            return Error(reason="governance_unavailable")

    # ------------------------------------------------------------------
    # Resume (logging wrapper around Command(resume=...))
    # ------------------------------------------------------------------

    async def resume(
        self,
        graph: CompiledGraph,
        config: RunnableConfig,
        value: Any,
    ) -> Any | Error:
        """Resume a parked thread with a human decision.

        Wraps `graph.ainvoke(Command(resume=value), config)` with structured
        logging at both ends. Returns the resulting state on success,
        Error("governance_unavailable") on failure (fail-closed, lock 4).

        The human's decision must already be journaled by the caller
        (gate_decided event) BEFORE calling this — resume is execution,
        not evidence.
        """
        thread_id = (config.get("configurable") or {}).get("thread_id", "unknown")
        try:
            logger.info(
                "checkpoint.resume_requested",
                extra={
                    "thread_id": thread_id,
                    "resume_value_type": type(value).__name__,
                },
            )
            result = await graph.ainvoke(Command(resume=value), config)
            logger.info(
                "checkpoint.resume_completed",
                extra={"thread_id": thread_id},
            )
            return result
        except Exception as exc:
            logger.error(
                "checkpoint.resume_failed",
                extra={"thread_id": thread_id, "error": str(exc)},
            )
            return Error(reason="governance_unavailable")


class _CheckpointManagerCtx:
    """Async context manager that owns the saver connection lifecycle."""

    def __init__(self, conn_string: str) -> None:
        self._conn_string = conn_string
        self.manager: CheckpointManager | None = None

    async def __aenter__(self) -> CheckpointManager:
        mgr = CheckpointManager(self._conn_string)
        redacted = _redact(self._conn_string)
        try:
            mgr._ctx = AsyncPostgresSaver.from_conn_string(self._conn_string)
            saver = await mgr._ctx.__aenter__()
            mgr._saver = saver
            await saver.setup()
            mgr._healthy = True
            self.manager = mgr
            logger.info("checkpoint_manager.ready", extra={"conn": redacted})
            return mgr
        except Exception as exc:
            mgr._healthy = False
            logger.error(
                "checkpoint_manager.init_failed",
                extra={"error": str(exc), "conn": redacted},
            )
            # Best-effort cleanup of a half-open context
            if mgr._ctx is not None:
                try:
                    await mgr._ctx.__aexit__(None, None, None)
                except Exception:
                    pass
            raise

    async def __aexit__(self, *exc_info: Any) -> None:
        mgr = self.manager
        if mgr is not None and mgr._ctx is not None:
            try:
                await mgr._ctx.__aexit__(*exc_info)
            except Exception:
                logger.warning("checkpoint_manager.close_failed", exc_info=True)
            mgr._saver = None
            mgr._healthy = False
            logger.info("checkpoint_manager.closed")
        self.manager = None
