"""CLI chat harness for any compiled LangGraph graph.

Talks to a graph interactively: sends inputs, prints state, and when the
graph parks on interrupt() it shows the interrupt payload and prompts for
the resume value (JSON or plain text). Uses CheckpointManager so all
park/resume transitions are logged.

Usage:
    uv run python tests/cli_chat.py             # demo graph + Postgres
    WARDEN_PG_URI=... uv run python tests/cli_chat.py

As a library:
    from tests.cli_chat import run_chat
    await run_chat(my_graph, thread_id="t1", manager=my_manager)

Commands inside the chat:
    /state      show current checkpoint state
    /history    walk the checkpoint history
    /new        start a fresh thread (parked state stays in the past thread)
    /resume X   resume the parked graph with value X
    /quit       exit
    <text>      send text as graph input (via input_fn)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import uuid
from collections.abc import Callable
from typing import Any

from langchain_core.runnables import RunnableConfig
from langgraph.graph.state import CompiledStateGraph

from warden.checkpoint import CheckpointManager
from warden.demo_graph import build_demo_graph
from warden.models import CheckpointInfo, Error

# ---------------------------------------------------------------------------
# Default wiring
# ---------------------------------------------------------------------------

DEFAULT_PG_URI = "postgresql://postgres:@/postgres?host=/tmp/opencode/pgdata-warden"


def default_input_fn(text: str) -> dict[str, Any]:
    """Default: append raw text to a `messages` list state."""
    return {"messages": [text]}


def _parse_resume_value(raw: str) -> Any:
    """JSON if parseable (e.g. {"verdict": "approve"}), else raw string."""
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _render_state(result: dict[str, Any]) -> None:
    messages = result.get("messages")
    if messages:
        print("messages:")
        for i, m in enumerate(messages, 1):
            print(f"  {i}. {_msg_text(m)}")
    for key, val in result.items():
        if key != "messages":
            print(f"{key}: {val!r}")


def _msg_text(msg: Any) -> str:
    """Render a message — plain str or a LangChain message object."""
    content = getattr(msg, "content", None)
    if content is not None:
        role = type(msg).__name__
        return f"[{role}] {content}"
    return str(msg)


def _render_interrupts(result: dict[str, Any]) -> list[Any]:
    interrupts = result.get("__interrupt__") or []
    if not interrupts:
        return []
    print("\n*** GRAPH PARKED — human decision required ***")
    for i, intr in enumerate(interrupts, 1):
        print(f"  interrupt {i}: {json.dumps(intr.value, indent=2, default=str)}")
    return list(interrupts)


# ---------------------------------------------------------------------------
# State / history display
# ---------------------------------------------------------------------------


async def _show_state(
    graph: CompiledStateGraph[Any, Any, Any, Any],
    config: RunnableConfig,
    manager: CheckpointManager | None,
) -> None:
    if manager is not None:
        info = await manager.get_state_info(graph, config)
        if isinstance(info, Error):
            print(f"state: unavailable ({info.reason})")
            return
        _print_info(info)
    else:
        state = await graph.aget_state(config)
        print(
            f"checkpoint: {state.config.get('configurable', {}).get('checkpoint_id')}"
        )
        print(f"pending interrupts: {len(state.interrupts)}")


async def _show_history(
    graph: CompiledStateGraph[Any, Any, Any, Any],
    config: RunnableConfig,
    manager: CheckpointManager | None,
) -> None:
    if manager is None:
        print("history: needs a CheckpointManager")
        return
    history = await manager.get_state_history(graph, config)
    if isinstance(history, Error):
        print(f"history: unavailable ({history.reason})")
        return
    if not history:
        print("history: empty thread")
        return
    for info in history:
        _print_info(info)


def _print_info(info: CheckpointInfo) -> None:
    parked = " PARKED" if info.has_pending_interrupts else ""
    print(
        f"  step={info.step} checkpoint={info.checkpoint_id[:13]}…{parked}"
    )


# ---------------------------------------------------------------------------
# The chat loop
# ---------------------------------------------------------------------------


async def run_chat(
    graph: CompiledStateGraph[Any, Any, Any, Any],
    *,
    thread_id: str | None = None,
    manager: CheckpointManager | None = None,
    input_fn: Callable[[str], dict[str, Any]] = default_input_fn,
) -> None:
    """Interactive chat against `graph`. Parks on interrupt, resumes on input."""
    tid = thread_id or f"cli-{uuid.uuid4().hex[:8]}"
    config: RunnableConfig = {"configurable": {"thread_id": tid}}
    print(f"thread: {tid}")
    print("commands: /state /history /new /resume <value> /quit")
    if manager is not None:
        if not await manager.health_check():
            print("WARNING: checkpoint store unhealthy — park/resume may fail")

    # Rejoining a parked thread (e.g. CLI restarted mid-park): prompt now.
    try:
        existing = await graph.aget_state(config)
    except Exception as exc:
        print(f"state check failed: {exc}")
        existing = None
    if existing is not None and existing.interrupts:
        _render_interrupts({"__interrupt__": list(existing.interrupts)})
        if not await _prompt_for_resume(graph, config, manager):
            print(f"bye (thread {tid} stays parked)")
            return

    while True:
        try:
            line = (await asyncio.to_thread(input, "\nyou> ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue

        if line in ("/quit", "/exit"):
            break
        if line == "/state":
            await _show_state(graph, config, manager)
            continue
        if line == "/history":
            await _show_history(graph, config, manager)
            continue
        if line == "/new":
            tid = f"cli-{uuid.uuid4().hex[:8]}"
            config = {"configurable": {"thread_id": tid}}
            print(f"new thread: {tid}")
            continue
        if line.startswith("/resume"):
            raw = line[len("/resume"):].strip()
            if not raw:
                print("usage: /resume <value>   (JSON or plain text)")
                continue
            result = await _resume_and_render(
                graph, config, manager, _parse_resume_value(raw)
            )
            if result is not None and result.get("__interrupt__"):
                if not await _prompt_for_resume(graph, config, manager):
                    break
            continue

        # Plain text -> graph input
        try:
            result = await graph.ainvoke(input_fn(line), config)
        except Exception as exc:
            print(f"invoke failed: {exc}")
            continue
        _render_state(result)
        interrupts = _render_interrupts(result)
        if interrupts:
            if not await _prompt_for_resume(graph, config, manager):
                break

    print(f"bye (thread {tid} stays parked in the store if interrupt pending)")


async def _prompt_for_resume(
    graph: CompiledStateGraph[Any, Any, Any, Any],
    config: RunnableConfig,
    manager: CheckpointManager | None,
) -> bool:
    """Prompt for resume values until the graph is no longer parked.

    EOF-safe: Ctrl-D / Ctrl-C at the prompt aborts cleanly (returns False)
    instead of raising. Re-prompts when a resume re-parks the graph
    (validation-loop pattern). Returns False = user aborted, caller exits.
    """
    while True:
        try:
            raw = (await asyncio.to_thread(input, "resume> ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if raw in ("/quit", "/exit"):
            # Leave the thread parked; never treat quit as a deny decision.
            return False
        if not raw:
            print("empty decision — still parked")
            continue
        result = await _resume_and_render(
            graph, config, manager, _parse_resume_value(raw)
        )
        if result is None:
            print("resume failed — still parked")
            continue
        if not result.get("__interrupt__"):
            return True
        print("graph re-parked — decision required again")


async def _resume_and_render(
    graph: CompiledStateGraph[Any, Any, Any, Any],
    config: RunnableConfig,
    manager: CheckpointManager | None,
    value: Any,
) -> dict[str, Any] | None:
    """Resume the graph and render the outcome. None = resume failed."""
    if manager is not None:
        result = await manager.resume(graph, config, value)
        if isinstance(result, Error):
            print(f"resume failed: {result.reason}")
            return None
    else:
        from langgraph.types import Command

        result = await graph.ainvoke(Command(resume=value), config)
    _render_state(result)
    _render_interrupts(result)  # validation loops may park again
    return result


# ---------------------------------------------------------------------------
# Entry point: demo graph + Postgres
# ---------------------------------------------------------------------------


DEFAULT_PG_DIR = "/tmp/opencode/pgdata-warden"


def _resolve_pg_uri(explicit: str | None) -> str:
    """Env var > --pg flag > bundled pgserver at DEFAULT_PG_DIR.

    pgserver stops the server at process exit (cleanup_mode='stop'), but the
    data directory persists — the next CLI start re-attaches to the same
    checkpoints. Restart the CLI and /resume the same thread: that IS the
    crash-recovery demo.
    """
    import os

    if explicit:
        return explicit

    from warden.config import settings

    if settings.postgres_uri:
        return settings.postgres_uri

    env = os.environ.get("WARDEN_PG_URI")
    if env:
        return env
    try:
        import pgserver  # type: ignore[import-not-found]

        os.makedirs(DEFAULT_PG_DIR, exist_ok=True)
        return str(pgserver.get_server(DEFAULT_PG_DIR).get_uri())
    except Exception:
        print(
            f"warning: pgserver unavailable, falling back to {DEFAULT_PG_URI}",
            file=sys.stderr,
        )
        return DEFAULT_PG_URI


async def _amain(pg_uri: str, thread_id: str | None) -> int:
    async with CheckpointManager.create(pg_uri) as manager:
        graph = build_demo_graph(manager.checkpointer)
        await run_chat(graph, thread_id=thread_id, manager=manager)
    return 0


def main() -> None:
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure):
        reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description="Aegis CLI chat harness")
    parser.add_argument(
        "--pg",
        default=None,
        help="Postgres URI for the checkpointer (default: env WARDEN_PG_URI, "
        "then bundled pgserver)",
    )
    parser.add_argument("--thread", default=None, help="resume an existing thread")
    parser.add_argument("-v", "--verbose", action="store_true", help="show checkpoint logs")
    args = parser.parse_args()

    pg_uri = _resolve_pg_uri(args.pg)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(name)s %(message)s",
    )
    sys.exit(asyncio.run(_amain(pg_uri, args.thread)))


if __name__ == "__main__":
    main()
