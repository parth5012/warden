"""Demo graph for exercising the checkpoint system.

Flow: START -> draft -> approval(interrupt) -> send / abort -> END

The approval node parks the run via interrupt(). A human decision
("approve" / "deny") resumes it via Command(resume=...). Used by the
tests and the CLI chat harness.
"""

from __future__ import annotations

from typing import Any, Literal

from typing_extensions import Annotated, TypedDict
import operator

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command, interrupt


class DemoState(TypedDict):
    messages: Annotated[list[str], operator.add]
    approved: bool


def draft_node(state: DemoState) -> dict[str, Any]:
    return {"messages": ["Drafted email: 'Weekly report ready' -> team@example.com"]}


def approval_node(state: DemoState) -> Command[Literal["send", "abort"]]:
    """Park for human approval. No side effects before interrupt().

    On resume the node re-runs from the top; interrupt() returns the
    human's decision, so everything above it must be idempotent (it is:
    this node does nothing before interrupt()).
    """
    decision = interrupt(
        {
            "action": "send_email",
            "recipient": "team@example.com",
            "body": "Weekly report ready",
            "ask": "approve or deny?",
        }
    )
    if decision in ("approve", "approved", True):
        return Command(update={"approved": True}, goto="send")
    return Command(update={"approved": False}, goto="abort")


def send_node(state: DemoState) -> dict[str, Any]:
    return {"messages": ["Email sent to team@example.com."]}


def abort_node(state: DemoState) -> dict[str, Any]:
    return {"messages": ["Aborted: email NOT sent."]}


def build_demo_graph(
    checkpointer: BaseCheckpointSaver[Any] | None = None,
) -> CompiledStateGraph[Any, Any, Any, Any]:
    """Compile the demo graph with the given checkpointer.

    Returns the compiled graph ready for invoke/ainvoke with a thread_id.
    """
    builder = StateGraph(DemoState)
    builder.add_node("draft", draft_node)
    builder.add_node("approval", approval_node)
    builder.add_node("send", send_node)
    builder.add_node("abort", abort_node)
    builder.add_edge(START, "draft")
    builder.add_edge("draft", "approval")
    builder.add_edge("send", END)
    builder.add_edge("abort", END)
    return builder.compile(checkpointer=checkpointer)
