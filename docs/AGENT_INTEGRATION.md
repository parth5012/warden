# Aegis — Agent Integration Guide

> How to integrate custom AI agents (LangGraph, LangChain, OpenAI, Anthropic, or external bots) with Aegis AI Governance & Seam Interception.

---

## 1. Architecture Overview

In Aegis, agents do not run unmonitored. When an agent proposes an action (file deletion, database DDL, bash execution, or outbound network socket), the proposal must cross the **GuardedExecutor Seam**.

```
User Prompt (Chat UI / API)
         │
         ▼
   AI Agent Logic (LangGraph / LLM / Custom)
         │  (Proposes Tool Action)
         ▼
 ┌────────────────────────────────────────┐
 │       GuardedExecutor Seam             │
 │                                        │
 │  ├── Invariant Check (Lock 5)          │ ──► TERMINAL DENY (e.g. SEC-HOST-00)
 │  │                                     │
 │  ├── Policy Escalation (Lock 2)        │ ──► HITL INTERCEPTION GATE (e.g. SEC-FS-04)
 │  │                                     │       (1-Click Operator Review in Chat UI)
 │  └── Clearance Check                   │ ──► DISPATCH TO SANDBOX (Exit 0)
 └────────────────────────────────────────┘
         │
         ▼
 Immutable WAL & Audit Journal
```

---

## 2. In-Process Python Integration (3 Lines of Code)

You can plug any custom agent into Aegis by inheriting from `BaseAgent` and registering it with `AGENT_REGISTRY`:

```python
from warden.agent_engine import BaseAgent, AgentTurnResult, AGENT_REGISTRY, ChatMessage
from warden.models import Action, ActionKind

class MyCustomAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="MyCustomAgent",
            model="gpt-4o / custom-fine-tune",
            description="My specialized production worker agent.",
            system_prompt="You are a production assistant under Aegis governance.",
        )

    async def process_message(
        self,
        user_message: str,
        thread_id: str,
        history: list[ChatMessage],
    ) -> AgentTurnResult:
        # 1. Your LLM / agent logic here:
        # e.g., response = await my_llm.ainvoke(user_message)

        # 2. If the agent wants to propose a tool action:
        proposed_action = Action(
            id=f"act_custom_{uuid.uuid4().hex[:6]}",
            kind=ActionKind.TOOL,
            name="run_shell",
            payload={"command": "python manage.py migrate"},
            run_id=f"run_{thread_id}",
            thread_id=thread_id,
        )

        return AgentTurnResult(
            reply="I am ready to run database migrations.",
            action=proposed_action,
            policy_id="SEC-DB-02",  # Optional: policy rule to evaluate
            policy_reason="Production schema migration",
        )

# Register into the live Aegis Chat Console:
AGENT_REGISTRY.register(MyCustomAgent())
```

Once registered, **MyCustomAgent** instantly appears in the Agent selection dropdown in the Chat console (`/chat`).

---

## 3. Quick Lambda / Function Hook

If you just have an async python function:

```python
from warden.agent_engine import PluggableAgent, AGENT_REGISTRY, AgentTurnResult

async def my_agent_callback(user_message: str, thread_id: str, history) -> AgentTurnResult:
    # Call your agent pipeline or LangGraph compiled graph
    return AgentTurnResult(reply=f"Processed: {user_message}")

AGENT_REGISTRY.register(
    PluggableAgent(
        name="FastAgent",
        model="local-llm",
        handler_fn=my_agent_callback,
    )
)
```

---

## 4. HTTP / Webhook Integration (External Agent Services)

For agents running in another container, Kubernetes pod, or microservice:

### Endpoint:
`POST /api/chat/hook`

### Request Body:
```json
{
  "agent": "ExternalBillingAgent",
  "model": "claude-3-5-sonnet",
  "message": "User requested account refund",
  "thread_id": "thread_billing_101",
  "action": {
    "name": "process_stripe_refund",
    "payload": {
      "customer_id": "cus_9942",
      "amount_cents": 50000
    },
    "policy_id": "SEC-FIN-01"
  }
}
```

### Response:
```json
{
  "agent": "ExternalBillingAgent",
  "thread_id": "thread_billing_101",
  "governance": {
    "verdict": "escalated",
    "gate_id": "gate_8912e34a",
    "status": "pending_operator_approval"
  },
  "timestamp": "2026-10-12T20:20:00Z"
}
```

---

## 5. Built-In Governance Test Scenarios in `/chat`

| User Prompt | Action Triggered | Policy Rule | Seam Behavior |
|---|---|---|---|
| *"Delete obsolete temporary files in /workspace/tmp/"* | `FILE_BATCH_DELETE` (5 files) | `SEC-FS-04` | **ESCALATE (HITL)**: Displays live 1-click Approve / Deny card in chat |
| *"Delete /etc/shadow"* | `run_shell(rm /etc/shadow)` | `SEC-HOST-00` | **TERMINAL DENY (Lock 5)**: Permanently blocked; immutable |
| *"Formulate a schema ALTER migration"* | `SQL_SCHEMA_MIGRATION` | `SEC-DB-02` | **ESCALATE (HITL)**: Requires operator confirmation |
| *"Inspect the project workspace"* | `FILE_READ` | `SEC-FS-01` | **ALLOW**: Dispatches to Sandbox and returns read results |
