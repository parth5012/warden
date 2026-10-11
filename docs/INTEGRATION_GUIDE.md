# Warden — Integration Guide

> Component dependencies, producer/consumer relationships, integration order, and mock interfaces for modules not yet implemented.

---

## 1. Integration Order

Build and integrate components in this sequence. Do not start a component before its dependencies are green (tests + mypy + manual demo).

```
Phase 0 (done)
  [1] models.py              ← no dependencies
  [2] checkpoint.py          ← depends on models.py, LangGraph, psycopg3
  [3] demo_graph.py          ← depends on LangGraph, checkpoint.py
  [4] tests (CLI harness)    ← depends on [1]–[3]

Phase 1 (in progress)
  [5]  journal.py            ← depends on models.py, psycopg3
  [6]  policy/engine.py      ← depends on models.py, journal.py
  [7]  hitl/runner.py        ← depends on models.py, journal.py, LangGraph
  [8]  sandbox.py            ← depends on models.py
  [9]  llm.py                ← depends on models.py, journal.py, langchain-openai
  [10] executor.py           ← depends on [5]–[9]
  [11] agents/ops_assistant  ← depends on executor.py, checkpoint.py
  [12] projections/          ← depends on journal.py
  [13] app/ (FastAPI)        ← depends on [10]–[12]
  [14] app/views/ (Jinja+HTMX) ← depends on [13]
```

---

## 2. Component Dependency Graph

```
models.py
    │
    ├── checkpoint.py ──────────────────────────────────────────────► demo_graph.py
    │       │                                                              │
    │       │                                                         cli_chat.py (tests)
    │       │
    ├── journal.py ──────────────────────────────────────────────────► projections/
    │       │
    ├── policy/engine.py ─────────────────────────────────────────────┐
    │       │                                                          │
    ├── hitl/runner.py ─────────────────────────────────────────────  │
    │       │                                                          │
    ├── sandbox.py ──────────────────────────────────────────────  ───┤
    │       │                                                          │
    └── llm.py ──────────────────────────────────────────────────  ───┘
                                                                       │
                                                               executor.py
                                                                       │
                                                         agents/ops_assistant.py
                                                                       │
                                                               app/main.py (FastAPI)
                                                                       │
                                                         app/views/ (Jinja + HTMX)
```

---

## 3. Component Contracts

### 3.1 `executor.py` — GuardedExecutor

**Depends on:** `models.py`, `journal.py`, `policy/engine.py`, `sandbox.py`, `llm.py`

**Interface (proposed):**

```python
# PROPOSED interface — not yet implemented
class GuardedExecutor:
    def __init__(
        self,
        journal: AuditJournal,
        policy: PolicyEngine,
        sandbox: SandboxPort,
        llm_client: GuardedLLMClient,
    ) -> None: ...

    async def execute(
        self,
        action: Action,
        ctx: ExecutionContext,
        approval: GateDecision | None = None,
    ) -> Outcome: ...
```

**Mock for callers that cannot wait for the real implementation:**

```python
# tests/mocks/mock_executor.py — proposed mock
class MockExecutor:
    """In-memory executor for agent and UI testing."""

    def __init__(self, default_outcome: Outcome = Allowed(result="ok")) -> None:
        self.default_outcome = default_outcome
        self.calls: list[Action] = []

    async def execute(self, action: Action, ctx: Any, approval: Any = None) -> Outcome:
        self.calls.append(action)
        return self.default_outcome
```

---

### 3.2 `journal.py` — AuditJournal

**Depends on:** `models.py`, psycopg3

**Interface (proposed):**

```python
# PROPOSED interface — not yet implemented
class AuditJournal:
    async def append(self, event: JournalEvent) -> None: ...
    async def query(self, filters: JournalQuery) -> list[JournalEvent]: ...
```

**Mock for callers:**

```python
# tests/mocks/mock_journal.py — proposed mock
class MockJournal:
    """In-memory journal for unit testing."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    async def append(self, event: Any) -> None:
        self.events.append(event)

    async def query(self, filters: Any = None) -> list[dict]:
        return list(self.events)
```

---

### 3.3 `policy/engine.py` — PolicyEngine

**Depends on:** `models.py`, `journal.py` (for version reads), psycopg3 + pgvector

**Interface (proposed):**

```python
# PROPOSED interface — not yet implemented
class PolicyDecision(str, Enum):
    ALLOW    = "allow"
    ESCALATE = "escalate"
    DENY     = "deny"

@dataclass
class PolicyResult:
    decision:    PolicyDecision
    policy_name: str | None
    reason:      str

class PolicyEngine:
    async def evaluate(
        self,
        action: Action,
        ctx: ExecutionContext,
    ) -> PolicyResult: ...
```

**Mock for callers:**

```python
# tests/mocks/mock_policy.py — proposed mock
class MockPolicyEngine:
    """Configurable policy engine for testing."""

    def __init__(self, default: PolicyDecision = PolicyDecision.ALLOW) -> None:
        self.default = default
        self.overrides: dict[str, PolicyDecision] = {}

    async def evaluate(self, action: Action, ctx: Any) -> PolicyResult:
        decision = self.overrides.get(action.name, self.default)
        return PolicyResult(decision=decision, policy_name=None, reason="mock")
```

**Seed policies (minimum for Phase 1 demo):**

| Rule name | Action name | Decision | Rationale |
|---|---|---|---|
| `no_destructive_sql` | `drop_table`, `truncate_table` | `deny` | Terminal — no approval |
| `escalate_external_email` | `send_email` | `escalate` | Requires human approval |
| `allow_sandbox_shell` | `run_shell` | `escalate` | Sandbox executes; still gated |

---

### 3.4 `hitl/runner.py` — HITL Re-entry Helper

**Depends on:** `models.py`, `executor.py`, LangGraph `interrupt`/`Command`

**Interface (proposed):**

```python
# PROPOSED interface — not yet implemented
async def run_gated(
    action: Action,
    ctx: ExecutionContext,
    executor: GuardedExecutor,
    park_fn: Callable[[GateRequest], Awaitable[GateDecision]],
) -> Allowed | Denied | Error: ...
```

The `park_fn` is the LangGraph `interrupt()` wrapper — it parks the graph and returns the human decision when the graph is resumed.

**Sequence:**
1. Call `executor.execute(action, ctx)`.
2. If `Allowed` or `Denied` or `Error` → return as-is.
3. If `Pending(gate_request)` → call `park_fn(gate_request)` → `interrupt()` → parked.
4. On resume, call `executor.execute(action, ctx, approval=decision)`.
5. Return the second outcome.

---

### 3.5 `sandbox.py` — SandboxPort

**Depends on:** `models.py`

**Interface (proposed):**

```python
# PROPOSED interface — not yet implemented
class SandboxPort:
    async def run(self, action: Action) -> ExecutionResult: ...
```

Dispatch rules:
- `action.name` in `{run_shell, run_code, write_file, read_file}` → subprocess adapter
- All other tool names → in-process adapter
- `action.kind == "llm"` → must not reach SandboxPort (handled by LLM client)

**Mock:**

```python
class MockSandbox:
    async def run(self, action: Action) -> ExecutionResult:
        return ExecutionResult(
            action_id=action.id,
            outcome_kind="allowed",
            result=f"mock result for {action.name}",
            error_code=None, error_detail=None,
            duration_ms=50, timed_out=False, cancelled=False,
        )
```

---

### 3.6 `llm.py` — GuardedLLMClient

**Depends on:** `models.py`, `journal.py`, langchain-openai

**Interface (proposed):**

```python
# PROPOSED interface — not yet implemented
class GuardedLLMClient:
    async def invoke(self, action: Action) -> ExecutionResult: ...
```

Side effects: appends `llm_usage` event to the journal after every call.

**Mock:**

```python
class MockLLMClient:
    def __init__(self, response: str = "mock LLM response") -> None:
        self.response = response
        self.calls: list[Action] = []

    async def invoke(self, action: Action) -> ExecutionResult:
        self.calls.append(action)
        return ExecutionResult(
            action_id=action.id, outcome_kind="allowed",
            result=self.response, error_code=None, error_detail=None,
            duration_ms=100, timed_out=False, cancelled=False,
        )
```

---

## 4. Failure Behavior

| Component | Failure mode | Outcome |
|---|---|---|
| Journal unavailable on write-ahead | `append(action_requested)` raises | `Error("governance_unavailable")` — action NOT executed |
| PolicyEngine raises | Exception in `evaluate()` | `Error("governance_unavailable")` — action NOT executed |
| Checkpoint unavailable on park | `interrupt()` cannot persist | LangGraph raises — resume not possible |
| Journal unavailable on gate_decided | `append(gate_decided)` raises | Return `503` from API — do not resume the graph |
| Sandbox timeout | Subprocess exceeds timeout | `ExecutionResult(timed_out=True)` → `action_failed` journaled |
| LLM provider unavailable | HTTP error from provider | `ExecutionResult(error_code="provider_error")` → `action_failed` journaled |
| Projection query fails | Read error | Return empty result + `503` — source journal is unaffected |

**Critical rule:** Never blindly retry a tool action after a crash if the action may have already completed externally (e.g. email sent). The write-ahead pattern allows detecting "intent was recorded" but not "external side effect completed". Document this explicitly in the ops-assistant agent.

---

## 5. Local Integration Testing

Before writing integration tests, ensure:

1. `pgserver` is available: `uv run python -c "import pgserver; print('ok')"`
2. Baseline tests pass: `uv run pytest tests/test_checkpoint.py`
3. mypy is clean: `uv run mypy src tests`

### Integration test fixture pattern

```python
# Pattern for Phase 1 integration tests (proposed)
@pytest.fixture(scope="function")
async def integrated_executor(pg_uri: str):
    """Full executor stack with real Postgres, in-memory policy and sandbox."""
    async with CheckpointManager.create(pg_uri) as manager:
        journal = PostgresJournal(manager.conn)
        policy = MockPolicyEngine()
        sandbox = MockSandbox()
        llm = MockLLMClient()
        executor = GuardedExecutor(journal, policy, sandbox, llm)
        yield executor
```

### Environment variables for integration tests

```bash
WARDEN_PG_URI=...       # optional: override bundled pgserver
WARDEN_LLM_PROVIDER=openai   # required for LLM integration tests
OPENAI_API_KEY=...           # required for real LLM tests
```

---

## 6. Producer / Consumer Relationships

| Producer | Event / Data | Consumer |
|---|---|---|
| `GuardedExecutor` | `action_requested` event | `AuditJournal` |
| `GuardedExecutor` | `action_denied` event | `AuditJournal` |
| `GuardedExecutor` | `gate_requested` event | `AuditJournal`, HITL inbox projection |
| `GuardedExecutor` | `action_completed` event | `AuditJournal`, telemetry projection |
| LLM adapter | `llm_usage` event | `AuditJournal`, telemetry projection |
| Human (via API) | `gate_decided` event | `AuditJournal`, `graph.ainvoke(Command(resume=...))` |
| `AuditJournal` | All events | telemetry projection, inbox projection, decision-graph projection |
| Projections | View models | FastAPI routes, Jinja templates |
| LangGraph checkpointer | Checkpoint state | `CheckpointManager.resume()`, `run_gated()` |

---

## 7. Stable Contracts That Must Not Change

The following are locked and all modules must conform to them:

1. `Action` dataclass fields — `id`, `kind`, `name`, `payload`, `run_id`, `thread_id`. Do not add required fields without migrating all callers.
2. `Outcome = Allowed | Denied | Pending | Error` — the four variants. Do not add a fifth.
3. `execute()` return type — always `Outcome`. Never raises for environmental failures.
4. `GateRequest.gate_id` and `GateDecision.gate_id` — the binding key between request and decision.
5. Journal write-ahead — `action_requested` must be appended before `evaluate()` is called.
6. History ordering — `get_state_history()` returns oldest-first (`step` non-decreasing).
