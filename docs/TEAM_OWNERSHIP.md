# Warden — Team Ownership

> Workstream boundaries, parallel development rules, and integration responsibilities.
> Use this document to decide who owns what before writing a single line of code.

---

## Workstream Summary

| Workstream | Short name | Primary responsibility |
|---|---|---|
| A | UI | Jinja/HTMX templates, dashboard, inbox, audit explorer |
| B | API | FastAPI routes, request validation, response serialization |
| C | Executor | GuardedExecutor + PolicyEngine |
| D | Workflow | LangGraph ops-assistant agent + HITL re-entry helper |
| E | Storage | AuditJournal + SandboxPort |
| F | Infra | PostgreSQL infra, Guarded LLM client, projections, integration testing |

These are suggested workstream boundaries, not headcount assumptions. One person can own multiple workstreams.

---

## Workstream A — UI and Operator Dashboard

### Owned files (proposed — do not create source dirs)

```
app/views/
    dashboard.html
    run_detail.html
    inbox.html
    audit.html
    policies.html
    base.html
app/static/
    warden.css
```

### Responsibility

- Implement all Jinja2 templates and HTMX interaction patterns.
- Consume JSON from API routes (workstream B) and render HTML.
- Implement polling patterns for the inbox and dashboard using HTMX `hx-trigger="every 5s"`.
- Document loading, empty, error, and disconnected states.

### Explicit exclusions

- Does NOT own FastAPI route handlers (workstream B).
- Does NOT own projection logic (workstream F).
- Does NOT implement React or any client-side build step.

### Dependencies

| Dependency | From | Stable? |
|---|---|---|
| JSON shape of `/inbox` | Workstream B | Use mock per [`docs/API_CONTRACT.md`](API_CONTRACT.md) |
| JSON shape of `/dashboard` | Workstream B | Use mock per [`docs/API_CONTRACT.md`](API_CONTRACT.md) |
| JSON shape of `/runs/{thread_id}` | Workstream B | Use mock per [`docs/API_CONTRACT.md`](API_CONTRACT.md) |
| JSON shape of `/audit` | Workstream B | Use mock per [`docs/API_CONTRACT.md`](API_CONTRACT.md) |

### Mocking strategy

Use FastAPI `TestClient` with mock route handlers that return the exact JSON shapes from `API_CONTRACT.md`. Workstream A can develop and test templates independently.

### Acceptance criteria

- All four Phase 1 demo views render correctly with real data.
- Inbox polls every 5 seconds and updates without a page reload.
- Denied actions display a red "not approvable" badge.
- Pending actions display an "Approve / Deny" decision form.
- Dashboard shows token cost, latency, and tool usage per run.
- All views handle the empty state gracefully.

---

## Workstream B — FastAPI Application and HTTP Contracts

### Owned files (proposed)

```
app/
    main.py
    api/
        runs.py
        inbox.py
        audit.py
        dashboard.py
        policies.py
        health.py
    views/
        routes.py      (page routes that render Jinja templates)
    middleware.py
    auth.py            (Warden-Key validation)
    dependencies.py    (FastAPI DI: executor, journal, policy)
```

### Responsibility

- Implement all FastAPI route handlers per [`docs/API_CONTRACT.md`](API_CONTRACT.md).
- Own request validation (Pydantic models).
- Own `Warden-Key` header authentication (`auth.py`).
- Own service layer: inject `GuardedExecutor`, `AuditJournal`, `PolicyEngine` via FastAPI `Depends()`.
- Serve Jinja templates for page routes.
- Serve HTMX partial fragments (HTML vs JSON based on `HX-Request` header).

### Explicit exclusions

- Does NOT own governance logic (executor, policy, journal — workstreams C/E).
- Does NOT own Jinja template design (workstream A).
- Does NOT own projection calculation (workstream F).

### Dependencies

| Dependency | From | Stable? |
|---|---|---|
| `GuardedExecutor.execute()` interface | Workstream C | Use `MockExecutor` (see INTEGRATION_GUIDE) |
| `AuditJournal.query()` | Workstream E | Use `MockJournal` |
| Projection view models | Workstream F | Use static fixtures |

### Stable contracts (workstream B produces these)

- All HTTP routes in `API_CONTRACT.md`.
- `Warden-Key` resolution → `principal: str`.
- Pydantic request/response schemas.

### Acceptance criteria

- All proposed routes in `API_CONTRACT.md` respond correctly.
- Invalid `Warden-Key` returns `401`.
- Missing gate returns `404`.
- Already-decided gate returns `409`.
- Infrastructure failure returns `503`, not `500`.
- All routes have corresponding pytest tests.

---

## Workstream C — GuardedExecutor and PolicyEngine

### Owned files (proposed)

```
src/warden/
    executor.py
    policy/
        engine.py
        store.py
        versions.py
```

### Responsibility

- Implement `GuardedExecutor.execute()` per [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) and the execution flow in [`../ARCHITECTURE.md`](../ARCHITECTURE.md).
- Implement write-ahead journaling (append `action_requested` before `evaluate()`).
- Implement `PolicyEngine.evaluate()` — load rules, match action, return `allow`/`escalate`/`deny`.
- Implement `policy/store.py` — PostgreSQL CRUD + pgvector embedding storage.
- Implement `policy/versions.py` — append-only version table.
- Implement seed policy loading.

### Explicit exclusions

- Does NOT implement the HITL re-entry helper (workstream D).
- Does NOT implement the sandbox or LLM client (workstreams D/E/F).
- Does NOT implement FastAPI routes (workstream B).

### Dependencies

| Dependency | From | Stable? |
|---|---|---|
| `AuditJournal.append()` | Workstream E | Use `MockJournal` (INTEGRATION_GUIDE) |
| `SandboxPort.run()` | Workstream E | Use `MockSandbox` |
| `GuardedLLMClient.invoke()` | Workstream F | Use `MockLLMClient` |

### Stable contracts (workstream C produces these)

- `GuardedExecutor.execute(action, ctx, approval?) → Outcome` — must match exactly.
- `PolicyEngine.evaluate(action, ctx) → PolicyResult`.
- Seed policies loaded correctly on boot.

### Parallel-development rule

The `executor.py` interface is the most critical shared contract. Define the full Python interface (docstring + type signature) **before any other workstream builds a caller**. Every caller must use `MockExecutor` until the real implementation is ready.

### Acceptance criteria

- `execute()` never raises for environmental failures.
- `DENY` is terminal — no code path leads from `Denied` to execution.
- Write-ahead: `action_requested` is in the journal before `evaluate()` is called.
- Policy matrix: allow / escalate / deny each produce the correct `Outcome`.
- Seed policies block `DROP TABLE` (deny) and gate `send_email` (escalate).

---

## Workstream D — LangGraph Workflow and HITL Re-entry

### Owned files (proposed)

```
src/warden/
    hitl/
        runner.py
        gate.py
agents/
    ops_assistant.py
```

### Responsibility

- Implement `hitl/runner.py`: the `run_gated()` re-entry helper (called from graph nodes).
- Implement `agents/ops_assistant.py`: the single ops-assistant graph (Phase 1).
- Wire the HITL loop: `execute()` → `Pending` → `interrupt()` → park → resume → `execute()`.
- Ensure the node re-run on resume is idempotent (write-ahead key handles this).

### Explicit exclusions

- Does NOT implement `GuardedExecutor.execute()` (workstream C).
- Does NOT implement `AuditJournal` (workstream E).
- The re-entry helper is written ONCE. It is not rewritten per agent.

### Dependencies

| Dependency | From | Stable? |
|---|---|---|
| `GuardedExecutor.execute()` | Workstream C | Use `MockExecutor` |
| `CheckpointManager` | Phase 0 ✅ | Stable |
| LangGraph `interrupt`, `Command` | LangGraph | Stable |

### Key design rule

`execute()` returns `Pending` explicitly. `run_gated()` (not `execute()`) calls `interrupt()`. This is Lock 2 — do not implement transparent interrupts inside `execute()`.

### Acceptance criteria

- Email send: graph parks on `interrupt()`, resumes on approval, action executes.
- Denial by reviewer: action NOT executed, `Denied` outcome recorded.
- Crash recovery: park, kill process, restart, resume thread — workflow continues.
- No duplicate output: the draft node does not re-execute after resume.
- Ops-assistant covers the four Phase 1 demo points.

---

## Workstream E — AuditJournal and SandboxPort

### Owned files (proposed)

```
src/warden/
    journal.py
    sandbox.py
```

### Responsibility

- Implement `AuditJournal`: append-only PostgreSQL write with idempotency index.
- Implement `SandboxPort`: subprocess adapter (code/shell/file) + in-process adapter (API tools).
- Subprocess adapter: timeout enforcement, scrubbed environment, output capture.
- Journal: `append()`, `query()` with filters.

### Explicit exclusions

- Does NOT implement the executor (workstream C).
- Does NOT implement projections (workstream F).

### Dependencies

| Dependency | From | Stable? |
|---|---|---|
| `models.py` `Action`, `Outcome` | Phase 0 ✅ | Stable |
| PostgreSQL connection | Workstream F (infra) | Use `pg_uri` fixture |

### Stable contracts (workstream E produces these)

- `AuditJournal.append(event)` — idempotent for write-ahead event kinds.
- `AuditJournal.query(filters)` — returns ordered events.
- `SandboxPort.run(action)` — always returns `ExecutionResult`, never raises.

### Security acceptance criteria

- Subprocess env is fully scrubbed — no credentials or env vars leak into subprocess.
- Subprocess timeout fires and returns `timed_out=True`.
- `rm -rf /` in a shell action is contained (process dies at timeout; filesystem damage is bounded by OS-level limits).
- Journal row is never overwritten — only appended.

---

## Workstream F — PostgreSQL, LLM Client, Projections, Integration Testing

### Owned files (proposed)

```
src/warden/
    llm.py
    projections/
        telemetry.py
        inbox.py
        decision_graph.py
migrations/
    001_journal_events.sql
    002_policies.sql
    003_policy_versions.sql
tests/
    test_executor_integration.py   (integration tests across all components)
    test_e2e_demo.py               (Phase 1 four-beat demo test)
```

### Responsibility

- Implement `GuardedLLMClient`: invoke model via langchain-openai, journal usage.
- Implement all three projection functions (`telemetry`, `inbox`, `decision_graph`).
- Write and maintain PostgreSQL migrations.
- Own the integration and e2e test suite.
- Own pgvector setup for policy semantic retrieval (Phase 2).

### Explicit exclusions

- Does NOT implement the executor (workstream C).
- Does NOT implement FastAPI routes (workstream B).

### Dependencies

All other workstreams must be complete (or have stable mocks) before integration tests can run.

### Acceptance criteria

- Migrations run idempotently on a fresh Postgres instance.
- Telemetry projection aggregates token counts and latency correctly.
- Inbox projection shows only `pending` gate requests.
- Decision-graph projection correctly joins journal events to checkpoint steps.
- Integration test covers the full Phase 1 four-beat demo.

---

## Parallel Development Rules

1. **Never define your own `Outcome` variant.** Use `models.py`.
2. **Never define your own approval schema.** Use `GateRequest` / `GateDecision` from `models.py`.
3. **Never parse checkpoint state for audit data.** Journal = evidence, checkpointer = control flow (Lock 3).
4. **Always use `MockExecutor` / `MockJournal` / `MockSandbox`** when your dependency is not ready. Definitions are in [`INTEGRATION_GUIDE.md`](INTEGRATION_GUIDE.md).
5. **Workstream C (executor interface) must be finalized first.** All other workstreams that call `execute()` depend on its signature.
6. **DENY is terminal in all code paths.** No workstream may add a bypass.
7. **No React, no client-side build.** UI is Jinja + HTMX (Lock 12).

---

## Integration Owner

The developer responsible for workstream F also owns the final integration test (`test_e2e_demo.py`) that proves all four Phase 1 demo beats work end-to-end. This is the Phase 1 exit criterion.

If there is a conflict between two workstreams' assumptions about a shared interface, raise it by opening a discussion against `CONTEXT.md` before implementing either side.

---

## Suggested Milestones

| Milestone | Deliverable | Workstreams |
|---|---|---|
| M1 — Executor interface frozen | `executor.py` type signatures + docstrings published; `MockExecutor` available | C |
| M2 — Journal and Sandbox green | `journal.py` + `sandbox.py` tested independently | E |
| M3 — Executor + Policy green | `execute()` + `PolicyEngine` unit tests pass; all four outcome types verified | C |
| M4 — HITL loop green | `run_gated()` + ops-assistant park/resume demo works in CLI | D |
| M5 — FastAPI skeleton green | All routes in `API_CONTRACT.md` respond (even with mock data) | B |
| M6 — Projections + UI green | Dashboard, inbox, audit render with real journal data | A, F |
| M7 — Phase 1 integration | `test_e2e_demo.py` passes; four demo beats verified; mypy clean | F, all |
