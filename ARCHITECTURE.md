# ARCHITECTURE.md — Warden

AI Agent Governance & Human Accountability System. Full system design — the shared understanding from the design grilling. Decisions are in `CONTEXT.md`; build order is in `ROADMAP.md`.

## 1. What Warden is

A governance layer that LangGraph agents run *through*. Every LLM call and tool call crosses one seam — the **GuardedExecutor** — which journals it, checks it against policy, parks it for human approval when policy is unsure, sandboxes it when it executes, and returns one honest verdict. Nothing downstream of the seam can be skipped.

Four PS bullets, four mechanisms:

| PS bullet | Mechanism |
|---|---|
| Multi-agent telemetry (tokens, tools, latency) | One write path → `AuditJournal` → projections |
| HITL gates for irreversible actions | Policy `escalate` → `Pending` → re-entry helper parks → approvals inbox → resume |
| Policy guardrails + sandbox enforcement | `PolicyEngine.evaluate` (deny terminal) + `SandboxPort` adapter |
| Searchable audit + decision-graph explainability | Journal projections: search, decision graph joined to checkpoint steps |

## 2. The seam

```python
outcome = await executor.execute(action, ctx)
# -> Allowed(result) | Denied(reason, policy) | Pending(gate_request) | Error(reason)
```

- `Action = {id, kind: tool|llm, name, payload, run_id, thread_id}`
- `ctx` carries run identity from LangGraph config.
- **Invariant:** `execute()` never raises for environmental reasons — only bugs raise. Store down → `Error(governance_unavailable)` (fail-closed, lock 4). `Pending` is data, never an exception (lock 2).
- Callers: only the HITL re-entry helper (below) and telemetry-free read paths. Graph nodes never call tools or the model directly.

## 3. Execution flow (inside `execute()`)

```
1. journal.append(action_requested)        # keyed (run_id, action_id) — idempotent
2. decision = policy.evaluate(action, ctx) # deny-by-default
   deny      -> journal.append(denied)     # TERMINAL. no human may approve (lock 5)
   escalate  -> journal.append(gate_requested) -> return Pending
   allow     -> continue
3. (Pending path — outside execute) human decides via inbox
4. sandbox.run(action)                     # tools only; adapter routes itself (lock 7)
   llm kind  -> llm_client.invoke(action)  # usage -> journal (injected adapter)
5. journal.append(action_completed | action_failed)
6. return Allowed(result) | Error(...)
```

**Re-entry helper** (`warden/hitl/runner.py`, written ONCE, lock 2):

```python
outcome = await run_gated(action, ctx)   # called from graph nodes
# runs execute() -> on Pending: park via injected park-fn (LangGraph interrupt)
# -> resume (Command(resume=decision)) -> node re-runs -> execute(..., approval=decision)
# -> returns Allowed | Denied | Error
```

Journal idempotency (step 1 key) is what makes the node's re-run on resume safe.

**Division of labor (lock 3):** checkpointer = *where the run is parked* + resume value (LangGraph owns this, we build none of it). Journal = *what happened*, forever. Approvals inbox reads the journal projection — never parses checkpoint state.

## 4. Package layout

```
warden/
  warden/
    executor.py         # GuardedExecutor — the seam
    models.py           # Action, Outcome, journal event types
    journal.py          # AuditJournal: append(), query(), idempotent key
    policy/
      engine.py         # PolicyEngine.evaluate -> Layered L0 (Static) -> L1 (DeBERTa) -> L2 (Granite Guardian)
      store.py          # DB rows + pgvector retrieval adapter
      versions.py       # append-only policy_versions (lock 9 guardrail)
    hitl/
      gate.py           # gate request/decision types
      runner.py         # THE re-entry helper
      sandbox/           SandboxPort interface (port.py), registry (registry.py), Docker adapter (docker.py)
    llm.py              # LLM client adapter (usage -> journal)
    projections/        # telemetry.py, inbox.py, decision_graph.py — pure funcs
  app/
    main.py             # FastAPI app
    api/                # JSON endpoints (below)
    views/              # Jinja templates + HTMX (lock 12)
  agents/
    ops_assistant.py    # phase 1 graph
  policies/seed/        # seed rules, loaded on first boot (lock 9)
  tests/
```

Dependency rule: `warden/` imports nothing from `app/` or `agents/`. The governance kernel is a library; FastAPI and graphs are its callers.

## 5. Data model (Postgres + pgvector, one store)

| Table | Role |
|---|---|
| `journal_events` | append-only. `id, run_id, action_id, thread_id, checkpoint_step, kind, payload jsonb, actor, ts`. Idempotent on `(run_id, action_id, kind)` for write-ahead kinds |
| `policies` | current rule rows + embedding (pgvector) |
| `policy_versions` | append-only: `policy_id, version, content, who, when` |
| LangGraph checkpointer | same Postgres, different concern — park/resume only |

Approvals inbox, telemetry cards, decision graph, leaderboard = **projections** over `journal_events` (read-time; materialize only if slow).

## 6. HTTP surface (JSON-clean, HTMX renders them)

```
POST /runs                      start a thread (agent id in body)
GET  /runs/{thread_id}          status + timeline (projection)
GET  /inbox                     pending gate requests (HTMX partial)
POST /gates/{gate_id}/decision  {verdict: approve|deny, reason} + Warden-Key header
GET  /audit?q=&run=&kind=       searchable audit log
GET  /runs/{thread_id}/graph    decision-graph projection (joined to checkpoints)
GET  /dashboard                 telemetry: cost, latency, tool usage
# phase 2:
GET/POST /policies              list/create; POST /policies/{id} appends a version
```

Approve flow: append `gate_decided` event → `graph.invoke(Command(resume=...), config)` → run continues from the parked node.

## 7. Security posture

- Named-key header auth for approve/deny + policy writes (lock 8). Keys in env, principal recorded in journal.
- Fail-closed everywhere (lock 4). DENY terminal (lock 5).
- Sandbox: Docker container containment with --network=none, read-only rootfs, tmpfs scratch, 30s/256MB/1 CPU caps, --rm, and single workspace bind mount (D:\tmp) for code/shell/file tools; API tools in-process (reopened lock 7). Registry declares tool profiles and limits; adapter raises SandboxUnavailable on daemon down/missing image/unknown profile (fail-closed, executor maps to Error(governance_unavailable)). GuardedExecutor classifier decides whether a call is sandboxed; the sandbox package decides how.
- LLM egress: provider allowlist in config; `Error` if action targets an unlisted provider.

## 8. Testing strategy

The interface is the test surface:
- **Unit:** in-memory journal adapter, fake gate, in-process sandbox adapter, fake LLM client. `execute()` verdicts, idempotent write-ahead, policy matrix (allow/escalate/deny), re-entry helper loop.
- **Integration (real Postgres & Docker):** journal replay after kill mid-park, pgvector retrieval, version append; real Docker integration proofs with clean skip-gate when daemon is unavailable (tests/test_sandbox_integration.py proving network-none, read-only rootfs, timeout kill, and zero leftover containers).
- **E2E (Playwright):** the four Phase-1 beats — approve a gate in the UI, watch denial, watch sandbox containment, read the dashboard.

Two adapters per seam (journal, sandbox, gate, LLM client, policy store) = the seams are real, not decorative.

## 9. Demo flow (Phase 1)

1. Start run: "email the weekly report, clean up old files, show me the orders table."
2. Dashboard fills live: tokens, cost, latency per call.
3. `DROP TABLE` attempt → **Denied**, red card: "policy: no destructive SQL. not approvable."
4. Shell `rm -rf` → contained in Docker sandbox with network isolation, timeout logged.
5. Email send → **gated**: inbox shows request with full context → approve as `alice` → sends → timeline shows `requested → decided(approve, alice) → completed`.
6. Kill the process mid-park, restart, resume the thread — write-ahead intent proves nothing was lost.
