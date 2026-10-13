# CONTEXT.md — Warden: AI Agent Governance & Human Accountability

Product name: **Warden** (lock 11). Repo: https://github.com/parth5012/warden (branch `main`).

Status: **design grilling in progress.** Decisions below are LOCKED — do not re-litigate in later sessions; reopen only with a load-bearing reason and record it in `DECISIONS.md`.

## Domain glossary

| Term | Meaning |
|---|---|
| **Action** | The unit that crosses the executor seam. `kind ∈ {tool, llm}`. Tools = emails, DB writes, payments, code exec. LLM = model calls. |
| **GuardedExecutor** | The deep module. One interface: `execute(action, ctx) -> Outcome`. All governance lives behind it. |
| **Outcome** | `Allowed(result)` \| `Denied(reason, policy)` \| `Pending(gate_request)` \| `Error(reason)`. |
| **Policy decision** | `allow` \| `escalate` \| `deny`. Only `escalate` ever reaches a human. |
| **Gate (HITL)** | Human approval point. Expressed as `Pending(gate_request)`; parked by the re-entry helper. |
| **Grant (Capability)** | Human-issued, task-scoped, time-bound capability auto-allowing covered `escalate` actions without human parking. |
| **Custody lease (dropped)** | Yash PR-16 supervisor-minted specialist assignment token; dropped in favor of user grants. |
| **Re-entry helper** | The single function (in `governance/hitl/`) that runs `execute()` → parks on `Pending` → resumes with the human decision → re-calls `execute()`. Every demo graph calls this; nobody rewrites it. |
| **AuditJournal** | Append-only event store. Source of truth for telemetry, search, decision graph, approvals inbox. |
| **Projection** | Pure function `events -> view`. Cost rollup, latency, decision graph, approvals inbox are all projections. |
| **Checkpointer** | LangGraph's durable store. Owns *where a run is parked* + resume values. Never parsed for audit — journal owns *what happened*. |
| **Gate request** | Journal event emitted when policy says `escalate`. Feeds the approvals inbox. |
| **run_id / action_id / thread_id** | Identity keys. Journal idempotency key = `(run_id, action_id)`. Events also carry LangGraph `thread_id` + checkpoint step. |

## Locked decisions

1. **Both tool and LLM calls cross the seam** (`Action.kind ∈ {tool, llm}`). One path → telemetry and decision graph are pure journal projections, no join against callback logs.
2. **`execute()` returns Pending explicitly** — no invisible interrupt inside it. Park orchestration lives ONCE in the re-entry helper, called from graph nodes. (Chosen over transparent-interrupt: data can't be swallowed by a broad `except Exception`.)
3. **Write-ahead + checkpointer division of labor.** `action_requested` appended *before* the gate, keyed `(run_id, action_id)` → idempotent no-op when LangGraph re-runs the node. Checkpointer = control-flow fault tolerance (park/resume). Journal = evidence. Approvals inbox reads journal projection, never checkpoint state.
4. **Fail-closed.** Governance store unavailable → `Error(governance_unavailable)`, distinct from `Denied`. Interface invariant: `execute()` never raises for environmental reasons — only bugs raise.
5. **DENY is terminal.** No human override of a policy `deny`. Humans only resolve `escalate`. Wrong rule → edit the policy (versioned, audited).
6. **Standalone repo:** `D:\work\projects\ps5-governance` — own git history, clean for hackathon submission.
7. **One sandbox port, Docker containment.** (Reopened 2026-10-11, DECISIONS.md entry 1). Every tool action calls `sandbox.run(action)`; inside the adapter, code/shell/file tools → Docker container (--network=none, read-only rootfs, 256MB/1 CPU/30s caps, tmpfs, single workspace bind mount, SandboxUnavailable fail-closed), API tools → in-process. LLM actions skip sandbox — timeout + token accounting only. Subprocess adapter dropped.
8. **Approver identity = named keys.** A few `name:key` pairs in an env file, sent as a header. `approver: alice` must be a true statement in the journal. Not real auth, doesn't pretend to be. No login system.
9. **Policies live in the DB.** One store tells the whole accountability story (actions, approvals, rule changes). Guardrail: append-only `policy_versions` table (`policy_id, version, content, who, when`) — lock 5's "edits are logged" promise. Repo ships seed policies loaded on first boot; after that, DB owns the truth. pgvector index lives beside the rows — atomic, no file-sync pipeline.
10. **Demo = phased, single agent first.** Phase 1: one "ops assistant" agent with email + DB + shell tools, proving all 4 PS bullets on one graph (gate on send, deny on DROP TABLE, sandbox on rm -rf, cost/latency telemetry). Then expand slowly (see ROADMAP.md): policy editor UI → multi-agent cost comparison → polish. Don't build multi-agent before the core story works.
11. **Name = Warden.** One word, enforcement + oversight, not 400 repos deep.
12. **UI = server-rendered in the FastAPI app.** Jinja + HTMX, one process, no build step. Endpoints stay JSON-clean so a React frontend can lift later if ever needed.

### Derived implications (follow from locks, not separately decided)

- For `kind=llm`, `execute()` invokes the model itself through an injected **LLM client adapter** (`Action(kind=llm, model, messages)` → provider call → `response.usage` → journal). Graph nodes never call the model directly — that would recreate the second telemetry path rejected in decision 1.

## Open questions (grilling queue)

- Sandbox scope: DONE (lock 7)
- Approver identity: DONE (lock 8)
- What `execute()` does for an LLM action: DONE (derived from locks 1+7 — injected LLM client adapter)
- Policy storage: DONE (lock 9)
- Demo scenario: DONE (lock 10, phases in ROADMAP.md)
- FastAPI surface + approvals UI shape: DONE (lock 12 — server-rendered Jinja+HTMX, JSON-clean endpoints)
- Product name: DONE (lock 11 — Warden)

## Related docs

- `ARCHITECTURE.md` — full system design (the shared understanding)
- `ROADMAP.md` — build phases with exit criteria
- `DECISIONS.md` — TBD, one entry per lock with rationale/alternatives

## Stack (from PS)

FastAPI · LangGraph · Python · Chroma/pgvector for policy retrieval.
