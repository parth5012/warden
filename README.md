# Warden — AI Agent Governance & Human Accountability

> **Every LLM call and tool call crosses one seam. Nothing downstream can be skipped.**

Warden is a governance layer that LangGraph-based agents run *through*. It provides a single, auditable execution path for all agent actions: every call is journaled, checked against policy, sandboxed, and — when policy is unsure — parked for human approval before any side effect takes place.

---

## Problem Statement

Autonomous AI agents can take irreversible actions: send emails, modify databases, run shell commands, call external APIs. Without a governance layer:

- You cannot audit what an agent did or why.
- You cannot intercept dangerous actions before they execute.
- You cannot require human sign-off on high-risk operations.
- You cannot enforce deterministic policy across multiple agents.

Warden solves this by making **every action cross a single, policy-enforced execution seam** before it can touch the outside world.

---

## Core Security Principle

```
No agent node calls a tool or model directly.
Everything goes through GuardedExecutor.execute(action, ctx) → Outcome.
```

The four possible outcomes are:

| Outcome | Meaning |
|---|---|
| `Allowed(result)` | Action passed policy and completed successfully |
| `Denied(reason, policy)` | Action blocked by policy — **terminal, no human override** |
| `Pending(gate_request)` | Action escalated — human approval required before execution |
| `Error(reason)` | Governance infrastructure failure — fail-closed, action not executed |

---

## Architecture Summary

```
Agent Graph (LangGraph)
        │
        ▼
  GuardedExecutor          ◄── the single seam
   ├── AuditJournal         write-ahead, append-only evidence
   ├── PolicyEngine         allow / escalate / deny
   ├── HITL Re-entry        park → human approval → resume
   ├── SandboxPort          subprocess adapter (code, shell, file tools)
   └── LLM Client Adapter   guarded model calls with usage journaling
        │
        ▼
  FastAPI App (Jinja + HTMX)
   ├── Approvals Inbox
   ├── Audit Explorer
   ├── Telemetry Dashboard
   └── Policy Viewer
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full design and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for component-level diagrams.

---

## Current Progress

| Phase | Status | What it covers |
|---|---|---|
| **0 — Foundation** | ✅ Complete | Scaffold, domain models, checkpoint manager, demo graph, 22 tests |
| **1 — Core story** | 🔨 In progress | GuardedExecutor, AuditJournal, PolicyEngine, HITL, Sandbox, FastAPI, ops-assistant agent |
| **2 — Policy as a product** | ⬜ Planned | Policy CRUD UI, pgvector semantic rule retrieval |
| **3 — Multi-agent** | ⬜ Planned | Second agent, cost/latency leaderboard |
| **4 — Explainability** | ⬜ Planned | Decision-graph view, run replay, searchable audit UI |

See [`STATUS.md`](STATUS.md) for the detailed build log and [`ROADMAP.md`](ROADMAP.md) for phase exit criteria.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11 |
| Package manager | [uv](https://github.com/astral-sh/uv) |
| Agent framework | LangGraph ≥ 0.4.0 |
| Checkpoint persistence | `langgraph-checkpoint-postgres` ≥ 2.0.0 |
| Database | PostgreSQL + pgvector |
| DB driver | psycopg3 (async) + psycopg-pool |
| LLM integration | langchain-core + langchain-openai |
| Web framework | FastAPI *(planned Phase 1)* |
| UI | Jinja2 + HTMX, server-rendered *(planned Phase 1)* |
| Testing | pytest + pytest-asyncio, real PostgreSQL via `pgserver` |
| Type checking | mypy (strict mode) |

---

## Repository Map

```
warden/
├── README.md                   ← you are here
├── ARCHITECTURE.md             ← full system design (authoritative)
├── CONTEXT.md                  ← locked design decisions + glossary
├── ROADMAP.md                  ← phased build plan with exit criteria
├── STATUS.md                   ← what is built right now
├── LOG.md                      ← session-by-session build log
├── LEARNINGS.md                ← LangGraph / tooling gotchas
├── pyproject.toml              ← uv project config
├── src/
│   └── warden/
│       ├── __init__.py
│       ├── models.py           ← Action, Outcome, Gate types, CheckpointInfo
│       ├── checkpoint.py       ← CheckpointManager (IMPLEMENTED)
│       ├── demo_graph.py       ← draft→approval→send/abort demo graph
│       ├── hitl/               ← HITL re-entry helper (stub)
│       ├── policy/             ← PolicyEngine (stub)
│       └── projections/        ← Telemetry, inbox, decision graph (stub)
├── tests/
│   ├── __init__.py
│   ├── conftest.py             ← session-scoped real-Postgres fixture
│   ├── cli_chat.py             ← interactive CLI harness (IMPLEMENTED)
│   ├── test_checkpoint.py      ← 12 checkpoint tests (IMPLEMENTED)
│   └── test_cli_chat.py        ← 4 CLI loop regression tests (IMPLEMENTED)
└── docs/
    ├── README.md               ← documentation index
    ├── ARCHITECTURE.md         ← component diagrams
    ├── API_CONTRACT.md         ← HTTP interface specification
    ├── DATA_MODEL.md           ← domain types and persistence schemas
    ├── INTEGRATION_GUIDE.md    ← component wiring and integration order
    ├── TEAM_OWNERSHIP.md       ← workstream ownership and parallel dev
    ├── DEVELOPMENT_GUIDE.md    ← environment setup and coding conventions
    ├── TESTING_STRATEGY.md     ← test inventory and acceptance criteria
    ├── SECURITY_MODEL.md       ← threat model and enforcement posture
    ├── REALTIME_EVENTS.md      ← HTMX polling and server-sent events
    ├── LOCAL_SETUP.md          ← quick-start installation guide
    └── features/               ← per-feature READMEs (14 slices)
```

---

## Installation

### Prerequisites

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) package manager
- PostgreSQL *(or use the bundled `pgserver` for development)*

### Setup

```bash
# Clone the repository
git clone https://github.com/parth5012/warden
cd warden

# Install all dependencies including dev tools
uv sync --extra dev

# Verify installation
uv run python -c "import warden; print('OK')"
```

---

## Running Tests

```bash
# Run all tests (requires no external Postgres — pgserver starts automatically)
uv run pytest

# Run with verbose checkpoint logs
uv run pytest -v

# Run a specific test file
uv run pytest tests/test_checkpoint.py

# Type-check all source and tests
uv run mypy src tests
```

Current baseline: **22 passed**, mypy **0 errors** (strict mode, 12 files).

---

## Running the CLI Harness

```bash
# Start interactive demo chat (auto-starts PostgreSQL via pgserver)
uv run python tests/cli_chat.py

# Resume a specific thread (crash-recovery demo)
uv run python tests/cli_chat.py --thread <thread-id>

# Use a custom PostgreSQL URI
WARDEN_PG_URI=postgresql://... uv run python tests/cli_chat.py

# Show checkpoint logs
uv run python tests/cli_chat.py --verbose
```

### CLI Commands

| Command | Action |
|---|---|
| `/state` | Show current checkpoint state |
| `/history` | Walk the full checkpoint history |
| `/new` | Start a fresh thread |
| `/resume <value>` | Resume a parked graph with a decision value |
| `/quit` | Exit cleanly (parked thread stays persisted) |
| `<text>` | Send text as graph input |

---

## Documentation Index

| Document | Purpose |
|---|---|
| [`docs/README.md`](docs/README.md) | Documentation index and reading order |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Component diagrams and flow |
| [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md) | HTTP interface specifications |
| [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) | Domain types and persistence schemas |
| [`docs/INTEGRATION_GUIDE.md`](docs/INTEGRATION_GUIDE.md) | Component wiring and integration order |
| [`docs/TEAM_OWNERSHIP.md`](docs/TEAM_OWNERSHIP.md) | Workstream boundaries |
| [`docs/DEVELOPMENT_GUIDE.md`](docs/DEVELOPMENT_GUIDE.md) | Coding conventions and PR workflow |
| [`docs/TESTING_STRATEGY.md`](docs/TESTING_STRATEGY.md) | Test inventory and acceptance criteria |
| [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) | Threat model and enforcement |
| [`docs/REALTIME_EVENTS.md`](docs/REALTIME_EVENTS.md) | HTMX event contracts |
| [`docs/LOCAL_SETUP.md`](docs/LOCAL_SETUP.md) | Quick-start setup |
| [`docs/features/`](docs/features/) | Per-feature READMEs (14 slices) |

---

## Current Limitations

- **No FastAPI app yet** — the web UI and HTTP endpoints are Phase 1 planned work.
- **No GuardedExecutor yet** — the core execution seam is not implemented.
- **No AuditJournal yet** — event persistence is not implemented.
- **No PolicyEngine yet** — policy evaluation is not implemented.
- **Subprocess sandbox is not a production security boundary** — it provides timeout and environment isolation; it does not replace a container-level sandbox.
- **Named-key authentication is not real auth** — it is a demonstration mechanism for the hackathon.
- **DENY is always terminal** — policy denials cannot be overridden by any human.

---

## Contribution Workflow

1. Read [`CONTEXT.md`](CONTEXT.md) to understand the locked decisions before writing code.
2. Read [`docs/TEAM_OWNERSHIP.md`](docs/TEAM_OWNERSHIP.md) to identify your workstream.
3. Read the relevant feature README under [`docs/features/`](docs/features/).
4. Use mock interfaces defined in [`docs/INTEGRATION_GUIDE.md`](docs/INTEGRATION_GUIDE.md) when your dependency is not yet implemented.
5. All PRs must pass `uv run pytest` and `uv run mypy src tests` with zero errors.
6. Do not change locked decisions in `CONTEXT.md` without opening a discussion.
