# STATUS.md — Aegis: What's Built

> Last updated: 2026-10-11

---

## Overall Progress

| Phase | Name | Status |
|---|---|---|
| 0 | Foundation | ✅ Done |
| 1 | Core story (single ops-assistant agent) | 🔨 In progress |
| 2 | Policy as a product | ⬜ Not started |
| 3 | Multi-agent | ⬜ Not started |
| 4 | Explainability polish | ⬜ Not started |

---

## What's Actually Built

### ✅ Project scaffold
- `pyproject.toml` — uv-managed, Python 3.11, direct deps declared (`psycopg-pool`, `langchain-core`, `typing-extensions`)
- `src/warden/` package, `tests/` package (both with `__init__.py`)
- `.gitignore`, `.python-version`

---

### ✅ `src/warden/models.py`
Core domain types:
- `Action` — unit that crosses the executor seam (`kind ∈ {tool, llm}`, `name`, `payload`, `run_id`, `thread_id`)
- `Outcome` — `Allowed` | `Denied` | `Pending` | `Error`
- Gate types (`GateRequest`, `GateDecision`)
- `CheckpointInfo` — view type for checkpoint state inspection

---

### ✅ `src/warden/checkpoint.py` — `CheckpointManager`
The deep module for LangGraph checkpoint infrastructure:

| Feature | Detail |
|---|---|
| `create(conn_string)` | Async context manager, owns `AsyncPostgresSaver` lifecycle; idempotent setup on every boot |
| `health_check()` | Probes connection (handles both connection and pool) |
| `get_state_info()` | Logged state inspection, **fail-closed** → `Error("governance_unavailable")`, never raises |
| `get_state_history()` | Returns oldest-first ordered history (reversed from LangGraph default newest-first) |
| `resume(graph, config, value)` | Logging wrapper around `graph.ainvoke(Command(resume=...))`, fail-closed |
| Connection string redaction | `_redact()` — masks URI userinfo **and** keyword-DSN `password=...` form; urlsplit-based |

---

### ✅ `src/warden/demo_graph.py`
Draft demo LangGraph graph:
- Three-node flow: `draft → interrupt(approval) → send/abort`
- Proves park/resume mechanics with the checkpointer

---

### ✅ `tests/conftest.py`
- Session-scoped real-PostgreSQL fixture (via bundled `pgserver`, no root required)

---

### ✅ `tests/test_checkpoint.py` — 12 tests vs real Postgres
Covers:
- Idempotent setup
- Park/resume (approve + deny paths)
- No duplicate output on resume
- **Manager-restart recovery** (crash-and-rejoin)
- History walk (asserts non-decreasing step order)
- Fail-closed after close (`state`, `history`, `resume` all return `Error`)
- Bad-connection startup failure
- `_redact` — 6-case parametrize (URI form, keyword-DSN, `@` in query string, etc.)

---

### ✅ `tests/cli_chat.py` — CLI chat harness
Reusable interactive CLI for any compiled LangGraph graph:

| Command | Behaviour |
|---|---|
| `/state` | Print current checkpoint state |
| `/history` | Walk all checkpoint steps |
| `/new` | Start a new thread |
| `/resume` | Manually trigger resume |
| `/quit` | Exit cleanly (no traceback on EOF/Ctrl-C) |
| _(parked thread on rejoin)_ | Auto-detects park, prompts for resume decision |

- Auto-starts bundled `pgserver`; `--pg` / `WARDEN_PG_URI` to override
- Server intentionally left running so restart-and-resume is demoable
- `/quit` at the `resume>` prompt exits cleanly without treating it as a decision value (bug fix)

---

### ✅ `tests/test_cli_chat.py` — 4 regression tests
- `/quit` at resume prompt → thread stays parked
- Empty re-prompt stays in prompt loop
- Failed resume → re-prompts (doesn't route as decision)
- Re-park loop re-prompts correctly

---

## Key Design Decisions Locked In

| Lock | Decision |
|---|---|
| 1 | Both tool and LLM calls cross the executor seam |
| 2 | `execute()` returns `Pending` explicitly — no transparent interrupt inside it |
| 3 | Write-ahead + checkpointer division of labour: journal = evidence, checkpointer = control-flow |
| 4 | Fail-closed everywhere — `execute()` never raises for environmental reasons |
| 5 | DENY is terminal — no human override of a policy deny |
| 7 | One sandbox port, adapter routes itself |
| 8 | Approver identity = named keys in env |
| 9 | Policies live in DB (`policy_versions` append-only) |
| 10 | Single ops-assistant agent first, then expand |
| 11 | Product name = **Aegis** |
| 12 | UI = Jinja + HTMX, server-rendered in FastAPI, JSON-clean endpoints |

---

## What's NOT Built Yet (Phase 1 remaining)

- `GuardedExecutor` (`executor.py`) — the core seam
- `AuditJournal` (`journal.py`) — append-only event store + write-ahead
- `PolicyEngine` (`policy/engine.py`) — allow / escalate / deny evaluation
- HITL re-entry helper (`hitl/runner.py` → `run_gated`)
- `SandboxPort` (`sandbox.py`) — subprocess adapter
- LLM client adapter (`llm.py`)
- Projections: telemetry, inbox, decision graph (`projections/`)
- FastAPI app (`app/`) + all HTTP endpoints
- Ops-assistant agent graph (`agents/ops_assistant.py`)
- Postgres migrations + pgvector setup
- Seed policies

---

## Test & Quality Status

```
pytest   →  22 passed (12 checkpoint + 4 cli loop + 6 redact)
mypy     →  0 errors (strict mode, 12 files)
PR #1    →  OPEN, CodeRabbit pass, GitGuardian pass, merge state CLEAN
```
