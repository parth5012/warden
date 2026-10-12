# ROADMAP.md — PS5 build phases

Decision 10: start with ONE agent that proves all four PS bullets, then expand slowly. Each phase ends with something demoable. Do not start a phase before the previous one is green (tests + typecheck + manual demo run).

## Phase 0 — Foundation
- Repo init, Python env, FastAPI skeleton, Postgres + pgvector, LangGraph installed
- `CONTEXT.md`, this file, `DECISIONS.md` seeded from the grilling session
- Empty `AuditJournal` + migrations

## Phase 1 — The core story (single ops-assistant agent)
One graph, four proof points:
1. **Telemetry** — LLM calls + tool calls journaled: token cost, latency, tool usage (projections over the journal)
2. **HITL gate** — email send → policy `escalate` → `Pending` → re-entry helper parks → approvals inbox shows the request → approve with named key → action executes
3. **Guardrail deny** — `DROP TABLE` → policy `deny` → terminal, no approval possible (demo the refusal)
4. **Sandbox** — shell tool `rm -rf` → contained in Docker container with network isolation

Exit criteria: judge can watch all four beats live; `pytest` green; journal survives a kill -9 mid-park (write-ahead replay works).

## Phase 2 — Policy as a product
- Policy CRUD API + versions table (append-only, lock 9)
- Minimal policy editor UI: change a rule live → very next action behaves differently
- pgvector semantic retrieval wired into `PolicyEngine.evaluate` ("which rule applies?")

Exit criteria: live rule-change demo, `policy_versions` shows who/when/what.

Lock 12 note: the Phase 1 console was delivered as plain HTML renderers + HTMX partials (no Jinja), so the ARCHITECTURE.md layout now points at `app/dashboard.py` instead of `app/views/`.

## Phase 3 — Expand the cast (multi-agent)
- Second agent (researcher or writer) sharing the same executor
- Cross-agent cost/latency leaderboard (projection, no new tables)
- Run comparison view: two threads, one timeline

## Phase 4 — Explainability polish
- Decision-graph view: journal events → graph, joined with checkpoint steps (lock 3)
- Searchable audit log UI (filters: run, actor, action kind, verdict)
- Run replay: pick a run, walk it event by event

## Explicitly out of scope (for now)

- Login/roles (lock 8: named keys only)
  - Subprocess sandbox adapter (dropped in favor of Docker network isolation, DECISIONS.md entry 1)
- Policy override by humans (lock 5: DENY is terminal)
- Anything in `CONTEXT.md` open-questions list that isn't picked up by a phase
- Jinja templates: the console currently uses plain HTML renderers + HTMX partials, not Jinja
