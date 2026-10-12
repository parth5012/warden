# Warden — Documentation Index

This directory contains shared architecture, API, data model, security, testing, and integration documents for the Warden project.

**Start here if you are new to the project.** After reading this index, follow the recommended reading order below before touching any code.

---

## Recommended Reading Order

### For all contributors

1. [`../CONTEXT.md`](../CONTEXT.md) — **Read this first.** Locked design decisions and the domain glossary.
2. [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — Full system design and the four PS demonstration points.
3. [`../ROADMAP.md`](../ROADMAP.md) — Build phases and exit criteria.
4. [`../STATUS.md`](../STATUS.md) — What is implemented right now vs. what is planned.
5. [`ARCHITECTURE.md`](ARCHITECTURE.md) — Component-level diagrams and execution flows.

### Before writing code

6. [`DATA_MODEL.md`](DATA_MODEL.md) — Domain types, action lifecycle, proposed persistence schemas.
7. [`API_CONTRACT.md`](API_CONTRACT.md) — HTTP endpoints (existing vs. proposed).
8. [`INTEGRATION_GUIDE.md`](INTEGRATION_GUIDE.md) — Component dependencies and mock interfaces.
9. [`TEAM_OWNERSHIP.md`](TEAM_OWNERSHIP.md) — Which workstream owns which files and interfaces.

### Before writing tests

10. [`TESTING_STRATEGY.md`](TESTING_STRATEGY.md) — Test inventory, acceptance criteria, fixture conventions.
11. [`SECURITY_MODEL.md`](SECURITY_MODEL.md) — Security tests and threat model.

### Environment setup

12. [`LOCAL_SETUP.md`](LOCAL_SETUP.md) — Exact setup commands.
13. [`DEVELOPMENT_GUIDE.md`](DEVELOPMENT_GUIDE.md) — Coding conventions, branch workflow, troubleshooting.

---

## Document Index

### Shared Architecture and Contracts

| Document | Purpose | Status |
|---|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Component diagrams, execution flows, mermaid diagrams | Available |
| [`LAYERED_SAFETY_ARCHITECTURE.md`](LAYERED_SAFETY_ARCHITECTURE.md) | 3-tier policy engine: L0 static AST, L1 DeBERTa, L2 Granite Guardian | Available |
| [`API_CONTRACT.md`](API_CONTRACT.md) | HTTP routes, request/response schemas, auth requirements | Available |
| [`DATA_MODEL.md`](DATA_MODEL.md) | Domain types, persistence schemas, contract definitions | Available |
| [`INTEGRATION_GUIDE.md`](INTEGRATION_GUIDE.md) | Component wiring, integration order, mock interfaces | Available |

### Team and Process

| Document | Purpose | Status |
|---|---|---|
| [`TEAM_OWNERSHIP.md`](TEAM_OWNERSHIP.md) | Workstream ownership, parallel development rules | Available |
| [`DEVELOPMENT_GUIDE.md`](DEVELOPMENT_GUIDE.md) | Environment, conventions, PR workflow | Available |
| [`LOCAL_SETUP.md`](LOCAL_SETUP.md) | Quick-start installation | Available |

### Quality and Security

| Document | Purpose | Status |
|---|---|---|
| [`TESTING_STRATEGY.md`](TESTING_STRATEGY.md) | Test inventory, scenarios, acceptance criteria | Available |
| [`SECURITY_MODEL.md`](SECURITY_MODEL.md) | Threat model, enforcement posture, unresolved risks | Available |
| [`REALTIME_EVENTS.md`](REALTIME_EVENTS.md) | HTMX polling, SSE contracts | Available |

---

## Feature Documentation (14 Slices)

Each slice corresponds to a major feature area. All are under [`features/`](features/).

| # | Slice | Owner workstream | Phase | Status |
|---|---|---|---|---|
| 01 | [UI and Operator Dashboard](features/01_ui_dashboard/README.md) | A | 1 | Planned |
| 02 | [FastAPI Application and HTTP](features/02_fastapi_http/README.md) | B | 1 | Planned |
| 03 | [GuardedExecutor](features/03_guarded_executor/README.md) | C | 1 | Planned |
| 04 | [PolicyEngine](features/04_policy_engine/README.md) | C | 1 | Planned |
| 05 | [HITL Approval and Re-entry](features/05_hitl_approval/README.md) | D | 1 | Partially implemented |
| 06 | [Ops-Assistant Agent](features/06_ops_assistant_agent/README.md) | D | 1 | Planned |
| 07 | [SandboxPort](features/07_sandbox/README.md) | E | 1 | Planned |
| 08 | [AuditJournal](features/08_audit_journal/README.md) | E | 1 | Planned |
| 09 | [PostgreSQL and Checkpoint](features/09_postgres_checkpoint/README.md) | F | 0 ✅ | Implemented |
| 10 | [Guarded LLM Client and Telemetry](features/10_llm_client_telemetry/README.md) | F | 1 | Planned |
| 11 | [Projections and Visibility](features/11_projections/README.md) | F | 1 | Planned |
| 12 | [Auth and Approval Authorization](features/12_auth_approval/README.md) | B/C | 1 | Planned |
| 13 | [Testing and Security Validation](features/13_testing_security/README.md) | All | All | Ongoing |
| 14 | [Local Dev and Demo Readiness](features/14_local_dev_demo/README.md) | All | All | Ongoing |

---

## Ownership Conventions

- **Implemented** — code exists and tests pass. Do not change architecture without discussion.
- **Planned** — documented interface that must be implemented. Use the mock contract in [`INTEGRATION_GUIDE.md`](INTEGRATION_GUIDE.md) while building.
- **Stub** — directory exists with `__init__.py` only. Ready for implementation.

### Status Labels in Feature READMEs

| Label | Meaning |
|---|---|
| ✅ IMPLEMENTED | Code exists, tests pass, mypy clean |
| 🔨 IN PROGRESS | Partially implemented or PR open |
| 📋 PLANNED | Documented, not yet started |
| 🔒 LOCKED | Design decision frozen — see CONTEXT.md |

---

## Contributing to Documentation

- Documentation for implemented features lives next to the source when practical; otherwise under `docs/features/`.
- Do not duplicate contract definitions. Link to [`DATA_MODEL.md`](DATA_MODEL.md) and [`API_CONTRACT.md`](API_CONTRACT.md) from feature READMEs.
- Keep "implemented" and "planned" clearly separated in every document.
- The root [`ARCHITECTURE.md`](../ARCHITECTURE.md) and [`CONTEXT.md`](../CONTEXT.md) are authoritative. Do not contradict them.
