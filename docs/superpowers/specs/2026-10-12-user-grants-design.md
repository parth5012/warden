# User-Granted Temporary Permissions ("Grants") — Design Spec

Date: 2026-10-12 | Status: approved design, pending spec review | Session: `.tmp/sessions/2026-10-12-pr16-leases-evals/`

## 1. Problem

Today every risky action parks for per-action approval (`escalate → Pending → inbox → approve`). For a task that is *inherently* risky ("clean up `/workspace/tmp/`, drop table `staging_imports`"), the user answers the same question N times. Yash's PR-16 leases do not solve this: they are supervisor-minted custody tokens proving *which specialist was assigned*, not human authorizations saying *what the agent may do*. Decision: drop the custody-lease design; build user-minted, task-scoped, time-bound permission grants instead.

## 2. Goal

Let the user say once, up front (or at the first gate): "for this task, the agent may perform these risky operations, within these bounds, for this long / this many times." Covered `escalate` actions then auto-allow (journaled as grant consumption) instead of parking. Everything else behaves exactly as today.

## 3. Non-goals

- No override of `deny`. Lock 5 stands: terminal denies are never grantable. Scoped destructive work becomes grantable via *policy reclassification* (§5), not via lock amendment.
- No supervisor-minted custody tokens. `src/warden/leases.py` + `tests/test_leases.py` (PR-16 port) are removed in implementation.
- No login/roles beyond named keys (lock 8). `granted_by` is a named key recorded in the journal.
- Golden eval datasets (`tests/evals/golden/`) are kept; they are policy data, unaffected.

## 4. Concepts

- **Grant**: a human-issued, task-scoped capability. Fields: `id`, `thread_id`, `granted_by` (named key), `scope` (list of scope rules), `ttl_seconds`, `max_uses`, `uses`, `status` (`active | exhausted | expired | revoked`), `created_at`, `reason` (why the task needs it).
- **Scope rule**: `{tool, constraints}`. Constraints use exact-plus-prefix matching: exact names for structured targets (table `staging_imports`, service `postgres_primary`); path prefixes for files (`/workspace/tmp/`). Anything outside all rules is not covered.
- **Lifecycle**: `active` → (`uses >= max_uses` → `exhausted`) / (wall-clock past `created_at + ttl` → `expired`) / (explicit revoke → `revoked`) / (thread ends → `expired`). First terminal state wins; evaluation is fail-closed (missing/corrupt/expired store → no coverage → park as today).

## 5. Policy reclassification (policy change, not lock change)

Today `exec_db_mutation` with `DROP TABLE` and sensitive reads are blanket L0/L1 `deny`. New behavior:

- **Unparseable or unbounded destructive intent stays `deny`**: `DROP DATABASE`, `rm -rf /`, `/etc/shadow`, path traversal, unparseable payloads. Terminal, ungrantable, unchanged UI ("not approvable").
- **Scoped, parseable destructive intent becomes `escalate`** with dedicated rule ids (e.g. `scoped-ddl-drop-table`, `scoped-fs-batch-delete`): an explicit single table name, or a file operation confined under an explicit path prefix. The engine only asserts *parseability + boundedness*; it never sees grants.
- `batch_delete_files` / `mass_delete` / `restart_service` / `send_email` remain `escalate` as today and are grantable without reclassification.

## 6. Executor integration (approach A: executor-side check)

On the `escalate` path only, after `POLICY_EVALUATED` is journaled and before `GATE_REQUESTED`:

1. Look up live grants for `action.thread_id` (store interface `GrantsStore`, in-memory first, Postgres later).
2. Find the first `active` grant whose scope rules cover `(action.name, payload)` per §4 matching.
3. If found: `uses += 1` (transition to `exhausted` if at max), journal `grant_consumed {grant_id, action_id, uses_left}`, return `Allowed` via the normal execution path (sandbox/side-effect handling unchanged).
4. If none: proceed to `Pending` exactly as today.
5. `deny` and `Error` paths are untouched — no grant lookup occurs.

Journal owns the evidence: `grant_issued`, `grant_consumed`, `grant_revoked`, `grant_expired` (on lazy observation) join the existing event stream; inbox/audit timeline renders them like gate events.

## 7. Issuance, revocation, expiry

- **Path 1 — upfront**: task start form gains an optional grant block (scope rules builder, TTL default 30 min, max-uses default 5, reason). Issued with the run's first journal events, `granted_by` from the `Warden-Key` header.
- **Path 2 — inbox upgrade**: on any `Pending` gate, the approver may choose "grant rest of task" — prefilled scope suggestion derived from the parked action (same tool, constraints narrowed from its payload), editable TTL/uses — instead of one-shot approve. Issues the grant *and* resolves the parked gate under it (one `grant_consumed`).
- **Revocation**: `POST /grants/{id}/revoke` (named key) → `revoked`, effective on the next executor check (in-flight execution is never killed). Grants list shows live `uses`/`remaining` countdowns.
- **Defaults**: TTL 30 min (5–240 range), max-uses 5 (1–50). Task end expires all its grants.

## 8. API / UI surface

- `POST /grants` (issue), `GET /grants?thread_id=` (list), `POST /grants/{id}/revoke`; all JSON-clean, HTMX partials for cards/table (lock 12).
- Approvals page: "grant rest of task" action beside approve/deny; grants section with revoke buttons.
- Audit search gains `grant_issued|grant_consumed|grant_revoked` kinds.

## 9. Testing

- Unit: scope-matching matrix (exact/prefix/miss), expiry boundary, uses exhaustion, revoke, corrupt store fail-closed, `deny` never consults grants.
- Integration: upfront-grant run auto-allows N then parks on N+1; inbox-upgrade resolves parked gate; revoke mid-run re-parks; kill-mid-park replay preserves `uses`.
- E2E: issue → risky task completes uninterrupted → revoke → next attempt parks.

## 10. Rollout

1. Remove `src/warden/leases.py`, `tests/test_leases.py` (untracked port, no migration).
2. Policy: add scoped-destructive `escalate` rules + tests; keep all `deny` tests green.
3. Kernel: `GrantsStore` protocol + in-memory adapter + executor check + journal events + tests.
4. HTTP + UI: grants endpoints, task-form block, inbox upgrade, grants list, audit kinds.
5. Docs: CONTEXT glossary entry (Grant vs Gate), DECISIONS entry for the reclassification.

## Self-review (2026-10-12)

- Placeholders: none — defaults, ranges, and rule ids are concrete.
- Consistency: §5 reclassifies *parseable/bounded* destructive intent only; §6 never consults grants on `deny` — lock 5 holds throughout.
- Scope: single feature slice (executor check + reclassification + issuance UI); Postgres-backed store explicitly deferred.
- Ambiguity resolved: matching is exact-plus-prefix (§4), not semantic; TTL default 30 min; in-flight executions survive revoke.
