# Grant-05: Grants HTTP + task form + inbox upgrade + grants list

Labels: `wayfinder:task` (AFK) · Map: [User-Granted Temporary Permissions](../2026-10-12-user-grants-map.md)
Blocked by: Grant-04 · Claim: _unclaimed_

## Question

Expose both issuance paths (upfront grant block, inbox "grant rest of task") plus grant management UI, all JSON-clean with HTMX partials (lock 12).

## Do

1. Endpoints (new router, e.g. `app/grants.py`): `POST /grants` (issue: thread_id, scope rules, ttl 5–240 default 30, max-uses 1–50 default 5, reason; `granted_by` from `Warden-Key` header), `GET /grants?thread_id=`, `POST /grants/{id}/revoke`. Validate ranges; 404 unknown id; 409 already-terminal revoke.
2. Task start form: optional grant block prefilled with the defaults; issued alongside the run's first journal events.
3. Approvals page: beside approve/deny, "grant rest of task" — scope suggestion derived from the parked action (same tool, constraints narrowed from its payload; human-editable TTL/uses). Issuing it also resolves the parked gate under the grant (exactly one `grant_consumed`).
4. Grants list section: live `uses`, remaining countdown, revoke buttons; revocation effective on next executor check (never kills in-flight execution).
5. Tests: endpoint validation ranges, prefill derivation from a parked gate, revoke-then-act re-parks (via TestClient).

## Done when

- [ ] Both issuance paths work end to end against the Grant-04 executor behavior.
- [ ] pytest + mypy clean; templates render without Jinja errors.

## Context pointers

- Spec §7–8: `docs/superpowers/specs/2026-10-12-user-grants-design.md`
- Existing patterns: `app/leases.py` (HTMX table/fragment style — copy the interaction shape, not the mock store), `backend/api/inbox.py`

## Resolution

_unresolved — agent: append routes + manual click-through notes + verification output, then mark boxes._
