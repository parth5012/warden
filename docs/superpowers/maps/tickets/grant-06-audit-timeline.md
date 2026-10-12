# Grant-06: Audit kinds + timeline rendering

Labels: `wayfinder:task` (AFK) · Map: [User-Granted Temporary Permissions](../2026-10-12-user-grants-map.md)
Blocked by: Grant-04 (parallel with Grant-05) · Claim: _unclaimed_

## Question

Make grants first-class evidence in the audit trail: searchable kinds and a readable per-thread timeline.

## Do

1. Audit search (`backend/api/audit.py` + views): add `grant_issued | grant_consumed | grant_revoked` (| `grant_expired` if emitted) to kind filters and seed/mock entries if the audit page uses them.
2. Thread timeline (`backend/api/runs.py` + templates): render grant events inline with gate events (issued by whom, consumed with uses-left, revoked/expired), reusing the gate-event card style.
3. Tests: kind filter returns grant events; timeline for a grant-using thread shows issued → consumed ×N → parked/exhausted in causal order.

## Done when

- [ ] Grant events searchable and visible in thread timelines.
- [ ] pytest + mypy clean.

## Context pointers

- Spec §6 (journal owns evidence), §8: `docs/superpowers/specs/2026-10-12-user-grants-design.md`
- Journal projection conventions: `ARCHITECTURE.md` §5; inbox/audit patterns: `backend/api/audit.py`

## Resolution

_unresolved — agent: append what renders where + verification output, then mark boxes._
