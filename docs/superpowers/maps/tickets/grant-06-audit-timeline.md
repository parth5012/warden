# Grant-06: Audit kinds + timeline rendering

Labels: `wayfinder:task` (AFK) · Map: [User-Granted Temporary Permissions](../2026-10-12-user-grants-map.md)
Blocked by: Grant-04 · Claim: `@me`

## Question

Make grants first-class evidence in the audit trail: searchable kinds and a readable per-thread timeline.

## Do

1. Audit search (`backend/api/audit.py` + views): add `grant_issued | grant_consumed | grant_revoked` (| `grant_expired` if emitted) to kind filters and seed/mock entries if the audit page uses them.
2. Thread timeline (`backend/api/runs.py` + templates): render grant events inline with gate events (issued by whom, consumed with uses-left, revoked/expired), reusing the gate-event card style.
3. Tests: kind filter returns grant events; timeline for a grant-using thread shows issued → consumed ×N → parked/exhausted in causal order.

## Done when

- [x] Grant events searchable and visible in thread timelines.
- [x] pytest + mypy clean.

## Context pointers

- Spec §6 (journal owns evidence), §8: `docs/superpowers/specs/2026-10-12-user-grants-design.md`
- Journal projection conventions: `ARCHITECTURE.md` §5; inbox/audit patterns: `backend/api/audit.py`

## Resolution

Added `grant_issued`, `grant_consumed`, and `grant_revoked` audit entries and kind filtering to `backend/api/audit.py`. Updated `backend/api/runs.py` to project decision graph with grant nodes and causal edges, and updated `frontend/views.py` and `run_detail.html` to render inline timeline events for grant operations. Added integration test suite in `tests/test_audit_timeline.py`. All 311 tests pass (6 skipped); mypy strict clean (0 errors in 69 files).
