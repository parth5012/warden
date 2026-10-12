# Grant-04: Executor grant check + journal events

Labels: `wayfinder:task` (AFK) · Map: [User-Granted Temporary Permissions](../2026-10-12-user-grants-map.md)
Blocked by: Grant-02, Grant-03 · Claim: _unclaimed_

## Question

Wire grants into `GuardedExecutor.execute()`: a live covering grant on the `escalate` path auto-allows (journaled); everything else behaves as today.

## Do

1. Read `src/warden/executor.py` (escalate → `Pending` path) and `src/warden/journal.py` (event kinds).
2. After `POLICY_EVALUATED` is journaled and only when verdict is `escalate`: query the `GrantsStore` for `action.thread_id`; on covering active grant → `consume`, journal `grant_consumed {grant_id, action_id, uses_left}`, continue down the normal execution path (sandbox/side-effect handling unchanged) to `Allowed`.
3. No grant → `Pending` exactly as today. `deny`/`Error` paths: no grant lookup at all (lock 5).
4. Add journal event kinds `grant_issued`, `grant_consumed`, `grant_revoked`, `grant_expired` (lazy expiry on observation is fine).
5. Tests: upfront grant auto-allows then parks at max-uses+1; no-grant parks; revoke mid-run re-parks; `deny` action with a broad grant still denies; kill-mid-park replay preserves `uses` semantics.

## Done when

- [ ] Escalate+grant → `Allowed` with `grant_consumed`; escalate alone → `Pending`; deny+grant → `Denied`.
- [ ] Full `uv run pytest -q` green; mypy strict clean.

## Context pointers

- Spec §6 (executor integration): `docs/superpowers/specs/2026-10-12-user-grants-design.md`
- Seam invariants: `ARCHITECTURE.md` §2–3; locks: `CONTEXT.md`

## Resolution

_unresolved — agent: append behavior matrix results + verification output, then mark boxes._
