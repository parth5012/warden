# Grant-03: GrantsStore protocol + in-memory adapter

Labels: `wayfinder:task` (AFK) · Map: [User-Granted Temporary Permissions](../2026-10-12-user-grants-map.md)
Blocked by: none (frontier) · Claim: _unclaimed_

## Question

Build the grant storage seam (protocol + in-memory adapter + matching logic) that the executor will consult — no executor changes in this ticket.

## Do

1. New module `src/warden/grants.py` (kernel side; imports nothing from `app/`): frozen `Grant` dataclass (`id`, `thread_id`, `granted_by`, `scope` rules, `ttl_seconds`, `max_uses`, `uses`, `status`, `created_at`, `reason`) and `ScopeRule{tool, constraints}`; `GrantsStore` protocol (`issue`, `get`, `list_for_thread`, `consume`, `revoke`); `InMemoryGrantsStore`.
2. Matching: exact names for structured targets (table/service), path-prefix for files; anything outside all rules uncovered. Fail-closed: missing/corrupt/expired/revoked/exhausted → no coverage (never raise for environmental reasons).
3. Lifecycle: `active → exhausted | expired | revoked`; wall-clock TTL (injectable clock for tests); `consume` is atomic-ish (increment + transition at max).
4. Unit tests `tests/test_grants.py`: matching matrix (exact hit / prefix hit / miss / wrong tool / wrong thread), expiry boundary, exhaustion at max-uses, revoke, corrupt-entry fail-closed.

## Done when

- [ ] Protocol + adapter + lifecycle + matching implemented and unit-tested.
- [ ] `uv run pytest tests/test_grants.py -q` green; mypy strict clean on new files.

## Context pointers

- Spec §4 (concepts), §7 defaults (TTL 30 min, uses 5): `docs/superpowers/specs/2026-10-12-user-grants-design.md`
- Style reference (pure, clock-injected kernel): deleted `src/warden/leases.py` pattern — do NOT copy its custody semantics.

## Resolution

_unresolved — agent: append file paths + test count + verification output, then mark boxes._
