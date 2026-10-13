# Map: User-Granted Temporary Permissions ("Grants") → Implementation Handover

Labels: `wayfinder:map`
Destination: all tickets closed and the Grants feature from `docs/superpowers/specs/2026-10-12-user-grants-design.md` implemented, tested (pytest green, mypy strict clean), and demoable — so the receiving agent needs no further decisions, only execution.

## Notes

- Domain: Warden (FastAPI + LangGraph + Python). Every session: read `CONTEXT.md` (locks 1–12), the spec above, and `.tmp/sessions/2026-10-12-pr16-leases-evals/context.md` before touching code.
- Standing rules: `warden/` imports nothing from `app/`; fail-closed everywhere; `deny` is terminal (lock 5) — no ticket may change that; one step at a time; STOP on test/build failure (report, propose, request approval — never auto-fix); `uv run pytest`, `uv run --extra dev python -m mypy src tests`.
- All tickets are AFK `task` tickets (spec already approved — no human decisions remain). Claim a ticket by adding `Claimed: <agent/session>` to its file; close by adding `Resolution:` + checking its boxes.
- Blocking is recorded in each ticket's `Blocked by:` field (local-markdown fallback — no native tracker). Frontier = open tickets with all blockers closed.

## Decisions so far

- [User Grants design spec](../specs/2026-10-12-user-grants-design.md): executor-side grant check on the `escalate` path; scoped destructive intent reclassified to `escalate`, unbounded stays terminal `deny`; upfront + inbox issuance; exact-plus-prefix matching; 30-min/5-use defaults; Yash-style custody leases dropped.
- [Grant scope](../specs/2026-10-12-user-grants-design.md): task capability (tool allowlist + TTL + max-uses).
- [Deny boundary](../specs/2026-10-12-user-grants-design.md): reclassify delete tools (policy change, not lock change).
- [Issuance moment](../specs/2026-10-12-user-grants-design.md): both paths (upfront form + inbox upgrade).
- [Scope precision](../specs/2026-10-12-user-grants-design.md): exact + prefix rules.

## Not yet specified

- Postgres-backed `GrantsStore` migration (in-memory ships first; PG adapter graduates when Phase-2 policy store work starts).
- pgvector semantic scope matching (exact/prefix only for v1).

## Out of scope

- Human override of `deny` (lock 5) — ruled out in the design spec.
- Supervisor-minted custody leases (PR-16 design) — dropped, see ticket Grant-01.
- Login/roles beyond named keys (lock 8).

## Tickets (GitHub issues — refer by name)

1. [Grant-01: Remove the Yash-style leases port](https://github.com/parth5012/warden/issues/26) — [closed in #32]
2. [Grant-02: Reclassify scoped destructive intent to escalate](https://github.com/parth5012/warden/issues/25) — [closed in #34]
3. [Grant-03: GrantsStore protocol + in-memory adapter](https://github.com/parth5012/warden/issues/31) — [closed in #35]
4. [Grant-04: Executor grant check + journal events](https://github.com/parth5012/warden/issues/30) — [closed in #36]
5. [Grant-05: Grants HTTP + task form + inbox upgrade + grants list](https://github.com/parth5012/warden/issues/29) — [closed in #37]
6. [Grant-06: Audit kinds + timeline rendering](https://github.com/parth5012/warden/issues/27) — [closed in #38]
7. [Grant-07: E2E proof + docs + rollout verification](https://github.com/parth5012/warden/issues/28) — [closed in #39]
