# Grant-07: E2E proof + docs + rollout verification

Labels: `wayfinder:task` (AFK) · Map: [User-Granted Temporary Permissions](../2026-10-12-user-grants-map.md)
Blocked by: Grant-05, Grant-06 · Claim: _unclaimed_

## Question

Prove the whole story end to end and record the decisions, closing the map.

## Do

1. E2E (extend `tests/test_web.py` style or a Playwright pass per `ARCHITECTURE.md` §8): issue upfront grant → risky task (scoped file delete + named-table drop) completes with zero parks → revoke → next attempt parks; inbox-upgrade path resolves a parked gate and covers the rest.
2. Docs: `CONTEXT.md` glossary entry (Grant vs Gate vs custody lease — one line each); `DECISIONS.md` entry for the scoped-destructive reclassification (rationale, alternatives, why not a lock change); update `ROADMAP.md` Phase-1/2 notes if the demo flow changes.
3. Rollout verification: full `uv run pytest -q`, `uv run --extra dev python -m mypy src tests`, manual demo click-through (task form → run → grants list → revoke → audit timeline); record the demo script in `LOG.md`.
4. Confirm map closure: every Grant-01…06 ticket closed with resolutions; move map to done.

## Done when

- [ ] E2E green; docs entries present; LOG.md demo script recorded.
- [ ] Map destination met: feature implemented, tested, demoable with no open decisions.

## Context pointers

- Spec §9–10: `docs/superpowers/specs/2026-10-12-user-grants-design.md`
- Testing strategy: `ARCHITECTURE.md` §8; demo flow: `ARCHITECTURE.md` §9

## Resolution

_unresolved — agent: append E2E results + docs links + verification output, then mark boxes._
