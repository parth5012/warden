# Grant-01: Remove the Yash-style leases port

Labels: `wayfinder:task` (AFK) · Map: [User-Granted Temporary Permissions](../2026-10-12-user-grants-map.md)
Blocked by: none (frontier) · Claim: `@me`

## Question

Remove the ported PR-16 custody-lease files so the Grants implementation starts from a clean tree with no competing lease concept.

## Do

1. Delete `src/warden/leases.py` and `tests/test_leases.py` (both untracked ports; nothing imports them — verify with `rg "warden.leases|warden\.leases|from warden import leases"` first).
2. Keep `tests/evals/golden/` and `tests/evals/test_golden_verdicts.py` untouched (policy data, still valuable).
3. Run `uv run pytest -q` (expect same pass count minus the 13 removed lease tests) and `uv run --extra dev python -m mypy src tests` (expect clean).

## Done when

- [x] Both files gone; no references remain.
- [x] pytest green, mypy strict clean.
- [x] Tree clean of custody lease ports; evals preserved.

## Context pointers

- Spec §3 (non-goals), §10 step 1: `docs/superpowers/specs/2026-10-12-user-grants-design.md`
- Session context: `.tmp/sessions/2026-10-12-pr16-leases-evals/context.md`

## Resolution

Verified `src/warden/leases.py` and `tests/test_leases.py` removed with 0 references remaining in repo. Preserved golden evals dataset in `tests/evals/` and checked in user grants spec and map documents. Verification passed: 265 passed, 6 skipped; mypy strict 0 errors in 65 source files.
