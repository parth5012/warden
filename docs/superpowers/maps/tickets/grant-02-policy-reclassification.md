# Grant-02: Reclassify scoped destructive intent to escalate

Labels: `wayfinder:task` (AFK) · Map: [User-Granted Temporary Permissions](../2026-10-12-user-grants-map.md)
Blocked by: none (frontier) · Claim: `@me`

## Question

Shift *parseable, bounded* destructive intent from terminal `deny` to grantable `escalate` with dedicated rule ids, keeping unbounded destruction terminal.

## Do

1. Read `src/warden/policy/engine.py`, `src/warden/policy/layers_static.py`, `src/warden/tools/deny_tools.py`, and existing deny tests.
2. Add `escalate` classification (new rule ids, e.g. `scoped-ddl-drop-table`, `scoped-fs-batch-delete`) for: single explicit table-name DDL (`DROP TABLE <name>`, no wildcards/multi-statement) and file operations confined under an explicit path prefix. Everything else destructive stays `deny`: `DROP DATABASE`, `rm -rf /`, `/etc/shadow`, traversal (`..`), unparseable payloads.
3. The engine asserts only parseability + boundedness — it must not know about grants.
4. Tests: new escalate cases for each scoped pattern; assert all existing `deny` tests still deny (lock 5 regression net).

## Done when

- [x] Scoped patterns escalate with the new rule ids; unbounded patterns still deny.
- [x] `uv run pytest -q` green; `uv run --extra dev python -m mypy src tests` clean.
- [x] Docstrings on all new public symbols; `from __future__ import annotations` in new modules.

## Context pointers

- Spec §5 (reclassification): `docs/superpowers/specs/2026-10-12-user-grants-design.md`
- Locks: `CONTEXT.md` (5 deny-terminal, 4 fail-closed); conventions: `docs/DEVELOPMENT_GUIDE.md`

## Resolution

Reclassified scoped destructive patterns: single explicit table DDL (`scoped-ddl-drop-table`) and bounded file deletion under `/workspace/tmp/` (`scoped-fs-batch-delete`) now escalate at L0 static policy layer. Unbounded actions (`DROP DATABASE`, multi-statement DDL, `CASCADE`, unconfined `rm -rf /`, secret/path traversal) remain terminal `deny` (`no-destructive-sql`, `no-destructive-shell`). Tests pass: 273 passed, 6 skipped; mypy strict clean (0 errors in 65 files).
