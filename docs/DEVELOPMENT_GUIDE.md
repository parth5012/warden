# Aegis — Development Guide

> Environment setup, coding conventions, branch workflow, and troubleshooting.
> For exact installation commands, see [`LOCAL_SETUP.md`](LOCAL_SETUP.md).

---

## 1. Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.11+ | Enforced by `pyproject.toml` `requires-python = ">=3.11"` |
| uv | Latest | Package manager — see https://github.com/astral-sh/uv |
| Git | Any recent | |
| PostgreSQL | Optional | `pgserver` bundles Postgres 16 for development |

> **No Docker or root required.** The `pgserver` PyPI package bundles PostgreSQL 16 binaries and runs over a UNIX socket. Tests and the CLI auto-start it.

---

## 2. Installation

```bash
# Install all runtime + dev dependencies
uv sync --extra dev

# Verify Python version
uv run python --version    # must be 3.11.x

# Verify key packages
uv run python -c "import langgraph, psycopg, warden; print('ok')"
```

---

## 3. Running Tests

```bash
# All tests (pgserver starts automatically — no setup needed)
uv run pytest

# Specific file
uv run pytest tests/test_checkpoint.py

# With verbose output
uv run pytest -v

# Fail fast on first error
uv run pytest -x

# Show captured stdout (useful for debugging checkpoint logs)
uv run pytest -s
```

**Current baseline:** 22 passed, 0 errors. Do not merge code that reduces this count.

---

## 4. Type Checking

```bash
# Check all source and tests (strict mode)
uv run mypy src tests
```

mypy is configured in `pyproject.toml` with `strict = true`. This means:
- All functions must be annotated.
- No implicit `Any`.
- `warn_return_any = true`.
- `warn_unused_configs = true`.

**Current baseline:** 0 errors across 12 files. All PRs must maintain this.

**Known gotchas from `LEARNINGS.md`:**
- `CompiledStateGraph` requires explicit generic args: `CompiledStateGraph[Any, Any, Any, Any]`
- Config params must be typed `RunnableConfig` (from `langchain_core.runnables`), not `dict[str, Any]`
- `tests/` is a package (has `__init__.py`) — import as `from tests import cli_chat`, not with `mypy_path`

---

## 5. Running the CLI Harness

```bash
# Auto-starts PostgreSQL and opens interactive chat
uv run python tests/cli_chat.py

# Resume an existing parked thread
uv run python tests/cli_chat.py --thread <thread-id>

# Use a custom Postgres URI
WARDEN_PG_URI=postgresql://... uv run python tests/cli_chat.py

# Enable checkpoint logs
uv run python tests/cli_chat.py --verbose
```

**pgserver behavior:** Postgres stops at process exit (`atexit`) but the **data directory persists**. Restart the CLI and the same thread IDs are still there. This is what makes the crash-recovery demo work. Do not pass a pgserver URI from one process to another — each CLI invocation should resolve pgserver itself.

---

## 6. Project Layout and Module Rules

```
src/warden/     ← governance kernel — imports NOTHING from app/ or agents/
app/            ← FastAPI caller — imports from warden/ only
agents/         ← graph nodes — imports from warden/ only
tests/          ← imports from warden/ and tests/ package
```

**The dependency direction is strictly one-way.** If you find yourself importing from `app/` inside `warden/`, you have violated the boundary.

---

## 7. Coding Conventions

### Python style

- Formatter: `ruff format` or `black` (neither is configured yet — pick one and document it here when you do).
- Linter: `ruff check` (recommended, not yet configured).
- All public functions and classes must have docstrings.
- Preserve all existing comments and docstrings unrelated to your change.
- Use `from __future__ import annotations` at the top of every new module.

### Domain types

- Use the types from `src/warden/models.py`. Do not create local variants.
- `Outcome` is a union type — exhaustively match all four variants in code that handles outcomes.
- `Action` is `frozen=True`. Do not mutate it.

### Error handling

- Functions inside `warden/` that touch IO must be fail-closed: return `Error("governance_unavailable")` on infrastructure failure, never raise (Lock 4).
- Functions in `app/` that call `execute()` should translate `Error` outcomes into `503` HTTP responses.
- Never log raw connection strings. Use `_redact()` from `checkpoint.py` or an equivalent.

### Async

- All IO in `warden/` is async. Use `async def` and `await` consistently.
- Do not use `asyncio.run()` inside library code — only in CLI entry points.
- Test fixtures use `pytest-asyncio` with `asyncio_mode = "auto"` (configured in `pyproject.toml`).

---

## 8. Environment Variables

| Variable | Default | Required for |
|---|---|---|
| `WARDEN_PG_URI` | auto (pgserver) | Production Postgres or CI |
| `WARDEN_APPROVER_KEYS` | — | Named approver keys (`alice:key1,bob:key2`) |
| `OPENAI_API_KEY` | — | LLM integration (Phase 1) |
| `WARDEN_LLM_PROVIDER` | `openai` | LLM provider selection |
| `WARDEN_HOST` | `127.0.0.1` | FastAPI bind host (Phase 1) |
| `WARDEN_PORT` | `8000` | FastAPI bind port (Phase 1) |

> **Never commit secrets.** Use `.env` locally (not tracked by git). See `.gitignore`.

---

## 9. Branch and PR Workflow

1. **Branch naming:** `feature/<slice>-<description>` (e.g. `feature/03-guarded-executor`)
2. **Before opening a PR:**
   - `uv run pytest` → all pass
   - `uv run mypy src tests` → 0 errors
3. **PR checklist:**
   - Tests added for new behaviour
   - Docstrings present on new public symbols
   - No existing files overwritten without justification
   - No locked decisions changed (CONTEXT.md)
4. **Review:** Request CodeRabbit review with `@coderabbitai review`. Apply all non-low findings before merge.
5. **Merge:** Squash merge to keep history clean.

---

## 10. Adding a Dependency

1. `uv add <package>` for runtime deps, `uv add --dev <package>` for dev-only.
2. Add it to the appropriate section in `pyproject.toml` (runtime `[project.dependencies]` or `[project.optional-dependencies].dev`).
3. Commit both `pyproject.toml` and the updated `uv.lock`.

---

## 11. Troubleshooting

### `pgserver` not starting

- Ensure `pgserver` is installed: `uv run python -c "import pgserver"`
- Check disk space — pgserver needs a writable temp dir
- Try a fresh data dir: `rm -rf /tmp/opencode/pgdata-warden` and restart

### `AsyncPostgresSaver.from_conn_string()` returns a context manager, not a saver

This is a known gotcha (LEARNINGS.md #2). Use:
```python
ctx = from_conn_string(uri)
saver = await ctx.__aenter__()
```
or use `CheckpointManager.create()` which handles this correctly.

### mypy `StateSnapshot.metadata` attribute error

`metadata` arrives as a plain `dict` after serde (LEARNINGS.md #1). Use:
```python
step = meta["step"] if isinstance(meta, dict) else meta.step
```

### `tests/` import not found by mypy

`tests/` is a package with `__init__.py`. Import as `from tests import cli_chat`. Do NOT add `mypy_path = ["tests"]` — it causes duplicate module detection (LEARNINGS.md #14).

### mypy `rg` patterns starting with `-`

Use `rg -n -- '<pattern>'` (LEARNINGS.md #11).

### `CompiledStateGraph` mypy generic errors

Annotate as `CompiledStateGraph[Any, Any, Any, Any]` (LEARNINGS.md #7).

### Config dict mypy overload errors

Type config as `RunnableConfig` from `langchain_core.runnables`, not `dict[str, Any]` (LEARNINGS.md #8).
