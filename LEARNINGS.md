# LEARNINGS.md — Warden

## Checkpointing / LangGraph

1. **`StateSnapshot.metadata` arrives as a plain `dict` after serde**, not a `CheckpointMetadata` object — `meta.step` raises `AttributeError`. Handle both: `meta["step"] if isinstance(meta, dict) else meta.step`. (Caught by first test run against real Postgres.)
2. **`AsyncPostgresSaver.from_conn_string()` is an `@asynccontextmanager`**, not a plain factory: use `ctx = from_conn_string(uri); saver = await ctx.__aenter__()`. Calling it and treating the return value as the saver silently loses the connection.
3. **`StateSnapshot` has a top-level `interrupts` field** — no need to walk `state.tasks[].interrupts`.
4. **`StateSnapshot` has NO `step` field** (older docs show it) — step lives in `metadata["step"]`. `created_at` is an ISO `str | None`, not a datetime.
5. **`AsyncPostgresSaver.conn` is `AsyncConnection | AsyncConnectionPool`** — health probes must branch (pool has no `.execute`; use `async with pool.connection()`).
6. **On resume, LangGraph restarts the interrupted node from the top** — code before `interrupt()` inside that node re-runs. Prior *completed* nodes do NOT re-run (verified by the no-duplicate-drafts test). Side effects before `interrupt()` must be idempotent.
7. **`CompiledStateGraph` is generic with 4 params** (`StateT, ContextT, InputT, OutputT`) — mypy strict needs explicit args (`CompiledStateGraph[Any, Any, Any, Any]`).
8. **Config params must be typed `RunnableConfig`** (TypedDict from `langchain_core.runnables`), not `dict[str, Any]`, or every `ainvoke`/`aget_state` call fails overload resolution under mypy strict.
9. **No Docker/sudo/root in this environment** — `pgserver` PyPI package bundles PostgreSQL 16 binaries and runs over a UNIX socket (`postgresql://postgres:@/postgres?host=<dir>`), works with psycopg3 async. Use it for real-DB tests.

## Tooling

10. `uv init` expects `src/<pkg>/` layout when a build backend is set — package must live under `src/`.
11. `rg` treats patterns starting with `-` as flags — use `rg -n -- '<pattern>'`.
12. **pgserver stops PostgreSQL at process exit** (`cleanup_mode='stop'` default + `atexit`). The *data directory* persists, so a new process re-attaches to the same checkpoints — that's what makes the CLI crash-recovery demo work, not a long-lived server. Never hand a URI obtained from a throwaway `get_server` process to another CLI invocation: the server is already (or about to be) stopped. Let each CLI resolve pgserver itself.
13. **Piped-input CLI tests: every line is consumed by whatever prompt is active.** `/quit` right after a parking input lands in the *resume* prompt, not the main loop, and was silently treated as a deny decision. Slash commands must be recognized at every prompt (or documented as decisions).
14. **`tests/` is a package** (empty `__init__.py` since 4fd3ff0). Import helpers as `from tests import cli_chat`; adding `mypy_path = ["tests"]` makes mypy see the module twice (`tests.cli_chat` + `cli_chat`) and fail hard.
