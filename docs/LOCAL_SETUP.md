# Aegis — Local Setup

> Exact prerequisites and commands to get Aegis running locally.
> For coding conventions and PR workflow, see [`DEVELOPMENT_GUIDE.md`](DEVELOPMENT_GUIDE.md).

---

## Prerequisites

| Requirement | Version | How to install |
|---|---|---|
| Python | 3.11+ | https://python.org or `pyenv install 3.11` |
| uv | Latest | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Git | Any | https://git-scm.com |

> **PostgreSQL is not required separately.** The `pgserver` package bundles PostgreSQL 16 binaries. Tests and the CLI auto-start it.

---

## Step 1 — Clone and Install

```bash
git clone https://github.com/parth5012/warden
cd warden

# Install runtime + dev dependencies
uv sync --extra dev

# Verify
uv run python -c "import langgraph, psycopg, warden; print('Installation OK')"
```

---

## Step 2 — Run Tests

No additional setup needed. pgserver starts automatically.

```bash
uv run pytest
```

Expected output:
```
22 passed in X.XXs
```

---

## Step 3 — Type Check

```bash
uv run mypy src tests
```

Expected output:
```
Success: no issues found in 12 source files
```

---

## Step 4 — Run the CLI Harness

```bash
uv run python tests/cli_chat.py
```

This auto-starts PostgreSQL (pgserver) and opens an interactive demo chat.

### CLI crash-recovery demo

```bash
# Terminal 1: start a run, park it, then Ctrl-C
uv run python tests/cli_chat.py
# you> hello
# *** GRAPH PARKED — human decision required ***
# resume> ^C   ← Ctrl-C here

# Terminal 2: restart and resume the same thread
uv run python tests/cli_chat.py --thread <thread-id-from-terminal-1>
# graph detects the parked state automatically
# resume> approve
# → Email sent
```

---

## Environment Variables (Optional)

```bash
# Override the PostgreSQL URI (default: bundled pgserver)
export WARDEN_PG_URI=postgresql://postgres:@/postgres?host=/tmp/warden-pg

# Named approver keys (required for Phase 1 FastAPI approval API)
export WARDEN_APPROVER_KEYS=alice:key-abc123,bob:key-def456

# LLM provider (required for Phase 1 LLM integration)
export OPENAI_API_KEY=sk-...
export WARDEN_LLM_PROVIDER=openai
```

Create a `.env` file for local development (it is in `.gitignore`):

```bash
# .env (not committed)
WARDEN_PG_URI=...
WARDEN_APPROVER_KEYS=alice:mykey
OPENAI_API_KEY=sk-...
```

---

## Starting the FastAPI App (Phase 1 — Not Yet Implemented)

Once the FastAPI app is built (Phase 1), the startup command will be:

```bash
# PROPOSED — not yet available
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The dashboard will be available at `http://localhost:8000`.

---

## Troubleshooting

### pgserver fails to start

```bash
# Check pgserver is installed
uv run python -c "import pgserver; print('ok')"

# Try a fresh data directory
rm -rf /tmp/opencode/pgdata-warden
uv run python tests/cli_chat.py
```

### `uv sync` fails

```bash
# Verify Python version
python --version    # must be 3.11.x

# Clear uv cache and retry
uv cache clean
uv sync --extra dev
```

### mypy errors about `CompiledStateGraph`

Annotate as `CompiledStateGraph[Any, Any, Any, Any]`. See [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md#11-troubleshooting).

### Tests fail with "connection refused"

pgserver may be starting slowly. Run `uv run pytest -v` to see more detail. If tests always fail on a fresh machine, check that the temp directory is writable.

### Import `from tests import cli_chat` fails

`tests/` must be a Python package. Verify `tests/__init__.py` exists. Do not add `mypy_path = ["tests"]` to `pyproject.toml`.
