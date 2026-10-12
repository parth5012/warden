"""Shared test fixtures: PostgreSQL (via configured URI or bundled pgserver)."""

from __future__ import annotations

import asyncio
import shutil
import sys
import tempfile
from collections.abc import Iterator

import pytest

# psycopg async mode is incompatible with Windows' default ProactorEventLoop;
# the selector loop is required for AsyncPostgresSaver tests on Windows.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from warden.config import settings


@pytest.fixture(scope="session")
def pg_uri() -> Iterator[str]:
    """Session-scoped PostgreSQL URI."""
    if settings.postgres_uri:
        yield settings.postgres_uri
        return

    import pgserver

    dbdir = tempfile.mkdtemp(prefix="warden-pg-")
    srv = pgserver.get_server(dbdir)  # type: ignore[attr-defined]
    try:
        yield str(srv.get_uri())
    finally:
        try:
            srv.cleanup()
        finally:
            shutil.rmtree(dbdir, ignore_errors=True)
