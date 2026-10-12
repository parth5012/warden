"""Shared test fixtures: PostgreSQL (via configured URI or bundled pgserver)."""

from __future__ import annotations

import asyncio
import shutil
import sys
import tempfile
from collections.abc import Iterator

import pytest

if sys.platform == "win32":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

from warden.config import settings


@pytest.fixture(scope="session")
def pg_uri() -> Iterator[str]:
    """Session-scoped PostgreSQL URI."""
    if settings.postgres_uri:
        yield settings.postgres_uri
        return

    import pgserver  # type: ignore[import-not-found]

    dbdir = tempfile.mkdtemp(prefix="warden-pg-")
    srv = pgserver.get_server(dbdir)
    try:
        yield str(srv.get_uri())
    finally:
        try:
            srv.cleanup()
        finally:
            shutil.rmtree(dbdir, ignore_errors=True)
