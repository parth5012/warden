"""Shared test fixtures: a real PostgreSQL (bundled via pgserver)."""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Iterator

import pgserver
import pytest


@pytest.fixture(scope="session")
def pg_uri() -> Iterator[str]:
    """Session-scoped PostgreSQL over a UNIX socket (no root required)."""
    dbdir = tempfile.mkdtemp(prefix="warden-pg-")
    srv = pgserver.get_server(dbdir)  # type: ignore[attr-defined]
    try:
        yield srv.get_uri()
    finally:
        try:
            srv.cleanup()
        finally:
            shutil.rmtree(dbdir, ignore_errors=True)
