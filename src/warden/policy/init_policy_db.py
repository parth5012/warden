#!/usr/bin/env python
"""Init + seed the Warden PostgreSQL policy store.

Reads the Postgres connection string from src/warden/.env (CONNECTION_STRING), or
from WARDEN_PG_URI / PGDATABASE / DATABASE_URL / PG_URI / POSTGRES_URI if set in the
process environment. Creates the pgvector extension, the policies and policy_versions
tables (idempotent), then seeds the default policy corpus.

This is the script for initializing the tables in the db for the policy engine and
seeding them, intended to be run against the project's real Postgres (for example the
Neon database referenced in src/warden/.env).
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Connection resolution
# ---------------------------------------------------------------------------

ENV_KEYS = (
    "CONNECTION_STRING",
    "WARDEN_PG_URI",
    "PGDATABASE",
    "DATABASE_URL",
    "PG_URI",
    "POSTGRES_URI",
)


def _load_pg_uri_from_file(path: Path) -> str | None:
    """Best-effort parse of a dotenv-ish file for a Postgres URI value."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip().upper()
        val = val.strip().strip('"').strip("'")
        if key in ENV_KEYS or key.endswith("_URI") or key.endswith("_CONNECTION"):
            return val
    return None


def resolve_pg_uri() -> str:
    """Return the Postgres URI to use for policy init/seed."""
    # Process environment takes precedence (useful for CI and explicit runs).
    for key in ENV_KEYS:
        val = os.environ.get(key)
        if val:
            return val

    # Fall back to the project-level .env sitting next to this script.
    candidate = Path(__file__).resolve().parent.parent / ".env"
    if candidate.is_file():
        val = _load_pg_uri_from_file(candidate)
        if val:
            # Mutate process env so downstream code sees the same value.
            os.environ["WARDEN_PG_URI"] = val
            return val

    raise SystemExit(
        "Could not find a Postgres connection string.\n"
        "Expected one of these in the environment: " + ", ".join(ENV_KEYS) + "\n"
        "Or a CONNECTION_STRING in: " + str(candidate)
    )


# ---------------------------------------------------------------------------
# Seeding
# ---------------------------------------------------------------------------

SEED: list[tuple[str, str, str, str]] = [
    ("p-allow-read-only", "allow", "read_table get_customer lookup allowed read_only query records table customers allowed read_table read_table", "ops-init"),
    ("p-allow-search-lookup", "allow", "search_kb search knowledge base lookup query allowed read onboarding", "ops-init"),
    ("p-deny-pii-export", "deny", "db_export export customer PII personal data forbidden exfiltrate bulk", "ops-init"),
    ("p-allow-internal-report-export", "allow", "db_export export weekly report aggregated analytics allowed operations internal", "ops-init"),
    ("p-escalate-external-api-call", "escalate", "call_external_api external api third party mutation escalated human approve destination", "ops-init"),
    ("p-legacy-default-deny", "deny", "default deny unless a named policy explicitly allows the action", "ops-init"),]


def _upsert_policy(
    store: object,
    emb: object,
    policy_id: str,
    verdict: str,
    text: str,
    *,
    who: str = "ops-init",
    name: str | None = None,
) -> str:
    """Add or re-seed a single policy row with its initial version 1.

    Uses the same upsert semantics as PgVectorPolicyStore.add_policy so the
    init/seed script is idempotent when re-run against an existing database.
    """
    from warden.policy.store import PgVectorPolicyStore
    from warden.policy.engine import HashEmbeddings

    assert isinstance(store, PgVectorPolicyStore)
    assert isinstance(emb, HashEmbeddings)

    emb_list: list[float] = list(emb.embed_query(text))
    name = name or policy_id
    return store.add_policy(
        policy_id=policy_id,
        verdict=verdict,
        text=text,
        embedding=emb_list,
        who=who,
        name=name,
    )


# Canonical policy ids intended to be present in the live database.
POLICY_SEED: list[tuple[str, str, str, str]] = [
    ("p-allow-read-only", "allow", "read_table get_customer lookup allowed read_only query records table customers allowed read_table read_table", "ops-init"),
    ("p-allow-search-lookup", "allow", "search_kb search knowledge base lookup query allowed read onboarding", "ops-init"),
    ("p-deny-pii-export", "deny", "db_export export customer PII personal data forbidden exfiltrate bulk", "ops-init"),
    ("p-allow-internal-report-export", "allow", "db_export export weekly report aggregated analytics allowed operations internal", "ops-init"),
    ("p-escalate-external-api-call", "escalate", "call_external_api external api third party mutation escalated human approve destination", "ops-init"),
    ("p-legacy-default-deny", "deny", "default deny unless a named policy explicitly allows the action", "ops-init"),
]

SEED_IDS = frozenset(pid for pid, *_ in POLICY_SEED)


def main() -> None:
    pg_uri = resolve_pg_uri()
    print("Using Postgres:", pg_uri[:48] + ("..." if len(pg_uri) > 48 else ""))

    t0 = time.time()
    from warden.policy.store import PgVectorPolicyStore, setup_policy_tables
    from warden.policy.engine import HashEmbeddings

    print("\n[1/3] Creating pgvector extension + policy tables (idempotent)...")
    setup_policy_tables(pg_uri)
    print(f"      setup_policy_tables done in {time.time() - t0:.2f}s")

    store = PgVectorPolicyStore(pg_uri)
    emb = HashEmbeddings(dim=64)

    print("\n[2/3] Seeding default policy corpus from POLICY_SEED...")
    for policy_id, verdict, text, who in POLICY_SEED:
        t1 = time.time()
        pid = _upsert_policy(
            store=store,
            emb=emb,
            policy_id=policy_id,
            verdict=verdict,
            text=text,
            who=who,
            name=policy_id,
        )
        print(f"      seeded {policy_id:34s} verdict={verdict:9s} pid={pid} in {time.time() - t1:.2f}s")

    print(f"\n[3/3] Listing seeded policies...")
    t2 = time.time()
    rows = store.list_policies(active_only=False)
    if not rows:
        print("      (no policies found after seed)")
    else:
        for row in rows:
            print(
                f"      - {row['name']:34s} action={row['action']:9s} "
                f"active={row['active']} version={row['current_version']} "
                f"rule_head={str(row['rule_text'])[:50]}"
            )
    print(f"      listed in {time.time() - t2:.2f}s")

    print(f"\nDone. Total time: {time.time() - t0:.2f}s")


if __name__ == "__main__":
    main()
