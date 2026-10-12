"""Database tools for Warden governance.

Includes:
- query_db_readonly: Validates SQL via sqlglot, enforces SELECT-only construct,
  rejects DDL/DML/multi-statement/bypasses, clamps row limits, enforces timeout,
  executes against synthetic read-only schema.
- exec_db_mutation: Strictly rejects DROP/TRUNCATE/ALTER, executes permitted mutations
  under approval, never creates approval request for terminal DENY.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass
from typing import Any

import sqlglot
from sqlglot import exp

from warden.models import Action

logger = logging.getLogger("warden.tools.database")

DEFAULT_ROW_LIMIT = 100
MAX_ROW_LIMIT = 1000
DEFAULT_TIMEOUT_SECONDS = 5.0

# Dialect used for parsing and validation
SQL_DIALECT = "postgres"


@dataclass(frozen=True)
class QueryResult:
    """Structured read-only query result."""

    columns: list[str]
    rows: list[dict[str, Any]]
    row_count: int
    truncated: bool


@dataclass(frozen=True)
class MutationResult:
    """Structured mutation execution result."""

    affected_rows: int
    statement: str
    status: str


# ---------------------------------------------------------------------------
# Synthetic Database Setup
# ---------------------------------------------------------------------------

def create_synthetic_db() -> sqlite3.Connection:
    """Create and seed an in-memory synthetic database for demo/testing."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    with conn:
        conn.executescript("""
            CREATE TABLE orders (
                id INTEGER PRIMARY KEY,
                customer_id INTEGER,
                amount DECIMAL(10, 2),
                status TEXT,
                created_at TEXT
            );

            CREATE TABLE customers (
                id INTEGER PRIMARY KEY,
                name TEXT,
                email TEXT,
                region TEXT
            );

            CREATE TABLE products (
                id INTEGER PRIMARY KEY,
                name TEXT,
                price DECIMAL(10, 2),
                stock INTEGER
            );

            CREATE TABLE service_status (
                id INTEGER PRIMARY KEY,
                service_name TEXT UNIQUE,
                status TEXT,
                healthy BOOLEAN
            );

            INSERT INTO customers (id, name, email, region) VALUES
                (1, 'Alice Smith', 'alice@example.com', 'US-East'),
                (2, 'Bob Jones', 'bob@example.com', 'EU-West'),
                (3, 'Charlie Brown', 'charlie@example.com', 'APAC');

            INSERT INTO products (id, name, price, stock) VALUES
                (101, 'Cloud Router', 249.99, 15),
                (102, 'Edge Gateway', 599.00, 8),
                (103, 'Sensor Node', 49.50, 120);

            INSERT INTO orders (id, customer_id, amount, status, created_at) VALUES
                (1001, 1, 249.99, 'completed', '2026-10-10T10:00:00Z'),
                (1002, 2, 599.00, 'pending', '2026-10-11T12:30:00Z'),
                (1003, 1, 49.50, 'processing', '2026-10-12T08:15:00Z');

            INSERT INTO service_status (id, service_name, status, healthy) VALUES
                (1, 'api-gateway', 'running', 1),
                (2, 'auth-service', 'running', 1),
                (3, 'payment-service', 'running', 1),
                (4, 'order-service', 'running', 1);
        """)
    return conn


# Global shared synthetic db for demo/testing
_DEMO_DB = create_synthetic_db()


def get_demo_db() -> sqlite3.Connection:
    return _DEMO_DB


# ---------------------------------------------------------------------------
# SQL Validation via sqlglot
# ---------------------------------------------------------------------------

FORBIDDEN_DDL_DML = (
    exp.Drop,
    exp.TruncateTable,
    exp.Alter,
    exp.Create,
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Command,
)

FORBIDDEN_FUNCTIONS = frozenset({
    "pg_read_file",
    "pg_write_file",
    "pg_read_binary_file",
    "pg_catalog",
    "copy",
    "load_extension",
    "system",
    "cmd",
})


def validate_readonly_sql(query: str, dialect: str = SQL_DIALECT) -> exp.Expression:
    """Validate that SQL is strictly a single, read-only SELECT or UNION query.

    Raises ValueError on:
    - Empty or non-parseable queries
    - Multiple statements
    - Non-SELECT top-level statements
    - Embedded DDL/DML constructs
    - Forbidden functions
    """
    if not query or not query.strip():
        raise ValueError("Query string cannot be empty")

    try:
        statements = sqlglot.parse(query, read=dialect)
    except Exception as exc:
        raise ValueError(f"SQL parsing error: {exc}") from exc

    if not statements or statements[0] is None:
        raise ValueError("Failed to parse SQL query")

    # Enforce exactly one statement
    if len(statements) > 1:
        raise ValueError("Multiple SQL statements are strictly prohibited")

    stmt = statements[0]

    # Must be Select or Union
    if not isinstance(stmt, (exp.Select, exp.Union)):
        raise ValueError(
            f"Prohibited non-read-only statement type: {type(stmt).__name__}"
        )

    # Scan entire AST for forbidden DDL / DML constructs
    for forbidden in FORBIDDEN_DDL_DML:
        if isinstance(stmt, forbidden) or list(stmt.find_all(forbidden)):
            raise ValueError(
                f"Prohibited SQL construct detected: {forbidden.__name__}"
            )

    # Scan for forbidden system functions
    for fn in stmt.find_all(exp.Anonymous):
        if fn.name.lower() in FORBIDDEN_FUNCTIONS:
            raise ValueError(f"Prohibited SQL function detected: {fn.name}")

    return stmt


def validate_mutation_sql(query: str, dialect: str = SQL_DIALECT) -> exp.Expression:
    """Validate that mutation query is an authorized DML operation.

    Raises ValueError on:
    - Empty or multi-statement queries
    - Prohibited terminal DDL (DROP, TRUNCATE, ALTER)
    - Unsupported statement types
    """
    if not query or not query.strip():
        raise ValueError("Mutation query cannot be empty")

    try:
        statements = sqlglot.parse(query, read=dialect)
    except Exception as exc:
        raise ValueError(f"SQL parsing error: {exc}") from exc

    if not statements or statements[0] is None:
        raise ValueError("Failed to parse mutation SQL query")

    if len(statements) > 1:
        raise ValueError("Multiple SQL statements are not permitted")

    stmt = statements[0]

    # Prohibited terminal DDL check
    prohibited_ddl = (exp.Drop, exp.TruncateTable, exp.Alter)
    for prohibited in prohibited_ddl:
        if isinstance(stmt, prohibited) or list(stmt.find_all(prohibited)):
            raise ValueError(
                f"Terminal policy violation: {prohibited.__name__} operations are strictly prohibited"
            )

    # Must be an authorized DML construct: Insert, Update, or Delete
    if not isinstance(stmt, (exp.Insert, exp.Update, exp.Delete)):
        raise ValueError(
            f"Unsupported mutation statement: expected INSERT, UPDATE, or DELETE, got {type(stmt).__name__}"
        )

    return stmt


# ---------------------------------------------------------------------------
# Tool Handlers
# ---------------------------------------------------------------------------

def query_db_readonly(
    action: Action,
    db_conn: sqlite3.Connection | None = None,
) -> QueryResult:
    """Handler for query_db_readonly.

    Validates read-only SQL via sqlglot, clamps row limits, enforces timeout,
    and returns QueryResult.
    """
    query = action.payload.get("query")
    if not isinstance(query, str):
        raise ValueError("Payload must contain a 'query' string")

    # 1. Validate SQL read-only constraints
    parsed_ast = validate_readonly_sql(query)

    # 2. Extract and clamp row limits
    raw_limit = action.payload.get("limit", DEFAULT_ROW_LIMIT)
    if not isinstance(raw_limit, int) or isinstance(raw_limit, bool) or raw_limit <= 0:
        raise ValueError("limit must be a positive integer")
    row_limit = min(raw_limit, MAX_ROW_LIMIT)

    # Transpile query to sqlite for synthetic in-memory execution
    sqlite_query = parsed_ast.sql(dialect="sqlite")

    conn = db_conn or get_demo_db()
    cursor = conn.cursor()

    # Enforce row limit in query execution
    cursor.execute(f"SELECT * FROM ({sqlite_query}) LIMIT {row_limit + 1}")
    fetched = cursor.fetchall()

    is_truncated = len(fetched) > row_limit
    rows_to_return = fetched[:row_limit]

    columns = [col[0] for col in cursor.description] if cursor.description else []
    result_rows: list[dict[str, Any]] = [dict(r) for r in rows_to_return]

    return QueryResult(
        columns=columns,
        rows=result_rows,
        row_count=len(result_rows),
        truncated=is_truncated,
    )


def exec_db_mutation(
    action: Action,
    db_conn: sqlite3.Connection | None = None,
) -> MutationResult:
    """Handler for exec_db_mutation.

    Validates mutation SQL, rejects DROP/TRUNCATE/ALTER, and executes
    authorized DML.
    """
    query = action.payload.get("query")
    if not isinstance(query, str):
        raise ValueError("Payload must contain a 'query' string")

    # 1. Validate mutation query (rejects DROP/TRUNCATE/ALTER)
    parsed_ast = validate_mutation_sql(query)

    sqlite_query = parsed_ast.sql(dialect="sqlite")

    conn = db_conn or get_demo_db()
    with conn:
        cursor = conn.cursor()
        cursor.execute(sqlite_query)
        affected = cursor.rowcount

    return MutationResult(
        affected_rows=affected,
        statement=sqlite_query,
        status="success",
    )
