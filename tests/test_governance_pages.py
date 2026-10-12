"""Unit and Integration tests for Aegis Governance Console Pages.

Tests:
- L1/L2 Policies (/policies)
- Ephemeral Leases (/leases)
- Execution Traces (/traces)
- Sandbox Runs (/sandbox)
- HTMX partial fragments, filtering, and action mutations.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


# ==============================================================================
# 1. POLICIES TESTS
# ==============================================================================

def test_policies_page_full_render() -> None:
    """Verify full HTML render for /policies."""
    response = client.get("/policies")
    assert response.status_code == 200
    assert "L1 & L2 Policy Governance" in response.text
    assert "SEC-FS-04" in response.text
    assert "SEM-PROMPT-01" in response.text
    assert "IMMUTABLE (LOCK 9)" in response.text


def test_policies_page_htmx_partial() -> None:
    """Verify HTMX fragment render when HX-Request is true."""
    response = client.get("/policies", headers={"HX-Request": "true"})
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert "policies-table" in response.text
    assert "SEC-FS-04" in response.text


def test_policies_tier_and_action_filtering() -> None:
    """Test filtering by L1 tier and action=deny."""
    res_l1 = client.get("/policies?tier=L1")
    assert res_l1.status_code == 200
    assert "SEC-FS-04" in res_l1.text
    assert "SEM-PROMPT-01" not in res_l1.text  # L2 rule

    res_l2 = client.get("/policies?tier=L2")
    assert res_l2.status_code == 200
    assert "SEM-PROMPT-01" in res_l2.text
    assert "SEC-FS-04" not in res_l2.text

    res_search = client.get("/policies?q=Mass")
    assert res_search.status_code == 200
    assert "SEC-FS-04" in res_search.text


def test_policies_toggle_active() -> None:
    """Test toggling policy active state."""
    response = client.post("/policies/SEC-FS-04/toggle")
    assert response.status_code == 200
    assert "policy-toggle-btn" in response.text


# ==============================================================================
# 2. EPHEMERAL LEASES TESTS
# ==============================================================================

def test_leases_page_full_render() -> None:
    """Verify full HTML render for /leases."""
    response = client.get("/leases")
    assert response.status_code == 200
    assert "Ephemeral Capability Leases" in response.text
    assert "LSE-901" in response.text
    assert "db:ddl_admin" in response.text
    assert "ZERO-AMBIENT AUTHORITY" in response.text


def test_leases_htmx_partial_and_filtering() -> None:
    """Verify HTMX partial filtering on leases."""
    response = client.get("/leases?status=ACTIVE", headers={"HX-Request": "true"})
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert "LSE-901" in response.text

    res_search = client.get("/leases?q=KubeAgent")
    assert res_search.status_code == 200
    assert "LSE-773" in res_search.text


def test_leases_revoke() -> None:
    """Test revoking an active lease."""
    response = client.post("/leases/LSE-842/revoke")
    assert response.status_code == 200
    assert "REVOKED" in response.text


def test_leases_issue_new() -> None:
    """Test issuing a new ephemeral capability lease."""
    payload = {
        "agent": "CodeAgent",
        "scope": "fs:tmp_purge",
        "ttl_minutes": 45,
        "max_operations": 8,
        "justification": "Purge temporary build logs",
    }
    response = client.post("/leases", data=payload, headers={"HX-Request": "true"})
    assert response.status_code == 200
    assert "fs:tmp_purge" in response.text
    assert "CodeAgent" in response.text


# ==============================================================================
# 3. EXECUTION TRACES TESTS
# ==============================================================================

def test_traces_page_full_render() -> None:
    """Verify full HTML render for /traces."""
    response = client.get("/traces")
    assert response.status_code == 200
    assert "Execution Traces" in response.text
    assert "thread_code_419" in response.text
    assert "POSTGRES SAVER (LOCK 2)" in response.text


def test_traces_filtering_and_htmx() -> None:
    """Test filtering by thread status."""
    response = client.get("/traces?status=PARKED_HITL", headers={"HX-Request": "true"})
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert "thread_code_419" in response.text

    res_search = client.get("/traces?q=thread_db_104")
    assert res_search.status_code == 200
    assert "thread_db_104" in res_search.text


def test_traces_detail_fragment() -> None:
    """Verify trace step timeline and state snapshot endpoint."""
    response = client.get("/traces/thread_code_419")
    assert response.status_code == 200
    assert "LangGraph Node Execution Timeline" in response.text
    assert "checkpoint_c419" in response.text or "chk_c419" in response.text
    assert "FILE_BATCH_DELETE" in response.text


def test_traces_detail_404() -> None:
    """Verify 404 on nonexistent thread trace."""
    response = client.get("/traces/nonexistent_thread_9999")
    assert response.status_code == 404


# ==============================================================================
# 4. SANDBOX RUNS TESTS
# ==============================================================================

def test_sandbox_page_full_render() -> None:
    """Verify full HTML render for /sandbox."""
    response = client.get("/sandbox")
    assert response.status_code == 200
    assert "Sandbox Execution Runs" in response.text
    assert "sb_run_941a" in response.text
    assert "SANDBOXPORT (CGROUPS V2)" in response.text


def test_sandbox_filtering_and_htmx() -> None:
    """Test filtering sandbox runs by tool and status."""
    response = client.get("/sandbox?status=SUCCESS", headers={"HX-Request": "true"})
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert "sb_run_941a" in response.text

    res_tool = client.get("/sandbox?tool=run_shell")
    assert res_tool.status_code == 200
    assert "sb_run_829c" in res_tool.text


def test_sandbox_logs_terminal_drawer() -> None:
    """Verify sandbox terminal log viewer."""
    response = client.get("/sandbox/sb_run_941a/logs")
    assert response.status_code == 200
    assert "Isolated Process Standard Output (stdout)" in response.text
    assert "billing_ledger_2026_q4" in response.text
    assert "Environment Variable Sanitization" in response.text


def test_sandbox_logs_404() -> None:
    """Verify 404 on nonexistent sandbox run."""
    response = client.get("/sandbox/nonexistent_sb_9999/logs")
    assert response.status_code == 404
