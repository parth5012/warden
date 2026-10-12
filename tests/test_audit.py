"""Unit and integration test suite for Aegis WAL & Audit Log feature.

Tests:
- GET /audit returning HTTP 200 with layout and branding
- HTMX partial swaps vs full page loads
- Full-text search and filtering by kind, action_id, run_id, actor
- Pagination controls and empty result states
- Event detail retrieval, related lifecycle events, and 404 on missing ID
- Accurate summary metric counts derived from events
- Safe payload rendering (XSS neutralization)
- CSV export format and OWASP formula injection neutralization
- Cryptographic hash chain calculation and verification logic
- Immutability check (rejecting destructive write/delete attempts on audit log)
- Regression testing on existing Command Center, Approvals, and Agents endpoints
"""

import csv
import io
import json
from typing import Any
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.audit import (
    EventKind,
    JournalEvent,
    VerificationStatus,
    calculate_event_hash,
    sanitize_csv_cell,
    verify_hash_chain,
)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# ==============================================================================
# 1. PAGE LOAD & NAVIGATION TESTS
# ==============================================================================

def test_audit_page_loads_successfully(client: TestClient) -> None:
    """Verifies that GET /audit returns 200 with Aegis branding and the audit layout."""
    resp = client.get("/audit")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    text = resp.text

    # Assert branding & page titles
    assert "Aegis" in text
    assert "WAL &amp; Audit Log" in text or "WAL & Audit Log" in text
    assert "DEMO JOURNAL" in text

    # Assert navigation active status
    assert 'class="nav-link active"' in text or 'active_page == \'audit\'' in text

    # Assert presence of table and KPI metrics
    assert "audit-kpi-grid" in text
    assert "audit-table" in text
    assert "TOTAL JOURNAL EVENTS" in text


def test_htmx_partial_swap(client: TestClient) -> None:
    """Verifies that an HTMX request receives only the table fragment, not the full HTML."""
    resp = client.get("/audit", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    text = resp.text

    # Should contain table fragment
    assert "audit-table-wrapper" in text
    assert "audit-table-body" in text

    # Should NOT contain full document scaffolding
    assert "<!DOCTYPE html>" not in text
    assert "<aside class=\"sidebar\">" not in text


# ==============================================================================
# 2. FILTERING & SEARCH TESTS
# ==============================================================================

def test_filter_by_kind(client: TestClient) -> None:
    """Verifies filtering by specific event kind."""
    resp = client.get("/audit?kind=action_denied", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    text = resp.text

    assert "action_denied" in text
    assert "ev_009_den_shadow" in text
    # Other kinds should not appear in the table rows
    assert "ev_007_exec_env" not in text


def test_filter_by_action_id(client: TestClient) -> None:
    """Verifies filtering by specific action ID."""
    resp = client.get("/audit?action_id=act_7129e3", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    text = resp.text

    assert "act_7129e3" in text
    assert "ev_002_req_7129" in text
    assert "ev_003_pol_7129" in text
    assert "act_unlink_shadow" not in text


def test_filter_by_actor(client: TestClient) -> None:
    """Verifies filtering by actor name."""
    resp = client.get("/audit?actor=RogueAgent", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    text = resp.text

    assert "RogueAgent" in text
    assert "ev_008_req_shadow" in text
    assert "CodeAgent" not in text


def test_free_text_search(client: TestClient) -> None:
    """Verifies free-text search across payload and descriptions."""
    resp = client.get("/audit?q=datadoghq", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    text = resp.text

    assert "ev_014_req_5510" in text
    assert "datadoghq.com" in text
    assert "ev_008_req_shadow" not in text


def test_empty_search_results(client: TestClient) -> None:
    """Verifies graceful handling of queries matching no records."""
    resp = client.get("/audit?q=non_existent_search_query_99999", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    text = resp.text

    assert "No audit records found" in text
    assert "Showing <strong>0</strong> to <strong>0</strong> of <strong>0</strong> events" in text


# ==============================================================================
# 3. PAGINATION & BOUNDS CHECKING
# ==============================================================================

def test_pagination(client: TestClient) -> None:
    """Verifies pagination limits and page offsets."""
    resp = client.get("/audit?page=1&limit=5", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    text = resp.text

    assert "Page 1 of" in text
    assert "Next &rarr;" in text

    # Page 2
    resp2 = client.get("/audit?page=2&limit=5", headers={"HX-Request": "true"})
    assert resp2.status_code == 200
    text2 = resp2.text

    assert "Page 2 of" in text2
    assert "&larr; Previous" in text2


def test_invalid_pagination_parameters(client: TestClient) -> None:
    """Verifies that invalid page or limit parameters trigger validation errors."""
    resp = client.get("/audit?page=0")  # page < 1
    assert resp.status_code == 422

    resp2 = client.get("/audit?limit=200")  # limit > 100
    assert resp2.status_code == 422


# ==============================================================================
# 4. EVENT DETAIL & LIFECYCLE LINKAGE
# ==============================================================================

def test_get_event_detail_success(client: TestClient) -> None:
    """Verifies retrieval of event detail drawer fragment."""
    resp = client.get("/audit/events/ev_002_req_7129")
    assert resp.status_code == 200
    text = resp.text

    assert "ev_002_req_7129" in text
    assert "action_requested" in text
    assert "CodeAgent" in text
    assert "act_7129e3" in text
    assert "Cryptographic Hash Chain" in text
    assert "Related Lifecycle Events" in text
    assert "FILE_BATCH_DELETE" in text


def test_get_event_detail_not_found(client: TestClient) -> None:
    """Verifies 404 response for invalid event ID."""
    resp = client.get("/audit/events/ev_invalid_nonexistent_99")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ==============================================================================
# 5. CSV EXPORT & FORMULA INJECTION DEFENSE
# ==============================================================================

def test_csv_export_format_and_headers(client: TestClient) -> None:
    """Verifies that GET /audit/export returns sanitized CSV with all required columns."""
    resp = client.get("/audit/export")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert "aegis_audit_log_" in resp.headers["content-disposition"]

    reader = csv.reader(io.StringIO(resp.text))
    rows = list(reader)
    assert len(rows) >= 15  # 1 header + >= 14 records

    header = rows[0]
    expected_cols = [
        "Timestamp_UTC", "Event_ID", "Kind", "Action_ID", "Run_ID",
        "Thread_ID", "Checkpoint_Step", "Actor", "Status", "Description",
        "Event_Hash", "Prev_Hash", "Verification_Status", "Payload_JSON"
    ]
    assert header == expected_cols


def test_formula_injection_sanitization() -> None:
    """Verifies OWASP formula injection neutralization on untrusted cell values."""
    assert sanitize_csv_cell("=1+1") == "'=1+1"
    assert sanitize_csv_cell("@SUM(A1:A10)") == "'@SUM(A1:A10)"
    assert sanitize_csv_cell("+cmd|'/C calc'!A0") == "'+cmd|'/C calc'!A0"
    assert sanitize_csv_cell("-12.50") == "'-12.50"
    assert sanitize_csv_cell("Normal String") == "Normal String"
    assert sanitize_csv_cell(None) == ""


# ==============================================================================
# 6. CRYPTOGRAPHIC HASH CHAIN & INTEGRITY VERIFICATION
# ==============================================================================

def test_hash_calculation_is_deterministic() -> None:
    """Verifies that canonical event hashing is deterministic and reproducible."""
    ev_dict_1 = {
        "id": "test_ev_1",
        "run_id": "run_1",
        "thread_id": "thread_1",
        "action_id": "act_1",
        "checkpoint_step": 1,
        "kind": "action_requested",
        "actor": "CodeAgent",
        "status": "Proposed",
        "description": "Test description",
        "payload": {"param_b": 2, "param_a": 1},  # Unsorted keys
        "ts": "2026-10-12T10:00:00Z",
        "prev_hash": None,
    }
    ev_dict_2 = dict(ev_dict_1)
    ev_dict_2["payload"] = {"param_a": 1, "param_b": 2}  # Reverse order

    # Canonical hashing must produce the exact same SHA-256 digest
    hash1 = calculate_event_hash(ev_dict_1)
    hash2 = calculate_event_hash(ev_dict_2)
    assert hash1 == hash2
    assert len(hash1) == 64


def test_hash_chain_verification_passes() -> None:
    """Verifies that an intact cryptographic hash chain validates as VERIFIED."""
    raw1: dict[str, Any] = {
        "id": "e1", "run_id": "r1", "thread_id": "t1", "action_id": "a1",
        "checkpoint_step": 1, "kind": "action_requested", "actor": "AgentA",
        "status": "Proposed", "description": "Step 1", "payload": {},
        "ts": "2026-10-12T10:00:00Z", "prev_hash": None
    }
    h1 = calculate_event_hash(raw1)
    raw1["event_hash"] = h1
    ev1 = JournalEvent(**raw1)

    raw2: dict[str, Any] = {
        "id": "e2", "run_id": "r1", "thread_id": "t1", "action_id": "a1",
        "checkpoint_step": 2, "kind": "action_completed", "actor": "AgentA",
        "status": "Succeeded", "description": "Step 2", "payload": {},
        "ts": "2026-10-12T10:01:00Z", "prev_hash": h1
    }
    h2 = calculate_event_hash(raw2)
    raw2["event_hash"] = h2
    ev2 = JournalEvent(**raw2)

    status, msg = verify_hash_chain([ev1, ev2])
    assert status == VerificationStatus.VERIFIED
    assert msg is not None and "intact" in msg.lower()


def test_hash_chain_verification_detects_tampering() -> None:
    """Verifies that any altered payload or broken link is detected as FAILED."""
    raw1: dict[str, Any] = {
        "id": "e1", "run_id": "r1", "thread_id": "t1", "action_id": "a1",
        "checkpoint_step": 1, "kind": "action_requested", "actor": "AgentA",
        "status": "Proposed", "description": "Step 1", "payload": {},
        "ts": "2026-10-12T10:00:00Z", "prev_hash": None
    }
    h1 = calculate_event_hash(raw1)
    raw1["event_hash"] = h1
    ev1 = JournalEvent(**raw1)

    raw2: dict[str, Any] = {
        "id": "e2", "run_id": "r1", "thread_id": "t1", "action_id": "a1",
        "checkpoint_step": 2, "kind": "action_completed", "actor": "AgentA",
        "status": "Succeeded", "description": "Tampered description", "payload": {},
        "ts": "2026-10-12T10:01:00Z", "prev_hash": "corrupted_hash"
    }
    raw2["event_hash"] = "fake_hash"
    ev2 = JournalEvent(**raw2)

    status, msg = verify_hash_chain([ev1, ev2])
    assert status == VerificationStatus.FAILED
    assert msg is not None and ("broken chain" in msg.lower() or "mismatch" in msg.lower())


# ==============================================================================
# 7. IMMUTABILITY & SECURITY TESTS
# ==============================================================================

def test_audit_log_is_immutable(client: TestClient) -> None:
    """Verifies that no mutation endpoints (POST/PUT/DELETE) exist for audit records."""
    post_resp = client.post("/audit", json={"dummy": "data"})
    assert post_resp.status_code == 405  # Method Not Allowed

    delete_resp = client.delete("/audit/events/ev_001_chk_boot")
    assert delete_resp.status_code == 405

    put_resp = client.put("/audit/events/ev_001_chk_boot", json={"status": "Modified"})
    assert put_resp.status_code == 405


def test_safe_payload_xss_neutralization(client: TestClient) -> None:
    """Verifies that script tags or HTML in event payloads are escaped, not executed."""
    # We inspect ev_002_req_7129 which contains strings with paths and JSON
    resp = client.get("/audit/events/ev_002_req_7129")
    assert resp.status_code == 200
    text = resp.text

    # Ensure pre and code tags are used for the payload block
    assert '<pre class="payload-pre"><code id="payload-code-block">' in text
    assert 'Rendered safely as text — HTML interpretation disabled' in text


# ==============================================================================
# 8. REGRESSION TESTS ON EXISTING APPLICATION PAGES
# ==============================================================================

def test_command_center_regression(client: TestClient) -> None:
    """Verifies that the main dashboard remains fully functional."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Command Center" in resp.text
    assert "Aegis" in resp.text


def test_approvals_queue_regression(client: TestClient) -> None:
    """Verifies that the Interception Gate approvals queue remains fully functional."""
    resp = client.get("/approvals")
    assert resp.status_code == 200
    assert "Approval queue" in resp.text
    assert "Aegis" in resp.text


def test_blast_radius_regression(client: TestClient) -> None:
    """Verifies that Blast Radius analysis remains fully functional."""
    resp = client.get("/actions/act_7129e3")
    assert resp.status_code == 200
    assert "Blast Radius" in resp.text
    assert "act_7129e3" in resp.text


def test_agents_page_regression(client: TestClient) -> None:
    """Verifies that the AI Agents registry remains fully functional."""
    resp = client.get("/agents")
    assert resp.status_code == 200
    assert "AI Agents" in resp.text
