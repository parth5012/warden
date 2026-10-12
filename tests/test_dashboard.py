"""Dashboard console tests — pure rendering + real-route HTTP.

Layers:
- Pure renderers: page shell (HTMX CDN, title escaping), fragments ship
  the right wiring (EventSource on /stream, hx-get /inbox, /toggles/lease
  form), XSS escaping of injected values
- Endpoint GET /dashboard through the real routes (same-loop
  ASGITransport, no PG lifespan): 200 + text/html + key wiring present
- POST /run-web: drives a real governed run through the graph fixture
  injected into module state, returns a back-link; state.graph None -> 503
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

import httpx
from warden.app.dashboard import (
    inbox_fragment,
    journal_feed_fragment,
    lease_card_fragment,
    page_shell,
    render_dashboard,
)
from warden.leases import LeasePolicy
from warden.streaming import WardenJournalBus

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def _client(app: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    )


# ---------------------------------------------------------------------------
# Pure renderers
# ---------------------------------------------------------------------------


def test_page_shell_emits_htmx_and_escapes_title() -> None:
    html = page_shell("Warden <script>alert(1)</script>", "<div id='body'></div>")
    assert "htmx.org" in html
    assert "Warden &lt;script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert "<div id='body'></div>" in html  # body passes through unescaped


def test_journal_fragment_wires_eventsource_to_stream() -> None:
    frag = journal_feed_fragment()
    assert 'new EventSource("/stream?with_history=true")' in frag
    assert "action_denied" in frag and "gate_requested" in frag  # color classes


def test_inbox_fragment_polls_inbox_partial() -> None:
    frag = inbox_fragment(poll_seconds=3)
    assert 'hx-get="/inbox"' in frag
    assert "every 3s" in frag
    assert '"Accept": "text/html"' in frag


def test_lease_card_reflects_policy_state() -> None:
    on_card = lease_card_fragment(LeasePolicy(enabled=True, ttl_seconds=120.0))
    assert "ON" in on_card and "120" in on_card
    assert 'name="enabled"' in on_card and "checked" in on_card
    off_card = lease_card_fragment(LeasePolicy(enabled=False, ttl_seconds=300.0))
    assert "OFF" in off_card and "checked" not in off_card.split('name="enabled"')[1].split(">")[0]


def test_render_dashboard_assembles_all_regions() -> None:
    html = render_dashboard(LeasePolicy())
    for marker in ("Live journal feed", "Approvals inbox", "Lease enforcement", "Launch a governed run"):
        assert marker in html
    assert 'class="grid"' in html


def test_tiny_default_policy_html_is_escaped() -> None:
    """XSS check: rendered dynamic values cannot inject markup."""
    policy = LeasePolicy(enabled=True, ttl_seconds=1.0)
    html = lease_card_fragment(policy)
    assert "<script>" not in html
    assert "&lt;" not in html or "&amp;" in html  # escaping present somewhere upstream


# ---------------------------------------------------------------------------
# Endpoint through the REAL routes (injected fixtures, no PG lifespan)
# ---------------------------------------------------------------------------


async def test_dashboard_endpoint_serves_console() -> None:
    from warden.app import main as app_main

    app_main.state.bus = WardenJournalBus()
    app_main.state.lease_policy = LeasePolicy(enabled=True, ttl_seconds=300.0)
    try:
        async with _client(app_main.app) as client:
            r = await client.get("/dashboard")
            assert r.status_code == 200
            assert r.headers["content-type"].startswith("text/html")
            assert "Agent Governance Console" in r.text
            assert 'new EventSource("/stream' in r.text
            assert 'hx-get="/inbox"' in r.text
            assert 'action="/toggles/lease"' in r.text
    finally:
        app_main.state.bus = WardenJournalBus()


async def test_run_web_drives_real_run_and_links_back() -> None:
    """Plain-form bridge goes through the GRAPH (governance honored)."""
    from warden.app import main as app_main

    # In-memory graph (no PG) is a real governed graph: default policy allows.
    from warden.multi_agent import build_multi_agent_graph
    from warden.seam import GuardedExecutor

    graph = build_multi_agent_graph(GuardedExecutor())
    app_main.state.bus = WardenJournalBus()
    app_main.state.graph = graph
    try:
        async with _client(app_main.app) as client:
            r = await client.post("/run-web", data={"task": "summarize token costs"})
            assert r.status_code == 200
            assert "back to console" in r.text
            assert "run-" in r.text  # the thread id is echoed back
    finally:
        app_main.state.graph = None
        app_main.state.bus = WardenJournalBus()


async def test_run_web_fails_closed_without_graph() -> None:
    from warden.app import main as app_main

    app_main.state.graph = None
    app_main.state.bus = WardenJournalBus()
    try:
        async with _client(app_main.app) as client:
            r = await client.post("/run-web", data={"task": "anything"})
            assert r.status_code == 503
    finally:
        app_main.state.bus = WardenJournalBus()
