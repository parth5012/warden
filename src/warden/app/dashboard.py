"""Dashboard — the operator console page (server-rendered, lock 12).

One page, no build step:
- **Live journal feed**: a vanilla `EventSource` on the existing
  `GET /stream` (SSE, Yash's streaming slice) appending event cards
  client-side — POST /runs, gate_requested, action_completed all appear
  in real time.
- **Approvals inbox**: HTMX polling of the existing `GET /inbox`
  (`hx-get`, every few seconds; the partial already ships as HTML when
  the request wants text/html — no new endpoint needed).
- **Lease toggle**: HTMX polling of `/toggles/lease`'s state card plus
  a standard HTML form POSTing to the existing `/toggles/lease` JSON
  endpoint (enable/disable + TTL), reinforce-swap via hx-swap.

Everything here is PURE string rendering — the route module (main.py)
imports these functions and only owns HTTP concerns. All dynamic values
are escaped via the shared `_esc`. The page degrades without JS to
static cards + normal form posts.
"""

from __future__ import annotations

from typing import Any

from warden.leases import LeasePolicy


# ---------------------------------------------------------------------------
# Fragments (pure, one per console region)
# ---------------------------------------------------------------------------

def _esc(s: Any) -> str:
    """Minimal HTML escaping (shared convention from main.py)."""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def page_shell(title: str, body_html: str) -> str:
    """The full HTML document with the HTMX CDN (lock 12: no build step)."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>
  :root {{ font-family: system-ui, sans-serif; }}
  body {{ margin: 0 auto; max-width: 1100px; padding: 1rem; background: #111; color: #eee; }}
  h1 {{ font-size: 1.4rem; }} h2 {{ font-size: 1.05rem; margin-bottom: .3rem; }}
  a {{ color: #6cf; }}
  .grid {{ display: grid; grid-template-columns: 1.4fr 1fr; gap: 1rem; align-items: start; }}
  .card {{ border: 1px solid #444; border-radius: 8px; padding: .75rem; margin-bottom: 1rem; background: #1a1a1a; }}
  .gate-card {{ border-left: 4px solid #888; padding: .4rem .6rem; margin: .35rem 0; background: #222; border-radius: 4px; }}
  .gate-card.pending {{ border-left-color: #f6c; }}
  .gate-card.decided {{ border-left-color: #6c6; opacity: .8; }}
  .journal-line {{ font-family: ui-monospace, monospace; font-size: .78rem; padding: .25rem .5rem;
                   border-bottom: 1px solid #333; white-space: pre-wrap; }}
  .journal-line.deny {{ color: #f97777; }} .journal-line.gate {{ color: #f6c; }}
  .journal-line.allow {{ color: #8c8; }}
  .lease-card {{ padding: .5rem; background: #222; border-radius: 4px; margin-bottom: .4rem; }}
  .inline-form {{ display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; margin-top: .5rem; }}
  input, button {{ background: #2a2a2a; color: #eee; border: 1px solid #555; border-radius: 4px; padding: .3rem .55rem; }}
  button {{ cursor: pointer; }} button:hover {{ background: #3a3a3a; }}
  .muted {{ color: #999; font-size: .8rem; }}
</style>
<script src="https://unpkg.com/htmx.org@2.0.4" defer></script>
</head>
<body>
<h1>Warden — Agent Governance Console</h1>
<p class="muted">Every agent action crosses the seam. This page is what the operator sees.</p>
{body_html}
</body>
</html>"""


def journal_feed_fragment() -> str:
    """Live SSE feed card, driven by vanilla EventSource (no HTMX SSE ext needed)."""
    return """<div class="card" id="feed-card">
<h2>Live journal feed</h2>
<p class="muted">Server-Sent Events from <code>GET /stream</code> — every seam event, newest last.</p>
<div id="journal"></div>
</div>
<script>
(function () {
  var box = document.getElementById("journal");
  var cls = function (ev) {
    if (ev === "action_denied") return "deny";
    if (ev === "gate_requested" || ev === "gate_decided") return "gate";
    if (ev === "action_completed") return "allow";
    return "";
  };
  try {
    var es = new EventSource("/stream?with_history=true");
    es.onmessage = function (e) {
      try { var d = JSON.parse(e.data); } catch (err) { return; }
      var div = document.createElement("div");
      div.className = "journal-line " + cls(d.event);
      div.textContent = "#" + (d.id != null ? d.id : "?") + " " + d.ts + "  " + d.event + "  "
        + JSON.stringify(d.payload);
      box.appendChild(div);
      while (box.childNodes.length > 200) { box.removeChild(box.firstChild); }
    };
  } catch (e) { /* no-SSE fallback: box stays empty */ }
})();
</script>"""


def inbox_fragment(poll_seconds: int = 3) -> str:
    """Approvals inbox, HTMX-polling the existing /inbox partial."""
    return f"""<div class="card" id="inbox-card" hx-get="/inbox" hx-headers='{{"Accept": "text/html"}}' hx-trigger="load, every {poll_seconds}s" hx-swap="innerHTML">
<h2>Approvals inbox</h2>
<span class="muted">loading…</span>
</div>"""


def lease_card_fragment(policy: LeasePolicy) -> str:
    """Lease-enforcement card: live policy state + plain-form toggle."""
    state = "ON" if policy.enabled else "OFF"
    cls = "lease-on" if policy.enabled else "lease-off"
    checked = "checked" if policy.enabled else ""
    ttl = policy.ttl_seconds
    return f"""<div class="card" id="lease-card" hx-get="/toggles/lease" hx-trigger="every 5s" hx-swap="none">
<h2>Lease enforcement</h2>
<div class="lease-card lease-{_esc(cls)}">
current state: <b>{_esc(state)}</b>, ttl <b>{_esc(ttl)}s</b>
</div>
<form method="post" action="/toggles/lease" _ = "">
<div class="inline-form">
<label><input type="checkbox" name="enabled" value="true" {_esc(checked)}> enforce leases</label>
<label>ttl (s) <input type="number" name="ttl_seconds" value="{_esc(ttl)}" min="1" step="1" style="width:6rem"></label>
<button type="submit" hx-post="/toggles/lease" hx-vals='js:{{enabled: this.form.enabled.checked, ttl_seconds: this.form.ttl_seconds.value}}' hx-swap="none">Apply</button>
</div>
</form>
<p class="muted">TTL applies to the next route; in-flight handoffs are never re-timed.</p>
</div>"""


def run_launcher_fragment() -> str:
    """Start-a-run form posting to the existing JSON /runs endpoint."""
    return """<div class="card" id="run-card">
<h2>Launch a governed run</h2>
<form method="post" action="/run-web" style="display:flex; gap:.5rem;">
<input name="task" placeholder="e.g. email the weekly report" style="flex:1" required>
<button type="submit">Run</button>
</form>
<p class="muted">The gate, if any, lands in the inbox above.</p>
</div>"""


def render_dashboard(policy: LeasePolicy) -> str:
    """Assemble the full page. Pure function of the current lease policy."""
    col1 = journal_feed_fragment() + run_launcher_fragment()
    col2 = inbox_fragment() + lease_card_fragment(policy)
    body = f'<div class="grid"><div>{col1}</div><div>{col2}</div></div>'
    return page_shell("Warden Console", body)
