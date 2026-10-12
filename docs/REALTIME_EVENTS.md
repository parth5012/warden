# Aegis — Real-time Events

> Event delivery mechanism for the Jinja + HTMX + FastAPI UI.
> Documents HTMX polling, server-sent events, payloads, and authorization.
> Proposed behavior is explicitly marked.

---

## 1. Architectural Choice

Aegis's UI is built with Jinja templates and HTMX, server-rendered through FastAPI (Lock 12). This means:

- **No WebSocket server** is required.
- **No JavaScript-heavy client** is needed.
- Real-time updates are delivered via **HTMX polling** or **Server-Sent Events (SSE)**, depending on the view.

The appropriate mechanism for each view is chosen based on:
- How frequently the data changes (inbox: infrequent; dashboard: moderate)
- Whether the user needs to be notified of a specific event (approval required: push preferred)
- Complexity budget (polling is simpler; SSE adds a long-lived connection)

---

## 2. HTMX Polling — Primary Mechanism 📋 PROPOSED

HTMX polling is the default update mechanism. Each panel declares its own poll interval using `hx-trigger="every Ns"`.

### How it works

```html
<!-- Example: approvals inbox panel — polls every 5 seconds -->
<div id="inbox-panel"
     hx-get="/inbox"
     hx-trigger="every 5s"
     hx-target="#inbox-panel"
     hx-swap="outerHTML">
  <!-- initial render from Jinja -->
</div>
```

The server returns an HTML fragment when the request carries `HX-Request: true`. FastAPI detects this header and returns the Jinja partial instead of a full page.

### Poll intervals by view

| View | Endpoint | Interval | Rationale |
|---|---|---|---|
| Approvals inbox | `GET /inbox` | 5 seconds | Human-time latency acceptable |
| Dashboard stats | `GET /dashboard` | 10 seconds | Aggregated data; less time-sensitive |
| Run timeline | `GET /runs/{thread_id}` | 3 seconds | Active run — operator watching |
| Audit log | `GET /audit` | Manual refresh | Stable data; no auto-poll needed |

### Server-side response

FastAPI route checks `HX-Request` header:

```python
# PROPOSED FastAPI route example
from fastapi import Request
from fastapi.templating import Jinja2Templates

@app.get("/inbox")
async def inbox(request: Request):
    data = await get_pending_gates()  # projection query
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            "partials/inbox_cards.html",
            {"request": request, "gates": data}
        )
    return templates.TemplateResponse(
        "inbox.html",
        {"request": request, "gates": data}
    )
```

---

## 3. Server-Sent Events (SSE) — Optional Enhancement 📋 PROPOSED

SSE provides push delivery from server to browser without polling overhead. It is appropriate for the approvals inbox when latency matters (reviewer is waiting on the page).

> **Note:** SSE adds a long-lived HTTP connection. This is more complex than polling and should only be implemented if polling latency is demonstrably inadequate for the demo.

### Proposed SSE endpoint

```
GET /events
```

**Query parameters:**

| Parameter | Description |
|---|---|
| `thread_id` | Subscribe to events for a specific thread |
| `kinds` | Comma-separated event kinds to receive (default: all) |

**Response:** `Content-Type: text/event-stream`

**Event format:**

```
event: gate_requested
id: <journal-event-id>
data: {"gate_id": "uuid", "action_name": "send_email", "requested_at": "..."}

event: gate_decided
id: <journal-event-id>
data: {"gate_id": "uuid", "verdict": "approve", "decided_by": "alice"}

event: action_completed
id: <journal-event-id>
data: {"action_id": "uuid", "action_name": "send_email", "outcome": "allowed"}

event: action_denied
id: <journal-event-id>
data: {"action_id": "uuid", "action_name": "drop_table", "policy": "no_destructive_sql"}
```

### Event types

| Event type | When emitted | Payload fields |
|---|---|---|
| `gate_requested` | Policy escalates | `gate_id`, `action_name`, `action_kind`, `requested_at` |
| `gate_decided` | Human decides | `gate_id`, `verdict`, `decided_by`, `decided_at` |
| `action_completed` | Action succeeds | `action_id`, `action_name`, `outcome`, `duration_ms` |
| `action_denied` | Policy denies | `action_id`, `action_name`, `policy`, `reason` |
| `action_failed` | Action errors | `action_id`, `action_name`, `error_code` |
| `run_completed` | Thread finishes | `thread_id`, `final_state` |

### HTMX with SSE

```html
<!-- Inbox panel subscribing to SSE for push updates -->
<div hx-ext="sse"
     sse-connect="/events?thread_id={{ thread_id }}"
     sse-swap="gate_requested">
  <div id="inbox-panel"
       hx-get="/inbox"
       hx-trigger="sse:gate_requested">
    <!-- updates when a gate_requested SSE event arrives -->
  </div>
</div>
```

---

## 4. Reconnection Behavior 📋 PROPOSED

### HTMX polling

HTMX polling is inherently resilient — if a request fails, the next poll attempt retries automatically. No special reconnection logic is needed.

### SSE reconnection

The browser's `EventSource` API automatically reconnects after connection loss with exponential backoff. The `id:` field in each event allows the server to replay missed events using the `Last-Event-ID` header on reconnect.

**Proposed server behavior on reconnect:**

```
GET /events?thread_id=xyz
Last-Event-ID: <last-seen-id>
```

The server queries the journal for events with `ts > last_seen_event.ts` and replays them before switching to live streaming.

---

## 5. Authorization 📋 PROPOSED

### Read events

The `/events` SSE endpoint and all polling endpoints are **unauthenticated** in the MVP. Any operator with access to the Aegis URL can view the dashboard and inbox.

### Write operations via HTMX

The approval decision form (`POST /gates/{gate_id}/decision`) requires the `Warden-Key` header. The Jinja template must include this as a hidden input or HTMX header:

```html
<!-- Approval form — sends Warden-Key as request header -->
<form hx-post="/gates/{{ gate.gate_id }}/decision"
      hx-headers='{"Warden-Key": "{{ warden_key }}"}'
      hx-target="#inbox-panel"
      hx-swap="outerHTML">
  <input type="hidden" name="verdict" value="approve">
  <input type="text" name="reason" placeholder="Reason..." required>
  <button type="submit">Approve</button>
</form>
```

> **Security note:** Embedding `warden_key` in a Jinja template means the key is sent to the browser. For the MVP this is acceptable. In a production deployment, this would be replaced with a proper session cookie and server-side key lookup.

---

## 6. Disconnected / Error States 📋 PROPOSED

Every UI view must handle the case where the server is unavailable.

| State | HTMX behavior | Visual treatment |
|---|---|---|
| Poll request fails (`503`) | HTMX retries on next interval | Show "Governance unavailable" banner |
| SSE connection dropped | Browser reconnects automatically | Show "Reconnecting…" indicator |
| Empty inbox | Server returns empty list | Show "No pending approvals" message |
| Run not found (`404`) | Route returns 404 page | Show "Run not found" message |
| Approval already decided (`409`) | Form submission fails | Show "Already decided" message inline |

---

## 7. Implementation Notes

- HTMX version: use the latest stable from CDN or bundle locally.
- For SSE support in HTMX, the `htmx-ext-sse` extension is required.
- FastAPI supports SSE via `fastapi.responses.StreamingResponse` with `media_type="text/event-stream"`.
- Long-lived SSE connections require the FastAPI server to use an async generator that yields events as they arrive from the journal.
- The journal must support an efficient "subscribe to new events" query (polling the journal on a short interval server-side, or using Postgres `LISTEN`/`NOTIFY`).

**Decision pending:** Whether to implement Postgres `LISTEN`/`NOTIFY` for SSE push delivery or use server-side polling of the journal. This decision should be made by workstream F before implementing the SSE endpoint.
