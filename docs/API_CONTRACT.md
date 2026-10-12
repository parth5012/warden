# Aegis — API Contract

> Documents all HTTP interfaces for the Aegis FastAPI application.
> Existing routes vs. proposed routes are clearly labelled.
> The UI uses Jinja + HTMX, server-rendered. All API routes return JSON. (Lock 12)

---

## Status Legend

| Label | Meaning |
|---|---|
| ✅ EXISTS | Route is implemented and tested |
| 📋 PROPOSED | Route is documented but not yet implemented |

No routes exist today (FastAPI app is Phase 1 planned work). All routes below are **📋 PROPOSED**.

---

## General Conventions

- **Base URL:** `http://localhost:8000` (configurable via `WARDEN_HOST` / `WARDEN_PORT`)
- **Content-Type:** `application/json` for all API responses; `text/html` for Jinja page routes
- **Authentication:** Named-key header `Warden-Key: <key>` for write operations (Lock 8). Read operations are unauthenticated in the MVP.
- **Error format:**

```json
{
  "error": "string — machine-readable code",
  "detail": "string — human-readable explanation",
  "request_id": "string — optional correlation ID"
}
```

- **Timestamps:** ISO 8601 UTC (`2026-10-11T17:00:00Z`)
- **IDs:** UUID strings

---

## 1. Health and Readiness 📋 PROPOSED

### `GET /health`

Basic liveness probe.

**Response 200:**
```json
{ "status": "ok" }
```

**Response 503:**
```json
{ "status": "degraded", "detail": "postgres unavailable" }
```

No authentication required.

---

### `GET /ready`

Readiness probe — confirms database connectivity and checkpoint tables are set up.

**Response 200:**
```json
{ "ready": true, "checkpoint_store": "ok", "journal": "ok" }
```

**Response 503:**
```json
{ "ready": false, "checkpoint_store": "error", "detail": "..." }
```

---

## 2. Run Lifecycle 📋 PROPOSED

### `POST /runs`

Start a new agent thread.

**Request:**
```json
{
  "agent_id": "ops_assistant",
  "input": "email the weekly report to team@example.com",
  "thread_id": "optional-client-supplied-id"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_id` | string | Yes | Identifies which agent graph to run |
| `input` | string | Yes | Initial user instruction |
| `thread_id` | string | No | Client-supplied thread ID; auto-generated if absent |

**Response 201:**
```json
{
  "thread_id": "uuid",
  "status": "running",
  "created_at": "2026-10-11T17:00:00Z"
}
```

**Errors:**
- `400` — unknown `agent_id` or malformed request
- `503` — governance infrastructure unavailable

---

### `GET /runs/{thread_id}`

Get the current status and timeline of a run.

**Path parameter:** `thread_id` — LangGraph thread ID

**Response 200:**
```json
{
  "thread_id": "uuid",
  "status": "running | parked | completed | failed",
  "has_pending_gate": true,
  "pending_gate_id": "uuid | null",
  "step": 3,
  "checkpoint_id": "uuid",
  "timeline": [
    {
      "event_kind": "action_requested",
      "action_name": "send_email",
      "ts": "2026-10-11T17:00:01Z",
      "outcome": null
    },
    {
      "event_kind": "gate_requested",
      "action_name": "send_email",
      "gate_id": "uuid",
      "ts": "2026-10-11T17:00:02Z",
      "outcome": "pending"
    }
  ]
}
```

Timeline is a journal projection ordered by timestamp.

**Errors:**
- `404` — thread not found

---

### `DELETE /runs/{thread_id}` 📋 PROPOSED

Request cancellation of a running or parked thread.

**Header:** `Warden-Key: <key>` required

**Response 202:**
```json
{ "thread_id": "uuid", "status": "cancellation_requested" }
```

> Note: Cancellation of a parked thread means the resume will never be called. The thread remains in the checkpoint store but will not be resumed.

---

## 3. Approvals Inbox 📋 PROPOSED

### `GET /inbox`

List pending gate requests. Used by the HTMX approvals inbox UI.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `run_id` | string | Filter by run |
| `limit` | integer | Max results (default: 50) |

**Response 200:**
```json
{
  "pending": [
    {
      "gate_id": "uuid",
      "action_id": "uuid",
      "run_id": "uuid",
      "thread_id": "uuid",
      "action_name": "send_email",
      "action_kind": "tool",
      "action_payload": { "recipient": "team@example.com", "body": "..." },
      "context": { "ask": "approve or deny?" },
      "requested_at": "2026-10-11T17:00:02Z"
    }
  ],
  "count": 1
}
```

This endpoint is also used as an HTMX partial for the approvals inbox panel.

---

### `POST /gates/{gate_id}/decision`

Submit a human decision for a pending gate.

**Header:** `Warden-Key: <key>` required

**Path parameter:** `gate_id` — UUID from `GateRequest.gate_id`

**Request:**
```json
{
  "verdict": "approve | deny",
  "reason": "Approved for weekly distribution"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `verdict` | string | Yes | `"approve"` or `"deny"` |
| `reason` | string | Yes | Reviewer's stated reason (recorded in journal) |

**Response 200:**
```json
{
  "gate_id": "uuid",
  "verdict": "approve",
  "decided_by": "alice",
  "decided_at": "2026-10-11T17:01:00Z",
  "thread_status": "running"
}
```

**Processing sequence:**
1. Validate `Warden-Key` header — resolve named principal.
2. Verify `gate_id` refers to a `pending` gate in the journal.
3. Append `gate_decided` event to journal.
4. Call `graph.invoke(Command(resume=decision), config)` to resume the parked thread.
5. Return the decision record.

**Errors:**
- `401` — missing or invalid `Warden-Key`
- `404` — `gate_id` not found
- `409` — gate already decided
- `422` — invalid verdict value
- `503` — governance infrastructure unavailable

---

## 4. Audit Journal 📋 PROPOSED

### `GET /audit`

Searchable audit log. Journal projection with filtering.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `q` | string | Full-text search in payload |
| `run_id` | string | Filter by run |
| `thread_id` | string | Filter by thread |
| `kind` | string | Filter by event kind (e.g. `action_denied`) |
| `actor` | string | Filter by actor |
| `from` | ISO 8601 | Start timestamp |
| `to` | ISO 8601 | End timestamp |
| `limit` | integer | Max results (default: 100) |
| `offset` | integer | Pagination offset |

**Response 200:**
```json
{
  "events": [
    {
      "id": "uuid",
      "run_id": "uuid",
      "thread_id": "uuid",
      "action_id": "uuid | null",
      "checkpoint_step": 2,
      "kind": "action_denied",
      "actor": "ops_assistant",
      "payload": { "action_name": "drop_table", "policy": "no_destructive_sql" },
      "ts": "2026-10-11T17:00:05Z"
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

---

### `GET /runs/{thread_id}/graph`

Decision-graph projection for a specific run. Returns journal events joined with checkpoint steps.

**Response 200:**
```json
{
  "thread_id": "uuid",
  "nodes": [
    { "id": "action_requested:uuid", "kind": "action_requested", "step": 1, "ts": "..." },
    { "id": "gate_requested:uuid",   "kind": "gate_requested",   "step": 1, "ts": "..." },
    { "id": "gate_decided:uuid",     "kind": "gate_decided",     "step": 1, "ts": "..." },
    { "id": "action_completed:uuid", "kind": "action_completed", "step": 2, "ts": "..." }
  ],
  "edges": [
    { "from": "action_requested:uuid", "to": "gate_requested:uuid" },
    { "from": "gate_requested:uuid",   "to": "gate_decided:uuid" },
    { "from": "gate_decided:uuid",     "to": "action_completed:uuid" }
  ]
}
```

---

## 5. Telemetry Dashboard 📋 PROPOSED

### `GET /dashboard`

Aggregated telemetry projection: token cost, latency, tool usage per run.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `run_id` | string | Limit to one run |
| `from` | ISO 8601 | Time range start |
| `to` | ISO 8601 | Time range end |

**Response 200:**
```json
{
  "summary": {
    "total_runs": 3,
    "total_llm_calls": 12,
    "total_tool_calls": 8,
    "total_tokens": 45000,
    "estimated_cost_usd": 0.14,
    "avg_latency_ms": 820
  },
  "by_run": [
    {
      "run_id": "uuid",
      "thread_id": "uuid",
      "llm_calls": 4,
      "tool_calls": 3,
      "total_tokens": 15000,
      "estimated_cost_usd": 0.05,
      "actions": [
        {
          "action_name": "send_email",
          "kind": "tool",
          "outcome": "allowed",
          "duration_ms": 230
        }
      ]
    }
  ]
}
```

---

## 6. Policy Inspection 📋 PROPOSED (Phase 2)

### `GET /policies`

List active policy rules.

**Response 200:**
```json
{
  "policies": [
    {
      "id": "uuid",
      "name": "no_destructive_sql",
      "action": "deny",
      "description": "Block DROP, TRUNCATE, DELETE without WHERE",
      "active": true,
      "created_at": "2026-10-11T17:00:00Z",
      "current_version": 1
    }
  ]
}
```

### `POST /policies` 📋 PROPOSED (Phase 2)

Create or update a policy rule. Appends to `policy_versions`.

**Header:** `Warden-Key: <key>` required

**Request:**
```json
{
  "name": "escalate_external_email",
  "action": "escalate",
  "description": "Require approval for email to external domains",
  "rule_text": "tool=send_email AND recipient NOT ENDS_WITH @internal.example.com"
}
```

**Response 201:**
```json
{
  "id": "uuid",
  "name": "escalate_external_email",
  "version": 1,
  "created_by": "alice",
  "created_at": "2026-10-11T17:02:00Z"
}
```

---

## 7. UI Routes (Jinja pages) 📋 PROPOSED

These routes render full HTML pages using Jinja templates. They are not JSON endpoints.

| Route | Template | Description |
|---|---|---|
| `GET /` | `dashboard.html` | Telemetry overview |
| `GET /runs` | `runs.html` | All runs list |
| `GET /runs/{thread_id}` | `run_detail.html` | Single run timeline |
| `GET /inbox` | `inbox.html` | Pending approvals (also HTMX partial) |
| `GET /audit` | `audit.html` | Searchable audit log |
| `GET /policies` | `policies.html` | Policy list and versions |

### HTMX Partial Routes

These routes return HTML fragments for HTMX polling/swap. They share paths with their JSON equivalents but return HTML when the request carries `HX-Request: true`.

| Route | Fragment | Refresh interval |
|---|---|---|
| `GET /inbox` with `HX-Request: true` | Inbox card list | Every 5 seconds (polling) |
| `GET /runs/{thread_id}` with `HX-Request: true` | Timeline fragment | On-demand |
| `GET /dashboard` with `HX-Request: true` | Stats cards | Every 10 seconds |

> FastAPI can distinguish HTMX requests via the `HX-Request` header and return either JSON or HTML from the same route path using response negotiation.

---

## 8. Error Handling

### Standard error codes

| HTTP | `error` field | Meaning |
|---|---|---|
| 400 | `bad_request` | Malformed request body or params |
| 401 | `unauthorized` | Missing or invalid `Warden-Key` |
| 404 | `not_found` | Resource does not exist |
| 409 | `conflict` | State conflict (e.g. gate already decided) |
| 422 | `validation_error` | Pydantic validation failure |
| 503 | `governance_unavailable` | Database or governance infrastructure down |

### Fail-closed behavior

If the governance infrastructure is unavailable, the API returns `503` and **does not execute any action**. This mirrors the `Error("governance_unavailable")` outcome from `execute()`.

---

## 9. Versioning and Compatibility

- API version is embedded in the `X-Aegis-Version` response header.
- Routes are unversioned in the URL path for the MVP.
- Breaking changes require a new path prefix (`/v2/...`) and a deprecation notice period.
- The JSON shape of every response must remain backwards-compatible within a major version.
