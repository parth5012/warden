# Dashboard improvements included

This update refines the existing FastAPI + Jinja2 + HTMX dashboard without replacing the team's current design.

## Changes
- Added a dedicated `/approvals` page instead of reusing the entire command-center dashboard.
- Derived top-level counts from the sample action and audit records currently loaded by `app/main.py`, rather than showing unrelated hardcoded counts.
- Limited the approval review queue to actions with `Pending` or `Escalated` status.
- Added a visible `DEMO DATA` marker to make clear that the current dataset is illustrative, not live telemetry.
- Added text search to the approval queue and kept risk filtering.
- Changed unknown action IDs on `/actions/{action_id}` to return HTTP 404 rather than silently showing the first action.
- Added responsive styles for the dedicated queue page.

## Run locally (Windows PowerShell)
From the `Warden/warden` directory:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install fastapi "uvicorn[standard]" jinja2 python-multipart
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/` for the command center and `http://127.0.0.1:8000/approvals` for the approval queue.

## Important limitations
- The action and audit records remain in-memory demo data; they are not yet persisted in PostgreSQL or connected to the team's policy, execution, tracing, or hash-chained audit components.
- Approve, deny, and escalate controls intentionally remain disabled until authentication, authorization, CSRF protection, transactional persistence, and the execution handoff are implemented and tested.
- Activity chart data and agent telemetry are still illustrative. Do not present them as live metrics.
