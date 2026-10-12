"""Render the governed-demo run.json as a self-contained HTML timeline."""

from __future__ import annotations

import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

KIND_COLORS = {
    "action_requested": "#58a6ff",
    "policy_evaluated": "#a371f7",
    "action_denied": "#f85149",
    "gate_requested": "#d29922",
    "gate_decided": "#3fb950",
    "execution_started": "#79c0ff",
    "action_completed": "#3fb950",
    "action_failed": "#f85149",
}

def badge(kind: str) -> str:
    color = KIND_COLORS.get(kind, "#8b949e")
    return f'<span style="display:inline-block;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:600;border:1px solid {color};color:{color}">{html.escape(kind)}</span>'


def main() -> None:
    run = json.loads((ROOT / ".tmp" / "governed_demo" / "run.json").read_text(encoding="utf-8"))
    events = run["events"]
    rows = []
    for i, e in enumerate(events, 1):
        rows.append(
            "<tr>"
            f"<td style='color:#8b949e'>{i}</td>"
            f"<td>{badge(e['kind'])}</td>"
            f"<td>{html.escape(str(e['actor']))}</td>"
            f"<td style='color:#8b949e'>{html.escape(str(e['thread_id']))}</td>"
            f"<td>{html.escape(str(e['status']))}</td>"
            f"<td>{html.escape(str(e['description']))[:140]}</td>"
            f"<td style='color:#8b949e;font-size:12px'>{html.escape(str(e['ts']))[11:19]}</td>"
            "</tr>"
        )
    tele_cards = []
    for agent, t in run["telemetry"].items():
        tele_cards.append(
            "<div style='flex:1;min-width:220px;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px'>"
            f"<div style='font-weight:700;margin-bottom:8px'>{html.escape(agent)}</div>"
            f"<div>LLM calls: <b>{t['llm_calls']}</b> · Tools: <b>{t['tool_calls']}</b></div>"
            f"<div>Gated: <b>{t['gated']}</b> · Denied: <b style='color:#f85149'>{t['denied']}</b></div>"
            f"<div>Tokens: {t['prompt_tokens']} in / {t['completion_tokens']} out</div>"
            f"<div>Latency: {t['latency_ms']} ms</div></div>"
        )
    chain = run["chain"]
    page = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Governed Demo Timeline — {html.escape(run['run_id'])}</title></head>
<body style="background:#0d1117;color:#e6edf3;font-family:system-ui,sans-serif;margin:0;padding:24px">
<h1 style="font-size:22px">Warden governed demo — live timeline</h1>
<p style="color:#8b949e">run {html.escape(run['run_id'])} · {len(events)} journal events ·
hash chain: <b style="color:#3fb950">{html.escape(chain['status'])}</b> ({html.escape(str(chain['detail']))})</p>
<div style="display:flex;gap:12px;flex-wrap:wrap;margin:16px 0">{''.join(tele_cards)}</div>
<table style="width:100%;border-collapse:collapse;font-size:14px">
<thead><tr style="text-align:left;color:#8b949e">
<th>#</th><th>event</th><th>actor</th><th>thread</th><th>status</th><th>description</th><th>time</th>
</tr></thead><tbody>
{''.join(rows)}
</tbody></table>
<p style="color:#8b949e;font-size:13px;margin-top:16px">One enforced path per action:
journal → policy → HITL on escalate → sandbox/in-process execution → journal. DENY terminal · fail-closed · LLM usage journaled.</p>
</body></html>"""
    out = ROOT / ".tmp" / "governed_demo" / "timeline.html"
    out.write_text(page, encoding="utf-8")
    print(f"timeline -> {out}")


if __name__ == "__main__":
    main()
