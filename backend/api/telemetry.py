"""Multi-agent telemetry rollups (tokens, tools, latency, costs).

Aggregates real data from the GuardedLLMClient telemetry store in backend.api.llm.
Returns zeros gracefully when no LLM calls have been recorded yet.
"""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


@router.get("")
async def get_telemetry_summary() -> dict[str, Any]:
    """Summary of token usage, execution latency, and tool invocations.

    Pulls real token counts from the GuardedLLMClient telemetry store.
    Values are zeroed when no LLM calls have been recorded in this session.
    """
    # Import here to avoid circular import; llm module is a sibling.
    # The guarded client records llm_usage telemetry into the shared journal,
    # so this endpoint reads that single append-only store instead of a
    # per-module record list.
    from backend.api import get_audit_journal

    journal = get_audit_journal()
    events = await journal.query()
    records: list[dict[str, Any]] = []
    for e in events:
        obj = e.__dict__ if not isinstance(e, dict) else e
        if isinstance(obj, dict) and isinstance(obj.get("payload"), dict):
            obj = {**obj, **obj["payload"]}
        if isinstance(obj, dict) and isinstance(obj.get("prompt_tokens"), int):
            records.append(obj)


    # Aggregate over all captured records
    llm_calls = len(records)
    total_prompt = sum(r.get("prompt_tokens") or 0 for r in records)
    total_completion = sum(r.get("completion_tokens") or 0 for r in records)
    total_tokens = sum(r.get("total_tokens") or 0 for r in records)
    costs: list[float] = []
    for record in records:
        cost = record.get("calculated_cost_usd")
        if cost is None:
            cost = record.get("estimated_cost_usd")
        costs.append(float(cost or 0.0))
    total_cost = sum(costs)
    avg_latency = (
        sum(r.get("latency_ms") or 0 for r in records) / llm_calls
        if llm_calls > 0
        else 0.0
    )

    # Per-model breakdown
    by_model: dict[str, dict[str, Any]] = {}
    for r in records:
        model = r.get("model") or "unknown"
        provider = r.get("provider") or "unknown"
        key = f"{provider}/{model}"
        if key not in by_model:
            by_model[key] = {
                "model": model,
                "provider": provider,
                "calls": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "cost_usd": 0.0,
            }
        by_model[key]["calls"] += 1
        by_model[key]["prompt_tokens"] += r.get("prompt_tokens") or 0
        by_model[key]["completion_tokens"] += r.get("completion_tokens") or 0
        by_model[key]["total_tokens"] += r.get("total_tokens") or 0
        by_model[key]["cost_usd"] += (
            r.get("calculated_cost_usd")
            if r.get("calculated_cost_usd") is not None
            else r.get("estimated_cost_usd") or 0.0
        )

    tool_calls_count = sum(len(r.get("tool_calls") or []) for r in records)

    return {
        "actions_total": llm_calls,
        "llm_calls_total": llm_calls,
        "tool_calls_total": tool_calls_count,
        "total_prompt_tokens": total_prompt,
        "total_completion_tokens": total_completion,
        "tokens_total": total_tokens,
        "estimated_cost_usd": round(total_cost, 6),
        "avg_latency_ms": round(avg_latency, 1),
        "by_model": by_model,
        "by_agent": by_model,
        "source": "guarded_llm_client",
        "note": (
            "Token counts are provider-reported when a provider is configured, "
            "otherwise tiktoken preflight estimates."
        ),
    }
