"""Live OpenAI test through GuardedLLMClient (telemetry + cost + latency).

Requires OPENAI_API_KEY in the environment. Makes one real OpenAI request when
run manually; never imported or executed by the test suite.
"""

from __future__ import annotations

import asyncio
from typing import Any

from warden.llm.client import GuardedLLMClient
from warden.llm.providers import OpenAIProviderAdapter
from warden.llm.types import LLMRequest
from warden.models import Action, ActionKind


async def main() -> None:
    async def openai_provider(req: LLMRequest) -> Any:
        adapter = OpenAIProviderAdapter.from_settings(
            request_timeout_s=req.timeout_s
        )
        return await adapter.invoke(req)

    events: list[dict[str, Any]] = []

    async def sink(event: dict[str, Any]) -> None:
        events.append(event)

    client = GuardedLLMClient(provider_caller=openai_provider, telemetry_sink=sink)
    action = Action(
        id="act-live-openai-001",
        kind=ActionKind.LLM,
        name="gpt-4o",
        payload={
            "model": "gpt-4o",
            "provider": "openai",
            "messages": [
                {"role": "user", "content": "Reply with exactly: governance live."}
            ],
            "max_tokens": 50,
        },
        run_id="run-live-openai",
        thread_id="thr-live-openai",
    )
    try:
        result = await client.invoke(action)
    except Exception as exc:
        if "OPENAI_API_KEY" in str(exc):
            print("LIVE-OPENAI: skipped (OPENAI_API_KEY is not configured)")
            return
        raise

    safe_result = str(result.result).encode("ascii", "replace").decode()
    print(f"LIVE-OPENAI: success={result.is_success} latency_ms={result.latency_ms} retries={result.retry_count}")
    print(f"LIVE-OPENAI: result={safe_result!r}")
    print(
        f"LIVE-OPENAI: prompt={result.usage.prompt_tokens} completion={result.usage.completion_tokens} "
        f"total={result.usage.total_tokens} source={result.usage.source.value}"
    )
    if result.cost is not None and result.cost.calculated_cost is not None:
        print(f"LIVE-OPENAI: cost_usd={result.cost.calculated_cost}")
    else:
        print("LIVE-OPENAI: cost_usd=unavailable")
    print(f"LIVE-OPENAI: telemetry_events={len(events)} outcome={events[0].get('outcome_kind') if events else 'none'}")


if __name__ == "__main__":
    asyncio.run(main())
