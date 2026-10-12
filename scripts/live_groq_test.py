"""Live Groq test through GuardedLLMClient (telemetry + cost + latency).

Requires GROQ_API_KEY in .env. Real network call to api.groq.com.
"""

from __future__ import annotations

import asyncio
from typing import Any

from warden.config import get_groq_llm, settings
from warden.llm.client import GuardedLLMClient
from warden.llm.types import LLMRequest
from warden.models import Action, ActionKind


async def main() -> None:
    llm = get_groq_llm()
    if llm is None:
        print("LIVE-GROQ: skipped (no key)")
        return

    async def groq_provider(req: LLMRequest) -> Any:
        msgs = req.messages
        text = " ".join(str(m.get("content", m)) for m in msgs) if isinstance(msgs, list) else str(msgs)
        return await llm.ainvoke(text)

    events: list[dict[str, Any]] = []

    async def sink(event: dict[str, Any]) -> None:
        events.append(event)

    client = GuardedLLMClient(provider_caller=groq_provider, telemetry_sink=sink)
    action = Action(
        id="act-live-groq-001",
        kind=ActionKind.LLM,
        name=settings.groq_model,
        payload={
            "model": settings.groq_model,
            "provider": "groq",
            "messages": [{"role": "user", "content": "Reply with exactly: governance live."}],
            "max_tokens": 50,
        },
        run_id="run-live-groq",
        thread_id="thr-live-groq",
    )
    result = await client.invoke(action)
    safe_result = str(result.result).encode("ascii", "replace").decode()
    print(f"LIVE-GROQ: success={result.is_success} latency_ms={result.latency_ms} retries={result.retry_count}")
    print(f"LIVE-GROQ: result={safe_result!r}")
    print(
        f"LIVE-GROQ: prompt={result.usage.prompt_tokens} completion={result.usage.completion_tokens} "
        f"total={result.usage.total_tokens} source={result.usage.source.value}"
    )
    if result.cost is not None and result.cost.calculated_cost is not None:
        print(f"LIVE-GROQ: cost_usd={result.cost.calculated_cost}")
    else:
        print("LIVE-GROQ: cost_usd=unpriced (model not in pricing catalog)")
    print(f"LIVE-GROQ: telemetry_events={len(events)} outcome={events[0].get('outcome_kind') if events else 'none'}")


if __name__ == "__main__":
    asyncio.run(main())
