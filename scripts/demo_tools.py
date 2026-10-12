"""Demo: 4 Phase-1 beats through ToolRouter.preview() + Groq draft stub.

No real network/DB/Docker required.
"""

from __future__ import annotations

import asyncio

from warden.tools.router import ToolRouter, draft_with_groq, make_tool_action


async def main() -> None:
    router = ToolRouter()
    beats = [
        ("1-safe-reads", "get_system_metrics", {"service": "orders", "metric": "cpu"}),
        ("2-hitl-gate", "send_email", {"recipient": "ops-team@example.com", "subject": "s", "body": "b"}),
        ("3-hard-deny", "exec_db_mutation", {"sql": "DROP TABLE old_logs;"}),
        ("4-sandbox", "exec_shell", {"command": "ls /workspace && echo cleaned"}),
    ]
    for label, name, payload in beats:
        outcome = router.preview(make_tool_action(name, payload, "run_demo", "thr_demo"))
        print(f"{label}: {name} -> {type(outcome).__name__}: {outcome}")
    draft = await draft_with_groq("weekly ops report")
    print("groq-draft:", draft.encode("ascii", "replace").decode())


if __name__ == "__main__":
    asyncio.run(main())
