import json
from warden.models import Action, ActionKind
from warden.policy.engine import HashEmbeddings, InMemoryPolicyStore, evaluate_l2, _cosine

emb = HashEmbeddings(dim=64)

# Final candidate corpus (the texts I intend to ship in v1).
candidates = {
    "p-allow-read-only": "read_table get_customer allowed read_only lookup query records table",
    "p-allow-search-lookup": "search_kb search knowledge base lookup query allowed read onboarding",
    "p-deny-pii-export": "db_export export customer PII personal data forbidden exfiltrate bulk",
    "p-allow-internal-report-export": "db_export export weekly report aggregated analytics allowed operations internal",
    "p-escalate-external-api-call": "call_external_api external api third party mutation escalated human approve destination",
    "p-invalid-verdict-maybe": "list_orders from the orders table allowed if requester on shift",
}

store = InMemoryPolicyStore(emb)
for pid, text in candidates.items():
    v = "allow" if pid.startswith("p-allow") else ("deny" if pid.startswith("p-deny") else ("maybe" if pid.startswith("p-invalid") else "escalate"))
    store.add_policy(pid, v, text)

def action(name, payload):
    return Action(id="x", kind=ActionKind.TOOL, name=name, payload=payload, run_id="x", thread_id="x")

def analyze(row_name, payload, expected_pid, label):
    a = action(row_name, payload)
    q = " ".join([row_name] + [str(x) for x in payload.values()])
    qvec = list(emb.embed_query(q))
    scored = []
    for pid, text in candidates.items():
        cvec = list(emb.embed_query(text))
        s = _cosine(qvec, cvec)
        v = "allow" if pid.startswith("p-allow") else ("deny" if pid.startswith("p-deny") else ("maybe" if pid.startswith("p-invalid") else "escalate"))
        scored.append((s, pid, v, text))
    scored.sort(reverse=True)
    top = scored[0]
    l2 = evaluate_l2(a, store, emb, threshold=0.8)
    nn_ok = top[1] == expected_pid
    match_at_08 = l2.matched
    band_lo = round(max(-1.0, top[0] - 0.05), 3)
    band_hi = round(min(1.0, top[0] + 0.05), 3)
    print(f"{label:34s} {row_name:16s} nn={top[1]!r:10s} (exp={expected_pid!r:10s} {'OK' if nn_ok else 'WRONG'}) sim={top[0]:.3f} band=[{band_lo},{band_hi}] match_at_0.8={match_at_08} verdict_at_0.8={l2.verdict}")
    return top[0], band_lo, band_hi

print("=== Final candidate texts: retrieval correctness + band derivation ===")
analyze("list_orders", {"query": "list open orders"}, "p-allow-read-only", "list_orders -> p-allow-read-only")
analyze("read_table", {"table": "customers", "limit": 100}, "p-allow-read-only", "read_table -> p-allow-read-only")
analyze("get_customer", {"customer_id": "42"}, "p-allow-read-only", "get_customer -> p-allow-read-only")
analyze("search_kb", {"query": "search the knowledge base for onboarding steps"}, "p-allow-search-lookup", "search_kb -> p-allow-search-lookup")
print()
analyze("db_export", {"query": "exporting customer PII data is forbidden"}, "p-deny-pii-export", "export-pii -> p-deny-pii-export")
analyze("db_export", {"query": "export the weekly report for operations"}, "p-allow-internal-report-export", "export-weekly -> p-allow-internal-report-export")
print()
analyze("call_external_api", {"destination": "third-party-crm", "mutation": "update contact"}, "p-escalate-external-api-call", "call_external_api -> p-escalate-external-api-call")
print()
print("Fail-closed rows (nearest neighbor is informational; assert escalate+unmatched at 0.8):")
for row_name, payload, label in [
    ("mystery_tool", {"query": "who knows what this does"}, "mystery_tool"),
    ("list_orders", {"query": "sunny in tokyo tomorrow"}, "list_orders(below-thresh)"),
    ("weather_lookup", {"query": "sunny in tokyo tomorrow"}, "weather_lookup"),
    ("list_orders", {"query": "some rule text"}, "list_orders(invalid-verdict near)"),
]:
    a = action(row_name, payload)
    q = " ".join([row_name] + [str(x) for x in payload.values()])
    qvec = list(emb.embed_query(q))
    scored = []
    for pid, text in candidates.items():
        cvec = list(emb.embed_query(text))
        s = _cosine(qvec, cvec)
        scored.append((s, pid))
    scored.sort(reverse=True)
    top = scored[0]
    l2 = evaluate_l2(a, store, emb, threshold=0.8)
    print(f"  {label:34s} {q!r:48s} nn={top[1]!r:10s} sim={top[0]:.3f} verdict_at_0.8={l2.verdict} matched={l2.matched}")
