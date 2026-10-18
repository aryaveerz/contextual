"""
End-to-End Live REST API Integration Test Suite for Contextual.
"""
from fastapi.testclient import TestClient
from app.main import app

def test_full_system():
    client = TestClient(app)

    print("=" * 65)
    print("  CONTEXTUAL - END-TO-END REST API & GOVERNANCE VERIFICATION")
    print("=" * 65)

    # 1. Auth Endpoint
    res = client.post("/api/auth/token", json={"username": "analyst-alice-01", "passphrase": "demo-alice-2026"})
    assert res.status_code == 200, f"Auth failed: {res.text}"
    alice_token = res.json()["access_token"]
    alice_headers = {"Authorization": f"Bearer {alice_token}"}

    res_lead = client.post("/api/auth/token", json={"username": "lead-carol-01", "passphrase": "demo-carol-2026"})
    assert res_lead.status_code == 200
    carol_token = res_lead.json()["access_token"]
    carol_headers = {"Authorization": f"Bearer {carol_token}"}
    print("[1/8 PASS] /api/auth/token: Issued valid JWT tokens for analyst and lead.")

    # 2. Investigate Day 2 (Baseline)
    res_inv2 = client.post("/api/investigate", headers=alice_headers, json={
        "finding_id": "finding-priv-esc-01",
        "world_time": "2026-01-02T00:00:00Z",
        "knowledge_time": "2026-01-02T00:00:00Z"
    })
    assert res_inv2.status_code == 200, f"Investigate failed: {res_inv2.text}"
    data2 = res_inv2.json()
    print(f"[2/8 PASS] /api/investigate Day 2 Baseline: Verdict = {data2['verdict']}, Attack Path = {data2['signals']['p1_path']}")

    # 3. Investigate Day 5 (Discovery)
    res_inv5 = client.post("/api/investigate", headers=alice_headers, json={
        "finding_id": "finding-priv-esc-01",
        "world_time": "2026-01-05T00:00:00Z",
        "knowledge_time": "2026-01-05T00:00:00Z"
    })
    assert res_inv5.status_code == 200
    data5 = res_inv5.json()
    receipt_id = data5["receipt_id"]
    print(f"[3/8 PASS] /api/investigate Day 5 Discovery: Verdict = {data5['verdict']}, Receipt ID = {receipt_id}")
    assert data5["evidence_digest"] is not None
    assert data5["hmac_signature"] is not None

    # 4. Agent Endpoint (3-iteration bounded loop)
    res_agent = client.post("/api/agent/investigate", headers=alice_headers, json={
        "finding_id": "finding-priv-esc-01",
        "world_time": "2026-01-05T00:00:00Z",
        "knowledge_time": "2026-01-05T00:00:00Z"
    })
    assert res_agent.status_code == 200
    agent_data = res_agent.json()
    assert agent_data["agent_metadata"]["iterations_used"] == 3
    print(f"[4/8 PASS] /api/agent/investigate: Executed bounded 3-iteration agent loop (iterations = {agent_data['agent_metadata']['iterations_used']}).")

    # 5. Gate A Review Disposition
    res_gate_a = client.post("/api/reviews/gate-a/disposition", headers=alice_headers, json={
        "receipt_id": receipt_id,
        "disposition": "APPROVED",
        "analyst_notes": "Verified attack path and accepted risk reconsideration."
    })
    assert res_gate_a.status_code == 201, f"Gate A failed: {res_gate_a.text}"
    gate_a_data = res_gate_a.json()
    print(f"[5/8 PASS] Gate A Review Disposition: Disposition = {gate_a_data['disposition']}, Lifecycle = {gate_a_data['lifecycle_state']}")

    # 6. Gate B Authorization - Separation of Duties Test
    # A) Attempt same reviewer authorizing -> MUST return 403 SEPARATION_OF_DUTIES
    res_same = client.post("/api/reviews/gate-b/authorize", headers=alice_headers, json={
        "receipt_id": receipt_id,
        "remediation_target": "role-data-reader-prod",
        "rollback_safe": True
    })
    assert res_same.status_code == 403, f"Expected 403 but got {res_same.status_code}"
    print("[6/8 PASS] Gate B Separation of Duties: Same reviewer rejected with HTTP 403 (SEPARATION_OF_DUTIES).")

    # B) Different authorizer (Lead Carol) -> MUST succeed
    res_diff = client.post("/api/reviews/gate-b/authorize", headers=carol_headers, json={
        "receipt_id": receipt_id,
        "remediation_target": "role-data-reader-prod",
        "rollback_safe": True
    })
    assert res_diff.status_code == 201, f"Gate B lead auth failed: {res_diff.text}"
    gate_b_data = res_diff.json()
    print(f"[6/8 PASS] Gate B Two-Man Authorization: Proposal Registered ID = {gate_b_data['proposal_id']}, Lifecycle = {gate_b_data['lifecycle_state']}")

    # 7. Decision History Retrieval
    finding_id = "finding-priv-esc-01"
    res_hist = client.get(f"/api/investigate/{finding_id}/history", headers=alice_headers)
    assert res_hist.status_code == 200, f"History failed: {res_hist.text}"
    hist_data = res_hist.json()
    history_count = len(hist_data.get("history", []))
    print(f"[7/8 PASS] /api/investigate/{{id}}/history: Retrieved {history_count} institutional decisions from FalkorDB graph memory.")

    # 8. Multi-Tenant IDOR Protection
    res_idor = client.post("/api/investigate", headers=alice_headers, json={
        "finding_id": "finding-beta-01",
        "world_time": "2026-01-05T00:00:00Z",
        "knowledge_time": "2026-01-05T00:00:00Z"
    })
    assert res_idor.status_code == 404, f"Expected 404 for IDOR, got {res_idor.status_code}"
    print("[8/8 PASS] Multi-Tenant IDOR Defense: Cross-tenant finding request returned HTTP 404 (Anti-Enumeration).")

    print("\n" + "=" * 65)
    print("  ALL 8 REST ENDPOINTS & GOVERNANCE POLICIES PASSED WITH 100% SUCCESS!")
    print("=" * 65)

if __name__ == "__main__":
    test_full_system()
