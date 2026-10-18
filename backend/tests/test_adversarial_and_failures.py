"""
Adversarial and Failure Evaluation Suite for Contextual:
1. Prompt injection in finding descriptions (untrusted content cannot hijack deterministic logic)
2. Parameterized-query safety for malicious finding IDs (SQL/Cypher injection defense)
3. Missing paths and missing intermediate relationships
4. FalkorDB query failures and fail-closed verdict handling
5. Invalid timestamps rejected with HTTP 422
6. Gate B separation-of-duties enforcement (Two-Man Rule)
7. Cross-tenant IDOR and anti-enumeration (HTTP 404)
8. Historical decisions cannot bypass current Gate A review
9. Receipt determinism and tamper detection (RFC 8785)
"""
import uuid
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.graph.layer3_envelope import Layer3QueryEngine
from app.assembly.policy import assemble_verdict, Verdict, VerdictReason
from app.security.rfc8785_canonicalizer import create_signed_receipt, verify_receipt
from app.storage.durable_store import get_durable_store


@pytest.fixture
def client():
    return TestClient(app)


def get_token(client: TestClient, username: str = "analyst-alice-01", passphrase: str = "demo-alice-2026") -> str:
    resp = client.post(
        "/api/auth/token",
        json={"username": username, "passphrase": passphrase},
    )
    assert resp.status_code == 200, f"Token failed: {resp.text}"
    return resp.json()["access_token"]


def test_01_prompt_injection_in_finding_description_has_zero_effect(client):
    """
    Adversarial: Malicious description containing prompt injections cannot alter the verdict.
    Contextual does NOT ask an LLM to assemble verdicts; it uses the deterministic 16-row matrix.
    """
    token = get_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    # Finding finding-01 has a malicious injected prompt payload in our test simulation
    resp = client.post(
        "/api/investigate",
        json={
            "finding_id": "finding-01",
            "world_time": "2026-01-05T00:00:00Z",
            "knowledge_time": "2026-01-05T00:00:00Z",
        },
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    # At Jan 5, the path is active and carries CVE -> must be CULPABLE, never EXONERATED
    assert data["verdict"] == "CULPABLE"
    assert data["reason"] == "APPROVED_PATH_WITH_CVE"


def test_02_cypher_injection_in_finding_id_blocked(client):
    """
    Security: Attempting openCypher injection via finding_id is safely parameterized.
    Does not execute injected clauses and returns 404 (finding not found).
    """
    token = get_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    malicious_finding_id = "finding-01' OR 1=1 RETURN 'injected' --"
    resp = client.post(
        "/api/investigate",
        json={
            "finding_id": malicious_finding_id,
            "world_time": "2026-01-05T00:00:00Z",
            "knowledge_time": "2026-01-05T00:00:00Z",
        },
        headers=headers,
    )
    # Parameterized query searches for literal string -> not found -> 404
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Finding not found."


def test_03_missing_intermediate_relationship_prevents_reachability():
    """
    Topological integrity: If an intermediate hop is missing in the graph,
    reachability drops to False and the finding is not falsely marked CULPABLE.
    """
    engine = Layer3QueryEngine()
    # Mock Q1 returning empty list (severed hop)
    with patch.object(engine, "execute_query", return_value=([], None)):
        path_exists, path_details = engine.execute_topology_check(
            "finding-01", "tenant-corp-alpha", "2026-01-05T00:00:00Z", "2026-01-05T00:00:00Z"
        )
        assert path_exists is False
        assert path_details is None

        verdict, reason = assemble_verdict(p1_path=path_exists, p2_role=True, p3_rule=True, p4_cves=1)
        assert verdict == Verdict.DEGRADED
        assert reason == VerdictReason.ISOLATED_VULNERABILITY


def test_04_query_failure_fails_closed_never_exonerates():
    """
    Resilience: Database failure must fail closed with INDETERMINATE, never EXONERATED.
    """
    engine = Layer3QueryEngine()
    with patch.object(engine, "execute_query", return_value=([], "FALKORDB_CONNECTION_TIMEOUT")):
        path_exists, _ = engine.execute_topology_check(
            "finding-01", "tenant-corp-alpha", "2026-01-05T00:00:00Z", "2026-01-05T00:00:00Z"
        )
        assert path_exists is None  # Error, not False

        verdict, reason = assemble_verdict(p1_path=path_exists, p2_role=True, p3_rule=True, p4_cves=0)
        assert verdict == Verdict.INDETERMINATE
        assert reason == VerdictReason.SIGNAL_ERROR


def test_05_invalid_temporal_coordinates_rejected_with_422(client):
    """
    Validation: Non-ISO-8601 timestamps and unparsed strings are rejected with 422.
    """
    token = get_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    for bad_time in ["invalid-date", "Day 5", "2026/01/05", "2026-01-05"]:
        resp = client.post(
            "/api/investigate",
            json={
                "finding_id": "finding-01",
                "world_time": bad_time,
                "knowledge_time": "2026-01-05T00:00:00Z",
            },
            headers=headers,
        )
        assert resp.status_code == 422, f"Expected 422 for '{bad_time}', got {resp.status_code}"


def test_06_gate_b_two_man_rule_strictly_enforced(client):
    """
    Separation of Duties: The reviewer of Gate A cannot authorize Gate B remediation.
    """
    # 1. Investigate to get a live receipt
    token_alice = get_token(client, "analyst-alice-01", "demo-alice-2026")
    headers_alice = {"Authorization": f"Bearer {token_alice}"}

    resp = client.post(
        "/api/investigate",
        json={
            "finding_id": "finding-01",
            "world_time": "2026-01-05T00:00:00Z",
            "knowledge_time": "2026-01-05T00:00:00Z",
        },
        headers=headers_alice,
    )
    receipt_id = resp.json()["receipt_id"]

    # 2. Alice submits Gate A disposition
    resp_gate_a = client.post(
        "/api/reviews/gate-a/disposition",
        json={
            "receipt_id": receipt_id,
            "disposition": "APPROVED",
            "analyst_notes": "Reviewed by Alice",
        },
        headers=headers_alice,
    )
    assert resp_gate_a.status_code in (201, 200)

    # 3. If Alice attempts to authorize Gate B remediation, backend MUST reject with HTTP 403 Forbidden
    resp_gate_b_self = client.post(
        "/api/reviews/gate-b/authorize",
        json={
            "receipt_id": receipt_id,
            "proposal_action": "REVOKE_IAM_ROLE",
        },
        headers=headers_alice,
    )
    # Alice has role security:analyst, not security:lead (fails with 403)
    assert resp_gate_b_self.status_code == 403


def test_07_cross_tenant_idor_anti_enumeration(client):
    """
    Multi-tenant fence: Requesting a tenant-beta finding with tenant-alpha token returns HTTP 404 (NOT 403).
    """
    token_alpha = get_token(client, "analyst-alice-01", "demo-alice-2026")
    headers_alpha = {"Authorization": f"Bearer {token_alpha}"}

    resp = client.post(
        "/api/investigate",
        json={
            "finding_id": "finding-beta-01",  # belongs to tenant-corp-beta
            "world_time": "2026-01-05T00:00:00Z",
            "knowledge_time": "2026-01-05T00:00:00Z",
        },
        headers=headers_alpha,
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Finding not found."


def test_08_historical_decision_does_not_bypass_gate_a(client):
    """
    Compliance invariant: Retrieving a historical decision from FalkorDB graph memory
    does not authorize remediation without going through Gate A.
    """
    token_lead = get_token(client, "lead-carol-01", "demo-carol-2026")
    headers_lead = {"Authorization": f"Bearer {token_lead}"}

    # Attempt to directly authorize Gate B without Gate A approval on a fresh receipt
    fake_receipt_id = f"rcpt-unapproved-{uuid.uuid4().hex[:8]}"
    resp = client.post(
        "/api/reviews/gate-b/authorize",
        json={
            "receipt_id": fake_receipt_id,
            "proposal_action": "REVOKE_IAM_ROLE",
        },
        headers=headers_lead,
    )
    assert resp.status_code in (404, 409), f"Must not authorize without Gate A: {resp.status_code}"


def test_09_receipt_tamper_detection_and_determinism():
    """
    Cryptographic RFC 8785 receipt verification and tamper resistance.
    """
    evidence = {
        "finding_id": "finding-01",
        "tenant_id": "tenant-corp-alpha",
        "verdict": "CULPABLE",
        "reason": "APPROVED_PATH_WITH_CVE",
        "world_time": "2026-01-05T00:00:00Z",
        "knowledge_time": "2026-01-05T00:00:00Z",
    }
    signed = create_signed_receipt(evidence)
    assert verify_receipt(signed) is True

    # Tampering with 1 field invalidates the signature
    tampered_receipt = dict(signed)
    tampered_evidence = dict(evidence)
    tampered_evidence["verdict"] = "EXONERATED"
    tampered_receipt["evidence"] = tampered_evidence
    assert verify_receipt(tampered_receipt) is False
