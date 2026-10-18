"""
API security hardening and input validation regression tests:
1. ISO-8601 timestamp validation rejects malformed dates with HTTP 422
2. Sanitized authentication error messages (no raw token exceptions returned)
3. Rate-limiting covers both /api/investigate and /api/agent/investigate with JWT identity
4. Fail-closed query handling (query failures produce INDETERMINATE, never EXONERATED)
"""
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.graph.layer3_envelope import Layer3QueryEngine
from app.assembly.policy import Verdict, VerdictReason, assemble_verdict


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


def test_01_malformed_timestamp_rejected_with_422(client):
    """Temporal input validation: Malformed timestamp rejected with HTTP 422."""
    token = get_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    # Test invalid world_time on /api/investigate
    payload_bad_world = {
        "finding_id": "finding-01",
        "world_time": "not-a-timestamp",
        "knowledge_time": "2026-01-05T00:00:00Z",
    }
    resp = client.post("/api/investigate", json=payload_bad_world, headers=headers)
    assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text}"

    # Test invalid knowledge_time on /api/agent/investigate
    payload_bad_kt = {
        "finding_id": "finding-01",
        "world_time": "2026-01-05T00:00:00Z",
        "knowledge_time": "2026-99-99",
    }
    resp_agent = client.post("/api/agent/investigate", json=payload_bad_kt, headers=headers)
    assert resp_agent.status_code == 422, f"Expected 422, got {resp_agent.status_code}: {resp_agent.text}"


def test_02_sanitized_auth_error_no_exception_leak(client):
    """Authentication errors return generic message, never raw exception text."""
    # Send a malformed JWT
    headers = {"Authorization": "Bearer totally.invalid.jwt.token"}
    resp = client.post(
        "/api/investigate",
        json={
            "finding_id": "finding-01",
            "world_time": "2026-01-05T00:00:00Z",
            "knowledge_time": "2026-01-05T00:00:00Z",
        },
        headers=headers,
    )
    assert resp.status_code == 401
    data = resp.json()
    assert data["detail"] == "Invalid or expired authentication token."
    assert "Traceback" not in resp.text
    assert "InvalidTokenError" not in resp.text
    assert "DecodeError" not in resp.text


def test_03_query_failure_fails_closed_never_exonerates():
    """Graph query failure produces INDETERMINATE, never EXONERATED."""
    engine = Layer3QueryEngine()

    # Mock execute_query to simulate a database query error
    with patch.object(engine, "execute_query", return_value=([], "QUERY_EXECUTION_ERROR_Q1")):
        path_exists, path_details = engine.execute_topology_check(
            "finding-01", "tenant-corp-alpha", "2026-01-05T00:00:00Z", "2026-01-05T00:00:00Z"
        )
        assert path_exists is None, "Query error must return None, not False"
        assert path_details is None

        # Verify policy assembly with None fails closed to INDETERMINATE
        verdict, reason = assemble_verdict(
            p1_path=path_exists,
            p2_role=True,
            p3_rule=True,
            p4_cves=0,
        )
        assert verdict == Verdict.INDETERMINATE
        assert reason == VerdictReason.SIGNAL_ERROR


def test_04_rate_limiting_protects_both_endpoints(client):
    """Rate limit protects both /api/investigate and /api/agent/investigate."""
    token = get_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    # Simulate exhausting the rate limit bucket for this principal
    from app.services.investigation import check_rate_limit, _rate_buckets
    client_key = "tenant-corp-alpha:analyst-alice-01"

    # Fill the bucket
    import time
    now = time.monotonic()
    _rate_buckets[client_key] = [now] * 65

    # Test /api/investigate is throttled
    resp = client.post(
        "/api/investigate",
        json={
            "finding_id": "finding-01",
            "world_time": "2026-01-05T00:00:00Z",
            "knowledge_time": "2026-01-05T00:00:00Z",
        },
        headers=headers,
    )
    assert resp.status_code == 429
    assert "Too many requests" in resp.json()["detail"]
    assert "Retry-After" in resp.headers

    # Test /api/agent/investigate is also throttled
    resp_agent = client.post(
        "/api/agent/investigate",
        json={
            "finding_id": "finding-01",
            "world_time": "2026-01-05T00:00:00Z",
            "knowledge_time": "2026-01-05T00:00:00Z",
        },
        headers=headers,
    )
    assert resp_agent.status_code == 429
    assert "Too many requests" in resp_agent.json()["detail"]

    # Clear bucket after test
    _rate_buckets.pop(client_key, None)


def test_05_security_headers_and_swagger_docs(client):
    """Enterprise OWASP security headers present on API; Swagger /docs allowed."""
    # API endpoints enforce strict CSP
    api_resp = client.get("/health")
    assert api_resp.status_code == 200
    assert api_resp.headers["x-content-type-options"] == "nosniff"
    assert api_resp.headers["x-frame-options"] == "DENY"
    assert api_resp.headers["content-security-policy"] == "default-src 'self'"

    # /docs endpoint receives CDN-compatible CSP and loads successfully
    docs_resp = client.get("/docs")
    assert docs_resp.status_code == 200
    assert "swagger-ui" in docs_resp.text
    assert "https://cdn.jsdelivr.net" in docs_resp.headers["content-security-policy"]

