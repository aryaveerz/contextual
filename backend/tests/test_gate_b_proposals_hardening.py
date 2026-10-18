"""
Regression test suite for Gate B remediation authorization and pr_status persistence:
1. GitHub integration not configured: persists as PENDING, pr_url is None, clear note.
2. GitHub PR successfully created: persists as OPEN, pr_url populated from GitHub response.
3. GitHub API rejects request: persists as PENDING, pr_url is None, proposal not lost.
4. GitHub request times out or network exception: persists as PENDING, pr_url is None.
5. Gate B rejected when Gate A has not approved the receipt (HTTP 409).
6. Gate B rejected when reviewer and authorizer are same identity (HTTP 403 SEPARATION_OF_DUTIES).
7. Tenant A cannot authorize a receipt owned by Tenant B (HTTP 404 IDOR defense).
8. Stored status always satisfies database CHECK(pr_status IN ('PENDING','DRAFT','OPEN','MERGED','CLOSED')).
"""
import uuid
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.config import get_settings
from app.storage.durable_store import get_durable_store

@pytest.fixture
def client():
    return TestClient(app)


def get_token(client: TestClient, username: str, passphrase: str) -> str:
    resp = client.post(
        "/api/auth/token",
        json={"username": username, "passphrase": passphrase},
    )
    assert resp.status_code == 200, f"Token failed for {username}: {resp.text}"
    return resp.json()["access_token"]


def create_test_receipt(store, tenant_id: str = "tenant-corp-alpha") -> str:
    receipt_id = f"rcpt-test-{uuid.uuid4().hex[:12]}"
    store.write_receipt(
        receipt_id=receipt_id,
        tenant_id=tenant_id,
        finding_id="finding-01",
        verdict="CULPABLE",
        world_time="2026-01-05T00:00:00Z",
        knowledge_time="2026-01-05T00:00:00Z",
        signals={"p1_path": True, "p2_role": True, "p3_rule": False, "p4_cves": 1},
        canonical_sha256="test-sha256",
        hmac_signature="test-hmac",
    )
    return receipt_id


def test_01_gate_b_github_not_configured(client):
    """
    Scenario 1: When GitHub credentials are not configured, proposal is persisted
    as PENDING, pr_url is None, and response honestly notes no PR created.
    """
    store = get_durable_store()
    receipt_id = create_test_receipt(store)

    # Approve Gate A with analyst-alice-01
    token_alice = get_token(client, "analyst-alice-01", "demo-alice-2026")
    res_a = client.post(
        "/api/reviews/gate-a/disposition",
        json={"receipt_id": receipt_id, "disposition": "APPROVED", "analyst_notes": "Evidence verified"},
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert res_a.status_code == 201

    # Authorize Gate B with lead-carol-01 (GitHub not configured)
    token_carol = get_token(client, "lead-carol-01", "demo-carol-2026")
    with patch("app.routers.reviews.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(github_token="", github_repo="")
        res_b = client.post(
            "/api/reviews/gate-b/authorize",
            json={"receipt_id": receipt_id, "proposal_action": "REVOKE_IAM_ROLE_ASSIGNMENT"},
            headers={"Authorization": f"Bearer {token_carol}"},
        )

    assert res_b.status_code == 201
    data = res_b.json()
    assert data["pr_status"] == "PENDING"
    assert data["pr_url"] is None
    assert "not configured" in data["note"].lower()

    # Verify directly from durable store
    stored = store.get_remediation_proposal(receipt_id, "tenant-corp-alpha")
    assert stored is not None
    assert stored["pr_status"] == "PENDING"
    assert stored["pr_url"] is None


def test_02_gate_b_github_pr_successfully_created(client):
    """
    Scenario 2: When GitHub integration is configured and PR creation succeeds,
    proposal is persisted as OPEN with the real html_url returned by GitHub.
    """
    store = get_durable_store()
    receipt_id = create_test_receipt(store)

    token_alice = get_token(client, "analyst-alice-01", "demo-alice-2026")
    client.post(
        "/api/reviews/gate-a/disposition",
        json={"receipt_id": receipt_id, "disposition": "APPROVED"},
        headers={"Authorization": f"Bearer {token_alice}"},
    )

    token_carol = get_token(client, "lead-carol-01", "demo-carol-2026")
    fake_gh_response = MagicMock(status_code=201)
    fake_gh_response.json.return_value = {
        "html_url": "https://github.com/corp/infra-repo/pull/742",
        "number": 742,
    }

    with patch("app.routers.reviews.get_settings") as mock_settings, \
         patch("httpx.post", return_value=fake_gh_response):
        mock_settings.return_value = MagicMock(github_token="ghp_live_test_token", github_repo="corp/infra-repo")
        res_b = client.post(
            "/api/reviews/gate-b/authorize",
            json={"receipt_id": receipt_id},
            headers={"Authorization": f"Bearer {token_carol}"},
        )

    assert res_b.status_code == 201
    data = res_b.json()
    assert data["pr_status"] == "OPEN"
    assert data["pr_url"] == "https://github.com/corp/infra-repo/pull/742"

    stored = store.get_remediation_proposal(receipt_id, "tenant-corp-alpha")
    assert stored["pr_status"] == "OPEN"
    assert stored["pr_url"] == "https://github.com/corp/infra-repo/pull/742"


def test_03_gate_b_github_api_rejects_request(client):
    """
    Scenario 3: When GitHub API returns non-200/201 (e.g. 422 Unprocessable Entity),
    proposal is persisted as PENDING, pr_url is None, and governance record is preserved.
    """
    store = get_durable_store()
    receipt_id = create_test_receipt(store)

    token_alice = get_token(client, "analyst-alice-01", "demo-alice-2026")
    client.post(
        "/api/reviews/gate-a/disposition",
        json={"receipt_id": receipt_id, "disposition": "APPROVED"},
        headers={"Authorization": f"Bearer {token_alice}"},
    )

    token_carol = get_token(client, "lead-carol-01", "demo-carol-2026")
    fake_gh_error = MagicMock(status_code=422)
    fake_gh_error.json.return_value = {"message": "Validation Failed: No commits between base and head"}

    with patch("app.routers.reviews.get_settings") as mock_settings, \
         patch("httpx.post", return_value=fake_gh_error):
        mock_settings.return_value = MagicMock(github_token="ghp_live_token", github_repo="corp/infra-repo")
        res_b = client.post(
            "/api/reviews/gate-b/authorize",
            json={"receipt_id": receipt_id},
            headers={"Authorization": f"Bearer {token_carol}"},
        )

    assert res_b.status_code == 201
    data = res_b.json()
    assert data["pr_status"] == "PENDING"
    assert data["pr_url"] is None
    assert "422" in data["note"]

    # Durable store record exists and is compliant
    stored = store.get_remediation_proposal(receipt_id, "tenant-corp-alpha")
    assert stored is not None
    assert stored["pr_status"] == "PENDING"
    assert stored["pr_url"] is None


def test_04_gate_b_github_request_timeout_or_network_error(client):
    """
    Scenario 4: When GitHub request times out or raises a network exception,
    the governance record is preserved with PENDING, pr_url is None, without losing authorization.
    """
    import httpx
    store = get_durable_store()
    receipt_id = create_test_receipt(store)

    token_alice = get_token(client, "analyst-alice-01", "demo-alice-2026")
    client.post(
        "/api/reviews/gate-a/disposition",
        json={"receipt_id": receipt_id, "disposition": "APPROVED"},
        headers={"Authorization": f"Bearer {token_alice}"},
    )

    token_carol = get_token(client, "lead-carol-01", "demo-carol-2026")
    with patch("app.routers.reviews.get_settings") as mock_settings, \
         patch("httpx.post", side_effect=httpx.ConnectTimeout("Connection to api.github.com timed out")):
        mock_settings.return_value = MagicMock(github_token="ghp_live_token", github_repo="corp/infra-repo")
        res_b = client.post(
            "/api/reviews/gate-b/authorize",
            json={"receipt_id": receipt_id},
            headers={"Authorization": f"Bearer {token_carol}"},
        )

    assert res_b.status_code == 201
    data = res_b.json()
    assert data["pr_status"] == "PENDING"
    assert data["pr_url"] is None
    assert "connecttimeout" in data["note"].lower()

    stored = store.get_remediation_proposal(receipt_id, "tenant-corp-alpha")
    assert stored is not None
    assert stored["pr_status"] == "PENDING"
    assert stored["pr_url"] is None


def test_05_gate_b_rejected_when_gate_a_not_approved(client):
    """
    Scenario 5: Gate B must be rejected (HTTP 409) if Gate A has not approved the receipt.
    """
    store = get_durable_store()
    receipt_id = create_test_receipt(store)

    token_carol = get_token(client, "lead-carol-01", "demo-carol-2026")
    # Gate A was NEVER submitted
    res_b = client.post(
        "/api/reviews/gate-b/authorize",
        json={"receipt_id": receipt_id},
        headers={"Authorization": f"Bearer {token_carol}"},
    )
    assert res_b.status_code == 409
    assert "Gate A must be APPROVED" in res_b.text

    # Now reject Gate A
    token_alice = get_token(client, "analyst-alice-01", "demo-alice-2026")
    client.post(
        "/api/reviews/gate-a/disposition",
        json={"receipt_id": receipt_id, "disposition": "REJECTED"},
        headers={"Authorization": f"Bearer {token_alice}"},
    )

    # Gate B still rejected
    res_b2 = client.post(
        "/api/reviews/gate-b/authorize",
        json={"receipt_id": receipt_id},
        headers={"Authorization": f"Bearer {token_carol}"},
    )
    assert res_b2.status_code == 409


import time
import jwt


def make_test_token(sub: str, roles: list, tenant_id: str = "tenant-corp-alpha") -> str:
    settings = get_settings()
    payload = {
        "sub": sub,
        "roles": roles,
        "tenant_id": tenant_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    return jwt.encode(payload, key=bytes.fromhex(settings.auth_jwt_secret), algorithm="HS256")


def test_06_gate_b_rejected_when_reviewer_equals_authorizer(client):
    """
    Scenario 6: Gate B must be rejected (HTTP 403 SEPARATION_OF_DUTIES)
    when reviewer_id == authorizer_id.
    """
    store = get_durable_store()
    receipt_id = create_test_receipt(store)

    # User who possesses both analyst and lead roles (e.g. lead-analyst)
    dual_token = make_test_token(
        sub="analyst-lead-sam",
        roles=["security:analyst", "security:lead"],
        tenant_id="tenant-corp-alpha",
    )

    # Sam approves Gate A
    res_a = client.post(
        "/api/reviews/gate-a/disposition",
        json={"receipt_id": receipt_id, "disposition": "APPROVED"},
        headers={"Authorization": f"Bearer {dual_token}"},
    )
    assert res_a.status_code == 201

    # Sam attempts to authorize Gate B for the same receipt -> MUST BE REJECTED
    res_b = client.post(
        "/api/reviews/gate-b/authorize",
        json={"receipt_id": receipt_id},
        headers={"Authorization": f"Bearer {dual_token}"},
    )
    assert res_b.status_code == 403
    assert res_b.headers.get("X-Error-Code") == "SEPARATION_OF_DUTIES"
    assert "Separation of Duties violation" in res_b.text


def test_07_tenant_a_cannot_authorize_tenant_b_receipt(client):
    """
    Scenario 7: Cross-tenant IDOR defense: Tenant A authorizer cannot authorize
    or access a receipt owned by Tenant B (must return HTTP 404).
    """
    store = get_durable_store()
    receipt_beta = create_test_receipt(store, tenant_id="tenant-corp-beta")

    # Gate A approved by a beta analyst
    token_beta_analyst = make_test_token(
        sub="analyst-beta-user",
        roles=["security:analyst"],
        tenant_id="tenant-corp-beta",
    )
    res_a = client.post(
        "/api/reviews/gate-a/disposition",
        json={"receipt_id": receipt_beta, "disposition": "APPROVED"},
        headers={"Authorization": f"Bearer {token_beta_analyst}"},
    )
    assert res_a.status_code == 201

    # Tenant A authorizer (Carol) tries to authorize Tenant B's receipt
    token_carol = get_token(client, "lead-carol-01", "demo-carol-2026")
    res_b = client.post(
        "/api/reviews/gate-b/authorize",
        json={"receipt_id": receipt_beta},
        headers={"Authorization": f"Bearer {token_carol}"},
    )
    # Anti-enumeration IDOR defense: MUST return 404 Not Found, never 403
    assert res_b.status_code == 404
    assert "Receipt not found" in res_b.text


def test_09_gate_b_github_missing_or_empty_html_url(client):
    """
    Scenario 9: If GitHub returns 200/201 but html_url is missing, null, empty, or not a string,
    proposal must be recorded as PENDING with pr_url is None.
    """
    store = get_durable_store()
    token_alice = get_token(client, "analyst-alice-01", "demo-alice-2026")
    token_carol = get_token(client, "lead-carol-01", "demo-carol-2026")

    invalid_payloads = [
        {"number": 742},  # missing html_url
        {"html_url": None, "number": 742},  # null
        {"html_url": "", "number": 742},  # empty string
        {"html_url": 99999, "number": 742},  # non-string
    ]

    for payload in invalid_payloads:
        receipt_id = create_test_receipt(store)
        client.post(
            "/api/reviews/gate-a/disposition",
            json={"receipt_id": receipt_id, "disposition": "APPROVED"},
            headers={"Authorization": f"Bearer {token_alice}"},
        )

        fake_resp = MagicMock(status_code=201)
        fake_resp.json.return_value = payload

        with patch("app.routers.reviews.get_settings") as mock_settings, \
             patch("httpx.post", return_value=fake_resp):
            mock_settings.return_value = MagicMock(github_token="ghp_live_test_token", github_repo="corp/infra-repo")
            res_b = client.post(
                "/api/reviews/gate-b/authorize",
                json={"receipt_id": receipt_id},
                headers={"Authorization": f"Bearer {token_carol}"},
            )

        assert res_b.status_code == 201
        data = res_b.json()
        assert data["pr_status"] == "PENDING"
        assert data["pr_url"] is None
        assert "lacked a valid https pr url" in data["note"].lower()

        stored = store.get_remediation_proposal(receipt_id, "tenant-corp-alpha")
        assert stored["pr_status"] == "PENDING"
        assert stored["pr_url"] is None


def test_10_gate_b_github_malformed_json_response(client):
    """
    Scenario 10: If GitHub returns 200/201 but response body is malformed JSON,
    proposal must be safely recorded as PENDING with pr_url is None.
    """
    store = get_durable_store()
    receipt_id = create_test_receipt(store)

    token_alice = get_token(client, "analyst-alice-01", "demo-alice-2026")
    client.post(
        "/api/reviews/gate-a/disposition",
        json={"receipt_id": receipt_id, "disposition": "APPROVED"},
        headers={"Authorization": f"Bearer {token_alice}"},
    )

    token_carol = get_token(client, "lead-carol-01", "demo-carol-2026")
    fake_resp = MagicMock(status_code=200)
    fake_resp.json.side_effect = ValueError("Unterminated string starting at line 1")

    with patch("app.routers.reviews.get_settings") as mock_settings, \
         patch("httpx.post", return_value=fake_resp):
        mock_settings.return_value = MagicMock(github_token="ghp_live_test_token", github_repo="corp/infra-repo")
        res_b = client.post(
            "/api/reviews/gate-b/authorize",
            json={"receipt_id": receipt_id},
            headers={"Authorization": f"Bearer {token_carol}"},
        )

    assert res_b.status_code == 201
    data = res_b.json()
    assert data["pr_status"] == "PENDING"
    assert data["pr_url"] is None
    assert "not a valid json object" in data["note"].lower()

    stored = store.get_remediation_proposal(receipt_id, "tenant-corp-alpha")
    assert stored["pr_status"] == "PENDING"
    assert stored["pr_url"] is None


def test_11_gate_b_github_non_dict_payload(client):
    """
    Scenario 11: If GitHub returns 200/201 with a JSON array or scalar instead of a dict,
    proposal must be safely recorded as PENDING with pr_url is None.
    """
    store = get_durable_store()
    token_alice = get_token(client, "analyst-alice-01", "demo-alice-2026")
    token_carol = get_token(client, "lead-carol-01", "demo-carol-2026")

    non_dict_payloads = [
        ["element1", "element2"],
        "raw_string_response",
        12345,
    ]

    for payload in non_dict_payloads:
        receipt_id = create_test_receipt(store)
        client.post(
            "/api/reviews/gate-a/disposition",
            json={"receipt_id": receipt_id, "disposition": "APPROVED"},
            headers={"Authorization": f"Bearer {token_alice}"},
        )

        fake_resp = MagicMock(status_code=200)
        fake_resp.json.return_value = payload

        with patch("app.routers.reviews.get_settings") as mock_settings, \
             patch("httpx.post", return_value=fake_resp):
            mock_settings.return_value = MagicMock(github_token="ghp_live_test_token", github_repo="corp/infra-repo")
            res_b = client.post(
                "/api/reviews/gate-b/authorize",
                json={"receipt_id": receipt_id},
                headers={"Authorization": f"Bearer {token_carol}"},
            )

        assert res_b.status_code == 201
        data = res_b.json()
        assert data["pr_status"] == "PENDING"
        assert data["pr_url"] is None
        assert "not a valid json object" in data["note"].lower()

        stored = store.get_remediation_proposal(receipt_id, "tenant-corp-alpha")
        assert stored["pr_status"] == "PENDING"
        assert stored["pr_url"] is None


def test_12_gate_b_github_rejects_insecure_http_url(client):
    """
    Scenario 12: If GitHub returns a PR URL with http:// instead of https://,
    it must be rejected and recorded as PENDING.
    """
    store = get_durable_store()
    receipt_id = create_test_receipt(store)

    token_alice = get_token(client, "analyst-alice-01", "demo-alice-2026")
    client.post(
        "/api/reviews/gate-a/disposition",
        json={"receipt_id": receipt_id, "disposition": "APPROVED"},
        headers={"Authorization": f"Bearer {token_alice}"},
    )

    token_carol = get_token(client, "lead-carol-01", "demo-carol-2026")
    fake_resp = MagicMock(status_code=201)
    fake_resp.json.return_value = {"html_url": "http://github.com/corp/infra-repo/pull/742"}

    with patch("app.routers.reviews.get_settings") as mock_settings, \
         patch("httpx.post", return_value=fake_resp):
        mock_settings.return_value = MagicMock(github_token="ghp_live_test_token", github_repo="corp/infra-repo")
        res_b = client.post(
            "/api/reviews/gate-b/authorize",
            json={"receipt_id": receipt_id},
            headers={"Authorization": f"Bearer {token_carol}"},
        )

    assert res_b.status_code == 201
    data = res_b.json()
    assert data["pr_status"] == "PENDING"
    assert data["pr_url"] is None
    assert "lacked a valid https pr url" in data["note"].lower()

    stored = store.get_remediation_proposal(receipt_id, "tenant-corp-alpha")
    assert stored["pr_status"] == "PENDING"
    assert stored["pr_url"] is None


def test_13_gate_b_github_rejects_unexpected_host_or_repo(client):
    """
    Scenario 13: If GitHub returns a URL pointing to an unexpected host (e.g. attacker domain)
    or unexpected repository (different org/repo), it must be rejected and recorded as PENDING.
    """
    store = get_durable_store()
    token_alice = get_token(client, "analyst-alice-01", "demo-alice-2026")
    token_carol = get_token(client, "lead-carol-01", "demo-carol-2026")

    invalid_urls = [
        # Non-PR endpoints in the configured repository
        "https://github.com/corp/infra-repo/issues/742",
        "https://github.com/corp/infra-repo/tree/main",
        "https://github.com/corp/infra-repo/commit/4b825dc642cb6eb9a060e54bf8d69288fbee4904",
        # Extra path segments after pull number
        "https://github.com/corp/infra-repo/pull/742/commits",
        "https://github.com/corp/infra-repo/pull/742/files",
        # Different repository
        "https://github.com/attacker-org/foreign-repo/pull/742",
        # Deceptive hostnames
        "https://evil-spoof.com/corp/infra-repo/pull/742",
        "https://github.com.attacker.com/corp/infra-repo/pull/742",
        # Unexpected port, malformed non-integer port, and embedded credentials
        "https://github.com:8080/corp/infra-repo/pull/742",
        "https://github.com:invalid_port/corp/infra-repo/pull/742",
        "https://github.com:999999999999/corp/infra-repo/pull/742",
        "https://user:pass@github.com/corp/infra-repo/pull/742",
        # Malformed or invalid pull request numbers
        "https://github.com/corp/infra-repo/pull/0",
        "https://github.com/corp/infra-repo/pull/-5",
        "https://github.com/corp/infra-repo/pull/abc",
    ]

    for bad_url in invalid_urls:
        receipt_id = create_test_receipt(store)
        client.post(
            "/api/reviews/gate-a/disposition",
            json={"receipt_id": receipt_id, "disposition": "APPROVED"},
            headers={"Authorization": f"Bearer {token_alice}"},
        )

        fake_resp = MagicMock(status_code=201)
        fake_resp.json.return_value = {"html_url": bad_url}

        with patch("app.routers.reviews.get_settings") as mock_settings, \
             patch("httpx.post", return_value=fake_resp):
            mock_settings.return_value = MagicMock(github_token="ghp_live_test_token", github_repo="corp/infra-repo")
            res_b = client.post(
                "/api/reviews/gate-b/authorize",
                json={"receipt_id": receipt_id},
                headers={"Authorization": f"Bearer {token_carol}"},
            )

        assert res_b.status_code == 201
        data = res_b.json()
        assert data["pr_status"] == "PENDING"
        assert data["pr_url"] is None
        assert "lacked a valid https pr url" in data["note"].lower()

        stored = store.get_remediation_proposal(receipt_id, "tenant-corp-alpha")
        assert stored["pr_status"] == "PENDING"
        assert stored["pr_url"] is None


def test_14_stored_status_always_satisfies_database_constraint(client):
    """
    Scenario 14: Verify that every stored remediation proposal in SQLite satisfies
    the database CHECK constraint: pr_status IN ('PENDING','DRAFT','OPEN','MERGED','CLOSED').
    """
    store = get_durable_store()
    allowed_statuses = {"PENDING", "DRAFT", "OPEN", "MERGED", "CLOSED"}

    with store._reader() as conn:
        rows = conn.execute("SELECT proposal_id, receipt_id, pr_status, pr_url FROM remediation_proposals").fetchall()

    assert len(rows) > 0, "Expected at least one remediation proposal to be stored"
    for row in rows:
        proposal = dict(row)
        assert proposal["pr_status"] in allowed_statuses, (
            f"Proposal {proposal['proposal_id']} violated check constraint with status '{proposal['pr_status']}'"
        )
        # If status is PENDING, verify pr_url is None or a valid non-fabricated string
        if proposal["pr_status"] == "PENDING":
            assert proposal["pr_url"] is None, (
                f"Pending proposal {proposal['proposal_id']} unexpectedly carries external URL: {proposal['pr_url']}"
            )
