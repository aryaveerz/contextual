import pytest
import tempfile
from pathlib import Path
from app.storage.durable_store import DurableStore


@pytest.fixture
def store():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_audit.db"
        yield DurableStore(db_path=db_path)


def test_write_and_get_receipt(store):
    store.write_receipt(
        receipt_id="rcpt-01",
        tenant_id="tenant-alpha",
        finding_id="find-01",
        verdict="EXONERATED",
        world_time="2026-01-02T00:00:00Z",
        knowledge_time="2026-01-02T00:00:00Z",
        signals={"p1": False, "p2": True, "p3": True, "p4": 0},
        canonical_sha256="abc123sha",
        hmac_signature="sig456hmac",
    )

    # Scoped retrieval
    r = store.get_receipt("rcpt-01", "tenant-alpha")
    assert r is not None
    assert r["receipt_id"] == "rcpt-01"
    assert r["verdict"] == "EXONERATED"
    assert r["signals"]["p1"] is False
    assert r["canonical_sha256"] == "abc123sha"

    # IDOR Defense: Wrong tenant cannot see receipt
    r_beta = store.get_receipt("rcpt-01", "tenant-beta")
    assert r_beta is None


def test_list_receipts_for_finding(store):
    store.write_receipt(
        receipt_id="rcpt-01",
        tenant_id="tenant-alpha",
        finding_id="find-01",
        verdict="EXONERATED",
        world_time="2026-01-02T00:00:00Z",
        knowledge_time="2026-01-02T00:00:00Z",
        signals={"p1": False},
        canonical_sha256="sha1",
        hmac_signature="sig1",
    )
    store.write_receipt(
        receipt_id="rcpt-02",
        tenant_id="tenant-alpha",
        finding_id="find-01",
        verdict="CULPABLE",
        world_time="2026-01-05T00:00:00Z",
        knowledge_time="2026-01-05T00:00:00Z",
        signals={"p1": True},
        canonical_sha256="sha2",
        hmac_signature="sig2",
    )

    receipts = store.list_receipts_for_finding("find-01", "tenant-alpha")
    assert len(receipts) == 2
    assert receipts[0]["receipt_id"] == "rcpt-01"
    assert receipts[1]["receipt_id"] == "rcpt-02"


def test_gate_a_and_gate_b_flow(store):
    # Setup receipt
    store.write_receipt(
        receipt_id="rcpt-10",
        tenant_id="tenant-alpha",
        finding_id="find-10",
        verdict="CULPABLE",
        world_time="2026-01-05T00:00:00Z",
        knowledge_time="2026-01-05T00:00:00Z",
        signals={"p1": True},
        canonical_sha256="sha10",
        hmac_signature="sig10",
    )

    # Gate A disposition
    store.write_review_disposition(
        disposition_id="disp-01",
        receipt_id="rcpt-10",
        tenant_id="tenant-alpha",
        reviewer_id="reviewer-alice",
        disposition="APPROVED",
        analyst_notes="Confirmed attack path valid",
    )
    d = store.get_review_disposition("rcpt-10", "tenant-alpha")
    assert d is not None
    assert d["reviewer_id"] == "reviewer-alice"
    assert d["disposition"] == "APPROVED"

    # Gate B proposal
    store.write_remediation_proposal(
        proposal_id="prop-01",
        receipt_id="rcpt-10",
        tenant_id="tenant-alpha",
        authorizer_id="lead-bob",
        pr_status="PENDING",
    )
    p = store.get_remediation_proposal("rcpt-10", "tenant-alpha")
    assert p is not None
    assert p["authorizer_id"] == "lead-bob"
    assert p["pr_status"] == "PENDING"
    assert p["pr_url"] is None

    # Update proposal with real PR URL
    store.update_proposal_pr_url("prop-01", "tenant-alpha", "https://github.com/org/repo/pull/42", "OPEN")
    p_updated = store.get_remediation_proposal("rcpt-10", "tenant-alpha")
    assert p_updated["pr_url"] == "https://github.com/org/repo/pull/42"
    assert p_updated["pr_status"] == "OPEN"
