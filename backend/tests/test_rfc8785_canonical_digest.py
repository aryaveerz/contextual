"""
Unit test suite for RFC 8785 canonical JSON digest and HMAC signature generation.
"""
import pytest
from app.security.rfc8785_canonicalizer import (
    canonicalize_json,
    compute_sha256_digest,
    compute_hmac_signature,
    create_signed_receipt,
    verify_receipt
)


def test_canonical_json_key_sorting():
    """Test RFC8785 key sorting by Unicode code point."""
    data = {
        "zebra": 1,
        "alpha": 2,
        "Beta": 3,
        "123": 4
    }
    
    canonical = canonicalize_json(data)
    
    # RFC8785: Keys sorted by Unicode code point
    # Order should be: "123", "Beta", "alpha", "zebra"
    assert canonical == '{"123":4,"Beta":3,"alpha":2,"zebra":1}'


def test_canonical_json_no_whitespace():
    """Test RFC8785 removes insignificant whitespace."""
    data = {"key": "value", "nested": {"inner": 123}}
    
    canonical = canonicalize_json(data)
    
    # No spaces after colons or commas
    assert ' ' not in canonical
    assert canonical == '{"key":"value","nested":{"inner":123}}'


def test_sha256_digest_deterministic():
    """Test SHA-256 digest is deterministic."""
    data = {"finding_id": "finding-01", "disposition": "EXONERATED"}
    
    canonical = canonicalize_json(data)
    digest1 = compute_sha256_digest(canonical)
    digest2 = compute_sha256_digest(canonical)
    
    # Same input produces same digest
    assert digest1 == digest2
    assert len(digest1) == 64  # SHA-256 hex = 64 chars


def test_hmac_signature_deterministic():
    """Test HMAC-SHA256 signature is deterministic."""
    canonical = '{"finding_id":"finding-01"}'
    secret = "a" * 64  # 64-char hex secret
    
    sig1 = compute_hmac_signature(canonical, secret)
    sig2 = compute_hmac_signature(canonical, secret)
    
    # Same input + secret produces same signature
    assert sig1 == sig2
    assert len(sig1) == 64  # HMAC-SHA256 hex = 64 chars


def test_create_signed_receipt():
    """Test signed receipt creation."""
    evidence = {
        "finding_id": "finding-01",
        "disposition": "HUMAN_REVIEW_REQUIRED",
        "timestamp": "2026-01-05T00:00:00Z"
    }
    
    receipt = create_signed_receipt(evidence)
    
    # Verify receipt structure
    assert "evidence" in receipt
    assert "canonical_sha256" in receipt
    assert "hmac" in receipt
    assert "algorithm" in receipt
    assert "canonical_scheme" in receipt
    
    assert receipt["evidence"] == evidence
    assert receipt["algorithm"] == "HMAC-SHA256"
    assert receipt["canonical_scheme"] == "RFC8785"
    assert len(receipt["canonical_sha256"]) == 64
    assert len(receipt["hmac"]) == 64


def test_verify_receipt_valid():
    """Test valid receipt verification."""
    evidence = {
        "finding_id": "finding-01",
        "disposition": "NO_ACTION"
    }
    
    receipt = create_signed_receipt(evidence)
    
    # Valid receipt should verify
    assert verify_receipt(receipt) is True


def test_verify_receipt_tampered_evidence():
    """Test tampering detection - modified evidence."""
    evidence = {
        "finding_id": "finding-01",
        "disposition": "NO_ACTION"
    }
    
    receipt = create_signed_receipt(evidence)
    
    # Tamper with evidence
    receipt["evidence"]["disposition"] = "AUTOMATED_PROPOSAL"
    
    # Tampered receipt should fail verification
    assert verify_receipt(receipt) is False


def test_verify_receipt_tampered_digest():
    """Test tampering detection - modified digest."""
    evidence = {
        "finding_id": "finding-01",
        "disposition": "NO_ACTION"
    }
    
    receipt = create_signed_receipt(evidence)
    
    # Tamper with digest
    receipt["canonical_sha256"] = "0" * 64
    
    # Tampered receipt should fail verification
    assert verify_receipt(receipt) is False


def test_verify_receipt_tampered_signature():
    """Test tampering detection - modified signature."""
    evidence = {
        "finding_id": "finding-01",
        "disposition": "NO_ACTION"
    }
    
    receipt = create_signed_receipt(evidence)
    
    # Tamper with signature
    receipt["hmac"] = "f" * 64
    
    # Tampered receipt should fail verification
    assert verify_receipt(receipt) is False


def test_different_evidence_different_digest():
    """Test different evidence produces different digest."""
    evidence1 = {"finding_id": "finding-01", "disposition": "NO_ACTION"}
    evidence2 = {"finding_id": "finding-02", "disposition": "NO_ACTION"}
    
    receipt1 = create_signed_receipt(evidence1)
    receipt2 = create_signed_receipt(evidence2)
    
    # Different evidence should produce different digests
    assert receipt1["canonical_sha256"] != receipt2["canonical_sha256"]
    assert receipt1["hmac"] != receipt2["hmac"]


def test_timestamp_change_invalidates_receipt():
    """Test even 1ms timestamp change invalidates receipt."""
    evidence = {
        "finding_id": "finding-01",
        "timestamp": "2026-01-05T00:00:00.000Z"
    }
    
    receipt = create_signed_receipt(evidence)
    
    # Change timestamp by 1 millisecond
    receipt["evidence"]["timestamp"] = "2026-01-05T00:00:00.001Z"
    
    # Should fail verification
    assert verify_receipt(receipt) is False
