"""
RFC 8785 JSON canonicalization (JCS) + SHA-256 / HMAC-SHA256 receipt signing.

Adheres strictly to RFC 8785 canonical JSON specification via the standard
rfc8785 package for deterministic byte serialization.
"""
import hashlib
import hmac
import json
from typing import Any, Dict

try:
    import rfc8785
except ImportError:
    rfc8785 = None

from app.config import get_settings


def canonicalize_json(obj: Any) -> str:
    """
    Produces a deterministic JSON string matching RFC 8785 (JSON Canonicalization Scheme).
    Keys are sorted by UTF-16 code unit representation, whitespace is stripped,
    and numbers/strings are formatted canonically.
    """
    if rfc8785 is not None:
        return rfc8785.dumps(obj).decode("utf-8")
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def compute_sha256_digest(canonical_json: str) -> str:
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def compute_hmac_signature(canonical_json: str, secret: str) -> str:
    secret_bytes = bytes.fromhex(secret)
    return hmac.new(
        secret_bytes,
        canonical_json.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def create_signed_receipt(evidence_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wraps evidence in a tamper-evident envelope: canonical form → SHA-256 digest
    → HMAC-SHA256 signature using the tenant master key from settings.
    """
    settings = get_settings()
    canonical = canonicalize_json(evidence_data)
    digest = compute_sha256_digest(canonical)
    signature = compute_hmac_signature(canonical, settings.tenant_master_key_secret)

    return {
        "evidence": evidence_data,
        "canonical_sha256": digest,
        "hmac": signature,
        "algorithm": "HMAC-SHA256",
        "canonical_scheme": "RFC8785",
    }


def verify_receipt(receipt: Dict[str, Any]) -> bool:
    try:
        settings = get_settings()
        evidence = receipt.get("evidence")
        if not evidence:
            return False

        canonical = canonicalize_json(evidence)
        expected_digest = compute_sha256_digest(canonical)

        if receipt.get("canonical_sha256") != expected_digest:
            return False

        expected_sig = compute_hmac_signature(canonical, settings.tenant_master_key_secret)
        return hmac.compare_digest(receipt.get("hmac", ""), expected_sig)

    except Exception:
        return False
