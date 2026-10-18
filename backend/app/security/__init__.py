"""
Cryptographic signing utilities: RFC 8785 canonicalization, SHA-256 digests, HMAC receipts.
"""
from .rfc8785_canonicalizer import (
    canonicalize_json,
    compute_sha256_digest,
    compute_hmac_signature,
    create_signed_receipt,
    verify_receipt
)

__all__ = [
    "canonicalize_json",
    "compute_sha256_digest",
    "compute_hmac_signature",
    "create_signed_receipt",
    "verify_receipt"
]
