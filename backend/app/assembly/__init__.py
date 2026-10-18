"""
Policy assembly engine and Layer 2 invariant validators.
"""
from .policy import (
    Verdict,
    VerdictReason,
    assemble_verdict,
    format_verdict_result,
    PolicyDisposition,
    DiscrepancyReason,
    assemble_policy_disposition,
    format_disposition_result,
)

__all__ = [
    # Primary canonical names
    "Verdict",
    "VerdictReason",
    "assemble_verdict",
    "format_verdict_result",
    # Backward compatibility
    "PolicyDisposition",
    "DiscrepancyReason",
    "assemble_policy_disposition",
    "format_disposition_result",
]
