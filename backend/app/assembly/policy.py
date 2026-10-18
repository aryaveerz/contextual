"""
Policy verdict assembly.

Four signals drive the verdict: whether an attack path exists (P1), whether the
acting role is authorized (P2), whether a governing rule is active (P3), and how
many CVEs are open against the finding (P4). The combination maps to one of four
outcome labels: EXONERATED, DEGRADED, CULPABLE, or INDETERMINATE.
"""
from enum import Enum
from typing import Optional


class Verdict(str, Enum):
    EXONERATED = "EXONERATED"
    DEGRADED = "DEGRADED"
    CULPABLE = "CULPABLE"
    INDETERMINATE = "INDETERMINATE"


class VerdictReason(str, Enum):
    """Reason codes that explain what drove the verdict."""
    # EXONERATED reasons
    CERTIFIED_COMPLIANT = "CERTIFIED_COMPLIANT"
    VERIFIED_INTENDED_ARCHITECTURE = "VERIFIED_INTENDED_ARCHITECTURE"
    # DEGRADED reasons
    ISOLATED_VULNERABILITY = "ISOLATED_VULNERABILITY"
    POLICY_EXPIRED = "POLICY_EXPIRED"
    ROLE_UNMAPPED_NO_PATH = "ROLE_UNMAPPED_NO_PATH"
    MULTIPLE_POLICY_MISALIGNMENTS = "MULTIPLE_POLICY_MISALIGNMENTS"
    # CULPABLE reasons
    RULE_GAP_WITH_VULNERABILITY = "RULE_GAP_WITH_VULNERABILITY"
    UNMAPPED_ROLE_WITH_VULNERABILITY = "UNMAPPED_ROLE_WITH_VULNERABILITY"
    UNMANAGED_STATE_WITH_VULNERABILITY = "UNMANAGED_STATE_WITH_VULNERABILITY"
    APPROVED_PATH_WITH_CVE = "APPROVED_PATH_WITH_CVE"
    UNAUTHORIZED_ACTIVE_PATH = "UNAUTHORIZED_ACTIVE_PATH"
    CRITICAL_ATTACK_PATH_WITH_CVE = "CRITICAL_ATTACK_PATH_WITH_CVE"
    SHADOW_PRIVILEGE_ESCALATION = "SHADOW_PRIVILEGE_ESCALATION"
    SHADOW_ROLE_WITH_CVE = "SHADOW_ROLE_WITH_CVE"
    ROGUE_ARCHITECTURE_VECTOR = "ROGUE_ARCHITECTURE_VECTOR"
    CATASTROPHIC_COMPROMISE = "CATASTROPHIC_COMPROMISE"
    # Error
    SIGNAL_ERROR = "SIGNAL_ERROR"


def assemble_verdict(
    p1_path: Optional[bool],
    p2_role: Optional[bool],
    p3_rule: Optional[bool],
    p4_cves: Optional[int],
) -> tuple[Verdict, VerdictReason]:
    """
    Evaluate all four signals and return the matching (Verdict, VerdictReason) pair.
    Returns INDETERMINATE if any signal is None - fail-closed by design.
    """
    # Fail-closed: any missing signal → INDETERMINATE
    if p1_path is None or p2_role is None or p3_rule is None or p4_cves is None:
        return (Verdict.INDETERMINATE, VerdictReason.SIGNAL_ERROR)

    # Invariant: signal types and bounds (Layer 2 invariants)
    # Note: bool is a subclass of int in Python, so isinstance(True, int) is True; check bool explicitly
    if not isinstance(p1_path, bool) or not isinstance(p2_role, bool) or not isinstance(p3_rule, bool):
        return (Verdict.INDETERMINATE, VerdictReason.SIGNAL_ERROR)
    if isinstance(p4_cves, bool) or not isinstance(p4_cves, int) or p4_cves < 0 or p4_cves > 9_007_199_254_740_991:
        return (Verdict.INDETERMINATE, VerdictReason.SIGNAL_ERROR)

    has_cves: bool = p4_cves > 0

    # Walk through every (P1, P2, P3, P4) combination. has_cves collapses P4 to bool.
    # Row  1: F T T 0  → EXONERATED  (certified compliant)
    if not p1_path and p2_role and p3_rule and not has_cves:
        return (Verdict.EXONERATED, VerdictReason.CERTIFIED_COMPLIANT)

    # Row  2: F T T >0 → DEGRADED   (isolated vulnerability, disconnected node)
    if not p1_path and p2_role and p3_rule and has_cves:
        return (Verdict.DEGRADED, VerdictReason.ISOLATED_VULNERABILITY)

    # Row  3: F T F 0  → DEGRADED   (governing policy expired / superseded)
    if not p1_path and p2_role and not p3_rule and not has_cves:
        return (Verdict.DEGRADED, VerdictReason.POLICY_EXPIRED)

    # Row  4: F T F >0 → CULPABLE   (rule gap + vulnerability)
    if not p1_path and p2_role and not p3_rule and has_cves:
        return (Verdict.CULPABLE, VerdictReason.RULE_GAP_WITH_VULNERABILITY)

    # Row  5: F F T 0  → DEGRADED   (role unmapped, no traffic path)
    if not p1_path and not p2_role and p3_rule and not has_cves:
        return (Verdict.DEGRADED, VerdictReason.ROLE_UNMAPPED_NO_PATH)

    # Row  6: F F T >0 → CULPABLE   (unmapped role + active vulnerability)
    if not p1_path and not p2_role and p3_rule and has_cves:
        return (Verdict.CULPABLE, VerdictReason.UNMAPPED_ROLE_WITH_VULNERABILITY)

    # Row  7: F F F 0  → DEGRADED   (multiple policy misalignments)
    if not p1_path and not p2_role and not p3_rule and not has_cves:
        return (Verdict.DEGRADED, VerdictReason.MULTIPLE_POLICY_MISALIGNMENTS)

    # Row  8: F F F >0 → CULPABLE   (unmanaged state + active vulnerability)
    if not p1_path and not p2_role and not p3_rule and has_cves:
        return (Verdict.CULPABLE, VerdictReason.UNMANAGED_STATE_WITH_VULNERABILITY)

    # Row  9: T T T 0  → EXONERATED (verified intended architecture path)
    if p1_path and p2_role and p3_rule and not has_cves:
        return (Verdict.EXONERATED, VerdictReason.VERIFIED_INTENDED_ARCHITECTURE)

    # Row 10: T T T >0 → CULPABLE   (approved path carries active CVE)
    if p1_path and p2_role and p3_rule and has_cves:
        return (Verdict.CULPABLE, VerdictReason.APPROVED_PATH_WITH_CVE)

    # Row 11: T T F 0  → CULPABLE   (traffic path active under expired rule)
    if p1_path and p2_role and not p3_rule and not has_cves:
        return (Verdict.CULPABLE, VerdictReason.UNAUTHORIZED_ACTIVE_PATH)

    # Row 12: T T F >0 → CULPABLE   (critical attack path + CVE)
    if p1_path and p2_role and not p3_rule and has_cves:
        return (Verdict.CULPABLE, VerdictReason.CRITICAL_ATTACK_PATH_WITH_CVE)

    # Row 13: T F T 0  → CULPABLE   (shadow privilege escalation path)
    if p1_path and not p2_role and p3_rule and not has_cves:
        return (Verdict.CULPABLE, VerdictReason.SHADOW_PRIVILEGE_ESCALATION)

    # Row 14: T F T >0 → CULPABLE   (shadow role + CVE → immediate remediation)
    if p1_path and not p2_role and p3_rule and has_cves:
        return (Verdict.CULPABLE, VerdictReason.SHADOW_ROLE_WITH_CVE)

    # Row 15: T F F 0  → CULPABLE   (rogue architecture vector)
    if p1_path and not p2_role and not p3_rule and not has_cves:
        return (Verdict.CULPABLE, VerdictReason.ROGUE_ARCHITECTURE_VECTOR)

    # Row 16: T F F >0 → CULPABLE   (catastrophic compromise state)
    if p1_path and not p2_role and not p3_rule and has_cves:
        return (Verdict.CULPABLE, VerdictReason.CATASTROPHIC_COMPROMISE)

    # Should never reach here - every combination is handled above.
    return (Verdict.INDETERMINATE, VerdictReason.SIGNAL_ERROR)  # pragma: no cover


def format_verdict_result(
    verdict: Verdict,
    reason: VerdictReason,
    p1_path: Optional[bool],
    p2_role: Optional[bool],
    p3_rule: Optional[bool],
    p4_cves: Optional[int],
    blast_radius: Optional[dict] = None,
) -> dict:
    """Serialize verdict + reason + raw signals into the API response shape."""
    signals = {
        "p1_path": p1_path,
        "p2_role": p2_role,
        "p3_rule": p3_rule,
        "p4_cves": p4_cves,
    }
    if blast_radius is not None:
        signals["blast_radius"] = blast_radius

    return {
        "verdict": verdict.value,
        "reason": reason.value,
        "signals": signals,
        "human_review_required": verdict == Verdict.CULPABLE,
    }


# Legacy 2-signal API kept for test compatibility - don't use in new code.
class PolicyDisposition(str, Enum):
    """Legacy 2-signal disposition enum."""
    AUTOMATED_PROPOSAL = "AUTOMATED_PROPOSAL"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
    NO_ACTION = "NO_ACTION"
    INDETERMINATE = "INDETERMINATE"


class DiscrepancyReason(str, Enum):
    """Legacy 2-signal discrepancy reason codes."""
    BOTH_SIGNALS_PRESENT = "BOTH_SIGNALS_PRESENT"
    TOPOLOGY_ONLY_DISCREPANCY = "TOPOLOGY_ONLY_DISCREPANCY"
    RULE_CHANGE_ONLY_DISCREPANCY = "RULE_CHANGE_ONLY_DISCREPANCY"
    EXONERATED = "EXONERATED"
    ERROR = "ERROR"


def assemble_policy_disposition(
    s_topo: Optional[bool],
    s_rule: Optional[bool]
) -> tuple[PolicyDisposition, DiscrepancyReason]:
    """Legacy 2-signal truth table disposition assembly."""
    if s_topo is None or s_rule is None:
        return (PolicyDisposition.INDETERMINATE, DiscrepancyReason.ERROR)

    if s_topo is True and s_rule is True:
        return (PolicyDisposition.AUTOMATED_PROPOSAL, DiscrepancyReason.BOTH_SIGNALS_PRESENT)
    elif s_topo is True and s_rule is False:
        return (PolicyDisposition.HUMAN_REVIEW_REQUIRED, DiscrepancyReason.TOPOLOGY_ONLY_DISCREPANCY)
    elif s_topo is False and s_rule is True:
        return (PolicyDisposition.HUMAN_REVIEW_REQUIRED, DiscrepancyReason.RULE_CHANGE_ONLY_DISCREPANCY)
    else:  # False, False
        return (PolicyDisposition.NO_ACTION, DiscrepancyReason.EXONERATED)


def format_disposition_result(
    disposition: PolicyDisposition,
    reason: DiscrepancyReason,
    s_topo: Optional[bool],
    s_rule: Optional[bool]
) -> dict:
    """Legacy 2-signal format result."""
    return {
        "disposition": disposition.value,
        "reason": reason.value,
        "signals": {
            "s_topo": s_topo,
            "s_rule": s_rule
        },
        "human_review_required": disposition == PolicyDisposition.HUMAN_REVIEW_REQUIRED
    }

