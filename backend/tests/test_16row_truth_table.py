import pytest
from app.assembly.policy import (
    Verdict,
    VerdictReason,
    assemble_verdict,
    format_verdict_result,
)

def test_16_row_matrix_complete_coverage():
    # 16-row policy matrix test cases: (p1_path, p2_role, p3_rule, p4_cves, expected_verdict, expected_reason)
    matrix = [
        # Row 1: F, T, T, 0 -> EXONERATED
        (False, True, True, 0, Verdict.EXONERATED, VerdictReason.CERTIFIED_COMPLIANT),
        # Row 2: F, T, T, >0 -> DEGRADED
        (False, True, True, 2, Verdict.DEGRADED, VerdictReason.ISOLATED_VULNERABILITY),
        # Row 3: F, T, F, 0 -> DEGRADED
        (False, True, False, 0, Verdict.DEGRADED, VerdictReason.POLICY_EXPIRED),
        # Row 4: F, T, F, >0 -> CULPABLE
        (False, True, False, 1, Verdict.CULPABLE, VerdictReason.RULE_GAP_WITH_VULNERABILITY),
        # Row 5: F, F, T, 0 -> DEGRADED
        (False, False, True, 0, Verdict.DEGRADED, VerdictReason.ROLE_UNMAPPED_NO_PATH),
        # Row 6: F, F, T, >0 -> CULPABLE
        (False, False, True, 3, Verdict.CULPABLE, VerdictReason.UNMAPPED_ROLE_WITH_VULNERABILITY),
        # Row 7: F, F, F, 0 -> DEGRADED
        (False, False, False, 0, Verdict.DEGRADED, VerdictReason.MULTIPLE_POLICY_MISALIGNMENTS),
        # Row 8: F, F, F, >0 -> CULPABLE
        (False, False, False, 4, Verdict.CULPABLE, VerdictReason.UNMANAGED_STATE_WITH_VULNERABILITY),
        # Row 9: T, T, T, 0 -> EXONERATED
        (True, True, True, 0, Verdict.EXONERATED, VerdictReason.VERIFIED_INTENDED_ARCHITECTURE),
        # Row 10: T, T, T, >0 -> CULPABLE
        (True, True, True, 1, Verdict.CULPABLE, VerdictReason.APPROVED_PATH_WITH_CVE),
        # Row 11: T, T, F, 0 -> CULPABLE
        (True, True, False, 0, Verdict.CULPABLE, VerdictReason.UNAUTHORIZED_ACTIVE_PATH),
        # Row 12: T, T, F, >0 -> CULPABLE
        (True, True, False, 2, Verdict.CULPABLE, VerdictReason.CRITICAL_ATTACK_PATH_WITH_CVE),
        # Row 13: T, F, T, 0 -> CULPABLE
        (True, False, True, 0, Verdict.CULPABLE, VerdictReason.SHADOW_PRIVILEGE_ESCALATION),
        # Row 14: T, F, T, >0 -> CULPABLE
        (True, False, True, 1, Verdict.CULPABLE, VerdictReason.SHADOW_ROLE_WITH_CVE),
        # Row 15: T, F, F, 0 -> CULPABLE
        (True, False, False, 0, Verdict.CULPABLE, VerdictReason.ROGUE_ARCHITECTURE_VECTOR),
        # Row 16: T, F, F, >0 -> CULPABLE
        (True, False, False, 5, Verdict.CULPABLE, VerdictReason.CATASTROPHIC_COMPROMISE),
    ]

    for p1, p2, p3, p4, exp_verdict, exp_reason in matrix:
        verdict, reason = assemble_verdict(p1, p2, p3, p4)
        assert verdict == exp_verdict, f"Failed for {p1}, {p2}, {p3}, {p4}: got {verdict}, expected {exp_verdict}"
        assert reason == exp_reason, f"Failed reason for {p1}, {p2}, {p3}, {p4}: got {reason}, expected {exp_reason}"


def test_fail_closed_indeterminate():
    none_cases = [
        (None, True, True, 0),
        (True, None, True, 0),
        (True, True, None, 0),
        (True, True, True, None),
        (None, None, None, None),
    ]
    for p1, p2, p3, p4 in none_cases:
        verdict, reason = assemble_verdict(p1, p2, p3, p4)
        assert verdict == Verdict.INDETERMINATE
        assert reason == VerdictReason.SIGNAL_ERROR


def test_format_verdict_result():
    res = format_verdict_result(Verdict.CULPABLE, VerdictReason.APPROVED_PATH_WITH_CVE, True, True, True, 1)
    assert res["verdict"] == "CULPABLE"
    assert res["reason"] == "APPROVED_PATH_WITH_CVE"
    assert res["signals"]["p1_path"] is True
    assert res["signals"]["p4_cves"] == 1
    assert res["human_review_required"] is True
