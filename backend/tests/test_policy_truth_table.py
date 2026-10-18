"""
Unit test suite for policy disposition truth table assembly.

Evaluates 4-disposition assembly logic and fail-closed handling.
"""
import pytest
from app.assembly.policy import (
    PolicyDisposition,
    DiscrepancyReason,
    assemble_policy_disposition,
    format_disposition_result
)


def test_truth_table_row1_both_true():
    """Test: S_topo=True + S_rule=True → AUTOMATED_PROPOSAL"""
    disposition, reason = assemble_policy_disposition(s_topo=True, s_rule=True)
    
    assert disposition == PolicyDisposition.AUTOMATED_PROPOSAL
    assert reason == DiscrepancyReason.BOTH_SIGNALS_PRESENT


def test_truth_table_row2_topo_only():
    """Test: S_topo=True + S_rule=False → HUMAN_REVIEW_REQUIRED (TOPOLOGY_ONLY)"""
    disposition, reason = assemble_policy_disposition(s_topo=True, s_rule=False)
    
    assert disposition == PolicyDisposition.HUMAN_REVIEW_REQUIRED
    assert reason == DiscrepancyReason.TOPOLOGY_ONLY_DISCREPANCY


def test_truth_table_row3_rule_only():
    """Test: S_topo=False + S_rule=True → HUMAN_REVIEW_REQUIRED (RULE_CHANGE_ONLY)"""
    disposition, reason = assemble_policy_disposition(s_topo=False, s_rule=True)
    
    assert disposition == PolicyDisposition.HUMAN_REVIEW_REQUIRED
    assert reason == DiscrepancyReason.RULE_CHANGE_ONLY_DISCREPANCY


def test_truth_table_row4_both_false():
    """Test: S_topo=False + S_rule=False → NO_ACTION (EXONERATED)"""
    disposition, reason = assemble_policy_disposition(s_topo=False, s_rule=False)
    
    assert disposition == PolicyDisposition.NO_ACTION
    assert reason == DiscrepancyReason.EXONERATED


def test_truth_table_none_topo():
    """Test: S_topo=None (error) → INDETERMINATE"""
    disposition, reason = assemble_policy_disposition(s_topo=None, s_rule=True)
    
    assert disposition == PolicyDisposition.INDETERMINATE
    assert reason == DiscrepancyReason.ERROR


def test_truth_table_none_rule():
    """Test: S_rule=None (error) → INDETERMINATE"""
    disposition, reason = assemble_policy_disposition(s_topo=True, s_rule=None)
    
    assert disposition == PolicyDisposition.INDETERMINATE
    assert reason == DiscrepancyReason.ERROR


def test_truth_table_both_none():
    """Test: S_topo=None + S_rule=None (both error) → INDETERMINATE"""
    disposition, reason = assemble_policy_disposition(s_topo=None, s_rule=None)
    
    assert disposition == PolicyDisposition.INDETERMINATE
    assert reason == DiscrepancyReason.ERROR


def test_format_disposition_result():
    """Test disposition result formatting."""
    disposition = PolicyDisposition.HUMAN_REVIEW_REQUIRED
    reason = DiscrepancyReason.TOPOLOGY_ONLY_DISCREPANCY
    
    result = format_disposition_result(disposition, reason, s_topo=True, s_rule=False)
    
    assert result["disposition"] == "HUMAN_REVIEW_REQUIRED"
    assert result["reason"] == "TOPOLOGY_ONLY_DISCREPANCY"
    assert result["signals"]["s_topo"] is True
    assert result["signals"]["s_rule"] is False
    assert result["human_review_required"] is True


def test_format_no_action_result():
    """Test NO_ACTION disposition formatting."""
    disposition = PolicyDisposition.NO_ACTION
    reason = DiscrepancyReason.EXONERATED
    
    result = format_disposition_result(disposition, reason, s_topo=False, s_rule=False)
    
    assert result["disposition"] == "NO_ACTION"
    assert result["reason"] == "EXONERATED"
    assert result["human_review_required"] is False


def test_complete_truth_table_coverage():
    """Test all 16 possible combinations (including None values)."""
    test_cases = [
        # (s_topo, s_rule, expected_disposition, expected_reason)
        (True, True, PolicyDisposition.AUTOMATED_PROPOSAL, DiscrepancyReason.BOTH_SIGNALS_PRESENT),
        (True, False, PolicyDisposition.HUMAN_REVIEW_REQUIRED, DiscrepancyReason.TOPOLOGY_ONLY_DISCREPANCY),
        (False, True, PolicyDisposition.HUMAN_REVIEW_REQUIRED, DiscrepancyReason.RULE_CHANGE_ONLY_DISCREPANCY),
        (False, False, PolicyDisposition.NO_ACTION, DiscrepancyReason.EXONERATED),
        (None, True, PolicyDisposition.INDETERMINATE, DiscrepancyReason.ERROR),
        (None, False, PolicyDisposition.INDETERMINATE, DiscrepancyReason.ERROR),
        (True, None, PolicyDisposition.INDETERMINATE, DiscrepancyReason.ERROR),
        (False, None, PolicyDisposition.INDETERMINATE, DiscrepancyReason.ERROR),
        (None, None, PolicyDisposition.INDETERMINATE, DiscrepancyReason.ERROR),
    ]
    
    for s_topo, s_rule, expected_disp, expected_reason in test_cases:
        disposition, reason = assemble_policy_disposition(s_topo, s_rule)
        assert disposition == expected_disp, f"Failed for s_topo={s_topo}, s_rule={s_rule}"
        assert reason == expected_reason, f"Failed reason for s_topo={s_topo}, s_rule={s_rule}"
