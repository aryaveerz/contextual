import pytest
from app.lifecycle.state_machine import (
    LifecycleState,
    InvestigationStateMachine,
    TransitionError,
    restore_state_machine,
)


def test_linear_lifecycle_happy_path():
    sm = InvestigationStateMachine()
    assert sm.state == LifecycleState.RECEIPT_CREATED
    assert not sm.is_terminal

    # Transition 1: RECEIPT_CREATED -> GATE_A_PENDING
    sm.transition(LifecycleState.GATE_A_PENDING)
    assert sm.state == LifecycleState.GATE_A_PENDING

    # Transition 2: GATE_A_PENDING -> GATE_A_APPROVED
    sm.transition(LifecycleState.GATE_A_APPROVED)
    assert sm.state == LifecycleState.GATE_A_APPROVED

    # Transition 3: GATE_A_APPROVED -> PROPOSAL_DRAFTED
    sm.transition(LifecycleState.PROPOSAL_DRAFTED)
    assert sm.state == LifecycleState.PROPOSAL_DRAFTED

    # Transition 4: PROPOSAL_DRAFTED -> GATE_B_PENDING
    sm.transition(LifecycleState.GATE_B_PENDING)
    assert sm.state == LifecycleState.GATE_B_PENDING

    # Transition 5: GATE_B_PENDING -> GATE_B_APPROVED
    sm.transition(LifecycleState.GATE_B_APPROVED)
    assert sm.state == LifecycleState.GATE_B_APPROVED

    # Transition 6: GATE_B_APPROVED -> EXECUTION_AUTHORIZED
    sm.transition(LifecycleState.EXECUTION_AUTHORIZED)
    assert sm.state == LifecycleState.EXECUTION_AUTHORIZED

    # Transition 7: EXECUTION_AUTHORIZED -> AUDIT_ARCHIVED
    sm.transition(LifecycleState.AUDIT_ARCHIVED)
    assert sm.state == LifecycleState.AUDIT_ARCHIVED
    assert sm.is_terminal


def test_gate_rejection_paths():
    # Gate A rejection is terminal
    sm_a = InvestigationStateMachine()
    sm_a.transition(LifecycleState.GATE_A_PENDING)
    sm_a.transition(LifecycleState.GATE_A_REJECTED)
    assert sm_a.state == LifecycleState.GATE_A_REJECTED
    assert sm_a.is_terminal
    with pytest.raises(TransitionError):
        sm_a.transition(LifecycleState.PROPOSAL_DRAFTED)

    # Gate B rejection is terminal
    sm_b = InvestigationStateMachine()
    sm_b.transition(LifecycleState.GATE_A_PENDING)
    sm_b.transition(LifecycleState.GATE_A_APPROVED)
    sm_b.transition(LifecycleState.PROPOSAL_DRAFTED)
    sm_b.transition(LifecycleState.GATE_B_PENDING)
    sm_b.transition(LifecycleState.GATE_B_REJECTED)
    assert sm_b.state == LifecycleState.GATE_B_REJECTED
    assert sm_b.is_terminal


def test_illegal_shortcuts_fail_closed():
    sm = InvestigationStateMachine()
    # Illegal direct jump: RECEIPT_CREATED -> EXECUTION_AUTHORIZED
    with pytest.raises(TransitionError) as excinfo:
        sm.transition(LifecycleState.EXECUTION_AUTHORIZED)
    assert "Forbidden transition" in str(excinfo.value)

    # Illegal direct jump: RECEIPT_CREATED -> GATE_B_PENDING
    with pytest.raises(TransitionError):
        sm.transition(LifecycleState.GATE_B_PENDING)


def test_restore_state_machine():
    restored = restore_state_machine("GATE_B_PENDING")
    assert restored.state == LifecycleState.GATE_B_PENDING
    restored.transition(LifecycleState.GATE_B_APPROVED)
    assert restored.state == LifecycleState.GATE_B_APPROVED


def test_invalid_state_restore():
    with pytest.raises(ValueError) as exc:
        restore_state_machine("INVALID_STATE_XYZ")
    assert "Unknown lifecycle state" in str(exc.value)
