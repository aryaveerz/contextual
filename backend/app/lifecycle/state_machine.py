"""
Investigation lifecycle state machine: 8 states, fail-closed transitions.

The path is linear: no shortcuts, no skipping gates. Any attempt to jump
directly from e.g. RECEIPT_CREATED to EXECUTION_AUTHORIZED raises TransitionError.
Role-based access checks are the caller's responsibility; this module only
enforces sequence ordering.

    RECEIPT_CREATED -> GATE_A_PENDING -> GATE_A_APPROVED / GATE_A_REJECTED
    GATE_A_APPROVED -> PROPOSAL_DRAFTED -> GATE_B_PENDING
    GATE_B_PENDING  -> GATE_B_APPROVED / GATE_B_REJECTED
    GATE_B_APPROVED -> EXECUTION_AUTHORIZED -> AUDIT_ARCHIVED
"""
from enum import Enum
from typing import FrozenSet, Set


class LifecycleState(str, Enum):
    """Eight canonical lifecycle states for an investigation."""
    RECEIPT_CREATED      = "RECEIPT_CREATED"
    GATE_A_PENDING       = "GATE_A_PENDING"
    GATE_A_APPROVED      = "GATE_A_APPROVED"
    GATE_A_REJECTED      = "GATE_A_REJECTED"
    PROPOSAL_DRAFTED     = "PROPOSAL_DRAFTED"
    GATE_B_PENDING       = "GATE_B_PENDING"
    GATE_B_APPROVED      = "GATE_B_APPROVED"
    GATE_B_REJECTED      = "GATE_B_REJECTED"
    EXECUTION_AUTHORIZED = "EXECUTION_AUTHORIZED"
    AUDIT_ARCHIVED       = "AUDIT_ARCHIVED"


class TransitionError(Exception):
    """Raised when a forbidden state transition is attempted."""
    def __init__(self, from_state: LifecycleState, to_state: LifecycleState):
        self.from_state = from_state
        self.to_state = to_state
        super().__init__(
            f"Forbidden transition: {from_state.value} -> {to_state.value}. "
            f"Valid next states: {[s.value for s in VALID_TRANSITIONS.get(from_state, set())]}"
        )


# Transition adjacency map: anything not listed as a successor is forbidden.
VALID_TRANSITIONS: dict[LifecycleState, FrozenSet[LifecycleState]] = {
    LifecycleState.RECEIPT_CREATED: frozenset({
        LifecycleState.GATE_A_PENDING,
    }),
    LifecycleState.GATE_A_PENDING: frozenset({
        LifecycleState.GATE_A_APPROVED,
        LifecycleState.GATE_A_REJECTED,
    }),
    LifecycleState.GATE_A_APPROVED: frozenset({
        LifecycleState.PROPOSAL_DRAFTED,
    }),
    LifecycleState.GATE_A_REJECTED: frozenset(),    # terminal: requires re-investigation
    LifecycleState.PROPOSAL_DRAFTED: frozenset({
        LifecycleState.GATE_B_PENDING,
    }),
    LifecycleState.GATE_B_PENDING: frozenset({
        LifecycleState.GATE_B_APPROVED,
        LifecycleState.GATE_B_REJECTED,
    }),
    LifecycleState.GATE_B_APPROVED: frozenset({
        LifecycleState.EXECUTION_AUTHORIZED,
    }),
    LifecycleState.GATE_B_REJECTED: frozenset(),    # terminal: returns to proposal drafting
    LifecycleState.EXECUTION_AUTHORIZED: frozenset({
        LifecycleState.AUDIT_ARCHIVED,
    }),
    LifecycleState.AUDIT_ARCHIVED: frozenset(),     # terminal: immutable audit record
}


# State machine implementation

class InvestigationStateMachine:
    """
    Fail-closed investigation lifecycle state machine.

    Usage:
        sm = InvestigationStateMachine(current_state=LifecycleState.RECEIPT_CREATED)
        sm.transition(LifecycleState.GATE_A_PENDING)   # OK
        sm.transition(LifecycleState.AUDIT_ARCHIVED)   # raises TransitionError
    """

    def __init__(self, current_state: LifecycleState = LifecycleState.RECEIPT_CREATED):
        self._state = current_state

    @property
    def state(self) -> LifecycleState:
        """Return the current lifecycle state."""
        return self._state

    @property
    def valid_next_states(self) -> FrozenSet[LifecycleState]:
        """Return the set of states reachable from the current state."""
        return VALID_TRANSITIONS.get(self._state, frozenset())

    @property
    def is_terminal(self) -> bool:
        """True if no further transitions are possible."""
        return len(self.valid_next_states) == 0

    def can_transition(self, target: LifecycleState) -> bool:
        """Non-throwing check: is the transition from current state to target allowed?"""
        return target in self.valid_next_states

    def transition(self, target: LifecycleState) -> LifecycleState:
        """
        Perform a state transition.

        Raises:
            TransitionError: If the transition is not in VALID_TRANSITIONS.

        Returns:
            The new current state.
        """
        if not self.can_transition(target):
            raise TransitionError(self._state, target)
        self._state = target
        return self._state

    def to_dict(self) -> dict:
        """Serialize state machine snapshot for API response."""
        return {
            "current_state": self._state.value,
            "valid_next_states": [s.value for s in self.valid_next_states],
            "is_terminal": self.is_terminal,
        }


# Convenience factory

def restore_state_machine(stored_state: str) -> InvestigationStateMachine:
    """
    Reconstruct a state machine from a persisted state string.

    Args:
        stored_state: The string value of a LifecycleState enum member.

    Returns:
        InvestigationStateMachine positioned at the stored state.

    Raises:
        ValueError: If stored_state is not a valid LifecycleState.
    """
    try:
        state = LifecycleState(stored_state)
    except ValueError:
        raise ValueError(
            f"Unknown lifecycle state: '{stored_state}'. "
            f"Valid states: {[s.value for s in LifecycleState]}"
        )
    return InvestigationStateMachine(current_state=state)
