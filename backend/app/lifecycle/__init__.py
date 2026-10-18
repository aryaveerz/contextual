"""
Investigation lifecycle: fail-closed 8-state machine.
"""
from .state_machine import (
    LifecycleState,
    TransitionError,
    InvestigationStateMachine,
    restore_state_machine,
    VALID_TRANSITIONS,
)

__all__ = [
    "LifecycleState",
    "TransitionError",
    "InvestigationStateMachine",
    "restore_state_machine",
    "VALID_TRANSITIONS",
]
