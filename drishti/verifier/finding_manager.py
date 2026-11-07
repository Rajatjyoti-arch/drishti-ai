"""Finding Lifecycle Manager for Drishti AI.

Implements an audit-tracked finite state machine governing travel security findings:
  CANDIDATE -> VERIFYING -> CONFIRMED -> RETEST_REQUIRED -> VERIFYING -> FIXED / REOPENED
"""

import logging
from typing import Dict, List, Optional

from drishti.core.models import VerifiedFinding
from drishti.verifier.models import FindingLifecycleState, LifecycleTransition

logger = logging.getLogger(__name__)

# Valid state machine transitions
ALLOWED_TRANSITIONS = {
    FindingLifecycleState.CANDIDATE: {
        FindingLifecycleState.VERIFYING,
    },
    FindingLifecycleState.VERIFYING: {
        FindingLifecycleState.CONFIRMED,
        FindingLifecycleState.NOT_REPRODUCED,
        FindingLifecycleState.INCONCLUSIVE,
        FindingLifecycleState.FIXED,
        FindingLifecycleState.REOPENED,
    },
    FindingLifecycleState.CONFIRMED: {
        FindingLifecycleState.RETEST_REQUIRED,
    },
    FindingLifecycleState.RETEST_REQUIRED: {
        FindingLifecycleState.VERIFYING,
    },
    FindingLifecycleState.FIXED: {
        FindingLifecycleState.REOPENED,  # Regression
        FindingLifecycleState.RETEST_REQUIRED,
    },
    FindingLifecycleState.REOPENED: {
        FindingLifecycleState.RETEST_REQUIRED,
        FindingLifecycleState.VERIFYING,
    },
    FindingLifecycleState.NOT_REPRODUCED: {
        FindingLifecycleState.VERIFYING,
    },
    FindingLifecycleState.INCONCLUSIVE: {
        FindingLifecycleState.VERIFYING,
    },
}


class FindingLifecycleManager:
    """Manages finding lifecycles with transition validation and audit trails."""

    def __init__(self):
        self._findings: Dict[str, VerifiedFinding] = {}
        self._states: Dict[str, FindingLifecycleState] = {}
        self._history: Dict[str, List[LifecycleTransition]] = {}

    def register_finding(
        self,
        finding: VerifiedFinding,
        initial_state: FindingLifecycleState = FindingLifecycleState.CONFIRMED,
    ) -> None:
        """Registers a finding into the lifecycle manager."""
        fid = finding.finding_id
        self._findings[fid] = finding
        self._states[fid] = initial_state
        if fid not in self._history:
            self._history[fid] = []

        initial_transition = LifecycleTransition(
            finding_id=fid,
            from_state=initial_state,
            to_state=initial_state,
            reason="Initial finding registration",
            actor="VerificationOracle",
        )
        self._history[fid].append(initial_transition)
        logger.info(f"Registered finding '{fid}' in state {initial_state.value}.")

    def transition_state(
        self,
        finding_id: str,
        new_state: FindingLifecycleState,
        reason: str,
        actor: str = "VerificationOracle",
        evidence_ref: Optional[str] = None,
    ) -> LifecycleTransition:
        """Transitions a finding to a new lifecycle state if allowed by the state machine."""
        if finding_id not in self._states:
            raise KeyError(f"Finding '{finding_id}' is not registered in the lifecycle manager.")

        current_state = self._states[finding_id]
        allowed = ALLOWED_TRANSITIONS.get(current_state, set())

        if new_state not in allowed:
            raise ValueError(
                f"Invalid lifecycle transition for finding '{finding_id}': "
                f"cannot transition from {current_state.value} to {new_state.value}. "
                f"Allowed target states: {[s.value for s in allowed]}."
            )

        self._states[finding_id] = new_state
        transition = LifecycleTransition(
            finding_id=finding_id,
            from_state=current_state,
            to_state=new_state,
            reason=reason,
            actor=actor,
            evidence_ref=evidence_ref,
        )
        self._history[finding_id].append(transition)
        logger.info(
            f"Finding '{finding_id}' transitioned from {current_state.value} to "
            f"{new_state.value} (Actor: {actor}, Reason: {reason})."
        )
        return transition

    def get_state(self, finding_id: str) -> FindingLifecycleState:
        """Returns the current state of a registered finding."""
        if finding_id not in self._states:
            raise KeyError(f"Finding '{finding_id}' is not registered.")
        return self._states[finding_id]

    def get_finding(self, finding_id: str) -> Optional[VerifiedFinding]:
        """Retrieves finding details by ID."""
        return self._findings.get(finding_id)

    def get_history(self, finding_id: str) -> List[LifecycleTransition]:
        """Returns the complete audit transition history for a finding."""
        return list(self._history.get(finding_id, []))

    def list_findings(
        self,
        state: Optional[FindingLifecycleState] = None,
    ) -> List[VerifiedFinding]:
        """Lists registered findings, optionally filtered by lifecycle state."""
        if state is None:
            return list(self._findings.values())
        return [
            f
            for fid, f in self._findings.items()
            if self._states.get(fid) == state
        ]
