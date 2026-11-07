"""Finding Lifecycle Manager for Drishti AI.

Implements an audit-tracked, durable finite state machine governing travel security findings:
  CANDIDATE -> VERIFYING -> CONFIRMED -> RETEST_REQUIRED -> VERIFYING -> FIXED / REOPENED

Features:
- Durable SQLite audit persistence surviving process restarts.
- Idempotent finding registration protecting existing findings from overwrite.
- Append-only transition history with cryptographic evidence references.
- Validated state machine transitions preventing illegal state jumps.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sqlite3
import threading
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
    """Manages finding lifecycles with transition validation and SQLite audit durability."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or Path(".drishti_lifecycle.db")
        self._lock = threading.Lock()
        self._findings: Dict[str, VerifiedFinding] = {}
        self._states: Dict[str, FindingLifecycleState] = {}
        self._history: Dict[str, List[LifecycleTransition]] = {}

        self._init_db()
        self._load_from_db()

    def _init_db(self) -> None:
        """Initializes SQLite schema for findings and lifecycle transitions."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS finding_records (
                        finding_id TEXT PRIMARY KEY,
                        invariant_id TEXT NOT NULL,
                        current_state TEXT NOT NULL,
                        finding_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS lifecycle_transitions (
                        transition_id TEXT PRIMARY KEY,
                        finding_id TEXT NOT NULL,
                        from_state TEXT NOT NULL,
                        to_state TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        evidence_ref TEXT
                    );
                """)
                conn.commit()

    def _load_from_db(self) -> None:
        """Recovers findings, current states, and complete transition history from SQLite."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT finding_id, current_state, finding_json FROM finding_records"
                )
                for fid, state_str, fjson in cursor.fetchall():
                    try:
                        self._states[fid] = FindingLifecycleState(state_str)
                        self._findings[fid] = VerifiedFinding.model_validate_json(fjson)
                        self._history[fid] = []
                    except Exception as e:
                        logger.error(f"Failed to load finding '{fid}' from database: {e}")

                cursor.execute(
                    "SELECT transition_id, finding_id, from_state, to_state, timestamp, actor, reason, evidence_ref "
                    "FROM lifecycle_transitions ORDER BY rowid ASC"
                )
                for tid, fid, f_state, t_state, ts, actor, reason, ev_ref in cursor.fetchall():
                    if fid not in self._history:
                        self._history[fid] = []
                    tr = LifecycleTransition(
                        transition_id=tid,
                        finding_id=fid,
                        from_state=FindingLifecycleState(f_state),
                        to_state=FindingLifecycleState(t_state),
                        timestamp=ts,
                        actor=actor,
                        reason=reason,
                        evidence_ref=ev_ref,
                    )
                    self._history[fid].append(tr)

    def register_finding(
        self,
        finding: VerifiedFinding,
        initial_state: FindingLifecycleState = FindingLifecycleState.CONFIRMED,
    ) -> None:
        """Registers a finding into the lifecycle manager.

        IDEMPOTENT: If the finding ID is already registered, keeps existing state and history
        rather than overwriting it.
        """
        fid = finding.finding_id
        with self._lock:
            if fid in self._findings:
                logger.info(
                    f"Finding '{fid}' is already registered in state {self._states[fid].value}; "
                    f"preserving existing finding and audit history."
                )
                return

            now = datetime.now(timezone.utc).isoformat()
            self._findings[fid] = finding
            self._states[fid] = initial_state
            self._history[fid] = []

            initial_transition = LifecycleTransition(
                finding_id=fid,
                from_state=initial_state,
                to_state=initial_state,
                reason="Initial finding registration",
                actor="VerificationOracle",
                evidence_ref=finding.request_evidence_hash,
            )
            self._history[fid].append(initial_transition)

            # Persist to SQLite
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO finding_records 
                    (finding_id, invariant_id, current_state, finding_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        fid,
                        finding.invariant_id.value,
                        initial_state.value,
                        finding.model_dump_json(),
                        now,
                        now,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO lifecycle_transitions 
                    (transition_id, finding_id, from_state, to_state, timestamp, actor, reason, evidence_ref)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        initial_transition.transition_id,
                        fid,
                        initial_transition.from_state.value,
                        initial_transition.to_state.value,
                        initial_transition.timestamp,
                        initial_transition.actor,
                        initial_transition.reason,
                        initial_transition.evidence_ref,
                    ),
                )
                conn.commit()

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
        with self._lock:
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

            now = datetime.now(timezone.utc).isoformat()
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

            # Persist update to SQLite
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "UPDATE finding_records SET current_state = ?, updated_at = ? WHERE finding_id = ?",
                    (new_state.value, now, finding_id),
                )
                conn.execute(
                    """
                    INSERT INTO lifecycle_transitions 
                    (transition_id, finding_id, from_state, to_state, timestamp, actor, reason, evidence_ref)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        transition.transition_id,
                        finding_id,
                        transition.from_state.value,
                        transition.to_state.value,
                        transition.timestamp,
                        transition.actor,
                        transition.reason,
                        transition.evidence_ref,
                    ),
                )
                conn.commit()

        logger.info(
            f"Finding '{finding_id}' transitioned from {current_state.value} to "
            f"{new_state.value} (Actor: {actor}, Reason: {reason})."
        )
        return transition

    def get_state(self, finding_id: str) -> FindingLifecycleState:
        """Returns the current state of a registered finding."""
        with self._lock:
            if finding_id not in self._states:
                raise KeyError(f"Finding '{finding_id}' is not registered.")
            return self._states[finding_id]

    def get_finding(self, finding_id: str) -> Optional[VerifiedFinding]:
        """Retrieves finding details by ID."""
        with self._lock:
            return self._findings.get(finding_id)

    def get_history(self, finding_id: str) -> List[LifecycleTransition]:
        """Returns the complete audit transition history for a finding."""
        with self._lock:
            return list(self._history.get(finding_id, []))

    def list_findings(
        self,
        state: Optional[FindingLifecycleState] = None,
    ) -> List[VerifiedFinding]:
        """Lists registered findings, optionally filtered by lifecycle state."""
        with self._lock:
            if state is None:
                return list(self._findings.values())
            return [
                f
                for fid, f in self._findings.items()
                if self._states.get(fid) == state
            ]
