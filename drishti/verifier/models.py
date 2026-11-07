"""Verification Oracle and Finding Lifecycle typed data contracts for Drishti AI.

Defines:
1. ExecutionOutcome: Explicit 4-way specialist execution outcome states.
2. EvidenceReference & EvidenceManifest: Cryptographically traceable execution telemetry.
3. ExecutorRunResult: Structured result contract emitted by specialist executors.
4. FindingLifecycleState: Multi-state lifecycle machine for vulnerability findings.
5. VerificationAttempt & VerificationResult: Evidence-backed verification decisions.
6. LifecycleTransition: Audit-tracked transitions between finding states.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field

from drishti.core.models import (
    CandidateFinding,
    InvariantType,
    ReproductionRecipe,
    VerificationStatus,
    VerifiedFinding,
)


class ExecutionOutcome(str, Enum):
    """Explicit specialist execution outcome classifications."""

    CANDIDATE = "CANDIDATE"
    EXPECTED_REJECTION = "EXPECTED_REJECTION"
    INCONCLUSIVE = "INCONCLUSIVE"
    ABORTED = "ABORTED"


class FindingLifecycleState(str, Enum):
    """Definitive lifecycle states for travel platform security findings."""

    CANDIDATE = "CANDIDATE"
    VERIFYING = "VERIFYING"
    CONFIRMED = "CONFIRMED"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    INCONCLUSIVE = "INCONCLUSIVE"
    RETEST_REQUIRED = "RETEST_REQUIRED"
    FIXED = "FIXED"
    REOPENED = "REOPENED"


class EvidenceReference(BaseModel):
    """Point-in-time evidence reference for an individual execution step."""

    request_id: str
    step_id: str
    phase: str
    method: str
    url: str
    status_code: int
    response_digest: str
    policy_decision_nonce: str = ""
    latency_ms: int = 0
    captured_bindings: Dict[str, Any] = Field(default_factory=dict)


class EvidenceManifest(BaseModel):
    """Immutable, audit-ready manifest of all execution telemetry and payload digests."""

    manifest_id: str = Field(default_factory=lambda: f"evm_{uuid.uuid4().hex[:12]}")
    plan_id: str
    execution_id: str
    invariant_id: InvariantType
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    evidence_references: List[EvidenceReference] = Field(default_factory=list)
    raw_payload_hashes: Dict[str, str] = Field(default_factory=dict)
    audit_ledger_checkpoint: Optional[str] = None
    canary_spec_digest: Optional[str] = None


class ExecutorRunResult(BaseModel):
    """Structured execution result returned by all specialist security executors.

    Separates candidate finding proposals from final confirmation, providing
    rich context, execution telemetry, and lifecycle metadata.
    """

    execution_id: str = Field(default_factory=lambda: f"run_{uuid.uuid4().hex[:12]}")
    plan_id: str
    invariant_id: InvariantType
    outcome: ExecutionOutcome
    candidate: Optional[CandidateFinding] = None
    evidence_manifest: EvidenceManifest
    completed_steps: List[str] = Field(default_factory=list)
    failed_step: Optional[str] = None
    reason: str = ""
    persisted_resource_id: Optional[str] = None
    baseline_summary: Optional[Dict[str, Any]] = None
    probe_summary: Optional[Dict[str, Any]] = None

    @property
    def finding(self) -> Optional[CandidateFinding]:
        """Convenience accessor matching candidate finding."""
        return self.candidate


class VerificationAttempt(BaseModel):
    """Telemetry and outcome of a single verification or retest attempt."""

    attempt_id: str = Field(default_factory=lambda: f"att_{uuid.uuid4().hex[:10]}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: VerificationStatus
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    confidence_rationale: str
    read_back_performed: bool = False
    read_back_status: Optional[int] = None
    read_back_matched: bool = False
    evidence_validation_passed: bool = True
    details: Dict[str, Any] = Field(default_factory=dict)


class VerificationResult(BaseModel):
    """Independent verification decision emitted exclusively by the Verification Oracle."""

    result_id: str = Field(default_factory=lambda: f"vr_{uuid.uuid4().hex[:12]}")
    candidate_id: str
    invariant_id: InvariantType
    status: VerificationStatus
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    confidence_rationale: str
    evidence_manifest_id: str
    attempts: List[VerificationAttempt] = Field(default_factory=list)
    verified_finding: Optional[VerifiedFinding] = None
    recommended_action: str = ""


class LifecycleTransition(BaseModel):
    """Audit-logged state transition in the finding lifecycle."""

    transition_id: str = Field(default_factory=lambda: f"tr_{uuid.uuid4().hex[:10]}")
    finding_id: str
    from_state: FindingLifecycleState
    to_state: FindingLifecycleState
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    actor: str = "VerificationOracle"
    reason: str
    evidence_ref: Optional[str] = None
