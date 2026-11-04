"""Core data models and structured types for Drishti AI."""

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from enum import Enum
import uuid

class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    PAUSE = "PAUSE"
    STOP = "STOP"

class InvariantType(str, Enum):
    TENANT_ISOLATION = "I-01-TENANT-ISOLATION"
    PRICING_INTEGRITY = "I-02-SERVER-AUTHORITATIVE-PRICING"
    HOLD_EXPIRATION = "I-03-PERISHABLE-HOLD-EXPIRATION"
    REFUND_IDEMPOTENCY = "I-04-REFUND-BOUNDS-IDEMPOTENCY"

class VerificationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    INCONCLUSIVE = "INCONCLUSIVE"

class OutgoingTestRequest(BaseModel):
    request_id: str = Field(default_factory=lambda: f"req_{uuid.uuid4().hex[:12]}")
    method: str = Field(..., pattern="^(GET|POST|PUT|PATCH|DELETE)$")
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[Any] = None
    target_tenant_id: str
    target_invariant: InvariantType
    credential_ref: Optional[str] = None
    test_id: str = Field(default="test_default")

class PolicyDecision(BaseModel):
    decision_id: str = Field(default_factory=lambda: f"dec_{uuid.uuid4().hex[:12]}")
    action: PolicyAction
    approved: bool
    reason: str
    sanitized_url: str
    budget_remaining: int
    approval_required: bool = False
    policy_version: str = "1.0.0"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class CanaryFixture(BaseModel):
    fixture_id: str
    owner_tenant_id: str
    object_id: str
    canary_key: str
    canary_value: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class InferredEndpoint(BaseModel):
    endpoint_id: str
    method: str
    path_template: str
    auth_required: bool
    roles_observed: List[str]
    parameters: Dict[str, str]
    source_har_request_id: str
    raw_packet_hash: str
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    discovered_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class AttackHypothesis(BaseModel):
    hypothesis_id: str
    target_endpoint: InferredEndpoint
    invariant_targeted: InvariantType
    rationale: str
    test_strategy: str
    attacker_tenant_id: str
    victim_tenant_id: str
    risk_level: str = Field(default="ROUTINE", pattern="^(ROUTINE|ELEVATED|HIGH)$")

class CandidateFinding(BaseModel):
    candidate_id: str
    hypothesis: AttackHypothesis
    observed_status_code: int
    raw_response_snippet: str
    detected_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class ReproductionRecipe(BaseModel):
    step_number: int
    description: str
    curl_command: str
    expected_status: int

class VerifiedFinding(BaseModel):
    finding_id: str
    invariant_id: InvariantType
    status: VerificationStatus
    title: str
    target_endpoint: str
    violated_rule: str
    confidence_score: float
    business_impact: Dict[str, Any]
    exposed_sensitive_fields: List[str]
    reproduction_steps: List[ReproductionRecipe]
    request_evidence_hash: str
    raw_response_diff: str
    suggested_fix: str
    verified_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
