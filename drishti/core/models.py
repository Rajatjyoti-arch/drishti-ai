"""Core data schemas for Drishti AI."""

from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum

class InvariantType(str, Enum):
    TENANT_ISOLATION = "I-01-TENANT-ISOLATION"
    PRICING_INTEGRITY = "I-02-SERVER-AUTHORITATIVE-PRICING"
    HOLD_EXPIRATION = "I-03-PERISHABLE-HOLD-EXPIRATION"
    REFUND_IDEMPOTENCY = "I-04-REFUND-BOUNDS-IDEMPOTENCY"

class VerificationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    INCONCLUSIVE = "INCONCLUSIVE"

try:
    from pydantic import BaseModel, Field

    class OutgoingTestRequest(BaseModel):
        method: str = Field(..., pattern="^(GET|POST|PUT|PATCH|DELETE)$")
        url: str
        headers: Dict[str, str] = Field(default_factory=dict)
        body: Optional[Any] = None
        target_tenant_id: str
        target_invariant: InvariantType

    class PolicyDecision(BaseModel):
        allowed: bool
        reason: str
        sanitized_url: str

    class InferredEndpoint(BaseModel):
        endpoint_id: str
        method: str = Field(..., pattern="^(GET|POST|PUT|PATCH|DELETE)$")
        path_template: str
        auth_required: bool
        roles_observed: List[str]
        parameters: Dict[str, str]
        source_har_request_id: str
        raw_packet_hash: str
        confidence_score: float = Field(..., ge=0.0, le=1.0)
        discovered_at: datetime = Field(default_factory=datetime.utcnow)

    class AttackHypothesis(BaseModel):
        hypothesis_id: str
        target_endpoint: InferredEndpoint
        invariant_targeted: InvariantType
        rationale: str
        test_strategy: str
        attacker_tenant_id: str
        victim_tenant_id: str
        risk_level: str = Field(..., pattern="^(ROUTINE|ELEVATED|HIGH)$")

    class CandidateFinding(BaseModel):
        candidate_id: str
        hypothesis: AttackHypothesis
        observed_status_code: int
        raw_response_snippet: str
        detected_at: datetime = Field(default_factory=datetime.utcnow)

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
        verified_at: datetime = Field(default_factory=datetime.utcnow)
        suggested_fix: str

except ImportError:
    from dataclasses import dataclass, field

    @dataclass
    class OutgoingTestRequest:
        method: str
        url: str
        target_tenant_id: str
        target_invariant: InvariantType
        headers: Dict[str, str] = field(default_factory=dict)
        body: Optional[Any] = None

    @dataclass
    class PolicyDecision:
        allowed: bool
        reason: str
        sanitized_url: str

    @dataclass
    class InferredEndpoint:
        endpoint_id: str
        method: str
        path_template: str
        auth_required: bool
        roles_observed: List[str]
        parameters: Dict[str, str]
        source_har_request_id: str
        raw_packet_hash: str
        confidence_score: float
        discovered_at: datetime = field(default_factory=datetime.utcnow)

    @dataclass
    class AttackHypothesis:
        hypothesis_id: str
        target_endpoint: InferredEndpoint
        invariant_targeted: InvariantType
        rationale: str
        test_strategy: str
        attacker_tenant_id: str
        victim_tenant_id: str
        risk_level: str

    @dataclass
    class CandidateFinding:
        candidate_id: str
        hypothesis: AttackHypothesis
        observed_status_code: int
        raw_response_snippet: str
        detected_at: datetime = field(default_factory=datetime.utcnow)

    @dataclass
    class ReproductionRecipe:
        step_number: int
        description: str
        curl_command: str
        expected_status: int

    @dataclass
    class VerifiedFinding:
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
        verified_at: datetime = field(default_factory=datetime.utcnow)
