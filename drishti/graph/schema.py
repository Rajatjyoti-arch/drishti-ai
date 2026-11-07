"""Typed schema definitions for the Travel Security Intelligence Graph.

Defines typed nodes, edges, fact classifications, and evidence contracts
used to model multi-tenant B2B travel topologies, independent entity lifecycles,
and invariant bindings.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import hashlib
import json
from pydantic import BaseModel, Field


class NodeType(str, Enum):
    """Classifies entity nodes within the Travel Security Intelligence Graph."""
    TENANT = "Tenant"
    PRINCIPAL = "Principal"
    ROLE = "Role"
    ASSET = "Asset"
    ENDPOINT = "Endpoint"
    PARAMETER = "Parameter"
    BUSINESS_OBJECT = "BusinessObject"
    WORKFLOW_STATE = "WorkflowState"
    JOURNEY = "Journey"
    OBSERVATION = "Observation"
    INVARIANT = "Invariant"
    HYPOTHESIS = "Hypothesis"


class EdgeType(str, Enum):
    """Typed relationship edges connecting nodes in the MultiDiGraph."""
    # Behavioral and verification edges (evidence-aware)
    OBSERVED_REQUESTED_BY = "OBSERVED_REQUESTED_BY"
    OBSERVED_RESPONSE_TO = "OBSERVED_RESPONSE_TO"
    AUTHORIZED_ACCESS_CONFIRMED = "AUTHORIZED_ACCESS_CONFIRMED"

    # Business domain and ownership edges
    OWNS = "OWNS"
    PRODUCES = "PRODUCES"
    CONSUMES = "CONSUMES"

    # State machine transition edges
    TRANSITION_ALLOWED = "TRANSITION_ALLOWED"
    TRANSITION_OBSERVED = "TRANSITION_OBSERVED"

    # Invariant governance & evidence traceability
    BINDS_INVARIANT = "BINDS_INVARIANT"
    SUPPORTED_BY = "SUPPORTED_BY"

    # Structural relationships
    BELONGS_TO_TENANT = "BELONGS_TO_TENANT"
    HAS_ROLE = "HAS_ROLE"
    HOSTED_ON = "HOSTED_ON"
    HAS_PARAMETER = "HAS_PARAMETER"
    IN_STATE = "IN_STATE"
    STEP_IN_JOURNEY = "STEP_IN_JOURNEY"


class FactClassification(str, Enum):
    """Categorizes the epistemic certainty of a graph fact."""
    DECLARED = "DECLARED"        # Contractual or architectural specification
    OBSERVED = "OBSERVED"        # Seen in traffic, logs, or crawl captures
    INFERRED = "INFERRED"        # Derived via AST analysis or parameter normalization
    CONFIRMED = "CONFIRMED"      # Validated via active differential security tests


class EvidenceSourceType(str, Enum):
    """Identifies the origin of supporting evidence."""
    HAR = "HAR"
    CRAWLER = "CRAWLER"
    BUNDLE_AST = "BUNDLE_AST"
    VERIFIER = "VERIFIER"
    CONTRACT = "CONTRACT"
    STATIC_SPEC = "STATIC_SPEC"


class InvariantCategory(str, Enum):
    """Taxonomy of travel security invariants."""
    BOLA = "BOLA"
    PRICING_INTEGRITY = "PRICING_INTEGRITY"
    HOLD_LIFECYCLE = "HOLD_LIFECYCLE"
    PAYMENT_IDEMPOTENCY = "PAYMENT_IDEMPOTENCY"
    REFUND_BOUNDS = "REFUND_BOUNDS"


# ============================================================================
# Typed Node Models
# ============================================================================

class TenantNode(BaseModel):
    """Represents a B2B tenant organization (e.g. Agency A, Agency B, Supplier)."""
    tenant_id: str
    name: str
    tenant_type: str = "agency"  # agency, supplier, platform_operator
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def node_id(self) -> str:
        return f"tenant:{self.tenant_id}"


class PrincipalNode(BaseModel):
    """Represents an individual user, agent, or service identity within a tenant."""
    principal_id: str
    tenant_id: str
    roles: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def node_id(self) -> str:
        return f"principal:{self.tenant_id}:{self.principal_id}"


class RoleNode(BaseModel):
    """Represents an authority role (Agency Admin, Front Desk Agent, Sub-Agent)."""
    role_name: str
    tenant_id: Optional[str] = None
    description: Optional[str] = None

    @property
    def node_id(self) -> str:
        if self.tenant_id:
            return f"role:{self.role_name}:{self.tenant_id}"
        return f"role:{self.role_name}"


class AssetNode(BaseModel):
    """Represents a namespaced microservice, gateway, or API application."""
    asset_id: str
    canonical_origin: str = ""
    description: Optional[str] = None

    @property
    def node_id(self) -> str:
        return f"asset:{self.asset_id}"


class EndpointNode(BaseModel):
    """Represents a canonical normalized API endpoint."""
    endpoint_identity: str
    method: str
    route_template: str
    asset_id: str = "primary-api"
    canonical_origin: str = ""
    auth_required: bool = True
    roles_observed: List[str] = Field(default_factory=list)
    confidence: float = 1.0

    @property
    def node_id(self) -> str:
        # Canonical endpoint identity remains the unique key
        return f"endpoint:{self.endpoint_identity}"


class ParameterNode(BaseModel):
    """Represents an endpoint parameter (path, query, body, or header)."""
    endpoint_identity: str
    name: str
    location: str = "path"  # path, query, body, header
    semantic_type: str = "generic_parameter"
    is_financial: bool = False
    is_identifier: bool = False

    @property
    def node_id(self) -> str:
        return f"param:{self.endpoint_identity}:{self.location}:{self.name}"


class BusinessObjectNode(BaseModel):
    """Represents a travel business object (SearchQuery, Quote, Hold, Booking, Payment, Refund)."""
    object_type: str  # SearchQuery, Quote, Hold, Booking, Payment, Refund
    object_id: str
    owner_tenant_id: str
    canary_fixture_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def node_id(self) -> str:
        return f"obj:{self.owner_tenant_id}:{self.object_type.lower()}:{self.object_id}"


class WorkflowStateNode(BaseModel):
    """Represents an object-specific lifecycle state."""
    object_type: str  # Quote, Hold, Booking, Payment, Refund
    state_name: str
    description: Optional[str] = None

    @property
    def node_id(self) -> str:
        return f"state:{self.object_type}:{self.state_name}"


class JourneyNode(BaseModel):
    """Represents an ordered travel workflow journey (e.g. Flight Search to Booking)."""
    journey_id: str
    name: str
    description: str
    step_endpoint_identities: List[str] = Field(default_factory=list)

    @property
    def node_id(self) -> str:
        return f"journey:{self.journey_id}"


class ObservationNode(BaseModel):
    """Represents concrete evidentiary trace from HAR, crawler, or AST inspection."""
    observation_id: str
    source_type: EvidenceSourceType
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    canonical_digest: Optional[str] = None
    confidence: float = 1.0
    tenant_id: Optional[str] = None
    role_id: Optional[str] = None
    session_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

    @property
    def node_id(self) -> str:
        return f"obs:{self.observation_id}"


class InvariantNode(BaseModel):
    """Represents a security invariant rule bound to graph elements."""
    invariant_id: str  # e.g. I-01-TENANT-ISOLATION
    title: str
    description: str
    category: InvariantCategory
    sub_rules: List[str] = Field(default_factory=list)

    @property
    def node_id(self) -> str:
        return f"invariant:{self.invariant_id}"


class HypothesisNode(BaseModel):
    """Represents a testable security hypothesis generated from graph analysis."""
    hypothesis_id: str
    invariant_id: str
    target_endpoint_identity: str
    attacker_tenant_id: str
    victim_tenant_id: str
    rationale: str
    risk_level: str = "ROUTINE"
    supporting_evidence_ids: List[str] = Field(default_factory=list)

    @property
    def node_id(self) -> str:
        return f"hypothesis:{self.hypothesis_id}"


# ============================================================================
# Typed Graph Edge Contract
# ============================================================================

class GraphEdge(BaseModel):
    """Evidence-backed relationship edge connecting two nodes."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    classification: FactClassification = FactClassification.OBSERVED
    confidence: float = 1.0
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    evidence_refs: List[str] = Field(default_factory=list)
    tenant_context: Optional[str] = None
    role_context: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def edge_key(self) -> str:
        """Deterministic key for MultiDiGraph edge discrimination."""
        evidence_tag = hashlib.sha256(
            json.dumps(sorted(self.evidence_refs)).encode("utf-8")
        ).hexdigest()[:8] if self.evidence_refs else "decl"
        ctx = f"{self.tenant_context or '*'}_{self.role_context or '*'}"
        return f"{self.edge_type.value}:{self.classification.value}:{ctx}:{evidence_tag}"
