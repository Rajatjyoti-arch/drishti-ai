"""Data models and output contracts for API discovery and endpoint normalization."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ParameterLocation(str, Enum):
    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    BODY = "body"


class ParameterClassification(str, Enum):
    CONFIRMED = "CONFIRMED"
    INFERRED = "INFERRED"
    UNCERTAIN = "UNCERTAIN"


class SemanticType(str, Enum):
    BOOKING_ID = "booking_identifier"
    HOLD_ID = "hold_identifier"
    QUOTE_ID = "quote_identifier"
    FLIGHT_ID = "flight_identifier"
    TENANT_ID = "tenant_identifier"
    USER_ID = "user_identifier"
    UUID = "uuid"
    NUMERIC_ID = "numeric_id"
    DATE = "date"
    CURRENCY = "currency"
    GENERIC = "generic_parameter"


class ParameterCandidate(BaseModel):
    """Parameter discovered in a path template or query string."""
    name: str
    location: str = "path"
    semantic_type: str = SemanticType.GENERIC.value
    classification: str = ParameterClassification.INFERRED.value
    observed_values: List[str] = Field(default_factory=list)
    is_masked: bool = False


class ProvenanceSource(BaseModel):
    """Provenance tracking where an observation originated."""
    source: str = "HAR"
    observation_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    canonical_digest: Optional[str] = None
    creator: Optional[Dict[str, str]] = None
    browser: Optional[Dict[str, str]] = None

    @property
    def observation_digest(self) -> Optional[str]:
        """Alias for the captured request observation digest."""
        return self.canonical_digest


class ConfidenceAssessment(BaseModel):
    """Multi-signal confidence assessment for an inferred route."""
    score: float = Field(..., ge=0.0, le=1.0)
    signals: List[str] = Field(default_factory=list)


class EndpointObservation(BaseModel):
    """A raw observed HTTP request to be normalized."""
    method: str
    raw_url: str
    observation_id: str = "OBS-001"
    asset_id: str = "primary-api"
    origin: str = ""
    source: str = "HAR"
    canonical_digest: Optional[str] = None
    role: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    response_status: Optional[int] = None
    content_type: Optional[str] = None
    creator: Optional[Dict[str, str]] = None
    browser: Optional[Dict[str, str]] = None

    @property
    def observation_digest(self) -> Optional[str]:
        """Request observation digest representing this specific HTTP request."""
        return self.canonical_digest

    def get_origin(self) -> str:
        """Returns the explicitly specified origin or derives scheme://host:port from raw_url."""
        if self.origin:
            return self.origin
        from urllib.parse import urlparse
        parsed = urlparse(self.raw_url)
        if parsed.scheme and parsed.hostname:
            port_suffix = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
            return f"{parsed.scheme}://{parsed.hostname}{port_suffix}"
        return ""


class NormalizedEndpoint(BaseModel):
    """Canonical normalized API endpoint definition."""
    method: str
    route_template: str
    asset_id: str = "primary-api"
    canonical_origin: str = ""
    parameters: List[ParameterCandidate] = Field(default_factory=list)
    query_parameters: List[ParameterCandidate] = Field(default_factory=list)
    body_schema_digest: Optional[str] = None
    provenance: List[ProvenanceSource] = Field(default_factory=list)
    confidence: ConfidenceAssessment
    roles_observed: List[str] = Field(default_factory=list)
    discovered_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def endpoint_identity(self) -> str:
        """Fully namespaced deterministic endpoint identity:
        asset_id:canonical_origin:method:route_template
        """
        origin = self.canonical_origin.rstrip("/") if self.canonical_origin else "*"
        return f"{self.asset_id}:{origin}:{self.method.upper()}:{self.route_template}"

    @property
    def endpoint_key(self) -> str:
        """Unique key for deduplication namespaced by asset and origin."""
        return self.endpoint_identity

    @property
    def endpoint_signature(self) -> str:
        """Computes the contract identity digest identifying this API endpoint contract:
        endpoint_signature = sha256(canonical_json(asset_id, canonical_origin, method, route_template, sorted_query_keys, body_schema_digest))
        Distinct from observation_digest, which identifies an individual captured request.
        """
        import hashlib
        import json
        query_keys = sorted([p.name for p in self.query_parameters])
        contract = {
            "asset_id": self.asset_id,
            "body_schema_digest": self.body_schema_digest,
            "canonical_origin": self.canonical_origin,
            "method": self.method.upper(),
            "query_keys": query_keys,
            "route_template": self.route_template,
        }
        encoded = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class ChangeType(str, Enum):
    """Classifications of attack surface changes between inventory snapshots."""
    ENDPOINT_ADDED = "ENDPOINT_ADDED"
    ENDPOINT_REMOVED_CANDIDATE = "ENDPOINT_REMOVED_CANDIDATE"
    ENDPOINT_NOT_OBSERVED = "ENDPOINT_NOT_OBSERVED"
    METHOD_CHANGED = "METHOD_CHANGED"
    PATH_PARAMETER_ADDED = "PATH_PARAMETER_ADDED"
    QUERY_PARAMETER_ADDED = "QUERY_PARAMETER_ADDED"
    REQUEST_SCHEMA_CHANGED = "REQUEST_SCHEMA_CHANGED"
    RESPONSE_SCHEMA_CHANGED = "RESPONSE_SCHEMA_CHANGED"
    ROLE_OBSERVATION_CHANGED = "ROLE_OBSERVATION_CHANGED"
    BUNDLE_ROUTE_CHANGED = "BUNDLE_ROUTE_CHANGED"
    AUTHENTICATION_OBSERVATION_CHANGED = "AUTHENTICATION_OBSERVATION_CHANGED"
    SOURCE_ONLY_CHANGE = "SOURCE_ONLY_CHANGE"


class CaptureCompleteness(str, Enum):
    """Indicates whether an inventory capture was comprehensive or partial."""
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"


class InventorySnapshot(BaseModel):
    """A versioned snapshot of discovered API endpoints for an asset or deployment."""
    snapshot_id: str
    asset_id: str = "primary-api"
    deployment_id: Optional[str] = None
    source_types: List[str] = Field(default_factory=lambda: ["HAR"])
    captured_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    capture_completeness: str = CaptureCompleteness.COMPLETE.value
    endpoints: Dict[str, NormalizedEndpoint] = Field(default_factory=dict)
    snapshot_digest: Optional[str] = None

    def compute_snapshot_digest(self) -> str:
        """Computes deterministic digest over sorted endpoint identities and signatures."""
        import hashlib
        import json
        items = sorted([
            (ep_id, ep.endpoint_signature)
            for ep_id, ep in self.endpoints.items()
        ])
        payload = {
            "asset_id": self.asset_id,
            "deployment_id": self.deployment_id,
            "endpoints": items,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class EndpointChange(BaseModel):
    """A granular difference detected between two snapshots for an endpoint."""
    change_id: str
    endpoint_identity: str
    change_type: str
    previous_fingerprint: Optional[str] = None
    current_fingerprint: Optional[str] = None
    affected_parameters: List[str] = Field(default_factory=list)
    provenance: List[ProvenanceSource] = Field(default_factory=list)
    confidence: float = 0.90
    recommended_invariants: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


class AttackSurfaceChangeSet(BaseModel):
    """Versioned change set output highlighting security-relevant attack surface deltas."""
    changeset_id: str
    previous_snapshot_id: str
    current_snapshot_id: str
    changes: List[EndpointChange] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    recommended_invariants: List[str] = Field(default_factory=list)
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
