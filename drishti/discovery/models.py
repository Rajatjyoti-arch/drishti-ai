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


class ProvenanceSource(BaseModel):
    """Provenance tracking where an observation originated."""
    source: str = "HAR"
    observation_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    canonical_digest: Optional[str] = None


class ConfidenceAssessment(BaseModel):
    """Multi-signal confidence assessment for an inferred route."""
    score: float = Field(..., ge=0.0, le=1.0)
    signals: List[str] = Field(default_factory=list)


class NormalizedEndpoint(BaseModel):
    """Canonical normalized API endpoint definition."""
    method: str
    route_template: str
    parameters: List[ParameterCandidate] = Field(default_factory=list)
    query_parameters: List[ParameterCandidate] = Field(default_factory=list)
    provenance: List[ProvenanceSource] = Field(default_factory=list)
    confidence: ConfidenceAssessment
    roles_observed: List[str] = Field(default_factory=list)
    discovered_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def endpoint_key(self) -> str:
        """Deterministic unique key for deduplication."""
        return f"{self.method.upper()}:{self.route_template}"
