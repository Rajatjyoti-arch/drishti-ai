"""Data models for role-isolated journey-aware browser crawling and observation.

Defines role contexts, crawl sessions, travel journey steps, and sanitized
browser observations mediated through the Rust Security Kernel.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from drishti.discovery.models import CaptureCompleteness


class ActionType(str, Enum):
    """Types of browser interactions performed during a travel journey."""
    NAVIGATE = "NAVIGATE"
    CLICK = "CLICK"
    FILL = "FILL"
    SELECT = "SELECT"
    WAIT_FOR = "WAIT_FOR"
    API_CALL = "API_CALL"


class CrawlStatus(str, Enum):
    """Execution state of a browser crawl session."""
    INITIALIZED = "INITIALIZED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    TIMEOUT = "TIMEOUT"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    FAILED = "FAILED"


class RoleContext(BaseModel):
    """Multi-tenant role definition with isolated identity and session state."""
    role_name: str
    tenant_id: str
    agency_id: str
    auth_headers: Dict[str, str] = Field(default_factory=dict)
    cookies: List[Dict[str, Any]] = Field(default_factory=list)
    user_agent: Optional[str] = None
    storage_state: Dict[str, Any] = Field(default_factory=dict)

    @property
    def role_identifier(self) -> str:
        """Fully namespaced role identifier: tenant_id:role_name."""
        return f"{self.tenant_id}:{self.role_name}"


class JourneyStep(BaseModel):
    """A discrete user action in a B2B travel workflow (e.g. Search, Quote, Hold, Book)."""
    step_id: str
    step_name: str
    action_type: str = ActionType.NAVIGATE.value
    target: str  # URL or DOM selector
    value: Optional[str] = None  # Input value for fill/select
    payload: Optional[Dict[str, Any]] = None  # Request payload for API calls
    expected_status: Optional[int] = None
    timeout_ms: int = 5000
    is_critical: bool = True  # If critical step fails, journey halts


class JourneyPlan(BaseModel):
    """An ordered series of journey steps modeling a complete B2B travel flow."""
    plan_id: str
    name: str
    description: str
    steps: List[JourneyStep] = Field(default_factory=list)
    max_duration_seconds: int = 60
    max_requests: int = 100


class BrowserObservation(BaseModel):
    """A sanitized HTTP observation captured during browser execution."""
    observation_id: str
    session_id: str
    role_name: str
    tenant_id: str
    journey_step_id: Optional[str] = None
    method: str
    url: str
    status_code: int
    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: Optional[str] = None
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body: Optional[str] = None
    latency_ms: int = 0
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    guard_mediated: bool = True


class CrawlSession(BaseModel):
    """State tracking for a role-isolated crawl execution."""
    session_id: str
    role_context: RoleContext
    status: str = CrawlStatus.INITIALIZED.value
    capture_completeness: str = CaptureCompleteness.PARTIAL.value
    start_time: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: Optional[str] = None
    request_count: int = 0
    max_requests: int = 100
    completed_steps: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
