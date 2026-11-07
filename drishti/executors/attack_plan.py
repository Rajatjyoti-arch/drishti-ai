"""Attack Plan Models and Compiler for Drishti AI.

Compiles graph-derived attack hypotheses into versioned, declarative,
schema-validated, and budget-bounded AttackPlan execution contracts.
"""

from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import re
import secrets
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator, model_validator

from drishti.core.models import AttackHypothesis, InferredEndpoint, InvariantType
from drishti.graph.schema import HypothesisNode


class PlanPhase(str, Enum):
    """Execution lifecycle phase of an attack plan step."""
    SETUP = "SETUP"                      # Creates synthetic object / canary fixture
    NEGATIVE_CONTROL = "NEGATIVE_CONTROL"# Verifies authorized baseline behavior
    PROBE = "PROBE"                      # Executes the targeted cross-tenant or tampered request
    TEARDOWN = "TEARDOWN"                # Cleans up synthetic state if applicable


class CredentialBinding(BaseModel):
    """Opaque reference binding a tenant and role to a credential secret reference."""
    tenant_id: str = Field(..., min_length=1)
    role: str = Field(default="agent", min_length=1)
    credential_ref: str = Field(..., min_length=1)

    model_config = {"extra": "forbid"}

    @field_validator("credential_ref")
    @classmethod
    def validate_credential_reference(cls, v: str) -> str:
        """Ensures credential_ref is an opaque identifier and never a raw token or secret."""
        raw_token_patterns = [
            r"^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",  # JWT
            r"^(ghp_|gho_|sk-|secret_|password).*",                # Raw API keys / secrets
            r"^Bearer\s+",                                          # Raw Bearer token string
        ]
        for pattern in raw_token_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError(
                    f"credential_ref must be an opaque reference ID, not a raw credential or token: {v[:10]}..."
                )
        if " " in v:
            raise ValueError("credential_ref cannot contain whitespace")
        return v


class ExecutionBudget(BaseModel):
    """Per-plan request count, duration, and payload size bounds."""
    max_requests: int = Field(default=10, ge=1, le=100)
    max_duration_seconds: int = Field(default=30, ge=1, le=300)
    max_response_size_bytes: int = Field(default=65536, ge=512, le=5242880)

    model_config = {"extra": "forbid"}


class PlanPrecondition(BaseModel):
    """Declarative precondition required before plan execution."""
    precondition_id: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    target_entity: str = Field(..., min_length=1)
    required_state: str = Field(..., min_length=1)

    model_config = {"extra": "forbid"}


class NegativeControl(BaseModel):
    """Expected baseline behavior proving the security test is statistically meaningful."""
    control_id: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    actor_tenant_id: str = Field(..., min_length=1)
    credential_ref: str = Field(..., min_length=1)
    expected_status_code: int = Field(default=200, ge=100, le=599)
    assertion_rule: str = Field(..., min_length=1)

    model_config = {"extra": "forbid"}


class CanarySpec(BaseModel):
    """Synthetic object and protected-value verification contract."""
    canary_id: str = Field(..., min_length=1)
    owner_tenant_id: str = Field(..., min_length=1)
    object_type: str = Field(default="booking", min_length=1)
    canary_key: str = Field(default="passenger_name", min_length=1)
    canary_value_digest: str = Field(..., min_length=64, max_length=64)  # SHA-256
    mutation_allowed: bool = False

    model_config = {"extra": "forbid"}


class PlanStep(BaseModel):
    """An individual bounded, declarative test operation within an AttackPlan."""
    step_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    phase: PlanPhase = PlanPhase.PROBE
    method: str = Field(..., pattern="^(GET|POST|PUT|PATCH|DELETE)$")
    target_endpoint_identity: str = Field(..., min_length=1)
    endpoint_route_template: str = Field(..., min_length=1)
    actor_tenant_id: str = Field(..., min_length=1)
    credential_ref: str = Field(..., min_length=1)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[Any] = None
    expected_status_baseline: Optional[int] = None
    requires_mutation_approval: bool = False
    is_critical: bool = True

    model_config = {"extra": "forbid"}


# Alias for backwards and forwards compatibility
AttackPlanStep = PlanStep



class AttackPlan(BaseModel):
    """Complete versioned, schema-validated execution manifest."""
    plan_version: str = "1.0.0"
    plan_id: str = Field(..., min_length=1)
    hypothesis_id: str = Field(..., min_length=1)
    invariant_id: InvariantType
    target_endpoint_identity: str = Field(..., min_length=1)
    attacker_tenant_id: str = Field(..., min_length=1)
    victim_tenant_id: str = Field(..., min_length=1)
    attacker_credential: CredentialBinding
    victim_credential: CredentialBinding
    budget: ExecutionBudget = Field(default_factory=ExecutionBudget)
    preconditions: List[PlanPrecondition] = Field(default_factory=list)
    negative_controls: List[NegativeControl] = Field(default_factory=list)
    canary_spec: Optional[CanarySpec] = None
    steps: List[PlanStep] = Field(default_factory=list)
    synthetic_mutation_approved: bool = False
    expires_at: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def validate_plan_invariants(self) -> "AttackPlan":
        """Enforces tenant isolation, credential binding, and mutation approval boundaries."""
        # 1. Distinct tenants
        if self.attacker_tenant_id == self.victim_tenant_id:
            raise ValueError(
                f"Attacker tenant ({self.attacker_tenant_id}) and victim tenant ({self.victim_tenant_id}) must be distinct."
            )

        # 2. Tenant binding: Credentials cannot be interchanged
        if self.attacker_credential.tenant_id != self.attacker_tenant_id:
            raise ValueError(
                f"Attacker credential tenant ({self.attacker_credential.tenant_id}) does not match "
                f"plan attacker tenant ({self.attacker_tenant_id})."
            )
        if self.victim_credential.tenant_id != self.victim_tenant_id:
            raise ValueError(
                f"Victim credential tenant ({self.victim_credential.tenant_id}) does not match "
                f"plan victim tenant ({self.victim_tenant_id})."
            )

        # 3. Synthetic mutation approval requirement
        has_mutation_step = any(
            step.requires_mutation_approval or (
                step.phase == PlanPhase.PROBE and step.method in ("POST", "PUT", "PATCH", "DELETE")
            )
            for step in self.steps
        )
        if has_mutation_step and not self.synthetic_mutation_approved:
            raise ValueError(
                "Plan contains mutating probe steps but synthetic_mutation_approved is False. "
                "Explicit approval is required for synthetic mutations."
            )

        # 4. Step tenant & credential binding consistency
        allowed_credentials = {
            self.attacker_tenant_id: self.attacker_credential.credential_ref,
            self.victim_tenant_id: self.victim_credential.credential_ref,
        }
        for step in self.steps:
            if step.actor_tenant_id not in allowed_credentials:
                raise ValueError(
                    f"Step '{step.step_id}' references unknown actor tenant '{step.actor_tenant_id}'. "
                    f"Must be '{self.attacker_tenant_id}' or '{self.victim_tenant_id}'."
                )
            expected_cred = allowed_credentials[step.actor_tenant_id]
            if step.credential_ref != expected_cred:
                raise ValueError(
                    f"Step '{step.step_id}' credential_ref '{step.credential_ref}' does not match "
                    f"bound credential '{expected_cred}' for tenant '{step.actor_tenant_id}'."
                )

        return self


class AttackPlanCompiler:
    """Compiles graph HypothesisNode or core AttackHypothesis instances into executable AttackPlan contracts."""

    @staticmethod
    def compile_plan(
        hypothesis: Union[HypothesisNode, AttackHypothesis],
        attacker_credential_ref: str = "cred:agency_b:admin",
        victim_credential_ref: str = "cred:agency_a:admin",
        budget: Optional[ExecutionBudget] = None,
        synthetic_mutation_approved: bool = False,
        seed: Optional[str] = None,
        ttl_minutes: int = 60,
    ) -> AttackPlan:
        """Compiles a fully validated, deterministic AttackPlan."""
        # Normalize hypothesis fields
        if isinstance(hypothesis, HypothesisNode):
            hyp_id = hypothesis.hypothesis_id
            inv_type = InvariantType(hypothesis.invariant_id)
            endpoint_id = hypothesis.target_endpoint_identity
            attacker_tenant = hypothesis.attacker_tenant_id
            victim_tenant = hypothesis.victim_tenant_id
        else:
            hyp_id = hypothesis.hypothesis_id
            inv_type = hypothesis.invariant_targeted
            endpoint_id = (
                hypothesis.target_endpoint.endpoint_id
                if hypothesis.target_endpoint.endpoint_id.count(":") >= 3
                else f"travel_api:canonical:{hypothesis.target_endpoint.method}:{hypothesis.target_endpoint.path_template}"
            )
            attacker_tenant = hypothesis.attacker_tenant_id
            victim_tenant = hypothesis.victim_tenant_id

        # Stable, reproducible plan ID
        seed_key = seed or "default"
        plan_hash = hashlib.sha256(f"{hyp_id}:{endpoint_id}:{seed_key}".encode("utf-8")).hexdigest()[:12]
        plan_id = f"PLAN-{plan_hash}"

        # Expiry timestamp
        created_dt = datetime.now(timezone.utc)
        expires_dt = created_dt + timedelta(minutes=ttl_minutes)
        expires_at = expires_dt.isoformat()

        # Credential bindings
        attacker_cred = CredentialBinding(
            tenant_id=attacker_tenant,
            role="admin",
            credential_ref=attacker_credential_ref,
        )
        victim_cred = CredentialBinding(
            tenant_id=victim_tenant,
            role="admin",
            credential_ref=victim_credential_ref,
        )

        plan_budget = budget or ExecutionBudget(
            max_requests=10,
            max_duration_seconds=30,
            max_response_size_bytes=65536,
        )

        # Parse route template from endpoint identity
        parts = endpoint_id.split(":")
        route_template = parts[3] if len(parts) >= 4 else "/api/v2/bookings/{booking_id}"
        method = parts[2] if len(parts) >= 3 else "GET"

        if inv_type == InvariantType.TENANT_ISOLATION:
            # Deterministic or high-entropy canary digest
            if seed:
                canary_secret = hashlib.sha256(f"canary:{plan_id}:{seed}".encode("utf-8")).hexdigest()[:16]
            else:
                canary_secret = secrets.token_hex(16)
            canary_digest = hashlib.sha256(canary_secret.encode("utf-8")).hexdigest()

            canary_spec = CanarySpec(
                canary_id=f"canary_{plan_hash[:8]}",
                owner_tenant_id=victim_tenant,
                object_type="booking",
                canary_key="passenger_name",
                canary_value_digest=canary_digest,
                mutation_allowed=False,
            )

            preconditions = [
                PlanPrecondition(
                    precondition_id=f"prec_{plan_hash[:6]}_victim_tenant",
                    description=f"Victim tenant '{victim_tenant}' must be provisioned and active.",
                    target_entity=f"tenant:{victim_tenant}",
                    required_state="ACTIVE",
                ),
                PlanPrecondition(
                    precondition_id=f"prec_{plan_hash[:6]}_target_endpoint",
                    description=f"Target endpoint '{endpoint_id}' must be registered in inventory.",
                    target_entity=endpoint_id,
                    required_state="REGISTERED",
                ),
            ]

            negative_controls = [
                NegativeControl(
                    control_id=f"ctrl_{plan_hash[:6]}_victim_own_read",
                    description=f"Victim tenant '{victim_tenant}' must be authorized to read its own canary booking.",
                    actor_tenant_id=victim_tenant,
                    credential_ref=victim_credential_ref,
                    expected_status_code=200,
                    assertion_rule="Victim authorized read must succeed with HTTP 200 and return canary.",
                ),
                NegativeControl(
                    control_id=f"ctrl_{plan_hash[:6]}_attacker_own_read",
                    description=f"Attacker tenant '{attacker_tenant}' must be authorized to read its own booking.",
                    actor_tenant_id=attacker_tenant,
                    credential_ref=attacker_credential_ref,
                    expected_status_code=200,
                    assertion_rule="Attacker authorized read must succeed with HTTP 200.",
                ),
            ]

            steps = [
                PlanStep(
                    step_id="step_1_create_victim_canary",
                    name="Provision Synthetic Canary Booking (Victim)",
                    phase=PlanPhase.SETUP,
                    method="POST",
                    target_endpoint_identity="travel_api:canonical:POST:/api/v2/bookings",
                    endpoint_route_template="/api/v2/bookings",
                    actor_tenant_id=victim_tenant,
                    credential_ref=victim_credential_ref,
                    parameters={"passenger_name": f"Canary-{canary_secret[:8]}"},
                    body={"passenger_name": f"Canary-{canary_secret[:8]}", "passenger_passport": "A1234567"},
                    expected_status_baseline=200,
                    is_critical=True,
                ),
                PlanStep(
                    step_id="step_2_negative_control_victim_read",
                    name="Verify Legitimate Access (Victim Negative Control)",
                    phase=PlanPhase.NEGATIVE_CONTROL,
                    method="GET",
                    target_endpoint_identity="travel_api:canonical:GET:/api/v2/bookings/{booking_id}",
                    endpoint_route_template="/api/v2/bookings/{booking_id}",
                    actor_tenant_id=victim_tenant,
                    credential_ref=victim_credential_ref,
                    parameters={"booking_id": "{canary_booking_id}"},
                    expected_status_baseline=200,
                    is_critical=True,
                ),
                PlanStep(
                    step_id="step_3_negative_control_attacker_read",
                    name="Verify Attacker Identity Health (Attacker Negative Control)",
                    phase=PlanPhase.NEGATIVE_CONTROL,
                    method="GET",
                    target_endpoint_identity="travel_api:canonical:GET:/api/v2/bookings/{booking_id}",
                    endpoint_route_template="/api/v2/bookings/{booking_id}",
                    actor_tenant_id=attacker_tenant,
                    credential_ref=attacker_credential_ref,
                    parameters={"booking_id": "{attacker_booking_id}"},
                    expected_status_baseline=200,
                    is_critical=True,
                ),
                PlanStep(
                    step_id="step_4_cross_tenant_probe",
                    name="Execute Cross-Tenant Read Probe",
                    phase=PlanPhase.PROBE,
                    method="GET",
                    target_endpoint_identity=endpoint_id,
                    endpoint_route_template=route_template,
                    actor_tenant_id=attacker_tenant,
                    credential_ref=attacker_credential_ref,
                    parameters={"booking_id": "{canary_booking_id}"},
                    expected_status_baseline=403,
                    is_critical=True,
                ),
            ]

            return AttackPlan(
                plan_id=plan_id,
                hypothesis_id=hyp_id,
                invariant_id=inv_type,
                target_endpoint_identity=endpoint_id,
                attacker_tenant_id=attacker_tenant,
                victim_tenant_id=victim_tenant,
                attacker_credential=attacker_cred,
                victim_credential=victim_cred,
                budget=plan_budget,
                preconditions=preconditions,
                negative_controls=negative_controls,
                canary_spec=canary_spec,
                steps=steps,
                synthetic_mutation_approved=synthetic_mutation_approved,
                expires_at=expires_at,
            )

        elif inv_type == InvariantType.PRICING_INTEGRITY:
            preconditions = [
                PlanPrecondition(
                    precondition_id=f"prec_{plan_hash[:6]}_authoritative_quote",
                    description="Authoritative quote must be fetched from pricing service.",
                    target_entity="quote:QT_BASELINE",
                    required_state="QUOTED",
                ),
                PlanPrecondition(
                    precondition_id=f"prec_{plan_hash[:6]}_hold_acquired",
                    description="Inventory hold must be acquired and unexpired.",
                    target_entity="hold:HLD_BASELINE",
                    required_state="HELD",
                ),
            ]

            negative_controls = [
                NegativeControl(
                    control_id=f"ctrl_{plan_hash[:6]}_baseline_quote_validity",
                    description="Untampered booking request must succeed at server quote price.",
                    actor_tenant_id=attacker_tenant,
                    credential_ref=attacker_credential_ref,
                    expected_status_code=200,
                    assertion_rule="Server-authoritative quote price must be accepted.",
                )
            ]

            steps = [
                PlanStep(
                    step_id="step_1_acquire_hold",
                    name="Acquire Server Inventory Hold",
                    phase=PlanPhase.SETUP,
                    method="POST",
                    target_endpoint_identity="travel_api:canonical:POST:/api/v2/holds",
                    endpoint_route_template="/api/v2/holds",
                    actor_tenant_id=attacker_tenant,
                    credential_ref=attacker_credential_ref,
                    body={"quote_id": "QT_GOA_501"},
                    expected_status_baseline=200,
                    is_critical=True,
                ),
                PlanStep(
                    step_id="step_2_negative_control_quote_verification",
                    name="Verify Quote Baseline Parameters",
                    phase=PlanPhase.NEGATIVE_CONTROL,
                    method="GET",
                    target_endpoint_identity="travel_api:canonical:GET:/api/v2/quotes/{quote_id}",
                    endpoint_route_template="/api/v2/quotes/{quote_id}",
                    actor_tenant_id=attacker_tenant,
                    credential_ref=attacker_credential_ref,
                    parameters={"quote_id": "QT_GOA_501"},
                    expected_status_baseline=200,
                    is_critical=True,
                ),
                PlanStep(
                    step_id="step_3_price_tampering_probe",
                    name="Execute Client-Controlled Minor Units Tampering Probe",
                    phase=PlanPhase.PROBE,
                    method="POST",
                    target_endpoint_identity=endpoint_id,
                    endpoint_route_template=route_template,
                    actor_tenant_id=attacker_tenant,
                    credential_ref=attacker_credential_ref,
                    body={
                        "client_amount_minor_units": 100,  # 1 INR tampering attempt
                        "client_currency": "INR",
                        "passenger_name": "Budget Explorer",
                    },
                    expected_status_baseline=400,
                    requires_mutation_approval=True,
                    is_critical=True,
                ),
            ]

            return AttackPlan(
                plan_id=plan_id,
                hypothesis_id=hyp_id,
                invariant_id=inv_type,
                target_endpoint_identity=endpoint_id,
                attacker_tenant_id=attacker_tenant,
                victim_tenant_id=victim_tenant,
                attacker_credential=attacker_cred,
                victim_credential=victim_cred,
                budget=plan_budget,
                preconditions=preconditions,
                negative_controls=negative_controls,
                canary_spec=None,
                steps=steps,
                synthetic_mutation_approved=synthetic_mutation_approved,
                expires_at=expires_at,
            )

        else:
            raise NotImplementedError(f"Plan compilation for invariant '{inv_type}' is not yet supported.")
