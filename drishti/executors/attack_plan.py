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


class ParsedEndpointIdentity(BaseModel):
    """Typed structure representing a parsed canonical endpoint identity.

    Format: asset_id:canonical_origin:method:route_template
    Supports HTTP, HTTPS, custom ports, and routes with path parameters.
    """
    asset_id: str = Field(..., min_length=1)
    origin: str = Field(..., min_length=1)
    method: str = Field(..., pattern="^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$")
    route_template: str = Field(..., min_length=1)

    model_config = {"extra": "forbid"}

    @classmethod
    def parse(cls, endpoint_identity: str) -> "ParsedEndpointIdentity":
        """Parses canonical endpoint identities safely, handling origin colons and ports."""
        if endpoint_identity.count(":") < 2:
            raise ValueError(f"Invalid endpoint identity format: '{endpoint_identity}'")
        try:
            # Parse method and route from right to left
            prefix, method, route = endpoint_identity.rsplit(":", 2)
            if ":" in prefix:
                asset_id, origin = prefix.split(":", 1)
            else:
                asset_id, origin = prefix, "canonical"

            method = method.upper()
            if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                raise ValueError(f"Invalid HTTP method in endpoint identity: '{method}'")
            if not route.startswith("/"):
                raise ValueError(f"Route template must start with '/': '{route}'")

            return cls(
                asset_id=asset_id,
                origin=origin,
                method=method,
                route_template=route,
            )
        except Exception as e:
            raise ValueError(f"Failed to parse endpoint identity '{endpoint_identity}': {e}") from e


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
        # Check against raw token patterns
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

        # Allowlist check for opaque reference formats
        allowed_pattern = r"^([a-z0-9_-]+:[a-z0-9_\-:]+|mock_jwt_[a-z0-9_\-]+|ref:[a-z0-9_\-\.:]+)$"
        if not re.match(allowed_pattern, v, re.IGNORECASE):
            raise ValueError(
                f"credential_ref '{v}' does not match allowed opaque reference format (e.g. cred:tenant:role, mock_jwt_*, ref:*)"
            )
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


class CanarySecretStore:
    """Protected in-memory execution-time store for high-entropy canary secret values."""
    _store: Dict[str, str] = {}

    @classmethod
    def store_secret(cls, secret_ref: str, value: str) -> None:
        cls._store[secret_ref] = value

    @classmethod
    def get_secret(cls, secret_ref: str) -> Optional[str]:
        return cls._store.get(secret_ref)

    @classmethod
    def clear(cls) -> None:
        cls._store.clear()


class CanarySpec(BaseModel):
    """Synthetic object and protected-value verification contract."""
    canary_id: str = Field(..., min_length=1)
    owner_tenant_id: str = Field(..., min_length=1)
    object_type: str = Field(default="booking", min_length=1)
    canary_key: str = Field(default="passenger_name", min_length=1)
    canary_value_digest: str = Field(..., min_length=64, max_length=64)  # SHA-256
    canary_secret_ref: str = Field(..., min_length=1)                    # Opaque secret reference
    mutation_allowed: bool = False

    model_config = {"extra": "forbid"}


class OutputBinding(BaseModel):
    """Maps a field from a step's JSON response into the execution context."""
    source_field: str = Field(..., min_length=1)
    context_variable: str = Field(..., min_length=1)
    default_value: Optional[str] = None

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
    output_bindings: List[OutputBinding] = Field(default_factory=list)

    model_config = {"extra": "forbid"}

    @field_validator("headers")
    @classmethod
    def validate_headers_no_raw_auth(cls, headers: Dict[str, str]) -> Dict[str, str]:
        """Prohibits raw authorization or session headers; authentication must be mediated."""
        for k in headers:
            if k.lower() in ("authorization", "cookie", "proxy-authorization", "x-api-key"):
                raise ValueError(
                    f"PlanStep.headers must not contain raw authentication header '{k}'. "
                    f"Authentication must be mediated via credential references."
                )
        return headers


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
    fixture_setup_approved: bool = False
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

        # 3a. Synthetic fixture setup approval requirement
        has_setup_mutation = any(
            step.phase == PlanPhase.SETUP and step.method in ("POST", "PUT", "PATCH", "DELETE")
            for step in self.steps
        )
        if has_setup_mutation and not self.fixture_setup_approved:
            raise ValueError(
                "Plan contains synthetic fixture setup operations (POST/PUT/PATCH/DELETE) but "
                "fixture_setup_approved is False. Explicit approval is required for fixture setup."
            )

        # 3b. Security probe mutation approval requirement
        has_probe_mutation = any(
            step.requires_mutation_approval or (
                step.phase == PlanPhase.PROBE and step.method in ("POST", "PUT", "PATCH", "DELETE")
            )
            for step in self.steps
        )
        if has_probe_mutation and not self.synthetic_mutation_approved:
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

        # 5. Negative control tenant & credential binding consistency
        for ctrl in self.negative_controls:
            if ctrl.actor_tenant_id not in allowed_credentials:
                raise ValueError(
                    f"Negative control '{ctrl.control_id}' references unknown actor tenant '{ctrl.actor_tenant_id}'. "
                    f"Must be '{self.attacker_tenant_id}' or '{self.victim_tenant_id}'."
                )
            expected_cred = allowed_credentials[ctrl.actor_tenant_id]
            if ctrl.credential_ref != expected_cred:
                raise ValueError(
                    f"Negative control '{ctrl.control_id}' credential_ref '{ctrl.credential_ref}' "
                    f"does not match bound credential '{expected_cred}' for tenant '{ctrl.actor_tenant_id}'."
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
        fixture_setup_approved: bool = True,
        synthetic_mutation_approved: bool = False,
        seed: Optional[str] = None,
        ttl_minutes: int = 60,
        tampering_mode: str = "amount",
        tampered_amount_minor_units: int = 100,
        tampered_currency: str = "IDR",
    ) -> AttackPlan:
        """Compiles a fully validated AttackPlan with typed endpoint parsing and exact canary digests."""
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
                if hypothesis.target_endpoint.endpoint_id.count(":") >= 2
                else f"travel_api:canonical:{hypothesis.target_endpoint.method}:{hypothesis.target_endpoint.path_template}"
            )
            attacker_tenant = hypothesis.attacker_tenant_id
            victim_tenant = hypothesis.victim_tenant_id

        # Typed parsing of canonical endpoint identity (safely handles origins with colons and ports)
        parsed_ep = ParsedEndpointIdentity.parse(endpoint_id)
        route_template = parsed_ep.route_template
        method = parsed_ep.method

        # Extract dynamic resource identifier parameter from route template (e.g. {booking_id}, {hold_id}, {reservation_id})
        route_params = re.findall(r"\{([a-zA-Z0-9_]+)\}", route_template)
        resource_param = route_params[0] if route_params else "booking_id"

        # Generate exact canary token and digest
        if inv_type == InvariantType.TENANT_ISOLATION:
            if seed:
                canary_token = hashlib.sha256(f"canary:{seed}:{hyp_id}".encode("utf-8")).hexdigest()[:16]
            else:
                canary_token = secrets.token_hex(16)
            canary_value = f"CANARY_TOKEN_{canary_token}"
            canary_digest = hashlib.sha256(canary_value.encode("utf-8")).hexdigest()
        else:
            canary_value = ""
            canary_digest = ""

        # Plan ID generation: deterministic when seed is provided, unique nonce when seed is None
        if seed:
            execution_key = f"seed:{seed}"
        else:
            execution_key = f"nonce:{secrets.token_hex(8)}"

        plan_hash = hashlib.sha256(
            f"{hyp_id}:{endpoint_id}:{execution_key}:{canary_digest}".encode("utf-8")
        ).hexdigest()[:12]
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

        if inv_type == InvariantType.TENANT_ISOLATION:
            canary_id = f"canary_{plan_hash[:8]}"
            canary_secret_ref = f"canary_secret:{canary_id}"

            # Store exact plaintext value in protected execution-time store
            CanarySecretStore.store_secret(canary_secret_ref, canary_value)

            canary_spec = CanarySpec(
                canary_id=canary_id,
                owner_tenant_id=victim_tenant,
                object_type="booking",
                canary_key="passenger_name",
                canary_value_digest=canary_digest,
                canary_secret_ref=canary_secret_ref,
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
                # Step 1: SETUP - Agency A creates synthetic canary booking (captures victim_booking_id)
                PlanStep(
                    step_id="step_1_create_victim_canary",
                    name="Provision Synthetic Canary Booking (Victim)",
                    phase=PlanPhase.SETUP,
                    method="POST",
                    target_endpoint_identity="travel_api:canonical:POST:/api/v2/bookings",
                    endpoint_route_template="/api/v2/bookings",
                    actor_tenant_id=victim_tenant,
                    credential_ref=victim_credential_ref,
                    parameters={"passenger_name": canary_value},
                    body={"passenger_name": canary_value, "metadata": {"canary_id": canary_id}},
                    expected_status_baseline=200,
                    is_critical=True,
                    output_bindings=[
                        OutputBinding(source_field="booking_id", context_variable="victim_booking_id")
                    ],
                ),
                # Step 2: SETUP - Agency B provisions its own legitimate fixture booking (captures attacker_booking_id)
                PlanStep(
                    step_id="step_2_create_attacker_fixture",
                    name="Provision Legitimate Fixture Booking (Attacker)",
                    phase=PlanPhase.SETUP,
                    method="POST",
                    target_endpoint_identity="travel_api:canonical:POST:/api/v2/bookings",
                    endpoint_route_template="/api/v2/bookings",
                    actor_tenant_id=attacker_tenant,
                    credential_ref=attacker_credential_ref,
                    parameters={"passenger_name": "Legitimate Attacker Passenger"},
                    body={"passenger_name": "Legitimate Attacker Passenger", "metadata": {"fixture": True}},
                    expected_status_baseline=200,
                    is_critical=True,
                    output_bindings=[
                        OutputBinding(source_field="booking_id", context_variable="attacker_booking_id")
                    ],
                ),
                # Step 3: NEGATIVE_CONTROL - Agency A reads its own canary booking
                PlanStep(
                    step_id="step_3_negative_control_victim_read",
                    name="Verify Legitimate Access (Victim Negative Control)",
                    phase=PlanPhase.NEGATIVE_CONTROL,
                    method="GET",
                    target_endpoint_identity="travel_api:canonical:GET:/api/v2/bookings/{booking_id}",
                    endpoint_route_template="/api/v2/bookings/{booking_id}",
                    actor_tenant_id=victim_tenant,
                    credential_ref=victim_credential_ref,
                    parameters={"booking_id": "$victim_booking_id"},
                    expected_status_baseline=200,
                    is_critical=True,
                ),
                # Step 4: NEGATIVE_CONTROL - Agency B reads its own booking
                PlanStep(
                    step_id="step_4_negative_control_attacker_read",
                    name="Verify Attacker Identity Health (Attacker Negative Control)",
                    phase=PlanPhase.NEGATIVE_CONTROL,
                    method="GET",
                    target_endpoint_identity="travel_api:canonical:GET:/api/v2/bookings/{booking_id}",
                    endpoint_route_template="/api/v2/bookings/{booking_id}",
                    actor_tenant_id=attacker_tenant,
                    credential_ref=attacker_credential_ref,
                    parameters={"booking_id": "$attacker_booking_id"},
                    expected_status_baseline=200,
                    is_critical=True,
                ),
                # Step 5: PROBE - Agency B requests Agency A's booking
                PlanStep(
                    step_id="step_5_cross_tenant_probe",
                    name="Execute Cross-Tenant Read Probe",
                    phase=PlanPhase.PROBE,
                    method="GET",
                    target_endpoint_identity=endpoint_id,
                    endpoint_route_template=route_template,
                    actor_tenant_id=attacker_tenant,
                    credential_ref=attacker_credential_ref,
                    parameters={resource_param: "$victim_booking_id"},
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
                fixture_setup_approved=fixture_setup_approved,
                synthetic_mutation_approved=synthetic_mutation_approved,
                expires_at=expires_at,
            )

        elif inv_type == InvariantType.PRICING_INTEGRITY:
            preconditions = [
                PlanPrecondition(
                    precondition_id=f"prec_{plan_hash[:6]}_search_endpoint",
                    description="Pricing search endpoint must be registered in inventory.",
                    target_entity="travel_api:canonical:POST:/api/v2/search",
                    required_state="REGISTERED",
                ),
                PlanPrecondition(
                    precondition_id=f"prec_{plan_hash[:6]}_holds_endpoint",
                    description="Inventory hold endpoint must be registered in inventory.",
                    target_entity="travel_api:canonical:POST:/api/v2/holds",
                    required_state="REGISTERED",
                ),
                PlanPrecondition(
                    precondition_id=f"prec_{plan_hash[:6]}_bookings_endpoint",
                    description="Booking creation endpoint must be registered in inventory.",
                    target_entity="travel_api:canonical:POST:/api/v2/bookings",
                    required_state="REGISTERED",
                ),
            ]

            negative_controls = [
                NegativeControl(
                    control_id=f"ctrl_{plan_hash[:6]}_baseline_quote_validity",
                    description="Untampered booking request must succeed at server quote price.",
                    actor_tenant_id=attacker_tenant,
                    credential_ref=attacker_credential_ref,
                    expected_status_code=200,
                    assertion_rule="Server-authoritative quote price must be accepted without tampering.",
                )
            ]

            probe_body = (
                {
                    "hold_token": "$tamper_hold_token",
                    "client_amount_minor_units": 1800000,
                    "client_currency": tampered_currency,
                    "passenger_name": "Currency Tamperer",
                    "passenger_passport": "P1234567",
                }
                if tampering_mode == "currency"
                else {
                    "hold_token": "$tamper_hold_token",
                    "client_amount_minor_units": tampered_amount_minor_units,
                    "client_currency": "INR",
                    "passenger_name": "Price Tamperer",
                    "passenger_passport": "P1234567",
                }
            )

            steps = [
                # Step 1: Discover Authoritative Server Quote via Search
                PlanStep(
                    step_id="step_1_search_quote",
                    name="Query Authoritative Quotes via Search",
                    phase=PlanPhase.SETUP,
                    method="POST",
                    target_endpoint_identity="travel_api:canonical:POST:/api/v2/search",
                    endpoint_route_template="/api/v2/search",
                    actor_tenant_id=attacker_tenant,
                    credential_ref=attacker_credential_ref,
                    body={"destination": "GOA", "check_in": "2026-12-01", "nights": 2},
                    expected_status_baseline=200,
                    is_critical=True,
                    output_bindings=[
                        OutputBinding(source_field="quote_id", context_variable="baseline_quote_id"),
                        OutputBinding(source_field="amount_minor_units", context_variable="baseline_amount"),
                        OutputBinding(source_field="currency", context_variable="baseline_currency"),
                        OutputBinding(source_field="expires_at", context_variable="baseline_expires_at"),
                    ],
                ),
                # Step 2: Acquire Baseline Inventory Hold
                PlanStep(
                    step_id="step_2_acquire_baseline_hold",
                    name="Acquire Baseline Inventory Hold",
                    phase=PlanPhase.SETUP,
                    method="POST",
                    target_endpoint_identity="travel_api:canonical:POST:/api/v2/holds",
                    endpoint_route_template="/api/v2/holds",
                    actor_tenant_id=attacker_tenant,
                    credential_ref=attacker_credential_ref,
                    parameters={"quote_id": "$baseline_quote_id"},
                    body={"quote_id": "$baseline_quote_id"},
                    expected_status_baseline=200,
                    is_critical=True,
                    output_bindings=[
                        OutputBinding(source_field="hold_token", context_variable="baseline_hold_token")
                    ],
                ),
                # Step 3: Verify Untampered Baseline Booking (Negative Control)
                PlanStep(
                    step_id="step_3_negative_control_untampered_booking",
                    name="Verify Untampered Authoritative Booking",
                    phase=PlanPhase.NEGATIVE_CONTROL,
                    method="POST",
                    target_endpoint_identity="travel_api:canonical:POST:/api/v2/bookings",
                    endpoint_route_template="/api/v2/bookings",
                    actor_tenant_id=attacker_tenant,
                    credential_ref=attacker_credential_ref,
                    parameters={"hold_token": "$baseline_hold_token"},
                    body={
                        "hold_token": "$baseline_hold_token",
                        "passenger_name": "Legitimate Price Verifier",
                        "passenger_passport": "P1234567",
                    },
                    expected_status_baseline=200,
                    is_critical=True,
                    output_bindings=[
                        OutputBinding(source_field="booking_id", context_variable="baseline_booking_id"),
                        OutputBinding(source_field="amount_minor_units", context_variable="confirmed_baseline_amount"),
                        OutputBinding(source_field="currency", context_variable="confirmed_baseline_currency"),
                    ],
                ),
                # Step 4: Acquire Fresh Hold for Tamper Probe (Prevents Reused Hold Tokens)
                PlanStep(
                    step_id="step_4_acquire_tamper_hold",
                    name="Acquire Fresh Inventory Hold for Tampering Probe",
                    phase=PlanPhase.SETUP,
                    method="POST",
                    target_endpoint_identity="travel_api:canonical:POST:/api/v2/holds",
                    endpoint_route_template="/api/v2/holds",
                    actor_tenant_id=attacker_tenant,
                    credential_ref=attacker_credential_ref,
                    parameters={"quote_id": "$baseline_quote_id"},
                    body={"quote_id": "$baseline_quote_id"},
                    expected_status_baseline=200,
                    is_critical=True,
                    output_bindings=[
                        OutputBinding(source_field="hold_token", context_variable="tamper_hold_token")
                    ],
                ),
                # Step 5: Execute Client Pricing/Currency Tampering Probe
                PlanStep(
                    step_id="step_5_price_tampering_probe",
                    name=f"Execute Client-Controlled {tampering_mode.title()} Tampering Probe",
                    phase=PlanPhase.PROBE,
                    method="POST",
                    target_endpoint_identity=endpoint_id,
                    endpoint_route_template=route_template,
                    actor_tenant_id=attacker_tenant,
                    credential_ref=attacker_credential_ref,
                    parameters={"hold_token": "$tamper_hold_token"},
                    body=probe_body,
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
                fixture_setup_approved=fixture_setup_approved,
                synthetic_mutation_approved=synthetic_mutation_approved,
                expires_at=expires_at,
            )

        else:
            raise NotImplementedError(f"Plan compilation for invariant '{inv_type}' is not yet supported.")
