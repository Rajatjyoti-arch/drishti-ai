"""Unit and acceptance tests for typed AttackPlan schemas, endpoint parsing, and compiler."""

import hashlib
import json
import pytest
from pydantic import ValidationError

from drishti.core.models import InvariantType
from drishti.executors.attack_plan import (
    AttackPlan,
    AttackPlanCompiler,
    CanarySecretStore,
    CanarySpec,
    CredentialBinding,
    ExecutionBudget,
    NegativeControl,
    OutputBinding,
    ParsedEndpointIdentity,
    PlanPhase,
    PlanPrecondition,
    PlanStep,
)
from drishti.graph.schema import HypothesisNode


def test_endpoint_identity_parsing_http_and_https_with_ports():
    """Verify that canonical endpoint identities with HTTPS origins and ports parse correctly."""
    # 1. HTTPS origin with custom port and parameter
    ep1 = "mock_travel_api:https://booking.tbo.com:8443:GET:/api/v1/bookings/{booking_id}"
    parsed1 = ParsedEndpointIdentity.parse(ep1)
    assert parsed1.asset_id == "mock_travel_api"
    assert parsed1.origin == "https://booking.tbo.com:8443"
    assert parsed1.method == "GET"
    assert parsed1.route_template == "/api/v1/bookings/{booking_id}"

    # 2. HTTP origin with localhost port
    ep2 = "travel_api:http://localhost:8000:POST:/api/v2/holds"
    parsed2 = ParsedEndpointIdentity.parse(ep2)
    assert parsed2.asset_id == "travel_api"
    assert parsed2.origin == "http://localhost:8000"
    assert parsed2.method == "POST"
    assert parsed2.route_template == "/api/v2/holds"

    # 3. Canonical asset origin
    ep3 = "travel_api:canonical:GET:/api/v2/bookings"
    parsed3 = ParsedEndpointIdentity.parse(ep3)
    assert parsed3.asset_id == "travel_api"
    assert parsed3.origin == "canonical"
    assert parsed3.method == "GET"
    assert parsed3.route_template == "/api/v2/bookings"

    # 4. Invalid endpoint formats rejected
    with pytest.raises(ValueError):
        ParsedEndpointIdentity.parse("invalid_endpoint")
    with pytest.raises(ValueError):
        ParsedEndpointIdentity.parse("asset:origin:INVALIDMETHOD:/route")
    with pytest.raises(ValueError):
        ParsedEndpointIdentity.parse("asset:origin:GET:no_slash_route")


def test_plan_strict_schema_rejects_unknown_fields():
    """Verify that all plan models reject arbitrary unknown fields (extra='forbid')."""
    with pytest.raises(ValidationError):
        CredentialBinding(
            tenant_id="agency_a",
            role="admin",
            credential_ref="cred:agency_a:admin",
            unexpected_field="disallowed",
        )

    with pytest.raises(ValidationError):
        ExecutionBudget(max_requests=5, rogue_limit=999)

    with pytest.raises(ValidationError):
        PlanPrecondition(
            precondition_id="p1",
            description="test",
            target_entity="ent",
            required_state="OK",
            unknown_attr="fail",
        )

    with pytest.raises(ValidationError):
        CanarySpec(
            canary_id="c1",
            owner_tenant_id="agency_a",
            canary_value_digest="a" * 64,
            canary_secret_ref="canary_secret:c1",
            extra_token="leak",
        )

    with pytest.raises(ValidationError):
        PlanStep(
            step_id="s1",
            name="Step 1",
            phase=PlanPhase.PROBE,
            method="GET",
            target_endpoint_identity="ep:1",
            endpoint_route_template="/test",
            actor_tenant_id="agency_a",
            credential_ref="cred:agency_a:admin",
            arbitrary_payload="disallowed",
        )


def test_tenant_binding_rejects_interchanged_credentials():
    """Verify that attacker and victim credentials cannot be interchanged or mismatched."""
    with pytest.raises(ValidationError, match="Attacker credential tenant"):
        AttackPlan(
            plan_id="PLAN-001",
            hypothesis_id="HYP-001",
            invariant_id=InvariantType.TENANT_ISOLATION,
            target_endpoint_identity="travel_api:canonical:GET:/api/v2/bookings/{booking_id}",
            attacker_tenant_id="agency_b",
            victim_tenant_id="agency_a",
            attacker_credential=CredentialBinding(tenant_id="agency_a", role="admin", credential_ref="cred:a:admin"),
            victim_credential=CredentialBinding(tenant_id="agency_a", role="admin", credential_ref="cred:a:admin"),
            expires_at="2027-01-01T00:00:00Z",
        )

    with pytest.raises(ValidationError, match="must be distinct"):
        AttackPlan(
            plan_id="PLAN-002",
            hypothesis_id="HYP-002",
            invariant_id=InvariantType.TENANT_ISOLATION,
            target_endpoint_identity="travel_api:canonical:GET:/api/v2/bookings/{booking_id}",
            attacker_tenant_id="agency_a",
            victim_tenant_id="agency_a",
            attacker_credential=CredentialBinding(tenant_id="agency_a", role="admin", credential_ref="cred:a:admin"),
            victim_credential=CredentialBinding(tenant_id="agency_a", role="admin", credential_ref="cred:a:admin"),
            expires_at="2027-01-01T00:00:00Z",
        )


def test_credential_secrecy_and_allowlist():
    """Verify that raw tokens are rejected and only allowed opaque references pass."""
    raw_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG4B"
    with pytest.raises(ValidationError, match="must be an opaque reference ID, not a raw credential"):
        CredentialBinding(tenant_id="agency_a", credential_ref=raw_jwt)

    with pytest.raises(ValidationError, match="must be an opaque reference ID, not a raw credential"):
        CredentialBinding(tenant_id="agency_a", credential_ref="sk-live-1234567890abcdef")

    with pytest.raises(ValidationError, match="must be an opaque reference ID, not a raw credential"):
        CredentialBinding(tenant_id="agency_a", credential_ref="Bearer secret_token")

    # Valid opaque references
    cred1 = CredentialBinding(tenant_id="agency_a", credential_ref="cred:agency_a:admin")
    assert cred1.credential_ref == "cred:agency_a:admin"

    cred2 = CredentialBinding(tenant_id="agency_b", credential_ref="mock_jwt_agency_b_admin_token")
    assert cred2.credential_ref == "mock_jwt_agency_b_admin_token"


def test_plan_step_headers_reject_raw_authentication():
    """Verify that PlanStep.headers prohibits raw authorization headers or cookies."""
    with pytest.raises(ValidationError, match="must not contain raw authentication header"):
        PlanStep(
            step_id="step_auth_leak",
            name="Auth Leak Step",
            phase=PlanPhase.PROBE,
            method="GET",
            target_endpoint_identity="ep:1",
            endpoint_route_template="/test",
            actor_tenant_id="agency_b",
            credential_ref="cred:agency_b:admin",
            headers={"Authorization": "Bearer leaked_token"},
        )

    with pytest.raises(ValidationError, match="must not contain raw authentication header"):
        PlanStep(
            step_id="step_cookie_leak",
            name="Cookie Leak Step",
            phase=PlanPhase.PROBE,
            method="GET",
            target_endpoint_identity="ep:1",
            endpoint_route_template="/test",
            actor_tenant_id="agency_b",
            credential_ref="cred:agency_b:admin",
            headers={"Cookie": "session=123"},
        )


def test_negative_control_credential_validation():
    """Verify that negative controls are validated against their declared actor tenant and plan credentials."""
    attacker_cred = CredentialBinding(tenant_id="agency_b", credential_ref="cred:agency_b:admin")
    victim_cred = CredentialBinding(tenant_id="agency_a", credential_ref="cred:agency_a:admin")

    # Control with unmapped tenant
    bad_ctrl_tenant = NegativeControl(
        control_id="ctrl_rogue",
        description="Rogue control",
        actor_tenant_id="agency_rogue",
        credential_ref="cred:agency_a:admin",
        assertion_rule="Must fail",
    )
    with pytest.raises(ValidationError, match="references unknown actor tenant"):
        AttackPlan(
            plan_id="PLAN-CTRL-1",
            hypothesis_id="HYP-CTRL-1",
            invariant_id=InvariantType.TENANT_ISOLATION,
            target_endpoint_identity="ep:1",
            attacker_tenant_id="agency_b",
            victim_tenant_id="agency_a",
            attacker_credential=attacker_cred,
            victim_credential=victim_cred,
            negative_controls=[bad_ctrl_tenant],
            expires_at="2027-01-01T00:00:00Z",
        )

    # Control with swapped credential
    bad_ctrl_cred = NegativeControl(
        control_id="ctrl_swapped",
        description="Swapped cred control",
        actor_tenant_id="agency_a",
        credential_ref="cred:agency_b:admin",  # Attacker cred for victim tenant!
        assertion_rule="Must fail",
    )
    with pytest.raises(ValidationError, match="does not match bound credential"):
        AttackPlan(
            plan_id="PLAN-CTRL-2",
            hypothesis_id="HYP-CTRL-2",
            invariant_id=InvariantType.TENANT_ISOLATION,
            target_endpoint_identity="ep:1",
            attacker_tenant_id="agency_b",
            victim_tenant_id="agency_a",
            attacker_credential=attacker_cred,
            victim_credential=victim_cred,
            negative_controls=[bad_ctrl_cred],
            expires_at="2027-01-01T00:00:00Z",
        )


def test_synthetic_mutation_approval_enforcement():
    """Verify that probe steps requiring mutation or with non-GET verbs fail without approval."""
    attacker_cred = CredentialBinding(tenant_id="agency_b", credential_ref="cred:agency_b:admin")
    victim_cred = CredentialBinding(tenant_id="agency_a", credential_ref="cred:agency_a:admin")

    mutating_step = PlanStep(
        step_id="step_probe_patch",
        name="Cross-Tenant Mutation Probe",
        phase=PlanPhase.PROBE,
        method="PATCH",
        target_endpoint_identity="travel_api:canonical:PATCH:/api/v2/bookings/{booking_id}",
        endpoint_route_template="/api/v2/bookings/{booking_id}",
        actor_tenant_id="agency_b",
        credential_ref="cred:agency_b:admin",
        requires_mutation_approval=True,
    )

    with pytest.raises(ValidationError, match="Explicit approval is required for synthetic mutations"):
        AttackPlan(
            plan_id="PLAN-005",
            hypothesis_id="HYP-005",
            invariant_id=InvariantType.TENANT_ISOLATION,
            target_endpoint_identity="travel_api:canonical:PATCH:/api/v2/bookings/{booking_id}",
            attacker_tenant_id="agency_b",
            victim_tenant_id="agency_a",
            attacker_credential=attacker_cred,
            victim_credential=victim_cred,
            steps=[mutating_step],
            synthetic_mutation_approved=False,
            expires_at="2027-01-01T00:00:00Z",
        )


def test_exact_canary_digest_verification_and_store():
    """Verify that the declared canary digest matches the exact canary value placed in synthetic booking."""
    hyp = HypothesisNode(
        node_id="hyp:test_i01",
        hypothesis_id="HYP-I01-CANARY-EXACT",
        invariant_id=InvariantType.TENANT_ISOLATION.value,
        target_endpoint_identity="travel_api:canonical:GET:/api/v2/bookings/{booking_id}",
        attacker_tenant_id="agency_b",
        victim_tenant_id="agency_a",
        rationale="Verify exact canary digest consistency",
    )

    plan = AttackPlanCompiler.compile_plan(hyp, seed="exact_canary_test")

    # Step 1 is victim canary setup
    step1 = plan.steps[0]
    assert step1.phase == PlanPhase.SETUP
    canary_value_in_body = step1.body["passenger_name"]

    # Compute digest of the exact value in the body
    computed_digest = hashlib.sha256(canary_value_in_body.encode("utf-8")).hexdigest()

    # Assert exact match with canary_spec.canary_value_digest
    assert plan.canary_spec is not None
    assert plan.canary_spec.canary_value_digest == computed_digest

    # Verify secret store has the exact value
    stored_secret = CanarySecretStore.get_secret(plan.canary_spec.canary_secret_ref)
    assert stored_secret == canary_value_in_body

    # Assert no unnecessary passport data is included
    assert "passenger_passport" not in step1.body


def test_distinct_plan_ids_for_nondeterministic_executions():
    """Verify that compiling without a seed produces distinct plan IDs and canaries, preventing collisions."""
    hyp = HypothesisNode(
        node_id="hyp:test_i01",
        hypothesis_id="HYP-I01-COLLISION-CHECK",
        invariant_id=InvariantType.TENANT_ISOLATION.value,
        target_endpoint_identity="travel_api:canonical:GET:/api/v2/bookings/{booking_id}",
        attacker_tenant_id="agency_b",
        victim_tenant_id="agency_a",
        rationale="Collision prevention check",
    )

    # 1. Non-deterministic compilation (seed=None) -> distinct plans and distinct canaries
    plan_a = AttackPlanCompiler.compile_plan(hyp, seed=None)
    plan_b = AttackPlanCompiler.compile_plan(hyp, seed=None)
    assert plan_a.plan_id != plan_b.plan_id
    assert plan_a.canary_spec.canary_id != plan_b.canary_spec.canary_id
    assert plan_a.canary_spec.canary_value_digest != plan_b.canary_spec.canary_value_digest

    # 2. Deterministic compilation (seed="reproducible") -> identical plans and canaries
    plan_c1 = AttackPlanCompiler.compile_plan(hyp, seed="reproducible")
    plan_c2 = AttackPlanCompiler.compile_plan(hyp, seed="reproducible")
    assert plan_c1.plan_id == plan_c2.plan_id
    assert plan_c1.canary_spec.canary_id == plan_c2.canary_spec.canary_id
    assert plan_c1.canary_spec.canary_value_digest == plan_c2.canary_spec.canary_value_digest


def test_setup_output_binding_for_two_tenant_fixtures():
    """Verify that I-01 compiler sets up output capture for both victim and attacker fixtures."""
    hyp = HypothesisNode(
        node_id="hyp:test_i01",
        hypothesis_id="HYP-I01-FIXTURES-001",
        invariant_id=InvariantType.TENANT_ISOLATION.value,
        target_endpoint_identity="mock_travel_api:https://travel.api:GET:/api/v2/bookings/{booking_id}",
        attacker_tenant_id="agency_b",
        victim_tenant_id="agency_a",
        rationale="Dual tenant fixture verification",
    )

    plan = AttackPlanCompiler.compile_plan(hyp, seed="dual_fixture_seed")

    # 5 Total steps
    assert len(plan.steps) == 5

    # Step 1: SETUP Victim -> captures victim_booking_id
    s1 = plan.steps[0]
    assert s1.phase == PlanPhase.SETUP
    assert s1.actor_tenant_id == "agency_a"
    assert len(s1.output_bindings) == 1
    assert s1.output_bindings[0].context_variable == "victim_booking_id"

    # Step 2: SETUP Attacker -> captures attacker_booking_id
    s2 = plan.steps[1]
    assert s2.phase == PlanPhase.SETUP
    assert s2.actor_tenant_id == "agency_b"
    assert len(s2.output_bindings) == 1
    assert s2.output_bindings[0].context_variable == "attacker_booking_id"

    # Step 3: NEGATIVE_CONTROL Victim reads victim_booking_id
    s3 = plan.steps[2]
    assert s3.phase == PlanPhase.NEGATIVE_CONTROL
    assert s3.actor_tenant_id == "agency_a"
    assert s3.parameters["booking_id"] == "$victim_booking_id"

    # Step 4: NEGATIVE_CONTROL Attacker reads attacker_booking_id
    s4 = plan.steps[3]
    assert s4.phase == PlanPhase.NEGATIVE_CONTROL
    assert s4.actor_tenant_id == "agency_b"
    assert s4.parameters["booking_id"] == "$attacker_booking_id"

    # Step 5: PROBE Attacker requests victim_booking_id
    s5 = plan.steps[4]
    assert s5.phase == PlanPhase.PROBE
    assert s5.actor_tenant_id == "agency_b"
    assert s5.parameters["booking_id"] == "$victim_booking_id"
