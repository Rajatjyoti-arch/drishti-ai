"""Unit and acceptance tests for typed AttackPlan schemas and AttackPlanCompiler."""

import json
import pytest
from pydantic import ValidationError

from drishti.core.models import InvariantType
from drishti.executors.attack_plan import (
    AttackPlan,
    AttackPlanCompiler,
    CanarySpec,
    CredentialBinding,
    ExecutionBudget,
    NegativeControl,
    PlanPhase,
    PlanPrecondition,
    PlanStep,
)
from drishti.graph.schema import HypothesisNode


def test_plan_strict_schema_rejects_unknown_fields():
    """Verify that all plan models reject arbitrary unknown fields (extra='forbid')."""
    # 1. CredentialBinding
    with pytest.raises(ValidationError):
        CredentialBinding(
            tenant_id="agency_a",
            role="admin",
            credential_ref="cred:agency_a:admin",
            unexpected_field="disallowed",
        )

    # 2. ExecutionBudget
    with pytest.raises(ValidationError):
        ExecutionBudget(max_requests=5, rogue_limit=999)

    # 3. PlanPrecondition
    with pytest.raises(ValidationError):
        PlanPrecondition(
            precondition_id="p1",
            description="test",
            target_entity="ent",
            required_state="OK",
            unknown_attr="fail",
        )

    # 4. CanarySpec
    with pytest.raises(ValidationError):
        CanarySpec(
            canary_id="c1",
            owner_tenant_id="agency_a",
            canary_value_digest="a" * 64,
            extra_token="leak",
        )

    # 5. PlanStep
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
    # Mismatched attacker credential tenant
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

    # Identical attacker and victim tenants
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


def test_credential_secrecy_rejects_raw_tokens_and_passwords():
    """Verify that raw JWT tokens, API keys, and passwords are strictly rejected as credential_ref."""
    raw_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG4B"
    with pytest.raises(ValidationError, match="must be an opaque reference ID, not a raw credential"):
        CredentialBinding(tenant_id="agency_a", credential_ref=raw_jwt)

    with pytest.raises(ValidationError, match="must be an opaque reference ID, not a raw credential"):
        CredentialBinding(tenant_id="agency_a", credential_ref="sk-live-1234567890abcdef")

    with pytest.raises(ValidationError, match="must be an opaque reference ID, not a raw credential"):
        CredentialBinding(tenant_id="agency_a", credential_ref="Bearer secret_token")


def test_endpoint_binding_and_step_consistency():
    """Verify that steps referencing an unregistered tenant or mismatched credential are rejected."""
    attacker_cred = CredentialBinding(tenant_id="agency_b", credential_ref="cred:agency_b:admin")
    victim_cred = CredentialBinding(tenant_id="agency_a", credential_ref="cred:agency_a:admin")

    # Step with unknown tenant
    step_bad_tenant = PlanStep(
        step_id="step_rogue",
        name="Rogue Step",
        phase=PlanPhase.PROBE,
        method="GET",
        target_endpoint_identity="travel_api:canonical:GET:/api/v2/bookings/{booking_id}",
        endpoint_route_template="/api/v2/bookings/{booking_id}",
        actor_tenant_id="agency_rogue",
        credential_ref="cred:agency_b:admin",
    )

    with pytest.raises(ValidationError, match="references unknown actor tenant"):
        AttackPlan(
            plan_id="PLAN-003",
            hypothesis_id="HYP-003",
            invariant_id=InvariantType.TENANT_ISOLATION,
            target_endpoint_identity="travel_api:canonical:GET:/api/v2/bookings/{booking_id}",
            attacker_tenant_id="agency_b",
            victim_tenant_id="agency_a",
            attacker_credential=attacker_cred,
            victim_credential=victim_cred,
            steps=[step_bad_tenant],
            expires_at="2027-01-01T00:00:00Z",
        )

    # Step with credential belonging to other tenant
    step_swapped_cred = PlanStep(
        step_id="step_swapped",
        name="Swapped Cred Step",
        phase=PlanPhase.PROBE,
        method="GET",
        target_endpoint_identity="travel_api:canonical:GET:/api/v2/bookings/{booking_id}",
        endpoint_route_template="/api/v2/bookings/{booking_id}",
        actor_tenant_id="agency_b",
        credential_ref="cred:agency_a:admin",  # Swapped!
    )

    with pytest.raises(ValidationError, match="does not match bound credential"):
        AttackPlan(
            plan_id="PLAN-004",
            hypothesis_id="HYP-004",
            invariant_id=InvariantType.TENANT_ISOLATION,
            target_endpoint_identity="travel_api:canonical:GET:/api/v2/bookings/{booking_id}",
            attacker_tenant_id="agency_b",
            victim_tenant_id="agency_a",
            attacker_credential=attacker_cred,
            victim_credential=victim_cred,
            steps=[step_swapped_cred],
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

    # Without approval -> raises ValidationError
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

    # With approval -> succeeds
    plan = AttackPlan(
        plan_id="PLAN-005",
        hypothesis_id="HYP-005",
        invariant_id=InvariantType.TENANT_ISOLATION,
        target_endpoint_identity="travel_api:canonical:PATCH:/api/v2/bookings/{booking_id}",
        attacker_tenant_id="agency_b",
        victim_tenant_id="agency_a",
        attacker_credential=attacker_cred,
        victim_credential=victim_cred,
        steps=[mutating_step],
        synthetic_mutation_approved=True,
        expires_at="2027-01-01T00:00:00Z",
    )
    assert plan.synthetic_mutation_approved is True


def test_compile_i01_plan_reproducibility_and_structure():
    """Verify that compiling an I-01 hypothesis with a seed produces deterministic, complete plans."""
    hyp = HypothesisNode(
        node_id="hyp:test_i01",
        hypothesis_id="HYP-I01-BOOKING-001",
        invariant_id=InvariantType.TENANT_ISOLATION.value,
        target_endpoint_identity="travel_api:canonical:GET:/api/v2/bookings/{booking_id}",
        attacker_tenant_id="agency_b",
        victim_tenant_id="agency_a",
        rationale="Cross-tenant access to booking resource",
    )

    plan_1 = AttackPlanCompiler.compile_plan(
        hypothesis=hyp,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        seed="deterministic_run_1",
    )
    plan_2 = AttackPlanCompiler.compile_plan(
        hypothesis=hyp,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        seed="deterministic_run_1",
    )

    # Reproducible plan ID
    assert plan_1.plan_id == plan_2.plan_id
    assert plan_1.plan_id.startswith("PLAN-")

    # Invariant and endpoint binding
    assert plan_1.invariant_id == InvariantType.TENANT_ISOLATION
    assert plan_1.target_endpoint_identity == "travel_api:canonical:GET:/api/v2/bookings/{booking_id}"

    # Canary spec generated with SHA-256 digest
    assert plan_1.canary_spec is not None
    assert plan_1.canary_spec.owner_tenant_id == "agency_a"
    assert len(plan_1.canary_spec.canary_value_digest) == 64

    # Preconditions and Negative Controls
    assert len(plan_1.preconditions) == 2
    assert len(plan_1.negative_controls) == 2
    assert any("Victim" in c.description for c in plan_1.negative_controls)
    assert any("Attacker" in c.description for c in plan_1.negative_controls)

    # 4 Ordered steps: Setup -> Negative Control (Victim) -> Negative Control (Attacker) -> Probe
    assert len(plan_1.steps) == 4
    assert plan_1.steps[0].phase == PlanPhase.SETUP
    assert plan_1.steps[1].phase == PlanPhase.NEGATIVE_CONTROL
    assert plan_1.steps[2].phase == PlanPhase.NEGATIVE_CONTROL
    assert plan_1.steps[3].phase == PlanPhase.PROBE

    # Serialized plan contains NO raw secret
    dump = json.loads(plan_1.model_dump_json())
    assert dump["attacker_credential"]["credential_ref"] == "cred:agency_b:admin"
    assert "eyJ" not in plan_1.model_dump_json()


def test_compile_i02_plan_pricing():
    """Verify that compiling an I-02 pricing integrity hypothesis produces valid multi-phase plans."""
    hyp = HypothesisNode(
        node_id="hyp:test_i02",
        hypothesis_id="HYP-I02-CHECKOUT-001",
        invariant_id=InvariantType.PRICING_INTEGRITY.value,
        target_endpoint_identity="travel_api:canonical:POST:/api/v2/bookings",
        attacker_tenant_id="agency_b",
        victim_tenant_id="agency_a",
        rationale="Client-controlled pricing tampering on checkout",
    )

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hyp,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        synthetic_mutation_approved=True,
    )

    assert plan.invariant_id == InvariantType.PRICING_INTEGRITY
    assert len(plan.steps) == 3
    # Step 1: Hold setup
    assert plan.steps[0].phase == PlanPhase.SETUP
    # Step 2: Quote negative control
    assert plan.steps[1].phase == PlanPhase.NEGATIVE_CONTROL
    # Step 3: Tampered amount probe
    assert plan.steps[2].phase == PlanPhase.PROBE
    assert plan.steps[2].body["client_amount_minor_units"] == 100
