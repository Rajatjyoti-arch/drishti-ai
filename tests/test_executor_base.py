"""Unit and acceptance tests for ISpecialistExecutor base contract, budgets, and safety boundaries."""

import hashlib
import json
import pytest
from unittest.mock import AsyncMock, MagicMock
import httpx

from drishti.core.exceptions import PolicyViolationError
from drishti.core.models import (
    AttackHypothesis,
    CandidateFinding,
    ExecutionResult,
    InferredEndpoint,
    InvariantType,
    OutgoingTestRequest,
    PolicyAction,
    PolicyDecision,
    VerificationStatus,
    VerifiedFinding,
)
from drishti.executors.attack_plan import (
    AttackPlan,
    AttackPlanCompiler,
    CredentialBinding,
    ExecutionBudget,
    PlanPhase,
    PlanStep,
)
from drishti.executors.base import (
    BudgetExhaustedError,
    ExecutionCancelledError,
    ISpecialistExecutor,
    redact_and_bound_evidence,
)
from drishti.graph.schema import HypothesisNode
from drishti.policy.client import SafeHttpClient


class DummyI01Executor(ISpecialistExecutor):
    """Concrete specialist executor testing I-01 tenant isolation contracts."""
    supported_invariant = InvariantType.TENANT_ISOLATION

    async def execute(self, plan: AttackPlan) -> CandidateFinding:
        self.check_plan_supported(plan)
        self.check_preconditions(plan)

        # Execute steps
        last_resp = None
        for step in plan.steps:
            resolved_url = f"http://test.local{step.endpoint_route_template}"
            resp, exec_res = await self.send_guarded_request(plan, step, resolved_url)
            last_resp = resp

        # Construct candidate finding
        inferred_ep = InferredEndpoint(
            endpoint_id="ep_test",
            method=plan.steps[-1].method,
            path_template=plan.steps[-1].endpoint_route_template,
            auth_required=True,
            roles_observed=["admin"],
            parameters={},
            source_har_request_id="har_1",
            raw_packet_hash="hash_1",
            confidence_score=0.95,
        )
        hyp = AttackHypothesis(
            hypothesis_id=plan.hypothesis_id,
            target_endpoint=inferred_ep,
            invariant_targeted=plan.invariant_id,
            rationale="Test candidate",
            test_strategy="Probe",
            attacker_tenant_id=plan.attacker_tenant_id,
            victim_tenant_id=plan.victim_tenant_id,
        )
        return CandidateFinding(
            candidate_id=f"cand_{plan.plan_id}",
            hypothesis=hyp,
            observed_status_code=last_resp.status_code if last_resp else 500,
            raw_response_snippet=last_resp.text if last_resp else "",
        )


class DummyI02Executor(ISpecialistExecutor):
    """Concrete specialist executor testing I-02 pricing integrity contracts."""
    supported_invariant = InvariantType.PRICING_INTEGRITY

    async def execute(self, plan: AttackPlan) -> CandidateFinding:
        self.check_plan_supported(plan)
        return MagicMock(spec=CandidateFinding)


@pytest.fixture
def mock_safe_http_client():
    client = MagicMock(spec=SafeHttpClient)
    # Return mock HTTP 200 response
    resp = httpx.Response(
        status_code=200,
        headers={"content-type": "application/json"},
        text='{"status": "ok", "passenger_name": "Canary Passenger", "passport": "Z1234567"}',
        request=httpx.Request("GET", "http://test.local/api/v2/bookings/1"),
    )
    client.send_request = AsyncMock(return_value=resp)
    return client


def test_invariant_binding_rejects_mismatched_plan(mock_safe_http_client):
    """Verify that an I-01 executor strictly rejects an I-02 plan with ValueError."""
    executor = DummyI01Executor(http_client=mock_safe_http_client)

    hyp_i02 = HypothesisNode(
        node_id="hyp:test_i02",
        hypothesis_id="HYP-I02-CHECKOUT-001",
        invariant_id=InvariantType.PRICING_INTEGRITY.value,
        target_endpoint_identity="travel_api:canonical:POST:/api/v2/bookings",
        attacker_tenant_id="agency_b",
        victim_tenant_id="agency_a",
        rationale="Client-controlled minor units tampering on checkout",
    )
    plan_i02 = AttackPlanCompiler.compile_plan(
        hypothesis=hyp_i02,
        synthetic_mutation_approved=True,
    )

    with pytest.raises(ValueError, match="supports 'I-01-TENANT-ISOLATION', cannot execute plan targeting 'I-02"):
        executor.check_plan_supported(plan_i02)


@pytest.mark.asyncio
async def test_budget_reservation_and_exhaustion(mock_safe_http_client):
    """Verify that request budget is reserved before execution and exhaustion prevents subsequent requests."""
    executor = DummyI01Executor(http_client=mock_safe_http_client, budget_limit=2)

    step = PlanStep(
        step_id="step_probe",
        name="Probe Step",
        phase=PlanPhase.PROBE,
        method="GET",
        target_endpoint_identity="ep:1",
        endpoint_route_template="/test",
        actor_tenant_id="agency_b",
        credential_ref="cred:b:admin",
    )
    plan = AttackPlan(
        plan_id="PLAN-BGT",
        hypothesis_id="HYP-BGT",
        invariant_id=InvariantType.TENANT_ISOLATION,
        target_endpoint_identity="ep:1",
        attacker_tenant_id="agency_b",
        victim_tenant_id="agency_a",
        attacker_credential=CredentialBinding(tenant_id="agency_b", credential_ref="cred:b:admin"),
        victim_credential=CredentialBinding(tenant_id="agency_a", credential_ref="cred:a:admin"),
        budget=ExecutionBudget(max_requests=2),
        steps=[step],
        expires_at="2027-01-01T00:00:00Z",
    )

    # 1st request -> ok
    await executor.send_guarded_request(plan, step, "http://test.local/test")
    assert executor.requests_executed == 1

    # 2nd request -> ok
    await executor.send_guarded_request(plan, step, "http://test.local/test")
    assert executor.requests_executed == 2

    # 3rd request -> BudgetExhaustedError raised; no HTTP dispatch occurs
    with pytest.raises(BudgetExhaustedError, match="budget exhausted: 2/2"):
        await executor.send_guarded_request(plan, step, "http://test.local/test")

    # Assert exactly 2 requests reached SafeHttpClient
    assert mock_safe_http_client.send_request.call_count == 2


@pytest.mark.asyncio
async def test_cancellation_emergency_stop_halts_execution(mock_safe_http_client):
    """Verify that triggering cancel() stops execution immediately before dispatch."""
    executor = DummyI01Executor(http_client=mock_safe_http_client)
    executor.cancel("Killswitch engaged")

    step = PlanStep(
        step_id="step_probe",
        name="Probe Step",
        phase=PlanPhase.PROBE,
        method="GET",
        target_endpoint_identity="ep:1",
        endpoint_route_template="/test",
        actor_tenant_id="agency_b",
        credential_ref="cred:b:admin",
    )
    plan = AttackPlan(
        plan_id="PLAN-STOP",
        hypothesis_id="HYP-STOP",
        invariant_id=InvariantType.TENANT_ISOLATION,
        target_endpoint_identity="ep:1",
        attacker_tenant_id="agency_b",
        victim_tenant_id="agency_a",
        attacker_credential=CredentialBinding(tenant_id="agency_b", credential_ref="cred:b:admin"),
        victim_credential=CredentialBinding(tenant_id="agency_a", credential_ref="cred:a:admin"),
        expires_at="2027-01-01T00:00:00Z",
    )

    with pytest.raises(ExecutionCancelledError, match="execution cancelled"):
        await executor.send_guarded_request(plan, step, "http://test.local/test")

    # HTTP client was never touched
    assert mock_safe_http_client.send_request.call_count == 0


@pytest.mark.asyncio
async def test_guard_denial_no_fallback_transport(mock_safe_http_client):
    """Verify that when PolicyGate denies a request, executor raises PolicyViolationError without fallback."""
    mock_safe_http_client.send_request.side_effect = PolicyViolationError(
        "Transport request REJECTED by Policy Gate [DENY]: Egress target out-of-scope"
    )
    executor = DummyI01Executor(http_client=mock_safe_http_client)

    step = PlanStep(
        step_id="step_denied",
        name="Denied Step",
        phase=PlanPhase.PROBE,
        method="GET",
        target_endpoint_identity="ep:1",
        endpoint_route_template="/test",
        actor_tenant_id="agency_b",
        credential_ref="cred:b:admin",
    )
    plan = AttackPlan(
        plan_id="PLAN-DENY",
        hypothesis_id="HYP-DENY",
        invariant_id=InvariantType.TENANT_ISOLATION,
        target_endpoint_identity="ep:1",
        attacker_tenant_id="agency_b",
        victim_tenant_id="agency_a",
        attacker_credential=CredentialBinding(tenant_id="agency_b", credential_ref="cred:b:admin"),
        victim_credential=CredentialBinding(tenant_id="agency_a", credential_ref="cred:a:admin"),
        expires_at="2027-01-01T00:00:00Z",
    )

    with pytest.raises(PolicyViolationError, match="REJECTED by Policy Gate"):
        await executor.send_guarded_request(plan, step, "http://malicious.external/test")


def test_evidence_redaction_and_bounding():
    """Verify that evidence capture bounds payload size and redacts credentials, bearer tokens, and PII."""
    raw_sensitive_body = (
        '{"status": "CONFIRMED", "auth_token": "secret_abc123", '
        '"passenger_passport": "Z9876543", "passenger_name": "Alice Smith"}'
    )
    snippet, digest = redact_and_bound_evidence(raw_sensitive_body, max_length=200)

    # Secret and passport are redacted
    assert "secret_abc123" not in snippet
    assert "[REDACTED]" in snippet
    assert "Z9876543" not in snippet
    assert "[REDACTED_PII]" in snippet

    # Digest matches raw body exactly
    expected_digest = hashlib.sha256(raw_sensitive_body.encode("utf-8")).hexdigest()
    assert digest == expected_digest

    # Long body is truncated
    long_body = "x" * 1000
    bounded_snippet, _ = redact_and_bound_evidence(long_body, max_length=100)
    assert len(bounded_snippet) < 150
    assert "[TRUNCATED_EVIDENCE]" in bounded_snippet


@pytest.mark.asyncio
async def test_finding_semantics_executor_emits_candidate_only(mock_safe_http_client):
    """Verify that executors emit CandidateFinding and cannot emit CONFIRMED or VerifiedFinding."""
    executor = DummyI01Executor(http_client=mock_safe_http_client)

    hyp = HypothesisNode(
        node_id="hyp:test_i01",
        hypothesis_id="HYP-I01-BOOKING-001",
        invariant_id=InvariantType.TENANT_ISOLATION.value,
        target_endpoint_identity="travel_api:canonical:GET:/api/v2/bookings/{booking_id}",
        attacker_tenant_id="agency_b",
        victim_tenant_id="agency_a",
        rationale="Cross-tenant read candidate verification",
    )
    plan = AttackPlanCompiler.compile_plan(hyp, seed="test_finding_semantics")

    finding = await executor.execute(plan)

    # Assert return type is CandidateFinding
    assert isinstance(finding, CandidateFinding)
    assert not isinstance(finding, VerifiedFinding)

    # Candidate finding does not have CONFIRMED status
    assert hasattr(finding, "candidate_id")
    assert hasattr(finding, "observed_status_code")
    assert hasattr(finding, "raw_response_snippet")
    assert not hasattr(finding, "status")  # VerificationStatus belongs only to VerifiedFinding
