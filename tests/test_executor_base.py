"""Unit and acceptance tests for ISpecialistExecutor base contract, budgets, and safety boundaries."""

import hashlib
import json
import time
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
    VerifiedFinding,
)
from drishti.executors.attack_plan import (
    AttackPlan,
    AttackPlanCompiler,
    CredentialBinding,
    ExecutionBudget,
    OutputBinding,
    PlanPhase,
    PlanStep,
)
from drishti.executors.base import (
    BudgetExhaustedError,
    ExecutionCancelledError,
    ISpecialistExecutor,
    redact_and_bound_evidence,
    sanitize_response_headers,
)
from drishti.graph.schema import HypothesisNode
from drishti.policy.client import SafeHttpClient


class DummyI01Executor(ISpecialistExecutor):
    """Concrete specialist executor testing I-01 tenant isolation contracts."""
    supported_invariant = InvariantType.TENANT_ISOLATION

    async def execute(self, plan: AttackPlan) -> CandidateFinding:
        self.check_plan_supported(plan)
        self.check_preconditions(plan)

        last_resp = None
        for step in plan.steps:
            resolved_url = self.resolve_step_url(step, base_url="http://test.local")
            resp, exec_res = await self.send_guarded_request(plan, step, resolved_url)
            last_resp = resp

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


@pytest.fixture
def mock_safe_http_client():
    client = MagicMock(spec=SafeHttpClient)
    resp = httpx.Response(
        status_code=200,
        headers={
            "content-type": "application/json",
            "set-cookie": "session_id=secret123; HttpOnly",
            "x-api-key": "internal_secret_key",
        },
        text='{"status": "ok", "booking_id": "BK-9999", "passenger_name": "Canary Passenger"}',
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
async def test_stricter_effective_request_budget_enforcement(mock_safe_http_client):
    """Verify that the stricter of plan request budget and executor limit is enforced."""
    # Case 1: Executor limit (2) is stricter than Plan limit (10)
    executor1 = DummyI01Executor(http_client=mock_safe_http_client, budget_limit=2)
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
    plan1 = AttackPlan(
        plan_id="PLAN-BGT-1",
        hypothesis_id="HYP-BGT-1",
        invariant_id=InvariantType.TENANT_ISOLATION,
        target_endpoint_identity="ep:1",
        attacker_tenant_id="agency_b",
        victim_tenant_id="agency_a",
        attacker_credential=CredentialBinding(tenant_id="agency_b", credential_ref="cred:b:admin"),
        victim_credential=CredentialBinding(tenant_id="agency_a", credential_ref="cred:a:admin"),
        budget=ExecutionBudget(max_requests=10),
        steps=[step],
        expires_at="2027-01-01T00:00:00Z",
    )

    await executor1.send_guarded_request(plan1, step, "http://test.local/test")
    await executor1.send_guarded_request(plan1, step, "http://test.local/test")
    with pytest.raises(BudgetExhaustedError, match="budget exhausted: 2/2"):
        await executor1.send_guarded_request(plan1, step, "http://test.local/test")

    # Case 2: Plan limit (1) is stricter than Executor limit (5)
    executor2 = DummyI01Executor(http_client=mock_safe_http_client, budget_limit=5)
    plan2 = AttackPlan(
        plan_id="PLAN-BGT-2",
        hypothesis_id="HYP-BGT-2",
        invariant_id=InvariantType.TENANT_ISOLATION,
        target_endpoint_identity="ep:1",
        attacker_tenant_id="agency_b",
        victim_tenant_id="agency_a",
        attacker_credential=CredentialBinding(tenant_id="agency_b", credential_ref="cred:b:admin"),
        victim_credential=CredentialBinding(tenant_id="agency_a", credential_ref="cred:a:admin"),
        budget=ExecutionBudget(max_requests=1),
        steps=[step],
        expires_at="2027-01-01T00:00:00Z",
    )

    await executor2.send_guarded_request(plan2, step, "http://test.local/test")
    with pytest.raises(BudgetExhaustedError, match="budget exhausted: 1/1"):
        await executor2.send_guarded_request(plan2, step, "http://test.local/test")


@pytest.mark.asyncio
async def test_duration_deadline_enforcement(mock_safe_http_client):
    """Verify that exceeding the plan's max_duration_seconds raises BudgetExhaustedError."""
    executor = DummyI01Executor(http_client=mock_safe_http_client)
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
        plan_id="PLAN-DUR",
        hypothesis_id="HYP-DUR",
        invariant_id=InvariantType.TENANT_ISOLATION,
        target_endpoint_identity="ep:1",
        attacker_tenant_id="agency_b",
        victim_tenant_id="agency_a",
        attacker_credential=CredentialBinding(tenant_id="agency_b", credential_ref="cred:b:admin"),
        victim_credential=CredentialBinding(tenant_id="agency_a", credential_ref="cred:a:admin"),
        budget=ExecutionBudget(max_requests=10, max_duration_seconds=1),
        steps=[step],
        expires_at="2027-01-01T00:00:00Z",
    )

    # First request sets start time
    await executor.send_guarded_request(plan, step, "http://test.local/test")

    # Simulate elapsed duration exceeding 1s
    executor._execution_start_time = time.monotonic() - 2.0

    with pytest.raises(BudgetExhaustedError, match="Execution duration limit exceeded"):
        await executor.send_guarded_request(plan, step, "http://test.local/test")


@pytest.mark.asyncio
async def test_response_size_budget_enforcement(mock_safe_http_client):
    """Verify that oversized responses breaching max_response_size_bytes raise BudgetExhaustedError."""
    # Mock an oversized response (e.g. 5000 bytes when budget is 1024)
    oversized_text = "A" * 5000
    oversized_resp = httpx.Response(
        status_code=200,
        text=oversized_text,
        request=httpx.Request("GET", "http://test.local/api/v2/large"),
    )
    mock_safe_http_client.send_request = AsyncMock(return_value=oversized_resp)

    executor = DummyI01Executor(http_client=mock_safe_http_client)
    step = PlanStep(
        step_id="step_large",
        name="Large Step",
        phase=PlanPhase.PROBE,
        method="GET",
        target_endpoint_identity="ep:1",
        endpoint_route_template="/large",
        actor_tenant_id="agency_b",
        credential_ref="cred:b:admin",
    )
    plan = AttackPlan(
        plan_id="PLAN-SIZE",
        hypothesis_id="HYP-SIZE",
        invariant_id=InvariantType.TENANT_ISOLATION,
        target_endpoint_identity="ep:1",
        attacker_tenant_id="agency_b",
        victim_tenant_id="agency_a",
        attacker_credential=CredentialBinding(tenant_id="agency_b", credential_ref="cred:b:admin"),
        victim_credential=CredentialBinding(tenant_id="agency_a", credential_ref="cred:a:admin"),
        budget=ExecutionBudget(max_requests=5, max_response_size_bytes=1024),
        steps=[step],
        expires_at="2027-01-01T00:00:00Z",
    )

    with pytest.raises(BudgetExhaustedError, match="exceeds maximum allowed budget"):
        await executor.send_guarded_request(plan, step, "http://test.local/large")


@pytest.mark.asyncio
async def test_sensitive_response_header_sanitization(mock_safe_http_client):
    """Verify that sensitive headers (Set-Cookie, x-api-key, Authorization) are sanitized in telemetry."""
    executor = DummyI01Executor(http_client=mock_safe_http_client)
    step = PlanStep(
        step_id="step_head",
        name="Header Step",
        phase=PlanPhase.PROBE,
        method="GET",
        target_endpoint_identity="ep:1",
        endpoint_route_template="/test",
        actor_tenant_id="agency_b",
        credential_ref="cred:b:admin",
    )
    plan = AttackPlan(
        plan_id="PLAN-HEAD",
        hypothesis_id="HYP-HEAD",
        invariant_id=InvariantType.TENANT_ISOLATION,
        target_endpoint_identity="ep:1",
        attacker_tenant_id="agency_b",
        victim_tenant_id="agency_a",
        attacker_credential=CredentialBinding(tenant_id="agency_b", credential_ref="cred:b:admin"),
        victim_credential=CredentialBinding(tenant_id="agency_a", credential_ref="cred:a:admin"),
        steps=[step],
        expires_at="2027-01-01T00:00:00Z",
    )

    _, exec_res = await executor.send_guarded_request(plan, step, "http://test.local/test")

    # Sensitive headers sanitized
    assert exec_res.headers["set-cookie"] == "[REDACTED_HEADER]"
    assert exec_res.headers["x-api-key"] == "[REDACTED_HEADER]"
    assert "secret123" not in str(exec_res.headers)

    # Safe headers preserved
    assert exec_res.headers["content-type"] == "application/json"


@pytest.mark.asyncio
async def test_execution_context_resolution_and_output_binding(mock_safe_http_client):
    """Verify that setup outputs are captured into execution context and resolved in subsequent step URLs."""
    executor = DummyI01Executor(http_client=mock_safe_http_client)

    # Setup step with output binding: captures "booking_id" as "victim_booking_id"
    setup_step = PlanStep(
        step_id="step_setup",
        name="Setup Canary",
        phase=PlanPhase.SETUP,
        method="POST",
        target_endpoint_identity="travel_api:canonical:POST:/api/v2/bookings",
        endpoint_route_template="/api/v2/bookings",
        actor_tenant_id="agency_a",
        credential_ref="cred:a:admin",
        output_bindings=[OutputBinding(source_field="booking_id", context_variable="victim_booking_id")],
    )

    # Subsequent probe step using context variable in URL template
    probe_step = PlanStep(
        step_id="step_probe",
        name="Probe Booking",
        phase=PlanPhase.PROBE,
        method="GET",
        target_endpoint_identity="travel_api:canonical:GET:/api/v2/bookings/{booking_id}",
        endpoint_route_template="/api/v2/bookings/{booking_id}",
        actor_tenant_id="agency_b",
        credential_ref="cred:b:admin",
        parameters={"booking_id": "$victim_booking_id"},
    )

    plan = AttackPlan(
        plan_id="PLAN-CTX",
        hypothesis_id="HYP-CTX",
        invariant_id=InvariantType.TENANT_ISOLATION,
        target_endpoint_identity="travel_api:canonical:GET:/api/v2/bookings/{booking_id}",
        attacker_tenant_id="agency_b",
        victim_tenant_id="agency_a",
        attacker_credential=CredentialBinding(tenant_id="agency_b", credential_ref="cred:b:admin"),
        victim_credential=CredentialBinding(tenant_id="agency_a", credential_ref="cred:a:admin"),
        steps=[setup_step, probe_step],
        expires_at="2027-01-01T00:00:00Z",
    )

    # 1. Execute setup step
    setup_url = executor.resolve_step_url(setup_step, base_url="http://test.local")
    resp, _ = await executor.send_guarded_request(plan, setup_step, setup_url)

    # Output binding captured BK-9999 from mock response
    assert executor.execution_context["victim_booking_id"] == "BK-9999"

    # 2. Resolve probe step URL -> correctly substitutes BK-9999
    probe_url = executor.resolve_step_url(probe_step, base_url="http://test.local")
    assert probe_url == "http://test.local/api/v2/bookings/BK-9999"


def test_resolve_step_url_unbound_variable_raises_error(mock_safe_http_client):
    """Verify that referencing an undefined context variable raises ValueError."""
    executor = DummyI01Executor(http_client=mock_safe_http_client)
    probe_step = PlanStep(
        step_id="step_probe",
        name="Probe Booking",
        phase=PlanPhase.PROBE,
        method="GET",
        target_endpoint_identity="ep:1",
        endpoint_route_template="/api/v2/bookings/{booking_id}",
        actor_tenant_id="agency_b",
        credential_ref="cred:b:admin",
        parameters={"booking_id": "$unbound_var"},
    )

    with pytest.raises(ValueError, match="Unbound context variable 'unbound_var'"):
        executor.resolve_step_url(probe_step, base_url="http://test.local")


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

    assert isinstance(finding, CandidateFinding)
    assert not isinstance(finding, VerifiedFinding)
    assert hasattr(finding, "candidate_id")
    assert hasattr(finding, "observed_status_code")
    assert hasattr(finding, "raw_response_snippet")
    assert not hasattr(finding, "status")
