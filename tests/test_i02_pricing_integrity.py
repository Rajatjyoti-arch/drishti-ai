"""Acceptance tests for I-02 Server-Authoritative Pricing Specialist Executor (PricingIntegrityExecutor).

Verifies:
1. Untampered baseline booking is accepted at authoritative server price and currency.
2. Client amount tampering:
   - Vulnerable app accepts tampered amount (100 INR vs 1,800,000 INR) -> CandidateFinding emitted.
   - Patched app rejects mismatch with HTTP 400 -> No candidate finding (invariant held).
3. Client currency tampering:
   - Vulnerable app accepts tampered currency (IDR vs INR) -> CandidateFinding emitted.
   - Patched app rejects mismatch with HTTP 400 -> No candidate finding (invariant held).
4. Safety & Inconclusive handling:
   - Expired quotes, invalid holds, and 5xx errors do not emit false candidate findings.
   - Distinct hold tokens are acquired and never reused across runs.
5. Budget and cancellation boundaries:
   - Request budgets and emergency stop are strictly enforced.
"""

import time
from unittest.mock import MagicMock
import httpx
import pytest

from drishti.core.exceptions import BudgetExhaustedError, ExecutionCancelledError
from drishti.core.models import (
    CandidateFinding,
    InvariantType,
    PolicyAction,
    PolicyDecision,
    VerifiedFinding,
)
from drishti.executors.attack_plan import (
    AttackPlanCompiler,
    ExecutionBudget,
)
from drishti.executors.i02_pricing_integrity import PricingIntegrityExecutor
from drishti.graph.schema import HypothesisNode
from drishti.policy.client import SafeHttpClient
from drishti.policy.transports import InProcessFixtureTransport
from drishti.verifier.models import ExecutionOutcome, ExecutorRunResult
from tests.fixtures.mock_travel_api import create_travel_app
from tests.fixtures.patched_app import create_patched_app
from tests.fixtures.vulnerable_app import (
    VulnerableTravelService,
    create_vulnerable_app,
)


@pytest.fixture
def hypothesis_i02():
    return HypothesisNode(
        hypothesis_id="hyp_travel_pricing_02",
        invariant_id=InvariantType.PRICING_INTEGRITY.value,
        target_endpoint_identity="travel_api:canonical:POST:/api/v2/bookings",
        attacker_tenant_id="AG_DELHI_02",
        victim_tenant_id="AG_MUMBAI_01",
        rationale="Client-controlled price parameters may override server quote during checkout transition",
    )


def build_mock_policy_gate():
    gate = MagicMock()
    gate.budgets.execution.timeout_seconds = 10.0
    gate.budgets.execution.max_requests_per_test = 20

    async def allow_eval(req, approval_token=None):
        return PolicyDecision(
            action=PolicyAction.ALLOW,
            approved=True,
            reason="Authorized by test policy gate",
            sanitized_url=req.url,
            budget_remaining=100,
        )

    gate.evaluate_request.side_effect = allow_eval
    return gate


@pytest.mark.asyncio
async def test_pricing_executor_finds_amount_tampering_on_vulnerable_app(hypothesis_i02):
    """Vulnerable app blindly accepts client_amount_minor_units = 100 instead of 1,800,000 INR."""
    gate = build_mock_policy_gate()
    app = create_vulnerable_app()
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i02,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        tampering_mode="amount",
        tampered_amount_minor_units=100,  # 1 INR tampering attempt
        fixture_setup_approved=True,
        synthetic_mutation_approved=True,
        seed="test_pricing_amt_vuln",
    )

    executor = PricingIntegrityExecutor(http_client=http_client)
    run_res = await executor.execute(plan, base_url="http://test")

    # Verify a candidate finding was produced with proof evidence
    assert run_res.outcome == ExecutionOutcome.CANDIDATE
    assert run_res.candidate is not None
    finding = run_res.candidate
    assert isinstance(finding, CandidateFinding)
    assert not isinstance(finding, VerifiedFinding)
    assert finding.observed_status_code == 200
    assert finding.hypothesis.invariant_targeted == InvariantType.PRICING_INTEGRITY
    assert "Amount Tampering" in finding.hypothesis.rationale
    assert executor.baseline is not None
    assert executor.baseline.amount_minor_units == 1800000
    assert executor.baseline.currency == "INR"
    assert len(executor.execution_history) == 5


@pytest.mark.asyncio
async def test_pricing_executor_rejects_amount_tampering_on_patched_app(hypothesis_i02):
    """Patched app enforces authoritative server quote and returns HTTP 400 on amount tampering."""
    gate = build_mock_policy_gate()
    app = create_patched_app()
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i02,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        tampering_mode="amount",
        tampered_amount_minor_units=100,
        fixture_setup_approved=True,
        synthetic_mutation_approved=True,
        seed="test_pricing_amt_patched",
    )

    executor = PricingIntegrityExecutor(http_client=http_client)
    run_res = await executor.execute(plan, base_url="http://test")

    # Invariant holds: Patched app returns HTTP 400 Bad Request; EXPECTED_REJECTION outcome
    assert run_res.outcome == ExecutionOutcome.EXPECTED_REJECTION
    assert run_res.candidate is None
    assert len(executor.execution_history) == 5
    probe_exec = executor.execution_history[-1]
    assert probe_exec.status_code == 400


@pytest.mark.asyncio
async def test_pricing_executor_finds_currency_tampering_on_vulnerable_app(hypothesis_i02):
    """Vulnerable app accepts client_currency = 'IDR' instead of authoritative 'INR'."""
    gate = build_mock_policy_gate()
    app = create_vulnerable_app()
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i02,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        tampering_mode="currency",
        tampered_currency="IDR",
        fixture_setup_approved=True,
        synthetic_mutation_approved=True,
        seed="test_pricing_curr_vuln",
    )

    executor = PricingIntegrityExecutor(http_client=http_client)
    run_res = await executor.execute(plan, base_url="http://test")

    assert run_res.outcome == ExecutionOutcome.CANDIDATE
    assert run_res.candidate is not None
    finding = run_res.candidate
    assert isinstance(finding, CandidateFinding)
    assert finding.observed_status_code == 200
    assert "Currency Tampering" in finding.hypothesis.rationale
    assert executor.baseline is not None
    assert executor.baseline.currency == "INR"


@pytest.mark.asyncio
async def test_pricing_executor_rejects_currency_tampering_on_patched_app(hypothesis_i02):
    """Patched app returns HTTP 400 on currency mismatch and prevents finding emission."""
    gate = build_mock_policy_gate()
    app = create_patched_app()
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i02,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        tampering_mode="currency",
        tampered_currency="IDR",
        fixture_setup_approved=True,
        synthetic_mutation_approved=True,
        seed="test_pricing_curr_patched",
    )

    executor = PricingIntegrityExecutor(http_client=http_client)
    run_res = await executor.execute(plan, base_url="http://test")

    assert run_res.outcome == ExecutionOutcome.EXPECTED_REJECTION
    assert run_res.candidate is None
    assert executor.execution_history[-1].status_code == 400


@pytest.mark.asyncio
async def test_pricing_executor_aborts_on_expired_quote(hypothesis_i02):
    """If the authoritative quote is expired, execution aborts and returns None (inconclusive)."""
    gate = build_mock_policy_gate()
    service = VulnerableTravelService()
    # Explicitly set quote expiry to 1 hour in the past
    service.quotes["QT_GOA_501"].expires_at = time.time() - 3600
    app = create_travel_app(service)
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i02,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        fixture_setup_approved=True,
        synthetic_mutation_approved=True,
    )

    executor = PricingIntegrityExecutor(http_client=http_client)
    run_res = await executor.execute(plan, base_url="http://test")

    # Assert expired quote is detected, returns INCONCLUSIVE outcome,
    # and no hold or booking steps are executed.
    assert run_res.outcome == ExecutionOutcome.INCONCLUSIVE
    assert run_res.candidate is None
    assert len(executor.execution_history) == 1
    assert executor.baseline is None, "Expired quote must not be stored as an authoritative baseline"


@pytest.mark.asyncio
async def test_pricing_executor_aborts_on_missing_baseline_fields(hypothesis_i02):
    """If the untampered negative control booking response omits confirmed amount/currency, executor aborts."""
    gate = build_mock_policy_gate()
    app = create_vulnerable_app()
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i02,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        fixture_setup_approved=True,
        synthetic_mutation_approved=True,
    )

    # Remove confirmed amount output binding from negative control step so context variable remains None
    plan.steps[2].output_bindings = [
        b for b in plan.steps[2].output_bindings if b.context_variable != "confirmed_baseline_amount"
    ]

    executor = PricingIntegrityExecutor(http_client=http_client)
    run_res = await executor.execute(plan, base_url="http://test")

    # Must abort cleanly without dispatching probe
    assert run_res.outcome == ExecutionOutcome.INCONCLUSIVE
    assert run_res.candidate is None
    assert len(executor.execution_history) == 3


@pytest.mark.asyncio
async def test_pricing_executor_aborts_on_failed_negative_control(hypothesis_i02):
    """If the untampered negative control fails, executor aborts without running the tampering probe."""
    gate = build_mock_policy_gate()
    app = create_vulnerable_app()
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i02,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        fixture_setup_approved=True,
        synthetic_mutation_approved=True,
    )

    # Corrupt step 3 route template to trigger a failure in untampered baseline
    plan.steps[2].endpoint_route_template = "/api/v2/non_existent_bookings"

    executor = PricingIntegrityExecutor(http_client=http_client)
    run_res = await executor.execute(plan, base_url="http://test")

    # Negative control failed -> aborts cleanly, INCONCLUSIVE outcome
    assert run_res.outcome == ExecutionOutcome.INCONCLUSIVE
    assert run_res.candidate is None
    assert len(executor.execution_history) == 3


@pytest.mark.asyncio
async def test_pricing_executor_fresh_hold_tokens_not_reused(hypothesis_i02):
    """Verifies that separate, distinct hold tokens are acquired for baseline and probe."""
    gate = build_mock_policy_gate()
    app = create_vulnerable_app()
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i02,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        fixture_setup_approved=True,
        synthetic_mutation_approved=True,
    )

    executor = PricingIntegrityExecutor(http_client=http_client)
    await executor.execute(plan, base_url="http://test")

    baseline_token = executor.execution_context.get("baseline_hold_token")
    tamper_token = executor.execution_context.get("tamper_hold_token")

    assert baseline_token is not None
    assert tamper_token is not None
    assert baseline_token != tamper_token, "Hold tokens must never be reused across steps"


@pytest.mark.asyncio
async def test_pricing_executor_handles_5xx_server_error(hypothesis_i02):
    """Server error (500) during probe produces an inconclusive result (None), not a false candidate."""
    gate = build_mock_policy_gate()
    app = create_vulnerable_app()
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i02,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        fixture_setup_approved=True,
        synthetic_mutation_approved=True,
    )

    executor = PricingIntegrityExecutor(http_client=http_client)

    # Mock server returning 500 on probe step
    orig_send = executor.send_guarded_request

    async def mock_send(plan, step, resolved_url, approval_token=None, resolved_body=None):
        if step.step_id == "step_5_price_tampering_probe":
            req = httpx.Request(step.method, resolved_url)
            resp = httpx.Response(500, request=req, content=b'{"error": "Internal database crash"}')
            from drishti.core.models import ExecutionResult
            return resp, ExecutionResult(request_id="500_req", status_code=500)
        return await orig_send(plan=plan, step=step, resolved_url=resolved_url, approval_token=approval_token, resolved_body=resolved_body)

    executor.send_guarded_request = mock_send

    run_res = await executor.execute(plan, base_url="http://test")
    assert run_res.outcome == ExecutionOutcome.INCONCLUSIVE
    assert run_res.candidate is None


@pytest.mark.asyncio
async def test_pricing_executor_enforces_budget_limit(hypothesis_i02):
    """Enforces request budget limits."""
    gate = build_mock_policy_gate()
    app = create_vulnerable_app()
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i02,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        budget=ExecutionBudget(max_requests=2, max_duration_seconds=30),
        fixture_setup_approved=True,
        synthetic_mutation_approved=True,
    )

    executor = PricingIntegrityExecutor(http_client=http_client, budget_limit=2)
    with pytest.raises(BudgetExhaustedError):
        await executor.execute(plan, base_url="http://test")


@pytest.mark.asyncio
async def test_pricing_executor_emergency_stop_cancellation(hypothesis_i02):
    """Enforces cooperative cancellation on emergency stop."""
    gate = build_mock_policy_gate()
    app = create_vulnerable_app()
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i02,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        fixture_setup_approved=True,
        synthetic_mutation_approved=True,
    )

    executor = PricingIntegrityExecutor(http_client=http_client)
    executor.cancel("Operator triggered emergency stop")

    with pytest.raises(ExecutionCancelledError) as exc_info:
        await executor.execute(plan, base_url="http://test")
    assert "emergency stop" in str(exc_info.value).lower()
