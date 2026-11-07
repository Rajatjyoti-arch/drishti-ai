"""Tests for I-01 Tenant Isolation Specialist Executor (BOLAExecutor).

Verifies:
1. Differential execution: Vulnerable app triggers CandidateFinding, Patched app returns None (403 Forbidden).
2. Negative controls: Failed victim negative control aborts execution and yields None.
3. Candidate finding contract: Executor emits CandidateFinding, never CONFIRMED or VerifiedFinding.
4. Policy and budget enforcement: Request limits and emergency stop cancellation.
"""

from unittest.mock import MagicMock
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
    CanarySecretStore,
    ExecutionBudget,
)
from drishti.executors.i01_tenant_isolation import BOLAExecutor
from drishti.policy.client import SafeHttpClient
from drishti.policy.gate import PolicyGate
from drishti.policy.transports import InProcessFixtureTransport
from drishti.graph.schema import HypothesisNode
from drishti.verifier.models import ExecutionOutcome, ExecutorRunResult
from tests.fixtures.patched_app import create_patched_app
from tests.fixtures.vulnerable_app import create_vulnerable_app


@pytest.fixture
def hypothesis_i01():
    return HypothesisNode(
        hypothesis_id="hyp_travel_bola_01",
        invariant_id=InvariantType.TENANT_ISOLATION.value,
        target_endpoint_identity="travel_api:canonical:GET:/api/v2/bookings/{booking_id}",
        attacker_tenant_id="AG_DELHI_02",
        victim_tenant_id="AG_MUMBAI_01",
        rationale="Multi-tenant booking lookup exposes BOLA vulnerability without agency isolation",
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
async def test_bola_executor_finds_vulnerability_on_vulnerable_app(hypothesis_i01):
    """Executes BOLAExecutor against the vulnerable B2B travel application and verifies CandidateFinding."""
    gate = build_mock_policy_gate()
    app = create_vulnerable_app()
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i01,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        fixture_setup_approved=True,
        seed="test_seed_vuln",
    )

    executor = BOLAExecutor(http_client=http_client)
    run_res = await executor.execute(plan, base_url="http://test")

    # Verify a candidate finding was produced
    assert run_res.outcome == ExecutionOutcome.CANDIDATE
    assert run_res.candidate is not None
    finding = run_res.candidate
    assert isinstance(finding, CandidateFinding)
    assert not isinstance(finding, VerifiedFinding)
    assert finding.observed_status_code == 200
    assert finding.hypothesis.invariant_targeted == InvariantType.TENANT_ISOLATION
    assert finding.hypothesis.attacker_tenant_id == "AG_DELHI_02"
    assert finding.hypothesis.victim_tenant_id == "AG_MUMBAI_01"

    # Canary value should be present in raw response snippet or history
    canary_val = CanarySecretStore.get_secret(plan.canary_spec.canary_secret_ref)
    assert canary_val is not None
    # Verify execution history recorded all 5 steps (setup x2, negative control x2, probe x1)
    assert len(executor.execution_history) == 5
    probe_exec = executor.execution_history[-1]
    assert probe_exec.status_code == 200


@pytest.mark.asyncio
async def test_bola_executor_reports_clean_on_patched_app(hypothesis_i01):
    """Executes BOLAExecutor against the patched B2B travel application and confirms no finding emitted."""
    gate = build_mock_policy_gate()
    app = create_patched_app()
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i01,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        fixture_setup_approved=True,
        seed="test_seed_patched",
    )

    executor = BOLAExecutor(http_client=http_client)
    run_res = await executor.execute(plan, base_url="http://test")

    # On patched app, unauthorized cross-tenant read must return 403 Forbidden and yield EXPECTED_REJECTION
    assert run_res.outcome == ExecutionOutcome.EXPECTED_REJECTION
    assert run_res.candidate is None
    assert len(executor.execution_history) == 5
    probe_exec = executor.execution_history[-1]
    assert probe_exec.status_code == 403


@pytest.mark.asyncio
async def test_bola_executor_aborts_on_failed_negative_control(hypothesis_i01):
    """If victim negative control fails, executor must abort and emit no candidate finding."""
    gate = build_mock_policy_gate()
    app = create_vulnerable_app()
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i01,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        fixture_setup_approved=True,
        seed="test_seed_neg_control",
    )

    # Intentionally alter step 3 (victim negative control) to expect a non-existent route
    plan.steps[2].endpoint_route_template = "/api/v2/non_existent_route"

    executor = BOLAExecutor(http_client=http_client)
    run_res = await executor.execute(plan, base_url="http://test")

    # Must abort cleanly without executing probe
    assert run_res.outcome == ExecutionOutcome.INCONCLUSIVE
    assert run_res.candidate is None
    # Should stop after step 3
    assert len(executor.execution_history) == 3


@pytest.mark.asyncio
async def test_bola_executor_enforces_budget_limits(hypothesis_i01):
    """Verifies that executor respects request budget limit."""
    gate = build_mock_policy_gate()
    app = create_vulnerable_app()
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i01,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        budget=ExecutionBudget(max_requests=2, max_duration_seconds=30),
        fixture_setup_approved=True,
    )

    executor = BOLAExecutor(http_client=http_client, budget_limit=2)
    with pytest.raises(BudgetExhaustedError):
        await executor.execute(plan, base_url="http://test")


@pytest.mark.asyncio
async def test_bola_executor_emergency_stop_cancellation(hypothesis_i01):
    """Verifies cooperative cancellation and emergency stop."""
    gate = build_mock_policy_gate()
    app = create_vulnerable_app()
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i01,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        fixture_setup_approved=True,
    )

    executor = BOLAExecutor(http_client=http_client)
    executor.cancel("User initiated emergency stop")

    with pytest.raises(ExecutionCancelledError) as exc_info:
        await executor.execute(plan, base_url="http://test")
    assert "emergency stop" in str(exc_info.value).lower()
