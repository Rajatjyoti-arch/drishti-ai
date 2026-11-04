"""Adversarial tests proving the PolicyGate and SafeHttpClient cannot be bypassed."""

import pytest
import asyncio
from pathlib import Path
from drishti.core.contract import AuthorizationContract, TestTenants
from drishti.core.config import ExecutionBudgets, RateLimitConfig, ExecutionConfig, CircuitBreakerConfig
from drishti.core.models import OutgoingTestRequest, InvariantType, PolicyAction
from drishti.core.exceptions import PolicyViolationError
from drishti.audit.ledger import TamperEvidentLedger
from drishti.policy.gate import PolicyGate
from drishti.policy.client import SafeHttpClient

@pytest.fixture
def test_setup(tmp_path):
    contract = AuthorizationContract(
        permitted_targets=["127.0.0.1", "localhost"],
        test_tenants=TestTenants(
            attacker_tenant_id="AG_MUMBAI_01",
            victim_tenant_id="AG_DELHI_02"
        ),
        prohibited_actions=["DROP", "DELETE_PRODUCTION_DATA"]
    )
    budgets = ExecutionBudgets(
        rate_limit=RateLimitConfig(requests_per_second=10.0, burst_capacity=5, max_concurrency=2),
        execution=ExecutionConfig(max_requests_per_test=3, max_total_requests_per_run=5),
        circuit_breaker=CircuitBreakerConfig(consecutive_5xx_threshold=2)
    )
    ledger = TamperEvidentLedger(db_path=tmp_path / "bypass_test.db")
    gate = PolicyGate(contract, budgets, ledger)
    client = SafeHttpClient(gate)
    return gate, client

@pytest.mark.asyncio
async def test_prohibited_action_keyword_is_blocked(test_setup):
    gate, client = test_setup
    req = OutgoingTestRequest(
        method="POST",
        url="http://127.0.0.1:8000/api/v2/query",
        body={"query": "DROP TABLE bookings;"},
        target_tenant_id="AG_MUMBAI_01",
        target_invariant=InvariantType.TENANT_ISOLATION
    )
    decision = await gate.evaluate_request(req)
    assert decision.action == PolicyAction.DENY
    assert decision.approved is False
    assert "Prohibited destructive action" in decision.reason

@pytest.mark.asyncio
async def test_out_of_scope_request_is_denied(test_setup):
    gate, client = test_setup
    req = OutgoingTestRequest(
        method="GET",
        url="https://api.external-unauthorized-target.com/leak",
        target_tenant_id="AG_MUMBAI_01",
        target_invariant=InvariantType.TENANT_ISOLATION
    )
    decision = await gate.evaluate_request(req)
    assert decision.action == PolicyAction.DENY
    assert decision.approved is False
    assert "Scope violation" in decision.reason

@pytest.mark.asyncio
async def test_per_test_budget_exhaustion_blocks_further_requests(test_setup):
    gate, client = test_setup
    req = OutgoingTestRequest(
        method="GET",
        url="http://127.0.0.1:8000/api/v2/hotels",
        target_tenant_id="AG_MUMBAI_01",
        target_invariant=InvariantType.TENANT_ISOLATION,
        test_id="test_budget_run"
    )
    # Permitted max_requests_per_test = 3
    d1 = await gate.evaluate_request(req)
    assert d1.approved is True
    d2 = await gate.evaluate_request(req)
    assert d2.approved is True
    d3 = await gate.evaluate_request(req)
    assert d3.approved is True

    # 4th request must be rejected (PAUSE / budget constraint)
    d4 = await gate.evaluate_request(req)
    assert d4.approved is False
    assert d4.action == PolicyAction.PAUSE
    assert "Per-test budget" in d4.reason

@pytest.mark.asyncio
async def test_circuit_breaker_trips_on_consecutive_5xx(test_setup):
    gate, client = test_setup
    gate.health_monitor.record_telemetry(latency_ms=10.0, status_code=500)
    assert gate.health_monitor.is_circuit_open is False

    # Second 500 trips threshold (set to 2)
    try:
        gate.health_monitor.record_telemetry(latency_ms=10.0, status_code=500)
    except Exception:
        pass # Expected EmergencyStopTriggered

    assert gate.health_monitor.is_circuit_open is True

    req = OutgoingTestRequest(
        method="GET",
        url="http://127.0.0.1:8000/api/v2/hotels",
        target_tenant_id="AG_MUMBAI_01",
        target_invariant=InvariantType.TENANT_ISOLATION
    )
    decision = await gate.evaluate_request(req)
    assert decision.action == PolicyAction.STOP
    assert decision.approved is False
    assert "circuit breaker is open" in decision.reason.lower()

from unittest.mock import AsyncMock, MagicMock
from drishti.policy.browser_guard import BrowserGuard

@pytest.mark.asyncio
async def test_browser_guard_aborts_out_of_scope_browser_request(test_setup):
    gate, client = test_setup
    guard = BrowserGuard(gate.scope_validator, gate.ledger)
    
    mock_route = AsyncMock()
    mock_request = MagicMock()
    mock_request.url = "https://unauthorized-destination.com/leak.js"
    mock_request.method = "GET"
    
    await guard.intercept_route(mock_route, mock_request)
    mock_route.abort.assert_awaited_once_with("blockedbyclient")
    mock_route.continue_.assert_not_awaited()

@pytest.mark.asyncio
async def test_browser_guard_permits_in_scope_browser_request(test_setup):
    gate, client = test_setup
    guard = BrowserGuard(gate.scope_validator, gate.ledger)
    
    mock_route = AsyncMock()
    mock_request = MagicMock()
    mock_request.url = "http://127.0.0.1:8000/app.js"
    mock_request.method = "GET"
    
    await guard.intercept_route(mock_route, mock_request)
    mock_route.continue_.assert_awaited_once()
    mock_route.abort.assert_not_awaited()
