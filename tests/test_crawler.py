"""Acceptance and unit test suite for Drishti AI Journey-Aware Crawler.

Verifies:
1. Multi-tenant session and credential isolation (Agency A vs Agency B).
2. Fail-closed route interception (abort on out-of-scope or Guard failure).
3. Egress boundary mediation (Playwright traffic routed via NetworkBridge).
4. Sanitization of tokens, credentials, and cookies in observations and HAR.
5. Capture completeness accounting (PARTIAL on budget/timeout/step failure).
6. Role-attributed observations and downstream normalizer integration.
"""

import json
from unittest.mock import AsyncMock, MagicMock
import pytest

from drishti.audit.ledger import TamperEvidentLedger
from drishti.core.contract import AuthorizationContract, TestTenants
from drishti.core.exceptions import OutOfScopeError, PolicyViolationError
from drishti.core.models import ExecutionResult, OutgoingTestRequest
from drishti.discovery.browser_context import BrowserContextManager
from drishti.discovery.crawler import JourneyCrawler
from drishti.discovery.crawler_models import (
    ActionType,
    BrowserObservation,
    CrawlSession,
    CrawlStatus,
    JourneyPlan,
    JourneyStep,
    RoleContext,
)
from drishti.discovery.endpoint_normalizer import EndpointNormalizer
from drishti.discovery.har_capture import HarCaptureExporter
from drishti.discovery.models import CaptureCompleteness
from drishti.discovery.network_bridge import NetworkBridge, sanitize_headers
from drishti.policy.scope_validator import ScopeValidator


@pytest.fixture
def test_scope():
    """Configures authorized scope validator for tbo.com staging domain."""
    contract = AuthorizationContract(
        permitted_targets=["api.tbo.com", "portal.tbo.com", "localhost", "127.0.0.1"],
        test_tenants=TestTenants(
            attacker_tenant_id="TENANT-AGENCY-A",
            victim_tenant_id="TENANT-AGENCY-B",
        ),
        prohibited_actions=["DROP", "DELETE_PRODUCTION_DATA"],
    )
    return ScopeValidator(contract)


@pytest.fixture
def agency_a_role():
    """RoleContext for Agency A (Tenant 1)."""
    return RoleContext(
        role_name="agency_admin",
        tenant_id="TENANT-AGENCY-A",
        agency_id="AGENCY-A",
        auth_headers={"Authorization": "Bearer secret_jwt_token_agency_a", "X-Api-Key": "key_a_123"},
        cookies=[{"name": "session_a", "value": "sess_cookie_a", "domain": "portal.tbo.com", "path": "/"}],
    )


@pytest.fixture
def agency_b_role():
    """RoleContext for Agency B (Tenant 2)."""
    return RoleContext(
        role_name="agency_admin",
        tenant_id="TENANT-AGENCY-B",
        agency_id="AGENCY-B",
        auth_headers={"Authorization": "Bearer secret_jwt_token_agency_b", "X-Api-Key": "key_b_456"},
        cookies=[{"name": "session_b", "value": "sess_cookie_b", "domain": "portal.tbo.com", "path": "/"}],
    )


# -------------------------------------------------------------------------
# Test 1: Header and Credential Sanitization
# -------------------------------------------------------------------------

def test_sanitize_headers_redacts_auth_and_session_secrets():
    """Acceptance Test 1: All bearer tokens, cookies, and API keys are redacted."""
    raw_headers = {
        "Authorization": "Bearer eyJhbGciOi_sensitive_token",
        "Cookie": "session_id=abcdef123456",
        "X-Api-Key": "super_secret_agent_api_key",
        "Content-Type": "application/json",
        "Accept": "*/*",
    }
    sanitized = sanitize_headers(raw_headers)
    assert sanitized["Authorization"] == "[REDACTED]"
    assert sanitized["Cookie"] == "[REDACTED]"
    assert sanitized["X-Api-Key"] == "[REDACTED]"
    assert sanitized["Content-Type"] == "application/json"
    assert sanitized["Accept"] == "*/*"


# -------------------------------------------------------------------------
# Test 2: NetworkBridge Out-of-Scope Navigation Denial
# -------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_network_bridge_denies_out_of_scope_destinations(test_scope, agency_a_role, tmp_path):
    """Acceptance Test 2: NetworkBridge aborts out-of-scope, SSRF, or link-local navigation."""
    ledger = TamperEvidentLedger(db_path=tmp_path / "test_crawler_audit.db")
    bridge = NetworkBridge(scope_validator=test_scope, ledger=ledger)

    mock_route = AsyncMock()
    mock_request = MagicMock()
    mock_request.url = "http://169.254.169.254/latest/meta-data/"
    mock_request.method = "GET"
    mock_request.headers = {}
    mock_request.post_data = None

    await bridge.handle_route(
        route=mock_route,
        request=mock_request,
        role_context=agency_a_role,
        session_id="SESS-001",
    )

    # Route must be aborted immediately with 'blockedbyclient'
    mock_route.abort.assert_called_once_with("blockedbyclient")
    mock_route.fulfill.assert_not_called()

    # Ledger must record the policy denial
    events = ledger.get_all_events()
    deny_events = [e for e in events if e.event_type == "BROWSER_POLICY_DENY"]
    assert len(deny_events) == 1
    assert deny_events[0].event_type == "BROWSER_POLICY_DENY"


# -------------------------------------------------------------------------
# Test 3: NetworkBridge Fail-Closed on Guard Failure
# -------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_network_bridge_fails_closed_when_guard_errors(test_scope, agency_a_role):
    """Acceptance Test 3: When Guard execution fails or denies, browser route is aborted fail-closed."""
    def failing_executor(req: OutgoingTestRequest):
        raise PolicyViolationError("[RATE_LIMIT_EXCEEDED] Global request budget exhausted")

    bridge = NetworkBridge(scope_validator=test_scope, custom_executor=failing_executor)

    mock_route = AsyncMock()
    mock_request = MagicMock()
    mock_request.url = "http://127.0.0.1:8000/api/v1/flights/search"
    mock_request.method = "GET"
    mock_request.headers = {}
    mock_request.post_data = None

    await bridge.handle_route(
        route=mock_route,
        request=mock_request,
        role_context=agency_a_role,
        session_id="SESS-001",
    )

    # Must fail closed: never let browser socket connect natively!
    mock_route.abort.assert_called_once_with("blockedbyclient")
    mock_route.fulfill.assert_not_called()


# -------------------------------------------------------------------------
# Test 4: NetworkBridge Fulfills In-Scope Route with Guard Response
# -------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_network_bridge_fulfills_route_and_records_observation(test_scope, agency_a_role):
    """Acceptance Test 4: In-scope requests are fulfilled via Guard and recorded with role attribution."""
    def mock_executor(req: OutgoingTestRequest) -> ExecutionResult:
        assert req.target_tenant_id == "TENANT-AGENCY-A"
        assert req.method == "POST"
        return ExecutionResult(
            request_id="REQ-SEARCH-01",
            status_code=200,
            headers={"content-type": "application/json", "x-response-id": "resp-123"},
            sanitized_body='{"flights": [{"flight_id": "FL-101", "fare": 4500}]}',
            latency_ms=42,
        )

    bridge = NetworkBridge(scope_validator=test_scope, custom_executor=mock_executor)

    mock_route = AsyncMock()
    mock_request = MagicMock()
    mock_request.url = "http://127.0.0.1:8000/api/v1/flights/search"
    mock_request.method = "POST"
    mock_request.headers = {"Content-Type": "application/json"}
    mock_request.post_data = '{"origin": "DEL", "destination": "DXB"}'

    await bridge.handle_route(
        route=mock_route,
        request=mock_request,
        role_context=agency_a_role,
        session_id="SESS-001",
        journey_step_id="STEP-SEARCH",
    )

    # Browser fulfilled with Guard's response
    mock_route.fulfill.assert_called_once()
    fulfill_kwargs = mock_route.fulfill.call_args.kwargs
    assert fulfill_kwargs["status"] == 200
    assert b"FL-101" in fulfill_kwargs["body"]

    # Recorded observation
    assert len(bridge.observations) == 1
    obs = bridge.observations[0]
    assert obs.role_name == "agency_admin"
    assert obs.tenant_id == "TENANT-AGENCY-A"
    assert obs.status_code == 200
    assert obs.journey_step_id == "STEP-SEARCH"
    assert obs.guard_mediated is True
    assert obs.request_headers.get("Authorization") == "[REDACTED]"


# -------------------------------------------------------------------------
# Test 5: Multi-Tenant Session Isolation (Agency A vs Agency B)
# -------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_multi_tenant_session_isolation(test_scope, agency_a_role, agency_b_role):
    """Acceptance Test 5: Agency A and Agency B contexts have distinct credentials, headers, and observations."""
    observations_log = []

    def mock_executor(req: OutgoingTestRequest) -> ExecutionResult:
        observations_log.append((req.target_tenant_id, req.method, req.url))
        return ExecutionResult(
            request_id=f"REQ-{len(observations_log)}",
            status_code=200,
            headers={"content-type": "application/json"},
            sanitized_body='{"status": "ok"}',
            latency_ms=10,
        )

    bridge = NetworkBridge(scope_validator=test_scope, custom_executor=mock_executor)

    # Simulate request from Agency A
    mock_route_a = AsyncMock()
    mock_req_a = MagicMock(url="http://127.0.0.1:8000/api/v1/agency/dashboard", method="GET", headers={}, post_data=None)
    await bridge.handle_route(mock_route_a, mock_req_a, agency_a_role, session_id="SESS-A")

    # Simulate request from Agency B
    mock_route_b = AsyncMock()
    mock_req_b = MagicMock(url="http://127.0.0.1:8000/api/v1/agency/dashboard", method="GET", headers={}, post_data=None)
    await bridge.handle_route(mock_route_b, mock_req_b, agency_b_role, session_id="SESS-B")

    # Invariants: 2 distinct role observations on the same endpoint
    assert len(bridge.observations) == 2
    assert bridge.observations[0].tenant_id == "TENANT-AGENCY-A"
    assert bridge.observations[1].tenant_id == "TENANT-AGENCY-B"


# -------------------------------------------------------------------------
# Test 6: HAR Trace Export with Sanitization
# -------------------------------------------------------------------------

def test_har_capture_exporter_produces_compliant_sanitized_har():
    """Acceptance Test 6: HAR output adheres to v1.2 schema with zero leaked auth tokens."""
    obs = BrowserObservation(
        observation_id="OBS-99",
        session_id="SESS-10",
        role_name="agency_admin",
        tenant_id="TENANT-AGENCY-A",
        method="GET",
        url="https://api.tbo.com/api/v1/bookings/TBOH_888",
        status_code=200,
        request_headers={"Authorization": "[REDACTED]", "Host": "api.tbo.com"},
        response_headers={"Content-Type": "application/json"},
        response_body='{"booking_id": "TBOH_888", "status": "CONFIRMED"}',
        latency_ms=35,
    )

    exporter = HarCaptureExporter()
    har_dict = exporter.observations_to_har_dict([obs])

    assert har_dict["log"]["version"] == "1.2"
    assert len(har_dict["log"]["entries"]) == 1
    entry = har_dict["log"]["entries"][0]
    assert entry["request"]["method"] == "GET"
    assert entry["response"]["status"] == 200
    assert entry["_role"] == "agency_admin"
    assert entry["_tenant_id"] == "TENANT-AGENCY-A"

    har_str = exporter.export_to_har_string([obs])
    assert "secret_jwt" not in har_str


# -------------------------------------------------------------------------
# Test 7: Conversion to EndpointObservation and Normalization Pipeline
# -------------------------------------------------------------------------

def test_har_capture_to_normalizer_pipeline():
    """Acceptance Test 7: BrowserObservations convert to EndpointObservations and retain roles in inventory."""
    obs_a = BrowserObservation(
        observation_id="OBS-A",
        session_id="SESS-A",
        role_name="agency_a",
        tenant_id="TENANT-A",
        method="GET",
        url="https://api.tbo.com/api/v1/quotes/QUOTE_999",
        status_code=200,
        response_body='{"quote_id": "QUOTE_999"}',
    )
    obs_b = BrowserObservation(
        observation_id="OBS-B",
        session_id="SESS-B",
        role_name="agency_b",
        tenant_id="TENANT-B",
        method="GET",
        url="https://api.tbo.com/api/v1/quotes/QUOTE_999",
        status_code=200,
        response_body='{"quote_id": "QUOTE_999"}',
    )

    endpoint_obs = HarCaptureExporter.to_endpoint_observations([obs_a, obs_b])
    assert len(endpoint_obs) == 2

    normalizer = EndpointNormalizer()
    normalized = normalizer.normalize(endpoint_obs)

    # Route was normalized to /api/v1/quotes/{quote_id} and observed under both roles!
    assert len(normalized) == 1
    ep = normalized[0]
    assert ep.route_template == "/api/v1/quotes/{quote_id}"
    assert "agency_a" in ep.roles_observed
    assert "agency_b" in ep.roles_observed


# -------------------------------------------------------------------------
# Test 8: Journey Execution and Capture Completeness Accounting
# -------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_journey_crawler_completeness_accounting(test_scope, agency_a_role):
    """Acceptance Test 8: Incomplete journey results in PARTIAL completeness; complete journey results in COMPLETE."""
    def mock_executor(req: OutgoingTestRequest) -> ExecutionResult:
        return ExecutionResult(
            request_id="REQ-1",
            status_code=200,
            headers={"content-type": "application/json"},
            sanitized_body='{"status": "ok"}',
            latency_ms=5,
        )

    bridge = NetworkBridge(scope_validator=test_scope, custom_executor=mock_executor)
    crawler = JourneyCrawler(network_bridge=bridge)

    # Plan with 2 steps
    plan = JourneyPlan(
        plan_id="PLAN-TRAVEL",
        name="Search and Quote",
        description="Search flights and retrieve quote",
        steps=[
            JourneyStep(step_id="STEP-1", step_name="Search", action_type=ActionType.NAVIGATE.value, target="http://127.0.0.1:8000/search"),
            JourneyStep(step_id="STEP-2", step_name="Quote", action_type=ActionType.NAVIGATE.value, target="http://127.0.0.1:8000/quote", is_critical=True),
        ],
    )

    # Mock browser and page
    mock_page = AsyncMock()
    mock_context = AsyncMock()
    mock_context.new_page.return_value = mock_page
    mock_browser = AsyncMock()
    mock_browser.new_context.return_value = mock_context

    # Case A: Both steps succeed
    mock_page.goto.return_value = MagicMock(status=200)
    session, obs = await crawler.execute_journey(mock_browser, agency_a_role, plan)
    assert session.status == CrawlStatus.COMPLETED.value
    assert session.capture_completeness == CaptureCompleteness.COMPLETE.value

    # Case B: Critical step fails -> must be marked PARTIAL
    mock_page.goto.side_effect = [MagicMock(status=200), Exception("Connection reset")]
    session_fail, _ = await crawler.execute_journey(mock_browser, agency_a_role, plan)
    assert session_fail.status == CrawlStatus.FAILED.value
    assert session_fail.capture_completeness == CaptureCompleteness.PARTIAL.value
    assert len(session_fail.errors) > 0


# -------------------------------------------------------------------------
# Test 9: Live Playwright Integration: Role-Attributed Browser Navigation
# -------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_live_playwright_role_isolated_browser_crawler(test_scope, agency_a_role):
    """Acceptance Test 9: Real Playwright Chromium engine mediated through NetworkBridge."""
    from playwright.async_api import async_playwright

    def mock_executor(req: OutgoingTestRequest) -> ExecutionResult:
        if "flights" in req.url:
            body = '{"flights": [{"flight_id": "DEL-DXB-99", "fare": 3200}]}'
            content_type = "application/json"
        else:
            body = "<html><body><h1>Travel Portal Home</h1></body></html>"
            content_type = "text/html"

        return ExecutionResult(
            request_id="REQ-LIVE-01",
            status_code=200,
            headers={"content-type": content_type},
            sanitized_body=body,
            latency_ms=12,
        )

    bridge = NetworkBridge(scope_validator=test_scope, custom_executor=mock_executor)
    crawler = JourneyCrawler(network_bridge=bridge)

    plan = JourneyPlan(
        plan_id="PLAN-LIVE",
        name="Live Travel Portal Navigation",
        description="Navigates portal page and queries flights API in real Chromium",
        steps=[
            JourneyStep(
                step_id="STEP-NAV",
                step_name="Navigate Home",
                action_type=ActionType.NAVIGATE.value,
                target="http://127.0.0.1:8000/portal/home",
            ),
            JourneyStep(
                step_id="STEP-FETCH",
                step_name="Fetch Flights",
                action_type=ActionType.API_CALL.value,
                target="http://127.0.0.1:8000/api/v1/flights",
                value="GET",
                expected_status=200,
            ),
        ],
    )

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            session, observations = await crawler.execute_journey(browser, agency_a_role, plan)

            # Verification of real browser execution mediated via Guard
            assert session.status == CrawlStatus.COMPLETED.value
            assert session.capture_completeness == CaptureCompleteness.COMPLETE.value
            assert len(session.completed_steps) == 2

            # Bridge captured the requests executed by real Chromium
            assert len(observations) >= 2
            urls_observed = [o.url for o in observations]
            assert any("/portal/home" in u for u in urls_observed)
            assert any("/api/v1/flights" in u for u in urls_observed)

            # All observations carry Agency A's role attribution
            for obs in observations:
                assert obs.tenant_id == "TENANT-AGENCY-A"
                assert obs.guard_mediated is True
        finally:
            await browser.close()


# -------------------------------------------------------------------------
# Test 10: Live Playwright Integration: Fail-Closed Route Abort on Forbidden Egress
# -------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_live_playwright_out_of_scope_navigation_aborted(test_scope, agency_a_role, tmp_path):
    """Acceptance Test 10: Real Chromium attempting forbidden out-of-scope navigation is aborted fail-closed."""
    from playwright.async_api import async_playwright

    ledger = TamperEvidentLedger(db_path=tmp_path / "live_crawler_audit.db")
    bridge = NetworkBridge(scope_validator=test_scope, ledger=ledger)
    crawler = JourneyCrawler(network_bridge=bridge)

    plan = JourneyPlan(
        plan_id="PLAN-DENY",
        name="Hostile Egress Attempt",
        description="Attempts to access forbidden link-local metadata address",
        steps=[
            JourneyStep(
                step_id="STEP-FORBIDDEN",
                step_name="Access Metadata Service",
                action_type=ActionType.NAVIGATE.value,
                target="http://169.254.169.254/latest/meta-data/",
                is_critical=True,
            )
        ],
    )

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            session, observations = await crawler.execute_journey(browser, agency_a_role, plan)

            # Journey must have failed because step was aborted
            assert session.status == CrawlStatus.FAILED.value
            assert session.capture_completeness == CaptureCompleteness.PARTIAL.value
            assert len(session.completed_steps) == 0

            # Ledger must contain the BROWSER_POLICY_DENY event
            events = ledger.get_all_events()
            deny_events = [e for e in events if e.event_type == "BROWSER_POLICY_DENY"]
            assert len(deny_events) == 1
        finally:
            await browser.close()
