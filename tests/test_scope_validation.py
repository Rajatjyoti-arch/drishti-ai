"""Adversarial tests for ScopeValidator and EgressGuard."""

import pytest
from drishti.core.contract import AuthorizationContract, TestTenants
from drishti.policy.scope_validator import ScopeValidator
from drishti.policy.egress_guard import EgressGuard
from drishti.core.exceptions import OutOfScopeError

@pytest.fixture
def mock_contract():
    return AuthorizationContract(
        permitted_targets=["staging.tbo-sandbox.internal", "localhost", "127.0.0.1"],
        test_tenants=TestTenants(
            attacker_tenant_id="AG_MUMBAI_01",
            victim_tenant_id="AG_DELHI_02"
        ),
        prohibited_actions=["DROP", "DELETE_PRODUCTION_DATA"]
    )

def test_scope_validator_allows_permitted_target(mock_contract):
    validator = ScopeValidator(mock_contract)
    is_valid, reason = validator.validate_url("http://127.0.0.1:8000/api/v2/hotels")
    assert is_valid is True

def test_scope_validator_rejects_unauthorized_host(mock_contract):
    validator = ScopeValidator(mock_contract)
    with pytest.raises(OutOfScopeError, match="not in permitted targets"):
        validator.validate_url("https://malicious-external-site.com/steal-data")

def test_scope_validator_rejects_forbidden_scheme(mock_contract):
    validator = ScopeValidator(mock_contract)
    with pytest.raises(OutOfScopeError, match="Forbidden scheme"):
        validator.validate_url("gopher://127.0.0.1:8000/something")

def test_scope_validator_rejects_forbidden_port(mock_contract):
    validator = ScopeValidator(mock_contract)
    with pytest.raises(OutOfScopeError, match="Forbidden destination port"):
        validator.validate_url("http://127.0.0.1:22/ssh-probe")

def test_egress_guard_blocks_out_of_scope_redirect(mock_contract):
    validator = ScopeValidator(mock_contract)
    guard = EgressGuard(validator)
    
    current_url = "http://127.0.0.1:8000/api/v1/auth"
    malicious_redirect = "https://attacker-controlled-server.com/callback"
    
    with pytest.raises(OutOfScopeError, match="BLOCKED by EgressGuard"):
        guard.validate_redirect(current_url, malicious_redirect)
