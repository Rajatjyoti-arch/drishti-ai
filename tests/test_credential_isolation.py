"""Adversarial tests for CredentialBroker isolation, expiration, and target bindings."""

import pytest
import time
from drishti.policy.credential_broker import CredentialBroker
from drishti.core.exceptions import PolicyViolationError

@pytest.fixture
def broker():
    return CredentialBroker()

def test_credential_broker_enforces_target_binding(broker):
    # Authorized target: localhost
    cred = broker.get_credential("agency_a_admin", "localhost", "bola_test")
    assert cred.tenant_id == "AG_MUMBAI_01"
    assert "Bearer" in cred.auth_header_value

    # Unauthorized target: should be rejected
    with pytest.raises(PolicyViolationError, match="NOT authorized for target"):
        broker.get_credential("agency_a_admin", "external-unauthorized-api.com", "bola_test")

def test_credential_broker_enforces_revocation(broker):
    broker.revoke_credential("agency_b_admin")
    with pytest.raises(PolicyViolationError, match="has been REVOKED"):
        broker.get_credential("agency_b_admin", "localhost", "bola_test")

def test_credential_broker_detects_expiration(broker):
    cred = broker.get_credential("agency_a_subagent", "localhost", "test_expiry")
    assert cred.is_expired() is False
    # Manually shift expiry to past
    cred.expires_at = time.time() - 10
    assert cred.is_expired() is True

def test_credential_broker_rejects_unknown_reference(broker):
    with pytest.raises(PolicyViolationError, match="Unknown credential reference"):
        broker.get_credential("non_existent_agency", "localhost", "test")
