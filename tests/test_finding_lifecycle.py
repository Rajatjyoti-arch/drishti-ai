"""Unit tests for FindingLifecycleManager state transitions and audit history."""

import pytest
from drishti.core.models import InvariantType, VerificationStatus, VerifiedFinding
from drishti.verifier.finding_manager import FindingLifecycleManager
from drishti.verifier.models import FindingLifecycleState


@pytest.fixture
def sample_verified_finding():
    return VerifiedFinding(
        finding_id="VF-travel-001",
        invariant_id=InvariantType.TENANT_ISOLATION,
        status=VerificationStatus.CONFIRMED,
        title="BOLA in Booking API",
        target_endpoint="travel_api:canonical:GET:/api/v2/bookings/{booking_id}",
        violated_rule="OWASP API1:2023",
        confidence_score=0.98,
        business_impact={"confidentiality": "CRITICAL"},
        exposed_sensitive_fields=["passenger_passport"],
        reproduction_steps=[],
        request_evidence_hash="evm_hash_1",
        raw_response_diff="canary_token_revealed",
        suggested_fix="Validate tenant ownership",
    )


def test_finding_registration_and_initial_state(sample_verified_finding):
    """Registering a finding initializes state and transition history."""
    mgr = FindingLifecycleManager()
    mgr.register_finding(sample_verified_finding, initial_state=FindingLifecycleState.CONFIRMED)

    assert mgr.get_state("VF-travel-001") == FindingLifecycleState.CONFIRMED
    assert mgr.get_finding("VF-travel-001") is not None
    history = mgr.get_history("VF-travel-001")
    assert len(history) == 1
    assert history[0].to_state == FindingLifecycleState.CONFIRMED


def test_valid_lifecycle_transitions(sample_verified_finding):
    """CONFIRMED -> RETEST_REQUIRED -> VERIFYING -> FIXED workflow."""
    mgr = FindingLifecycleManager()
    mgr.register_finding(sample_verified_finding, initial_state=FindingLifecycleState.CONFIRMED)

    # 1. Dev team deploys patch -> mark RETEST_REQUIRED
    tr1 = mgr.transition_state(
        finding_id="VF-travel-001",
        new_state=FindingLifecycleState.RETEST_REQUIRED,
        reason="Patch deployed in staging",
        actor="DevSecOps",
    )
    assert tr1.to_state == FindingLifecycleState.RETEST_REQUIRED
    assert mgr.get_state("VF-travel-001") == FindingLifecycleState.RETEST_REQUIRED

    # 2. Automated retest initiated -> mark VERIFYING
    tr2 = mgr.transition_state(
        finding_id="VF-travel-001",
        new_state=FindingLifecycleState.VERIFYING,
        reason="Automated retest probe dispatched",
        actor="VerificationOracle",
    )
    assert tr2.to_state == FindingLifecycleState.VERIFYING

    # 3. Target correctly rejects probe with 403 Forbidden -> mark FIXED
    tr3 = mgr.transition_state(
        finding_id="VF-travel-001",
        new_state=FindingLifecycleState.FIXED,
        reason="Retest confirmed 403 Forbidden across all tenants",
        actor="VerificationOracle",
    )
    assert tr3.to_state == FindingLifecycleState.FIXED
    assert len(mgr.get_history("VF-travel-001")) == 4


def test_invalid_lifecycle_transition_raises_error(sample_verified_finding):
    """Direct invalid transition (e.g. CONFIRMED -> FIXED without verification) is rejected."""
    mgr = FindingLifecycleManager()
    mgr.register_finding(sample_verified_finding, initial_state=FindingLifecycleState.CONFIRMED)

    with pytest.raises(ValueError, match="Invalid lifecycle transition"):
        mgr.transition_state(
            finding_id="VF-travel-001",
            new_state=FindingLifecycleState.FIXED,
            reason="Illegal jump to FIXED",
        )


def test_reopen_regression_transition(sample_verified_finding):
    """FIXED -> REOPENED when regression is detected in later scans."""
    mgr = FindingLifecycleManager()
    mgr.register_finding(sample_verified_finding, initial_state=FindingLifecycleState.CONFIRMED)

    mgr.transition_state("VF-travel-001", FindingLifecycleState.RETEST_REQUIRED, "Retest")
    mgr.transition_state("VF-travel-001", FindingLifecycleState.VERIFYING, "Verifying")
    mgr.transition_state("VF-travel-001", FindingLifecycleState.FIXED, "Fixed")

    # Regression detected in production canary monitor
    tr = mgr.transition_state(
        "VF-travel-001",
        FindingLifecycleState.REOPENED,
        "Regression: Canary token disclosed again during canary scan",
    )
    assert tr.to_state == FindingLifecycleState.REOPENED
    assert mgr.get_state("VF-travel-001") == FindingLifecycleState.REOPENED


def test_list_findings_filter(sample_verified_finding):
    """Filter registered findings by lifecycle state."""
    mgr = FindingLifecycleManager()
    mgr.register_finding(sample_verified_finding, initial_state=FindingLifecycleState.CONFIRMED)

    confirmed = mgr.list_findings(state=FindingLifecycleState.CONFIRMED)
    fixed = mgr.list_findings(state=FindingLifecycleState.FIXED)

    assert len(confirmed) == 1
    assert len(fixed) == 0
