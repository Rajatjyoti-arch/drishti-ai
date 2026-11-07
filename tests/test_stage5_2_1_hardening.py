"""Regression and hardening tests for Stage 5.2.1.

Verifies:
1. EXPECTED_REJECTION with corrupted manifest returns INCONCLUSIVE.
2. EXPECTED_REJECTION after Guard denial returns INCONCLUSIVE.
3. Canary secret unavailable fails closed (INCONCLUSIVE).
4. Unrelated generic "canary" string is not confirmed.
5. Forged SHA-256 digest is detected and rejected.
6. Missing audit checkpoint fails evidence validation.
7. Invalid policy decision nonce fails evidence validation.
8. Amount matches but currency differs is not confirmed.
9. Currency matches but amount differs is not confirmed.
10. Reused finding ID preserves existing history.
11. Process restart recovers lifecycle history from SQLite.
12. I-02 recipe with environment variable actually expands in Bash.
13. I-01 recipe honors target_path and safely encodes resource ID.
"""

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from drishti.core.models import (
    AttackHypothesis,
    CandidateFinding,
    InferredEndpoint,
    InvariantType,
    PolicyAction,
    PolicyDecision,
    VerificationStatus,
    VerifiedFinding,
)
from drishti.policy.client import SafeHttpClient
from drishti.policy.transports import InProcessFixtureTransport
from drishti.verifier.evidence_validator import EvidenceValidator
from drishti.verifier.finding_manager import FindingLifecycleManager
from drishti.verifier.models import (
    EvidenceManifest,
    EvidenceReference,
    ExecutionOutcome,
    ExecutorRunResult,
    FindingLifecycleState,
)
from drishti.verifier.oracle import VerificationOracle
from drishti.verifier.reproduction import ReproductionRecipeGenerator
from tests.fixtures.vulnerable_app import create_vulnerable_app


def build_mock_gate():
    gate = MagicMock()
    gate.budgets.execution.timeout_seconds = 10.0

    async def mock_eval(req, approval_token=None):
        return PolicyDecision(
            action=PolicyAction.ALLOW,
            approved=True,
            reason="Test allow",
            sanitized_url="http://test",
            budget_remaining=100,
            decision_id="dec_0123456789ab",
        )

    gate.evaluate_request = mock_eval
    gate.credential_broker.get_credential.return_value = MagicMock(
        auth_header_key="Authorization",
        auth_header_value="Bearer mock_jwt_agency_b_admin_token",
    )
    return gate


@pytest.fixture
def valid_candidate_finding():
    return CandidateFinding(
        candidate_id="cand_test_001",
        hypothesis=AttackHypothesis(
            hypothesis_id="hyp_test_001",
            target_endpoint=InferredEndpoint(
                endpoint_id="test_ep",
                method="GET",
                path_template="/api/v2/bookings/{booking_id}",
                auth_required=True,
                roles_observed=["agency_admin"],
                parameters={},
                source_har_request_id="syn_1",
                raw_packet_hash="a" * 64,
                confidence_score=0.95,
            ),
            invariant_targeted=InvariantType.TENANT_ISOLATION,
            rationale="BOLA candidate",
            test_strategy="Probe",
            attacker_tenant_id="agency_b",
            victim_tenant_id="agency_a",
        ),
        observed_status_code=200,
        raw_response_snippet='{"canary_token": "secret_canary_value_123"}',
    )


# 1. EXPECTED_REJECTION with corrupted manifest -> INCONCLUSIVE
@pytest.mark.asyncio
async def test_expected_rejection_with_corrupted_manifest_is_inconclusive():
    gate = build_mock_gate()
    http_client = SafeHttpClient(
        policy_gate=gate,
        transport=InProcessFixtureTransport(app=create_vulnerable_app()),
    )

    # Manifest with invalid digest format
    ref = EvidenceReference(
        request_id="req_corrupt",
        step_id="step_probe",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/api/v2/bookings/TBOH_1",
        status_code=200,
        response_digest="invalid_short_digest",
        policy_decision_nonce="dec_0123456789ab",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-CORRUPT",
        execution_id="run_corrupt",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref],
        audit_ledger_checkpoint="chk_1234567890abcdef",
    )

    run_result = ExecutorRunResult(
        plan_id="PLAN-CORRUPT",
        invariant_id=InvariantType.TENANT_ISOLATION,
        outcome=ExecutionOutcome.EXPECTED_REJECTION,
        evidence_manifest=manifest,
        reason="Target application rejected probe with HTTP 403",
    )

    oracle = VerificationOracle(http_client=http_client)
    res = await oracle.verify(run_result, base_url="http://test")

    assert res.status == VerificationStatus.INCONCLUSIVE
    assert res.confidence_score == 0.30
    assert "Evidence manifest validation failed on expected rejection" in res.confidence_rationale


# 2. EXPECTED_REJECTION after Guard denial -> INCONCLUSIVE (confidence: 0.0)
@pytest.mark.asyncio
async def test_expected_rejection_after_guard_denial_is_inconclusive():
    gate = build_mock_gate()
    http_client = SafeHttpClient(
        policy_gate=gate,
        transport=InProcessFixtureTransport(app=create_vulnerable_app()),
    )

    ref = EvidenceReference(
        request_id="req_valid",
        step_id="step_probe",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/api/v2/bookings/TBOH_1",
        status_code=200,
        response_digest="a" * 64,
        policy_decision_nonce="dec_0123456789ab",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-DENIED",
        execution_id="run_denied",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref],
        audit_ledger_checkpoint="chk_1234567890abcdef",
    )

    run_result = ExecutorRunResult(
        plan_id="PLAN-DENIED",
        invariant_id=InvariantType.TENANT_ISOLATION,
        outcome=ExecutionOutcome.EXPECTED_REJECTION,
        evidence_manifest=manifest,
        reason="Transport request REJECTED by Policy Gate [DENY]: Target out of scope",
    )

    oracle = VerificationOracle(http_client=http_client)
    res = await oracle.verify(run_result, base_url="http://test")

    assert res.status == VerificationStatus.INCONCLUSIVE
    assert res.confidence_score == 0.0
    assert "rejected by Policy Gate / Guard" in res.confidence_rationale


# 3. Canary secret unavailable -> fails closed (INCONCLUSIVE)
@pytest.mark.asyncio
async def test_canary_secret_unavailable_fails_closed_inconclusive(valid_candidate_finding):
    gate = build_mock_gate()
    http_client = SafeHttpClient(
        policy_gate=gate,
        transport=InProcessFixtureTransport(app=create_vulnerable_app()),
    )

    ref_nc = EvidenceReference(
        request_id="req_nc",
        step_id="step_nc",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/api/v2/bookings/TBOH_1",
        status_code=200,
        response_digest="a" * 64,
        policy_decision_nonce="dec_0123456789ab",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-CANARY-FAIL",
        execution_id="run_canary_fail",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref_nc],
        canary_spec_digest="b" * 64,
        audit_ledger_checkpoint="chk_1234567890abcdef",
    )

    run_result = ExecutorRunResult(
        plan_id="PLAN-CANARY-FAIL",
        invariant_id=InvariantType.TENANT_ISOLATION,
        outcome=ExecutionOutcome.CANDIDATE,
        candidate=valid_candidate_finding,
        evidence_manifest=manifest,
        persisted_resource_id="TBOH_1",
    )

    oracle = VerificationOracle(http_client=http_client)
    # canary_secret=None (unavailable) -> must fail closed
    res = await oracle.verify(run_result, base_url="http://test", canary_secret=None)

    assert res.status == VerificationStatus.INCONCLUSIVE
    assert res.confidence_score == 0.30
    assert any("failing closed" in issue for issue in res.attempts[0].details.get("issues", []))


# 4. Unrelated generic "canary" string is not confirmed
@pytest.mark.asyncio
async def test_unrelated_generic_canary_string_not_confirmed(valid_candidate_finding):
    gate = build_mock_gate()
    http_client = SafeHttpClient(
        policy_gate=gate,
        transport=InProcessFixtureTransport(app=create_vulnerable_app()),
    )

    # Mock send_request for read-back to return an unrelated "canary" word
    async def mock_readback_send(req, approval_token=None, max_response_size_bytes=None):
        import httpx
        # Returns generic canary status without the actual secret
        content = b'{"status": "CONFIRMED", "canary_status": "enabled", "booking_id": "TBOH_1"}'
        return httpx.Response(200, content=content)

    http_client.send_request = mock_readback_send

    secret = "exact_canary_token_9999"
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()

    ref_nc = EvidenceReference(
        request_id="req_nc",
        step_id="step_nc",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/api/v2/bookings/TBOH_1",
        status_code=200,
        response_digest="a" * 64,
        policy_decision_nonce="dec_0123456789ab",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-GENERIC",
        execution_id="run_generic",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref_nc],
        canary_spec_digest=digest,
        audit_ledger_checkpoint="chk_1234567890abcdef",
    )

    run_result = ExecutorRunResult(
        plan_id="PLAN-GENERIC",
        invariant_id=InvariantType.TENANT_ISOLATION,
        outcome=ExecutionOutcome.CANDIDATE,
        candidate=valid_candidate_finding,
        evidence_manifest=manifest,
        persisted_resource_id="TBOH_1",
    )

    oracle = VerificationOracle(http_client=http_client)
    res = await oracle.verify(run_result, base_url="http://test", canary_secret=secret)

    # Generic "canary_status" does NOT confirm
    assert res.status == VerificationStatus.INCONCLUSIVE
    assert res.verified_finding is None


# 5. Forged SHA-256 digest is rejected by validator
def test_forged_sha256_digest_rejected():
    validator = EvidenceValidator()
    real_body = '{"booking_id": "TBOH_123", "amount": 100}'
    real_digest = hashlib.sha256(real_body.encode("utf-8")).hexdigest()
    forged_digest = "f" * 64  # valid hex format, but wrong content!

    ref = EvidenceReference(
        request_id="req_1",
        step_id="step_1",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/1",
        status_code=200,
        response_digest=forged_digest,
        policy_decision_nonce="dec_0123456789ab",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-FORGED",
        execution_id="run_forged",
        invariant_id=InvariantType.PRICING_INTEGRITY,
        evidence_references=[ref],
        audit_ledger_checkpoint="chk_1234567890abcdef",
    )

    # Pass actual raw payloads to verify re-computation detects forgery
    report = validator.validate_manifest(
        manifest=manifest,
        raw_payloads={"req_1": real_body},
    )

    assert not report.is_valid
    assert not report.digests_verified
    assert any("forged digest" in issue for issue in report.issues)


# 6. Missing audit checkpoint fails evidence validation
def test_missing_audit_checkpoint_fails_validation():
    validator = EvidenceValidator()
    ref = EvidenceReference(
        request_id="req_1",
        step_id="step_1",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/1",
        status_code=200,
        response_digest="a" * 64,
        policy_decision_nonce="dec_0123456789ab",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-NO-CHK",
        execution_id="run_no_chk",
        invariant_id=InvariantType.PRICING_INTEGRITY,
        evidence_references=[ref],
        audit_ledger_checkpoint=None,  # missing checkpoint!
    )
    report = validator.validate_manifest(manifest)
    assert not report.is_valid
    assert any("Missing required audit ledger checkpoint" in issue for issue in report.issues)


# 7. Invalid policy decision nonce fails evidence validation
def test_invalid_policy_decision_nonce_fails_validation():
    validator = EvidenceValidator()
    ref = EvidenceReference(
        request_id="req_1",
        step_id="step_1",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/1",
        status_code=200,
        response_digest="a" * 64,
        policy_decision_nonce="invalid_nonce_without_prefix",  # missing dec_ prefix!
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-BAD-NONCE",
        execution_id="run_bad_nonce",
        invariant_id=InvariantType.PRICING_INTEGRITY,
        evidence_references=[ref],
        audit_ledger_checkpoint="chk_1234567890abcdef",
    )
    report = validator.validate_manifest(manifest)
    assert not report.is_valid
    assert any("invalid or missing policy decision nonce" in issue for issue in report.issues)


# 8. Amount matches but currency differs -> Not confirmed
@pytest.mark.asyncio
async def test_i02_read_back_amount_matches_but_currency_differs_not_confirmed(valid_candidate_finding):
    gate = build_mock_gate()
    http_client = SafeHttpClient(
        policy_gate=gate,
        transport=InProcessFixtureTransport(app=create_vulnerable_app()),
    )

    # Readback returns tampered amount 100, but wrong currency 'USD' (expected authoritative quote was 'INR')
    async def mock_readback(req, approval_token=None, max_response_size_bytes=None):
        import httpx
        content = b'{"status": "CONFIRMED", "amount_minor_units": 100, "currency": "USD"}'
        return httpx.Response(200, content=content)

    http_client.send_request = mock_readback

    ref_nc = EvidenceReference(
        request_id="req_nc",
        step_id="step_nc",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/api/v2/bookings/TBOH_1",
        status_code=200,
        response_digest="a" * 64,
        policy_decision_nonce="dec_0123456789ab",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-PRICE-MISMATCH",
        execution_id="run_price_mismatch",
        invariant_id=InvariantType.PRICING_INTEGRITY,
        evidence_references=[ref_nc],
        audit_ledger_checkpoint="chk_1234567890abcdef",
    )

    run_result = ExecutorRunResult(
        plan_id="PLAN-PRICE-MISMATCH",
        invariant_id=InvariantType.PRICING_INTEGRITY,
        outcome=ExecutionOutcome.CANDIDATE,
        candidate=valid_candidate_finding,
        evidence_manifest=manifest,
        persisted_resource_id="TBOH_1",
        baseline_summary={"amount_minor_units": 1800000, "currency": "INR"},
        probe_summary={"tampered_amount": 100, "tampered_currency": None},  # Amount tampering variant
    )

    oracle = VerificationOracle(http_client=http_client)
    res = await oracle.verify(run_result, base_url="http://test")

    # Currency is USD instead of INR -> must NOT be confirmed
    assert res.status == VerificationStatus.INCONCLUSIVE
    assert res.verified_finding is None


# 9. Currency matches but amount differs -> Not confirmed
@pytest.mark.asyncio
async def test_i02_read_back_currency_matches_but_amount_differs_not_confirmed(valid_candidate_finding):
    gate = build_mock_gate()
    http_client = SafeHttpClient(
        policy_gate=gate,
        transport=InProcessFixtureTransport(app=create_vulnerable_app()),
    )

    # Readback returns tampered currency 'IDR', but wrong amount 99999 (expected authoritative quote was 1800000)
    async def mock_readback(req, approval_token=None, max_response_size_bytes=None):
        import httpx
        content = b'{"status": "CONFIRMED", "amount_minor_units": 99999, "currency": "IDR"}'
        return httpx.Response(200, content=content)

    http_client.send_request = mock_readback

    ref_nc = EvidenceReference(
        request_id="req_nc",
        step_id="step_nc",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/api/v2/bookings/TBOH_1",
        status_code=200,
        response_digest="a" * 64,
        policy_decision_nonce="dec_0123456789ab",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-CURR-MISMATCH",
        execution_id="run_curr_mismatch",
        invariant_id=InvariantType.PRICING_INTEGRITY,
        evidence_references=[ref_nc],
        audit_ledger_checkpoint="chk_1234567890abcdef",
    )

    run_result = ExecutorRunResult(
        plan_id="PLAN-CURR-MISMATCH",
        invariant_id=InvariantType.PRICING_INTEGRITY,
        outcome=ExecutionOutcome.CANDIDATE,
        candidate=valid_candidate_finding,
        evidence_manifest=manifest,
        persisted_resource_id="TBOH_1",
        baseline_summary={"amount_minor_units": 1800000, "currency": "INR"},
        probe_summary={"tampered_amount": None, "tampered_currency": "IDR"},  # Currency tampering variant
    )

    oracle = VerificationOracle(http_client=http_client)
    res = await oracle.verify(run_result, base_url="http://test")

    assert res.status == VerificationStatus.INCONCLUSIVE
    assert res.verified_finding is None


# 10. Reused finding ID preserves existing history
def test_reused_finding_id_preserves_existing_history(tmp_path):
    db_file = tmp_path / "lifecycle.db"
    mgr = FindingLifecycleManager(db_path=db_file)

    vf = VerifiedFinding(
        finding_id="VF-IDEMPOTENT-001",
        invariant_id=InvariantType.TENANT_ISOLATION,
        status=VerificationStatus.CONFIRMED,
        title="BOLA Finding",
        target_endpoint="/ep",
        violated_rule="Rule 1",
        confidence_score=0.95,
        business_impact={},
        exposed_sensitive_fields=[],
        reproduction_steps=[],
        request_evidence_hash="evm_1",
        raw_response_diff="diff",
        suggested_fix="Fix",
    )

    # Initial registration in CONFIRMED state
    mgr.register_finding(vf, initial_state=FindingLifecycleState.CONFIRMED)
    mgr.transition_state("VF-IDEMPOTENT-001", FindingLifecycleState.RETEST_REQUIRED, "Retest needed")

    assert mgr.get_state("VF-IDEMPOTENT-001") == FindingLifecycleState.RETEST_REQUIRED
    assert len(mgr.get_history("VF-IDEMPOTENT-001")) == 2

    # Attempt to re-register with same finding ID
    mgr.register_finding(vf, initial_state=FindingLifecycleState.CONFIRMED)

    # State must NOT be reset to CONFIRMED; existing state and history preserved!
    assert mgr.get_state("VF-IDEMPOTENT-001") == FindingLifecycleState.RETEST_REQUIRED
    assert len(mgr.get_history("VF-IDEMPOTENT-001")) == 2


# 11. Process restart recovers lifecycle history from SQLite
def test_process_restart_recovers_lifecycle_history(tmp_path):
    db_file = tmp_path / "durable_lifecycle.db"
    mgr1 = FindingLifecycleManager(db_path=db_file)

    vf = VerifiedFinding(
        finding_id="VF-DURABLE-001",
        invariant_id=InvariantType.PRICING_INTEGRITY,
        status=VerificationStatus.CONFIRMED,
        title="Pricing Flaw",
        target_endpoint="/ep",
        violated_rule="CWE-472",
        confidence_score=0.98,
        business_impact={},
        exposed_sensitive_fields=[],
        reproduction_steps=[],
        request_evidence_hash="evm_durable",
        raw_response_diff="diff",
        suggested_fix="Fix",
    )

    mgr1.register_finding(vf, initial_state=FindingLifecycleState.CONFIRMED)
    mgr1.transition_state("VF-DURABLE-001", FindingLifecycleState.RETEST_REQUIRED, "Patch staged")
    mgr1.transition_state("VF-DURABLE-001", FindingLifecycleState.VERIFYING, "Running retest probe")
    mgr1.transition_state("VF-DURABLE-001", FindingLifecycleState.FIXED, "Target returns 400")

    # Simulate process termination and restart with a fresh manager pointing to same SQLite database
    mgr2 = FindingLifecycleManager(db_path=db_file)

    assert mgr2.get_state("VF-DURABLE-001") == FindingLifecycleState.FIXED
    assert mgr2.get_finding("VF-DURABLE-001") is not None
    assert mgr2.get_finding("VF-DURABLE-001").finding_id == "VF-DURABLE-001"

    history = mgr2.get_history("VF-DURABLE-001")
    assert len(history) == 4
    assert history[-1].to_state == FindingLifecycleState.FIXED
    assert history[-1].reason == "Target returns 400"


# 12. I-02 recipe with environment variable actually expands in Bash
def test_i02_reproduction_recipe_expands_in_bash():
    recipes = ReproductionRecipeGenerator.generate_i02_recipes(
        booking_id="TBOH_123",
        tampered_amount=100,
        tampered_currency="INR",
        authoritative_amount=1800000,
        authoritative_currency="INR",
    )

    probe_step = recipes[2]
    # Verify the curl command contains the -d argument
    assert "-d" in probe_step.curl_command

    # Run actual bash command evaluating the -d payload with exported environment variable
    test_token = "HLD_REAL_TOKEN_9999"
    bash_script = f"""
    export DRISHTI_HOLD_TOKEN="{test_token}"
    payload=$(echo {probe_step.curl_command.split('-d ')[1]})
    echo "$payload"
    """

    res = subprocess.run(
        ["bash", "-c", bash_script],
        capture_output=True,
        text=True,
        check=True,
    )
    output = res.stdout.strip()
    data = json.loads(output)
    # Assert that $DRISHTI_HOLD_TOKEN expanded to HLD_REAL_TOKEN_9999 and was NOT a literal string
    assert data["hold_token"] == test_token
    assert data["client_amount_minor_units"] == 100
    assert data["client_currency"] == "INR"


# 13. I-01 recipe honors target_path and safely encodes resource ID
def test_i01_reproduction_recipe_honors_target_path():
    custom_path = "/api/v3/special_tenant/bookings/{booking_id}/summary"
    recipes = ReproductionRecipeGenerator.generate_i01_recipes(
        victim_booking_id="TBOH_victim/foo?bar",
        target_path=custom_path,
    )

    probe_step = recipes[2]
    # Must use custom_path template
    assert "/api/v3/special_tenant/bookings/" in probe_step.curl_command
    assert "/summary" in probe_step.curl_command
    # Slashes and question marks in booking ID must be URL-encoded (%2F, %3F)
    assert "TBOH_victim%2Ffoo%3Fbar" in probe_step.curl_command
