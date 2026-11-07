"""Unit tests for verification and finding lifecycle data models."""

import pytest
from drishti.core.models import (
    AttackHypothesis,
    CandidateFinding,
    InferredEndpoint,
    InvariantType,
    VerificationStatus,
    VerifiedFinding,
)
from drishti.verifier.models import (
    EvidenceManifest,
    EvidenceReference,
    ExecutionOutcome,
    ExecutorRunResult,
    FindingLifecycleState,
    LifecycleTransition,
    VerificationAttempt,
    VerificationResult,
)


def test_execution_outcome_enum():
    """Verify execution outcome states."""
    assert ExecutionOutcome.CANDIDATE == "CANDIDATE"
    assert ExecutionOutcome.EXPECTED_REJECTION == "EXPECTED_REJECTION"
    assert ExecutionOutcome.INCONCLUSIVE == "INCONCLUSIVE"
    assert ExecutionOutcome.ABORTED == "ABORTED"


def test_finding_lifecycle_state_enum():
    """Verify lifecycle state values."""
    assert FindingLifecycleState.CANDIDATE == "CANDIDATE"
    assert FindingLifecycleState.VERIFYING == "VERIFYING"
    assert FindingLifecycleState.CONFIRMED == "CONFIRMED"
    assert FindingLifecycleState.NOT_REPRODUCED == "NOT_REPRODUCED"
    assert FindingLifecycleState.INCONCLUSIVE == "INCONCLUSIVE"
    assert FindingLifecycleState.RETEST_REQUIRED == "RETEST_REQUIRED"
    assert FindingLifecycleState.FIXED == "FIXED"
    assert FindingLifecycleState.REOPENED == "REOPENED"


def test_evidence_manifest_creation():
    """Verify creation and serialization of EvidenceReference and EvidenceManifest."""
    ref = EvidenceReference(
        request_id="req_001",
        step_id="step_1_probe",
        phase="PROBE",
        method="GET",
        url="http://test/api/v2/bookings/TBOH_123",
        status_code=200,
        response_digest="a" * 64,
        policy_decision_nonce="dec_nonce_1",
        latency_ms=45,
        captured_bindings={"booking_id": "TBOH_123"},
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-001",
        execution_id="run_001",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref],
        raw_payload_hashes={"step_1_probe": "a" * 64},
        canary_spec_digest="b" * 64,
    )

    assert manifest.manifest_id.startswith("evm_")
    assert len(manifest.evidence_references) == 1
    assert manifest.evidence_references[0].status_code == 200
    assert manifest.canary_spec_digest == "b" * 64


def test_executor_run_result():
    """Verify ExecutorRunResult contract and convenience finding property."""
    manifest = EvidenceManifest(
        plan_id="PLAN-002",
        execution_id="run_002",
        invariant_id=InvariantType.PRICING_INTEGRITY,
    )

    cand = CandidateFinding(
        candidate_id="cand_002",
        hypothesis=AttackHypothesis(
            hypothesis_id="hyp_002",
            target_endpoint=InferredEndpoint(
                endpoint_id="test:ep",
                method="POST",
                path_template="/api/v2/bookings",
                auth_required=True,
                roles_observed=["agency_admin"],
                parameters={},
                source_har_request_id="req_0",
                raw_packet_hash="c" * 64,
                confidence_score=0.95,
            ),
            invariant_targeted=InvariantType.PRICING_INTEGRITY,
            rationale="Pricing flaw",
            test_strategy="tamper",
            attacker_tenant_id="agency_b",
            victim_tenant_id="agency_a",
        ),
        observed_status_code=200,
        raw_response_snippet='{"amount_minor_units": 100}',
    )

    result = ExecutorRunResult(
        plan_id="PLAN-002",
        invariant_id=InvariantType.PRICING_INTEGRITY,
        outcome=ExecutionOutcome.CANDIDATE,
        candidate=cand,
        evidence_manifest=manifest,
        completed_steps=["step_1", "step_2"],
        persisted_resource_id="TBOH_456",
        baseline_summary={"amount_minor_units": 1800000},
        probe_summary={"tampered_amount": 100},
    )

    assert result.outcome == ExecutionOutcome.CANDIDATE
    assert result.finding is not None
    assert result.finding.candidate_id == "cand_002"
    assert result.persisted_resource_id == "TBOH_456"
