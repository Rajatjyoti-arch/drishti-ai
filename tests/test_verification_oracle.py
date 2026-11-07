"""End-to-End tests for VerificationOracle, independent read-back, and confidence scoring."""

import hashlib
from pathlib import Path
import tempfile
import pytest
from unittest.mock import MagicMock

from drishti.audit.ledger import TamperEvidentLedger
from drishti.core.models import (
    InvariantType,
    PolicyAction,
    PolicyDecision,
    VerificationStatus,
)
from drishti.executors.attack_plan import AttackPlanCompiler, CanarySecretStore
from drishti.executors.i01_tenant_isolation import BOLAExecutor
from drishti.executors.i02_pricing_integrity import PricingIntegrityExecutor
from drishti.graph.schema import HypothesisNode
from drishti.policy.client import SafeHttpClient
from drishti.policy.gate import PolicyGate
from drishti.policy.transports import InProcessFixtureTransport
from drishti.verifier.models import ExecutionOutcome, ExecutorRunResult
from drishti.verifier.oracle import VerificationOracle
from tests.fixtures.patched_app import create_patched_app
from tests.fixtures.vulnerable_app import create_vulnerable_app


def build_mock_policy_gate():
    gate = MagicMock()
    decisions = {}
    db_file = Path(tempfile.mktemp(suffix=".db"))
    ledger = TamperEvidentLedger(db_path=db_file)
    gate.ledger = ledger

    async def mock_eval(req, approval_token=None):
        dec = PolicyDecision(
            action=PolicyAction.ALLOW,
            approved=True,
            reason="Approved for testing",
            sanitized_url=req.url,
            budget_remaining=100,
        )
        decisions[dec.decision_id] = {
            "decision_id": dec.decision_id,
            "request_id": req.request_id,
            "test_id": req.test_id,
            "action": "ALLOW",
            "approved": True,
            "url": req.url,
            "method": req.method,
        }
        ledger.record_event(
            event_id=dec.decision_id,
            event_type="POLICY_ALLOW",
            payload_digest=hashlib.sha256(f"{req.method}:{req.url}".encode()).hexdigest(),
            metadata={"request_id": req.request_id, "url": req.url},
        )
        return dec

    gate.evaluate_request = mock_eval
    gate.get_decision = lambda did: decisions.get(did)
    gate.budgets.execution.timeout_seconds = 10.0

    def mock_get_cred(credential_ref, target_hostname, purpose):
        if "agency_a" in (credential_ref or "") or "AG_MUMBAI" in (credential_ref or ""):
            return MagicMock(
                auth_header_key="Authorization",
                auth_header_value="Bearer mock_jwt_agency_a_admin_token",
            )
        return MagicMock(
            auth_header_key="Authorization",
            auth_header_value="Bearer mock_jwt_agency_b_admin_token",
        )

    gate.credential_broker.get_credential.side_effect = mock_get_cred
    return gate


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


@pytest.fixture
def hypothesis_i02():
    return HypothesisNode(
        hypothesis_id="hyp_travel_pricing_02",
        invariant_id=InvariantType.PRICING_INTEGRITY.value,
        target_endpoint_identity="travel_api:canonical:POST:/api/v2/bookings",
        attacker_tenant_id="AG_DELHI_02",
        victim_tenant_id="AG_MUMBAI_01",
        rationale="Client price parameters may override server quote during checkout transition",
    )


@pytest.mark.asyncio
async def test_oracle_confirms_i01_bola_on_vulnerable_app(hypothesis_i01):
    """Oracle performs independent read-back and confirms I-01 BOLA vulnerability with high confidence."""
    gate = build_mock_policy_gate()
    app = create_vulnerable_app()
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i01,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        fixture_setup_approved=True,
        seed="oracle_test_bola_vuln",
    )

    # 1. Specialist executor runs and produces candidate
    executor = BOLAExecutor(http_client=http_client)
    run_result = await executor.execute(plan, base_url="http://test")
    assert run_result.outcome == ExecutionOutcome.CANDIDATE
    assert run_result.candidate is not None

    canary_secret = CanarySecretStore.get_secret(plan.canary_spec.canary_secret_ref)

    # 2. Independent Verification Oracle audits manifest and runs independent read-back
    oracle = VerificationOracle(http_client=http_client)
    verif_res = await oracle.verify(
        run_result=run_result,
        base_url="http://test",
        canary_secret=canary_secret,
    )

    assert verif_res.status == VerificationStatus.CONFIRMED
    assert verif_res.confidence_score >= 0.95
    assert "read-back confirmed" in verif_res.confidence_rationale

    vf = verif_res.verified_finding
    assert vf is not None
    assert vf.invariant_id == InvariantType.TENANT_ISOLATION
    assert "OWASP API1:2023" in vf.violated_rule
    assert "passenger_passport" in vf.exposed_sensitive_fields
    assert len(vf.reproduction_steps) == 4
    assert "Enforce tenant ownership validation" in vf.suggested_fix


@pytest.mark.asyncio
async def test_oracle_verifies_i01_defense_on_patched_app(hypothesis_i01):
    """Oracle verifies that patched app maintained tenant isolation (NOT_REPRODUCED, 1.0 confidence)."""
    gate = build_mock_policy_gate()
    app = create_patched_app()
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i01,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        fixture_setup_approved=True,
        seed="oracle_test_bola_patched",
    )

    executor = BOLAExecutor(http_client=http_client)
    run_result = await executor.execute(plan, base_url="http://test")
    assert run_result.outcome == ExecutionOutcome.EXPECTED_REJECTION

    oracle = VerificationOracle(http_client=http_client)
    verif_res = await oracle.verify(run_result=run_result, base_url="http://test")

    assert verif_res.status == VerificationStatus.NOT_REPRODUCED
    assert verif_res.confidence_score == 1.0
    assert verif_res.verified_finding is None


@pytest.mark.asyncio
async def test_oracle_confirms_i02_pricing_tampering_on_vulnerable_app(hypothesis_i02):
    """Oracle independently reads back persisted database record to confirm financial manipulation."""
    gate = build_mock_policy_gate()
    app = create_vulnerable_app()
    transport = InProcessFixtureTransport(app=app)
    http_client = SafeHttpClient(policy_gate=gate, transport=transport)

    plan = AttackPlanCompiler.compile_plan(
        hypothesis=hypothesis_i02,
        attacker_credential_ref="cred:agency_b:admin",
        victim_credential_ref="cred:agency_a:admin",
        tampering_mode="amount",
        tampered_amount_minor_units=100,  # ₹1.00
        fixture_setup_approved=True,
        synthetic_mutation_approved=True,
        seed="oracle_test_pricing_vuln",
    )

    executor = PricingIntegrityExecutor(http_client=http_client)
    run_result = await executor.execute(plan, base_url="http://test")
    assert run_result.outcome == ExecutionOutcome.CANDIDATE
    assert run_result.persisted_resource_id is not None

    oracle = VerificationOracle(http_client=http_client)
    verif_res = await oracle.verify(run_result=run_result, base_url="http://test")

    assert verif_res.status == VerificationStatus.CONFIRMED
    assert verif_res.confidence_score >= 0.95

    # Check attempt details confirm independent read-back matched persisted price
    attempt = verif_res.attempts[0]
    assert attempt.read_back_performed
    assert attempt.read_back_matched
    assert attempt.details.get("persisted_amount") == 100

    vf = verif_res.verified_finding
    assert vf is not None
    assert vf.invariant_id == InvariantType.PRICING_INTEGRITY
    assert vf.business_impact["financial_loss"] == "CRITICAL"
    assert len(vf.reproduction_steps) == 4


@pytest.mark.asyncio
async def test_oracle_verifies_i02_defense_on_patched_app(hypothesis_i02):
    """Oracle verifies patched app rejected pricing tampering (NOT_REPRODUCED)."""
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
        seed="oracle_test_pricing_patched",
    )

    executor = PricingIntegrityExecutor(http_client=http_client)
    run_result = await executor.execute(plan, base_url="http://test")
    assert run_result.outcome == ExecutionOutcome.EXPECTED_REJECTION

    oracle = VerificationOracle(http_client=http_client)
    verif_res = await oracle.verify(run_result=run_result, base_url="http://test")

    assert verif_res.status == VerificationStatus.NOT_REPRODUCED
    assert verif_res.confidence_score == 1.0


@pytest.mark.asyncio
async def test_oracle_marks_inconclusive_on_failed_manifest():
    """If evidence manifest contains digest discrepancies, oracle marks INCONCLUSIVE."""
    gate = build_mock_policy_gate()
    http_client = SafeHttpClient(
        policy_gate=gate,
        transport=InProcessFixtureTransport(app=create_vulnerable_app()),
    )

    # Construct invalid manifest with corrupted digest
    from drishti.verifier.models import EvidenceManifest, EvidenceReference

    ref = EvidenceReference(
        request_id="req_corrupt",
        step_id="step_probe",
        phase="PROBE",
        method="GET",
        url="http://test/api/v2/bookings/TBOH_1",
        status_code=200,
        response_digest="invalid_short_digest",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-CORRUPT",
        execution_id="run_corrupt",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref],
    )

    from drishti.core.models import AttackHypothesis, CandidateFinding, InferredEndpoint
    cand = CandidateFinding(
        candidate_id="cand_corrupt",
        hypothesis=AttackHypothesis(
            hypothesis_id="hyp_corrupt",
            target_endpoint=InferredEndpoint(
                endpoint_id="test:ep",
                method="GET",
                path_template="/api/v2/bookings/{booking_id}",
                auth_required=True,
                roles_observed=["agency_admin"],
                parameters={},
                source_har_request_id="syn",
                raw_packet_hash="a" * 64,
                confidence_score=0.9,
            ),
            invariant_targeted=InvariantType.TENANT_ISOLATION,
            rationale="Test rationale",
            test_strategy="Probe",
            attacker_tenant_id="agency_b",
            victim_tenant_id="agency_a",
        ),
        observed_status_code=200,
        raw_response_snippet="{}",
    )

    run_result = ExecutorRunResult(
        plan_id="PLAN-CORRUPT",
        invariant_id=InvariantType.TENANT_ISOLATION,
        outcome=ExecutionOutcome.CANDIDATE,
        candidate=cand,
        evidence_manifest=manifest,
    )

    oracle = VerificationOracle(http_client=http_client)
    verif_res = await oracle.verify(run_result=run_result, base_url="http://test")

    assert verif_res.status == VerificationStatus.INCONCLUSIVE
    assert verif_res.confidence_score == 0.30
    assert verif_res.verified_finding is None
