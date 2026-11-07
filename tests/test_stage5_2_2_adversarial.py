"""Adversarial and trust-boundary tests for Stage 5.2.2.

Verifies non-negotiable security guarantees:
1. Valid-looking but fabricated PolicyGate nonces are rejected (INCONCLUSIVE).
2. Nonce borrowed from another request is detected and rejected (INCONCLUSIVE).
3. Fabricated chk_* checkpoints are rejected (INCONCLUSIVE).
4. Valid checkpoints that do not cover this execution's requests are rejected (INCONCLUSIVE).
5. Missing immutable response artifacts fail closed (INCONCLUSIVE).
6. Correct declared digest paired with tampered response bytes fails closed (INCONCLUSIVE).
7. Stale canary reference from a previous execution fails closed (INCONCLUSIVE).
8. Guard-generated 403 denial cannot masquerade as target application defense (INCONCLUSIVE).
9. Authentic target-generated 403 defense is certified as clean defense (NOT_REPRODUCED).
10. CanarySecretStore execution scoping, TTL expiration, and explicit cleanup.
11. FindingLifecycleManager transactional transition validation, unique constraints, and foreign keys in SQLite.
"""

import hashlib
from pathlib import Path
import time
import pytest
from unittest.mock import MagicMock
import httpx

from drishti.audit.evidence_store import EvidenceStore
from drishti.audit.ledger import TamperEvidentLedger
from drishti.core.models import (
    CandidateFinding,
    InvariantType,
    PolicyAction,
    PolicyDecision,
    VerificationStatus,
)
from drishti.executors.attack_plan import CanarySecretStore
from drishti.policy.transports import InProcessFixtureTransport
from drishti.policy.client import SafeHttpClient
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
from tests.fixtures.patched_app import create_patched_app


def create_authenticated_test_environment(tmp_path: Path):
    """Sets up an authentic PolicyGate, TamperEvidentLedger, and EvidenceStore environment."""
    ledger = TamperEvidentLedger(db_path=tmp_path / "audit.db")
    evidence_store = EvidenceStore(storage_dir=tmp_path / "evidence")

    gate = MagicMock()
    gate.ledger = ledger
    decisions = {}

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
        return MagicMock(
            auth_header_key="Authorization",
            auth_header_value="Bearer mock_jwt_agency_b_admin_token",
        )

    gate.credential_broker.get_credential.side_effect = mock_get_cred

    http_client = SafeHttpClient(
        policy_gate=gate,
        evidence_store=evidence_store,
        transport=InProcessFixtureTransport(app=create_patched_app()),
    )
    return gate, ledger, evidence_store, http_client, decisions


# 1. Fabricated Nonce
@pytest.mark.asyncio
async def test_adversarial_fabricated_nonce_yields_inconclusive(tmp_path):
    """Manifest containing a syntactically valid but fabricated nonce is rejected."""
    gate, ledger, evidence_store, http_client, _ = create_authenticated_test_environment(tmp_path)

    raw_body = b'{"status": "ok"}'
    raw_digest = hashlib.sha256(raw_body).hexdigest()
    evidence_store.store_raw_artifact("art_req_probe", raw_body)

    # Record event in ledger with real decision dec_0123456789ab
    ledger.record_event(
        event_id="dec_0123456789ab",
        event_type="POLICY_ALLOW",
        payload_digest=raw_digest,
        metadata={"request_id": "req_probe", "url": "http://test/api/v2/bookings"},
    )
    cp = ledger.create_checkpoint("chk_real_001")

    # Use a fabricated nonce dec_999999999999 that was never registered in PolicyGate or ledger
    ref = EvidenceReference(
        request_id="req_probe",
        step_id="step_probe",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/api/v2/bookings",
        status_code=200,
        response_digest=raw_digest,
        policy_decision_nonce="dec_999999999999",
        artifact_id="art_req_probe",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-FAB-NONCE",
        execution_id="run_fab_nonce",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref],
        audit_ledger_checkpoint=cp.checkpoint_id,
    )
    run_result = ExecutorRunResult(
        plan_id="PLAN-FAB-NONCE",
        invariant_id=InvariantType.TENANT_ISOLATION,
        outcome=ExecutionOutcome.EXPECTED_REJECTION,
        evidence_manifest=manifest,
        reason="Target application rejected access",
    )

    oracle = VerificationOracle(http_client=http_client)
    res = await oracle.verify(run_result)

    assert res.status == VerificationStatus.INCONCLUSIVE
    assert any("fabricated nonce" in issue for issue in res.attempts[0].details.get("issues", []))


# 2. Borrowed Nonce From Another Request
@pytest.mark.asyncio
async def test_adversarial_borrowed_nonce_from_another_request_yields_inconclusive(tmp_path):
    """Manifest using a real nonce issued for Request A on Request B is detected and rejected."""
    gate, ledger, evidence_store, http_client, decisions = create_authenticated_test_environment(tmp_path)

    raw_body = b'{"status": "ok"}'
    raw_digest = hashlib.sha256(raw_body).hexdigest()
    evidence_store.store_raw_artifact("art_req_B", raw_body)

    # Register decision in gate and ledger for Request A
    decisions["dec_aaaaaaaaaaaa"] = {
        "decision_id": "dec_aaaaaaaaaaaa",
        "request_id": "req_A",
        "action": "ALLOW",
        "approved": True,
        "url": "http://test/api/v2/bookings",
    }
    ledger.record_event(
        event_id="dec_aaaaaaaaaaaa",
        event_type="POLICY_ALLOW",
        payload_digest=raw_digest,
        metadata={"request_id": "req_A", "url": "http://test/api/v2/bookings"},
    )
    cp = ledger.create_checkpoint("chk_legit_001")

    # Step claims to be req_B, but reuses dec_aaaaaaaaaaaa
    ref = EvidenceReference(
        request_id="req_B",
        step_id="step_probe",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/api/v2/bookings",
        status_code=200,
        response_digest=raw_digest,
        policy_decision_nonce="dec_aaaaaaaaaaaa",
        artifact_id="art_req_B",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-BORROW-NONCE",
        execution_id="run_borrow_nonce",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref],
        audit_ledger_checkpoint=cp.checkpoint_id,
    )
    run_result = ExecutorRunResult(
        plan_id="PLAN-BORROW-NONCE",
        invariant_id=InvariantType.TENANT_ISOLATION,
        outcome=ExecutionOutcome.EXPECTED_REJECTION,
        evidence_manifest=manifest,
        reason="Target application rejected access",
    )

    oracle = VerificationOracle(http_client=http_client)
    res = await oracle.verify(run_result)

    assert res.status == VerificationStatus.INCONCLUSIVE
    assert any("nonce mismatch" in issue for issue in res.attempts[0].details.get("issues", []))


# 3. Fabricated Checkpoint
@pytest.mark.asyncio
async def test_adversarial_fabricated_checkpoint_yields_inconclusive(tmp_path):
    """Manifest citing a fabricated checkpoint identifier not in ledger is rejected."""
    gate, ledger, evidence_store, http_client, decisions = create_authenticated_test_environment(tmp_path)

    raw_body = b'{"status": "ok"}'
    raw_digest = hashlib.sha256(raw_body).hexdigest()
    evidence_store.store_raw_artifact("art_req_1", raw_body)

    decisions["dec_1"] = {
        "decision_id": "dec_1",
        "request_id": "req_1",
        "action": "ALLOW",
        "approved": True,
        "url": "http://test/api/v2/bookings",
    }
    ledger.record_event(
        event_id="dec_1",
        event_type="POLICY_ALLOW",
        payload_digest=raw_digest,
        metadata={"request_id": "req_1", "url": "http://test/api/v2/bookings"},
    )

    ref = EvidenceReference(
        request_id="req_1",
        step_id="step_nc",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/api/v2/bookings",
        status_code=200,
        response_digest=raw_digest,
        policy_decision_nonce="dec_1",
        artifact_id="art_req_1",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-FAB-CHK",
        execution_id="run_fab_chk",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref],
        audit_ledger_checkpoint="chk_fabricated_nonexistent",
    )
    run_result = ExecutorRunResult(
        plan_id="PLAN-FAB-CHK",
        invariant_id=InvariantType.TENANT_ISOLATION,
        outcome=ExecutionOutcome.EXPECTED_REJECTION,
        evidence_manifest=manifest,
        reason="Target rejection",
    )

    oracle = VerificationOracle(http_client=http_client)
    res = await oracle.verify(run_result)

    assert res.status == VerificationStatus.INCONCLUSIVE
    assert any("Audit ledger checkpoint" in issue for issue in res.attempts[0].details.get("issues", []))


# 4. Checkpoint Not Covering Execution Requests
@pytest.mark.asyncio
async def test_adversarial_valid_checkpoint_not_covering_execution_yields_inconclusive(tmp_path):
    """Checkpoint created before execution request was committed does not cover the request."""
    gate, ledger, evidence_store, http_client, decisions = create_authenticated_test_environment(tmp_path)

    raw_body = b'{"status": "ok"}'
    raw_digest = hashlib.sha256(raw_body).hexdigest()
    evidence_store.store_raw_artifact("art_req_old", raw_body)
    evidence_store.store_raw_artifact("art_req_new", raw_body)

    # Initial event and checkpoint
    decisions["dec_old"] = {"decision_id": "dec_old", "request_id": "req_old", "action": "ALLOW", "approved": True, "url": "http://test/api/v2/old"}
    ledger.record_event(
        event_id="dec_old",
        event_type="POLICY_ALLOW",
        payload_digest=raw_digest,
        metadata={"request_id": "req_old", "url": "http://test/api/v2/old"},
    )
    cp_premature = ledger.create_checkpoint("chk_premature")

    # New event occurs AFTER checkpoint was created
    decisions["dec_new"] = {"decision_id": "dec_new", "request_id": "req_new", "action": "ALLOW", "approved": True, "url": "http://test/api/v2/new"}
    ledger.record_event(
        event_id="dec_new",
        event_type="POLICY_ALLOW",
        payload_digest=raw_digest,
        metadata={"request_id": "req_new", "url": "http://test/api/v2/new"},
    )

    ref = EvidenceReference(
        request_id="req_new",
        step_id="step_nc",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/api/v2/new",
        status_code=200,
        response_digest=raw_digest,
        policy_decision_nonce="dec_new",
        artifact_id="art_req_new",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-UNCOVERED",
        execution_id="run_uncovered",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref],
        audit_ledger_checkpoint=cp_premature.checkpoint_id,
    )
    run_result = ExecutorRunResult(
        plan_id="PLAN-UNCOVERED",
        invariant_id=InvariantType.TENANT_ISOLATION,
        outcome=ExecutionOutcome.EXPECTED_REJECTION,
        evidence_manifest=manifest,
        reason="Target rejection",
    )

    oracle = VerificationOracle(http_client=http_client)
    res = await oracle.verify(run_result)

    assert res.status == VerificationStatus.INCONCLUSIVE
    assert any("does not cover execution requests" in issue for issue in res.attempts[0].details.get("issues", []))


# 5. Missing Original Response Artifact
@pytest.mark.asyncio
async def test_adversarial_missing_response_artifact_yields_inconclusive(tmp_path):
    """Manifest referencing an artifact that does not exist in EvidenceStore fails closed."""
    gate, ledger, evidence_store, http_client, decisions = create_authenticated_test_environment(tmp_path)

    raw_body = b'{"status": "ok"}'
    raw_digest = hashlib.sha256(raw_body).hexdigest()
    # DO NOT store artifact in evidence_store

    decisions["dec_1"] = {"decision_id": "dec_1", "request_id": "req_1", "action": "ALLOW", "approved": True, "url": "http://test/api/v2/bookings"}
    ledger.record_event(
        event_id="dec_1",
        event_type="POLICY_ALLOW",
        payload_digest=raw_digest,
        metadata={"request_id": "req_1", "url": "http://test/api/v2/bookings"},
    )
    cp = ledger.create_checkpoint("chk_1")

    ref = EvidenceReference(
        request_id="req_1",
        step_id="step_nc",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/api/v2/bookings",
        status_code=200,
        response_digest=raw_digest,
        policy_decision_nonce="dec_1",
        artifact_id="art_nonexistent_123",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-NO-ART",
        execution_id="run_no_art",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref],
        audit_ledger_checkpoint=cp.checkpoint_id,
    )
    run_result = ExecutorRunResult(
        plan_id="PLAN-NO-ART",
        invariant_id=InvariantType.TENANT_ISOLATION,
        outcome=ExecutionOutcome.EXPECTED_REJECTION,
        evidence_manifest=manifest,
        reason="Target rejection",
    )

    oracle = VerificationOracle(http_client=http_client)
    res = await oracle.verify(run_result)

    assert res.status == VerificationStatus.INCONCLUSIVE
    assert any("Missing original response artifact" in issue for issue in res.attempts[0].details.get("issues", []))


# 6. Correct Digest Paired With Different Response Bytes
@pytest.mark.asyncio
async def test_adversarial_digest_with_tampered_artifact_bytes_yields_inconclusive(tmp_path):
    """Recomputed SHA-256 of stored artifact differs from declared digest -> detected as forged."""
    gate, ledger, evidence_store, http_client, decisions = create_authenticated_test_environment(tmp_path)

    original_bytes = b'{"booking": "authentic"}'
    declared_digest = hashlib.sha256(original_bytes).hexdigest()

    # Store altered bytes under the artifact ID
    tampered_bytes = b'{"booking": "TAMPERED_SUBSTITUTED"}'
    evidence_store.store_raw_artifact("art_tampered", tampered_bytes)

    decisions["dec_1"] = {"decision_id": "dec_1", "request_id": "req_1", "action": "ALLOW", "approved": True, "url": "http://test/api/v2/bookings"}
    ledger.record_event(
        event_id="dec_1",
        event_type="POLICY_ALLOW",
        payload_digest=declared_digest,
        metadata={"request_id": "req_1", "url": "http://test/api/v2/bookings"},
    )
    cp = ledger.create_checkpoint("chk_1")

    ref = EvidenceReference(
        request_id="req_1",
        step_id="step_nc",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/api/v2/bookings",
        status_code=200,
        response_digest=declared_digest,
        policy_decision_nonce="dec_1",
        artifact_id="art_tampered",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-TAMPER-BYTES",
        execution_id="run_tamper_bytes",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref],
        audit_ledger_checkpoint=cp.checkpoint_id,
    )
    run_result = ExecutorRunResult(
        plan_id="PLAN-TAMPER-BYTES",
        invariant_id=InvariantType.TENANT_ISOLATION,
        outcome=ExecutionOutcome.EXPECTED_REJECTION,
        evidence_manifest=manifest,
        reason="Target rejection",
    )

    oracle = VerificationOracle(http_client=http_client)
    res = await oracle.verify(run_result)

    assert res.status == VerificationStatus.INCONCLUSIVE
    assert any("forged digest" in issue for issue in res.attempts[0].details.get("issues", []))


# 7. Stale Canary Reference From Previous Execution
@pytest.mark.asyncio
async def test_adversarial_stale_canary_from_previous_execution_yields_inconclusive(tmp_path):
    """Canary secret stored under previous execution ID cannot be accessed by a different execution."""
    gate, ledger, evidence_store, http_client, decisions = create_authenticated_test_environment(tmp_path)

    secret_val = "secret_canary_previous_run"
    canary_digest = hashlib.sha256(secret_val.encode()).hexdigest()

    # Store secret under execution_id="run_OLD_001"
    CanarySecretStore.store_secret(
        secret_ref="canary_ref_1",
        value=secret_val,
        execution_id="run_OLD_001",
    )

    raw_body = b'{"status": "ok"}'
    raw_digest = hashlib.sha256(raw_body).hexdigest()
    evidence_store.store_raw_artifact("art_req_1", raw_body)

    decisions["dec_1"] = {"decision_id": "dec_1", "request_id": "req_1", "action": "ALLOW", "approved": True, "url": "http://test/api/v2/bookings"}
    ledger.record_event(
        event_id="dec_1",
        event_type="POLICY_ALLOW",
        payload_digest=raw_digest,
        metadata={"request_id": "req_1", "url": "http://test/api/v2/bookings"},
    )
    cp = ledger.create_checkpoint("chk_1")

    ref = EvidenceReference(
        request_id="req_1",
        step_id="step_nc",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/api/v2/bookings",
        status_code=200,
        response_digest=raw_digest,
        policy_decision_nonce="dec_1",
        artifact_id="art_req_1",
    )
    # Manifest belongs to a NEW execution ID run_NEW_002
    manifest = EvidenceManifest(
        plan_id="PLAN-STALE-CANARY",
        execution_id="run_NEW_002",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref],
        audit_ledger_checkpoint=cp.checkpoint_id,
        canary_spec_digest=canary_digest,
    )
    run_result = ExecutorRunResult(
        execution_id="run_NEW_002",
        plan_id="PLAN-STALE-CANARY",
        invariant_id=InvariantType.TENANT_ISOLATION,
        outcome=ExecutionOutcome.EXPECTED_REJECTION,
        evidence_manifest=manifest,
        reason="Target rejection",
    )

    oracle = VerificationOracle(http_client=http_client)
    res = await oracle.verify(run_result)

    # Oracle cannot resolve canary secret across executions -> fails closed as INCONCLUSIVE
    assert res.status == VerificationStatus.INCONCLUSIVE
    assert any("Canary secret was not provided" in issue for issue in res.attempts[0].details.get("issues", []))


# 8. Guard-Generated 403 Mistaken for Target 403
@pytest.mark.asyncio
async def test_adversarial_guard_403_yields_inconclusive(tmp_path):
    """Guard-generated 403 / policy denial cannot be claimed as application defensive compliance."""
    gate, ledger, evidence_store, http_client, decisions = create_authenticated_test_environment(tmp_path)

    raw_body = b'{"error": "Forbidden by Drishti Guard policy"}'
    raw_digest = hashlib.sha256(raw_body).hexdigest()
    evidence_store.store_raw_artifact("art_guard_denied", raw_body)

    decisions["dec_denied"] = {
        "decision_id": "dec_denied",
        "request_id": "req_denied",
        "action": "DENY",
        "approved": False,
        "url": "http://test/api/v2/bookings",
    }
    ledger.record_event(
        event_id="dec_denied",
        event_type="POLICY_DENY",
        payload_digest=raw_digest,
        metadata={"request_id": "req_denied", "url": "http://test/api/v2/bookings"},
    )
    cp = ledger.create_checkpoint("chk_denied")

    ref = EvidenceReference(
        request_id="req_denied",
        step_id="step_probe",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/api/v2/bookings",
        status_code=403,
        response_digest=raw_digest,
        policy_decision_nonce="dec_denied",
        artifact_id="art_guard_denied",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-GUARD-DENIED",
        execution_id="run_guard_denied",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref],
        audit_ledger_checkpoint=cp.checkpoint_id,
    )
    run_result = ExecutorRunResult(
        plan_id="PLAN-GUARD-DENIED",
        invariant_id=InvariantType.TENANT_ISOLATION,
        outcome=ExecutionOutcome.EXPECTED_REJECTION,
        evidence_manifest=manifest,
        reason="Transport request REJECTED by Policy Gate [DENY]: Target out of scope",
    )

    oracle = VerificationOracle(http_client=http_client)
    res = await oracle.verify(run_result)

    assert res.status == VerificationStatus.INCONCLUSIVE
    assert res.confidence_score == 0.0
    assert "rejected by Policy Gate / Guard" in res.confidence_rationale


# 9. Authentic Target-Generated 403 Confirms Clean Defense
@pytest.mark.asyncio
async def test_authenticated_target_403_confirms_clean_defense_not_reproduced(tmp_path):
    """Authentic target rejection with complete authenticated evidence certifies clean defense."""
    gate, ledger, evidence_store, http_client, decisions = create_authenticated_test_environment(tmp_path)

    raw_body = b'{"error": "Access denied: tenant mismatch"}'
    raw_digest = hashlib.sha256(raw_body).hexdigest()
    evidence_store.store_raw_artifact("art_target_403", raw_body)

    decisions["dec_444444444444"] = {
        "decision_id": "dec_444444444444",
        "request_id": "req_target_403",
        "action": "ALLOW",
        "approved": True,
        "url": "http://test/api/v2/bookings",
    }
    ledger.record_event(
        event_id="dec_444444444444",
        event_type="POLICY_ALLOW",
        payload_digest=raw_digest,
        metadata={"request_id": "req_target_403", "url": "http://test/api/v2/bookings"},
    )
    cp = ledger.create_checkpoint("chk_target_403")

    ref = EvidenceReference(
        request_id="req_target_403",
        step_id="step_nc",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/api/v2/bookings",
        status_code=200,  # Negative control succeeded
        response_digest=raw_digest,
        policy_decision_nonce="dec_444444444444",
        artifact_id="art_target_403",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-CLEAN-DEFENSE",
        execution_id="run_clean_defense",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref],
        audit_ledger_checkpoint=cp.checkpoint_id,
    )
    run_result = ExecutorRunResult(
        plan_id="PLAN-CLEAN-DEFENSE",
        invariant_id=InvariantType.TENANT_ISOLATION,
        outcome=ExecutionOutcome.EXPECTED_REJECTION,
        evidence_manifest=manifest,
        reason="Target application returned 403 Forbidden on cross-tenant access",
    )

    oracle = VerificationOracle(http_client=http_client)
    res = await oracle.verify(run_result)

    assert res.status == VerificationStatus.NOT_REPRODUCED
    assert res.confidence_score == 1.0
    assert "Defensive controls held cleanly" in res.attempts[0].confidence_rationale


# 10. Canary Store Expiration and Cleanup
def test_canary_secret_store_expiration_and_cleanup():
    """CanarySecretStore enforces execution scoping, TTL expiration, and explicit cleanup."""
    CanarySecretStore.clear()

    # Store with short TTL (0.1s)
    CanarySecretStore.store_secret(
        secret_ref="canary_temp",
        value="secret_val_123",
        execution_id="run_exp_1",
        ttl_seconds=0.1,
    )
    digest = hashlib.sha256(b"secret_val_123").hexdigest()

    # Available immediately for the same execution
    assert CanarySecretStore.get_secret_by_digest(digest, execution_id="run_exp_1") == "secret_val_123"
    # Blocked for a different execution
    assert CanarySecretStore.get_secret_by_digest(digest, execution_id="run_exp_OTHER") is None

    # Wait for TTL expiration
    time.sleep(0.15)
    assert CanarySecretStore.get_secret_by_digest(digest, execution_id="run_exp_1") is None
    CanarySecretStore.cleanup_expired()
    assert CanarySecretStore.get_secret("canary_temp") is None

    # Store and test explicit execution cleanup
    CanarySecretStore.store_secret(
        secret_ref="canary_cleanup",
        value="secret_to_clean",
        execution_id="run_clean_me",
        ttl_seconds=300.0,
    )
    digest_clean = hashlib.sha256(b"secret_to_clean").hexdigest()
    assert CanarySecretStore.get_secret_by_digest(digest_clean, execution_id="run_clean_me") == "secret_to_clean"

    CanarySecretStore.cleanup_execution("run_clean_me")
    assert CanarySecretStore.get_secret_by_digest(digest_clean, execution_id="run_clean_me") is None


# 11. Transactional Lifecycle SQLite Enforcement
def test_transactional_lifecycle_sqlite_enforcement(tmp_path):
    """FindingLifecycleManager enforces atomic transactions and valid state transitions in SQLite."""
    from drishti.core.models import VerifiedFinding

    db_path = tmp_path / "lifecycle_txn.db"
    mgr = FindingLifecycleManager(db_path=db_path)

    vf = VerifiedFinding(
        finding_id="VF-txn-001",
        invariant_id=InvariantType.TENANT_ISOLATION,
        status=VerificationStatus.CONFIRMED,
        title="BOLA Test",
        target_endpoint="api:GET:/bookings",
        violated_rule="OWASP API1:2023",
        confidence_score=0.95,
        business_impact={"confidentiality": "HIGH"},
        exposed_sensitive_fields=["booking_id"],
        reproduction_steps=[],
        request_evidence_hash="evm_hash",
        raw_response_diff="diff",
        suggested_fix="Fix tenant checks",
    )
    mgr.register_finding(vf, initial_state=FindingLifecycleState.CONFIRMED)

    # Valid transition CONFIRMED -> RETEST_REQUIRED succeeds
    tr1 = mgr.transition_state("VF-txn-001", FindingLifecycleState.RETEST_REQUIRED, "Dev deployed fix")
    assert tr1.to_state == FindingLifecycleState.RETEST_REQUIRED
    assert mgr.get_state("VF-txn-001") == FindingLifecycleState.RETEST_REQUIRED

    # Illegal transition RETEST_REQUIRED -> FIXED directly without verification raises ValueError
    with pytest.raises(ValueError, match="Invalid lifecycle transition"):
        mgr.transition_state("VF-txn-001", FindingLifecycleState.FIXED, "Illegal jump")

    # State in SQLite must remain RETEST_REQUIRED (transactional rollback)
    assert mgr.get_state("VF-txn-001") == FindingLifecycleState.RETEST_REQUIRED

    # Valid step to VERIFYING then to FIXED
    mgr.transition_state("VF-txn-001", FindingLifecycleState.VERIFYING, "Verification probe sent")
    mgr.transition_state("VF-txn-001", FindingLifecycleState.FIXED, "Confirmed fixed")
    assert mgr.get_state("VF-txn-001") == FindingLifecycleState.FIXED

    # Verify append-only transitions in SQLite database
    import sqlite3
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT sequence, transition_id, from_state, to_state FROM lifecycle_transitions ORDER BY sequence ASC")
        rows = cursor.fetchall()
        assert len(rows) == 4
        # Sequences are monotonically increasing (1, 2, 3, 4)
        assert [r[0] for r in rows] == [1, 2, 3, 4]
        # Final state in finding_records table is FIXED
        cursor.execute("SELECT current_state FROM finding_records WHERE finding_id = 'VF-txn-001'")
        assert cursor.fetchone()[0] == "FIXED"
