"""Unit tests for EvidenceValidator."""

import hashlib
import pytest
from drishti.audit.evidence_store import EvidenceStore
from drishti.audit.ledger import TamperEvidentLedger
from drishti.core.models import InvariantType
from drishti.verifier.evidence_validator import EvidenceValidator
from drishti.verifier.models import EvidenceManifest, EvidenceReference


def test_validator_rejects_empty_manifest():
    """Manifest with no references is rejected."""
    manifest = EvidenceManifest(
        plan_id="PLAN-EMPTY",
        execution_id="run_empty",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[],
    )
    report = EvidenceValidator.validate_manifest(manifest)
    assert not report.is_valid
    assert "zero execution step references" in report.issues[0]


def test_validator_detects_missing_negative_control():
    """Manifest without negative control phase is flagged."""
    ref = EvidenceReference(
        request_id="req_1",
        step_id="step_probe",
        phase="PROBE",
        method="GET",
        url="http://test/api/v2/bookings/TBOH_1",
        status_code=200,
        response_digest="a" * 64,
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-NO-NC",
        execution_id="run_no_nc",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref],
    )
    report = EvidenceValidator.validate_manifest(manifest)
    assert not report.is_valid
    assert any("Missing required negative control phase" in issue for issue in report.issues)


def test_validator_detects_failed_negative_control():
    """Negative control with non-2xx status code is flagged."""
    ref_nc = EvidenceReference(
        request_id="req_nc",
        step_id="step_nc",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/api/v2/bookings/TBOH_1",
        status_code=500,
        response_digest="b" * 64,
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-FAIL-NC",
        execution_id="run_fail_nc",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref_nc],
    )
    report = EvidenceValidator.validate_manifest(manifest)
    assert not report.is_valid
    assert any("unexpected HTTP status 500" in issue for issue in report.issues)


def test_validator_verifies_canary_secret_digest(tmp_path):
    """Matching canary secret passes; mismatched secret is rejected."""
    secret = "secret_canary_token_123"
    expected_digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()

    raw_body = b"canary_response_payload"
    raw_digest = hashlib.sha256(raw_body).hexdigest()

    ledger = TamperEvidentLedger(db_path=tmp_path / "ledger.db")
    ledger.record_event(
        event_id="dec_0123456789ab",
        event_type="POLICY_ALLOW",
        payload_digest=raw_digest,
        metadata={"request_id": "req_nc", "url": "http://test/api/v2/bookings/TBOH_1"},
    )
    cp = ledger.create_checkpoint("chk_1234567890abcdef")

    store = EvidenceStore(storage_dir=tmp_path / "evidence")
    store.store_raw_artifact("art_req_nc", raw_body)

    validator = EvidenceValidator(evidence_store=store, ledger=ledger)

    ref_nc = EvidenceReference(
        request_id="req_nc",
        step_id="step_nc",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/api/v2/bookings/TBOH_1",
        status_code=200,
        response_digest=raw_digest,
        policy_decision_nonce="dec_0123456789ab",
        artifact_id="art_req_nc",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-CANARY",
        execution_id="run_canary",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref_nc],
        canary_spec_digest=expected_digest,
        audit_ledger_checkpoint=cp.checkpoint_id,
    )

    # Valid secret
    report_valid = validator.validate_manifest(manifest, canary_secret=secret)
    assert report_valid.is_valid
    assert report_valid.canary_digest_matched

    # Wrong secret
    report_wrong = validator.validate_manifest(manifest, canary_secret="wrong_secret")
    assert not report_wrong.is_valid
    assert any("does not match manifest canary_spec_digest" in issue for issue in report_wrong.issues)


def test_validator_flags_invalid_digest_format():
    """Digest that is not 64-char hex is rejected."""
    ref_nc = EvidenceReference(
        request_id="req_nc",
        step_id="step_nc",
        phase="NEGATIVE_CONTROL",
        method="GET",
        url="http://test/api/v2/bookings/TBOH_1",
        status_code=200,
        response_digest="invalid_short_digest",
    )
    manifest = EvidenceManifest(
        plan_id="PLAN-BAD-DIGEST",
        execution_id="run_bad_digest",
        invariant_id=InvariantType.TENANT_ISOLATION,
        evidence_references=[ref_nc],
    )
    report = EvidenceValidator.validate_manifest(manifest)
    assert not report.is_valid
    assert any("invalid or missing response digest" in issue for issue in report.issues)
