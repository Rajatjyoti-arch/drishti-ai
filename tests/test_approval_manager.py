"""Adversarial tests for HumanApprovalManager token verification and risk enforcement."""

import pytest
from drishti.policy.approval_manager import HumanApprovalManager

def test_approval_manager_classifies_risk_levels():
    mgr = HumanApprovalManager()
    assert mgr.is_approval_required("ROUTINE") is False
    assert mgr.is_approval_required("routine") is False
    assert mgr.is_approval_required("ELEVATED") is True
    assert mgr.is_approval_required("HIGH") is True

def test_approval_manager_lifecycle():
    mgr = HumanApprovalManager()
    req = mgr.request_approval("test_pricing_01", "Altering checkout price", "HIGH")
    assert req.status == "PENDING"
    assert req.approval_token is None

    # Verification fails before approval
    assert mgr.verify_approval_token(req.request_id, "random_token") is False

    # Grant approval
    token = mgr.grant_approval(req.request_id)
    assert token.startswith("token_granted_")
    assert req.status == "APPROVED"

    # Verification passes with genuine token, fails with counterfeit
    assert mgr.verify_approval_token(req.request_id, token) is True
    assert mgr.verify_approval_token(req.request_id, "forged_token") is False

def test_approval_manager_rejects_unknown_request():
    mgr = HumanApprovalManager()
    with pytest.raises(ValueError, match="Unknown approval request ID"):
        mgr.grant_approval("non_existent_request_id")
