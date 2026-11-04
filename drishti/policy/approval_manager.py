"""Human-in-the-loop approval manager for elevated or high-risk test classes."""

import uuid
from typing import Dict, Optional
from pydantic import BaseModel

class ApprovalRequest(BaseModel):
    request_id: str
    test_id: str
    action_description: str
    risk_level: str
    status: str = "PENDING"
    approval_token: Optional[str] = None

class HumanApprovalManager:
    """
    Ensures destructive, billing-related, or high-risk test operations
    cannot execute without an authorized human sign-off token.
    """
    def __init__(self):
        self._requests: Dict[str, ApprovalRequest] = {}

    def is_approval_required(self, risk_level: str) -> bool:
        return risk_level.upper() in {"ELEVATED", "HIGH"}

    def request_approval(self, test_id: str, action_description: str, risk_level: str) -> ApprovalRequest:
        req_id = f"appr_{uuid.uuid4().hex[:8]}"
        req = ApprovalRequest(
            request_id=req_id,
            test_id=test_id,
            action_description=action_description,
            risk_level=risk_level
        )
        self._requests[req_id] = req
        return req

    def grant_approval(self, request_id: str) -> str:
        req = self._requests.get(request_id)
        if not req:
            raise ValueError(f"Unknown approval request ID: {request_id}")
        token = f"token_granted_{uuid.uuid4().hex[:12]}"
        req.status = "APPROVED"
        req.approval_token = token
        return token

    def verify_approval_token(self, request_id: str, token: str) -> bool:
        req = self._requests.get(request_id)
        if not req or req.status != "APPROVED":
            return False
        return req.approval_token == token
