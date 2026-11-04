"""Deterministic Policy Gate enforcing the Authorization Contract."""

from urllib.parse import urlparse
from drishti.core.contract import AuthorizationContract
from drishti.core.models import OutgoingTestRequest, PolicyDecision
from drishti.core.exceptions import OutOfScopeError, PolicyViolationError

class DeterministicPolicyGate:
    def __init__(self, contract: AuthorizationContract):
        self.contract = contract
        self.total_requests = 0

    def evaluate_request(self, request: OutgoingTestRequest) -> PolicyDecision:
        parsed = urlparse(request.url)
        host = parsed.hostname or ""

        # 1. Target Allowlist Check
        if not any(permitted in host for permitted in self.contract.permitted_targets):
            raise OutOfScopeError(
                f"Target host '{host}' is NOT in permitted allowlist: {self.contract.permitted_targets}"
            )

        # 2. Total Request Budget Check
        if self.total_requests >= self.contract.request_budgets.max_total_requests_per_run:
            raise PolicyViolationError(
                f"Exceeded max total requests limit: {self.contract.request_budgets.max_total_requests_per_run}"
            )

        # 3. Payload Safety Filter Check
        body_str = str(request.body).upper() if request.body else ""
        for prohibited in self.contract.prohibited_actions:
            if prohibited in body_str:
                raise PolicyViolationError(
                    f"Prohibited destructive action keyword '{prohibited}' detected in request body"
                )

        self.total_requests += 1
        return PolicyDecision(
            allowed=True,
            reason="Request conforms to Authorization Contract allowlist and budgets",
            sanitized_url=request.url
        )
