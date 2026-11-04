"""Centralized deterministic Policy Gate orchestrating all safety, budget, and audit checks."""

from urllib.parse import urlparse
from typing import Optional
from drishti.core.contract import AuthorizationContract
from drishti.core.config import ExecutionBudgets
from drishti.core.models import OutgoingTestRequest, PolicyDecision, PolicyAction
from drishti.core.exceptions import OutOfScopeError, PolicyViolationError, EmergencyStopTriggered
from drishti.policy.scope_validator import ScopeValidator
from drishti.policy.egress_guard import EgressGuard
from drishti.policy.rate_limiter import MultiBudgetRateLimiter
from drishti.policy.health_monitor import HealthMonitor
from drishti.policy.credential_broker import CredentialBroker
from drishti.policy.approval_manager import HumanApprovalManager
from drishti.audit.ledger import TamperEvidentLedger
from drishti.audit.hash_chain import sha256_digest

class PolicyGate:
    """
    Non-negotiable security boundary:
    Evaluates every candidate request against scope, budgets, health state,
    and prohibited action filters before transport execution.
    """
    def __init__(
        self,
        contract: AuthorizationContract,
        budgets: ExecutionBudgets,
        ledger: TamperEvidentLedger,
        credential_broker: Optional[CredentialBroker] = None
    ):
        self.contract = contract
        self.budgets = budgets
        self.ledger = ledger
        self.scope_validator = ScopeValidator(contract)
        self.egress_guard = EgressGuard(self.scope_validator)
        self.rate_limiter = MultiBudgetRateLimiter(budgets)
        self.health_monitor = HealthMonitor(budgets.circuit_breaker)
        self.credential_broker = credential_broker or CredentialBroker()
        self.approval_manager = HumanApprovalManager()

    async def evaluate_request(
        self,
        request: OutgoingTestRequest,
        approval_token: Optional[str] = None
    ) -> PolicyDecision:
        """
        Evaluates a request candidate. Returns a structured PolicyDecision.
        """
        # 1. Emergency stop / Circuit breaker check
        if self.health_monitor.is_circuit_open:
            decision = PolicyDecision(
                action=PolicyAction.STOP,
                approved=False,
                reason=f"Target circuit breaker is OPEN: {self.health_monitor.last_trip_reason}",
                sanitized_url=request.url,
                budget_remaining=self.rate_limiter.get_remaining_global_budget()
            )
            self._record_decision(decision, request)
            return decision

        # 2. Scope & Destination Check
        try:
            self.egress_guard.validate_request_target(request.url)
        except OutOfScopeError as e:
            decision = PolicyDecision(
                action=PolicyAction.DENY,
                approved=False,
                reason=f"Scope violation: {e}",
                sanitized_url=request.url,
                budget_remaining=self.rate_limiter.get_remaining_global_budget()
            )
            self._record_decision(decision, request)
            return decision

        # 3. Prohibited Action Keyword Filter
        body_str = str(request.body).upper() if request.body else ""
        for prohibited in self.contract.prohibited_actions:
            if prohibited in body_str:
                decision = PolicyDecision(
                    action=PolicyAction.DENY,
                    approved=False,
                    reason=f"Prohibited destructive action keyword '{prohibited}' detected in payload",
                    sanitized_url=request.url,
                    budget_remaining=self.rate_limiter.get_remaining_global_budget()
                )
                self._record_decision(decision, request)
                return decision

        # 4. Multi-Budget Rate Limiter Check
        try:
            await self.rate_limiter.acquire(request.test_id)
        except PolicyViolationError as e:
            decision = PolicyDecision(
                action=PolicyAction.PAUSE,
                approved=False,
                reason=f"Budget constraint: {e}",
                sanitized_url=request.url,
                budget_remaining=self.rate_limiter.get_remaining_global_budget()
            )
            self._record_decision(decision, request)
            return decision

        # 5. Adaptive Health Backoff Check
        try:
            await self.health_monitor.apply_health_backoff()
        except EmergencyStopTriggered as e:
            decision = PolicyDecision(
                action=PolicyAction.STOP,
                approved=False,
                reason=str(e),
                sanitized_url=request.url,
                budget_remaining=self.rate_limiter.get_remaining_global_budget()
            )
            self._record_decision(decision, request)
            return decision

        # Request Approved
        decision = PolicyDecision(
            action=PolicyAction.ALLOW,
            approved=True,
            reason="Request meets all scope, budget, and safety criteria",
            sanitized_url=request.url,
            budget_remaining=self.rate_limiter.get_remaining_global_budget()
        )
        self._record_decision(decision, request)
        return decision

    def _record_decision(self, decision: PolicyDecision, request: OutgoingTestRequest) -> None:
        """Commits the policy evaluation to the tamper-evident ledger."""
        payload_digest = sha256_digest(f"{request.method}:{request.url}:{decision.action.value}")
        self.ledger.record_event(
            event_id=decision.decision_id,
            event_type=f"POLICY_{decision.action.value}",
            payload_digest=payload_digest,
            metadata={
                "request_id": request.request_id,
                "url": request.url,
                "reason": decision.reason,
                "budget_remaining": decision.budget_remaining
            }
        )
