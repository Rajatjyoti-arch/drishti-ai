"""Specialist Security Executor Base Contract for Drishti AI.

Enforces:
1. Strict policy gate mediation for 100% of outbound test traffic (zero unmediated sockets).
2. Per-test request budget tracking with atomic reservation and hard execution ceilings.
3. Cooperative cancellation and emergency stop handling.
4. Bounded, redacted evidence collection and SHA-256 payload digest tracking.
5. Strict candidate-only finding semantics (executors cannot emit CONFIRMED findings).
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import hashlib
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
import uuid

import httpx

from drishti.core.exceptions import PolicyViolationError
from drishti.core.models import (
    AttackHypothesis,
    CandidateFinding,
    ExecutionResult,
    InferredEndpoint,
    InvariantType,
    OutgoingTestRequest,
    VerifiedFinding,
)
from drishti.executors.attack_plan import AttackPlan, AttackPlanStep
from drishti.policy.client import SafeHttpClient

logger = logging.getLogger(__name__)


class BudgetExhaustedError(Exception):
    """Raised when an executor breaches its configured request budget limit."""
    pass


class ExecutionCancelledError(Exception):
    """Raised when an active security execution is terminated by emergency stop."""
    pass


def redact_and_bound_evidence(
    text: str,
    max_length: int = 500,
) -> Tuple[str, str]:
    """Redacts sensitive credentials, tokens, PII, and bounds response snippet length.

    Returns:
        (sanitized_bounded_snippet, sha256_digest_of_raw_body)
    """
    if not text:
        return "", hashlib.sha256(b"").hexdigest()

    raw_digest = hashlib.sha256(text.encode("utf-8")).hexdigest()

    # Redact sensitive credentials and PII patterns
    sanitized = text
    patterns = [
        (r'("?(?:password|token|secret|access_token|authorization|auth_token)"?\s*[:=]\s*)"[^"]+"', r'\1"[REDACTED]"'),
        (r'Bearer\s+[A-Za-z0-9_\-\.]+', 'Bearer [REDACTED_TOKEN]'),
        (r'\b[A-Z][0-9]{7}\b', '[REDACTED_PII_PASSPORT]'),
        (r'("?(?:passenger_passport|passport_number|passport)"?\s*[:=]\s*)"[^"]+"', r'\1"[REDACTED_PII]"'),
    ]
    for pattern, repl in patterns:
        sanitized = re.sub(pattern, repl, sanitized, flags=re.IGNORECASE)

    # Bound to max_length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "... [TRUNCATED_EVIDENCE]"

    return sanitized, raw_digest


class ISpecialistExecutor(ABC):
    """Abstract base contract for specialist security verification executors."""

    supported_invariant: InvariantType

    def __init__(
        self,
        http_client: SafeHttpClient,
        budget_limit: Optional[int] = None,
    ):
        self.http_client = http_client
        self.budget_limit = budget_limit
        self.requests_executed: int = 0
        self.is_cancelled: bool = False
        self._cancel_reason: str = ""
        self.execution_history: List[ExecutionResult] = []

    def cancel(self, reason: str = "Emergency stop signal received") -> None:
        """Triggers immediate cancellation and halts all further outbound probes."""
        self.is_cancelled = True
        self._cancel_reason = reason
        logger.warning(f"Specialist executor {self.__class__.__name__} received cancellation: {reason}")

    def reset(self) -> None:
        """Resets executor state and telemetry between test executions."""
        self.requests_executed = 0
        self.is_cancelled = False
        self._cancel_reason = ""
        self.execution_history.clear()

    def check_plan_supported(self, plan: AttackPlan) -> None:
        """Verifies that the attack plan matches the executor's supported invariant."""
        if plan.invariant_id != self.supported_invariant:
            raise ValueError(
                f"Executor {self.__class__.__name__} supports '{self.supported_invariant.value}', "
                f"cannot execute plan targeting '{plan.invariant_id.value}'."
            )

    def check_preconditions(self, plan: AttackPlan) -> None:
        """Verifies plan temporal validity and preconditions before execution."""
        expires = datetime.fromisoformat(plan.expires_at)
        now = datetime.now(timezone.utc)
        if now > expires:
            raise ExecutionCancelledError(
                f"Attack plan '{plan.plan_id}' expired at {plan.expires_at} (current time {now.isoformat()})."
            )

    async def send_guarded_request(
        self,
        plan: AttackPlan,
        step: AttackPlanStep,
        resolved_url: str,
        approval_token: Optional[str] = None,
        resolved_body: Optional[Any] = None,
    ) -> Tuple[httpx.Response, ExecutionResult]:
        """Mediates an HTTP test request through the SafeHttpClient and PolicyGate.

        Enforces atomic budget reservation, cooperative cancellation checks,
        evidence redaction, and strict zero-fallback policy denial behavior.
        """
        # Pre-dispatch cancellation check
        if self.is_cancelled:
            raise ExecutionCancelledError(
                f"Cannot dispatch step '{step.step_id}'; execution cancelled ({self._cancel_reason})."
            )

        # Atomic budget reservation
        max_allowed = self.budget_limit if self.budget_limit is not None else plan.budget.max_requests
        if self.requests_executed >= max_allowed:
            raise BudgetExhaustedError(
                f"Executor request budget exhausted: {self.requests_executed}/{max_allowed} requests used."
            )

        # Reserve budget slot atomically before network call
        self.requests_executed += 1

        req_id = f"exec_req_{uuid.uuid4().hex[:10]}"
        outgoing = OutgoingTestRequest(
            request_id=req_id,
            method=step.method.upper(),
            url=resolved_url,
            headers=dict(step.headers),
            body=resolved_body if resolved_body is not None else step.body,
            target_tenant_id=step.actor_tenant_id,
            target_invariant=plan.invariant_id,
            credential_ref=step.credential_ref,
            test_id=step.step_id,
        )

        try:
            response = await self.http_client.send_request(outgoing, approval_token=approval_token)
        except PolicyViolationError as pve:
            logger.error(f"Policy gate denied outbound request for step '{step.step_id}': {pve}")
            # Strict policy gate contract: never fall back to unmediated sockets
            raise

        # Post-dispatch cancellation check
        if self.is_cancelled:
            raise ExecutionCancelledError(
                f"Execution cancelled during/after step '{step.step_id}' ({self._cancel_reason})."
            )

        sanitized_snippet, raw_digest = redact_and_bound_evidence(
            response.text or "",
            max_length=min(plan.budget.max_response_size_bytes, 1000),
        )

        try:
            latency_ms = int(response.elapsed.total_seconds() * 1000)
        except Exception:
            latency_ms = 0

        exec_res = ExecutionResult(
            request_id=req_id,
            status_code=response.status_code,
            headers=dict(response.headers),
            sanitized_body=sanitized_snippet,
            latency_ms=latency_ms,
            response_digest=raw_digest,
        )
        self.execution_history.append(exec_res)
        return response, exec_res

    @abstractmethod
    async def execute(self, plan: AttackPlan) -> CandidateFinding:
        """Executes an attack plan and produces a candidate finding for oracle verification.

        IMPORTANT: Specialist executors must emit CandidateFinding, NEVER a confirmed finding.
        Independent verification is strictly the responsibility of the Verification Oracle.
        """
        pass
