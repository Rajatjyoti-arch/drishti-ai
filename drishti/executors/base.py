"""Specialist Security Executor Base Contract for Drishti AI.

Enforces:
1. Strict policy gate mediation for 100% of outbound test traffic (zero unmediated sockets).
2. Per-test request budget tracking with atomic reservation, duration deadlines, and hard ceilings.
3. Cooperative cancellation and emergency stop handling.
4. Bounded, redacted evidence collection, response header sanitization, and SHA-256 payload digests.
5. Typed execution context and response output binding.
6. Strict candidate-only finding semantics (executors cannot emit CONFIRMED findings).
"""

from abc import ABC, abstractmethod
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

import httpx

from drishti.core.exceptions import (
    BudgetExhaustedError,
    ExecutionCancelledError,
    PolicyViolationError,
)
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

SENSITIVE_HEADER_KEYS = {
    "authorization",
    "set-cookie",
    "cookie",
    "x-api-key",
    "proxy-authorization",
    "www-authenticate",
    "x-auth-token",
}


def sanitize_response_headers(headers: httpx.Headers) -> Dict[str, str]:
    """Sanitizes sensitive authentication headers and cookies in execution telemetry."""
    sanitized: Dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADER_KEYS:
            sanitized[k] = "[REDACTED_HEADER]"
        else:
            sanitized[k] = v
    return sanitized


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
        self._execution_start_time: Optional[float] = None
        self.execution_history: List[ExecutionResult] = []
        self.execution_context: Dict[str, Any] = {}

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
        self._execution_start_time = None
        self.execution_history.clear()
        self.execution_context.clear()

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

    def resolve_step_url(self, step: AttackPlanStep, base_url: str = "") -> str:
        """Resolves route template parameters using step parameters and typed execution context.

        Strictly rejects any unresolved placeholders ({...}) before dispatch.
        """
        url = f"{base_url.rstrip('/')}{step.endpoint_route_template}"
        for param_key, param_val in step.parameters.items():
            if isinstance(param_val, str) and param_val.startswith("$"):
                var_name = param_val[1:]
                if var_name not in self.execution_context:
                    raise ValueError(
                        f"Unbound context variable '{var_name}' required for step '{step.step_id}'."
                    )
                resolved_val = str(self.execution_context[var_name])
            else:
                resolved_val = str(param_val)

            # Substitute in URL path template {param_key}
            placeholder = f"{{{param_key}}}"
            if placeholder in url:
                url = url.replace(placeholder, resolved_val)

        # Strict validation: reject any unresolved placeholders in the URL
        unresolved = re.findall(r"\{([a-zA-Z0-9_]+)\}", url)
        if unresolved:
            raise ValueError(
                f"Unresolved route placeholders {unresolved} in step '{step.step_id}' URL: '{url}'."
            )

        return url

    def capture_step_outputs(self, step: AttackPlanStep, response: httpx.Response) -> None:
        """Extracts declared output bindings from JSON response into typed execution context."""
        if not step.output_bindings:
            return

        try:
            json_data = response.json()
            if isinstance(json_data, dict):
                for binding in step.output_bindings:
                    val = json_data.get(binding.source_field, binding.default_value)
                    if val is not None:
                        self.execution_context[binding.context_variable] = str(val)
        except Exception as e:
            logger.debug(f"Failed to extract JSON output bindings for step '{step.step_id}': {e}")

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
        hard duration deadlines (cancelling in-flight requests), streaming response size bounds,
        and strict zero-fallback policy denial behavior.
        """
        # Pre-dispatch cancellation check
        if self.is_cancelled:
            raise ExecutionCancelledError(
                f"Cannot dispatch step '{step.step_id}'; execution cancelled ({self._cancel_reason})."
            )

        # Calculate remaining duration deadline
        now_mono = time.monotonic()
        if self._execution_start_time is None:
            self._execution_start_time = now_mono

        elapsed = now_mono - self._execution_start_time
        remaining_seconds = plan.budget.max_duration_seconds - elapsed

        if remaining_seconds <= 0:
            raise BudgetExhaustedError(
                f"Execution duration limit exceeded: {elapsed:.2f}s >= {plan.budget.max_duration_seconds}s limit."
            )

        # Atomic budget reservation (taking the stricter of plan and executor limit)
        effective_limit = min(
            plan.budget.max_requests,
            self.budget_limit if self.budget_limit is not None else plan.budget.max_requests,
        )
        if self.requests_executed >= effective_limit:
            raise BudgetExhaustedError(
                f"Executor request budget exhausted: {self.requests_executed}/{effective_limit} requests used."
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
            # Wrap in-flight request with remaining deadline timeout
            response = await asyncio.wait_for(
                self.http_client.send_request(
                    outgoing,
                    approval_token=approval_token,
                    max_response_size_bytes=plan.budget.max_response_size_bytes,
                ),
                timeout=remaining_seconds,
            )
        except asyncio.TimeoutError:
            self.cancel("Execution duration deadline exceeded during in-flight request")
            raise BudgetExhaustedError(
                f"In-flight request timed out: exceeded plan duration deadline of {plan.budget.max_duration_seconds}s."
            )
        except PolicyViolationError as pve:
            logger.error(f"Policy gate denied outbound request for step '{step.step_id}': {pve}")
            raise

        # Post-dispatch cancellation check
        if self.is_cancelled:
            raise ExecutionCancelledError(
                f"Execution cancelled during/after step '{step.step_id}' ({self._cancel_reason})."
            )

        # Enforce response payload size limit
        content_size = len(response.content) if hasattr(response, "content") else len((response.text or "").encode("utf-8"))
        if content_size > plan.budget.max_response_size_bytes:
            raise BudgetExhaustedError(
                f"Response size {content_size} bytes exceeds maximum allowed budget of {plan.budget.max_response_size_bytes} bytes."
            )

        # Capture declared outputs into execution context
        self.capture_step_outputs(step, response)

        # Redact and bound evidence body
        sanitized_snippet, raw_digest = redact_and_bound_evidence(
            response.text or "",
            max_length=min(plan.budget.max_response_size_bytes, 1000),
        )

        # Sanitize sensitive headers in telemetry
        sanitized_headers = sanitize_response_headers(response.headers)

        try:
            latency_ms = int(response.elapsed.total_seconds() * 1000)
        except Exception:
            latency_ms = 0

        exec_res = ExecutionResult(
            request_id=req_id,
            status_code=response.status_code,
            headers=sanitized_headers,
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
