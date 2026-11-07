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
from drishti.verifier.models import (
    EvidenceManifest,
    EvidenceReference,
    ExecutionOutcome,
    ExecutorRunResult,
)

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
        self.evidence_references: List[EvidenceReference] = []
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
        self.evidence_references.clear()
        self.execution_context.clear()

    def start_execution(self, plan: AttackPlan) -> None:
        """Initializes isolated per-execution state and validates plan contracts."""
        was_cancelled = self.is_cancelled
        cancel_reason = self._cancel_reason
        self.reset()
        if was_cancelled:
            self.is_cancelled = True
            self._cancel_reason = cancel_reason
            raise ExecutionCancelledError(
                f"Cannot start execution; already cancelled ({cancel_reason})."
            )
        self.check_plan_supported(plan)
        self.check_preconditions(plan)

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

    def resolve_step_body(self, step: AttackPlanStep) -> Any:
        """Recursively resolves dynamic context variables ($variable_name) inside the step request body."""
        if step.body is None:
            return None

        def _substitute(val: Any) -> Any:
            if isinstance(val, str) and val.startswith("$"):
                var_name = val[1:]
                if var_name in self.execution_context:
                    return self.execution_context[var_name]
                return val
            elif isinstance(val, dict):
                return {k: _substitute(v) for k, v in val.items()}
            elif isinstance(val, list):
                return [_substitute(item) for item in val]
            return val

        return _substitute(step.body)

    def capture_step_outputs(self, step: AttackPlanStep, response: httpx.Response) -> None:
        """Extracts declared output bindings from JSON response into typed execution context.

        Supports both dictionary responses and array responses (e.g. search operations returning quote lists).
        """
        if not step.output_bindings:
            return

        try:
            json_data = response.json()
            for binding in step.output_bindings:
                val = None
                if isinstance(json_data, dict):
                    val = json_data.get(binding.source_field, binding.default_value)
                elif isinstance(json_data, list) and len(json_data) > 0:
                    src = binding.source_field
                    idx = 0
                    field_name = src
                    if src.startswith("[") and "]" in src:
                        parts = src[1:].split("]", 1)
                        try:
                            idx = int(parts[0])
                            field_name = parts[1].lstrip(".")
                        except ValueError:
                            pass
                    if 0 <= idx < len(json_data) and isinstance(json_data[idx], dict):
                        val = json_data[idx].get(field_name, binding.default_value)
                    elif field_name == "self" or not field_name:
                        val = json_data[idx]

                if val is not None:
                    self.execution_context[binding.context_variable] = val
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
            body=resolved_body if resolved_body is not None else self.resolve_step_body(step),
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

        # Record point-in-time evidence reference for verification manifest
        step_bindings = {
            b.context_variable: self.execution_context.get(b.context_variable)
            for b in (step.output_bindings or [])
            if b.context_variable in self.execution_context
        }
        evidence_ref = EvidenceReference(
            request_id=req_id,
            step_id=step.step_id,
            phase=step.phase.value if hasattr(step.phase, "value") else str(step.phase),
            method=step.method.upper(),
            url=resolved_url,
            status_code=response.status_code,
            response_digest=raw_digest,
            policy_decision_nonce=exec_res.policy_decision_nonce or "",
            latency_ms=latency_ms,
            captured_bindings=step_bindings,
        )
        self.evidence_references.append(evidence_ref)

        return response, exec_res

    def build_evidence_manifest(
        self,
        plan: AttackPlan,
        execution_id: str,
    ) -> EvidenceManifest:
        """Constructs an EvidenceManifest capturing all execution step digests and bindings."""
        canary_digest = (
            plan.canary_spec.canary_value_digest
            if plan.canary_spec and plan.canary_spec.canary_value_digest
            else None
        )
        raw_payload_hashes = {
            ref.step_id: ref.response_digest
            for ref in self.evidence_references
        }
        return EvidenceManifest(
            plan_id=plan.plan_id,
            execution_id=execution_id,
            invariant_id=plan.invariant_id,
            evidence_references=list(self.evidence_references),
            raw_payload_hashes=raw_payload_hashes,
            canary_spec_digest=canary_digest,
        )

    @abstractmethod
    async def execute(self, plan: AttackPlan) -> ExecutorRunResult:
        """Executes an attack plan and produces an ExecutorRunResult for oracle verification.

        IMPORTANT: Specialist executors must emit candidate findings, NEVER a confirmed finding.
        Independent verification is strictly the responsibility of the Verification Oracle.
        """
        pass
