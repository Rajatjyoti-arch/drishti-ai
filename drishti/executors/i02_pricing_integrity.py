"""I-02 Server-Authoritative Pricing Specialist Executor for Drishti AI.

Implements PricingIntegrityExecutor verifying tariff and pricing boundaries:
1. Discovers authoritative quote via POST /api/v2/search and establishes typed PricingBaseline.
2. Acquires inventory hold via POST /api/v2/holds.
3. Executes negative control: verifies untampered booking succeeds at authoritative price and currency.
4. Acquires fresh inventory hold for the tampering probe (preventing hold token reuse).
5. Executes client-controlled price or currency tampering probe against POST /api/v2/bookings.
6. Asserts whether altered financial parameters were persisted, and emits CandidateFinding for independent oracle verification.
"""

import hashlib
import logging
import time
from typing import Any, Dict, Optional
import uuid

import httpx
from pydantic import BaseModel, Field

from drishti.core.models import (
    AttackHypothesis,
    CandidateFinding,
    ExecutionResult,
    InferredEndpoint,
    InvariantType,
)
from drishti.executors.attack_plan import (
    AttackPlan,
    ParsedEndpointIdentity,
    PlanPhase,
    PlanStep,
)
from drishti.executors.base import ISpecialistExecutor
from drishti.policy.client import SafeHttpClient

logger = logging.getLogger(__name__)


class PricingBaseline(BaseModel):
    """Authoritative quote baseline established during search and hold phases."""

    quote_id: str
    tenant_id: str
    amount_minor_units: int
    currency: str
    expires_at: float
    quote_digest: str


class PricingIntegrityExecutor(ISpecialistExecutor):
    """Specialist Security Executor targeting Invariant I-02: Server-Authoritative Pricing Integrity."""

    supported_invariant: InvariantType = InvariantType.PRICING_INTEGRITY

    def __init__(
        self,
        http_client: SafeHttpClient,
        budget_limit: Optional[int] = None,
    ):
        super().__init__(http_client=http_client, budget_limit=budget_limit)
        self.baseline: Optional[PricingBaseline] = None

    async def execute(
        self,
        plan: AttackPlan,
        base_url: str = "",
        approval_token: Optional[str] = None,
    ) -> Optional[CandidateFinding]:
        """Executes the multi-step I-02 pricing integrity attack plan.

        Returns:
            CandidateFinding: If the target accepts client-tampered price or currency in booking creation.
            None: If the target enforces authoritative pricing and rejects the probe (e.g. HTTP 400).

        IMPORTANT: Emits CandidateFinding only, NEVER a confirmed finding.
        Final verification and lifecycle transitions are strictly owned by the Verification Oracle.
        """
        self.start_execution(plan)
        self.baseline = None

        # Resolve effective base URL
        effective_base_url = base_url
        if not effective_base_url:
            parsed_identity = ParsedEndpointIdentity.parse(plan.target_endpoint_identity)
            if parsed_identity.origin.startswith("http://") or parsed_identity.origin.startswith("https://"):
                effective_base_url = parsed_identity.origin
            else:
                effective_base_url = "http://test"

        for step in plan.steps:
            resolved_url = self.resolve_step_url(step, base_url=effective_base_url)
            resolved_body = self.resolve_step_body(step)

            response, exec_res = await self.send_guarded_request(
                plan=plan,
                step=step,
                resolved_url=resolved_url,
                approval_token=approval_token,
                resolved_body=resolved_body,
            )

            # Phase 1: Setup - Search and Hold Acquisition
            if step.phase == PlanPhase.SETUP:
                if response.status_code != step.expected_status_baseline:
                    logger.error(
                        f"Setup step '{step.step_id}' failed with HTTP {response.status_code} "
                        f"(expected {step.expected_status_baseline})."
                    )
                    raise RuntimeError(
                        f"Setup step '{step.step_id}' failed: "
                        f"expected {step.expected_status_baseline}, got {response.status_code}."
                    )

                # Capture baseline quote parameters from search output
                if step.step_id == "step_1_search_quote":
                    quote_id = self.execution_context.get("baseline_quote_id")
                    amount = self.execution_context.get("baseline_amount")
                    currency = self.execution_context.get("baseline_currency")
                    expires_at = float(self.execution_context.get("baseline_expires_at", 0))

                    if not quote_id or amount is None or not currency:
                        raise RuntimeError(
                            f"Failed to extract baseline quote parameters from search step: context={self.execution_context}"
                        )

                    # Verify quote has not expired
                    if expires_at and expires_at < time.time():
                        logger.warning(
                            f"Authoritative quote '{quote_id}' is expired (expires_at={expires_at}); aborting plan."
                        )
                        return None

                    quote_signature = f"{quote_id}:{amount}:{currency}:{expires_at}"
                    self.baseline = PricingBaseline(
                        quote_id=str(quote_id),
                        tenant_id=step.actor_tenant_id,
                        amount_minor_units=int(amount),
                        currency=str(currency),
                        expires_at=expires_at,
                        quote_digest=hashlib.sha256(quote_signature.encode("utf-8")).hexdigest(),
                    )

            # Phase 2: Negative Control - Untampered Booking Baseline
            elif step.phase == PlanPhase.NEGATIVE_CONTROL:
                if response.status_code != step.expected_status_baseline:
                    logger.warning(
                        f"Negative control '{step.step_id}' failed with HTTP {response.status_code} "
                        f"(expected {step.expected_status_baseline}). Aborting plan."
                    )
                    return None

                # Verify confirmed untampered booking matches authoritative quote baseline
                confirmed_amount = self.execution_context.get("confirmed_baseline_amount")
                confirmed_currency = self.execution_context.get("confirmed_baseline_currency")

                if self.baseline:
                    if confirmed_amount is not None and int(confirmed_amount) != self.baseline.amount_minor_units:
                        logger.warning(
                            f"Negative control booking amount ({confirmed_amount}) differs from "
                            f"authoritative quote ({self.baseline.amount_minor_units}); aborting."
                        )
                        return None
                    if confirmed_currency is not None and str(confirmed_currency) != self.baseline.currency:
                        logger.warning(
                            f"Negative control booking currency ({confirmed_currency}) differs from "
                            f"authoritative quote ({self.baseline.currency}); aborting."
                        )
                        return None

            # Phase 3: Probe - Financial Manipulation Assessment
            elif step.phase == PlanPhase.PROBE:
                if response.status_code == 200:
                    try:
                        booking_data = response.json()
                    except Exception:
                        logger.warning("Probe returned 200 OK but body is not valid JSON; inconclusive.")
                        return None

                    if not isinstance(booking_data, dict):
                        logger.warning("Probe response JSON is not a dictionary; inconclusive.")
                        return None

                    actual_amount = booking_data.get("amount_minor_units")
                    actual_currency = booking_data.get("currency")

                    # Check which parameter was tampered in the probe request
                    tampered_amount = (
                        resolved_body.get("client_amount_minor_units")
                        if isinstance(resolved_body, dict)
                        else None
                    )
                    tampered_currency = (
                        resolved_body.get("client_currency")
                        if isinstance(resolved_body, dict)
                        else None
                    )

                    is_amount_violation = (
                        tampered_amount is not None
                        and self.baseline is not None
                        and tampered_amount != self.baseline.amount_minor_units
                        and actual_amount == tampered_amount
                    )

                    is_currency_violation = (
                        tampered_currency is not None
                        and self.baseline is not None
                        and tampered_currency != self.baseline.currency
                        and actual_currency == tampered_currency
                    )

                    if is_amount_violation or is_currency_violation:
                        flaw_type = "Currency Tampering" if is_currency_violation else "Amount Tampering"
                        logger.info(
                            f"I-02 Pricing Integrity flaw detected on '{plan.target_endpoint_identity}' ({flaw_type})! "
                            f"Server accepted client values (amount: {actual_amount}, currency: {actual_currency}) "
                            f"differing from authoritative quote (amount: {self.baseline.amount_minor_units}, "
                            f"currency: {self.baseline.currency})."
                        )
                        return self._create_candidate_finding(
                            plan=plan,
                            step=step,
                            response=response,
                            exec_res=exec_res,
                            flaw_type=flaw_type,
                            actual_amount=actual_amount,
                            actual_currency=actual_currency,
                        )
                    else:
                        logger.info(
                            "Probe returned 200 OK, but persisted booking maintained authoritative quote pricing. "
                            "Invariant held."
                        )
                        return None

                elif response.status_code in {400, 422}:
                    logger.info(
                        f"Server correctly rejected price/currency tampering attempt with HTTP {response.status_code}. "
                        "Pricing integrity invariant held."
                    )
                    return None
                elif response.status_code >= 500:
                    logger.warning(f"Target server returned HTTP {response.status_code}; inconclusive probe.")
                    return None
                else:
                    logger.warning(f"Unexpected probe response status HTTP {response.status_code}; inconclusive.")
                    return None

        return None

    def _create_candidate_finding(
        self,
        plan: AttackPlan,
        step: PlanStep,
        response: httpx.Response,
        exec_res: ExecutionResult,
        flaw_type: str,
        actual_amount: Any,
        actual_currency: Any,
    ) -> CandidateFinding:
        """Constructs an evidence-backed CandidateFinding contract for pricing integrity violations."""
        inferred_ep = InferredEndpoint(
            endpoint_id=plan.target_endpoint_identity,
            method=step.method.upper(),
            path_template=step.endpoint_route_template,
            auth_required=True,
            roles_observed=["agency_admin"],
            parameters=dict(step.parameters),
            source_har_request_id="synthetic",
            raw_packet_hash=exec_res.response_digest,
            confidence_score=0.99,
        )

        baseline_str = (
            f"{self.baseline.amount_minor_units} {self.baseline.currency}"
            if self.baseline
            else "unknown"
        )
        hypothesis = AttackHypothesis(
            hypothesis_id=plan.hypothesis_id,
            target_endpoint=inferred_ep,
            invariant_targeted=self.supported_invariant,
            rationale=(
                f"Server-authoritative pricing integrity violation ({flaw_type}) on "
                f"{step.method.upper()} {step.endpoint_route_template}: Application accepted client-controlled "
                f"financial parameter ({actual_amount} {actual_currency}) overriding the authoritative "
                f"server quote ({baseline_str})."
            ),
            test_strategy=f"Differential financial manipulation ({flaw_type.lower()}) against quote baseline",
            attacker_tenant_id=plan.attacker_tenant_id,
            victim_tenant_id=plan.victim_tenant_id,
            risk_level="HIGH",
        )

        return CandidateFinding(
            candidate_id=f"cand_{plan.plan_id[5:]}",
            hypothesis=hypothesis,
            observed_status_code=response.status_code,
            raw_response_snippet=exec_res.sanitized_body,
        )
