"""I-01 Tenant Isolation Specialist Executor for Drishti AI.

Implements BOLAExecutor verifying multi-tenant object access boundaries:
1. Provisions synthetic victim fixture with injected canary token.
2. Provisions attacker fixture to establish baseline legitimate context.
3. Runs negative controls verifying victim can read own resource and attacker can read own resource.
4. Executes cross-tenant read probe (attacker reading victim resource).
5. Detects canary token disclosure and emits CandidateFinding for independent oracle verification.
"""

import hashlib
import logging
from typing import Any, Dict, Optional
import uuid

import httpx

from drishti.core.models import (
    AttackHypothesis,
    CandidateFinding,
    ExecutionResult,
    InferredEndpoint,
    InvariantType,
)
from drishti.executors.attack_plan import (
    AttackPlan,
    CanarySecretStore,
    ParsedEndpointIdentity,
    PlanPhase,
)
from drishti.executors.base import ISpecialistExecutor
from drishti.policy.client import SafeHttpClient
from drishti.verifier.models import ExecutionOutcome, ExecutorRunResult

logger = logging.getLogger(__name__)


class BOLAExecutor(ISpecialistExecutor):
    """Specialist Security Executor targeting Invariant I-01: Multi-Tenant Data Isolation (BOLA/IDOR)."""

    supported_invariant: InvariantType = InvariantType.TENANT_ISOLATION

    def __init__(
        self,
        http_client: SafeHttpClient,
        budget_limit: Optional[int] = None,
    ):
        super().__init__(http_client=http_client, budget_limit=budget_limit)

    async def execute(
        self,
        plan: AttackPlan,
        base_url: str = "",
        approval_token: Optional[str] = None,
    ) -> ExecutorRunResult:
        """Executes the multi-step I-01 tenant isolation attack plan.

        Returns:
            ExecutorRunResult: Encapsulating ExecutionOutcome (CANDIDATE, EXPECTED_REJECTION,
            INCONCLUSIVE, ABORTED), evidence manifest, and candidate finding if observed.

        IMPORTANT: Emits CandidateFinding only, NEVER a confirmed finding.
        Final verification and lifecycle transitions are strictly owned by the Verification Oracle.
        """
        self.start_execution(plan)
        execution_id = f"run_{uuid.uuid4().hex[:12]}"
        completed_steps: list[str] = []

        canary_spec = plan.canary_spec
        expected_canary_token: Optional[str] = None
        if canary_spec and canary_spec.canary_secret_ref:
            expected_canary_token = CanarySecretStore.get_secret(canary_spec.canary_secret_ref)

        # Resolve effective base URL
        effective_base_url = base_url
        if not effective_base_url:
            parsed_identity = ParsedEndpointIdentity.parse(plan.target_endpoint_identity)
            if parsed_identity.origin.startswith("http://") or parsed_identity.origin.startswith("https://"):
                effective_base_url = parsed_identity.origin
            else:
                effective_base_url = "http://test"

        probe_response: Optional[httpx.Response] = None
        probe_exec_res: Optional[ExecutionResult] = None

        for step in plan.steps:
            resolved_url = self.resolve_step_url(step, base_url=effective_base_url)
            response, exec_res = await self.send_guarded_request(
                plan=plan,
                step=step,
                resolved_url=resolved_url,
                approval_token=approval_token,
            )
            completed_steps.append(step.step_id)

            # Phase-specific invariant and negative control evaluation
            if step.phase == PlanPhase.SETUP:
                if response.status_code != step.expected_status_baseline:
                    logger.error(
                        f"Fixture setup step '{step.step_id}' failed with status "
                        f"{response.status_code} (expected {step.expected_status_baseline})."
                    )
                    raise RuntimeError(
                        f"Fixture setup step '{step.step_id}' failed: "
                        f"expected {step.expected_status_baseline}, got {response.status_code}."
                    )

            elif step.phase == PlanPhase.NEGATIVE_CONTROL:
                if response.status_code != step.expected_status_baseline:
                    logger.warning(
                        f"Negative control step '{step.step_id}' failed with status "
                        f"{response.status_code} (expected {step.expected_status_baseline}). "
                        f"Target application environment is in unexpected state; aborting plan."
                    )
                    manifest = self.build_evidence_manifest(plan, execution_id)
                    return ExecutorRunResult(
                        execution_id=execution_id,
                        plan_id=plan.plan_id,
                        invariant_id=self.supported_invariant,
                        outcome=ExecutionOutcome.INCONCLUSIVE,
                        candidate=None,
                        evidence_manifest=manifest,
                        completed_steps=completed_steps,
                        failed_step=step.step_id,
                        reason=f"Negative control step '{step.step_id}' returned HTTP {response.status_code} (expected {step.expected_status_baseline})",
                        persisted_resource_id=self.execution_context.get("victim_booking_id"),
                    )

                # Verify canary visibility in victim's legitimate negative control read
                if step.actor_tenant_id == plan.victim_tenant_id and expected_canary_token:
                    if expected_canary_token not in response.text:
                        logger.warning(
                            f"Victim negative control read did not contain expected canary token; aborting."
                        )
                        manifest = self.build_evidence_manifest(plan, execution_id)
                        return ExecutorRunResult(
                            execution_id=execution_id,
                            plan_id=plan.plan_id,
                            invariant_id=self.supported_invariant,
                            outcome=ExecutionOutcome.INCONCLUSIVE,
                            candidate=None,
                            evidence_manifest=manifest,
                            completed_steps=completed_steps,
                            failed_step=step.step_id,
                            reason="Victim negative control read did not contain expected canary token",
                            persisted_resource_id=self.execution_context.get("victim_booking_id"),
                        )

            elif step.phase == PlanPhase.PROBE:
                probe_response = response
                probe_exec_res = exec_res

                # Check for cross-tenant data disclosure
                if response.status_code == 200:
                    disclosed = False
                    if expected_canary_token and expected_canary_token in response.text:
                        # Exact canary digest verification
                        computed_digest = hashlib.sha256(expected_canary_token.encode("utf-8")).hexdigest()
                        if not canary_spec or not canary_spec.canary_value_digest or computed_digest == canary_spec.canary_value_digest:
                            disclosed = True
                        else:
                            logger.warning(
                                f"Canary token found in response, but computed digest {computed_digest} "
                                f"did not match canary_spec.canary_value_digest ({canary_spec.canary_value_digest})."
                            )

                    if disclosed:
                        logger.info(
                            f"BOLA Vulnerability detected on '{plan.target_endpoint_identity}'! "
                            f"Attacker '{plan.attacker_tenant_id}' read victim '{plan.victim_tenant_id}' canary."
                        )
                        candidate = self._create_candidate_finding(
                            plan=plan,
                            step=step,
                            response=response,
                            exec_res=exec_res,
                        )
                        manifest = self.build_evidence_manifest(plan, execution_id)
                        return ExecutorRunResult(
                            execution_id=execution_id,
                            plan_id=plan.plan_id,
                            invariant_id=self.supported_invariant,
                            outcome=ExecutionOutcome.CANDIDATE,
                            candidate=candidate,
                            evidence_manifest=manifest,
                            completed_steps=completed_steps,
                            reason="Attacker successfully accessed victim private booking with canary disclosure",
                            persisted_resource_id=self.execution_context.get("victim_booking_id"),
                        )
                    else:
                        logger.info(
                            f"Cross-tenant probe returned 200 OK, but exact planned canary value "
                            f"was not disclosed in the response payload."
                        )
                        manifest = self.build_evidence_manifest(plan, execution_id)
                        return ExecutorRunResult(
                            execution_id=execution_id,
                            plan_id=plan.plan_id,
                            invariant_id=self.supported_invariant,
                            outcome=ExecutionOutcome.INCONCLUSIVE,
                            candidate=None,
                            evidence_manifest=manifest,
                            completed_steps=completed_steps,
                            reason="Cross-tenant probe returned 200 OK without planned canary value",
                            persisted_resource_id=self.execution_context.get("victim_booking_id"),
                        )
                elif response.status_code in {401, 403, 404}:
                    logger.info(
                        f"Cross-tenant read probe rejected with HTTP {response.status_code}. "
                        f"Tenant isolation invariant holds."
                    )
                    manifest = self.build_evidence_manifest(plan, execution_id)
                    return ExecutorRunResult(
                        execution_id=execution_id,
                        plan_id=plan.plan_id,
                        invariant_id=self.supported_invariant,
                        outcome=ExecutionOutcome.EXPECTED_REJECTION,
                        candidate=None,
                        evidence_manifest=manifest,
                        completed_steps=completed_steps,
                        reason=f"Cross-tenant read rejected with HTTP {response.status_code}",
                        persisted_resource_id=self.execution_context.get("victim_booking_id"),
                    )

        manifest = self.build_evidence_manifest(plan, execution_id)
        return ExecutorRunResult(
            execution_id=execution_id,
            plan_id=plan.plan_id,
            invariant_id=self.supported_invariant,
            outcome=ExecutionOutcome.INCONCLUSIVE,
            candidate=None,
            evidence_manifest=manifest,
            completed_steps=completed_steps,
            reason="Plan completed without executing probe step",
            persisted_resource_id=self.execution_context.get("victim_booking_id"),
        )

    def _create_candidate_finding(
        self,
        plan: AttackPlan,
        step: Any,
        response: httpx.Response,
        exec_res: ExecutionResult,
    ) -> CandidateFinding:
        """Constructs an evidence-backed CandidateFinding contract."""
        parsed_identity = ParsedEndpointIdentity.parse(plan.target_endpoint_identity)
        inferred_ep = InferredEndpoint(
            endpoint_id=plan.target_endpoint_identity,
            method=step.method.upper(),
            path_template=step.endpoint_route_template,
            auth_required=True,
            roles_observed=["agency_admin"],
            parameters=dict(step.parameters),
            source_har_request_id="synthetic",
            raw_packet_hash=exec_res.response_digest,
            confidence_score=0.98,
        )

        hypothesis = AttackHypothesis(
            hypothesis_id=plan.hypothesis_id,
            target_endpoint=inferred_ep,
            invariant_targeted=self.supported_invariant,
            rationale=(
                f"Multi-tenant data isolation failure (BOLA/IDOR) on {step.method.upper()} "
                f"{step.endpoint_route_template}: Attacker tenant '{plan.attacker_tenant_id}' "
                f"retrieved private booking belonging to victim tenant '{plan.victim_tenant_id}'."
            ),
            test_strategy="Guarded cross-tenant read probe with canary disclosure verification",
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
