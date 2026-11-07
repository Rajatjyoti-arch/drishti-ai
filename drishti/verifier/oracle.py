"""Verification Oracle for Drishti AI.

Strict separation of concerns:
- Specialist executors propose CandidateFindings.
- The Verification Oracle independently verifies them via:
  1. Cryptographic and structural manifest validation (fail-closed).
  2. Independent out-of-band API read-back verification against the target service.
  3. Transparent, rubric-based engineering confidence calculation.
  4. 3-way classification: CONFIRMED, NOT_REPRODUCED, INCONCLUSIVE.
  5. Generating production-ready VerifiedFinding contracts with remediation guidance.
"""

import hashlib
import json
import logging
from typing import Any, Dict, List, Optional
import uuid

import httpx

from drishti.core.models import (
    CandidateFinding,
    InvariantType,
    OutgoingTestRequest,
    VerificationStatus,
    VerifiedFinding,
)
from drishti.executors.attack_plan import CanarySecretStore
from drishti.policy.client import SafeHttpClient
from drishti.verifier.evidence_validator import EvidenceValidationReport, EvidenceValidator
from drishti.verifier.models import (
    ExecutionOutcome,
    ExecutorRunResult,
    VerificationAttempt,
    VerificationResult,
)
from drishti.verifier.reproduction import ReproductionRecipeGenerator

logger = logging.getLogger(__name__)


class VerificationOracle:
    """Independent oracle certifying or refuting candidate security findings."""

    def __init__(
        self,
        http_client: SafeHttpClient,
        evidence_validator: Optional[EvidenceValidator] = None,
    ):
        self.http_client = http_client
        if evidence_validator is not None:
            self.evidence_validator = evidence_validator
        else:
            pg = getattr(http_client, "policy_gate", None)
            ledger = getattr(pg, "ledger", None) if pg else None
            estore = getattr(http_client, "evidence_store", None)
            self.evidence_validator = EvidenceValidator(
                evidence_store=estore,
                ledger=ledger,
                policy_gate=pg,
            )

    async def verify(
        self,
        run_result: ExecutorRunResult,
        base_url: str = "http://test",
        canary_secret: Optional[str] = None,
        raw_payloads: Optional[Dict[str, str]] = None,
    ) -> VerificationResult:
        """Independently evaluates and verifies an executor's execution result.

        Enforces a strict 3-way classification:
        - CONFIRMED: Cryptographic evidence valid + independent API read-back matched.
        - NOT_REPRODUCED: Target application defenses held (e.g. 403/400).
        - INCONCLUSIVE: Broken negative control, expired baseline, manifest flaws, or failed read-back.
        """
        candidate = run_result.candidate
        effective_canary_secret = canary_secret
        if not effective_canary_secret and run_result.evidence_manifest.canary_spec_digest:
            effective_canary_secret = CanarySecretStore.get_secret_by_digest(
                run_result.evidence_manifest.canary_spec_digest,
                execution_id=run_result.execution_id,
            )

        # 1. Non-candidate execution outcomes: validate evidence before accepting defense claims
        if run_result.outcome == ExecutionOutcome.EXPECTED_REJECTION:
            # Check if rejection was caused by Guard / Policy Gate denial rather than target application
            guard_denial = False
            for ref in run_result.evidence_manifest.evidence_references:
                if self.http_client and hasattr(self.http_client, "policy_gate"):
                    pg = getattr(self.http_client, "policy_gate", None)
                    if pg and hasattr(pg, "get_decision") and ref.policy_decision_nonce:
                        dec = pg.get_decision(ref.policy_decision_nonce)
                        if dec and (dec.get("action") in ("DENY", "STOP", "PAUSE") or not dec.get("approved")):
                            guard_denial = True
                            break

            reason_lower = (run_result.reason or "").lower()
            if guard_denial or any(term in reason_lower for term in ["policy gate", "drishti-guard", "budget exhausted", "denied by policy", "guard denial"]):
                rationale = f"Probe was rejected by Policy Gate / Guard before reaching target ({run_result.reason}). Target defense unverified."
                attempt = VerificationAttempt(
                    status=VerificationStatus.INCONCLUSIVE,
                    confidence_score=0.0,
                    confidence_rationale="0.00: Guard-level denial halted execution before target evaluation.",
                    read_back_performed=False,
                    read_back_matched=False,
                    evidence_validation_passed=False,
                    details={"reason": run_result.reason},
                )
                return VerificationResult(
                    candidate_id=candidate.candidate_id if candidate else "none",
                    invariant_id=run_result.invariant_id,
                    status=VerificationStatus.INCONCLUSIVE,
                    confidence_score=0.0,
                    confidence_rationale=rationale,
                    evidence_manifest_id=run_result.evidence_manifest.manifest_id,
                    attempts=[attempt],
                    verified_finding=None,
                    recommended_action="Check policy gate configuration and test budgets.",
                )

            # P0: Validate manifest BEFORE accepting expected rejection as target defense
            validation_report = self.evidence_validator.validate_manifest(
                manifest=run_result.evidence_manifest,
                canary_secret=effective_canary_secret,
                raw_payloads=raw_payloads,
            )

            if not validation_report.is_valid:
                rationale = (
                    f"Evidence manifest validation failed on expected rejection: "
                    f"{'; '.join(validation_report.issues)}. Defensive assertion cannot be confirmed."
                )
                attempt = VerificationAttempt(
                    status=VerificationStatus.INCONCLUSIVE,
                    confidence_score=0.30,
                    confidence_rationale=f"0.30: Evidence anomalies present on rejected run: {'; '.join(validation_report.issues)}",
                    read_back_performed=False,
                    read_back_matched=False,
                    evidence_validation_passed=False,
                    details={"issues": validation_report.issues},
                )
                return VerificationResult(
                    candidate_id=candidate.candidate_id if candidate else "none",
                    invariant_id=run_result.invariant_id,
                    status=VerificationStatus.INCONCLUSIVE,
                    confidence_score=0.30,
                    confidence_rationale=rationale,
                    evidence_manifest_id=run_result.evidence_manifest.manifest_id,
                    attempts=[attempt],
                    verified_finding=None,
                    recommended_action="Audit execution telemetry and fix evidence integrity before accepting clean defense status.",
                )
                attempt = VerificationAttempt(
                    status=VerificationStatus.INCONCLUSIVE,
                    confidence_score=0.0,
                    confidence_rationale="0.00: Guard-level denial halted execution before target evaluation.",
                    read_back_performed=False,
                    read_back_matched=False,
                    evidence_validation_passed=True,
                    details={"reason": run_result.reason},
                )
                return VerificationResult(
                    candidate_id=candidate.candidate_id if candidate else "none",
                    invariant_id=run_result.invariant_id,
                    status=VerificationStatus.INCONCLUSIVE,
                    confidence_score=0.0,
                    confidence_rationale=rationale,
                    evidence_manifest_id=run_result.evidence_manifest.manifest_id,
                    attempts=[attempt],
                    verified_finding=None,
                    recommended_action="Check policy gate configuration and test budgets.",
                )

            # Target application properly enforced invariant rules
            rationale = (
                f"Target application defensive controls held. Probe was properly rejected by the application "
                f"({run_result.reason or 'expected authorization or input validation rejection'})."
            )
            attempt = VerificationAttempt(
                status=VerificationStatus.NOT_REPRODUCED,
                confidence_score=1.0,
                confidence_rationale="1.00: Defensive controls held cleanly; invariant maintained and verified.",
                read_back_performed=False,
                read_back_matched=False,
                evidence_validation_passed=True,
                details={"reason": run_result.reason},
            )
            return VerificationResult(
                candidate_id=candidate.candidate_id if candidate else "none",
                invariant_id=run_result.invariant_id,
                status=VerificationStatus.NOT_REPRODUCED,
                confidence_score=1.0,
                confidence_rationale=rationale,
                evidence_manifest_id=run_result.evidence_manifest.manifest_id,
                attempts=[attempt],
                verified_finding=None,
                recommended_action="No remediation needed. Target defense verified.",
            )

        if run_result.outcome in (ExecutionOutcome.INCONCLUSIVE, ExecutionOutcome.ABORTED):
            rationale = (
                f"Execution did not yield a conclusive candidate finding "
                f"({run_result.outcome.value}: {run_result.reason})."
            )
            attempt = VerificationAttempt(
                status=VerificationStatus.INCONCLUSIVE,
                confidence_score=0.0,
                confidence_rationale="0.00: Test execution was inconclusive or aborted before probe evaluation.",
                read_back_performed=False,
                read_back_matched=False,
                evidence_validation_passed=False,
                details={"reason": run_result.reason},
            )
            return VerificationResult(
                candidate_id=candidate.candidate_id if candidate else "none",
                invariant_id=run_result.invariant_id,
                status=VerificationStatus.INCONCLUSIVE,
                confidence_score=0.0,
                confidence_rationale=rationale,
                evidence_manifest_id=run_result.evidence_manifest.manifest_id,
                attempts=[attempt],
                verified_finding=None,
                recommended_action="Investigate target environment stability and rerun verification.",
            )

        # 2. Candidate evaluation: validate evidence manifest (fail-closed)
        if not candidate:
            return VerificationResult(
                candidate_id="none",
                invariant_id=run_result.invariant_id,
                status=VerificationStatus.INCONCLUSIVE,
                confidence_score=0.0,
                confidence_rationale="Execution marked CANDIDATE but no candidate object provided.",
                evidence_manifest_id=run_result.evidence_manifest.manifest_id,
                attempts=[],
                verified_finding=None,
                recommended_action="Rerun specialist executor with valid candidate emission.",
            )

        validation_report = self.evidence_validator.validate_manifest(
            manifest=run_result.evidence_manifest,
            canary_secret=effective_canary_secret,
            raw_payloads=raw_payloads,
        )

        if not validation_report.is_valid:
            logger.warning(
                f"Evidence manifest validation failed for candidate '{candidate.candidate_id}': "
                f"{validation_report.issues}"
            )
            attempt = VerificationAttempt(
                status=VerificationStatus.INCONCLUSIVE,
                confidence_score=0.30,
                confidence_rationale=(
                    f"0.30: Evidence manifest contains integrity anomalies: "
                    f"{'; '.join(validation_report.issues)}"
                ),
                read_back_performed=False,
                read_back_matched=False,
                evidence_validation_passed=False,
                details={"issues": validation_report.issues},
            )
            return VerificationResult(
                candidate_id=candidate.candidate_id,
                invariant_id=run_result.invariant_id,
                status=VerificationStatus.INCONCLUSIVE,
                confidence_score=0.30,
                confidence_rationale="Evidence manifest validation failed; candidate cannot be confirmed.",
                evidence_manifest_id=run_result.evidence_manifest.manifest_id,
                attempts=[attempt],
                verified_finding=None,
                recommended_action="Audit execution logs and cryptographic digests before trusting finding.",
            )

        # 3. Independent API Read-Back Verification
        read_back_performed = False
        read_back_status: Optional[int] = None
        read_back_matched = False
        read_back_details: Dict[str, Any] = {}

        if run_result.persisted_resource_id:
            read_back_performed = True
            try:
                (
                    read_back_status,
                    read_back_matched,
                    read_back_details,
                ) = await self._perform_independent_read_back(
                    run_result=run_result,
                    base_url=base_url,
                    canary_secret=effective_canary_secret,
                )
            except Exception as e:
                logger.error(f"Independent API read-back verification threw exception: {e}")
                read_back_details["error"] = str(e)

        # 4. Transparent Engineering Confidence Rubric
        score, rationale_items = self._compute_confidence_rubric(
            run_result=run_result,
            validation_report=validation_report,
            read_back_performed=read_back_performed,
            read_back_matched=read_back_matched,
        )

        status = VerificationStatus.CONFIRMED if read_back_matched and score >= 0.85 else VerificationStatus.INCONCLUSIVE
        confidence_rationale = " | ".join(rationale_items)

        attempt = VerificationAttempt(
            status=status,
            confidence_score=score,
            confidence_rationale=confidence_rationale,
            read_back_performed=read_back_performed,
            read_back_status=read_back_status,
            read_back_matched=read_back_matched,
            evidence_validation_passed=validation_report.is_valid,
            details=read_back_details,
        )

        verified_finding: Optional[VerifiedFinding] = None
        recommended_action = ""

        if status == VerificationStatus.CONFIRMED:
            verified_finding = self._build_verified_finding(
                run_result=run_result,
                confidence_score=score,
                read_back_details=read_back_details,
            )
            recommended_action = self._determine_recommended_action(run_result.invariant_id)
        else:
            recommended_action = "Target state unverified by independent API read-back. Retest required."

        return VerificationResult(
            candidate_id=candidate.candidate_id,
            invariant_id=run_result.invariant_id,
            status=status,
            confidence_score=score,
            confidence_rationale=confidence_rationale,
            evidence_manifest_id=run_result.evidence_manifest.manifest_id,
            attempts=[attempt],
            verified_finding=verified_finding,
            recommended_action=recommended_action,
        )

    async def _perform_independent_read_back(
        self,
        run_result: ExecutorRunResult,
        base_url: str,
        canary_secret: Optional[str],
    ) -> tuple[int, bool, Dict[str, Any]]:
        """Executes an out-of-band read request against the target service API to confirm persistence."""
        res_id = run_result.persisted_resource_id
        details: Dict[str, Any] = {"resource_id": res_id}

        # Dynamically derive attacker credentials and tenant from execution context
        attacker_tenant = (
            run_result.candidate.hypothesis.attacker_tenant_id
            if run_result.candidate
            else "agency_b"
        )
        cred_ref = (
            run_result.candidate.hypothesis.target_endpoint.parameters.get("credential_ref")
            if run_result.candidate
            else None
        ) or f"cred:{attacker_tenant.lower()}:admin"

        if run_result.invariant_id == InvariantType.TENANT_ISOLATION:
            # Independent API read-back for BOLA: attacker reading victim booking
            req = OutgoingTestRequest(
                method="GET",
                url=f"{base_url.rstrip('/')}/api/v2/bookings/{res_id}",
                target_tenant_id=attacker_tenant,
                target_invariant=run_result.invariant_id,
                credential_ref=cred_ref,
                test_id="oracle_readback_i01",
            )
            resp = await self.http_client.send_request(req)
            details["status_code"] = resp.status_code
            if resp.status_code == 200:
                # STRICT FAIL-CLOSED CANARY CHECK:
                # Reject generic "canary" substring matches. Must verify exact secret or token field.
                if not canary_secret:
                    details["canary_verification_error"] = "Canary secret not supplied for independent verification"
                    return resp.status_code, False, details

                has_canary = False
                try:
                    data = resp.json()
                    observed_token = (
                        data.get("canary_token")
                        or data.get("canary_value")
                        or data.get("canary_id")
                    )
                    if observed_token and str(observed_token) == str(canary_secret):
                        has_canary = True
                    elif canary_secret in resp.text:
                        # Exact secret string presence
                        has_canary = True
                except Exception:
                    if canary_secret in resp.text:
                        has_canary = True

                details["canary_observed"] = has_canary
                return resp.status_code, has_canary, details
            return resp.status_code, False, details

        elif run_result.invariant_id == InvariantType.PRICING_INTEGRITY:
            # Independent API read-back for Pricing: verify persisted booking amount in backend
            req = OutgoingTestRequest(
                method="GET",
                url=f"{base_url.rstrip('/')}/api/v2/bookings/{res_id}",
                target_tenant_id=attacker_tenant,
                target_invariant=run_result.invariant_id,
                credential_ref=cred_ref,
                test_id="oracle_readback_i02",
            )
            resp = await self.http_client.send_request(req)
            details["status_code"] = resp.status_code
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    persisted_amount = data.get("amount_minor_units")
                    persisted_currency = data.get("currency")
                    details["persisted_amount"] = persisted_amount
                    details["persisted_currency"] = persisted_currency

                    probe_summary = run_result.probe_summary or {}
                    baseline_summary = run_result.baseline_summary or {}
                    tampered_amount = probe_summary.get("tampered_amount")
                    tampered_currency = probe_summary.get("tampered_currency")
                    authoritative_amount = baseline_summary.get("amount_minor_units")
                    authoritative_currency = baseline_summary.get("currency")

                    # P1 FIX: Variant-specific comparison (AND instead of OR)
                    matched = False
                    if tampered_amount is not None and tampered_currency is None:
                        # Amount tampering: amount MUST match tampered value AND currency MUST match quote baseline
                        matched = (persisted_amount == tampered_amount) and (
                            authoritative_currency is None or persisted_currency == authoritative_currency
                        )
                    elif tampered_currency is not None and tampered_amount is None:
                        # Currency tampering: currency MUST match tampered value AND amount MUST match quote baseline
                        matched = (persisted_currency == tampered_currency) and (
                            authoritative_amount is None or persisted_amount == authoritative_amount
                        )
                    elif tampered_amount is not None and tampered_currency is not None:
                        matched = (persisted_amount == tampered_amount) and (persisted_currency == tampered_currency)

                    details["persisted_tampering_matched"] = matched
                    return resp.status_code, matched, details
                except Exception as e:
                    details["json_error"] = str(e)
                    return resp.status_code, False, details
            return resp.status_code, False, details

        return 0, False, details

    def _compute_confidence_rubric(
        self,
        run_result: ExecutorRunResult,
        validation_report: EvidenceValidationReport,
        read_back_performed: bool,
        read_back_matched: bool,
    ) -> tuple[float, List[str]]:
        """Transparent engineering confidence rubric.

        Weights:
        +0.25: Baseline negative controls executed and verified.
        +0.15: Authoritative quote / canary spec integrity verified.
        +0.30: Specialist probe produced 200 OK with violation characteristics.
        +0.20: Independent oracle API read-back confirmed persistent violation.
        +0.10: Tamper-evident evidence digests and payload hashes verified.
        """
        score = 0.0
        rationale: List[str] = []

        if validation_report.negative_control_verified:
            score += 0.25
            rationale.append("+0.25: Baseline negative controls executed and verified")
        else:
            rationale.append("+0.00: Negative controls missing or unverified")

        if validation_report.canary_digest_matched or run_result.baseline_summary:
            score += 0.15
            rationale.append("+0.15: Canary token digest / quote baseline integrity verified")
        else:
            rationale.append("+0.00: Canary digest unverified")

        if run_result.candidate and run_result.candidate.observed_status_code == 200:
            score += 0.30
            rationale.append("+0.30: Specialist probe returned 200 OK with violation payload")
        else:
            rationale.append("+0.00: Probe status not 200")

        if read_back_performed and read_back_matched:
            score += 0.20
            rationale.append("+0.20: Independent API read-back confirmed datastore persistence")
        else:
            rationale.append("+0.00: Independent API read-back unconfirmed")

        if validation_report.digests_verified:
            score += 0.10
            rationale.append("+0.10: Tamper-evident SHA-256 payload digests verified")
        else:
            rationale.append("+0.00: Payload digest anomalies present")

        final_score = min(1.0, round(score, 2))
        return final_score, rationale

    def _build_verified_finding(
        self,
        run_result: ExecutorRunResult,
        confidence_score: float,
        read_back_details: Dict[str, Any],
    ) -> VerifiedFinding:
        """Constructs a production-grade VerifiedFinding contract."""
        cand = run_result.candidate
        inv = run_result.invariant_id

        if inv == InvariantType.TENANT_ISOLATION:
            title = "Broken Object Level Authorization (BOLA) in Travel Booking Retrieval"
            violated_rule = "OWASP API1:2023 - Broken Object Level Authorization"
            impact = {
                "financial_loss": "LOW",
                "data_confidentiality": "CRITICAL",
                "regulatory_impact": "GDPR / DPDP Violations (PII Exposure)",
                "description": (
                    f"Agency '{cand.hypothesis.attacker_tenant_id}' can access private bookings, "
                    f"passenger passports, and PII of competitor '{cand.hypothesis.victim_tenant_id}'."
                ),
            }
            fields = ["passenger_passport", "passenger_name", "canary_token", "pnr"]
            recipes = ReproductionRecipeGenerator.generate_i01_recipes(
                victim_booking_id=run_result.persisted_resource_id or "$DRISHTI_VICTIM_BOOKING_ID",
            )
            suggested_fix = (
                "Enforce tenant ownership validation in get_booking handler: verify that "
                "booking.owner_tenant_id == session.tenant_id before returning booking data."
            )
        else:
            title = "Server-Authoritative Pricing Bypass in Checkout Booking Flow"
            violated_rule = "CWE-472: External Control of Assumed-Immutable Web Parameter"
            impact = {
                "financial_loss": "CRITICAL",
                "data_confidentiality": "LOW",
                "regulatory_impact": "Direct revenue fraud and booking margin collapse",
                "description": (
                    "Application trusts client-controlled price or currency parameters on checkout, "
                    "allowing malicious agencies to book inventory at arbitrary discounted rates."
                ),
            }
            fields = ["amount_minor_units", "currency", "client_amount_minor_units"]
            recipes = ReproductionRecipeGenerator.generate_i02_recipes(
                booking_id=run_result.persisted_resource_id,
                tampered_amount=(run_result.probe_summary or {}).get("tampered_amount"),
                tampered_currency=(run_result.probe_summary or {}).get("tampered_currency"),
                authoritative_amount=(run_result.baseline_summary or {}).get("amount_minor_units"),
                authoritative_currency=(run_result.baseline_summary or {}).get("currency"),
            )
            suggested_fix = (
                "Ensure booking prices are strictly derived from authoritative server quotes "
                "referenced by valid hold tokens. Reject any client-submitted price overrides with HTTP 400."
            )

        return VerifiedFinding(
            finding_id=f"VF-{cand.candidate_id[5:]}",
            invariant_id=inv,
            status=VerificationStatus.CONFIRMED,
            title=title,
            target_endpoint=cand.hypothesis.target_endpoint.endpoint_id,
            violated_rule=violated_rule,
            confidence_score=confidence_score,
            business_impact=impact,
            exposed_sensitive_fields=fields,
            reproduction_steps=recipes,
            request_evidence_hash=run_result.evidence_manifest.manifest_id,
            raw_response_diff=cand.raw_response_snippet,
            suggested_fix=suggested_fix,
        )

    def _determine_recommended_action(self, invariant_id: InvariantType) -> str:
        """Determines next remediation action based on invariant type."""
        if invariant_id == InvariantType.TENANT_ISOLATION:
            return (
                "CRITICAL: Restrict endpoint authorization logic immediately to enforce tenant boundaries. "
                "Schedule verification retest upon patch deployment."
            )
        elif invariant_id == InvariantType.PRICING_INTEGRITY:
            return (
                "HIGH: Remove client price parameter acceptance from booking API. "
                "Audit past bookings for price discrepancies and retest."
            )
        return "Review finding telemetry and apply defensive patches."
