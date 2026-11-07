"""Evidence Validator for Drishti AI Verification Oracle.

Validates:
1. Negative control phase completion and baseline legitimacy.
2. Cryptographic payload digests (SHA-256) and artifact re-computation.
3. Canary token injection and digest fidelity (fail-closed).
4. Policy decision nonces (dec_*) and request correlation.
5. Audit ledger checkpoints and chain consistency.
"""

import functools
import hashlib
import logging
import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from drishti.verifier.models import EvidenceManifest, EvidenceReference

logger = logging.getLogger(__name__)

HEX_64_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")
DECISION_NONCE_REGEX = re.compile(r"^dec_[a-fA-F0-9]{6,}$")


class class_or_instancemethod:
    """Descriptor enabling a method to be called as either an instance method or class method."""

    def __init__(self, func):
        self.func = func
        functools.update_wrapper(self, func)

    def __get__(self, instance, owner=None):
        if instance is None:
            @functools.wraps(self.func)
            def class_wrapper(*args, **kwargs):
                return self.func(owner(), *args, **kwargs)
            return class_wrapper

        @functools.wraps(self.func)
        def instance_wrapper(*args, **kwargs):
            return self.func(instance, *args, **kwargs)
        return instance_wrapper


class EvidenceValidationReport(BaseModel):
    """Validation report detailing evidence manifest integrity checks."""

    is_valid: bool
    checked_steps: int
    issues: List[str] = Field(default_factory=list)
    canary_digest_matched: bool = False
    negative_control_verified: bool = False
    digests_verified: bool = False


class EvidenceValidator:
    """Verifies evidence manifests prior to independent oracle verification."""

    def __init__(
        self,
        evidence_store: Optional[Any] = None,
        ledger: Optional[Any] = None,
        policy_gate: Optional[Any] = None,
    ):
        self.evidence_store = evidence_store
        self.ledger = ledger
        self.policy_gate = policy_gate

    @class_or_instancemethod
    def validate_manifest(
        self,
        manifest: EvidenceManifest,
        canary_secret: Optional[str] = None,
        raw_payloads: Optional[Dict[str, str]] = None,
    ) -> EvidenceValidationReport:
        """Runs cryptographic and structural validation checks on an EvidenceManifest."""
        return self._do_validate(manifest, canary_secret=canary_secret, raw_payloads=raw_payloads)

    def _do_validate(
        self,
        manifest: EvidenceManifest,
        canary_secret: Optional[str] = None,
        raw_payloads: Optional[Dict[str, str]] = None,
    ) -> EvidenceValidationReport:
        issues: List[str] = []
        checked_steps = len(manifest.evidence_references)
        negative_control_verified = False
        canary_digest_matched = False
        digests_verified = False

        if checked_steps == 0:
            issues.append("Evidence manifest contains zero execution step references.")
            return EvidenceValidationReport(
                is_valid=False,
                checked_steps=0,
                issues=issues,
                canary_digest_matched=False,
                negative_control_verified=False,
                digests_verified=False,
            )

        # 1. Negative control execution check
        neg_control_steps = [
            ref
            for ref in manifest.evidence_references
            if ref.phase.upper() == "NEGATIVE_CONTROL"
        ]

        if not neg_control_steps:
            issues.append("Missing required negative control phase in execution evidence.")
        else:
            all_neg_ok = True
            for nc in neg_control_steps:
                if nc.status_code not in {200, 201, 204}:
                    issues.append(
                        f"Negative control step '{nc.step_id}' returned unexpected "
                        f"HTTP status {nc.status_code}."
                    )
                    all_neg_ok = False
            if all_neg_ok:
                negative_control_verified = True

        # 2. Canary token digest validation (STRICT FAIL-CLOSED)
        if manifest.canary_spec_digest:
            if not HEX_64_REGEX.match(manifest.canary_spec_digest):
                issues.append(
                    f"Canary spec digest '{manifest.canary_spec_digest}' is not a valid 64-char SHA-256 hash."
                )
            elif canary_secret is None:
                # Fail-closed: missing verification material cannot be assumed valid
                issues.append(
                    "Canary secret was not provided to verify canary_spec_digest; failing closed."
                )
            else:
                computed_digest = hashlib.sha256(canary_secret.encode("utf-8")).hexdigest()
                if computed_digest.lower() == manifest.canary_spec_digest.lower():
                    canary_digest_matched = True
                else:
                    issues.append(
                        f"Canary secret digest ({computed_digest}) does not match manifest "
                        f"canary_spec_digest ({manifest.canary_spec_digest})."
                    )
        else:
            # Invariants not using synthetic canaries (e.g. pricing integrity)
            canary_digest_matched = True

        # 3. Policy decision nonces, response digest integrity, and artifact recomputation
        digest_errors = 0
        for ref in manifest.evidence_references:
            if not ref.request_id:
                issues.append(f"Step '{ref.step_id}' is missing request_id.")
                digest_errors += 1

            # Validate policy decision nonce format
            if not ref.policy_decision_nonce or not DECISION_NONCE_REGEX.match(ref.policy_decision_nonce):
                issues.append(
                    f"Step '{ref.step_id}' contains invalid or missing policy decision nonce: "
                    f"'{ref.policy_decision_nonce}'."
                )
                digest_errors += 1
            else:
                # Authoritative PolicyGate decision provenance check
                decision_record = None
                if self.policy_gate and hasattr(self.policy_gate, "get_decision"):
                    decision_record = self.policy_gate.get_decision(ref.policy_decision_nonce)
                elif self.ledger and hasattr(self.ledger, "get_event_by_id"):
                    ev = self.ledger.get_event_by_id(ref.policy_decision_nonce)
                    if ev and "metadata" in ev:
                        m = ev.get("metadata", {})
                        decision_record = {
                            "decision_id": ev["event_id"],
                            "request_id": m.get("request_id"),
                            "url": m.get("url"),
                            "action": ev["event_type"].replace("POLICY_", ""),
                            "approved": ev["event_type"] == "POLICY_ALLOW",
                        }

                if decision_record is None:
                    issues.append(
                        f"Step '{ref.step_id}' policy decision nonce '{ref.policy_decision_nonce}' "
                        f"was not authenticated by PolicyGate or ledger (fabricated nonce)."
                    )
                    digest_errors += 1
                else:
                    if decision_record.get("request_id") and decision_record["request_id"] != ref.request_id:
                        issues.append(
                            f"Step '{ref.step_id}' nonce '{ref.policy_decision_nonce}' was issued for request "
                            f"'{decision_record.get('request_id')}', not '{ref.request_id}' (nonce mismatch)."
                        )
                        digest_errors += 1
                    if decision_record.get("url") and decision_record["url"] != ref.url:
                        issues.append(
                            f"Step '{ref.step_id}' nonce target '{decision_record.get('url')}' does not match step URL '{ref.url}'."
                        )
                        digest_errors += 1
                    if decision_record.get("action") not in ("ALLOW", "POLICY_ALLOW") and not decision_record.get("approved"):
                        issues.append(
                            f"Step '{ref.step_id}' policy decision was denied or not approved (action={decision_record.get('action')})."
                        )
                        digest_errors += 1

            # Validate response digest format
            if not ref.response_digest or not HEX_64_REGEX.match(ref.response_digest):
                issues.append(
                    f"Step '{ref.step_id}' contains invalid or missing response digest: "
                    f"'{ref.response_digest}'."
                )
                digest_errors += 1

            # UNCONDITIONAL Response Artifact & SHA-256 Digest Recomputation
            raw_bytes: Optional[bytes] = None
            if raw_payloads:
                val = raw_payloads.get(ref.request_id) or raw_payloads.get(ref.step_id)
                if val is None and getattr(ref, "artifact_id", None):
                    val = raw_payloads.get(ref.artifact_id)
                if val is not None:
                    raw_bytes = val.encode("utf-8") if isinstance(val, str) else val

            if raw_bytes is None and self.evidence_store:
                art_id = getattr(ref, "artifact_id", None) or f"art_{ref.request_id}"
                if hasattr(self.evidence_store, "get_raw_artifact"):
                    raw_bytes = self.evidence_store.get_raw_artifact(art_id)
                    if raw_bytes is None:
                        raw_bytes = self.evidence_store.get_raw_artifact(ref.request_id)

            if raw_bytes is None:
                issues.append(
                    f"Missing original response artifact for step '{ref.step_id}' "
                    f"(artifact ID: '{getattr(ref, 'artifact_id', None) or ref.request_id}'). Cannot prove response authenticity."
                )
                digest_errors += 1
            else:
                recomputed = hashlib.sha256(raw_bytes).hexdigest()
                if recomputed.lower() != ref.response_digest.lower():
                    issues.append(
                        f"Step '{ref.step_id}' forged digest: payload SHA-256 ({recomputed}) "
                        f"does not match declared digest ({ref.response_digest})."
                    )
                    digest_errors += 1

            # Check cross-correlation with manifest.raw_payload_hashes if populated
            if manifest.raw_payload_hashes:
                expected_hash = manifest.raw_payload_hashes.get(
                    ref.request_id
                ) or manifest.raw_payload_hashes.get(ref.step_id)
                if expected_hash and expected_hash.lower() != ref.response_digest.lower():
                    issues.append(
                        f"Step '{ref.step_id}' response digest '{ref.response_digest}' does "
                        f"not match manifest raw payload hash '{expected_hash}'."
                    )
                    digest_errors += 1

        # 4. Audit ledger checkpoint verification (FAIL-CLOSED)
        if not manifest.audit_ledger_checkpoint:
            issues.append("Missing required audit ledger checkpoint in evidence manifest.")
            digest_errors += 1
        elif self.ledger and hasattr(self.ledger, "verify_checkpoint_coverage"):
            try:
                req_ids = [ref.request_id for ref in manifest.evidence_references if ref.request_id]
                if not self.ledger.verify_checkpoint_coverage(manifest.audit_ledger_checkpoint, request_ids=req_ids):
                    issues.append(
                        f"Audit ledger checkpoint '{manifest.audit_ledger_checkpoint}' could "
                        f"not be authenticated against authoritative ledger chain or does not cover execution requests."
                    )
                    digest_errors += 1
            except Exception as e:
                issues.append(f"Audit ledger verification error: {e}")
                digest_errors += 1
        else:
            issues.append(
                f"Audit ledger is not available to authenticate checkpoint '{manifest.audit_ledger_checkpoint}'; failing closed."
            )
            digest_errors += 1

        if digest_errors == 0:
            digests_verified = True

        is_valid = len(issues) == 0

        return EvidenceValidationReport(
            is_valid=is_valid,
            checked_steps=checked_steps,
            issues=issues,
            canary_digest_matched=canary_digest_matched,
            negative_control_verified=negative_control_verified,
            digests_verified=digests_verified,
        )
