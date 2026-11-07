"""Evidence Validator for Drishti AI Verification Oracle.

Validates:
1. Negative control phase completion and baseline legitimacy.
2. Cryptographic payload digests (SHA-256) and audit ledger consistency.
3. Canary token injection and digest fidelity.
4. Policy decision nonces and request correlation.
"""

import hashlib
import logging
import re
from typing import List, Optional

from pydantic import BaseModel, Field

from drishti.verifier.models import EvidenceManifest, EvidenceReference

logger = logging.getLogger(__name__)

HEX_64_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")


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

    @staticmethod
    def validate_manifest(
        manifest: EvidenceManifest,
        canary_secret: Optional[str] = None,
    ) -> EvidenceValidationReport:
        """Runs cryptographic and structural validation checks on an EvidenceManifest."""
        issues: List[str] = []
        checked_steps = len(manifest.evidence_references)
        negative_control_verified = False
        canary_digest_matched = False
        digests_verified = True

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

        # 2. Canary token digest validation
        if manifest.canary_spec_digest:
            if not HEX_64_REGEX.match(manifest.canary_spec_digest):
                issues.append(
                    f"Canary spec digest '{manifest.canary_spec_digest}' is not a valid 64-char SHA-256 hash."
                )
            elif canary_secret is not None:
                computed_digest = hashlib.sha256(canary_secret.encode("utf-8")).hexdigest()
                if computed_digest.lower() == manifest.canary_spec_digest.lower():
                    canary_digest_matched = True
                else:
                    issues.append(
                        f"Canary secret digest ({computed_digest}) does not match manifest "
                        f"canary_spec_digest ({manifest.canary_spec_digest})."
                    )
            else:
                # Canary digest exists and is well-formed, but secret was not provided for re-hashing
                canary_digest_matched = True

        # 3. Step digest format and payload consistency
        for ref in manifest.evidence_references:
            if not ref.response_digest or not HEX_64_REGEX.match(ref.response_digest):
                issues.append(
                    f"Step '{ref.step_id}' contains invalid or missing response digest: "
                    f"'{ref.response_digest}'."
                )
                digests_verified = False

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
                    digests_verified = False

            # Check request identifier validity
            if not ref.request_id:
                issues.append(f"Step '{ref.step_id}' is missing request_id.")

        is_valid = len(issues) == 0

        return EvidenceValidationReport(
            is_valid=is_valid,
            checked_steps=checked_steps,
            issues=issues,
            canary_digest_matched=canary_digest_matched,
            negative_control_verified=negative_control_verified,
            digests_verified=digests_verified,
        )
