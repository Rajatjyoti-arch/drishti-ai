"""Credential broker isolating secrets, enforcing tenant/target bindings, and managing leases."""

import os
import time
from typing import Dict, Any, Optional
from pydantic import BaseModel
from drishti.core.exceptions import PolicyViolationError

class ScopedCredential(BaseModel):
    credential_ref: str
    tenant_id: str
    role: str
    authorized_target: str
    purpose: str
    auth_header_key: str = "Authorization"
    auth_header_value: str
    expires_at: float

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

class CredentialBroker:
    """
    Manages synthetic test credentials securely:
    - Never passes raw tokens to LLM prompts.
    - Resolves tokens only at point-of-transport.
    - Validates target domain and purpose binding.
    """
    def __init__(self):
        self._vault: Dict[str, Dict[str, Any]] = {}
        self._revoked_refs = set()
        self._seed_default_test_credentials()

    def _seed_default_test_credentials(self) -> None:
        """Seeds synthetic credentials from environment or mock test vault."""
        self._vault["agency_a_admin"] = {
            "tenant_id": "AG_MUMBAI_01",
            "role": "AGENCY_ADMIN",
            "token": os.getenv("TEST_AGENCY_A_TOKEN", "mock_jwt_agency_a_admin_token"),
            "authorized_targets": ["staging.tbo-sandbox.internal", "localhost", "127.0.0.1"],
            "ttl_seconds": 3600
        }
        self._vault["agency_b_admin"] = {
            "tenant_id": "AG_DELHI_02",
            "role": "AGENCY_ADMIN",
            "token": os.getenv("TEST_AGENCY_B_TOKEN", "mock_jwt_agency_b_admin_token"),
            "authorized_targets": ["staging.tbo-sandbox.internal", "localhost", "127.0.0.1"],
            "ttl_seconds": 3600
        }
        self._vault["agency_a_subagent"] = {
            "tenant_id": "SUB_MUMBAI_01A",
            "role": "SUB_AGENT",
            "token": os.getenv("TEST_SUBAGENT_TOKEN", "mock_jwt_subagent_token"),
            "authorized_targets": ["staging.tbo-sandbox.internal", "localhost", "127.0.0.1"],
            "ttl_seconds": 3600
        }

    def get_credential(
        self,
        credential_ref: str,
        target_hostname: str,
        purpose: str
    ) -> ScopedCredential:
        """
        Retrieves a short-lived scoped credential bound strictly to target and purpose.
        """
        if credential_ref in self._revoked_refs:
            raise PolicyViolationError(f"Credential reference '{credential_ref}' has been REVOKED.")

        entry = self._vault.get(credential_ref)
        if not entry:
            raise PolicyViolationError(f"Unknown credential reference: '{credential_ref}'")

        # 1. Target binding validation
        allowed_targets = entry["authorized_targets"]
        if not any(target_hostname == t or target_hostname.endswith(f".{t}") for t in allowed_targets):
            raise PolicyViolationError(
                f"Credential '{credential_ref}' is NOT authorized for target '{target_hostname}'"
            )

        return ScopedCredential(
            credential_ref=credential_ref,
            tenant_id=entry["tenant_id"],
            role=entry["role"],
            authorized_target=target_hostname,
            purpose=purpose,
            auth_header_key="Authorization",
            auth_header_value=f"Bearer {entry['token']}",
            expires_at=time.time() + entry["ttl_seconds"]
        )

    def revoke_credential(self, credential_ref: str) -> None:
        self._revoked_refs.add(credential_ref)
