"""Safe HTTP transport client strictly enforced by the Policy Gate."""

import time
from urllib.parse import urlparse
import httpx
from typing import Dict, Any, Optional
from drishti.core.models import OutgoingTestRequest, PolicyAction
from drishti.core.exceptions import PolicyViolationError
from drishti.policy.gate import PolicyGate
from drishti.audit.evidence_store import EvidenceStore

class SafeHttpClient:
    """
    The only authorized HTTP transport interface.
    Every single outbound network call must pass through the Policy Gate.
    """
    def __init__(
        self,
        policy_gate: PolicyGate,
        evidence_store: Optional[EvidenceStore] = None
    ):
        self.policy_gate = policy_gate
        self.evidence_store = evidence_store or EvidenceStore()

    async def send_request(
        self,
        request: OutgoingTestRequest,
        approval_token: Optional[str] = None
    ) -> httpx.Response:
        """
        Executes a policy-governed network request:
        1. Authorizes via PolicyGate.
        2. Injects scoped credentials at transport boundary.
        3. Validates redirects through EgressGuard.
        4. Records health telemetry and stores sanitized evidence.
        """
        # 1. Policy Gate Evaluation
        decision = await self.policy_gate.evaluate_request(request, approval_token=approval_token)
        if decision.action != PolicyAction.ALLOW:
            raise PolicyViolationError(
                f"Transport request REJECTED by Policy Gate [{decision.action.value}]: {decision.reason}"
            )

        # 2. Credential Resolution at Transport Boundary
        headers = dict(request.headers)
        parsed = urlparse(request.url)
        host = parsed.hostname or ""

        if request.credential_ref:
            scoped_cred = self.policy_gate.credential_broker.get_credential(
                credential_ref=request.credential_ref,
                target_hostname=host,
                purpose=f"verify_{request.target_invariant.value}"
            )
            headers[scoped_cred.auth_header_key] = scoped_cred.auth_header_value

        # 3. Network Transport Execution
        start_time = time.monotonic()
        timeout = httpx.Timeout(self.policy_gate.budgets.execution.timeout_seconds)

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            try:
                response = await client.request(
                    method=request.method,
                    url=request.url,
                    headers=headers,
                    json=request.body if isinstance(request.body, dict) else None,
                    content=request.body if isinstance(request.body, (str, bytes)) else None
                )
            except Exception as e:
                # Record telemetry on connection failure
                self.policy_gate.health_monitor.record_telemetry(9999.0, 500)
                raise PolicyViolationError(f"Network transport error connecting to '{request.url}': {e}")

            latency_ms = (time.monotonic() - start_time) * 1000.0

            # 4. Handle Redirects through Egress Guard
            if response.is_redirect and "location" in response.headers:
                redirect_url = self.policy_gate.egress_guard.validate_redirect(
                    request.url, response.headers["location"]
                )
                # Redirect validated as in-scope; follow 1-hop
                response = await client.request(
                    method="GET",
                    url=redirect_url,
                    headers=headers
                )

        # 5. Record Health Telemetry
        self.policy_gate.health_monitor.record_telemetry(latency_ms, response.status_code)

        # 6. Store Sanitized Evidence
        evidence_file, digest = self.evidence_store.store_evidence(
            evidence_id=request.request_id,
            request_data={"method": request.method, "url": request.url, "headers": headers, "body": request.body},
            response_data={"status_code": response.status_code, "headers": dict(response.headers), "text": response.text}
        )

        return response
