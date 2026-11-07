"""Safe HTTP transport client strictly enforced by the Policy Gate.

Outbound sockets are owned exclusively by drishti-guard (via RustGuardTransport)
or in-process ASGI fixtures (via InProcessFixtureTransport).
Direct Python network egress is strictly forbidden.
"""

import time
from urllib.parse import urlparse
from typing import Dict, Any, Optional
import httpx

from drishti.core.models import OutgoingTestRequest, PolicyAction
from drishti.core.exceptions import BudgetExhaustedError, PolicyViolationError
from drishti.policy.gate import PolicyGate
from drishti.audit.evidence_store import EvidenceStore
from drishti.policy.transports import InProcessFixtureTransport, RustGuardTransport


class SafeHttpClient:
    """The only authorized HTTP transport interface.

    Every single outbound network call must pass through the Policy Gate.
    Direct Python network socket creation is prohibited.
    """
    def __init__(
        self,
        policy_gate: PolicyGate,
        evidence_store: Optional[EvidenceStore] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ):
        self.policy_gate = policy_gate
        self.evidence_store = evidence_store or EvidenceStore()

        # Enforce authorized transport: strictly forbid direct unmediated Python network sockets
        if transport is None:
            self.transport: httpx.AsyncBaseTransport = RustGuardTransport()
        elif isinstance(transport, (RustGuardTransport, InProcessFixtureTransport, httpx.ASGITransport)):
            self.transport = transport
        else:
            raise RuntimeError(
                f"Direct Python network transport is prohibited. "
                f"Transport must be an instance of RustGuardTransport or InProcessFixtureTransport, "
                f"got {type(transport).__name__}."
            )

    async def send_request(
        self,
        request: OutgoingTestRequest,
        approval_token: Optional[str] = None,
        max_response_size_bytes: Optional[int] = None,
    ) -> httpx.Response:
        """Executes a policy-governed network request:

        1. Authorizes via PolicyGate.
        2. Injects scoped credentials at transport boundary.
        3. Validates redirects through EgressGuard.
        4. Executes via RustGuardTransport or InProcessFixtureTransport.
        5. Enforces streaming byte ceiling to prevent memory buffering of oversized payloads.
        6. Records health telemetry and stores sanitized evidence.
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

        # Propagate metadata headers for Rust Guard IPC
        headers["x-drishti-target-tenant"] = request.target_tenant_id
        headers["x-drishti-target-invariant"] = request.target_invariant.value
        headers["x-drishti-test-id"] = request.test_id
        if request.credential_ref:
            headers["x-drishti-credential-ref"] = request.credential_ref

        # 3. Guarded Transport Execution (using streaming byte ceiling to prevent memory buffering)
        start_time = time.monotonic()
        timeout = httpx.Timeout(self.policy_gate.budgets.execution.timeout_seconds)

        client_kwargs: Dict[str, Any] = {
            "timeout": timeout,
            "follow_redirects": False,
            "transport": self.transport,
        }

        async with httpx.AsyncClient(**client_kwargs) as client:
            try:
                async with client.stream(
                    method=request.method,
                    url=request.url,
                    headers=headers,
                    json=request.body if isinstance(request.body, dict) else None,
                    content=request.body if isinstance(request.body, (str, bytes)) else None,
                ) as stream_resp:
                    chunks = []
                    total_bytes = 0
                    max_bytes = max_response_size_bytes or 65536

                    async for chunk in stream_resp.aiter_bytes():
                        total_bytes += len(chunk)
                        if total_bytes > max_bytes:
                            await stream_resp.aclose()
                            raise BudgetExhaustedError(
                                f"Response size exceeded streaming byte ceiling of {max_bytes} bytes "
                                f"(download aborted at {total_bytes} bytes)."
                            )
                        chunks.append(chunk)

                    body_bytes = b"".join(chunks)
                    response = httpx.Response(
                        status_code=stream_resp.status_code,
                        headers=stream_resp.headers,
                        content=body_bytes,
                        request=stream_resp.request,
                    )
            except BudgetExhaustedError:
                raise
            except Exception as e:
                self.policy_gate.health_monitor.record_telemetry(9999.0, 500)
                raise PolicyViolationError(f"Network transport error connecting to '{request.url}': {e}")

        latency_ms = (time.monotonic() - start_time) * 1000

        # 4. Telemetry and Evidence Recording
        self.policy_gate.health_monitor.record_telemetry(latency_ms, response.status_code)
        self.evidence_store.record_evidence(
            request=request,
            decision=decision,
            response_code=response.status_code,
            response_body=response.text[:2000] if response.text else ""
        )

        return response
