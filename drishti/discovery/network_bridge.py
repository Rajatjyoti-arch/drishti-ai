"""Network Bridge mediating Playwright browser traffic through the Rust Security Kernel.

Enforces request-level policy mediation: Playwright route requests are intercepted,
validated against the ScopeValidator, forwarded to the Rust Guard (or policy client),
and fulfilled with the sanitized response. If Guard enforcement fails or destination
is out-of-scope, navigation fails closed (aborted) and is never permitted to connect
directly via Chromium sockets.
"""

import json
import logging
import re
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from drishti.audit.hash_chain import sha256_digest
from drishti.audit.ledger import TamperEvidentLedger
from drishti.core.exceptions import OutOfScopeError, PolicyViolationError
from drishti.core.models import ExecutionResult, InvariantType, OutgoingTestRequest
from drishti.discovery.crawler_models import BrowserObservation, RoleContext
from drishti.ipc.client import GuardIpcError, RustGuardClient
from drishti.policy.scope_validator import ScopeValidator

logger = logging.getLogger(__name__)

# Sensitive header keys to redact from observation storage
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "token",
    "session",
    "proxy-authorization",
}

# Regex to scrub embedded credentials from URLs
RE_EMBEDDED_URL_CREDS = re.compile(r"://([^:@\s]+):([^@\s]+)@")


def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Redacts values of sensitive auth headers while preserving header names."""
    sanitized = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            sanitized[k] = "[REDACTED]"
        else:
            sanitized[k] = v
    return sanitized


class NetworkBridge:
    """Mediates Playwright browser network traffic through the Rust Guard kernel.

    Operates fail-closed: If the Guard rejects the request or is unreachable,
    the route is aborted with 'blockedbyclient'.
    """

    def __init__(
        self,
        scope_validator: ScopeValidator,
        guard_client: Optional[RustGuardClient] = None,
        custom_executor: Optional[Callable[[OutgoingTestRequest], ExecutionResult]] = None,
        ledger: Optional[TamperEvidentLedger] = None,
    ):
        self.scope_validator = scope_validator
        self.guard_client = guard_client
        self.custom_executor = custom_executor
        self.ledger = ledger
        self.observations: List[BrowserObservation] = []

    def clear_observations(self) -> None:
        """Resets the recorded observation list."""
        self.observations.clear()

    async def handle_route(
        self,
        route: Any,
        request: Any,
        role_context: RoleContext,
        session_id: str,
        journey_step_id: Optional[str] = None,
    ) -> None:
        """Playwright route interception handler:

        1. Validates destination scope (fails closed on SSRF / forbidden hosts).
        2. Constructs OutgoingTestRequest with role/tenant context.
        3. Executes request through Rust Guard (or custom executor).
        4. Fulfills browser route with sanitized response.
        5. Records sanitized, role-attributed BrowserObservation.
        """
        raw_url = request.url
        method = request.method.upper()

        # 1. Strict Scope Validation
        try:
            self.scope_validator.validate_url(raw_url)
        except (OutOfScopeError, Exception) as e:
            logger.warning(f"BrowserGuard blocked out-of-scope navigation to {raw_url}: {e}")
            if self.ledger:
                digest = sha256_digest(f"BROWSER_DENY:{method}:{raw_url}")
                self.ledger.record_event(
                    event_id=f"browser_abort_{hash(raw_url) & 0xFFFFFFFF:x}",
                    event_type="BROWSER_POLICY_DENY",
                    payload_digest=digest,
                    metadata={"url": raw_url, "reason": str(e), "role": role_context.role_identifier},
                )
            await route.abort("blockedbyclient")
            return

        # 2. Extract and sanitize request details
        req_headers = dict(request.headers)
        post_data = request.post_data

        # Merge role auth headers into outbound request
        for k, v in role_context.auth_headers.items():
            req_headers[k] = v

        outgoing_req = OutgoingTestRequest(
            target_tenant_id=role_context.tenant_id,
            url=raw_url,
            method=method,
            headers=req_headers,
            body=post_data,
            target_invariant=InvariantType.TENANT_ISOLATION,
        )

        # 3. Execute via Rust Guard or executor (Fail-Closed)
        exec_result: Optional[ExecutionResult] = None
        try:
            if self.custom_executor:
                exec_result = self.custom_executor(outgoing_req)
            elif self.guard_client:
                exec_result = self.guard_client.execute_request(outgoing_req)
            else:
                # No execution path configured -> fail closed!
                logger.error("No Guard client or executor configured in NetworkBridge. Aborting.")
                await route.abort("blockedbyclient")
                return
        except (GuardIpcError, PolicyViolationError, Exception) as e:
            logger.error(f"Guard execution failed for {method} {raw_url}: {e}")
            if self.ledger:
                digest = sha256_digest(f"GUARD_EXEC_ERROR:{method}:{raw_url}")
                self.ledger.record_event(
                    event_id=f"guard_err_{hash(raw_url) & 0xFFFFFFFF:x}",
                    event_type="GUARD_EXECUTION_FAILURE",
                    payload_digest=digest,
                    metadata={"url": raw_url, "error": str(e)},
                )
            await route.abort("blockedbyclient")
            return

        if not exec_result:
            await route.abort("blockedbyclient")
            return

        # 4. Filter response headers for browser fulfillment
        # Remove hop-by-hop headers and transfer-encoding which can conflict with Playwright fulfill
        filtered_headers = {}
        excluded_resp_headers = {
            "transfer-encoding",
            "content-encoding",
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "upgrade",
        }
        for hk, hv in exec_result.headers.items():
            if hk.lower() not in excluded_resp_headers:
                filtered_headers[hk] = hv

        # 5. Fulfill browser request with the Guard's verified response
        try:
            body_bytes = (
                exec_result.sanitized_body.encode("utf-8")
                if isinstance(exec_result.sanitized_body, str)
                else (exec_result.sanitized_body or b"")
            )
            await route.fulfill(
                status=exec_result.status_code,
                headers=filtered_headers,
                body=body_bytes,
            )
        except Exception as e:
            logger.warning(f"Error fulfilling route {raw_url}: {e}")
            await route.abort("failed")
            return

        # 6. Record role-attributed, sanitized observation
        observation = BrowserObservation(
            observation_id=exec_result.request_id or f"OBS-{hash(raw_url + str(exec_result.status_code)) & 0xFFFFFFFF:x}",
            session_id=session_id,
            role_name=role_context.role_name,
            tenant_id=role_context.tenant_id,
            journey_step_id=journey_step_id,
            method=method,
            url=RE_EMBEDDED_URL_CREDS.sub("://[REDACTED]@", raw_url),
            status_code=exec_result.status_code,
            request_headers=sanitize_headers(req_headers),
            request_body=post_data[:500] if post_data else None,
            response_headers=sanitize_headers(exec_result.headers),
            response_body=exec_result.sanitized_body[:1000] if exec_result.sanitized_body else None,
            latency_ms=exec_result.latency_ms,
            guard_mediated=True,
        )
        self.observations.append(observation)
