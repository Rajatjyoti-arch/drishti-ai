"""Transport abstractions enforcing zero-unmediated-socket architecture for Drishti AI.

Delegates 100% of outbound target networking to the Rust Security Kernel via Unix Domain Socket IPC,
or routes test requests directly into in-process ASGI test fixtures without opening sockets.
"""

import asyncio
from typing import Any, Optional
import httpx

from drishti.core.exceptions import PolicyViolationError
from drishti.core.models import InvariantType, OutgoingTestRequest
from drishti.ipc.client import GuardIpcError, RustGuardClient


class RustGuardTransport(httpx.AsyncBaseTransport):
    """Production and staging transport delegating outbound socket execution to drishti-guard over UDS."""

    def __init__(self, socket_path: Optional[str] = None):
        self.ipc_client = RustGuardClient(socket_path=socket_path)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Translates httpx.Request into OutgoingTestRequest and delegates execution to Rust Guard."""
        headers_dict = dict(request.headers)
        body = request.read()
        body_str = body.decode("utf-8") if body else None

        target_tenant = headers_dict.pop("x-drishti-target-tenant", "default")
        inv_str = headers_dict.pop("x-drishti-target-invariant", InvariantType.TENANT_ISOLATION.value)
        test_id = headers_dict.pop("x-drishti-test-id", "test_default")
        cred_ref = headers_dict.pop("x-drishti-credential-ref", None)

        try:
            inv_type = InvariantType(inv_str)
        except Exception:
            inv_type = InvariantType.TENANT_ISOLATION

        outgoing = OutgoingTestRequest(
            method=request.method,
            url=str(request.url),
            headers=headers_dict,
            body=body_str,
            target_tenant_id=target_tenant,
            target_invariant=inv_type,
            credential_ref=cred_ref,
            test_id=test_id,
        )

        try:
            exec_res = await asyncio.to_thread(self.ipc_client.execute_request, outgoing)
            return httpx.Response(
                status_code=exec_res.status_code,
                headers=exec_res.headers,
                content=exec_res.sanitized_body.encode("utf-8"),
                request=request,
            )
        except GuardIpcError as gie:
            raise PolicyViolationError(f"Rust Guard IPC transport error: {gie}") from gie


class InProcessFixtureTransport(httpx.ASGITransport):
    """Test-only transport mediating requests to in-process ASGI test fixtures without opening network sockets."""

    def __init__(self, app: Any, raise_app_exceptions: bool = False):
        super().__init__(app=app, raise_app_exceptions=raise_app_exceptions)
