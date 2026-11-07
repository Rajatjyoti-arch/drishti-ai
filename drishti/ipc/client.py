"""Python IPC Client connecting the Intelligence Layer to the Rust Security Kernel.

Transmits typed OutgoingTestRequests over a local Unix Domain Socket (/run/drishti/guard.sock)
and receives sanitized ExecutionResults verified by the Rust PolicyGate.
"""

import json
import os
import socket
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, Optional

from drishti.core.exceptions import PolicyViolationError
from drishti.core.models import ExecutionResult, InvariantType, OutgoingTestRequest

# Strict IPC protocol boundaries
MAX_IPC_FRAME_BYTES = 1024 * 1024  # 1 Megabyte maximum frame limit
DEFAULT_IPC_TIMEOUT_SECONDS = 10.0

INVARIANT_WIRE_MAP: Dict[Any, str] = {
    InvariantType.TENANT_ISOLATION: "I-01",
    InvariantType.PRICING_INTEGRITY: "I-02",
    InvariantType.HOLD_EXPIRATION: "I-03",
    InvariantType.REFUND_IDEMPOTENCY: "I-04",
    "I-01-TENANT-ISOLATION": "I-01",
    "I-02-SERVER-AUTHORITATIVE-PRICING": "I-02",
    "I-03-PERISHABLE-HOLD-EXPIRATION": "I-03",
    "I-04-REFUND-BOUNDS-IDEMPOTENCY": "I-04",
    "I-01": "I-01",
    "I-02": "I-02",
    "I-03": "I-03",
    "I-04": "I-04",
}

SENSITIVE_AUTH_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "proxy-authorization",
}


class GuardIpcError(Exception):
    """Base error raised when communicating with the Rust Security Kernel."""

    def __init__(self, message: str, error_code: str = "IPC_ERROR"):
        super().__init__(message)
        self.error_code = error_code


class RustGuardClient:
    """Unix Domain Socket IPC client communicating with drishti-guard."""

    CURRENT_VERSION = "1.0"
    DEFAULT_SOCKET_PATH = "/run/drishti/guard.sock"

    def __init__(
        self,
        socket_path: Optional[str] = None,
        timeout_seconds: float = DEFAULT_IPC_TIMEOUT_SECONDS,
    ):
        self.socket_path = (
            socket_path
            or os.environ.get("DRISHTI_GUARD_SOCK")
            or self.DEFAULT_SOCKET_PATH
        )
        self.timeout_seconds = timeout_seconds

    def execute_request(
        self,
        request: OutgoingTestRequest,
        timeout_seconds: Optional[float] = None,
    ) -> ExecutionResult:
        """Transmits an OutgoingTestRequest to the Rust Guard and returns ExecutionResult.

        Enforces:
        1. Exhaustive invariant wire mapping (I-01 to I-04, rejects unknown).
        2. Absolute secret scrubbing: raw authorization headers are never transmitted over IPC.
        3. End-to-end response frame ceilings (1MB max).
        4. Socket read and write timeouts.

        Raises:
            GuardIpcError: If the socket connection fails, times out, or response is oversized.
            PolicyViolationError: If the Rust PolicyGate blocks or throttles the request.
            ValueError: If an unknown invariant is supplied.
        """
        if not os.path.exists(self.socket_path):
            raise GuardIpcError(
                f"Rust Guard socket not found at {self.socket_path}. Is drishti-guard running?",
                error_code="SOCKET_NOT_FOUND",
            )

        # Convert request to JSON serializable dictionary
        req_dict: Dict[str, Any]
        if hasattr(request, "model_dump"):
            req_dict = request.model_dump(exclude_none=True)
        elif is_dataclass(request):
            req_dict = asdict(request)
        else:
            req_dict = dict(request)

        # Normalize field names to match canonical Rust OutgoingTestRequest schema
        if "url" in req_dict and "target_url" not in req_dict:
            req_dict["target_url"] = req_dict.pop("url")

        # Map invariant to Rust wire contract using exhaustive mapping
        inv_key = req_dict.pop("target_invariant", None) or req_dict.get("invariant_candidate")
        if inv_key is not None:
            if inv_key in INVARIANT_WIRE_MAP:
                req_dict["invariant_candidate"] = INVARIANT_WIRE_MAP[inv_key]
            else:
                raise ValueError(
                    f"Unknown or unsupported invariant wire representation: '{inv_key}'. "
                    f"Must be one of {list(INVARIANT_WIRE_MAP.keys())}."
                )

        # Scrub raw credentials: secrets must NEVER cross the IPC boundary from Python into Rust.
        # Rust Guard resolves credentials internally via its own credential broker.
        if "headers" in req_dict and isinstance(req_dict["headers"], dict):
            req_dict["headers"] = {
                k: v
                for k, v in req_dict["headers"].items()
                if k.lower() not in SENSITIVE_AUTH_HEADERS
            }

        # Remove keys with None values to maintain clean canonical JSON
        req_dict = {k: v for k, v in req_dict.items() if v is not None}

        payload = {
            "version": self.CURRENT_VERSION,
            "request": req_dict,
        }

        serialized = json.dumps(payload) + "\n"

        # Determine effective socket timeout (respecting request budget if specified)
        effective_timeout = timeout_seconds or (
            req_dict.get("timeout_ms", 0) / 1000.0 if req_dict.get("timeout_ms") else self.timeout_seconds
        )
        if effective_timeout <= 0:
            effective_timeout = self.timeout_seconds

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(effective_timeout)
        try:
            sock.connect(self.socket_path)
            sock.sendall(serialized.encode("utf-8"))

            # Read response frame bounded by MAX_IPC_FRAME_BYTES
            response_data = b""
            while b"\n" not in response_data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                if len(response_data) > MAX_IPC_FRAME_BYTES:
                    raise GuardIpcError(
                        f"IPC response frame exceeded maximum permitted limit ({MAX_IPC_FRAME_BYTES} bytes)",
                        error_code="RESPONSE_TOO_LARGE",
                    )

            if not response_data:
                raise GuardIpcError("Empty response from Rust Guard socket", "EMPTY_RESPONSE")

            line = response_data.decode("utf-8").strip()
            resp_json = json.loads(line)

            status = resp_json.get("status")
            if status == "OK":
                raw_res = resp_json.get("result", {})
                return ExecutionResult(
                    request_id=raw_res.get("request_id", ""),
                    status_code=raw_res.get("status_code", 0),
                    headers=raw_res.get("headers", {}),
                    sanitized_body=raw_res.get("sanitized_body", ""),
                    latency_ms=raw_res.get("latency_ms", 0),
                    policy_decision_nonce=raw_res.get("policy_decision_nonce", ""),
                    response_digest=raw_res.get("response_digest", ""),
                )
            else:
                error_code = resp_json.get("error_code", "UNKNOWN_ERROR")
                message = resp_json.get("message", "Policy violation")
                raise PolicyViolationError(f"[{error_code}] {message}")

        except socket.timeout as e:
            raise GuardIpcError(
                f"IPC request timed out after {effective_timeout:.2f}s: {e}",
                error_code="TIMEOUT",
            ) from e
        except socket.error as e:
            raise GuardIpcError(f"Socket I/O error connecting to Rust Guard: {e}", "SOCKET_IO") from e
        finally:
            sock.close()
