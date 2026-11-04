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
from drishti.core.models import ExecutionResult, OutgoingTestRequest


class GuardIpcError(Exception):
    """Base error raised when communicating with the Rust Security Kernel."""

    def __init__(self, message: str, error_code: str = "IPC_ERROR"):
        super().__init__(message)
        self.error_code = error_code


class RustGuardClient:
    """Unix Domain Socket IPC client communicating with drishti-guard."""

    CURRENT_VERSION = "1.0"
    DEFAULT_SOCKET_PATH = "/run/drishti/guard.sock"

    def __init__(self, socket_path: Optional[str] = None):
        self.socket_path = (
            socket_path
            or os.environ.get("DRISHTI_GUARD_SOCK")
            or self.DEFAULT_SOCKET_PATH
        )

    def execute_request(self, request: OutgoingTestRequest) -> ExecutionResult:
        """Transmits an OutgoingTestRequest to the Rust Guard and returns ExecutionResult.

        Raises:
            GuardIpcError: If the socket connection fails or the payload is invalid.
            PolicyViolationError: If the Rust PolicyGate blocks or throttles the request.
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
        if "target_invariant" in req_dict and "invariant_candidate" not in req_dict:
            inv = str(req_dict.pop("target_invariant"))
            req_dict["invariant_candidate"] = "I-01" if "01" in inv else "I-02"

        # Remove keys with None values to maintain clean canonical JSON
        req_dict = {k: v for k, v in req_dict.items() if v is not None}

        payload = {
            "version": self.CURRENT_VERSION,
            "request": req_dict,
        }

        serialized = json.dumps(payload) + "\n"

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(self.socket_path)
            sock.sendall(serialized.encode("utf-8"))

            # Read response frame
            response_data = b""
            while b"\n" not in response_data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk

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

        except socket.error as e:
            raise GuardIpcError(f"Socket I/O error connecting to Rust Guard: {e}", "SOCKET_IO")
        finally:
            sock.close()
