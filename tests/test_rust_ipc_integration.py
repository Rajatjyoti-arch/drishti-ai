"""Integration tests for the Python IPC Client communicating with drishti-guard."""

import json
import os
import socket
import tempfile
import threading
import pytest

from drishti.core.exceptions import PolicyViolationError
from drishti.core.models import InvariantType, OutgoingTestRequest
from drishti.ipc.client import GuardIpcError, RustGuardClient


def test_missing_socket_raises_guard_ipc_error():
    client = RustGuardClient(socket_path="/tmp/non_existent_guard_12345.sock")
    req = OutgoingTestRequest(
        request_id="req-1",
        test_id="t1",
        url="http://127.0.0.1:8000/api/v1/test",
        method="GET",
        target_tenant_id="agency_a",
        target_invariant=InvariantType.TENANT_ISOLATION,
    )
    with pytest.raises(GuardIpcError) as exc_info:
        client.execute_request(req)
    assert exc_info.value.error_code == "SOCKET_NOT_FOUND"


def test_python_to_rust_ipc_protocol_roundtrip():
    """Simulates the Unix socket server behaving according to drishti-guard IPC specification."""
    with tempfile.TemporaryDirectory() as temp_dir:
        socket_path = os.path.join(temp_dir, "guard_test.sock")

        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_sock.bind(socket_path)
        server_sock.listen(1)

        def mock_guard_server():
            conn, _ = server_sock.accept()
            data = conn.recv(4096).decode("utf-8")
            cmd = json.loads(data.strip())

            # Verify that client sent version 1.0 and well-formed request
            assert cmd.get("version") == "1.0"
            req = cmd.get("request", {})
            assert req.get("request_id") == "req-py-01"
            assert req.get("target_url") == "http://127.0.0.1:8000/api/v1/booking"

            # Return success response matching Rust ExecutionResult format
            resp = {
                "status": "OK",
                "result": {
                    "request_id": "req-py-01",
                    "status_code": 200,
                    "headers": {"content-type": "application/json"},
                    "sanitized_body": "{\"authenticated\": true}",
                    "latency_ms": 12,
                    "policy_decision_nonce": "nonce_test_abc123",
                    "response_digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                },
            }
            conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
            conn.close()

        server_thread = threading.Thread(target=mock_guard_server, daemon=True)
        server_thread.start()

        client = RustGuardClient(socket_path=socket_path)
        req = OutgoingTestRequest(
            request_id="req-py-01",
            test_id="test-ipc-01",
            url="http://127.0.0.1:8000/api/v1/booking",
            method="GET",
            target_tenant_id="agency_a",
            target_invariant=InvariantType.TENANT_ISOLATION,
        )

        result = client.execute_request(req)
        assert result.request_id == "req-py-01"
        assert result.status_code == 200
        assert result.policy_decision_nonce == "nonce_test_abc123"

        server_thread.join(timeout=2.0)
        server_sock.close()


def test_python_client_propagates_policy_violation_error():
    with tempfile.TemporaryDirectory() as temp_dir:
        socket_path = os.path.join(temp_dir, "guard_err.sock")

        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_sock.bind(socket_path)
        server_sock.listen(1)

        def mock_error_server():
            conn, _ = server_sock.accept()
            _ = conn.recv(4096)
            err_resp = {
                "status": "ERROR",
                "error_code": "SCOPE_VIOLATION",
                "message": "Target domain 'unauthorized-site.com' not permitted by policy allowlist",
            }
            conn.sendall((json.dumps(err_resp) + "\n").encode("utf-8"))
            conn.close()

        t = threading.Thread(target=mock_error_server, daemon=True)
        t.start()

        client = RustGuardClient(socket_path=socket_path)
        req = OutgoingTestRequest(
            request_id="req-py-err",
            test_id="test-scope-01",
            url="http://unauthorized-site.com",
            method="GET",
            target_tenant_id="agency_a",
            target_invariant=InvariantType.TENANT_ISOLATION,
        )

        with pytest.raises(PolicyViolationError) as exc_info:
            client.execute_request(req)

        assert "SCOPE_VIOLATION" in str(exc_info.value)
        assert "unauthorized-site.com" in str(exc_info.value)

        t.join(timeout=2.0)
        server_sock.close()
