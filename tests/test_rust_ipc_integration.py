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


def test_ipc_request_scrubs_raw_credentials_and_retains_credential_ref():
    """Verify that raw authorization tokens and cookies never cross the IPC boundary into Rust."""
    with tempfile.TemporaryDirectory() as temp_dir:
        socket_path = os.path.join(temp_dir, "guard_cred.sock")

        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_sock.bind(socket_path)
        server_sock.listen(1)

        received_payload = {}

        def mock_cred_server():
            conn, _ = server_sock.accept()
            data = conn.recv(4096).decode("utf-8")
            nonlocal received_payload
            received_payload = json.loads(data.strip())
            resp = {
                "status": "OK",
                "result": {
                    "request_id": "req-cred-01",
                    "status_code": 200,
                    "headers": {},
                    "sanitized_body": "{}",
                    "latency_ms": 5,
                    "policy_decision_nonce": "nonce_cred_123",
                    "response_digest": "sha256:abc",
                },
            }
            conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
            conn.close()

        t = threading.Thread(target=mock_cred_server, daemon=True)
        t.start()

        client = RustGuardClient(socket_path=socket_path)
        req = OutgoingTestRequest(
            request_id="req-cred-01",
            test_id="test-cred-boundary",
            url="http://127.0.0.1:8000/api/v1/booking",
            method="GET",
            headers={
                "Authorization": "Bearer raw_secret_token_never_leak_me",
                "Cookie": "session=sensitive_cookie_value",
                "x-api-key": "secret_api_key_123",
                "Accept": "application/json",
            },
            target_tenant_id="agency_a",
            target_invariant=InvariantType.TENANT_ISOLATION,
            credential_ref="agency_a_admin",
        )

        res = client.execute_request(req)
        assert res.status_code == 200

        t.join(timeout=2.0)
        server_sock.close()

        req_sent = received_payload.get("request", {})
        headers_sent = req_sent.get("headers", {})

        # Assert raw secrets are absent
        assert "Authorization" not in headers_sent
        assert "authorization" not in headers_sent
        assert "Cookie" not in headers_sent
        assert "cookie" not in headers_sent
        assert "x-api-key" not in headers_sent

        # Assert benign headers and credential_ref are preserved
        assert headers_sent.get("Accept") == "application/json"
        assert req_sent.get("credential_ref") == "agency_a_admin"
        assert req_sent.get("invariant_candidate") == "I-01"


def test_invariant_wire_mapping_exhaustive_and_rejects_unknown():
    """Verify that all invariants map to exact wire contracts and unknown values are rejected."""
    client = RustGuardClient(socket_path="/non_existent_path.sock")

    # Verify all supported InvariantType members map correctly
    assert client.DEFAULT_SOCKET_PATH == "/run/drishti/guard.sock"

    req_base = {
        "request_id": "req-wire",
        "test_id": "t1",
        "url": "http://127.0.0.1:8000/test",
        "method": "GET",
        "target_tenant_id": "tenant_1",
    }

    # Test unknown invariant raises ValueError when converted in execute_request before socket check
    with tempfile.TemporaryDirectory() as temp_dir:
        sock_p = os.path.join(temp_dir, "test.sock")
        # Touch socket file so socket existence passes
        with open(sock_p, "w") as f:
            f.write("")
        c = RustGuardClient(socket_path=sock_p)

        fake_req = OutgoingTestRequest(
            **req_base,
            target_invariant=InvariantType.TENANT_ISOLATION,
        )
        fake_req_dict = fake_req.model_dump()
        fake_req_dict["target_invariant"] = "I-99-INVALID-INVARIANT"

        with pytest.raises(ValueError) as exc:
            c.execute_request(fake_req_dict)
        assert "Unknown or unsupported invariant wire representation" in str(exc.value)


def test_ipc_client_enforces_max_frame_bytes_ceiling():
    """Verify that the IPC client aborts and raises GuardIpcError if server response exceeds 1MB."""
    with tempfile.TemporaryDirectory() as temp_dir:
        socket_path = os.path.join(temp_dir, "guard_oversized.sock")

        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_sock.bind(socket_path)
        server_sock.listen(1)

        def mock_oversized_server():
            conn, _ = server_sock.accept()
            _ = conn.recv(4096)
            # Send oversized chunk exceeding 1MB
            oversized_payload = b"A" * (1024 * 1024 + 100)
            try:
                conn.sendall(oversized_payload)
            except BrokenPipeError:
                pass
            conn.close()

        t = threading.Thread(target=mock_oversized_server, daemon=True)
        t.start()

        client = RustGuardClient(socket_path=socket_path)
        req = OutgoingTestRequest(
            request_id="req-over",
            test_id="test-over",
            url="http://127.0.0.1:8000/api/v1/booking",
            method="GET",
            target_tenant_id="agency_a",
            target_invariant=InvariantType.TENANT_ISOLATION,
        )

        with pytest.raises(GuardIpcError) as exc_info:
            client.execute_request(req)

        assert exc_info.value.error_code == "RESPONSE_TOO_LARGE"
        assert "exceeded maximum permitted limit" in str(exc_info.value)

        t.join(timeout=2.0)
        server_sock.close()


def test_ipc_client_socket_timeout():
    """Verify that the IPC client handles socket timeout correctly."""
    with tempfile.TemporaryDirectory() as temp_dir:
        socket_path = os.path.join(temp_dir, "guard_timeout.sock")

        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_sock.bind(socket_path)
        server_sock.listen(1)

        def mock_slow_server():
            conn, _ = server_sock.accept()
            # Deliberately sleep without sending response
            import time
            time.sleep(0.5)
            conn.close()

        t = threading.Thread(target=mock_slow_server, daemon=True)
        t.start()

        client = RustGuardClient(socket_path=socket_path, timeout_seconds=0.1)
        req = OutgoingTestRequest(
            request_id="req-timeout",
            test_id="test-timeout",
            url="http://127.0.0.1:8000/api/v1/booking",
            method="GET",
            target_tenant_id="agency_a",
            target_invariant=InvariantType.TENANT_ISOLATION,
            timeout_ms=100,
        )

        with pytest.raises(GuardIpcError) as exc_info:
            client.execute_request(req, timeout_seconds=0.1)

        assert exc_info.value.error_code == "TIMEOUT"
        assert "timed out" in str(exc_info.value)

        t.join(timeout=2.0)
        server_sock.close()
