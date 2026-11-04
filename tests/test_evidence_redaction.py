"""Adversarial tests for EvidenceStore automated redaction and size enforcement."""

import json
from pathlib import Path
from drishti.audit.evidence_store import EvidenceStore
from drishti.core.config import EvidenceConfig

def test_evidence_store_redacts_auth_headers_and_cookies(tmp_path):
    store = EvidenceStore(storage_dir=tmp_path / "evidence")
    raw_req = {
        "headers": {
            "Authorization": "Bearer secret_jwt_token_payload_xyz123",
            "Cookie": "session_id=secret_session_val_99; other=123"
        }
    }
    raw_resp = {"status": 200}
    evidence_file, digest = store.store_evidence("ev_1", raw_req, raw_resp)

    with open(evidence_file, "r") as f:
        content = f.read()

    assert "secret_jwt_token_payload_xyz123" not in content
    assert "[REDACTED_TOKEN]" in content
    assert "secret_session_val_99" not in content

def test_evidence_store_redacts_passwords_and_payment_cards(tmp_path):
    store = EvidenceStore(storage_dir=tmp_path / "evidence")
    raw_req = {
        "body": {
            "password": "SuperSecretPassword!",
            "card_number": "4111 2222 3333 4444"
        }
    }
    raw_resp = {"status": 200}
    evidence_file, digest = store.store_evidence("ev_2", raw_req, raw_resp)

    with open(evidence_file, "r") as f:
        content = f.read()

    assert "SuperSecretPassword!" not in content
    assert "[REDACTED_PASSWORD]" in content
    assert "4111 2222 3333 4444" not in content

def test_evidence_store_enforces_max_payload_size(tmp_path):
    config = EvidenceConfig(max_payload_size_bytes=200) # Small 200 byte limit
    store = EvidenceStore(storage_dir=tmp_path / "evidence", config=config)

    huge_req = {"data": "A" * 1000}
    evidence_file, digest = store.store_evidence("ev_huge", huge_req, {})

    with open(evidence_file, "r") as f:
        content = f.read()

    assert len(content.encode("utf-8")) <= 250
    assert "[TRUNCATED_AT_MAX_SIZE]" in content
