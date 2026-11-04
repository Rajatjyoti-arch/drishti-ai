"""Adversarial tests verifying the tamper-evident audit ledger and cryptographic hash chain."""

import os
import pytest
from pathlib import Path
from drishti.audit.ledger import TamperEvidentLedger
from drishti.audit.ledger_verifier import LedgerVerifier
from drishti.audit.hash_chain import AuditEventNode

@pytest.fixture
def temp_ledger(tmp_path):
    db_file = tmp_path / "test_audit.db"
    return TamperEvidentLedger(db_path=db_file)

def test_tamper_evident_ledger_records_and_verifies_intact_chain(temp_ledger):
    temp_ledger.record_event("evt_1", "REQUEST_ALLOW", "digest_1")
    temp_ledger.record_event("evt_2", "REQUEST_ALLOW", "digest_2")
    temp_ledger.record_event("evt_3", "REQUEST_DENY", "digest_3")

    events = temp_ledger.get_all_events()
    assert len(events) == 3

    is_valid, msg = LedgerVerifier.verify_chain(events)
    assert is_valid is True, msg

def test_ledger_detects_payload_modification(temp_ledger):
    temp_ledger.record_event("evt_1", "REQUEST_ALLOW", "digest_1")
    temp_ledger.record_event("evt_2", "REQUEST_ALLOW", "digest_2")

    events = temp_ledger.get_all_events()
    # Attacker alters payload digest of event 0 without updating current_hash
    tampered_event = AuditEventNode(
        sequence=events[0].sequence,
        event_id=events[0].event_id,
        timestamp=events[0].timestamp,
        event_type=events[0].event_type,
        payload_digest="tampered_unauthorized_digest",
        previous_hash=events[0].previous_hash,
        current_hash=events[0].current_hash
    )
    tampered_chain = [tampered_event, events[1]]

    is_valid, msg = LedgerVerifier.verify_chain(tampered_chain)
    assert is_valid is False
    assert "Hash integrity failed" in msg

def test_ledger_detects_event_deletion(temp_ledger):
    temp_ledger.record_event("evt_1", "REQUEST_ALLOW", "digest_1")
    temp_ledger.record_event("evt_2", "REQUEST_ALLOW", "digest_2")
    temp_ledger.record_event("evt_3", "REQUEST_ALLOW", "digest_3")

    events = temp_ledger.get_all_events()
    # Attacker deletes event 1
    tampered_chain = [events[0], events[2]]

    is_valid, msg = LedgerVerifier.verify_chain(tampered_chain)
    assert is_valid is False
    assert "Sequence discontinuity" in msg

def test_ledger_detects_event_reordering(temp_ledger):
    temp_ledger.record_event("evt_1", "REQUEST_ALLOW", "digest_1")
    temp_ledger.record_event("evt_2", "REQUEST_ALLOW", "digest_2")

    events = temp_ledger.get_all_events()
    # Swap order
    tampered_chain = [events[1], events[0]]

    is_valid, msg = LedgerVerifier.verify_chain(tampered_chain)
    assert is_valid is False

def test_signed_checkpoints_verification(temp_ledger):
    secret_key = b"super_secret_audit_checkpoint_key"
    temp_ledger.record_event("evt_1", "POLICY_ALLOW", "digest_1")
    temp_ledger.record_event("evt_2", "POLICY_DENY", "digest_2")

    cp = temp_ledger.create_checkpoint("cp_1", secret_key)
    events = temp_ledger.get_all_events()

    # Valid checkpoint check
    is_valid, msg = LedgerVerifier.verify_checkpoint(cp, events[-1], secret_key)
    assert is_valid is True, msg

    # Invalid secret key check
    wrong_key = b"wrong_signing_key"
    is_valid, msg = LedgerVerifier.verify_checkpoint(cp, events[-1], wrong_key)
    assert is_valid is False
