"""Tamper-evident cryptographic hash-chaining engine for audit events."""

import hashlib
import hmac
import json
from typing import Dict, Any, Optional

GENESIS_HASH = "0" * 64

def canonical_json(data: Dict[str, Any]) -> str:
    """Serializes dictionary to canonical JSON representation (deterministic key order, compact separators)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))

def sha256_digest(content: str | bytes) -> str:
    """Calculates SHA-256 hex digest."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()

class AuditEventNode:
    def __init__(
        self,
        sequence: int,
        event_id: str,
        timestamp: str,
        event_type: str,
        payload_digest: str,
        previous_hash: str,
        current_hash: Optional[str] = None
    ):
        self.sequence = sequence
        self.event_id = event_id
        self.timestamp = timestamp
        self.event_type = event_type
        self.payload_digest = payload_digest
        self.previous_hash = previous_hash
        self.current_hash = current_hash or self.compute_hash()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sequence": self.sequence,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "payload_digest": self.payload_digest,
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash
        }

    def compute_hash(self) -> str:
        """Computes current hash covering all integrity fields in canonical format."""
        canonical_payload = {
            "sequence": self.sequence,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "payload_digest": self.payload_digest,
            "previous_hash": self.previous_hash
        }
        return sha256_digest(canonical_json(canonical_payload))

class SignedCheckpoint:
    def __init__(
        self,
        checkpoint_id: str,
        sequence_covered: int,
        head_hash: str,
        timestamp: str,
        signature: str
    ):
        self.checkpoint_id = checkpoint_id
        self.sequence_covered = sequence_covered
        self.head_hash = head_hash
        self.timestamp = timestamp
        self.signature = signature

    @classmethod
    def create(
        cls,
        checkpoint_id: str,
        sequence_covered: int,
        head_hash: str,
        timestamp: str,
        secret_key: bytes
    ) -> "SignedCheckpoint":
        state_data = f"{checkpoint_id}:{sequence_covered}:{head_hash}:{timestamp}"
        sig = hmac.new(secret_key, state_data.encode("utf-8"), hashlib.sha256).hexdigest()
        return cls(checkpoint_id, sequence_covered, head_hash, timestamp, sig)

    def verify(self, secret_key: bytes) -> bool:
        state_data = f"{self.checkpoint_id}:{self.sequence_covered}:{self.head_hash}:{self.timestamp}"
        expected_sig = hmac.new(secret_key, state_data.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected_sig)
