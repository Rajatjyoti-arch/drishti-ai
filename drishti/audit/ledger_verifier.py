"""Independent verifier for tamper-evident audit ledger and checkpoint chains."""

from typing import List, Tuple, Optional
from drishti.audit.hash_chain import AuditEventNode, SignedCheckpoint, GENESIS_HASH

class LedgerVerifier:
    """
    Independently validates the cryptographic integrity of the audit chain:
    - Verifies monotonic sequence numbers.
    - Verifies genesis anchoring.
    - Recomputes SHA-256 hashes for every node.
    - Detects any insertion, deletion, reordering, or payload modification.
    - Verifies signed checkpoints.
    """
    @staticmethod
    def verify_chain(events: List[AuditEventNode]) -> Tuple[bool, str]:
        if not events:
            return True, "Audit ledger is empty (clean state)"

        expected_prev_hash = GENESIS_HASH

        for idx, event in enumerate(events):
            # 1. Monotonic sequence verification
            if event.sequence != idx:
                return (
                    False,
                    f"Sequence discontinuity at index {idx}: expected sequence {idx}, found {event.sequence} (possible event deletion or insertion)"
                )

            # 2. Previous hash link verification
            if event.previous_hash != expected_prev_hash:
                return (
                    False,
                    f"Hash link broken at sequence {event.sequence}: expected prev_hash '{expected_prev_hash}', found '{event.previous_hash}' (tampering detected)"
                )

            # 3. Current hash recomputation & verification
            recomputed_hash = event.compute_hash()
            if event.current_hash != recomputed_hash:
                return (
                    False,
                    f"Hash integrity failed at sequence {event.sequence}: recomputed '{recomputed_hash}' != stored '{event.current_hash}' (payload or metadata modified)"
                )

            expected_prev_hash = event.current_hash

        return True, f"Verified all {len(events)} events: audit chain is intact and valid"

    @staticmethod
    def verify_checkpoint(
        checkpoint: SignedCheckpoint,
        head_event: AuditEventNode,
        secret_key: bytes
    ) -> Tuple[bool, str]:
        if not checkpoint.verify(secret_key):
            return False, "Checkpoint signature is INVALID (unauthorized key or corrupted checkpoint)"

        if checkpoint.sequence_covered != head_event.sequence:
            return (
                False,
                f"Checkpoint sequence mismatch: checkpoint covers {checkpoint.sequence_covered}, but head is {head_event.sequence}"
            )

        if checkpoint.head_hash != head_event.current_hash:
            return (
                False,
                f"Checkpoint head hash mismatch: checkpoint claims '{checkpoint.head_hash}', actual head is '{head_event.current_hash}'"
            )

        return True, "Checkpoint signature and state verification PASSED"
