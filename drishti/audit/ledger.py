"""Tamper-evident audit ledger with transactional sequencing and hash-chain persistence."""

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from drishti.audit.hash_chain import AuditEventNode, SignedCheckpoint, GENESIS_HASH

DEFAULT_AUDIT_SIGNING_KEY = b"drishti_audit_secret_key_default"


class TamperEvidentLedger:
    """
    Append-only audit ledger backed by SQLite with ACID transaction guarantees.
    Every recorded event is mathematically linked to its predecessor via SHA-256 chaining.
    """
    def __init__(self, db_path: Path = Path(".drishti_audit.db"), signing_key: bytes = DEFAULT_AUDIT_SIGNING_KEY):
        self.db_path = db_path
        self.signing_key = signing_key
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY,
                    event_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    current_hash TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS checkpoints (
                    checkpoint_id TEXT PRIMARY KEY,
                    sequence_covered INTEGER NOT NULL,
                    head_hash TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    signature TEXT NOT NULL
                );
            """)
            conn.commit()

    def record_event(
        self,
        event_id: str,
        event_type: str,
        payload_digest: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AuditEventNode:
        """
        Thread-safe, atomic append of an audit event to the tamper-evident chain.
        """
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Query current chain head
                cursor.execute(
                    "SELECT sequence, current_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
                )
                head = cursor.fetchone()

                if head is None:
                    next_sequence = 0
                    prev_hash = GENESIS_HASH
                else:
                    next_sequence = head[0] + 1
                    prev_hash = head[1]

                timestamp = datetime.now(timezone.utc).isoformat()
                event_node = AuditEventNode(
                    sequence=next_sequence,
                    event_id=event_id,
                    timestamp=timestamp,
                    event_type=event_type,
                    payload_digest=payload_digest,
                    previous_hash=prev_hash
                )

                import json
                cursor.execute(
                    """
                    INSERT INTO audit_events 
                    (sequence, event_id, timestamp, event_type, payload_digest, previous_hash, current_hash, metadata_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_node.sequence,
                        event_node.event_id,
                        event_node.timestamp,
                        event_node.event_type,
                        event_node.payload_digest,
                        event_node.previous_hash,
                        event_node.current_hash,
                        json.dumps(metadata or {})
                    )
                )
                conn.commit()
                return event_node

    def get_all_events(self) -> List[AuditEventNode]:
        """Retrieves the full ordered event chain for verification."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT sequence, event_id, timestamp, event_type, payload_digest, previous_hash, current_hash FROM audit_events ORDER BY sequence ASC"
            )
            rows = cursor.fetchall()
            return [
                AuditEventNode(
                    sequence=r[0],
                    event_id=r[1],
                    timestamp=r[2],
                    event_type=r[3],
                    payload_digest=r[4],
                    previous_hash=r[5],
                    current_hash=r[6]
                )
                for r in rows
            ]

    def get_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a specific audit event by event_id with parsed metadata."""
        import json
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT sequence, event_id, timestamp, event_type, payload_digest, previous_hash, current_hash, metadata_json "
                "FROM audit_events WHERE event_id = ?",
                (event_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            try:
                meta = json.loads(row[7]) if row[7] else {}
            except Exception:
                meta = {}
            return {
                "sequence": row[0],
                "event_id": row[1],
                "timestamp": row[2],
                "event_type": row[3],
                "payload_digest": row[4],
                "previous_hash": row[5],
                "current_hash": row[6],
                "metadata": meta,
            }

    def create_checkpoint(
        self,
        checkpoint_id: str,
        signing_key: Optional[bytes] = None,
    ) -> Optional[SignedCheckpoint]:
        """Creates and stores a cryptographically signed checkpoint of the current head."""
        key = signing_key or self.signing_key
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT sequence, current_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
                head = cursor.fetchone()
                if not head:
                    return None

                timestamp = datetime.now(timezone.utc).isoformat()
                cp = SignedCheckpoint.create(
                    checkpoint_id=checkpoint_id,
                    sequence_covered=head[0],
                    head_hash=head[1],
                    timestamp=timestamp,
                    secret_key=key
                )
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO checkpoints (checkpoint_id, sequence_covered, head_hash, timestamp, signature)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (cp.checkpoint_id, cp.sequence_covered, cp.head_hash, cp.timestamp, cp.signature)
                )
                conn.commit()
                return cp

    def get_checkpoint(self, checkpoint_id: str) -> Optional[SignedCheckpoint]:
        """Retrieves a signed checkpoint record by checkpoint_id."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT checkpoint_id, sequence_covered, head_hash, timestamp, signature FROM checkpoints WHERE checkpoint_id = ?",
                (checkpoint_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return SignedCheckpoint(
                checkpoint_id=row[0],
                sequence_covered=row[1],
                head_hash=row[2],
                timestamp=row[3],
                signature=row[4]
            )

    def verify_checkpoint_coverage(
        self,
        checkpoint_id: str,
        request_ids: Optional[List[str]] = None,
        signing_key: Optional[bytes] = None,
    ) -> bool:
        """Verifies checkpoint cryptographic authenticity, chain linkage, and request coverage.

        Fails closed (returns False) if:
        1. Checkpoint does not exist in checkpoints table.
        2. HMAC signature verification fails.
        3. Checkpoint head_hash does not match the event at sequence_covered.
        4. Hash chain leading up to sequence_covered is broken or tampered.
        5. Any request_id in request_ids is not covered in the audit sequence.
        """
        import json
        key = signing_key or self.signing_key
        cp = self.get_checkpoint(checkpoint_id)
        if not cp:
            return False

        # 1. HMAC signature check
        if not cp.verify(key):
            return False

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT sequence, event_id, timestamp, event_type, payload_digest, previous_hash, current_hash, metadata_json "
                "FROM audit_events WHERE sequence <= ? ORDER BY sequence ASC",
                (cp.sequence_covered,)
            )
            rows = cursor.fetchall()
            if not rows:
                return False

            # Verify head matches
            if rows[-1][0] != cp.sequence_covered or rows[-1][6] != cp.head_hash:
                return False

            # 2. Hash chain integrity check
            covered_req_ids = set()
            for i, r in enumerate(rows):
                seq, eid, ts, etype, pdigest, prev_h, cur_h, meta_json = r
                node = AuditEventNode(
                    sequence=seq,
                    event_id=eid,
                    timestamp=ts,
                    event_type=etype,
                    payload_digest=pdigest,
                    previous_hash=prev_h,
                    current_hash=cur_h
                )
                if i == 0:
                    if prev_h != GENESIS_HASH:
                        return False
                else:
                    if prev_h != rows[i - 1][6]:
                        return False

                if node.compute_hash() != cur_h:
                    return False

                if meta_json:
                    try:
                        meta = json.loads(meta_json)
                        if isinstance(meta, dict) and "request_id" in meta:
                            covered_req_ids.add(meta["request_id"])
                    except Exception:
                        pass

            # 3. Request coverage check
            if request_ids:
                for req_id in request_ids:
                    if req_id and req_id not in covered_req_ids:
                        return False

            return True
