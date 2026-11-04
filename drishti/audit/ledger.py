"""Tamper-evident audit ledger with transactional sequencing and hash-chain persistence."""

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from drishti.audit.hash_chain import AuditEventNode, SignedCheckpoint, GENESIS_HASH

class TamperEvidentLedger:
    """
    Append-only audit ledger backed by SQLite with ACID transaction guarantees.
    Every recorded event is mathematically linked to its predecessor via SHA-256 chaining.
    """
    def __init__(self, db_path: Path = Path(".drishti_audit.db")):
        self.db_path = db_path
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

    def create_checkpoint(self, checkpoint_id: str, signing_key: bytes) -> Optional[SignedCheckpoint]:
        """Creates and stores a cryptographically signed checkpoint of the current head."""
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
                    secret_key=signing_key
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
