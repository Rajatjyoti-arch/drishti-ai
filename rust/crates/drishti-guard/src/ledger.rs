//! Dedicated single-writer thread SQLite audit ledger.
//!
//! Separates synchronous SQLite writes from asynchronous Tokio tasks using
//! a bounded channel and a dedicated OS worker thread.

use crate::hash_chain::{sign_checkpoint, HashChainError, LedgerEvent, GENESIS_HASH};
use chrono::{DateTime, Utc};
use crossbeam_channel::{bounded, Receiver, Sender};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use tokio::sync::oneshot;

/// Message sent across the channel to the dedicated writer thread.
enum WriterCommand {
    Append {
        event_type: String,
        payload: serde_json::Value,
        responder: oneshot::Sender<Result<LedgerEvent, LedgerError>>,
    },
    Checkpoint {
        secret: Vec<u8>,
        responder: oneshot::Sender<Result<CheckpointRecord, LedgerError>>,
    },
    Shutdown,
}

/// Checkpoint metadata record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRecord {
    pub last_sequence: u64,
    pub last_hash: String,
    pub signature: String,
    pub created_at: DateTime<Utc>,
}

/// Asynchronous handle to the single-writer SQLite audit ledger.
#[derive(Clone)]
pub struct AuditLedger {
    tx: Sender<WriterCommand>,
    db_path: PathBuf,
    is_running: Arc<AtomicBool>,
}

impl AuditLedger {
    /// Initializes a new or existing SQLite database and spawns the dedicated writer thread.
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let path = db_path.as_ref().to_path_buf();
        let (tx, rx) = bounded::<WriterCommand>(1024);
        let is_running = Arc::new(AtomicBool::new(true));

        // Initialize schema synchronously before spawning thread
        {
            let conn = Connection::open(&path).map_err(|e| LedgerError::Database(e.to_string()))?;
            init_schema(&conn)?;
        }

        let worker_path = path.clone();
        let running_flag = Arc::clone(&is_running);

        thread::Builder::new()
            .name("drishti-ledger-writer".to_string())
            .spawn(move || {
                writer_loop(worker_path, rx, running_flag);
            })
            .map_err(|e| LedgerError::ThreadSpawn(e.to_string()))?;

        Ok(Self {
            tx,
            db_path: path,
            is_running,
        })
    }

    /// Appends an event to the hash chain through the dedicated single-writer thread.
    /// This method is async and does not block Tokio's worker threads.
    pub async fn append(
        &self,
        event_type: impl Into<String>,
        payload: serde_json::Value,
    ) -> Result<LedgerEvent, LedgerError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(WriterCommand::Append {
                event_type: event_type.into(),
                payload,
                responder: resp_tx,
            })
            .map_err(|_| LedgerError::ChannelClosed)?;

        resp_rx.await.map_err(|_| LedgerError::WriterDropped)?
    }

    /// Creates and persists an HMAC-signed checkpoint of the ledger's current head.
    pub async fn create_checkpoint(&self, secret: &[u8]) -> Result<CheckpointRecord, LedgerError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(WriterCommand::Checkpoint {
                secret: secret.to_vec(),
                responder: resp_tx,
            })
            .map_err(|_| LedgerError::ChannelClosed)?;

        resp_rx.await.map_err(|_| LedgerError::WriterDropped)?
    }

    /// Reads all events from SQLite synchronously to verify full cryptographic integrity.
    pub fn verify_integrity(&self) -> Result<usize, LedgerError> {
        let conn = Connection::open(&self.db_path).map_err(|e| LedgerError::Database(e.to_string()))?;
        let mut stmt = conn
            .prepare("SELECT sequence_number, timestamp, event_type, payload, prev_hash, hash FROM ledger_events ORDER BY sequence_number ASC")
            .map_err(|e| LedgerError::Database(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                let seq: i64 = row.get(0)?;
                let ts_str: String = row.get(1)?;
                let event_type: String = row.get(2)?;
                let payload_str: String = row.get(3)?;
                let prev_hash: String = row.get(4)?;
                let hash: String = row.get(5)?;

                Ok((seq as u64, ts_str, event_type, payload_str, prev_hash, hash))
            })
            .map_err(|e| LedgerError::Database(e.to_string()))?;

        let mut expected_prev_hash = GENESIS_HASH.to_string();
        let mut count = 0;

        for (idx, row) in rows.enumerate() {
            let (seq, ts_str, event_type, payload_str, prev_hash, hash) =
                row.map_err(|e| LedgerError::Database(e.to_string()))?;

            let expected_seq = (idx + 1) as u64;
            if seq != expected_seq {
                return Err(LedgerError::SequenceGap {
                    expected: expected_seq,
                    found: seq,
                });
            }

            let timestamp = DateTime::parse_from_rfc3339(&ts_str)
                .map_err(|e| LedgerError::InvalidData(e.to_string()))?
                .with_timezone(&Utc);

            let payload: serde_json::Value =
                serde_json::from_str(&payload_str).map_err(|e| LedgerError::InvalidData(e.to_string()))?;

            let event = LedgerEvent {
                sequence_number: seq,
                timestamp,
                event_type,
                payload,
                prev_hash: prev_hash.clone(),
                hash: hash.clone(),
            };

            event.verify(&expected_prev_hash).map_err(LedgerError::Cryptographic)?;
            expected_prev_hash = hash;
            count += 1;
        }

        Ok(count)
    }

    /// Returns true if the writer thread is active and healthy.
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    /// Read the latest sequence and hash.
    pub fn get_latest(&self) -> Result<Option<(u64, String)>, LedgerError> {
        let conn = Connection::open(&self.db_path).map_err(|e| LedgerError::Database(e.to_string()))?;
        let mut stmt = conn
            .prepare("SELECT sequence_number, hash FROM ledger_events ORDER BY sequence_number DESC LIMIT 1")
            .map_err(|e| LedgerError::Database(e.to_string()))?;

        let mut rows = stmt.query([]).map_err(|e| LedgerError::Database(e.to_string()))?;
        if let Some(row) = rows.next().map_err(|e| LedgerError::Database(e.to_string()))? {
            let seq: i64 = row.get(0).map_err(|e| LedgerError::Database(e.to_string()))?;
            let hash: String = row.get(1).map_err(|e| LedgerError::Database(e.to_string()))?;
            Ok(Some((seq as u64, hash)))
        } else {
            Ok(None)
        }
    }
}

impl Drop for AuditLedger {
    fn drop(&mut self) {
        let _ = self.tx.send(WriterCommand::Shutdown);
    }
}

fn init_schema(conn: &Connection) -> Result<(), LedgerError> {
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;

        CREATE TABLE IF NOT EXISTS ledger_events (
            sequence_number INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ledger_checkpoints (
            last_sequence INTEGER PRIMARY KEY,
            last_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        "#,
    )
    .map_err(|e| LedgerError::Database(e.to_string()))
}

fn writer_loop(db_path: PathBuf, rx: Receiver<WriterCommand>, is_running: Arc<AtomicBool>) {
    let mut conn = match Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to open ledger SQLite database: {}", e);
            is_running.store(false, Ordering::SeqCst);
            return;
        }
    };

    while let Ok(cmd) = rx.recv() {
        match cmd {
            WriterCommand::Append {
                event_type,
                payload,
                responder,
            } => {
                let res = perform_append(&mut conn, &event_type, payload);
                let _ = responder.send(res);
            }
            WriterCommand::Checkpoint { secret, responder } => {
                let res = perform_checkpoint(&mut conn, &secret);
                let _ = responder.send(res);
            }
            WriterCommand::Shutdown => break,
        }
    }

    is_running.store(false, Ordering::SeqCst);
}

fn perform_append(
    conn: &mut Connection,
    event_type: &str,
    payload: serde_json::Value,
) -> Result<LedgerEvent, LedgerError> {
    let tx = conn.transaction().map_err(|e| LedgerError::Database(e.to_string()))?;

    let (last_seq, prev_hash) = {
        let mut stmt = tx
            .prepare("SELECT sequence_number, hash FROM ledger_events ORDER BY sequence_number DESC LIMIT 1")
            .map_err(|e| LedgerError::Database(e.to_string()))?;

        let mut rows = stmt.query([]).map_err(|e| LedgerError::Database(e.to_string()))?;
        if let Some(row) = rows.next().map_err(|e| LedgerError::Database(e.to_string()))? {
            let seq: i64 = row.get(0).map_err(|e| LedgerError::Database(e.to_string()))?;
            let hash: String = row.get(1).map_err(|e| LedgerError::Database(e.to_string()))?;
            (seq as u64, hash)
        } else {
            (0, GENESIS_HASH.to_string())
        }
    };

    let next_seq = last_seq + 1;
    let now = Utc::now();
    let event = LedgerEvent::new(next_seq, now, event_type, payload, prev_hash);

    let payload_str = serde_json::to_string(&event.payload)
        .map_err(|e| LedgerError::InvalidData(e.to_string()))?;

    tx.execute(
        "INSERT INTO ledger_events (sequence_number, timestamp, event_type, payload, prev_hash, hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            event.sequence_number as i64,
            event.timestamp.to_rfc3339(),
            event.event_type,
            payload_str,
            event.prev_hash,
            event.hash,
        ],
    )
    .map_err(|e| LedgerError::Database(e.to_string()))?;

    tx.commit().map_err(|e| LedgerError::Database(e.to_string()))?;
    Ok(event)
}

fn perform_checkpoint(conn: &mut Connection, secret: &[u8]) -> Result<CheckpointRecord, LedgerError> {
    let tx = conn.transaction().map_err(|e| LedgerError::Database(e.to_string()))?;

    let (last_seq, last_hash) = {
        let mut stmt = tx
            .prepare("SELECT sequence_number, hash FROM ledger_events ORDER BY sequence_number DESC LIMIT 1")
            .map_err(|e| LedgerError::Database(e.to_string()))?;

        let mut rows = stmt.query([]).map_err(|e| LedgerError::Database(e.to_string()))?;
        if let Some(row) = rows.next().map_err(|e| LedgerError::Database(e.to_string()))? {
            let seq: i64 = row.get(0).map_err(|e| LedgerError::Database(e.to_string()))?;
            let hash: String = row.get(1).map_err(|e| LedgerError::Database(e.to_string()))?;
            (seq as u64, hash)
        } else {
            (0, GENESIS_HASH.to_string())
        }
    };

    let now = Utc::now();
    let sig = sign_checkpoint(last_seq, &last_hash, secret);

    tx.execute(
        "INSERT OR REPLACE INTO ledger_checkpoints (last_sequence, last_hash, signature, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![last_seq as i64, last_hash, sig, now.to_rfc3339()],
    )
    .map_err(|e| LedgerError::Database(e.to_string()))?;

    tx.commit().map_err(|e| LedgerError::Database(e.to_string()))?;

    Ok(CheckpointRecord {
        last_sequence: last_seq,
        last_hash,
        signature: sig,
        created_at: now,
    })
}

/// Ledger error types.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("Database error: {0}")]
    Database(String),
    #[error("Thread spawn error: {0}")]
    ThreadSpawn(String),
    #[error("Ledger writer channel closed")]
    ChannelClosed,
    #[error("Ledger writer dropped response sender")]
    WriterDropped,
    #[error("Invalid data format: {0}")]
    InvalidData(String),
    #[error("Cryptographic chain violation: {0}")]
    Cryptographic(#[from] HashChainError),
    #[error("Sequence gap detected: expected {expected}, found {found}")]
    SequenceGap { expected: u64, found: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_concurrent_appends_preserve_single_valid_chain() {
        let temp = NamedTempFile::new().unwrap();
        let ledger = AuditLedger::open(temp.path()).unwrap();

        // Spawn 20 concurrent tasks appending to the ledger
        let mut handles = Vec::new();
        for i in 0..20 {
            let ledger_clone = ledger.clone();
            handles.push(tokio::spawn(async move {
                ledger_clone
                    .append("CONCURRENT_TEST", json!({"task_id": i}))
                    .await
                    .unwrap()
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // Verify that exactly 20 events were appended with a contiguous hash chain
        let count = ledger.verify_integrity().unwrap();
        assert_eq!(count, 20);

        let (latest_seq, _) = ledger.get_latest().unwrap().unwrap();
        assert_eq!(latest_seq, 20);
    }

    #[tokio::test]
    async fn test_tamper_detection_in_sqlite() {
        let temp = NamedTempFile::new().unwrap();
        let ledger = AuditLedger::open(temp.path()).unwrap();

        ledger.append("EVENT_1", json!({"step": 1})).await.unwrap();
        ledger.append("EVENT_2", json!({"step": 2})).await.unwrap();

        assert_eq!(ledger.verify_integrity().unwrap(), 2);

        // Directly modify a payload in SQLite behind the scenes (adversary simulation)
        {
            let conn = Connection::open(temp.path()).unwrap();
            conn.execute(
                "UPDATE ledger_events SET payload = '{\"step\":999}' WHERE sequence_number = 1",
                [],
            )
            .unwrap();
        }

        // Verification must detect tampering and fail closed
        assert!(ledger.verify_integrity().is_err());
    }
}
