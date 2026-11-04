//! Canonical JSON serialization and cryptographic SHA-256 hash chaining.
//!
//! Enforces deterministic, tamper-evident ordering for all security decisions,
//! test probes, and execution findings.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Genesis block previous hash constant (64 zero hex characters).
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A single immutable entry in the cryptographic audit ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEvent {
    /// Monotonically increasing sequence number starting at 1
    pub sequence_number: u64,
    /// Event recording timestamp in RFC 3339 format
    pub timestamp: DateTime<Utc>,
    /// Classification of the audit event (e.g. POLICY_EVALUATION, PROBE_TRANSMISSION)
    pub event_type: String,
    /// Arbitrary structured event payload
    pub payload: serde_json::Value,
    /// SHA-256 hash of the immediate predecessor event
    pub prev_hash: String,
    /// SHA-256 hash of this event's canonical representation
    pub hash: String,
}

impl LedgerEvent {
    /// Computes the deterministic SHA-256 digest of an event given its constituent fields.
    pub fn compute_hash(
        sequence_number: u64,
        timestamp: &DateTime<Utc>,
        event_type: &str,
        payload: &serde_json::Value,
        prev_hash: &str,
    ) -> String {
        let canonical_str = canonical_serialize(sequence_number, timestamp, event_type, payload, prev_hash);
        let mut hasher = Sha256::new();
        hasher.update(canonical_str.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Creates a new validated LedgerEvent linking to `prev_hash`.
    pub fn new(
        sequence_number: u64,
        timestamp: DateTime<Utc>,
        event_type: impl Into<String>,
        payload: serde_json::Value,
        prev_hash: impl Into<String>,
    ) -> Self {
        let event_type_str = event_type.into();
        let prev_hash_str = prev_hash.into();
        let hash = Self::compute_hash(
            sequence_number,
            &timestamp,
            &event_type_str,
            &payload,
            &prev_hash_str,
        );

        Self {
            sequence_number,
            timestamp,
            event_type: event_type_str,
            payload,
            prev_hash: prev_hash_str,
            hash,
        }
    }

    /// Verifies the cryptographic integrity and previous hash link of this event.
    pub fn verify(&self, expected_prev_hash: &str) -> Result<(), HashChainError> {
        if self.prev_hash != expected_prev_hash {
            return Err(HashChainError::PreviousHashMismatch {
                expected: expected_prev_hash.to_string(),
                actual: self.prev_hash.clone(),
                sequence: self.sequence_number,
            });
        }

        let computed = Self::compute_hash(
            self.sequence_number,
            &self.timestamp,
            &self.event_type,
            &self.payload,
            &self.prev_hash,
        );

        if self.hash != computed {
            return Err(HashChainError::HashVerificationFailed {
                recorded: self.hash.clone(),
                computed,
                sequence: self.sequence_number,
            });
        }

        Ok(())
    }
}

/// Produces a canonical string representation for hashing with sorted keys and compact whitespace.
pub fn canonical_serialize(
    sequence_number: u64,
    timestamp: &DateTime<Utc>,
    event_type: &str,
    payload: &serde_json::Value,
    prev_hash: &str,
) -> String {
    // To ensure exact byte-for-byte reproducibility:
    // Format JSON with keys sorted recursively and compact delimiters
    let canonical_payload = canonical_json_value(payload);

    format!(
        "{{\"event_type\":\"{}\",\"payload\":{},\"prev_hash\":\"{}\",\"sequence_number\":{},\"timestamp\":\"{}\"}}",
        event_type,
        canonical_payload,
        prev_hash,
        sequence_number,
        timestamp.to_rfc3339()
    )
}

/// Recursively formats a serde_json::Value into canonical JSON with sorted object keys.
pub fn canonical_json_value(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => if *b { "true".to_string() } else { "false".to_string() },
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => serde_json::to_string(s).unwrap(),
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json_value).collect();
            format!("[{}]", items.join(","))
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let entries: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical_json_value(&map[k])))
                .collect();
            format!("{{{}}}", entries.join(","))
        }
    }
}

/// Signs a ledger checkpoint using HMAC-SHA256.
pub fn sign_checkpoint(last_seq: u64, last_hash: &str, secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC supports any key length");
    mac.update(format!("{}:{}", last_seq, last_hash).as_bytes());
    format!("{:x}", mac.finalize().into_bytes())
}

/// Verifies an HMAC-SHA256 checkpoint signature.
pub fn verify_checkpoint(last_seq: u64, last_hash: &str, secret: &[u8], signature_hex: &str) -> bool {
    let expected = sign_checkpoint(last_seq, last_hash, secret);
    expected == signature_hex
}

/// Errors occurring during cryptographic hash-chain evaluation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HashChainError {
    #[error("Previous hash mismatch at sequence {sequence}: expected {expected}, got {actual}")]
    PreviousHashMismatch {
        sequence: u64,
        expected: String,
        actual: String,
    },
    #[error("Hash verification failed at sequence {sequence}: recorded {recorded}, computed {computed}")]
    HashVerificationFailed {
        sequence: u64,
        recorded: String,
        computed: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_genesis_event_and_chain() {
        let now = Utc::now();
        let payload1 = json!({"action": "ALLOW", "target": "https://api.travel.com/v1"});
        let event1 = LedgerEvent::new(1, now, "POLICY_CHECK", payload1, GENESIS_HASH);

        assert!(event1.verify(GENESIS_HASH).is_ok());
        assert_eq!(event1.prev_hash, GENESIS_HASH);

        let payload2 = json!({"status": 200, "latency_ms": 45});
        let event2 = LedgerEvent::new(2, now, "HTTP_RESPONSE", payload2, &event1.hash);

        assert!(event2.verify(&event1.hash).is_ok());
    }

    #[test]
    fn test_tamper_detection_on_payload() {
        let now = Utc::now();
        let payload = json!({"amount": 10000, "user": "alice"});
        let mut event = LedgerEvent::new(1, now, "BOOKING_REQUEST", payload, GENESIS_HASH);

        assert!(event.verify(GENESIS_HASH).is_ok());

        // Tamper with payload
        event.payload = json!({"amount": 100, "user": "alice"});
        assert!(matches!(
            event.verify(GENESIS_HASH),
            Err(HashChainError::HashVerificationFailed { .. })
        ));
    }

    #[test]
    fn test_checkpoint_signing_and_verification() {
        let secret = b"drishti_super_secret_audit_key_32";
        let seq = 42;
        let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let sig = sign_checkpoint(seq, hash, secret);
        assert!(verify_checkpoint(seq, hash, secret, &sig));
        assert!(!verify_checkpoint(seq + 1, hash, secret, &sig));
        assert!(!verify_checkpoint(seq, "tampered_hash", secret, &sig));
    }
}
