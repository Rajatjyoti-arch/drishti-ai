//! Drishti Guard: Native Security Kernel Daemon for Drishti AI.
//!
//! Provides OS-level physical network mediation, cryptographic audit ledgers,
//! token-bucket multi-budget rate limiting, and zero-leak credential isolation.

#![deny(unsafe_code)]

pub mod hash_chain;
pub mod ledger;

pub use hash_chain::{canonical_serialize, LedgerEvent, GENESIS_HASH};
pub use ledger::{AuditLedger, CheckpointRecord, LedgerError};

/// Release version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
