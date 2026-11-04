//! Drishti Guard: Native Security Kernel Daemon for Drishti AI.
//!
//! Provides OS-level physical network mediation, cryptographic audit ledgers,
//! token-bucket multi-budget rate limiting, and zero-leak credential isolation.

#![deny(unsafe_code)]

pub mod hash_chain;

pub use hash_chain::{canonical_serialize, LedgerEvent, GENESIS_HASH};

/// Release version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
