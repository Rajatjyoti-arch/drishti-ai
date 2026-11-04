//! Drishti Guard: Native Security Kernel Daemon for Drishti AI.
//!
//! Provides OS-level physical network mediation, cryptographic audit ledgers,
//! token-bucket multi-budget rate limiting, and zero-leak credential isolation.

#![deny(unsafe_code)]

pub mod credential_broker;
pub mod gate;
pub mod hash_chain;
pub mod ipc;
pub mod ledger;
pub mod rate_limiter;
pub mod scope_validator;
pub mod transport;

pub use credential_broker::{CredentialBroker, CredentialError, ScopedSecret};
pub use gate::{GateError, PolicyGate};
pub use hash_chain::{canonical_serialize, LedgerEvent, GENESIS_HASH};
pub use ipc::{IpcCommand, IpcResponse, IpcServer, CURRENT_IPC_VERSION, MAX_IPC_MESSAGE_BYTES};
pub use ledger::{AuditLedger, CheckpointRecord, LedgerError};
pub use rate_limiter::{ConcurrencyPermit, MultiBudgetRateLimiter, RateLimitError, RateLimiterConfig};
pub use scope_validator::{ResolvedTarget, ScopeError, ScopeValidator};
pub use transport::{SafeHttpClient, TransportError, MAX_REDIRECT_DEPTH};

/// Release version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
