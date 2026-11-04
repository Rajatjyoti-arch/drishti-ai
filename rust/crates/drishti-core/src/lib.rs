//! Drishti Core: Canonical domain models, contracts, and schema primitives.
//!
//! Provides strict, zero-cost, type-safe models for B2B travel entities,
//! authorization contracts, policy decisions, and verification findings.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod identity;
pub mod money;
pub mod policy;
pub mod travel;

pub use identity::{TenantContext, TenantId, UserId, UserRole};
pub use money::{CurrencyCode, Money, MoneyError, MoneyMinor};
pub use policy::{
    CanaryDefinition, ExecutionResult, Finding, InvariantId, OutgoingTestRequest, PolicyAction,
    PolicyDecision, PolicyModelError,
};
pub use travel::{
    BookRequest, Booking, BookingStatus, FlightOption, Hold, HoldRequest, HoldStatus, Quote,
    QuoteRequest, SearchRequest,
};

/// Workspace release version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
