//! Scoped Credential Broker and Secret Isolation.
//!
//! Stores synthetic tokens and API keys entirely inside the Rust Security Kernel memory.
//! Enforces:
//! 1. Target binding: Credentials can only be transmitted to explicit authorized hosts.
//! 2. Expiration and revocation checks.
//! 3. Zero leakage: Secrets are scrubbed in Debug displays and never returned across the IPC socket to Python.

use chrono::{DateTime, Utc};
use drishti_core::identity::TenantId;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::RwLock;

/// A scoped secret bound to an identity and authorized destination hosts.
#[derive(Clone)]
pub struct ScopedSecret {
    /// Symbolic alias referenced by Python (e.g., "agency_a_key")
    pub reference_alias: String,
    /// Raw secret value (e.g., Bearer token or API key)
    secret_value: String,
    /// Tenant identity owning this credential
    pub bound_tenant: TenantId,
    /// Authorized target hosts permitted to receive this secret
    pub allowed_hosts: HashSet<String>,
    /// Optional expiration timestamp
    pub expires_at: Option<DateTime<Utc>>,
    /// Revocation flag
    pub is_revoked: bool,
}

impl ScopedSecret {
    /// Creates a new ScopedSecret with strict host bindings.
    pub fn new(
        reference_alias: impl Into<String>,
        secret_value: impl Into<String>,
        bound_tenant: impl Into<TenantId>,
        allowed_hosts: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            reference_alias: reference_alias.into(),
            secret_value: secret_value.into(),
            bound_tenant: bound_tenant.into(),
            allowed_hosts: allowed_hosts.into_iter().map(|h| h.into().to_lowercase()).collect(),
            expires_at: None,
            is_revoked: false,
        }
    }

    /// Sets an expiration timestamp on the secret.
    pub fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Exposes raw secret value only to the internal transport layer.
    pub fn expose_secret(&self) -> &str {
        &self.secret_value
    }
}

impl fmt::Debug for ScopedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedSecret")
            .field("reference_alias", &self.reference_alias)
            .field("secret_value", &"[REDACTED]")
            .field("bound_tenant", &self.bound_tenant)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("expires_at", &self.expires_at)
            .field("is_revoked", &self.is_revoked)
            .finish()
    }
}

/// In-memory thread-safe credential broker.
#[derive(Debug, Default)]
pub struct CredentialBroker {
    secrets: RwLock<HashMap<String, ScopedSecret>>,
}

impl CredentialBroker {
    /// Creates a new empty credential broker.
    pub fn new() -> Self {
        Self {
            secrets: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a scoped secret into the broker.
    pub fn register(&self, secret: ScopedSecret) {
        let mut map = self.secrets.write().unwrap();
        map.insert(secret.reference_alias.clone(), secret);
    }

    /// Manually revokes a registered secret.
    pub fn revoke(&self, alias: &str) -> bool {
        let mut map = self.secrets.write().unwrap();
        if let Some(secret) = map.get_mut(alias) {
            secret.is_revoked = true;
            true
        } else {
            false
        }
    }

    /// Resolves and validates a secret for transmission to a specific target host.
    pub fn resolve_for_target(&self, alias: &str, target_host: &str) -> Result<String, CredentialError> {
        let map = self.secrets.read().unwrap();
        let secret = map
            .get(alias)
            .ok_or_else(|| CredentialError::UnknownReference(alias.to_string()))?;

        if secret.is_revoked {
            return Err(CredentialError::Revoked(alias.to_string()));
        }

        if let Some(exp) = secret.expires_at {
            if Utc::now() >= exp {
                return Err(CredentialError::Expired(alias.to_string()));
            }
        }

        let normalized_host = target_host.to_lowercase();
        if !secret.allowed_hosts.contains(&normalized_host) {
            return Err(CredentialError::HostMismatch {
                alias: alias.to_string(),
                target_host: normalized_host,
                allowed: secret.allowed_hosts.iter().cloned().collect(),
            });
        }

        Ok(secret.expose_secret().to_string())
    }
}

/// Credential broker errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CredentialError {
    #[error("Unknown credential alias reference: {0}")]
    UnknownReference(String),
    #[error("Credential '{0}' has been revoked")]
    Revoked(String),
    #[error("Credential '{0}' has expired")]
    Expired(String),
    #[error("Target binding violation: credential '{alias}' is not authorized for transmission to host '{target_host}' (authorized: {allowed:?})")]
    HostMismatch {
        alias: String,
        target_host: String,
        allowed: Vec<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_secret_is_redacted_in_debug_display() {
        let secret = ScopedSecret::new(
            "agency_a_key",
            "super_secret_bearer_token_xyz",
            TenantId::new("agency_a"),
            vec!["api.travel.com"],
        );

        let debug_str = format!("{:?}", secret);
        assert!(!debug_str.contains("super_secret_bearer_token_xyz"));
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[test]
    fn test_credential_target_binding_enforcement() {
        let broker = CredentialBroker::new();
        let secret = ScopedSecret::new(
            "agency_a_token",
            "auth_token_123",
            TenantId::new("agency_a"),
            vec!["authorized-api.travel.com", "localhost"],
        );
        broker.register(secret);

        // Allowed host succeeds
        let res = broker.resolve_for_target("agency_a_token", "authorized-api.travel.com");
        assert_eq!(res.unwrap(), "auth_token_123");

        // Unauthorized host is rejected
        let evil_res = broker.resolve_for_target("agency_a_token", "malicious-host.com");
        assert!(matches!(
            evil_res,
            Err(CredentialError::HostMismatch { .. })
        ));
    }

    #[test]
    fn test_credential_expiration_and_revocation() {
        let broker = CredentialBroker::new();
        let now = Utc::now();

        // Expired credential
        let expired_secret = ScopedSecret::new(
            "expired_key",
            "old_token",
            TenantId::new("agency_b"),
            vec!["localhost"],
        )
        .with_expiration(now - Duration::hours(1));
        broker.register(expired_secret);

        assert_eq!(
            broker.resolve_for_target("expired_key", "localhost"),
            Err(CredentialError::Expired("expired_key".to_string()))
        );

        // Revocation
        let active_secret = ScopedSecret::new(
            "to_revoke",
            "active_token",
            TenantId::new("agency_b"),
            vec!["localhost"],
        );
        broker.register(active_secret);

        assert!(broker.resolve_for_target("to_revoke", "localhost").is_ok());
        broker.revoke("to_revoke");
        assert_eq!(
            broker.resolve_for_target("to_revoke", "localhost"),
            Err(CredentialError::Revoked("to_revoke".to_string()))
        );
    }
}
