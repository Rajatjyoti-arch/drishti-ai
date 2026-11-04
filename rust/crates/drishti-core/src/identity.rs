//! Identity, tenant isolation, and role models for B2B travel ecosystems.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Strongly typed tenant identifier representing an Agency or Supplier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct TenantId(pub String);

impl TenantId {
    /// Creates a new TenantId from string-like input.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Returns a string slice reference.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for TenantId {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

impl From<&str> for TenantId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

/// Strongly typed user identifier within a tenant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct UserId(pub String);

impl UserId {
    /// Creates a new UserId.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Returns a string slice reference.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// B2B Travel User Role hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    /// Tenant administrator with configuration access
    Admin,
    /// Standard travel agent with search, quote, hold, and book rights
    Agent,
    /// Sub-agent with restricted search and hold rights
    SubAgent,
    /// Read-only auditor or compliance persona
    Auditor,
}

impl fmt::Display for UserRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admin => write!(f, "admin"),
            Self::Agent => write!(f, "agent"),
            Self::SubAgent => write!(f, "sub_agent"),
            Self::Auditor => write!(f, "auditor"),
        }
    }
}

/// Contextual identity of an authenticated participant in a travel transaction.
/// Notice: Raw bearer tokens and credentials are excluded by design to prevent leaks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TenantContext {
    /// Owning tenant / agency ID
    pub tenant_id: TenantId,
    /// Specific user performing the action
    pub user_id: UserId,
    /// Role authorizing specific capabilities
    pub role: UserRole,
    /// Optional session tracking identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

impl TenantContext {
    /// Creates a new tenant context.
    pub fn new(tenant_id: impl Into<TenantId>, user_id: impl Into<UserId>, role: UserRole) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            user_id: user_id.into(),
            role,
            session_id: None,
        }
    }

    /// Attaches an optional session identifier.
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_id_serialization() {
        let tenant = TenantId::new("agency_a");
        let json = serde_json::to_string(&tenant).unwrap();
        assert_eq!(json, "\"agency_a\"");

        let deserialized: TenantId = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, tenant);
    }

    #[test]
    fn test_role_serialization() {
        let role = UserRole::SubAgent;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"sub_agent\"");

        let deserialized: UserRole = serde_json::from_str("\"admin\"").unwrap();
        assert_eq!(deserialized, UserRole::Admin);
    }
}
