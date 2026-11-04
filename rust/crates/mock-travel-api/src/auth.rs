//! Synthetic authentication extractor for Axum B2B travel simulator.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use drishti_core::identity::*;
use serde_json::json;

/// Extracted authenticated tenant context.
#[derive(Debug, Clone)]
pub struct AuthContext(pub TenantContext);

impl<S> FromRequestParts<S> for AuthContext
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // 1. Check direct X-Tenant-Id header (for synthetic/direct test runners)
        if let Some(tenant_header) = parts.headers.get("x-tenant-id") {
            let tenant_str = tenant_header
                .to_str()
                .map_err(|_| AuthError::InvalidHeader)?;
            let role = parts
                .headers
                .get("x-user-role")
                .and_then(|r| r.to_str().ok())
                .and_then(|r| match r {
                    "admin" => Some(UserRole::Admin),
                    "sub_agent" => Some(UserRole::SubAgent),
                    "auditor" => Some(UserRole::Auditor),
                    _ => Some(UserRole::Agent),
                })
                .unwrap_or(UserRole::Agent);

            return Ok(AuthContext(TenantContext::new(
                tenant_str,
                format!("{}_user_01", tenant_str),
                role,
            )));
        }

        // 2. Check Bearer token in Authorization header
        if let Some(auth_header) = parts.headers.get("authorization") {
            let auth_str = auth_header
                .to_str()
                .map_err(|_| AuthError::InvalidHeader)?;

            let token = auth_str
                .strip_prefix("Bearer ")
                .or_else(|| auth_str.strip_prefix("bearer "))
                .unwrap_or(auth_str);

            let context = match token {
                "test_token_agency_a" | "agency_a_key" | "token_agency_a" => TenantContext::new(
                    "agency_a",
                    "agent_a_01",
                    UserRole::Agent,
                ),
                "test_token_agency_b" | "agency_b_key" | "token_agency_b" => TenantContext::new(
                    "agency_b",
                    "agent_b_01",
                    UserRole::Agent,
                ),
                "test_token_admin" | "admin_key" => TenantContext::new(
                    "agency_a",
                    "admin_01",
                    UserRole::Admin,
                ),
                _ => return Err(AuthError::InvalidToken),
            };

            return Ok(AuthContext(context));
        }

        // Default to unauthorized if neither header is provided
        Err(AuthError::MissingCredentials)
    }
}

/// Authentication rejection error types.
#[derive(Debug)]
pub enum AuthError {
    MissingCredentials,
    InvalidToken,
    InvalidHeader,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match self {
            Self::MissingCredentials => (
                StatusCode::UNAUTHORIZED,
                "AUTH_MISSING",
                "Missing Authorization or X-Tenant-Id header",
            ),
            Self::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                "INVALID_TOKEN",
                "Unrecognized bearer credentials token",
            ),
            Self::InvalidHeader => (
                StatusCode::BAD_REQUEST,
                "INVALID_HEADER",
                "Malformed authentication header encoding",
            ),
        };

        let body = Json(json!({
            "error": error_code,
            "message": message,
        }));

        (status, body).into_response()
    }
}
