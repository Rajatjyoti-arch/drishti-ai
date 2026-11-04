//! Central Policy Gate binding scope, rate limits, credentials, audit, and transport.
//!
//! Enforces:
//! 1. Nonce-signed, single-use policy decisions bound immutably to request parameters.
//! 2. Mandatory audit-before-send: probe intent must commit to the ledger before socket transmission.
//! 3. RAII concurrency release on completion or error.
//! 4. Audit-after-receive: raw response digests stored in the cryptographic ledger.

use crate::credential_broker::{CredentialBroker, CredentialError};
use crate::ledger::{AuditLedger, LedgerError};
use crate::rate_limiter::{MultiBudgetRateLimiter, RateLimitError};
use crate::scope_validator::{ScopeError, ScopeValidator};
use crate::transport::{SafeHttpClient, TransportError};
use chrono::Utc;
use drishti_core::policy::{ExecutionResult, OutgoingTestRequest, PolicyAction, PolicyDecision};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

/// Central Policy Gate coordinating all safety, transport, and audit subsystems.
#[derive(Clone)]
pub struct PolicyGate {
    scope_validator: ScopeValidator,
    rate_limiter: MultiBudgetRateLimiter,
    credential_broker: Arc<CredentialBroker>,
    audit_ledger: AuditLedger,
    http_client: SafeHttpClient,
}

impl PolicyGate {
    /// Constructs a fully assembled PolicyGate.
    pub fn new(
        scope_validator: ScopeValidator,
        rate_limiter: MultiBudgetRateLimiter,
        credential_broker: Arc<CredentialBroker>,
        audit_ledger: AuditLedger,
    ) -> Result<Self, GateError> {
        let http_client = SafeHttpClient::new(scope_validator.clone())
            .map_err(GateError::Transport)?;

        Ok(Self {
            scope_validator,
            rate_limiter,
            credential_broker,
            audit_ledger,
            http_client,
        })
    }

    /// Evaluates and executes an authorized test request submitted by the Python Intelligence Layer.
    pub async fn execute_request(
        &self,
        req: &OutgoingTestRequest,
    ) -> Result<ExecutionResult, GateError> {
        // 1. Validate Scope and Resolve Destination
        let resolved = self
            .scope_validator
            .validate_and_resolve(&req.target_url)
            .map_err(GateError::Scope)?;

        // 2. Acquire Rate Limiting & Concurrency Budget Permit
        let _permit = self
            .rate_limiter
            .acquire(&req.test_id)
            .map_err(GateError::RateLimit)?;

        // 3. Resolve Scoped Credential (if requested)
        let resolved_auth_header = if let Some(cred_alias) = &req.credential_ref {
            let token = self
                .credential_broker
                .resolve_for_target(cred_alias, &resolved.host_header)
                .map_err(GateError::Credential)?;
            Some(token)
        } else {
            None
        };

        // 4. Compute Bound Request Digest and Decision Nonce
        let decision_nonce = format!("nonce_{}", Uuid::new_v4().simple());
        let bound_digest = compute_request_digest(
            &req.method,
            &req.target_url,
            req.body.as_deref().unwrap_or(""),
        );

        let decision = PolicyDecision {
            action: PolicyAction::Allow,
            reason: "Target verified within authorized scope, budgets, and target bindings".to_string(),
            rule_matched: "SCOPE_RATE_CREDENTIAL_BOUND_OK".to_string(),
            decision_nonce: decision_nonce.clone(),
            bound_request_digest: bound_digest.clone(),
            evaluated_at: Utc::now(),
        };

        // 5. MANDATORY AUDIT-BEFORE-SEND
        let audit_intent_payload = json!({
            "request_id": req.request_id,
            "test_id": req.test_id,
            "method": req.method,
            "target_url": req.target_url,
            "decision": decision,
            "credential_ref": req.credential_ref,
            "invariant_candidate": req.invariant_candidate,
        });

        self.audit_ledger
            .append("PROBE_INTENT", audit_intent_payload)
            .await
            .map_err(GateError::AuditBeforeSendFailed)?;

        // 6. Transmit HTTP Request via Controlled Safe Transport
        let result = self
            .http_client
            .execute(
                &req.request_id,
                &req.method,
                &req.target_url,
                &req.headers,
                req.body.as_deref(),
                resolved_auth_header.as_deref(),
                &decision_nonce,
            )
            .await
            .map_err(GateError::Transport)?;

        // 7. AUDIT-AFTER-RECEIVE
        let audit_result_payload = json!({
            "request_id": result.request_id,
            "status_code": result.status_code,
            "latency_ms": result.latency_ms,
            "response_digest": result.response_digest,
            "decision_nonce": result.policy_decision_nonce,
        });

        self.audit_ledger
            .append("PROBE_RESULT", audit_result_payload)
            .await
            .map_err(GateError::Audit)?;

        Ok(result)
    }

    /// Access reference to the audit ledger for verification queries.
    pub fn ledger(&self) -> &AuditLedger {
        &self.audit_ledger
    }
}

/// Computes SHA-256 digest of bound request attributes.
fn compute_request_digest(method: &str, url: &str, body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}:{}", method.to_uppercase(), url, body).as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

/// Errors originating within the centralized PolicyGate.
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("Scope boundary violation: {0}")]
    Scope(#[from] ScopeError),
    #[error("Rate or budget exhaustion: {0}")]
    RateLimit(#[from] RateLimitError),
    #[error("Credential isolation error: {0}")]
    Credential(#[from] CredentialError),
    #[error("Transport execution error: {0}")]
    Transport(#[from] TransportError),
    #[error("Critical audit-before-send failure: {0}")]
    AuditBeforeSendFailed(LedgerError),
    #[error("Audit recording error: {0}")]
    Audit(LedgerError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_broker::ScopedSecret;
    use crate::rate_limiter::RateLimiterConfig;
    use axum::http::StatusCode as AxumStatusCode;
    use axum::routing::get;
    use axum::Router;
    use drishti_core::identity::TenantId;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use tempfile::NamedTempFile;
    use tokio::net::TcpListener;

    async fn spawn_mock_target() -> (String, u16) {
        let app = Router::new().route(
            "/api/v1/test",
            get(|| async { (AxumStatusCode::OK, "{\"status\":\"authorized\"}") }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (format!("http://{}", addr), addr.port())
    }

    #[tokio::test]
    async fn test_policy_gate_executes_and_audits_end_to_end() {
        let (base_url, port) = spawn_mock_target().await;
        let temp_db = NamedTempFile::new().unwrap();

        let validator = ScopeValidator::new()
            .with_domain("127.0.0.1")
            .with_scheme("http")
            .with_port(port)
            .with_loopback_allowed(true);

        let limiter = MultiBudgetRateLimiter::new(RateLimiterConfig::default());
        let broker = Arc::new(CredentialBroker::new());
        broker.register(ScopedSecret::new(
            "test_key",
            "Bearer valid_token_123",
            TenantId::new("agency_a"),
            vec!["127.0.0.1"],
        ));

        let ledger = AuditLedger::open(temp_db.path()).unwrap();
        let gate = PolicyGate::new(validator, limiter, broker, ledger).unwrap();

        let req = OutgoingTestRequest {
            request_id: "req-e2e-01".to_string(),
            test_id: "test-gate-01".to_string(),
            target_url: format!("{}/api/v1/test", base_url),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: None,
            tenant_context: None,
            credential_ref: Some("test_key".to_string()),
            invariant_candidate: None,
            timeout_ms: 5000,
        };

        let result = gate.execute_request(&req).await.unwrap();
        assert_eq!(result.status_code, 200);
        assert!(result.sanitized_body.contains("authorized"));

        // Verify that both PROBE_INTENT and PROBE_RESULT were recorded in the audit ledger
        let count = gate.ledger().verify_integrity().unwrap();
        assert_eq!(count, 2);
    }
}
