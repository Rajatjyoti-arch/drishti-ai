//! Controlled Reqwest Transport Client with Strict Redirect Re-validation and Destination Pinning.
//!
//! Enforces:
//! 1. Disabled automatic redirects: all 3xx responses are intercepted and re-validated against ScopeValidator.
//! 2. Bounded redirect depth to prevent infinite loops.
//! 3. Native TLS certificate verification (never disabled).
//! 4. Disabled uncontrolled environment proxies.

use crate::scope_validator::{ResolvedTarget, ScopeError, ScopeValidator};
use drishti_core::policy::ExecutionResult;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, LOCATION};
use reqwest::{Client, Method};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Instant;

/// Maximum number of allowed HTTP redirect hops.
pub const MAX_REDIRECT_DEPTH: u32 = 3;

/// Secure HTTP transport engine governed strictly by the Security Kernel.
#[derive(Clone)]
pub struct SafeHttpClient {
    client: Client,
    scope_validator: ScopeValidator,
    max_redirects: u32,
}

impl SafeHttpClient {
    /// Creates a new SafeHttpClient with auto-redirect disabled and secure defaults.
    pub fn new(scope_validator: ScopeValidator) -> Result<Self, TransportError> {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none()) // Enforce manual redirect handling
            .no_proxy()                                  // Prevent environment proxy hijacking
            .build()
            .map_err(|e| TransportError::ClientBuild(e.to_string()))?;

        Ok(Self {
            client,
            scope_validator,
            max_redirects: MAX_REDIRECT_DEPTH,
        })
    }

    /// Sets maximum allowed redirect depth.
    pub fn with_max_redirects(mut self, depth: u32) -> Self {
        self.max_redirects = depth;
        self
    }

    /// Executes an authorized test request with end-to-end redirect validation and timing.
    pub async fn execute(
        &self,
        request_id: &str,
        method: &str,
        initial_url: &str,
        headers: &HashMap<String, String>,
        body: Option<&str>,
        auth_header: Option<&str>,
        decision_nonce: &str,
    ) -> Result<ExecutionResult, TransportError> {
        let start_time = Instant::now();
        let mut current_url = initial_url.to_string();
        let mut hops = 0;

        let http_method = Method::from_str(method)
            .map_err(|e| TransportError::InvalidMethod(e.to_string()))?;

        loop {
            // 1. Re-validate destination scope before EVERY hop
            let resolved: ResolvedTarget = self
                .scope_validator
                .validate_and_resolve(&current_url)
                .map_err(TransportError::ScopeValidation)?;

            // 2. Assemble Request Headers
            let mut req_headers = HeaderMap::new();
            for (k, v) in headers {
                if let (Ok(h_name), Ok(h_val)) = (HeaderName::from_str(k), HeaderValue::from_str(v)) {
                    req_headers.insert(h_name, h_val);
                }
            }

            // Attach scoped credential header if provided
            if let Some(auth_val) = auth_header {
                if let Ok(h_val) = HeaderValue::from_str(auth_val) {
                    req_headers.insert(reqwest::header::AUTHORIZATION, h_val);
                }
            }

            // 3. Dispatch HTTP Request to Validated Target
            let mut req_builder = self
                .client
                .request(http_method.clone(), resolved.original_url.clone())
                .headers(req_headers);

            if let Some(b) = body {
                req_builder = req_builder.body(b.to_string());
            }

            let resp = req_builder
                .send()
                .await
                .map_err(|e| TransportError::Network(e.to_string()))?;

            let status = resp.status();

            // 4. Handle 3xx Redirect Interception
            if status.is_redirection() {
                hops += 1;
                if hops > self.max_redirects {
                    return Err(TransportError::MaxRedirectsExceeded(self.max_redirects));
                }

                let location_header = resp
                    .headers()
                    .get(LOCATION)
                    .ok_or_else(|| TransportError::MissingRedirectLocation)?
                    .to_str()
                    .map_err(|_| TransportError::InvalidRedirectHeader)?;

                // Resolve relative redirect against current URL
                let parsed_redirect = resolved
                    .original_url
                    .join(location_header)
                    .map_err(|e| TransportError::InvalidRedirectUrl(e.to_string()))?;

                current_url = parsed_redirect.to_string();
                continue;
            }

            // 5. Final Response Processing
            let latency_ms = start_time.elapsed().as_millis() as u64;
            let status_code = status.as_u16();

            let mut out_headers = HashMap::new();
            for (k, v) in resp.headers() {
                // Redact sensitive session cookies from returned headers
                if k.as_str().eq_ignore_ascii_case("set-cookie") {
                    out_headers.insert(k.to_string(), "[REDACTED_COOKIE]".to_string());
                } else if let Ok(val_str) = v.to_str() {
                    out_headers.insert(k.to_string(), val_str.to_string());
                }
            }

            let raw_bytes = resp
                .bytes()
                .await
                .map_err(|e| TransportError::Network(e.to_string()))?;

            // Compute SHA-256 hash of raw response frame
            let mut hasher = Sha256::new();
            hasher.update(&raw_bytes);
            let response_digest = format!("{:x}", hasher.finalize());

            let body_str = String::from_utf8_lossy(&raw_bytes).to_string();

            return Ok(ExecutionResult {
                request_id: request_id.to_string(),
                status_code,
                headers: out_headers,
                sanitized_body: body_str,
                latency_ms,
                policy_decision_nonce: decision_nonce.to_string(),
                response_digest,
            });
        }
    }
}

/// Transport execution errors.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum TransportError {
    #[error("Client initialization failed: {0}")]
    ClientBuild(String),
    #[error("Invalid HTTP method: {0}")]
    InvalidMethod(String),
    #[error("Scope validation failed before transmission: {0}")]
    ScopeValidation(#[from] ScopeError),
    #[error("Network I/O error during request: {0}")]
    Network(String),
    #[error("Redirect count exceeded maximum threshold ({0} hops)")]
    MaxRedirectsExceeded(u32),
    #[error("3xx redirect response missing Location header")]
    MissingRedirectLocation,
    #[error("Malformed Location header in redirect response")]
    InvalidRedirectHeader,
    #[error("Failed to parse redirect URL: {0}")]
    InvalidRedirectUrl(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode as AxumStatusCode;
    use axum::response::{IntoResponse, Redirect};
    use axum::routing::get;
    use axum::Router;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    async fn spawn_mock_server() -> String {
        let app = Router::new()
            .route("/ok", get(|| async { (AxumStatusCode::OK, "hello from test target") }))
            .route("/redirect_safe", get(|| async { Redirect::temporary("/ok") }))
            .route(
                "/redirect_evil",
                get(|| async {
                    // Redirects to evil target
                    (
                        AxumStatusCode::FOUND,
                        [(reqwest::header::LOCATION, "https://evil-unauthorized.com/steal")],
                        "",
                    )
                        .into_response()
                }),
            )
            .route(
                "/redirect_loop",
                get(|| async { Redirect::temporary("/redirect_loop") }),
            );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn test_transport_follows_safe_in_scope_redirect() {
        let base_url = spawn_mock_server().await;
        let port = base_url.split(':').last().unwrap().parse::<u16>().unwrap();

        let validator = ScopeValidator::new()
            .with_domain("127.0.0.1")
            .with_scheme("http")
            .with_port(port)
            .with_loopback_allowed(true);

        let client = SafeHttpClient::new(validator).unwrap();
        let headers = HashMap::new();

        let res = client
            .execute(
                "req-1",
                "GET",
                &format!("{}/redirect_safe", base_url),
                &headers,
                None,
                None,
                "nonce-test",
            )
            .await;

        assert!(res.is_ok());
        let exec = res.unwrap();
        assert_eq!(exec.status_code, 200);
        assert_eq!(exec.sanitized_body, "hello from test target");
    }

    #[tokio::test]
    async fn test_transport_blocks_out_of_scope_redirect() {
        let base_url = spawn_mock_server().await;
        let port = base_url.split(':').last().unwrap().parse::<u16>().unwrap();

        let validator = ScopeValidator::new()
            .with_domain("127.0.0.1")
            .with_scheme("http")
            .with_port(port)
            .with_loopback_allowed(true);

        let client = SafeHttpClient::new(validator).unwrap();
        let headers = HashMap::new();

        let res = client
            .execute(
                "req-evil",
                "GET",
                &format!("{}/redirect_evil", base_url),
                &headers,
                None,
                None,
                "nonce-test",
            )
            .await;

        // Redirect to evil-unauthorized.com MUST be blocked before following
        assert!(matches!(
            res,
            Err(TransportError::ScopeValidation(ScopeError::DomainNotAllowed(_)))
        ));
    }

    #[tokio::test]
    async fn test_transport_blocks_infinite_redirect_loop() {
        let base_url = spawn_mock_server().await;
        let port = base_url.split(':').last().unwrap().parse::<u16>().unwrap();

        let validator = ScopeValidator::new()
            .with_domain("127.0.0.1")
            .with_scheme("http")
            .with_port(port)
            .with_loopback_allowed(true);

        let client = SafeHttpClient::new(validator).unwrap();
        let headers = HashMap::new();

        let res = client
            .execute(
                "req-loop",
                "GET",
                &format!("{}/redirect_loop", base_url),
                &headers,
                None,
                None,
                "nonce-test",
            )
            .await;

        assert!(matches!(
            res,
            Err(TransportError::MaxRedirectsExceeded(MAX_REDIRECT_DEPTH))
        ));
    }
}
