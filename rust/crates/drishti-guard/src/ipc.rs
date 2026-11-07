//! Unix Domain Socket IPC Server for local process-isolated communication with Python.
//!
//! Enforces:
//! 1. Protocol version validation (rejects unsupported versions).
//! 2. Strict maximum payload size limit (rejects oversized messages).
//! 3. Bounded concurrency and per-request timeouts.
//! 4. Process-isolated Unix Domain Socket boundary.

use crate::gate::{GateError, PolicyGate};
use drishti_core::policy::{ExecutionResult, OutgoingTestRequest};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Current supported IPC protocol version.
pub const CURRENT_IPC_VERSION: &str = "1.0";

/// Maximum permitted IPC message frame size (1 Megabyte).
pub const MAX_IPC_MESSAGE_BYTES: usize = 1024 * 1024;

/// Maximum simultaneous client connections permitted on the socket.
pub const MAX_CONCURRENT_IPC_CONNECTIONS: usize = 64;

/// Maximum duration allowed for a client to transmit its request frame (5 seconds).
pub const IPC_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Incoming IPC command payload from the Python Intelligence Layer.
#[derive(Debug, Serialize, Deserialize)]
pub struct IpcCommand {
    /// Protocol version string
    pub version: String,
    /// Outgoing test request to evaluate and execute
    pub request: OutgoingTestRequest,
}

/// Outgoing IPC response returned to Python.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IpcResponse {
    Ok { result: ExecutionResult },
    Error { message: String, error_code: String },
}

/// Standalone Unix Domain Socket server managing IPC lifecycle.
pub struct IpcServer {
    socket_path: PathBuf,
    gate: Arc<PolicyGate>,
}

impl IpcServer {
    /// Constructs a new IPC server listening on the specified socket path.
    pub fn new(socket_path: impl AsRef<Path>, gate: Arc<PolicyGate>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            gate,
        }
    }

    /// Binds the Unix domain socket and enters the asynchronous accept loop.
    pub async fn run(&self) -> Result<(), std::io::Error> {
        // Safe socket cleanup: verify existing path is indeed a socket before unlinking
        if self.socket_path.exists() {
            if let Ok(meta) = fs::symlink_metadata(&self.socket_path) {
                if meta.file_type().is_socket() {
                    let _ = fs::remove_file(&self.socket_path);
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("Target socket path {:?} exists but is not a socket", self.socket_path),
                    ));
                }
            }
        }

        // Ensure parent directory exists
        if let Some(parent) = self.socket_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;

        // Set restrictive socket permissions (0600: read/write only by owner process)
        let metadata = fs::metadata(&self.socket_path)?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&self.socket_path, perms)?;

        tracing::info!("Drishti Guard IPC server listening on {:?}", self.socket_path);

        let connection_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_IPC_CONNECTIONS));

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    // Acquire owned connection permit before spawning task to prevent task starvation
                    let permit = match connection_semaphore.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            tracing::warn!("IPC server saturated: maximum concurrent connections reached; dropping connection");
                            drop(stream);
                            continue;
                        }
                    };

                    let gate_clone = Arc::clone(&self.gate);
                    tokio::spawn(async move {
                        let _permit = permit;
                        handle_client(stream, gate_clone).await;
                    });
                }
                Err(e) => {
                    tracing::warn!("Failed to accept incoming IPC connection: {}", e);
                }
            }
        }
    }
}

async fn handle_client(mut stream: UnixStream, gate: Arc<PolicyGate>) {
    let (reader, mut writer) = stream.split();
    // Wrap reader with .take() to strictly bound in-memory allocation during read
    let bounded_reader = reader.take((MAX_IPC_MESSAGE_BYTES + 1) as u64);
    let mut buf_reader = BufReader::new(bounded_reader);
    let mut line = String::new();

    // Enforce per-connection read timeout to prevent slowloris starvation
    let read_result = timeout(IPC_READ_TIMEOUT, buf_reader.read_line(&mut line)).await;

    match read_result {
        Ok(Ok(0)) => return, // Connection closed cleanly
        Ok(Ok(bytes_read)) => {
            if bytes_read > MAX_IPC_MESSAGE_BYTES || line.len() > MAX_IPC_MESSAGE_BYTES {
                let err_resp = IpcResponse::Error {
                    message: format!(
                        "IPC payload exceeded maximum permitted size limit ({} bytes)",
                        MAX_IPC_MESSAGE_BYTES
                    ),
                    error_code: "PAYLOAD_TOO_LARGE".to_string(),
                };
                let _ = send_response(&mut writer, &err_resp).await;
                return;
            }
        }
        Ok(Err(e)) => {
            tracing::error!("IPC stream read error: {}", e);
            return;
        }
        Err(_) => {
            let err_resp = IpcResponse::Error {
                message: "IPC request read timed out".to_string(),
                error_code: "READ_TIMEOUT".to_string(),
            };
            let _ = send_response(&mut writer, &err_resp).await;
            return;
        }
    }

    // Parse and validate version
    let cmd: IpcCommand = match serde_json::from_str(&line) {
        Ok(c) => c,
        Err(e) => {
            let err_resp = IpcResponse::Error {
                message: format!("Malformed IPC JSON request: {}", e),
                error_code: "MALFORMED_JSON".to_string(),
            };
            let _ = send_response(&mut writer, &err_resp).await;
            return;
        }
    };

    if cmd.version != CURRENT_IPC_VERSION {
        let err_resp = IpcResponse::Error {
            message: format!(
                "Unsupported IPC protocol version: {} (expected {})",
                cmd.version, CURRENT_IPC_VERSION
            ),
            error_code: "UNSUPPORTED_VERSION".to_string(),
        };
        let _ = send_response(&mut writer, &err_resp).await;
        return;
    }

    // Execute via PolicyGate
    let response = match gate.execute_request(&cmd.request).await {
        Ok(exec_result) => IpcResponse::Ok { result: exec_result },
        Err(err) => {
            let (code, msg) = match err {
                GateError::Scope(e) => ("SCOPE_VIOLATION", e.to_string()),
                GateError::RateLimit(e) => ("RATE_LIMIT_EXHAUSTED", e.to_string()),
                GateError::Credential(e) => ("CREDENTIAL_ERROR", e.to_string()),
                GateError::Transport(e) => ("TRANSPORT_ERROR", e.to_string()),
                GateError::AuditBeforeSendFailed(e) => ("AUDIT_FAILURE", e.to_string()),
                GateError::Audit(e) => ("AUDIT_FAILURE", e.to_string()),
            };
            IpcResponse::Error {
                message: msg,
                error_code: code.to_string(),
            }
        }
    };

    let _ = send_response(&mut writer, &response).await;
}

async fn send_response(
    writer: &mut tokio::net::unix::WriteHalf<'_>,
    resp: &IpcResponse,
) -> Result<(), std::io::Error> {
    let mut serialized = serde_json::to_string(resp).unwrap();
    if serialized.len() > MAX_IPC_MESSAGE_BYTES {
        let err_resp = IpcResponse::Error {
            message: format!(
                "IPC response exceeded maximum frame limit ({} bytes)",
                MAX_IPC_MESSAGE_BYTES
            ),
            error_code: "RESPONSE_TOO_LARGE".to_string(),
        };
        serialized = serde_json::to_string(&err_resp).unwrap();
    }
    serialized.push('\n');
    writer.write_all(serialized.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_broker::CredentialBroker;
    use crate::ledger::AuditLedger;
    use crate::rate_limiter::{MultiBudgetRateLimiter, RateLimiterConfig};
    use crate::scope_validator::ScopeValidator;
    use tempfile::NamedTempFile;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

    #[tokio::test]
    async fn test_ipc_rejects_unsupported_protocol_version() {
        let temp_socket = NamedTempFile::new().unwrap();
        let socket_path = temp_socket.path().to_path_buf();
        let _ = fs::remove_file(&socket_path);

        let temp_db = NamedTempFile::new().unwrap();
        let validator = ScopeValidator::new();
        let limiter = MultiBudgetRateLimiter::new(RateLimiterConfig::default());
        let broker = Arc::new(CredentialBroker::new());
        let ledger = AuditLedger::open(temp_db.path()).unwrap();
        let gate = Arc::new(PolicyGate::new(validator, limiter, broker, ledger).unwrap());

        let server = IpcServer::new(&socket_path, gate);
        let srv_socket = socket_path.clone();

        tokio::spawn(async move {
            server.run().await.unwrap();
        });

        // Wait briefly for socket creation
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let mut client = UnixStream::connect(&srv_socket).await.unwrap();

        // Send invalid version 9.9
        let invalid_req = serde_json::json!({
            "version": "9.9",
            "request": {
                "request_id": "r1",
                "test_id": "t1",
                "target_url": "https://api.travel.com",
                "method": "GET",
                "headers": {},
                "timeout_ms": 1000
            }
        });

        let mut data = serde_json::to_string(&invalid_req).unwrap();
        data.push('\n');
        client.write_all(data.as_bytes()).await.unwrap();

        let mut reader = BufReader::new(client);
        let mut resp_line = String::new();
        reader.read_line(&mut resp_line).await.unwrap();

        let resp: IpcResponse = serde_json::from_str(&resp_line).unwrap();
        match resp {
            IpcResponse::Error { error_code, .. } => {
                assert_eq!(error_code, "UNSUPPORTED_VERSION");
            }
            _ => panic!("Expected version rejection error"),
        }
    }
}
