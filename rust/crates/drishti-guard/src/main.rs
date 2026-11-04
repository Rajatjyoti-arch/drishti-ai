//! Entrypoint for the standalone drishti-guard daemon.

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Drishti Guard Daemon v{}", drishti_guard::VERSION);

    // Guard will listen on Unix Domain Socket /run/drishti/guard.sock
    Ok(())
}
