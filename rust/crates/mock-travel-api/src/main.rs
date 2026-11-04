//! Binary entrypoint for the Axum mock travel simulator.

use mock_travel_api::create_router;
use mock_travel_api::state::{AppState, ServiceMode};
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8000);

    let mode_str = std::env::var("MODE").unwrap_or_else(|_| "vulnerable".into());
    let mode = if mode_str.eq_ignore_ascii_case("patched") {
        ServiceMode::Patched
    } else {
        ServiceMode::Vulnerable
    };

    let state = AppState::new(mode);
    let app = create_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Starting Drishti Mock Travel API on {} in {:?} mode", addr, mode);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
