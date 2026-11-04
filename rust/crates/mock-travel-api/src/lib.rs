//! Mock Travel API: High-performance Axum B2B travel simulator with vulnerable and patched modes.

pub mod auth;
pub mod routes;
pub mod state;

use axum::routing::{get, post};
use axum::Router;
use state::AppState;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

/// Builds the Axum router for the mock travel API.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Flight Search
        .route("/api/v1/search", get(routes::search_flights))
        // Pricing & Quotes
        .route("/api/v1/quote", post(routes::create_quote))
        // Inventory Hold
        .route("/api/v1/hold", post(routes::create_hold))
        // Booking Confirmation
        .route("/api/v1/book", post(routes::confirm_booking))
        // Booking Inspection (BOLA target)
        .route("/api/v1/bookings/{id}", get(routes::get_booking))
        // Test Environment Reset
        .route("/api/v1/test/reset", post(routes::reset_environment))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
