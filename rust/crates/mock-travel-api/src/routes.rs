//! Shared B2B travel route handlers implementing both Vulnerable and Patched behaviors.

use crate::auth::AuthContext;
use crate::state::{AppState, ServiceMode};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};
use drishti_core::money::*;
use drishti_core::travel::*;
use serde::Deserialize;
use serde_json::json;

/// Query parameters for flight search.
#[derive(Debug, Deserialize)]
pub struct SearchParams {
    pub origin: String,
    pub destination: String,
    #[serde(default)]
    pub travel_date: Option<String>,
}

/// Helper to determine active mode (header takes precedence, then state default).
fn resolve_mode(headers: &HeaderMap, state: &AppState) -> ServiceMode {
    if let Some(mode_hdr) = headers.get("x-drishti-mode") {
        if let Ok(s) = mode_hdr.to_str() {
            if s.eq_ignore_ascii_case("patched") {
                return ServiceMode::Patched;
            } else if s.eq_ignore_ascii_case("vulnerable") {
                return ServiceMode::Vulnerable;
            }
        }
    }
    state.mode()
}

/// GET /api/v1/search
pub async fn search_flights(
    State(state): State<AppState>,
    _auth: AuthContext,
    Query(params): Query<SearchParams>,
) -> Response {
    let results = state.search_flights(&params.origin, &params.destination);
    Json(results).into_response()
}

/// POST /api/v1/quote
pub async fn create_quote(
    State(state): State<AppState>,
    AuthContext(tenant): AuthContext,
    Json(req): Json<QuoteRequest>,
) -> Response {
    let quote_id = state.next_id("q");
    let now = Utc::now();

    // Default base fare calculation
    let base_fare = MoneyMinor::new(10000); // $100.00
    let taxes = MoneyMinor::new(1500);      // $15.00
    let total = base_fare + taxes;

    let quote = Quote {
        quote_id,
        flight_id: req.flight_id,
        tenant_id: tenant.tenant_id,
        base_fare,
        taxes,
        total_price: total,
        currency: CurrencyCode::USD,
        created_at: now,
        expires_at: now + Duration::hours(2),
    };

    state.insert_quote(quote.clone());
    (StatusCode::CREATED, Json(quote)).into_response()
}

/// POST /api/v1/hold
pub async fn create_hold(
    State(state): State<AppState>,
    AuthContext(tenant): AuthContext,
    Json(req): Json<HoldRequest>,
) -> Response {
    let quote = match state.get_quote(&req.quote_id) {
        Some(q) => q,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "QUOTE_NOT_FOUND", "message": "Quotation not found"})),
            )
                .into_response();
        }
    };

    let hold_id = state.next_id("h");
    let now = Utc::now();

    let hold = Hold {
        hold_id,
        quote_id: req.quote_id,
        tenant_id: tenant.tenant_id,
        passenger_name: req.passenger_name,
        locked_price: quote.total_price,
        currency: quote.currency,
        status: HoldStatus::Active,
        expires_at: now + Duration::minutes(30),
        canary_token: req.canary_token,
    };

    state.insert_hold(hold.clone());
    (StatusCode::CREATED, Json(hold)).into_response()
}

/// POST /api/v1/book
pub async fn confirm_booking(
    State(state): State<AppState>,
    headers: HeaderMap,
    AuthContext(tenant): AuthContext,
    Json(req): Json<BookRequest>,
) -> Response {
    let mode = resolve_mode(&headers, &state);

    let hold = match state.get_hold(&req.hold_id) {
        Some(h) => h,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "HOLD_NOT_FOUND", "message": "Hold reservation not found"})),
            )
                .into_response();
        }
    };

    // Evaluate Mode Differences for I-01 / I-02:
    let debited_price = match mode {
        ServiceMode::Vulnerable => {
            // VULNERABLE MODE (I-02 Flaw):
            // Accepts client-submitted amount directly without validating against authoritative quote!
            if let Some(client_amt) = req.client_amount {
                client_amt
            } else {
                hold.locked_price
            }
        }
        ServiceMode::Patched => {
            // PATCHED MODE (I-01 & I-02 Defense):
            // 1. Strictly verify tenant ownership
            if hold.tenant_id != tenant.tenant_id {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "CROSS_TENANT_ACCESS_DENIED",
                        "message": "Tenant is not authorized to convert hold belonging to another agency"
                    })),
                )
                    .into_response();
            }

            // 2. Reject client-tampered pricing; enforce server-authoritative quote price
            if let Some(client_amt) = req.client_amount {
                if client_amt != hold.locked_price {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "TARIFF_INTEGRITY_VIOLATION",
                            "message": "Client amount does not match authoritative locked hold price"
                        })),
                    )
                        .into_response();
                }
            }

            hold.locked_price
        }
    };

    let booking_id = state.next_id("b");
    let now = Utc::now();

    let booking = Booking {
        booking_id,
        hold_id: hold.hold_id.clone(),
        quote_id: hold.quote_id.clone(),
        tenant_id: hold.tenant_id,
        passenger_name: hold.passenger_name,
        debited_price,
        currency: hold.currency,
        status: BookingStatus::Confirmed,
        created_at: now,
        canary_token: hold.canary_token,
    };

    state.update_hold_status(&hold.hold_id, HoldStatus::Converted);
    state.insert_booking(booking.clone());

    (StatusCode::CREATED, Json(booking)).into_response()
}

/// GET /api/v1/bookings/:id
pub async fn get_booking(
    State(state): State<AppState>,
    headers: HeaderMap,
    AuthContext(tenant): AuthContext,
    Path(booking_id): Path<String>,
) -> Response {
    let mode = resolve_mode(&headers, &state);

    let booking = match state.get_booking(&booking_id) {
        Some(b) => b,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "BOOKING_NOT_FOUND", "message": "Booking reservation not found"})),
            )
                .into_response();
        }
    };

    match mode {
        ServiceMode::Vulnerable => {
            // VULNERABLE MODE (I-01 BOLA Flaw):
            // Exposes full booking record and passenger PII / canary token to ANY authenticated tenant!
            Json(booking).into_response()
        }
        ServiceMode::Patched => {
            // PATCHED MODE (I-01 Defense):
            // Enforces strict tenant ownership check
            if booking.tenant_id != tenant.tenant_id {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "TENANT_ISOLATION_VIOLATION",
                        "message": "Access denied: booking belongs to another agency"
                    })),
                )
                    .into_response();
            }
            Json(booking).into_response()
        }
    }
}

/// POST /api/v1/test/reset
pub async fn reset_environment(State(mut state): State<AppState>) -> Response {
    state.reset();
    Json(json!({
        "status": "ok",
        "message": "Environment reset complete; seed fixtures restored"
    }))
    .into_response()
}
