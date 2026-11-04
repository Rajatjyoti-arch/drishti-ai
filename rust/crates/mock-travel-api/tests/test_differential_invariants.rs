//! Differential integration tests verifying I-01 (BOLA) and I-02 (Pricing)
//! across Vulnerable and Patched service modes in the Axum travel simulator.

use axum::Router;
use drishti_core::money::MoneyMinor;
use drishti_core::travel::{Booking, Hold, Quote};
use mock_travel_api::create_router;
use mock_travel_api::state::{AppState, ServiceMode};
use reqwest::{Client, StatusCode};
use serde_json::json;
use std::net::SocketAddr;
use tokio::net::TcpListener;

async fn spawn_test_server(mode: ServiceMode) -> (String, AppState) {
    let state = AppState::new(mode);
    let app: Router = create_router(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{}", addr), state)
}

#[tokio::test]
async fn test_invariant_i01_bola_differential() {
    let client = Client::new();

    // 1. VULNERABLE MODE: Cross-tenant booking read MUST expose canary (I-01 violation)
    let (vuln_url, _vuln_state) = spawn_test_server(ServiceMode::Vulnerable).await;

    // Agency A creates quote, hold with canary, and confirms booking
    let quote_res = client
        .post(format!("{}/api/v1/quote", vuln_url))
        .header("Authorization", "Bearer test_token_agency_a")
        .json(&json!({"flight_id": "AI-101", "passengers": 1}))
        .send()
        .await
        .unwrap();
    assert_eq!(quote_res.status(), StatusCode::CREATED);
    let quote: Quote = quote_res.json().await.unwrap();

    let hold_res = client
        .post(format!("{}/api/v1/hold", vuln_url))
        .header("Authorization", "Bearer test_token_agency_a")
        .json(&json!({
            "quote_id": quote.quote_id,
            "passenger_name": "Agency A VIP",
            "canary_token": "drishti_canary_bola_test_77"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(hold_res.status(), StatusCode::CREATED);
    let hold: Hold = hold_res.json().await.unwrap();

    let book_res = client
        .post(format!("{}/api/v1/book", vuln_url))
        .header("Authorization", "Bearer test_token_agency_a")
        .json(&json!({"hold_id": hold.hold_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(book_res.status(), StatusCode::CREATED);
    let booking: Booking = book_res.json().await.unwrap();

    // Agency B (Adversary tenant) attempts to read Agency A's booking
    let bola_res = client
        .get(format!("{}/api/v1/bookings/{}", vuln_url, booking.booking_id))
        .header("Authorization", "Bearer test_token_agency_b")
        .send()
        .await
        .unwrap();

    // Under vulnerable mode: 200 OK and canary token is exposed!
    assert_eq!(bola_res.status(), StatusCode::OK);
    let leaked_booking: Booking = bola_res.json().await.unwrap();
    assert_eq!(
        leaked_booking.canary_token.as_deref(),
        Some("drishti_canary_bola_test_77")
    );
    assert_eq!(leaked_booking.tenant_id.as_str(), "agency_a");

    // 2. PATCHED MODE: Cross-tenant booking read MUST return 403 Forbidden
    let (patched_url, _patched_state) = spawn_test_server(ServiceMode::Patched).await;

    // Agency A creates quote, hold, and booking on Patched server
    let q_res = client
        .post(format!("{}/api/v1/quote", patched_url))
        .header("Authorization", "Bearer test_token_agency_a")
        .json(&json!({"flight_id": "AI-101", "passengers": 1}))
        .send()
        .await
        .unwrap();
    let q: Quote = q_res.json().await.unwrap();

    let h_res = client
        .post(format!("{}/api/v1/hold", patched_url))
        .header("Authorization", "Bearer test_token_agency_a")
        .json(&json!({
            "quote_id": q.quote_id,
            "passenger_name": "Agency A Protected",
            "canary_token": "drishti_canary_protected_88"
        }))
        .send()
        .await
        .unwrap();
    let h: Hold = h_res.json().await.unwrap();

    let b_res = client
        .post(format!("{}/api/v1/book", patched_url))
        .header("Authorization", "Bearer test_token_agency_a")
        .json(&json!({"hold_id": h.hold_id}))
        .send()
        .await
        .unwrap();
    let b: Booking = b_res.json().await.unwrap();

    // Agency B attempts cross-tenant read on Patched server
    let defense_res = client
        .get(format!("{}/api/v1/bookings/{}", patched_url, b.booking_id))
        .header("Authorization", "Bearer test_token_agency_b")
        .send()
        .await
        .unwrap();

    // Under patched mode: 403 Forbidden; canary is never leaked
    assert_eq!(defense_res.status(), StatusCode::FORBIDDEN);

    // Legitimate owner (Agency A) CAN still read their own booking
    let authorized_read = client
        .get(format!("{}/api/v1/bookings/{}", patched_url, b.booking_id))
        .header("Authorization", "Bearer test_token_agency_a")
        .send()
        .await
        .unwrap();
    assert_eq!(authorized_read.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_invariant_i02_pricing_differential() {
    let client = Client::new();

    // 1. VULNERABLE MODE: Submitting client_amount = 100 ($1.00) charges $1.00 instead of $115.00
    let (vuln_url, _vuln_state) = spawn_test_server(ServiceMode::Vulnerable).await;

    let quote_res = client
        .post(format!("{}/api/v1/quote", vuln_url))
        .header("Authorization", "Bearer test_token_agency_a")
        .json(&json!({"flight_id": "AI-101"}))
        .send()
        .await
        .unwrap();
    let quote: Quote = quote_res.json().await.unwrap();
    assert_eq!(quote.total_price, MoneyMinor::new(11500)); // $115.00

    let hold_res = client
        .post(format!("{}/api/v1/hold", vuln_url))
        .header("Authorization", "Bearer test_token_agency_a")
        .json(&json!({
            "quote_id": quote.quote_id,
            "passenger_name": "Price Tamperer"
        }))
        .send()
        .await
        .unwrap();
    let hold: Hold = hold_res.json().await.unwrap();

    // Malicious booking request tampering price down to 100 minor units ($1.00)
    let tamper_res = client
        .post(format!("{}/api/v1/book", vuln_url))
        .header("Authorization", "Bearer test_token_agency_a")
        .json(&json!({
            "hold_id": hold.hold_id,
            "client_amount": 100
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(tamper_res.status(), StatusCode::CREATED);
    let tampered_booking: Booking = tamper_res.json().await.unwrap();
    // In Vulnerable mode, the system accepts $1.00!
    assert_eq!(tampered_booking.debited_price, MoneyMinor::new(100));

    // 2. PATCHED MODE: Submitting client_amount = 100 MUST be rejected with 400 Bad Request
    let (patched_url, _patched_state) = spawn_test_server(ServiceMode::Patched).await;

    let q_res = client
        .post(format!("{}/api/v1/quote", patched_url))
        .header("Authorization", "Bearer test_token_agency_a")
        .json(&json!({"flight_id": "AI-101"}))
        .send()
        .await
        .unwrap();
    let q: Quote = q_res.json().await.unwrap();

    let h_res = client
        .post(format!("{}/api/v1/hold", patched_url))
        .header("Authorization", "Bearer test_token_agency_a")
        .json(&json!({
            "quote_id": q.quote_id,
            "passenger_name": "Protected Passenger"
        }))
        .send()
        .await
        .unwrap();
    let h: Hold = h_res.json().await.unwrap();

    // Tampered request on patched mode
    let defense_res = client
        .post(format!("{}/api/v1/book", patched_url))
        .header("Authorization", "Bearer test_token_agency_a")
        .json(&json!({
            "hold_id": h.hold_id,
            "client_amount": 100
        }))
        .send()
        .await
        .unwrap();

    // In Patched mode: 400 Bad Request tariff integrity rejection!
    assert_eq!(defense_res.status(), StatusCode::BAD_REQUEST);

    // Legitimate confirmation (without tampered client amount) succeeds at full authoritative price
    let legit_res = client
        .post(format!("{}/api/v1/book", patched_url))
        .header("Authorization", "Bearer test_token_agency_a")
        .json(&json!({"hold_id": h.hold_id}))
        .send()
        .await
        .unwrap();

    assert_eq!(legit_res.status(), StatusCode::CREATED);
    let legit_booking: Booking = legit_res.json().await.unwrap();
    assert_eq!(legit_booking.debited_price, MoneyMinor::new(11500));
}
