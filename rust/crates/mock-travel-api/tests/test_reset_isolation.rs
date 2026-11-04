//! Environment reset and state isolation tests for the Axum travel simulator.

use axum::Router;
use drishti_core::travel::{Booking, Hold, Quote};
use mock_travel_api::create_router;
use mock_travel_api::state::{AppState, ServiceMode};
use reqwest::{Client, StatusCode};
use serde_json::json;
use std::net::SocketAddr;
use tokio::net::TcpListener;

async fn spawn_test_server() -> String {
    let state = AppState::new(ServiceMode::Vulnerable);
    let app: Router = create_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://{}", addr)
}

#[tokio::test]
async fn test_environment_reset_isolation() {
    let client = Client::new();
    let base_url = spawn_test_server().await;

    // 1. Initial seed booking b-seed-001 should exist
    let seed_res = client
        .get(format!("{}/api/v1/bookings/b-seed-001", base_url))
        .header("Authorization", "Bearer test_token_agency_a")
        .send()
        .await
        .unwrap();
    assert_eq!(seed_res.status(), StatusCode::OK);
    let seed_booking: Booking = seed_res.json().await.unwrap();
    assert_eq!(seed_booking.booking_id, "b-seed-001");

    // 2. Create a new custom quotation, hold, and booking
    let q_res = client
        .post(format!("{}/api/v1/quote", base_url))
        .header("Authorization", "Bearer test_token_agency_b")
        .json(&json!({"flight_id": "6E-202", "passengers": 1}))
        .send()
        .await
        .unwrap();
    let quote: Quote = q_res.json().await.unwrap();

    let h_res = client
        .post(format!("{}/api/v1/hold", base_url))
        .header("Authorization", "Bearer test_token_agency_b")
        .json(&json!({
            "quote_id": quote.quote_id,
            "passenger_name": "Temporary Test Passenger"
        }))
        .send()
        .await
        .unwrap();
    let hold: Hold = h_res.json().await.unwrap();

    let b_res = client
        .post(format!("{}/api/v1/book", base_url))
        .header("Authorization", "Bearer test_token_agency_b")
        .json(&json!({"hold_id": hold.hold_id}))
        .send()
        .await
        .unwrap();
    let created_booking: Booking = b_res.json().await.unwrap();

    // Verify created booking exists
    let verify_res = client
        .get(format!("{}/api/v1/bookings/{}", base_url, created_booking.booking_id))
        .header("Authorization", "Bearer test_token_agency_b")
        .send()
        .await
        .unwrap();
    assert_eq!(verify_res.status(), StatusCode::OK);

    // 3. Trigger Environment Reset POST /api/v1/test/reset
    let reset_res = client
        .post(format!("{}/api/v1/test/reset", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(reset_res.status(), StatusCode::OK);

    // 4. Verify that created booking is purged
    let purged_res = client
        .get(format!("{}/api/v1/bookings/{}", base_url, created_booking.booking_id))
        .header("Authorization", "Bearer test_token_agency_b")
        .send()
        .await
        .unwrap();
    assert_eq!(purged_res.status(), StatusCode::NOT_FOUND);

    // 5. Verify that seed booking b-seed-001 is faithfully restored
    let restored_seed_res = client
        .get(format!("{}/api/v1/bookings/b-seed-001", base_url))
        .header("Authorization", "Bearer test_token_agency_a")
        .send()
        .await
        .unwrap();
    assert_eq!(restored_seed_res.status(), StatusCode::OK);
}
