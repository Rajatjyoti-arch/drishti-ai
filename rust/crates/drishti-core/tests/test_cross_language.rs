//! Cross-language compatibility tests verifying that JSON produced by
//! Python Stage 1 and Stage 2 models deserializes cleanly into Rust core models.

use drishti_core::identity::*;
use drishti_core::policy::*;
use drishti_core::travel::*;

#[test]
fn test_python_outgoing_request_cross_compatibility() {
    // Exact JSON serialized from Python OutgoingTestRequest dataclass/Pydantic
    let python_json = r#"{
        "request_id": "py-req-001",
        "test_id": "test-bola-cross-lang",
        "target_url": "http://127.0.0.1:8000/api/v1/bookings/b_cross_10",
        "method": "GET",
        "headers": {
            "Accept": "application/json",
            "User-Agent": "DrishtiDAST/1.0"
        },
        "body": null,
        "tenant_context": {
            "tenant_id": "agency_b",
            "user_id": "user_b_01",
            "role": "agent"
        },
        "credential_ref": "agency_b_session",
        "invariant_candidate": "I-01",
        "timeout_ms": 5000
    }"#;

    let parsed: OutgoingTestRequest = serde_json::from_str(python_json).unwrap();
    assert_eq!(parsed.request_id, "py-req-001");
    assert_eq!(parsed.invariant_candidate, Some(InvariantId::I01));
    assert_eq!(parsed.credential_ref.as_deref(), Some("agency_b_session"));

    let tenant = parsed.tenant_context.unwrap();
    assert_eq!(tenant.tenant_id, TenantId::new("agency_b"));
    assert_eq!(tenant.role, UserRole::Agent);
}

#[test]
fn test_python_booking_cross_compatibility() {
    // Exact JSON response returned by mock_travel_api.py / vulnerable_app.py
    let python_booking_json = r#"{
        "booking_id": "b_agA_9918",
        "hold_id": "h_agA_5521",
        "quote_id": "q_DEL_BOM_101",
        "tenant_id": "agency_a",
        "passenger_name": "Canary Passenger",
        "debited_price": 45000,
        "currency": "USD",
        "status": "confirmed",
        "created_at": "2026-11-05T00:00:00Z",
        "canary_token": "drishti_canary_stage2_valid"
    }"#;

    let parsed: Booking = serde_json::from_str(python_booking_json).unwrap();
    assert_eq!(parsed.booking_id, "b_agA_9918");
    assert_eq!(parsed.tenant_id, TenantId::new("agency_a"));
    assert_eq!(parsed.debited_price.as_i64(), 45000);
    assert_eq!(parsed.status, BookingStatus::Confirmed);
    assert_eq!(
        parsed.canary_token.as_deref(),
        Some("drishti_canary_stage2_valid")
    );
}

#[test]
fn test_python_hold_cross_compatibility() {
    let python_hold_json = r#"{
        "hold_id": "h_hold_1234",
        "quote_id": "q_quote_5678",
        "tenant_id": "agency_b",
        "passenger_name": "Bob Smith",
        "locked_price": 32000,
        "currency": "INR",
        "status": "active",
        "expires_at": "2026-11-05T01:00:00Z",
        "canary_token": null
    }"#;

    let parsed: Hold = serde_json::from_str(python_hold_json).unwrap();
    assert_eq!(parsed.hold_id, "h_hold_1234");
    assert_eq!(parsed.locked_price.as_i64(), 32000);
    assert_eq!(parsed.status, HoldStatus::Active);
    assert!(parsed.canary_token.is_none());
}
