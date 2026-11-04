//! Golden serialization tests verifying exact JSON representations and invariants.

use chrono::{TimeZone, Utc};
use drishti_core::identity::*;
use drishti_core::money::*;
use drishti_core::policy::*;
use drishti_core::travel::*;
use std::collections::HashMap;

#[test]
fn test_golden_tenant_context() {
    let ctx = TenantContext {
        tenant_id: TenantId::new("agency_a"),
        user_id: UserId::new("user_123"),
        role: UserRole::Agent,
        session_id: Some("sess_abc".to_string()),
    };

    let json = serde_json::to_string(&ctx).unwrap();
    assert_eq!(
        json,
        r#"{"tenant_id":"agency_a","user_id":"user_123","role":"agent","session_id":"sess_abc"}"#
    );

    let roundtrip: TenantContext = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtrip, ctx);
}

#[test]
fn test_golden_money_minor() {
    let money = Money {
        amount: MoneyMinor::new(12550),
        currency: CurrencyCode::USD,
    };

    let json = serde_json::to_string(&money).unwrap();
    assert_eq!(json, r#"{"amount":12550,"currency":"USD"}"#);

    let roundtrip: Money = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtrip.amount.as_i64(), 12550);
    assert_eq!(roundtrip.amount.to_major_f64(), 125.50);
}

#[test]
fn test_golden_quote_and_booking_with_canary() {
    let timestamp = Utc.with_ymd_and_hms(2026, 11, 5, 0, 0, 0).unwrap();

    let quote = Quote {
        quote_id: "q-test-99".to_string(),
        flight_id: "AI-202".to_string(),
        tenant_id: TenantId::new("agency_b"),
        base_fare: MoneyMinor::new(50000),
        taxes: MoneyMinor::new(7500),
        total_price: MoneyMinor::new(57500),
        currency: CurrencyCode::INR,
        created_at: timestamp,
        expires_at: timestamp,
    };

    let quote_json = serde_json::to_string(&quote).unwrap();
    assert!(quote_json.contains(r#""tenant_id":"agency_b""#));
    assert!(quote_json.contains(r#""total_price":57500"#));

    let booking = Booking {
        booking_id: "b-test-99".to_string(),
        hold_id: "h-test-99".to_string(),
        quote_id: "q-test-99".to_string(),
        tenant_id: TenantId::new("agency_b"),
        passenger_name: "Alice Smith".to_string(),
        debited_price: MoneyMinor::new(57500),
        currency: CurrencyCode::INR,
        status: BookingStatus::Confirmed,
        created_at: timestamp,
        canary_token: Some("drishti_canary_sec_val_42".to_string()),
    };

    let booking_json = serde_json::to_string(&booking).unwrap();
    assert!(booking_json.contains(r#""canary_token":"drishti_canary_sec_val_42""#));
    assert!(booking_json.contains(r#""status":"confirmed""#));

    let roundtrip_booking: Booking = serde_json::from_str(&booking_json).unwrap();
    assert_eq!(roundtrip_booking.booking_id, "b-test-99");
    assert_eq!(
        roundtrip_booking.canary_token.as_deref(),
        Some("drishti_canary_sec_val_42")
    );
}

#[test]
fn test_golden_outgoing_request_and_decision() {
    let timestamp = Utc.with_ymd_and_hms(2026, 11, 5, 0, 0, 0).unwrap();

    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());

    let req = OutgoingTestRequest {
        request_id: "req-sec-01".to_string(),
        test_id: "test-pricing-01".to_string(),
        target_url: "http://127.0.0.1:8000/api/v1/book".to_string(),
        method: "POST".to_string(),
        headers,
        body: Some(r#"{"hold_id":"h-1","client_amount":100}"#.to_string()),
        tenant_context: Some(TenantContext {
            tenant_id: TenantId::new("agency_a"),
            user_id: UserId::new("agent_1"),
            role: UserRole::Agent,
            session_id: None,
        }),
        credential_ref: Some("agency_a_key".to_string()),
        invariant_candidate: Some(InvariantId::I02),
        timeout_ms: 5000,
    };

    let req_json = serde_json::to_string(&req).unwrap();
    assert!(req_json.contains(r#""invariant_candidate":"I-02""#));
    assert!(req_json.contains(r#""credential_ref":"agency_a_key""#));

    let decision = PolicyDecision {
        action: PolicyAction::Allow,
        reason: "Target within authorized scope and test budgets compliant".to_string(),
        rule_matched: "SCOPE_ALLOWLIST_AND_BUDGET_VERIFIED".to_string(),
        decision_nonce: "nonce_sec_99a8b7c6".to_string(),
        bound_request_digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        evaluated_at: timestamp,
    };

    let decision_json = serde_json::to_string(&decision).unwrap();
    assert!(decision_json.contains(r#""action":"allow""#));
    assert!(decision_json.contains(r#""decision_nonce":"nonce_sec_99a8b7c6""#));
}
