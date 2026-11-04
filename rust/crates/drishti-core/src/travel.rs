//! B2B Travel domain models: Quotes, Holds, Bookings, Search, and Canaries.
//!
//! Models the full travel state transition lifecycle:
//! Search ➔ Quote ➔ Hold ➔ Book (with Canary injection).

use crate::identity::TenantId;
use crate::money::{CurrencyCode, MoneyMinor};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Travel search criteria.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SearchRequest {
    /// Three-letter IATA origin airport code (e.g., "DEL")
    pub origin: String,
    /// Three-letter IATA destination airport code (e.g., "BOM")
    pub destination: String,
    /// Date of travel in YYYY-MM-DD format
    pub travel_date: String,
    /// Number of passengers
    #[serde(default = "default_passenger_count")]
    pub passengers: u32,
}

fn default_passenger_count() -> u32 {
    1
}

/// Available flight search result item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FlightOption {
    /// Flight identifier (e.g., "AI-101")
    pub flight_id: String,
    /// Operating carrier name
    pub carrier: String,
    /// Origin IATA code
    pub origin: String,
    /// Destination IATA code
    pub destination: String,
    /// Scheduled departure time
    pub departure_time: String,
    /// Base price in integer minor currency units
    pub base_price: MoneyMinor,
    /// ISO currency code
    pub currency: CurrencyCode,
}

/// Request to create a priced tariff quotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QuoteRequest {
    /// Flight identifier selected for quotation
    pub flight_id: String,
    /// Number of passenger seats
    #[serde(default = "default_passenger_count")]
    pub passengers: u32,
}

/// Server-authoritative travel quotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Quote {
    /// Unique quotation identifier
    pub quote_id: String,
    /// Referenced flight
    pub flight_id: String,
    /// Owning tenant ID
    pub tenant_id: TenantId,
    /// Base fare in minor units
    pub base_fare: MoneyMinor,
    /// Regulatory and airport taxes in minor units
    pub taxes: MoneyMinor,
    /// Total authoritative payable amount in minor units
    pub total_price: MoneyMinor,
    /// Currency code
    pub currency: CurrencyCode,
    /// Quotation timestamp
    pub created_at: DateTime<Utc>,
    /// Quotation expiration timestamp
    pub expires_at: DateTime<Utc>,
}

/// Status of an inventory reservation hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HoldStatus {
    /// Active temporary reservation
    Active,
    /// Hold expired past TTL window
    Expired,
    /// Successfully converted to confirmed booking
    Converted,
    /// Manually released
    Released,
}

/// Request to place temporary hold on quoted inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HoldRequest {
    /// Quotation ID being placed on hold
    pub quote_id: String,
    /// Primary passenger name
    pub passenger_name: String,
    /// Optional synthetic canary string to anchor multi-tenant isolation tests
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canary_token: Option<String>,
}

/// Inventory hold reservation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Hold {
    /// Unique hold identifier
    pub hold_id: String,
    /// Associated quotation ID
    pub quote_id: String,
    /// Owning tenant ID
    pub tenant_id: TenantId,
    /// Passenger name on reservation
    pub passenger_name: String,
    /// Guaranteed locked price in minor units
    pub locked_price: MoneyMinor,
    /// Currency code
    pub currency: CurrencyCode,
    /// Current hold lifecycle status
    pub status: HoldStatus,
    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Optional embedded canary for invariant verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canary_token: Option<String>,
}

/// Request to confirm and ticket a reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BookRequest {
    /// Hold ID being converted to a confirmed booking
    pub hold_id: String,
    /// Payment method identifier
    #[serde(default = "default_payment_method")]
    pub payment_method: String,
    /// Client-submitted payment amount in minor units
    /// Notice: Vulnerable implementations trust this value, while Patched
    /// implementations reject client amounts and verify authoritative quotes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_amount: Option<MoneyMinor>,
}

fn default_payment_method() -> String {
    "AGENCY_CREDIT_LINE".to_string()
}

/// Booking lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BookingStatus {
    /// Confirmed and ticketed
    Confirmed,
    /// Ticket cancelled
    Cancelled,
    /// Refunded back to agency ledger
    Refunded,
}

/// Final confirmed B2B travel booking record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Booking {
    /// Global booking reservation identifier (PNR)
    pub booking_id: String,
    /// Originating hold identifier
    pub hold_id: String,
    /// Associated quotation ID
    pub quote_id: String,
    /// Tenant that legitimately created and owns this booking
    pub tenant_id: TenantId,
    /// Primary passenger name
    pub passenger_name: String,
    /// Final debited transaction price in minor units
    pub debited_price: MoneyMinor,
    /// Currency code
    pub currency: CurrencyCode,
    /// Current booking status
    pub status: BookingStatus,
    /// Creation and ticketing timestamp
    pub created_at: DateTime<Utc>,
    /// Embedded verification canary token (if injected during test)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canary_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quote_serialization() {
        let quote = Quote {
            quote_id: "q-1001".to_string(),
            flight_id: "AI-101".to_string(),
            tenant_id: TenantId::new("agency_a"),
            base_fare: MoneyMinor::new(10000),
            taxes: MoneyMinor::new(1500),
            total_price: MoneyMinor::new(11500),
            currency: CurrencyCode::USD,
            created_at: Utc::now(),
            expires_at: Utc::now(),
        };

        let json = serde_json::to_string(&quote).unwrap();
        let parsed: Quote = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.quote_id, "q-1001");
        assert_eq!(parsed.total_price.as_i64(), 11500);
        assert_eq!(parsed.tenant_id, TenantId::new("agency_a"));
    }

    #[test]
    fn test_booking_with_canary() {
        let booking = Booking {
            booking_id: "b-2001".to_string(),
            hold_id: "h-1001".to_string(),
            quote_id: "q-1001".to_string(),
            tenant_id: TenantId::new("agency_a"),
            passenger_name: "John Doe".to_string(),
            debited_price: MoneyMinor::new(11500),
            currency: CurrencyCode::USD,
            status: BookingStatus::Confirmed,
            created_at: Utc::now(),
            canary_token: Some("drishti_canary_abc123".to_string()),
        };

        let json = serde_json::to_string(&booking).unwrap();
        assert!(json.contains("drishti_canary_abc123"));
        let parsed: Booking = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.canary_token.as_deref(), Some("drishti_canary_abc123"));
    }
}
