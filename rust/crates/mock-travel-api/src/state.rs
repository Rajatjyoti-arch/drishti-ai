//! In-memory state storage for B2B travel simulation.

use chrono::{Duration, Utc};
use drishti_core::identity::*;
use drishti_core::money::*;
use drishti_core::travel::*;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Operational mode for the travel service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceMode {
    /// Vulnerable to I-01 (BOLA) and I-02 (Tariff Tampering)
    Vulnerable,
    /// Secure implementation with tenant isolation and authoritative pricing
    Patched,
}

impl Default for ServiceMode {
    fn default() -> Self {
        Self::Vulnerable
    }
}

/// Core in-memory state store.
#[derive(Debug, Clone)]
pub struct AppState {
    inner: Arc<RwLock<AppStateInner>>,
}

#[derive(Debug)]
pub struct AppStateInner {
    pub mode: ServiceMode,
    pub flights: Vec<FlightOption>,
    pub quotes: HashMap<String, Quote>,
    pub holds: HashMap<String, Hold>,
    pub bookings: HashMap<String, Booking>,
    pub counter: u64,
}

impl AppState {
    /// Initialize state with default seed flight catalog.
    pub fn new(mode: ServiceMode) -> Self {
        let mut state = Self {
            inner: Arc::new(RwLock::new(AppStateInner {
                mode,
                flights: Vec::new(),
                quotes: HashMap::new(),
                holds: HashMap::new(),
                bookings: HashMap::new(),
                counter: 1000,
            })),
        };
        state.reset();
        state
    }

    /// Reset all state to clean initial seed fixtures.
    pub fn reset(&mut self) {
        let mut inner = self.inner.write().unwrap();
        inner.quotes.clear();
        inner.holds.clear();
        inner.bookings.clear();
        inner.counter = 1000;

        inner.flights = vec![
            FlightOption {
                flight_id: "AI-101".to_string(),
                carrier: "Air India".to_string(),
                origin: "DEL".to_string(),
                destination: "BOM".to_string(),
                departure_time: "08:00".to_string(),
                base_price: MoneyMinor::new(10000), // $100.00
                currency: CurrencyCode::USD,
            },
            FlightOption {
                flight_id: "6E-202".to_string(),
                carrier: "IndiGo".to_string(),
                origin: "DEL".to_string(),
                destination: "BLR".to_string(),
                departure_time: "11:30".to_string(),
                base_price: MoneyMinor::new(12500), // $125.00
                currency: CurrencyCode::USD,
            },
            FlightOption {
                flight_id: "EK-505".to_string(),
                carrier: "Emirates".to_string(),
                origin: "BOM".to_string(),
                destination: "DXB".to_string(),
                departure_time: "16:45".to_string(),
                base_price: MoneyMinor::new(35000), // $350.00
                currency: CurrencyCode::USD,
            },
        ];

        // Seed an initial booking for Agency A with an embedded canary
        let seed_quote_id = "q-seed-001".to_string();
        let seed_hold_id = "h-seed-001".to_string();
        let seed_booking_id = "b-seed-001".to_string();

        let now = Utc::now();
        let seed_quote = Quote {
            quote_id: seed_quote_id.clone(),
            flight_id: "AI-101".to_string(),
            tenant_id: TenantId::new("agency_a"),
            base_fare: MoneyMinor::new(10000),
            taxes: MoneyMinor::new(1500),
            total_price: MoneyMinor::new(11500),
            currency: CurrencyCode::USD,
            created_at: now,
            expires_at: now + Duration::hours(2),
        };

        let seed_booking = Booking {
            booking_id: seed_booking_id.clone(),
            hold_id: seed_hold_id,
            quote_id: seed_quote_id,
            tenant_id: TenantId::new("agency_a"),
            passenger_name: "Initial Seed Passenger".to_string(),
            debited_price: MoneyMinor::new(11500),
            currency: CurrencyCode::USD,
            status: BookingStatus::Confirmed,
            created_at: now,
            canary_token: Some("drishti_canary_seed_tenant_a".to_string()),
        };

        inner.quotes.insert(seed_quote.quote_id.clone(), seed_quote);
        inner.bookings.insert(seed_booking.booking_id.clone(), seed_booking);
    }

    /// Read service mode.
    pub fn mode(&self) -> ServiceMode {
        self.inner.read().unwrap().mode
    }

    /// Set service mode dynamically (for testing).
    pub fn set_mode(&self, mode: ServiceMode) {
        self.inner.write().unwrap().mode = mode;
    }

    /// Generate an incrementing unique identifier.
    pub fn next_id(&self, prefix: &str) -> String {
        let mut inner = self.inner.write().unwrap();
        inner.counter += 1;
        format!("{}-{}", prefix, inner.counter)
    }

    /// Search available flights matching criteria.
    pub fn search_flights(&self, origin: &str, destination: &str) -> Vec<FlightOption> {
        let inner = self.inner.read().unwrap();
        inner
            .flights
            .iter()
            .filter(|f| f.origin.eq_ignore_ascii_case(origin) && f.destination.eq_ignore_ascii_case(destination))
            .cloned()
            .collect()
    }

    /// Store a new quotation.
    pub fn insert_quote(&self, quote: Quote) {
        let mut inner = self.inner.write().unwrap();
        inner.quotes.insert(quote.quote_id.clone(), quote);
    }

    /// Retrieve a quotation by ID.
    pub fn get_quote(&self, quote_id: &str) -> Option<Quote> {
        let inner = self.inner.read().unwrap();
        inner.quotes.get(quote_id).cloned()
    }

    /// Store a new reservation hold.
    pub fn insert_hold(&self, hold: Hold) {
        let mut inner = self.inner.write().unwrap();
        inner.holds.insert(hold.hold_id.clone(), hold);
    }

    /// Retrieve a hold by ID.
    pub fn get_hold(&self, hold_id: &str) -> Option<Hold> {
        let inner = self.inner.read().unwrap();
        inner.holds.get(hold_id).cloned()
    }

    /// Update hold status.
    pub fn update_hold_status(&self, hold_id: &str, status: HoldStatus) {
        let mut inner = self.inner.write().unwrap();
        if let Some(hold) = inner.holds.get_mut(hold_id) {
            hold.status = status;
        }
    }

    /// Store a confirmed booking.
    pub fn insert_booking(&self, booking: Booking) {
        let mut inner = self.inner.write().unwrap();
        inner.bookings.insert(booking.booking_id.clone(), booking);
    }

    /// Retrieve a booking by ID.
    pub fn get_booking(&self, booking_id: &str) -> Option<Booking> {
        let inner = self.inner.read().unwrap();
        inner.bookings.get(booking_id).cloned()
    }
}
