//! Monetary representations using integer minor units (e.g., cents, paise)
//! to prevent floating-point rounding errors and tariff manipulation vulnerabilities.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::{Add, Sub};
use std::str::FromStr;

/// ISO 4217 Three-letter Currency Code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum CurrencyCode {
    /// United States Dollar
    USD,
    /// Indian Rupee
    INR,
    /// Euro
    EUR,
    /// British Pound Sterling
    GBP,
    /// United Arab Emirates Dirham
    AED,
    /// Singapore Dollar
    SGD,
}

impl fmt::Display for CurrencyCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::USD => write!(f, "USD"),
            Self::INR => write!(f, "INR"),
            Self::EUR => write!(f, "EUR"),
            Self::GBP => write!(f, "GBP"),
            Self::AED => write!(f, "AED"),
            Self::SGD => write!(f, "SGD"),
        }
    }
}

impl FromStr for CurrencyCode {
    type Err = MoneyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "USD" => Ok(Self::USD),
            "INR" => Ok(Self::INR),
            "EUR" => Ok(Self::EUR),
            "GBP" => Ok(Self::GBP),
            "AED" => Ok(Self::AED),
            "SGD" => Ok(Self::SGD),
            other => Err(MoneyError::UnsupportedCurrency(other.to_string())),
        }
    }
}

/// Monetary amount represented strictly as an integer in minor currency units
/// (e.g., $150.75 USD = 15075 cents).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(transparent)]
pub struct MoneyMinor(pub i64);

impl MoneyMinor {
    /// Zero monetary amount.
    pub const ZERO: Self = Self(0);

    /// Construct from raw minor units.
    pub const fn new(minor: i64) -> Self {
        Self(minor)
    }

    /// Construct from major units (e.g., 100 dollars = 10,000 cents).
    pub fn from_major(major: i64) -> Result<Self, MoneyError> {
        major
            .checked_mul(100)
            .map(Self)
            .ok_or(MoneyError::Overflow)
    }

    /// Convert minor units to floating-point major amount (for display/reporting only).
    pub fn to_major_f64(&self) -> f64 {
        self.0 as f64 / 100.0
    }

    /// Checked addition.
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }

    /// Checked subtraction.
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(Self)
    }

    /// Checked multiplication by integer scalar.
    pub fn checked_mul(self, scalar: i64) -> Option<Self> {
        self.0.checked_mul(scalar).map(Self)
    }

    /// Returns the raw integer minor units.
    pub const fn as_i64(&self) -> i64 {
        self.0
    }
}

impl fmt::Display for MoneyMinor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0 / 100;
        let frac = (self.0 % 100).abs();
        write!(f, "{}.{:02}", whole, frac)
    }
}

impl Add for MoneyMinor {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        self.checked_add(rhs).expect("Monetary arithmetic overflow")
    }
}

impl Sub for MoneyMinor {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self.checked_sub(rhs).expect("Monetary arithmetic underflow")
    }
}

/// Bound monetary quantity with an explicit currency code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Money {
    /// Amount in integer minor units
    pub amount: MoneyMinor,
    /// ISO currency code
    pub currency: CurrencyCode,
}

impl Money {
    /// Create a new bound monetary amount.
    pub const fn new(amount: MoneyMinor, currency: CurrencyCode) -> Self {
        Self { amount, currency }
    }

    /// Create from major amount and currency.
    pub fn from_major(major: i64, currency: CurrencyCode) -> Result<Self, MoneyError> {
        Ok(Self {
            amount: MoneyMinor::from_major(major)?,
            currency,
        })
    }
}

impl fmt::Display for Money {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.amount, self.currency)
    }
}

/// Monetary calculation and parsing errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MoneyError {
    /// Integer overflow during monetary arithmetic
    #[error("Monetary calculation overflow")]
    Overflow,
    /// Unsupported currency code provided
    #[error("Unsupported ISO currency code: {0}")]
    UnsupportedCurrency(String),
    /// Currency mismatch during operation
    #[error("Currency mismatch: {0} vs {1}")]
    CurrencyMismatch(CurrencyCode, CurrencyCode),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minor_conversion_and_formatting() {
        let money = MoneyMinor::from_major(150).unwrap();
        assert_eq!(money.as_i64(), 15000);
        assert_eq!(format!("{}", money), "150.00");

        let fractional = MoneyMinor::new(15075);
        assert_eq!(format!("{}", fractional), "150.75");
        assert_eq!(fractional.to_major_f64(), 150.75);
    }

    #[test]
    fn test_money_serialization() {
        let money = Money::new(MoneyMinor::new(45000), CurrencyCode::USD);
        let json = serde_json::to_string(&money).unwrap();
        assert_eq!(json, "{\"amount\":45000,\"currency\":\"USD\"}");

        let deserialized: Money = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, money);
    }

    #[test]
    fn test_currency_parsing() {
        assert_eq!(CurrencyCode::from_str("usd").unwrap(), CurrencyCode::USD);
        assert_eq!(CurrencyCode::from_str("INR").unwrap(), CurrencyCode::INR);
        assert!(CurrencyCode::from_str("XYZ").is_err());
    }
}
