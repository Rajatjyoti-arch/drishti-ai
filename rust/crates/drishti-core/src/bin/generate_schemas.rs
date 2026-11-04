//! Utility binary to generate canonical JSON Schemas from Rust domain contracts.
//!
//! Run with: `cargo run -p drishti-core --bin generate_schemas`

use drishti_core::identity::*;
use drishti_core::money::*;
use drishti_core::policy::*;
use drishti_core::travel::*;
use schemars::schema_for;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("schemas");

    fs::create_dir_all(&output_dir)?;

    println!("Generating JSON schemas into {:?}...", output_dir);

    // 1. Identity & Context
    let schema_tenant = schema_for!(TenantContext);
    fs::write(
        output_dir.join("TenantContext.schema.json"),
        serde_json::to_string_pretty(&schema_tenant)?,
    )?;

    // 2. Monetary
    let schema_money = schema_for!(Money);
    fs::write(
        output_dir.join("Money.schema.json"),
        serde_json::to_string_pretty(&schema_money)?,
    )?;

    // 3. Travel Domain
    let schema_quote = schema_for!(Quote);
    fs::write(
        output_dir.join("Quote.schema.json"),
        serde_json::to_string_pretty(&schema_quote)?,
    )?;

    let schema_hold = schema_for!(Hold);
    fs::write(
        output_dir.join("Hold.schema.json"),
        serde_json::to_string_pretty(&schema_hold)?,
    )?;

    let schema_booking = schema_for!(Booking);
    fs::write(
        output_dir.join("Booking.schema.json"),
        serde_json::to_string_pretty(&schema_booking)?,
    )?;

    // 4. Policy & Security Execution Boundary
    let schema_req = schema_for!(OutgoingTestRequest);
    fs::write(
        output_dir.join("OutgoingTestRequest.schema.json"),
        serde_json::to_string_pretty(&schema_req)?,
    )?;

    let schema_decision = schema_for!(PolicyDecision);
    fs::write(
        output_dir.join("PolicyDecision.schema.json"),
        serde_json::to_string_pretty(&schema_decision)?,
    )?;

    let schema_result = schema_for!(ExecutionResult);
    fs::write(
        output_dir.join("ExecutionResult.schema.json"),
        serde_json::to_string_pretty(&schema_result)?,
    )?;

    let schema_finding = schema_for!(Finding);
    fs::write(
        output_dir.join("Finding.schema.json"),
        serde_json::to_string_pretty(&schema_finding)?,
    )?;

    println!("Successfully generated all 9 canonical JSON schemas.");
    Ok(())
}
