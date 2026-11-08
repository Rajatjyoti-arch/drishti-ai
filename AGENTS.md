# Drishti AI - agent rules

## What this is
Agentic real-time DAST for a B2B travel platform. Authorized synthetic staging only.

## Non-negotiable safety rules
- Only the `safety` module/crate opens network connections to a target. All other code calls its client.
- Default-deny host allowlist; per-test and global request budgets; rate and concurrency limits; kill switch; audit log of every request.
- LLM output is only a proposal (a validated structured plan). An LLM never sends requests, sees secrets or confirms findings.
- Only the verifier may mark a finding confirmed.
- No denial-of-service, destructive tests, real payments, real personal data or bulk extraction.

## Rust conventions
- `cargo fmt`, `cargo clippy -- -D warnings` and `cargo test` must pass.
- No unwrap()/expect() in non-test code; return typed errors.
- Prefer the standard library; every new crate needs a one-line justification.
- Only the safety crate may depend on the HTTP client crate.

## Minimal-code guidance
Prefer the simplest solution, but safety checks, input validation, error handling, audit logging and tests are required, never "unnecessary".
