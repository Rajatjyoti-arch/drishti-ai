# Drishti AI - agent rules

## What this is
Agentic real-time DAST for a B2B travel platform. Authorized synthetic staging only.

## Non-negotiable safety rules
- Only `rust/crates/drishti-guard` opens physical network connections to a target. All other code mediates outbound calls through `drishti/policy/**` and `drishti/ipc/**` (calling the Guard IPC client).
- Default-deny host allowlist; per-test and global request budgets; rate and concurrency limits; kill switch; audit log of every request.
- LLM output is only a proposal (a validated structured plan). An LLM never sends requests, sees secrets or confirms findings.
- Only the verifier may mark a finding confirmed.
- No denial-of-service, destructive tests, real payments, real personal data or bulk extraction.

## Python conventions
- Linting and formatting: `ruff` (configured line-length 100, target version `py311`).
- Testing: `pytest` under `tests/` (with `pytest-asyncio` for async tests).
- Type hints required on all public functions and interfaces.
- No direct network calls outside `drishti/policy/**` and `drishti/ipc/**`.

## Rust conventions (rust/crates/**)
- `cargo fmt`, `cargo clippy -- -D warnings` and `cargo test` must pass.
- No unwrap()/expect() in non-test code; return typed errors.
- Prefer the standard library; every new crate needs a one-line justification.
- Only `rust/crates/drishti-guard` may depend on the HTTP client crate (`reqwest`).

## Minimal-code guidance
Prefer the simplest solution, but safety checks, input validation, error handling, audit logging and tests are required, never "unnecessary".
