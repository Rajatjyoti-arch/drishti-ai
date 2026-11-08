# Drishti AI - Project Seed

## Vision
Detect change in a staging travel platform, map the API without docs, plan minimal targeted tests, execute through a deterministic safety gate, verify independently, triage by business impact, report, retest after fixes.

## Constraints
- All non-negotiable safety rules in AGENTS.md apply.
- Stay inside approved targets (authorized synthetic staging environment only).
- Synthetic accounts only; no real payments, no real personal data.
- Minimum evidence needed for verification; no bulk extraction or denial-of-service.
- Log every single request in an immutable audit log.

## Milestones with Acceptance Gates

### Milestone A: Safe Foundation
- Out-of-scope host, unapproved method, and exhausted budget are rejected deterministically before any network call.

### Milestone B: Discovery and Graph
- Expected journey endpoints found, with source evidence.

### Milestone C: Inventory
- Seeded active, zombie, and shadow routes classified correctly.

### Milestone D: Planning and First Specialists
- Cross-agency IDOR and fare tampering first; every test tied to an invariant and run strictly through the deterministic safety gate.

### Milestone E: Verification, Triage, Retest
- Seeded flaw confirmed, negative control not confirmed, patched issue closes cleanly.

### Milestone F: Demo and Evaluation
- Every action and finding replayable directly from the audit log.
