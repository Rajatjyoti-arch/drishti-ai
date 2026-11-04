# Drishti AI: Agentic Real-Time DAST for B2B Travel Ecosystems

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Track](https://img.shields.io/badge/VOYAGEHACK_4.0-Fraud_Prevention_%26_Security-orange)](https://unstop.com)
[![Status](https://img.shields.io/badge/Milestone-P0_Frozen_Baseline-success)](#)

> *"See the journey. Understand the risk. Prove the vulnerability."*

**Drishti AI** is an autonomous, journey-aware Dynamic Application Security Testing (DAST) platform engineered specifically for the transactional and multi-tenant complexities of B2B travel ecosystems like **TBO.com**.

---

## 🏗️ Architecture Overview

Rather than analyzing disconnected HTTP endpoints, Drishti AI models the complete travel state machine and enforces platform invariants across deployments.

![Drishti AI Architecture](docs/architecture/Drishti_AI_Architecture.png)

---

## 📌 The Problem in B2B Travel Technology

B2B travel platforms connect airlines, hotel aggregators, and tour suppliers with thousands of travel agencies and sub-agencies. Daily deployments introduce subtle business-logic flaws that traditional, scheduled DAST tools completely miss:

1. **Multi-Tenant Boundary Failures (BOLA / IDOR):** One travel agency accessing, altering, or canceling bookings and passenger PII belonging to another agency.
2. **Checkout Tariff & Markup Tampering:** Modifying client-side price, currency codes, or markup parameters during the transition between reservation `Hold` and `Confirm`.
3. **Concurrent Double-Refund Abuse:** Parallel cancellation requests triggering duplicate refunds before database locks acquire.
4. **Zombie & Shadow APIs:** Deprecated `/v1/` routes or unmapped partner webhooks remaining active without modern authentication or rate limiting.

---

## 🛡️ The Four Architectural Mandates

Drishti AI is built on four non-negotiable architectural mandates:

### 1. Machine-Enforced Authorization Contract
All testing is bounded by a machine-readable, deterministic policy (`configs/auth_contract.json`). Any outbound request violating target allowlists, concurrency ceilings ($\le 2$), or rate budgets ($\le 5\text{ req/s}$) is dropped before network socket allocation. Prohibits destructive actions (no `DROP`, no DoS, no raw shell commands).

### 2. Evidence-Backed LLM Provenance
The LLM *proposes*; deterministic code *decides*. Every inferred endpoint, role permission, and parameter semantic must carry cryptographic provenance anchoring it to an observed raw network request (HAR frame ID + SHA-256 packet hash + confidence score $\ge 0.85$). Hallucinations are rejected at ingestion.

### 3. Strengthened Invariant Verification (I-01 BOLA)
Drishti AI rejects naive HTTP 200 checks. An invariant violation is confirmed only if:
* The response payload explicitly asserts ownership by the **victim tenant** (`owner_agency_id == victim_tenant_id`).
* The payload exposes sensitive fields (passenger full names, passport numbers, PNRs, or billing vouchers).

### 4. Strict Reproducibility
Every confirmed finding includes:
* The exact ordered state-setup request sequence.
* A self-contained, copy-pasteable cURL command with sanitized test tokens.
* Cryptographic request/response evidence hashes.
* An automated retest recipe that verifies ticket closure after remediation.

---

## ⚡ The Frozen 7-Step Single Loop (Milestone 1)

All active engineering is frozen around delivering **one complete, reproducible security finding** against the organizer's authorized staging sandbox:

```
[Target Change Ingested]
           │
           ▼
1. Detect Change ──────────────► Webhook, commit SHA, or HAR bundle diff
           │
           ▼
2. Discover Endpoints ─────────► Playwright crawl + provenance-backed LLM inference
           │
           ▼
3. Identify Invariant Candidate ► Match against I-01 (BOLA) or I-02 (Pricing Tampering)
           │
           ▼
4. Execute Authorized Test ────► Deterministic Policy Gate enforces allowlist & rates
           │
           ▼
5. Independent Verification ───► Clean fixtures + negative controls + ownership checks
           │
           ▼
6. Synthesize Report ──────────► Self-contained cURL PoC, response diff, code patch
           │
           ▼
7. Retest After Patch ─────────► Post-commit re-run confirms 403 Forbidden & closes issue
```

---

## 📊 P0 Feasibility Matrix

| Module / Component | P0 Functional Scope | Technical Dependencies | Potential Failure Modes | Mitigation & Fallback Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **Change Ingestion** | Ingest commit webhook, endpoint diff, or static HAR bundle. | Python 3.11+, Git diff parser, JSON Schema. | Missing/malformed webhook payloads; schema drifts. | Fallback to manual directory/HAR file watcher with standard schema validator. |
| **Recon & Crawl** | Extract authenticated routes across 2 agency roles via browser. | Playwright (Chromium), mitmproxy / HAR parser. | Anti-bot mechanisms, SPA hydration delays, dynamic element selectors. | Pre-recorded authenticated session tokens; deterministic URL list seeding. |
| **Endpoint Inference** | Infer endpoint path, parameters, roles, and journey position. | LLM (Claude 3.5 Sonnet / GPT-4o) + Pydantic v2. | Hallucinated routes, fabricated parameter types, missing auth headers. | **Strict Provenance Gate:** Every route must anchor to a real HAR request ID with confidence score $\ge 0.85$. |
| **Policy Gate & Safety** | Deterministic enforcement of domain allowlist, rate limits, budgets. | Token-bucket algorithm, Python standard library. | Misconfigured regex matching out-of-scope hosts; rate limit bursts. | Default-deny CIDR & host regex; hard concurrency ceiling $= 2$; immediate kill switch. |
| **Specialist Executor** | Execute BOLA (I-01) and Tariff Tampering (I-02) probes. | HTTPX (async), isolated credential broker. | Staging environment 500 errors; session token expiration during test. | Synthetic token refresher; exponential backoff on latency $> 300\text{ms}$; circuit breaker. |
| **Independent Verifier** | Reproduce candidate findings using clean fixtures & negative controls. | Isolated test runner, JSON path evaluator. | Flaky network false positives; verifier bias inheriting planner assumptions. | Strict separation: Verifier runs separate fixture setup and must pass negative control. |
| **Retest Engine** | Re-run minimal proof against updated commit SHA; verify remediation. | Git webhook listener, test runner. | Premature ticket closure due to partial fixes or caching. | Invariant assertion: Ticket closes **only** if negative control passes and exploit yields 403/404. |

---

## 📁 Repository Structure

```
drishti-ai/
├── README.md                           # Master architectural guide and setup instructions
├── pyproject.toml                      # Python 3.11+ packaging, dependencies, and lint configs
├── configs/
│   ├── auth_contract.json              # Active authorization contract (domains, accounts, limits)
│   └── test_profiles.json              # Synthetic tenant profiles (Agency A, Agency B, Sub-Agent)
├── docs/
│   ├── architecture/                   # Architecture diagrams (.png and editable .drawio)
│   ├── DRISHTI_AI_MASTER_PLAN.md       # Comprehensive system master plan
│   └── DRISHTI_AI_IMPLEMENTATION_SPEC.md # Detailed engineering and module specification
├── drishti/
│   ├── __init__.py
│   ├── main.py                         # Single-loop CLI entrypoint
│   ├── core/                           # Configuration, exceptions, and Pydantic data schemas
│   ├── discovery/                      # Playwright headless crawler and HAR traffic parser
│   ├── graph/                          # Travel Security Intelligence Graph (NetworkX)
│   ├── planner/                        # LLM hypothesis planner with provenance validation
│   ├── policy/                         # Deterministic Policy Gate, rate limiter, and audit ledger
│   ├── executors/                      # BOLA (I-01) and Tariff (I-02) specialist executors
│   ├── verifier/                       # Independent reproduction runner and negative controls
│   ├── reporter/                       # Structured ticket and cURL PoC synthesizer
│   └── retest/                         # Post-deployment remediation verification engine
└── tests/
    ├── unit/                           # Tests for policy gate, rate limiter, and parsers
    ├── integration/                    # Mock staging integration tests
    └── fixtures/                       # Recorded HAR files and synthetic staging responses
```

---

## 🚀 Quickstart & Setup

### Prerequisites
* Python 3.11 or newer
* Node.js & Playwright (for headless browser recon)

### Installation
```bash
# Clone the repository
git clone https://github.com/Rajatjyoti-arch/drishti-ai.git
cd drishti-ai

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# Install Playwright browser binaries
playwright install chromium
```

### Validate Authorization Contract
```bash
python3 -m drishti.main verify-contract --contract-path configs/auth_contract.json
```

---

## 🗓️ Six-Session Engineering Roadmap

* [x] **Session 1: Safety Foundation:** `auth_contract.json` schema, deterministic `PolicyGate` (allowlist, token-bucket limiter, SQLite ledger).
* [ ] **Session 2: Recon & Provenance:** Playwright role journeys, HAR indexing, LLM schema inference with SHA-256 evidence anchoring.
* [ ] **Session 3: Travel Intelligence Graph:** NetworkX model of `Search ➔ Quote ➔ Hold ➔ Book` and multi-tenant invariant bindings.
* [ ] **Session 4: Specialist Executors:** Implement `BOLAExecutor` (I-01) and `PricingExecutor` (I-02) dispatching through the Policy Gate.
* [ ] **Session 5: Independent Verifier:** Clean fixture runner, negative control baseline, and sensitive field exposure assertion.
* [ ] **Session 6: Milestone 1 Acceptance:** Full 7-stage loop execution against staging sandbox with automated retest closure.

---

## 🏆 Alignment with TBO VOYAGEHACK 4.0 Criteria

| Criterion | Weight | Drishti AI Architectural Guarantee |
| :--- | :--- | :--- |
| **Valid Findings & Severity** | **30%** | Targets deep B2B travel business logic (IDOR, fare tampering, refund races) rather than shallow generic fuzzing. |
| **Precision & Noise Control** | **20%** | Decoupled **Independent Verifier** with negative controls ensures verified reproducibility. |
| **Safety & Scope Discipline** | **20%** | Machine-enforced **Authorization Contract** with hard rate limits ($\le 5\text{ req/s}$) and emergency kill switches. |
| **Speed After Change** | **10%** | Event-driven change triggers execute targeted invariant tests in minutes. |
| **Report Quality & Actionability** | **10%** | Developer-ready tickets featuring self-contained cURL reproduction recipes and remediation code patches. |
| **Discovery & API Inventory** | **10%** | Reconciles traffic logs to categorize **Active**, **Zombie**, and **Shadow** APIs with actionable governance. |

---

## 📄 License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
