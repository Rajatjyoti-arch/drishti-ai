# DRISHTI AI — Master System Architecture & Technical Implementation Plan
**Project Title:** Drishti AI (*"See the journey. Understand the risk. Prove the vulnerability."*)  
**Event:** TBO.com VOYAGEHACK 4.0  
**Track:** Fraud Prevention & Security — Agentic Real-Time DAST  
**Document Status:** Complete Architecture Specification, System Blueprint & Submission Master  

---

## 1. Executive Summary & Core Thesis

B2B travel platforms such as **TBO.com** serve as complex transactional hubs connecting global inventory suppliers (airlines, hotels, activities) to thousands of travel agencies and sub-agencies. These platforms experience continuous code deployments, frequent third-party API updates, and multi-tenant transactional flows.

### The Limitations of Conventional Testing
Traditional Dynamic Application Security Testing (DAST) tools run on periodic schedules, examine endpoints in isolation, and focus on generic technical vulnerabilities (such as cross-site scripting or basic injection). However, the most critical risks in travel technology arise from **context-dependent business-logic and state-machine failures**:
* **Multi-Tenant Boundary Failures (BOLA / IDOR):** One agency reading or altering booking data, passenger vouchers, or invoices of another agency.
* **Tariff and Markup Tampering:** Modifying client-side price or currency parameters between reservation hold and booking confirmation.
* **Concurrent Race Conditions:** Duplicate cancellation requests or retried payment callbacks causing unearned refunds or double-crediting.
* **Zombie and Shadow APIs:** Legacy routes (e.g., deprecated `/v1/` endpoints) remaining active and accessible without modern access controls.

### The Drishti AI Solution
**Drishti AI** replaces scheduled, generic scanning with an **autonomous, continuous, journey-aware verification platform**. Rather than treating endpoints as disconnected URLs, Drishti AI reasons about **journeys and transaction invariants**. It builds a living **Travel Security Intelligence Graph**, models complete booking lifecycles, formulates hypothesis-driven verification plans, executes tests safely via a deterministic policy gate, independently validates findings with reproducible proofs, and retests patched code post-deployment.

---

## 2. Design Principles

1. **Journey-First, Endpoint-Aware:** Individual endpoints derive operational meaning from where they sit in the business flow. A confirmation endpoint cannot be properly validated without the context of prior search, quote, and hold states.
2. **Invariant-Driven Testing:** Define non-negotiable platform rules (e.g., *"Total refunds must never exceed the original captured payment"*), and verify whether controlled state transitions preserve those rules.
3. **LLM for Reasoning, Deterministic Code for Execution:** Language models analyze diffs, infer schemas, and propose verification plans within a strict schema. All network communication, rate limiting, safety checks, and evidence evaluations are enforced by **100% deterministic code**. The LLM never has raw network access or shell execution privileges.
4. **Safe by Construction:** Default-deny host allowlists, synthetic accounts only, isolated test data, strictly bounded concurrency, automated backoff on target latency, and a global emergency kill switch.
5. **Independent Verification:** The module that plans or executes a test cannot validate its own finding. A separate verifier with negative controls determines whether an observation is `Confirmed`, `Not Reproduced`, or `Inconclusive`.
6. **Business-Context Severity:** Findings are scored not solely by generic technical metrics (CVSS), but by **business impact**: financial exposure, passenger personal data privacy, inventory corruption, and tenant isolation integrity.
7. **Empirical Rigor:** Drishti AI avoids unrealistic claims such as "zero false positives." It measures precision and confidence transparently, routing ambiguous outcomes to human review.

---

## 3. P0 Feasibility Matrix & Threat Pressures

### 3.1 P0 Feasibility Matrix (Reconstructed & Formatted)

| Module / Component | P0 Functional Scope | Technical Dependencies | Potential Failure Modes | Mitigation & Fallback Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **Change Ingestion** | Ingest commit webhook, endpoint diff, or static HAR bundle. | Python 3.11+, Git diff parser, JSON Schema. | Missing/malformed webhook payloads; schema drifts. | Fallback to manual directory/HAR file watcher with standard schema validator. |
| **Recon & Crawl** | Extract authenticated routes across 2 agency roles via browser. | Playwright (Chromium), mitmproxy / HAR parser. | Anti-bot mechanisms, SPA hydration delays, dynamic element selectors. | Pre-recorded authenticated session tokens; deterministic URL list seeding. |
| **Endpoint Inference** | Infer endpoint path, parameters, roles, and journey position. | LLM (Claude 3.5 Sonnet / GPT-4o) + Pydantic v2. | Hallucinated routes, fabricated parameter types, missing auth headers. | **Strict Provenance Gate:** Every route must anchor to a real HAR request ID with confidence score $\ge 0.85$. |
| **Policy Gate & Safety** | Deterministic enforcement of domain allowlist, rate limits, budgets. | Token-bucket algorithm, Python standard library. | Misconfigured regex matching out-of-scope hosts; rate limit bursts. | Default-deny CIDR & host regex; hard concurrency ceiling $= 2$; immediate kill switch. |
| **Specialist Executor** | Execute BOLA (I-01) and Tariff Tampering (I-02) probes. | HTTPX (async), isolated credential broker. | Staging environment 500 errors; session token expiration during test. | Synthetic token refresher; exponential backoff on latency $> 300\text{ms}$; circuit breaker. |
| **Independent Verifier** | Reproduce candidate findings using clean fixtures & negative controls. | Isolated test runner, JSON path evaluator. | Flaky network false positives; verifier bias inheriting planner assumptions. | Strict separation: Verifier runs separate fixture setup and must pass negative control. |
| **Retest Engine** | Re-run minimal proof against updated commit SHA; verify remediation. | Git webhook listener, test runner. | Premature ticket closure due to partial fixes or caching. | Invariant assertion: Ticket closes **only** if negative control passes and exploit yields 403/404. |

### 3.2 High-Scale Reservation Threat Pressures
Drishti AI takes design inspiration from high-scale reservation and payment platforms (such as high-demand rail and airline reservation systems):

| Real-World Pressure | Drishti AI Focus Area | Security / Consistency Invariant |
| :--- | :--- | :--- |
| **High competition for scarce inventory** | Bounded concurrency and race checks | One inventory item cannot be committed to two conflicting bookings. |
| **Perishable reservation holds** | State transition and hold expiration | An expired or released hold token cannot authorize a subsequent confirmation. |
| **Network interruptions & retried webhooks** | Idempotency and callback integrity | Retried requests or duplicate callbacks cannot generate multiple charges or refunds. |
| **Dynamic multi-currency tariffs** | Server-authoritative quote integrity | Client-supplied prices, markups, or currency codes cannot override verified quotes. |
| **Hierarchical agency structures** | Multi-tenant authorization boundaries | An agency or sub-agent can only access resources belonging strictly to its scope. |
| **Evolving API versions** | Inventory reconciliation & drift detection | Legacy routes are discovered, classified (Active, Zombie, Shadow), and assigned remediation actions. |

---

## 4. End-to-End System Architecture

Drishti AI operates as an automated 14-stage loop:

```
[CI/CD Deploy / Gateway Traffic / Frontend Bundles]
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. CHANGE INTELLIGENCE & ORCHESTRATION                      │
│    • Ingests deploy webhooks, traffic logs, and AST diffs   │
│    • Prioritizes affected travel journeys and endpoints     │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. RECONNAISSANCE & APPLICATION MAPPING                     │
│    • Headless crawler (Playwright) authenticated by role    │
│    • Captures network traffic, schemas, and dependencies    │
└───────────────────────┬─────────────────────────────────────┘
                        │
        ┌───────────────┴───────────────┐
        ▼                               ▼
┌───────────────────────────────┐ ┌───────────────────────────┐
│ 3. TRAVEL SECURITY GRAPH      │ │ 4. ZOMBIE / SHADOW AGENT  │
│    • Nodes: Tenants, Roles,   │ │    • Reconciles routes    │
│      Endpoints, Invariants    │ │      against traffic logs │
│    • State machine mapping    │ │    • Flags Active/Zombie/ │
│                               │ │      Shadow candidates    │
└───────────────┬───────────────┘ └───────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. ATTACK PLANNER (LLM REASONING ENGINE)                    │
│    • Formulates targeted hypotheses from graph differences  │
│    • Categorizes tests: Routine, Elevated, or High-Risk     │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. DETERMINISTIC POLICY GATE & SAFETY BOUNDARY              │
│    • Host allowlist, credential vault, rate-limit buckets   │
│    • Concurrency caps, health monitoring, emergency stop    │
│    • Human approval required for elevated/high-risk tests   │
└───────────────────────┬─────────────────────────────────────┘
                        │ Approved Actions Only
                        ▼
┌─────────────────────────────────────────────────────────────┐
│ 7. SPECIALIST EXECUTOR MODULES (Targeting Staging Sandbox)  │
│    • Access Control (IDOR / BOLA)                           │
│    • Business Logic & Tariff Integrity                      │
│    • Inventory Exclusivity & Concurrency                    │
│    • Payment & Callback Idempotency                         │
│    • Authentication & Schema Hygiene                        │
└───────────────────────┬─────────────────────────────────────┘
                        │ Raw Test Responses
                        ▼
┌─────────────────────────────────────────────────────────────┐
│ 8. INDEPENDENT VERIFIER MODULE                              │
│    • Re-executes proof recipe using clean isolated fixtures │
│    • Tests negative controls to prevent false alarms        │
│    • Assigns status: Confirmed | Not Reproduced | Unknown   │
└───────────────────────┬─────────────────────────────────────┘
                        │ Confirmed Findings
                        ▼
┌─────────────────────────────────────────────────────────────┐
│ 9. TRIAGE, BUSINESS-IMPACT SCORING & TICKET GENERATION      │
│    • Calculates business risk (Financial, PII, Tenant scope)│
│    • Formats actionable developer ticket with cURL & patch  │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│ 10. AUTOMATED RETEST LOOP                                   │
│     • Re-evaluates proof post-patch; closes ticket on fix   │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. Travel Security Intelligence Graph & State Modeling

Rather than viewing the platform as disconnected HTTP endpoints, Drishti AI maintains a graph structure capturing B2B travel semantics:

### Graph Schema
* **Tenants:** `Agency_A`, `Agency_B`, `Platform_Operator`, `Supplier_Partner`.
* **Roles:** `Agency_Admin`, `Front_Desk_Agent`, `Sub_Agent`, `Finance_Officer`, `Unauthenticated`.
* **Endpoints:** Method, Path, Schema, Auth Mechanism, Version, Last Observed Timestamp.
* **Business Objects:** `Search_Query`, `Quote_Token`, `Hold_Token`, `Booking_Record`, `Passenger_Record`, `Invoice`, `Payment_Intent`, `Refund_Credit`.
* **Workflow States:** `SEARCHED`, `QUOTED`, `HELD`, `PAYMENT_PENDING`, `CONFIRMED`, `CANCELLED`, `REFUNDED`.
* **Invariants:** Explicit transactional and authorization rules bound to state transitions.

### Travel State Machine & Transition Invariants
```
[SEARCHED] ──(Select Room/Flight)──► [QUOTED] ──(Hold Request)──► [HELD]
                                                                     │
                         ┌───────────────────────────────────────────┴────────────────────────┐
                         ▼                                                                    ▼
                  [HELD_EXPIRED]                                                       [PAYMENT_PENDING]
                 (Hold TTL Elapsed)                                                           │
                                                                           ┌──────────────────┴──────────────────┐
                                                                           ▼                                     ▼
                                                                    [PAYMENT_FAILED]                        [CONFIRMED]
                                                                                                                 │
                                                                           ┌─────────────────────────────────────┴──────────────────┐
                                                                           ▼                                                        ▼
                                                                  [MODIFICATION_PENDING]                                  [CANCELLATION_PENDING]
                                                                           │                                                        │
                                                                           ▼                                                        ▼
                                                                      [CONFIRMED]                                              [CANCELLED]
                                                                                                                                    │
                                                                                                                                    ▼
                                                                                                                            [REFUND_PENDING]
                                                                                                                                    │
                                                                                                                                    ▼
                                                                                                                               [REFUNDED]
```

---

## 6. Core Business-Logic Invariants

Drishti AI tests against eight explicit invariants:

1. **Multi-Tenant Isolation (BOLA / IDOR):**  
   *Rule:* An identity authenticated under `Agency_B` cannot view, modify, or cancel any booking, passenger record, or invoice belonging to `Agency_A`.
2. **Server-Authoritative Pricing:**  
   *Rule:* Client-submitted tariffs, markups, discounts, or currency codes cannot alter the price established by the authoritative server-side quote.
3. **Hold Token Expiration:**  
   *Rule:* An expired or cancelled reservation hold cannot be converted into a confirmed booking.
4. **Payment Callback Idempotency:**  
   *Rule:* Repeated or delayed payment callbacks cannot create duplicate ledger credits or multiple ticket issuances for a single transaction.
5. **Refund Bounds & Idempotency:**  
   *Rule:* Concurrent or repeated cancellation requests cannot refund a transaction more than once; total refunds must never exceed the captured deposit.
6. **Sub-Agent Privilege Boundaries:**  
   *Rule:* Non-administrative roles cannot alter agency credit limits, commission structures, or billing terms.
7. **Supplier Isolation:**  
   *Rule:* Supplier integration credentials cannot access or modify inventory or settlement data of competing suppliers.
8. **Sensitive Data Protection:**  
   *Rule:* Error responses, debug paths, and system traces must never expose unmasked passenger passport data, payment card identifiers, or internal tokens.

---

## 7. The 5 Specialist Test Modules

1. **Access-Control Specialist:**  
   Validates object-level authorization across agency and sub-agent roles. Uses automated session-swapping fixtures to verify that tenant scoping is enforced server-side on every read and mutation route.
2. **Business-Logic & Tariff Specialist:**  
   Inspects multi-step booking flows. Injects modified tariff amounts, mismatched currency codes, and negative ancillary values to verify server-side validation.
3. **Inventory & Concurrency Specialist:**  
   Tests race conditions and state boundaries. Evaluates whether parallel hold confirmations or late confirmations of expired holds can lead to double allocation.
4. **Payment & Refund Specialist:**  
   Simulates retries, duplicate webhook callbacks, and parallel cancellation requests against sandbox payment handlers to verify idempotent processing.
5. **Authentication, API & Schema Specialist:**  
   Evaluates session token lifetimes, role boundaries, mass-assignment vulnerabilities, and endpoint schema consistency using structured test inputs.

---

## 8. Deterministic Safety Framework & Policy Boundary

To protect staging stability and prevent unintended system disruptions, every outgoing request must pass through an automated deterministic policy gate:

```
[Test Request Candidate]
           │
           ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. Target Allowlist Check (Authorized Hostname Only)        │
└──────────────────────────┬──────────────────────────────────┘
                           │ Passed
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Payload Safety Filter (Prohibits Destructive Actions)    │
└──────────────────────────┬──────────────────────────────────┘
                           │ Passed
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Rate Limiter (Token-Bucket: Max 5 req/s, Concurrency = 2)│
└──────────────────────────┬──────────────────────────────────┘
                           │ Passed
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Staging Health Check (Backoff on Latency Spike / 5xx)    │
└──────────────────────────┬──────────────────────────────────┘
                           │ Passed
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Synthetic Credential Broker (Redacts Real Data)          │
└──────────────────────────┬──────────────────────────────────┘
                           │ Passed
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. Cryptographic Request Audit Log                          │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
              [Delivered to Sandbox Target]
```

* **Global Emergency Stop:** A single command or dashboard toggle immediately cancels all running workers and revokes active test sessions.
* **Human Approval Requirement:** Any high-risk operation (such as modifying account-level financial parameters) requires explicit human authorization before execution.

---

## 9. Independent Verification & Finding Schema

To eliminate false alarms, candidate findings are evaluated by an independent verification step before any ticket is generated:

```
[Specialist Module] ──(Candidate Finding)──► [INDEPENDENT VERIFIER]
                                                   │
                                                   ├── 1. Provisions clean, isolated test fixtures
                                                   ├── 2. Executes minimal reproduction steps
                                                   └── 3. Runs NEGATIVE CONTROL test
                                                                 │
                          ┌──────────────────────────────────────┴──────────────────────────────────────┐
                          ▼                                             ▼                               ▼
                   [CONFIRMED]                                  [NOT REPRODUCED]                  [INCONCLUSIVE]
            (Reproduces 100% cleanly;                     (Transient network fluke or           (Sent to Human
             Negative control passes)                      unsupported assumption)              Review Queue)
                          │
                          ▼
           [Ticket Synthesized & Reported]
```

### Structured Finding Output
```json
{
  "finding_id": "DRI-IDOR-2026-0042",
  "title": "Cross-Agency Booking Object Authorization Bypass (BOLA / IDOR)",
  "vulnerability_class": "Broken Object Level Authorization",
  "status": "CONFIRMED",
  "target_service": "Booking Management Service",
  "endpoint": "GET /api/v2/agencies/{agency_id}/bookings/{booking_id}",
  "violated_invariant": "Agency B cannot read or manage bookings belonging to Agency A.",
  "confidence_score": 0.98,
  "business_impact": {
    "financial_risk": "Low (Direct), High (Contractual Penalties)",
    "data_exposure": "Passenger Full Names, Passport Numbers, Travel Itineraries",
    "tenant_isolation": "FAILED",
    "overall_severity": "HIGH"
  },
  "reproduction_proof": {
    "curl_command": "curl -X GET 'https://staging.tbo-sandbox.internal/api/v2/agencies/AG_MUMBAI_01/bookings/TBOH_992144' -H 'Authorization: Bearer <AG_DELHI_SUBAGENT_TOKEN>'",
    "expected_response_code": 403,
    "observed_response_code": 200,
    "evidence_diff_id": "audit_log_ref_882914"
  },
  "suggested_remediation": {
    "root_cause": "Endpoint extracts agency_id from URL path rather than validating against the authenticated JWT session context.",
    "code_fix": "assert session.agency_id == requested_agency_id, 'Access Denied: Tenant Mismatch'"
  },
  "retest_recipe": {
    "test_id": "VERIFY_DRI_IDOR_0042",
    "trigger": "git_commit_sha_updated"
  }
}
```

---

## 10. Zombie and Shadow API Governance

Drishti AI continuously reconciles the discovered surface against real traffic:

| Classification | Definition | Business Risk | Recommended Action |
| :--- | :--- | :--- | :--- |
| **Active API** | Route present in UI navigation and observed in current gateway traffic. | Standard operational surface. | Continuous DAST testing on deployment. |
| **Zombie API** | Discovered via frontend bundles or historical routes; responds to HTTP requests, but has **0 recorded traffic** in 30–90 day logs. | High: Deprecated endpoints often lack modern authentication and rate limits. | **Decommission:** Route to API Gateway team to deprecate with HTTP 410 Gone. |
| **Shadow API** | Observed in gateway traffic logs or partner webhooks, but completely absent from official documentation/OpenAPI specifications. | Critical: Unmonitored surface operating outside security governance. | **Catalog & Govern:** Generate OpenAPI spec, assign service owner, enforce gateway policy. |

---

## 11. Technology Stack

* **Workflow Orchestration:** Python 3.11+ / FastAPI / LangGraph (Stateful execution graph).
* **Reasoning Models:** Multi-tier model routing (Claude 3.5 Sonnet / GPT-4o for complex hypothesis planning; lightweight models for schema normalization).
* **Browser Automation & Recon:** Playwright (Headless Chromium) for role-based session crawling and HAR generation.
* **Network Interception:** mitmproxy and HTTPX for traffic recording and controlled replay.
* **Knowledge Graph Storage:** NetworkX (in-memory graph processing) with PostgreSQL / SQLite JSONB persistence.
* **Policy Enforcement:** Deterministic Python schema validation and token-bucket algorithms.
* **Dashboard & Visualization:** Next.js / Tailwind CSS (or Streamlit) displaying real-time API topologies and verified finding feeds.

---

## 12. Complete Slide-by-Slide Guide for Round 1 (3-Slide Deck)

### Slide 1: The Problem, Core Thesis & System Architecture
* **Slide Title:** Drishti AI: Autonomous Real-Time DAST for B2B Travel Platforms
* **Subtitle:** *From Blind Endpoint Scanning to Journey-Aware Invariant Testing*
* **Left Column (The Core Problem in B2B Travel):**
  * High deployment velocity creates critical business-logic gaps.
  * Conventional DAST runs periodically, scans endpoints in isolation, and misses stateful flaws (IDOR, fare tampering, duplicate refunds).
  * Zombie/Shadow APIs remain undocumented and exposed.
* **Right Column (The Drishti Architecture):**
  * Ingests CI/CD events, traffic logs, and frontend bundles.
  * Reconstructs the **Travel Security Intelligence Graph**.
  * Executes targeted tests through a **Deterministic Policy Gate**.
  * Validates every finding via an **Independent Verifier** and retests post-fix.
* **Visual Element:** Embed the top-level architecture flowchart from `Drishti_AI_Architecture.png`.

### Slide 2: Travel State Machine, Invariants & Specialist Verification
* **Slide Title:** Journey-Aware Testing: Validating Travel Invariants Safely
* **Subtitle:** *Targeting High-Impact Travel Business Logic with Hard Safety Guarantees*
* **Top Section (The Travel Lifecycle & Invariants):**
  * `Search ➔ Quote ➔ Hold ➔ Payment_Pending ➔ Confirmed ➔ Cancelled ➔ Refunded`
  * Tested Invariants: Multi-tenant isolation (BOLA/IDOR), server-authoritative tariffs, hold token TTLs, and refund idempotency.
* **Bottom Left (The 5 Specialist Modules):**
  * Access Control, Business Logic & Pricing, Reservation Concurrency, Payment/Refund Idempotency, and API Hygiene.
* **Bottom Right (Safety & Independent Verification):**
  * **Safety Policy Gate:** Strict target allowlist, credential vault, rate limiter (5 req/s), backoff, and kill switch.
  * **Independent Verifier:** Separate reproduction pipeline with negative controls ensuring reliable, reproducible findings.

### Slide 3: API Inventory Intelligence, Business Impact & Execution Roadmap
* **Slide Title:** API Surface Governance & Execution Roadmap
* **Subtitle:** *Actionable Findings, Zombie/Shadow Discovery, and Staged Prototype Delivery*
* **Left Column (Zombie & Shadow API Governance):**
  * Reconciles discovered routes against 30–90 day gateway traffic.
  * Categorizes endpoints: Active (test continuously), Zombie (recommend HTTP 410 decommission), Shadow (generate OpenAPI spec).
* **Center Column (Business-Context Reporting):**
  * Findings prioritized by business blast radius: financial exposure, PII risk, and tenant boundary impact.
  * Provides developer-ready tickets with exact cURL PoC, request/response diffs, and recommended code fixes.
* **Right Column (Prototype Milestones for Round 2):**
  * *Milestone A:* Safety gate, synthetic tenant vault, and audit ledger.
  * *Milestone B:* Browser crawler and Travel Security Graph construction.
  * *Milestone C:* Execution of IDOR, price tampering, and refund race checks.
  * *Milestone D:* Automated retest verification and dashboard export.
