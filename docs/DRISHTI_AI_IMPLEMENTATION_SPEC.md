# DRISHTI AI — Implementation Specification & Engineering Blueprint
**Target Milestone:** Milestone 1 — One complete, reproducible security finding against the organizer's authorized staging environment  
**Scope Freeze:** Core 7-Stage Single-Loop Execution (No UI dashboards, no graph visualizers, no extraneous invariants until Milestone 1 passes)  
**Document Status:** Approved Engineering Specification  

---

## 1. P0 Feasibility Matrix (Reconstructed & Formatted)

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

## 2. The Four Architectural Mandates

### 2.1 The Authorization Contract
All active execution is governed by a legally binding, machine-enforced authorization contract. Any attempted request outside these boundaries is dropped immediately by the policy engine before network socket allocation.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "AuthorizationContract",
  "type": "object",
  "properties": {
    "permitted_targets": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Exact FQDNs or IP ranges explicitly authorized by organizers"
    },
    "test_tenants": {
      "type": "object",
      "properties": {
        "attacker_tenant_id": { "type": "string" },
        "victim_tenant_id": { "type": "string" },
        "subagent_tenant_id": { "type": "string" }
      },
      "required": ["attacker_tenant_id", "victim_tenant_id"]
    },
    "request_budgets": {
      "type": "object",
      "properties": {
        "max_requests_per_second": { "type": "number", "maximum": 10.0 },
        "max_concurrent_connections": { "type": "integer", "maximum": 5 },
        "max_total_requests_per_run": { "type": "integer", "maximum": 500 }
      },
      "required": ["max_requests_per_second", "max_concurrent_connections", "max_total_requests_per_run"]
    },
    "prohibited_actions": {
      "type": "array",
      "items": { "type": "string" },
      "default": [
        "DROP", "DELETE_PRODUCTION_DATA", "DOS_BURST", "PERSISTENT_MODIFICATION",
        "BULK_DATA_EXTRACTION", "REAL_PAYMENT_SUBMISSION"
      ]
    },
    "emergency_stop_triggers": {
      "type": "object",
      "properties": {
        "latency_spike_threshold_ms": { "type": "integer", "default": 1000 },
        "consecutive_5xx_threshold": { "type": "integer", "default": 3 },
        "out_of_scope_attempt_action": { "type": "string", "enum": ["IMMEDIATE_TERMINATE"], "default": "IMMEDIATE_TERMINATE" }
      }
    }
  },
  "required": ["permitted_targets", "test_tenants", "request_budgets", "prohibited_actions", "emergency_stop_triggers"]
}
```

### 2.2 Evidence-Backed Provenance for LLM Reasoning
To eliminate hallucinations, the LLM is prohibited from asserting endpoints or journey states without verifiable proof. Every inferred schema node must carry cryptographic provenance anchoring it to an observed raw network request.

```
┌─────────────────────────────────────────────────────────────┐
│ RAW HAR / PROXY CAPTURE                                     │
│ Frame ID: har_req_88129                                      │
│ POST /api/v2/hotels/book HTTP/1.1                           │
│ Host: staging.tbo-sandbox.internal                          │
│ Payload: {"quote_id": "QT-991", "guest": "Alice"}          │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ LLM INFERENCE ENGINE (PROPOSAL ONLY)                        │
│ Proposal:                                                   │
│   • Path: /api/v2/hotels/book                               │
│   • Semantic: Reservation Confirmation                      │
│   • Source Frame: har_req_88129                             │
│   • Confidence: 0.94                                        │
│   • Evidence Anchor: SHA-256(Raw Request Headers + Body)    │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ DETERMINISTIC VALIDATOR (ACCEPT / REJECT)                   │
│   [Check 1] Does har_req_88129 exist in immutable storage?  │
│   [Check 2] Does SHA-256 match recorded packet hash?        │
│   [Check 3] Does Confidence Score >= 0.85?                  │
│   ==> ACCEPTED & INGESTED INTO GRAPH                        │
└─────────────────────────────────────────────────────────────┘
```

### 2.3 Strengthened Invariant I-01 (Tenant Isolation / BOLA) Verification
A naive check that only relies on HTTP 200 vs. HTTP 403 produces unacceptable false positives. An API may return HTTP 200 with an empty array, a localized error message, or unprivileged public metadata.

**Drishti AI Multi-Step Invariant Verification:**
```python
def verify_tenant_isolation_violation(
    attacker_tenant_id: str,
    victim_tenant_id: str,
    victim_object_id: str,
    response: HTTPResponse
) -> InvariantEvaluationResult:
    # 1. Gate: Response must indicate success
    if response.status_code not in (200, 201, 206):
        return InvariantEvaluationResult(status="PASSED_SECURE", reason="Status code not 2xx")
    
    body = response.json()
    
    # 2. Critical Check: Ownership Verification
    # Must explicitly prove the returned entity belongs to the VICTIM tenant
    owner_id = body.get("agency_id") or body.get("tenant_id") or body.get("owner_id")
    if owner_id != victim_tenant_id:
        return InvariantEvaluationResult(
            status="NOT_REPRODUCED",
            reason=f"Response does not assert ownership of victim tenant {victim_tenant_id}"
        )
    
    # 3. Critical Check: Sensitive Data Disclosure
    # Must prove protected fields were exposed (passengers, PNR, payment voucher)
    sensitive_markers = ["passenger_name", "passport_number", "pnr", "invoice_amount", "voucher_code"]
    exposed_fields = [k for k in sensitive_markers if k in body or any(k in str(v) for v in body.values())]
    
    if not exposed_fields:
        return InvariantEvaluationResult(
            status="INCONCLUSIVE",
            reason="Entity owned by victim returned, but zero sensitive fields exposed."
        )
        
    return InvariantEvaluationResult(
        status="CONFIRMED_VIOLATION",
        reason=f"Agency {attacker_tenant_id} successfully read Agency {victim_tenant_id} object {victim_object_id}.",
        exposed_fields=exposed_fields
    )
```

### 2.4 Strict Reproducibility Definition
Every finding filed by Drishti AI must be 100% reproducible by an external reviewer without using Drishti AI itself. A finding is considered reproducible **if and only if**:
1. **Ordered Sequence:** Contains the exact preceding state-setup requests (e.g., Step 1: Create Quote, Step 2: Acquire Hold, Step 3: Exploit).
2. **Self-Contained cURL Command:** Includes full headers, sanitized synthetic auth tokens, target host, and explicit payload.
3. **Response Evidence & Diff:** Preserves status code, response headers, and redacted body snippet proving invariant violation.
4. **Monotonic Audit Signature:** Cryptographic hash of the test session record and timestamp.
5. **Retest Recipe:** A deterministic script asserting that after remediation, the exact sequence yields HTTP 403/404 with ownership error.

---

## 3. Repository Architecture & Directory Structure

```
drishti-ai/
├── README.md                           # Setup, usage, and Milestone 1 reproduction instructions
├── pyproject.toml                      # Python 3.11+ packaging, dependencies, and lint configs
├── configs/
│   ├── auth_contract.json              # Active authorization contract (domains, accounts, limits)
│   └── test_profiles.json              # Synthetic tenant profiles (Agency A, Agency B, Sub-Agent)
├── drishti/
│   ├── __init__.py
│   ├── main.py                         # Single-loop CLI entrypoint
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py                   # Pydantic configuration loader
│   │   ├── contract.py                 # AuthorizationContract parser and validator
│   │   ├── exceptions.py               # Custom exceptions (PolicyViolation, HealthBreach)
│   │   └── models.py                   # Core Pydantic data schemas
│   ├── discovery/
│   │   ├── __init__.py
│   │   ├── crawler.py                  # Playwright headless role-based crawler
│   │   ├── har_parser.py               # Ingests and indexes raw network HAR files
│   │   └── bundle_inspector.py         # Extracts route patterns from frontend JS bundles
│   ├── graph/
│   │   ├── __init__.py
│   │   ├── schema.py                   # NetworkX node & edge definitions
│   │   └── engine.py                   # Living Travel Security Intelligence Graph
│   ├── planner/
│   │   ├── __init__.py
│   │   ├── prompt_templates.py         # Grounded prompts with strict JSON schema outputs
│   │   └── llm_orchestrator.py         # Generates hypotheses with provenance anchors
│   ├── policy/
│   │   ├── __init__.py
│   │   ├── gate.py                     # Deterministic Policy Gate & Scope Allowlist
│   │   ├── rate_limiter.py             # Token-bucket rate limiter & concurrency cap
│   │   ├── health_monitor.py           # Latency tracker and automatic backoff
│   │   └── audit_logger.py             # Immutable SQLite request/response ledger
│   ├── executors/
│   │   ├── __init__.py
│   │   ├── base.py                     # Abstract Base Class for Specialist Executors
│   │   ├── bola_executor.py            # BOLA / Cross-Agency IDOR specialist (I-01)
│   │   └── pricing_executor.py         # Fare & Markup Tampering specialist (I-02)
│   ├── verifier/
│   │   ├── __init__.py
│   │   ├── independent_verifier.py     # Independent reproduction runner
│   │   └── negative_controls.py        # Validates that normal behavior does not trip alarms
│   ├── reporter/
│   │   ├── __init__.py
│   │   ├── ticket_builder.py           # Synthesizes markdown and JSON findings
│   │   └── curl_generator.py           # Generates standalone standalone cURL recipes
│   └── retest/
│       ├── __init__.py
│       └── retest_engine.py            # Evaluates candidate patches against verification proof
└── tests/
    ├── unit/                           # Tests for policy gate, rate limiter, and parsers
    ├── integration/                    # Mock staging integration tests
    └── fixtures/                       # Recorded HAR files and synthetic staging responses
```

---

## 4. Module Interfaces & Python ABCs

### 4.1 Policy Gate Interface (`drishti.policy.gate`)
```python
from abc import ABC, abstractmethod
from drishti.core.models import OutgoingTestRequest, PolicyDecision

class IPolicyGate(ABC):
    """
    Non-negotiable deterministic security boundary.
    Every single HTTP request dispatched by executors, verifiers,
    or retest engines must pass through this interface.
    """

    @abstractmethod
    def evaluate_request(self, request: OutgoingTestRequest) -> PolicyDecision:
        """
        Validates target host, URI path, method, payload safety,
        tenant credentials, and current rate limits.
        Returns PolicyDecision(allowed=True) or raises PolicyViolationError.
        """
        pass

    @abstractmethod
    def record_response_telemetry(self, latency_ms: float, status_code: int) -> None:
        """
        Updates latency health monitors and triggers backoff if target shows strain.
        """
        pass

    @abstractmethod
    def trigger_emergency_stop(self, reason: str) -> None:
        """
        Immediately trips the circuit breaker, stopping all active threads.
        """
        pass
```

### 4.2 Specialist Executor Interface (`drishti.executors.base`)
```python
from abc import ABC, abstractmethod
from drishti.core.models import AttackHypothesis, CandidateFinding

class ISpecialistExecutor(ABC):
    """
    Abstract interface for vulnerability class specialists.
    """

    @property
    @abstractmethod
    def invariant_id(self) -> str:
        """Unique identifier of the invariant being verified (e.g., 'INV-01-TENANT-ISOLATION')"""
        pass

    @abstractmethod
    async def execute_test(self, hypothesis: AttackHypothesis) -> CandidateFinding | None:
        """
        Executes a targeted, bounded probe against the authorized staging environment.
        Must dispatch all requests via the injected IPolicyGate.
        """
        pass
```

### 4.3 Independent Verifier Interface (`drishti.verifier.independent_verifier`)
```python
from abc import ABC, abstractmethod
from drishti.core.models import CandidateFinding, VerifiedFinding

class IIndependentVerifier(ABC):
    """
    Decoupled verification module that proves or rejects candidate findings.
    """

    @abstractmethod
    async def verify_finding(self, candidate: CandidateFinding) -> VerifiedFinding:
        """
        1. Spins up an isolated, clean test fixture.
        2. Executes the candidate's exact reproduction recipe.
        3. Executes a negative control baseline.
        4. Validates ownership and sensitive data fields.
        Returns VerifiedFinding with status: CONFIRMED | NOT_REPRODUCED | INCONCLUSIVE.
        """
        pass
```

---

## 5. Core Data Schemas (Pydantic v2 Models)

```python
from pydantic import BaseModel, Field, HttpUrl
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum

class InvariantType(str, Enum):
    TENANT_ISOLATION = "I-01-TENANT-ISOLATION"
    PRICING_INTEGRITY = "I-02-SERVER-AUTHORITATIVE-PRICING"
    HOLD_EXPIRATION = "I-03-PERISHABLE-HOLD-EXPIRATION"
    REFUND_IDEMPOTENCY = "I-04-REFUND-BOUNDS-IDEMPOTENCY"

class VerificationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    INCONCLUSIVE = "INCONCLUSIVE"

class InferredEndpoint(BaseModel):
    endpoint_id: str
    method: str = Field(..., pattern="^(GET|POST|PUT|PATCH|DELETE)$")
    path_template: str
    auth_required: bool
    roles_observed: List[str]
    parameters: Dict[str, str]
    # Provenance fields
    source_har_request_id: str
    raw_packet_hash: str
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

class AttackHypothesis(BaseModel):
    hypothesis_id: str
    target_endpoint: InferredEndpoint
    invariant_targeted: InvariantType
    rationale: str
    test_strategy: str
    required_test_tenants: List[str]
    risk_level: str = Field(..., pattern="^(ROUTINE|ELEVATED|HIGH)$")

class ReproductionRecipe(BaseModel):
    step_number: int
    description: str
    curl_command: str
    expected_status: int
    payload_diff: Optional[Dict[str, Any]] = None

class VerifiedFinding(BaseModel):
    finding_id: str
    invariant_id: InvariantType
    status: VerificationStatus
    title: str
    target_endpoint: str
    violated_rule: str
    confidence_score: float
    # Blast radius
    business_impact: Dict[str, Any]
    exposed_sensitive_fields: List[str]
    # Strict Reproducibility
    reproduction_steps: List[ReproductionRecipe]
    request_evidence_hash: str
    raw_response_diff: str
    verified_at: datetime = Field(default_factory=datetime.utcnow)
    # Remediation
    suggested_fix: str
    retest_command: str
```

---

## 6. Execution Sequence: The 7-Step Frozen Loop

```
[Start Run: Staging Target + Auth Contract Loaded]
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 1: DETECT CHANGE                                       │
│ Ingest latest deploy event, git commit SHA, or HAR capture. │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 2: DISCOVER & INTERPRET ENDPOINTS                      │
│ Playwright executes role journeys; parses HAR traffic.      │
│ LLM infers parameters with PROVENANCE & CONFIDENCE >= 0.85. │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 3: IDENTIFY INVARIANT VIOLATION CANDIDATE              │
│ Planner matches endpoint against Invariant I-01 (IDOR) or   │
│ I-02 (Pricing Tampering); generates AttackHypothesis.       │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 4: EXECUTE POLICY-AUTHORIZED TEST                      │
│ Policy Gate verifies allowlist, budget, and credentials.    │
│ Specialist Executor dispatches rate-limited probe.          │
└─────────────────────┬───────────────────────────────────────┘
                      │ Candidate Finding (Raw Observation)
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 5: INDEPENDENT VERIFICATION & PROOF SYNTHESIS          │
│ Independent verifier checks:                                │
│   1. Negative control passes                                │
│   2. Victim ownership is strictly verified                  │
│   3. Sensitive fields are exposed                           │
│ Status confirmed: CONFIRMED.                                │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 6: GENERATE EVIDENCE-BACKED REPORT                     │
│ Synthesize self-contained finding with verified cURL PoC,   │
│ response diff, and developer patch.                         │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 7: RETEST AFTER REMEDIATION                            │
│ Dev deploys patch; Retest Engine re-executes exact proof.   │
│ Invariant passes (HTTP 403 / 404); Finding formally CLOSED. │
└─────────────────────────────────────────────────────────────┘
```

---

## 7. Six-Session Development Checklist (Path to Milestone 1)

This checklist provides a structured path for the engineering team to build, test, and deliver Milestone 1.

### Session 1: Safety Foundation, Contract & Immutable Ledger
* [ ] Initialize repository structure (`pyproject.toml`, directory layout).
* [ ] Implement `drishti.core.contract` and JSON Schema validation for `auth_contract.json`.
* [ ] Build `drishti.policy.gate`: strict FQDN domain allowlist and method filtering.
* [ ] Build `drishti.policy.rate_limiter`: token-bucket rate limiter (5 req/sec, max 2 concurrent).
* [ ] Build `drishti.policy.audit_logger`: SQLite immutable request/response ledger.
* [ ] **Session 1 Gate:** Unit test confirms any out-of-scope host or unapproved payload is immediately rejected before socket creation.

### Session 2: Recon, Traffic Capture & Provenance Extraction
* [ ] Configure Playwright headless crawler (`drishti.discovery.crawler`) with synthetic tenant credentials.
* [ ] Implement HAR file parser (`drishti.discovery.har_parser`) to extract requests, headers, and bodies.
* [ ] Build Pydantic model for `InferredEndpoint` with required `source_har_request_id` and SHA-256 hash.
* [ ] Wire LLM schema extraction prompt with structured output enforcement.
* [ ] **Session 2 Gate:** Ingesting a sample booking HAR yields structured endpoints with 100% verifiable packet hashes and confidence $\ge 0.85$.

### Session 3: Travel Security Intelligence Graph & Invariant Modeling
* [ ] Implement NetworkX graph engine (`drishti.graph.engine`).
* [ ] Define node classes: `Tenant`, `Role`, `Endpoint`, `BusinessObject`, `WorkflowState`.
* [ ] Model the primary travel state lifecycle: `Search ➔ Quote ➔ Hold ➔ Book`.
* [ ] Bind Invariant I-01 (Tenant Isolation) and Invariant I-02 (Server Pricing) to target nodes.
* [ ] **Session 3 Gate:** Graph accurately maps multi-tenant relationships and highlights when an endpoint accepts foreign tenant IDs.

### Session 4: Specialist Executors (BOLA & Pricing Tampering)
* [ ] Implement `ISpecialistExecutor` base class.
* [ ] Implement `BOLAExecutor` (`drishti.executors.bola_executor`):
  * Session A creates booking on Agency A.
  * Session B attempts to read/modify booking using Agency B credentials.
* [ ] Implement `PricingExecutor` (`drishti.executors.pricing_executor`):
  * Intercepts quote token and injects altered numeric fare / currency code.
* [ ] Route all executor network calls through the Policy Gate.
* [ ] **Session 4 Gate:** Executor successfully triggers candidate violation against a seeded local test harness.

### Session 5: Independent Verifier & Negative Controls
* [ ] Build `IndependentVerifier` (`drishti.verifier.independent_verifier`).
* [ ] Implement negative control runner (asserts that legitimate Agency A credentials access Agency A objects cleanly).
* [ ] Implement strict ownership and sensitive field parser (verifies `owner_id == victim_id` and checks for passenger/PNR leaks).
* [ ] Implement state labeling: `CONFIRMED`, `NOT_REPRODUCED`, or `INCONCLUSIVE`.
* [ ] **Session 5 Gate:** Verifier accurately flags a simulated empty 200 OK as `NOT_REPRODUCED`, and only flags real cross-tenant leaks as `CONFIRMED`.

### Session 6: Milestone 1 End-to-End Loop & Automated Retest
* [ ] Wire CLI command `drishti run --contract configs/auth_contract.json`.
* [ ] Generate standalone, self-contained markdown ticket with reproducible cURL commands.
* [ ] Build `RetestEngine` (`drishti.retest.retest_engine`):
  * Ingests a simulated patch commit.
  * Re-executes the exact verification recipe.
  * Asserts HTTP 403 Forbidden and closes ticket.
* [ ] **Milestone 1 Acceptance:** The entire 7-step loop runs from end to end against the authorized staging environment, producing one confirmed, reproducible finding that cleanly closes upon patch deployment.
