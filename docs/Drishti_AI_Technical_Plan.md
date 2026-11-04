# DRISHTI AI — Technical Plan & Architecture Blueprint

**Working title:** Drishti AI — Agentic Real-Time DAST for B2B Travel Ecosystems  
**Tagline:** *See the journey. Understand the risk. Prove the vulnerability.*  
**Track:** TBO Security Hackathon 2026 — Agentic Real-Time DAST  
**Document status:** Proposed solution blueprint; implementation and measured performance are not yet claimed.

---

## 1. Executive summary

Drishti AI is a business-context-aware security testing platform for B2B travel applications. It combines change detection, undocumented API discovery, travel-workflow modelling, targeted security tests, controlled execution, independent verification, business-impact triage, reporting and automated retesting.

Its central distinction from a generic scanner is that it reasons about **journeys and invariants**, not only URLs and payloads. It models how agencies, users, suppliers, bookings, passengers, inventory, payments and refunds relate to one another. It then tests whether the application preserves its security and transaction rules across normal, failure, retry and concurrent execution paths.

Drishti AI takes inspiration from engineering problems found in high-scale reservation and payment systems—such as scarce inventory, bursty demand, payment uncertainty, retries, concurrency and tenant boundaries. IRCTC/Tatkal is a useful public-facing reference for the *types of engineering pressures* involved; Drishti AI is not an attempt to reproduce IRCTC's internal architecture, and testing is limited to the hackathon's explicitly authorized synthetic staging environment.

**Product promise:** detect meaningful changes, select the tests that matter for those changes, prove findings with minimal evidence, and stay inside explicit safety constraints.

## 2. Problem and opportunity

B2B travel platforms combine several risk-heavy domains:

- Multi-tenant access: agencies, sub-agencies, suppliers, administrators and support roles share platform services.
- Stateful workflows: search, quote, hold, book, pay, confirm, modify, cancel and refund are dependent operations.
- Scarce inventory: seats, rooms, tickets and supplier allotments can be held or allocated by concurrent requests.
- Distributed transactions: booking, supplier confirmation, payment authorization/capture, callbacks and refunds may complete at different times.
- Evolving APIs: frontend bundles, partner integrations and backend releases introduce undocumented, deprecated or changed routes.

Periodic endpoint scanning can miss authorization and business-logic failures that only emerge across roles, objects, state transitions, retries or concurrency. Drishti AI targets those gaps while retaining conventional DAST techniques for suitable endpoints.

## 3. Design principles

1. **Journey-first, endpoint-aware:** represent the business workflow and still retain endpoint-level detail.
2. **Invariant-driven testing:** define what must always remain true, then test whether a controlled action violates it.
3. **LLM for reasoning, deterministic controls for execution:** models may propose hypotheses and test plans; policy enforcement, scope checks, request budgets, test execution and evidence validation must be deterministic.
4. **Safe by construction:** default-deny scope, synthetic accounts/data, staging-only execution, bounded concurrency, health checks and a global kill switch.
5. **Independent verification:** the attack planner/executor does not get to declare its own finding confirmed.
6. **Evidence before severity:** no confirmed issue without reproducible evidence; inconclusive results go to human review.
7. **Business-context severity:** explain impact in bookings, inventory, money, passenger data, supplier access and tenant isolation, alongside any conventional technical severity score.
8. **Human control over risky actions:** high-risk tests and critical findings require approval.
9. **No unsupported guarantees:** do not promise zero false positives or 100% reproducibility. Measure precision and report confidence transparently.

## 4. Scope

### 4.1 MVP scope

The first demonstrable version should implement a narrow, complete loop on a controlled travel application:

- Consume a deployment/change event or a supplied endpoint/bundle diff.
- Discover routes and parameters from a browser journey, captured HAR/proxy traffic and JavaScript bundles.
- Model at least two synthetic agencies and multiple roles.
- Build a small travel workflow graph with explicit security invariants.
- Reconcile discovered routes with provided traffic logs and label active, zombie or shadow candidates.
- Plan and safely execute a focused set of tests for cross-agency IDOR, fare/markup tampering, booking/hold concurrency and duplicate refund/idempotency issues.
- Independently verify findings with minimal evidence.
- Produce a structured report and human-readable dashboard/export.
- Retest a finding after a simulated fix.

### 4.2 Later extensions

- Additional authentication/session, mass-assignment, data-exposure, injection and controlled SSRF tests.
- Mobile and partner API coverage.
- Owner discovery from service/catalog metadata and richer ticketing integrations.
- More advanced graph-diff prioritization and drift detection.
- Additional supplier-specific workflows and failure models.

### 4.3 Explicit non-goals

- Scanning IRCTC or any real third-party system.
- Production testing without written authorization and a defined target list.
- Denial-of-service, stress testing, destructive tests, real payments, real passenger data or bulk data extraction.
- Claiming the platform has zero false positives, complete coverage or a guaranteed detection time before measurement.
- Letting an LLM execute arbitrary shell commands or arbitrary network requests.

## 5. Reference-system inspiration: what to borrow

The useful inspiration from high-scale reservation systems is not a specific undisclosed implementation. It is the set of properties that must remain correct under load and partial failure.

| Real-world pressure | Drishti AI test theme | Example security/consistency invariant |
|---|---|---|
| Many users competing for limited inventory | Bounded concurrency and hold/booking tests | One inventory unit cannot be committed to two incompatible bookings |
| Reservation holds expire | State-transition and expiry tests | An expired hold cannot authorize a later confirmation |
| Payment timeout or delayed callback | Retry and idempotency tests | A retry/callback cannot create a second charge or refund |
| Price and availability may change | Quote integrity tests | Client input cannot override authoritative server-side pricing |
| Many agencies share platform services | Tenant-isolation tests | An agency can access only objects it is authorized to access |
| Old and new APIs coexist | API inventory reconciliation | Legacy routes are identified, classified and assigned a recommended action |

**Tatkal-inspired module:** Drishti AI can model *bounded burst/concurrency behaviour* in a synthetic staging setup. It should test race windows, duplicate submissions, hold expiry, idempotency and fairness-related controls at a small, explicitly capped request budget. This is not a load test and must not create harmful traffic.

## 6. End-to-end architecture

The editable draw.io diagram is supplied separately. The logical flow is:

1. **Inputs and triggers:** CI/CD deploy events, API gateway/load-balancer logs, browser/HAR captures, frontend/mobile/partner bundles, DNS/certificate inventory, app logs, asset ownership and synthetic role credentials.
2. **Change intelligence/orchestrator:** normalize events, correlate changed assets and decide which journeys/endpoints need reassessment.
3. **Reconnaissance and app mapping:** crawl the approved UI with test roles, record requests/responses, extract routes from bundles and infer parameters, methods, authentication and object relationships.
4. **Travel Security Intelligence Graph:** store endpoints, roles, tenants, objects, workflow states, state transitions, invariants, supplier/payment dependencies, evidence and ownership metadata.
5. **Zombie/shadow inventory:** reconcile inferred API routes with 30–90 day traffic when available. Label endpoints active, zombie candidates or shadow candidates and preserve evidence for the classification.
6. **Attack planner:** use graph differences, business purpose, parameters, role relationships and known invariants to select minimal, relevant test cases.
7. **Risk/approval gate:** classify planned tests. Require human approval for high-risk or ambiguous actions. Reject unsupported/destructive test classes.
8. **Safety policy enforcement:** check target allowlist, environment, account, method/path policy, request budget, concurrency cap, health state and approval token before every request.
9. **Specialist executors:** access control; business logic/pricing; inventory/concurrency; payment/refund/idempotency; authentication/API hygiene/injection. Tool adapters may wrap controlled scanners where useful.
10. **Authorized staging target:** execute only against the provided production-like staging environment and synthetic data.
11. **Independent verifier:** reproduce the minimum proof using a separate verification plan and controlled fixtures. Return confirmed, not reproduced or inconclusive.
12. **Triage and business-impact scoring:** deduplicate, assess confidence, technical severity, business impact and likely owner.
13. **Human review and reporting:** critical/high-severity results receive review; ticket/dashboard output contains reproducible evidence and remediation guidance.
14. **Retest and feedback:** after a fix event, rerun the minimal regression proof; close only when the invariant is restored, otherwise reopen. Feed verified graph updates back into inventory and planning.

## 7. Travel Security Intelligence Graph

The graph is a core differentiator. It should model at least these node types:

- **Tenant:** agency, sub-agency, supplier or platform operator.
- **Identity and role:** user, service account, admin, agent, finance/support role.
- **API endpoint:** method, path pattern, service, version, auth requirement, parameters and last-seen metadata.
- **Business object:** quote, hold, booking, passenger, ticket, invoice, payment, refund, supplier allocation.
- **Workflow state:** searched, quoted, held, payment-pending, paid, confirmed, modified, cancelled, refund-pending, refunded, failed/expired.
- **Invariant:** access rule, price rule, inventory constraint, payment/refund rule or state-transition guard.
- **Evidence and finding:** request/response references, reproduction result, confidence, severity and owner.

Relationships include `OWNS`, `CAN_ACCESS`, `CREATES`, `TRANSITIONS_TO`, `CALLS`, `DEPENDS_ON`, `PROCESSES_PAYMENT_FOR`, `REFUNDS`, `EXPOSES` and `VIOLATES`.

For the MVP, this can be implemented using a relational database with explicit relationship tables/JSON fields. A dedicated graph database is optional; do not add infrastructure merely for appearance.

## 8. Workflow model and invariants

The travel lifecycle is not a single linear chain. Treat it as a configurable directed state graph with branches for supplier failure, payment failure, timeout, expiry, partial cancellation and retry.

Illustrative states:

`SEARCHED → QUOTED → HELD → PAYMENT_PENDING → PAID → CONFIRMED`

Possible branches:

- `HELD → EXPIRED`
- `PAYMENT_PENDING → PAYMENT_FAILED`
- `PAYMENT_PENDING → PAYMENT_UNKNOWN → RECONCILIATION_REQUIRED`
- `CONFIRMED → MODIFICATION_PENDING → CONFIRMED`
- `CONFIRMED → CANCELLATION_PENDING → CANCELLED → REFUND_PENDING → REFUNDED`
- `CONFIRMED → PARTIALLY_CANCELLED → PARTIAL_REFUND_PENDING → PARTIALLY_REFUNDED`

Core invariants to encode and test:

1. **Tenant isolation:** an identity from Agency B cannot read or mutate Agency A's booking, passenger, invoice or payment objects unless an explicitly authorized cross-tenant role exists.
2. **Server-authoritative pricing:** client-supplied fare, markup, currency, discount and total values cannot override an authoritative quote or pricing policy.
3. **Inventory exclusivity:** the same inventory unit cannot be committed to incompatible active bookings.
4. **Hold expiry:** an expired/released hold cannot be used to confirm a booking.
5. **Payment idempotency:** repeated requests or duplicate callbacks cannot create multiple captures for one intended payment operation.
6. **Refund idempotency and bounds:** repeated cancellation/refund attempts cannot create multiple refunds; total refunds cannot exceed the eligible captured amount.
7. **Role boundaries:** a sub-agent cannot perform administrative or financial actions outside its assigned permissions.
8. **Supplier isolation:** one supplier cannot access or alter another supplier's protected resources.

## 9. Specialist test agents

| Specialist | Primary coverage | Controlled proof example |
|---|---|---|
| Access-control agent | BOLA/IDOR, horizontal/vertical privilege, tenant isolation | Agency B attempts to read a synthetic Agency A booking; verifier checks ownership boundary |
| Business-logic agent | Fare/markup/currency, coupon reuse, skipped steps, negative values | Alter client values and compare with server-authoritative quote and persisted booking total |
| Inventory/concurrency agent | Hold expiry, duplicate allocation, race conditions | Small bounded set of synchronized requests against synthetic inventory; assert only permitted final state |
| Payment/refund agent | Retries, callbacks, idempotency, refund bounds | Replay a controlled callback or retry against a sandbox payment simulator and inspect ledger state |
| API/auth/data agent | Auth/session policy, mass assignment, excessive data, safe injection probes | Validate role and schema expectations with non-destructive test values |

Specialists should return a normalized test result, not decide severity or file tickets directly.

## 10. Safety architecture and execution contract

All requests—including verifier requests and retests—must pass the same deterministic policy enforcement layer.

**Default-deny controls:**

- Exact host/environment allowlist and approved path/method constraints.
- Only supplied synthetic identities and credentials from a secret vault.
- No real passenger/payment data; redact sensitive values from retained evidence.
- Per-test and global request budgets; low bounded concurrency; backoff on latency/errors/health alarms.
- Explicit prohibition on DoS, destructive actions, bulk extraction, persistence and out-of-scope redirect following.
- Egress restrictions for SSRF-like tests; use mock endpoints and controlled sinks.
- Global stop switch and immutable request audit trail.
- Human approval tokens for high-risk tests; approval must be bound to target, test type and time window.

**LLM isolation:** the model receives sanitized metadata and test observations, not raw secrets. It may propose a test plan in a strict schema. A deterministic validator rejects unknown hosts, unapproved methods, forbidden payload classes, excessive concurrency and unsupported actions. The model cannot invoke the network directly or retrieve credentials directly.

## 11. Independent verification and evidence

The verifier is a separate component with a narrow interface. It receives a candidate claim, a test fixture identifier and the minimum reproduction recipe; it does not blindly trust the attack agent's conclusion.

Each finding should include:

- Target service and endpoint (redacted where appropriate).
- Vulnerability class and violated invariant.
- Required test role/tenant and synthetic object identifiers.
- Minimal request/response evidence with secrets and PII redacted.
- Expected versus observed behaviour.
- Reproduction status: confirmed / not reproduced / inconclusive.
- Confidence and repeatability observations.
- Business impact and affected workflow.
- Suggested remediation and retest procedure.

Do not state “zero false positives.” Track confirmed findings, non-reproductions, inconclusive results and reviewer overrides to calculate precision over time.

## 12. Zombie and shadow API inventory

Use the TBO definitions:

- **Active:** discovered/mapped and seen in legitimate traffic.
- **Zombie:** still reachable/responsive but no legitimate traffic observed in the selected window.
- **Shadow:** observed in traffic but absent from the inferred/documented inventory.

A `/v1/` path is not automatically zombie; route naming is only a discovery hint. Lack of traffic is evidence over a defined observation window, not proof that an endpoint is safe to delete. Account for seasonality, low-frequency administrative operations, partner-specific traffic and incomplete logs.

For each candidate record: method/path, service/version, last-seen traffic, observation window, discovery source, auth requirement, reachability, data exposure assessment, comparison with current route, likely owner, confidence and recommended action (retain, document, restrict, investigate or decommission).

## 13. Risk scoring and reporting

Keep technical severity and business context visible as separate dimensions. Use a recognized technical scoring method where the evidence supports it, then add business context such as:

- Cross-tenant reach and number/type of affected objects.
- Passenger PII exposure.
- Financial exposure (payment, refund, credit or inventory value).
- Privilege level and workflow stage.
- Exploit preconditions and reproducibility.

Avoid an opaque single score. Report severity, confidence, business impact and rationale independently. Route critical/high findings to human review before external escalation.

## 14. Suggested implementation stack

This is a practical starting point, not a mandatory technology prescription.

| Layer | Suggested implementation | Rationale |
|---|---|---|
| Orchestrator/API | Python + FastAPI; a finite-state workflow engine or LangGraph if useful | Clear tool boundaries and observable workflow steps |
| Browser discovery | Playwright | Role-based journeys and HAR capture |
| HTTP/testing adapters | HTTPX/Requests; mitmproxy for traffic capture | Controlled request execution and replay |
| Scanner adapters | OWASP ZAP and carefully scoped Nuclei templates | Conventional coverage where appropriate; not a substitute for business-logic tests |
| Model | Optional local or hosted LLM behind a provider adapter | Route classification, hypothesis generation and plan explanation |
| Policy engine | Deterministic Python rules/schema validation | Non-LLM enforcement for scope, request budgets and approvals |
| Persistence | PostgreSQL; graph relationships represented in tables initially | Keeps the MVP deployable and auditable |
| Queue/budget coordination | Redis or a database-backed queue if parallel workers are required | Central request/concurrency budgets |
| UI/reporting | Lightweight web dashboard plus JSON/HTML/Markdown export | Demo findings, inventory and audit trail |
| Integrations | Webhook/Jira/Teams adapters, with offline export fallback | Ticket-ready reports without blocking the demo |

Do not begin with a large multi-agent framework. Start with an orchestrator, a structured test-plan schema, a few specialist modules, a policy gate and a verifier. Add agent autonomy only where it produces measurable value.

## 15. Demo scenario

A strong end-to-end demo should show one deployment-triggered finding:

1. A new/changed booking endpoint appears in a synthetic staging deployment.
2. Drishti detects the change and updates the endpoint graph.
3. Discovery associates it with the booking workflow and agency role.
4. The planner selects a cross-agency authorization test because the endpoint accepts a booking identifier.
5. The safety gate validates target, synthetic account, request budget and test approval.
6. The executor attempts one bounded cross-tenant access check.
7. The independent verifier confirms or rejects the candidate using a second controlled proof.
8. Triage produces a finding with expected/observed behaviour, business impact and remediation.
9. A simulated patch is deployed; the retest agent reruns the proof and marks the finding fixed only if the invariant now holds.

A second short demo can show a concurrency/payment invariant using a sandbox ledger and a small, explicitly bounded number of concurrent synthetic requests.

## 16. Build roadmap and acceptance gates

### Milestone A — Safe foundation

- Define target allowlist, test identities, synthetic data and request policy.
- Create audit logging, global stop switch and health monitor.
- Acceptance: out-of-scope host, unapproved method and exhausted request budget are rejected before network execution.

### Milestone B — Discovery and graph

- Capture one role-based booking journey.
- Parse HAR traffic and frontend bundles.
- Store endpoint, role, object and state-transition relationships.
- Acceptance: generated inventory identifies the expected journey endpoints and records source evidence.

### Milestone C — Inventory intelligence

- Ingest sample 30–90 day traffic logs.
- Reconcile traffic routes with discovered routes.
- Acceptance: seeded active, zombie and shadow examples are correctly classified with confidence and evidence.

### Milestone D — Attack planning and first specialists

- Implement cross-agency IDOR and fare/markup tests first.
- Add one bounded inventory/concurrency and one idempotency/refund test against simulators.
- Acceptance: each test is tied to an invariant and only runs through the policy gate.

### Milestone E — Verification, triage and retest

- Separate verifier workflow and normalized evidence schema.
- Add business-impact explanation, deduplication, report export and retest.
- Acceptance: seeded vulnerability is confirmed; a negative control is not reported as confirmed; a patched issue closes after retest.

### Milestone F — Live demonstration and evaluation

- Measure time from trigger to candidate and verified finding.
- Record request counts, policy denials, verifier outcomes and false-positive observations.
- Demonstrate API inventory and an audit replay.
- Acceptance: every demonstrated action is replayable from the audit log and remains within the approved environment.

## 17. Evaluation metrics

| Metric | Definition |
|---|---|
| Change-to-plan latency | Time from change event to approved test plan |
| Change-to-verified latency | Time from change event to confirmed finding |
| Precision | Confirmed true findings / all findings classified as confirmed after review |
| Verification rate | Candidate findings independently reproduced / candidates sent to verifier |
| Inconclusive rate | Candidate findings that cannot be safely confirmed or rejected |
| In-scope compliance | Requests within approved scope / total attempted requests (target: 100%) |
| Policy enforcement | Blocked out-of-scope/over-budget actions and successful audit coverage |
| Journey coverage | Number of modeled journeys and transitions with mapped tests |
| Inventory quality | Correctly classified seeded active/zombie/shadow routes |
| Retest closure accuracy | Fixed issues closed only after successful negative retest |

Report measured values from the actual prototype; do not substitute aspirational numbers.

## 18. Risks and mitigations

| Risk | Mitigation |
|---|---|
| LLM hallucinates routes or test logic | Treat outputs as hypotheses; require schema validation and evidence |
| Test causes state changes | Use disposable synthetic fixtures, transaction rollback/reset and restricted operations |
| Race test overloads staging | Very small concurrency caps, rate budgets, health alarms and immediate stop |
| False zombie classification | Use explicit observation windows, log completeness and confidence labels |
| Verifier shares attack-agent bias | Separate workflow, independent credentials/recipe and negative controls |
| Secrets leak into prompts/reports | Secret vault, redaction, least privilege and sanitized context |
| Architecture becomes too complex | Build a vertical slice; only add agents with measurable benefit |

## 19. How to explain the supplied reference flowchart

The uploaded screenshot is a cropped view of **Figure 1, “Reference architecture for agentic real-time DAST,” on page 3 of the TBO participant pack**. It is the challenge's suggested architecture, not a Drishti AI-specific diagram.

Visible elements and their meaning:

- **App knowledge graph** and **traffic logs (last 30–90 days)** feed the inventory agent.
- **Inventory agent (zombie/shadow APIs)** reconciles discovered routes with usage evidence.
- **Attack planner** chooses targeted tests.
- **Attack executor agents** cover access control, business logic, authentication, injection and SSRF.
- **Verifier agent** checks candidate findings.
- **Triage and severity agent** deduplicates and prioritizes them.
- **Reporter agent** sends results to Jira/Teams/dashboard.
- **Safety layer** enforces scope/allowlists, rate limits, health monitoring, test-account vault and request audit before requests reach the staging/production-like app.
- **Human reviewer** approves risky tests and reviews high-severity findings.
- **Retest loop** reruns a proof after a fix is deployed.

The new Drishti AI diagram retains this loop and makes several elements explicit: change intelligence, browser/HAR/bundle discovery, the travel security graph and invariants, reservation concurrency, payment/refund idempotency, a deterministic policy gate on every test request, a separate finding-review path and feedback into the graph.

**In one sentence:** the supplied diagram is the TBO reference architecture; Drishti AI is your proposed implementation, specialized for B2B travel journeys and transaction invariants.

---

## Appendix A — Example structured finding

```json
{
  "finding_id": "DRI-AC-001",
  "title": "Cross-agency booking object access",
  "status": "confirmed",
  "class": "broken_object_level_authorization",
  "environment": "authorized-synthetic-staging",
  "invariant": "An agency may access only bookings it owns or is explicitly authorized to manage.",
  "test_fixture": {
    "attacker_tenant": "AGENCY_B_TEST",
    "owner_tenant": "AGENCY_A_TEST",
    "object": "SYNTHETIC_BOOKING_001"
  },
  "expected": "Agency B receives an authorization denial and no protected booking data.",
  "observed": "The controlled verifier received booking data belonging to Agency A.",
  "evidence": "Redacted request/response references in the audit store",
  "confidence": "high",
  "business_impact": ["cross-tenant exposure", "booking data", "potential passenger PII"],
  "remediation": "Enforce server-side object ownership and tenant authorization on every read and mutation path.",
  "retest": "Repeat the same synthetic cross-tenant request after the fix; close only when denied."
}
```

## Appendix B — Scope reminder

Drishti AI is to be demonstrated only against the TBO-provided/approved production-like staging system and synthetic test data. IRCTC and other real systems are inspiration and must not be scanned or tested as part of this project.
