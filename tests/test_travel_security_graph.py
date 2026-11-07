"""Comprehensive acceptance test suite for Drishti AI Travel Security Intelligence Graph (Stage 4.1).

Verifies all core requirements and Stage 4.1 correctness enhancements:
1. Agency A and Agency B remain distinct nodes.
2. Identical routes on different services remain distinct (namespaced identity).
3. Multiple edges and evidence sources are preserved in MultiDiGraph.
4. A request attempt is not interpreted as confirmed authorization.
5. Partial captures never establish endpoint removal.
6. Allowed transitions and observed transitions remain separate.
7. An expired hold cannot transition to confirmed (Invariant I-03).
8. A refund cannot exceed the remaining refundable amount (Invariant I-04).
9. Payment/refund retries preserve idempotency (Invariant I-04).
10. I-01 and I-02 generate candidate paths from correct relationships.
11. Rebuilding the graph produces identical canonical digest.
12. Every generated attack hypothesis has traceable supporting evidence.
13. Same principal ID across two tenants -> separate nodes.
14. Same booking ID across two tenants -> separate nodes.
15. Crawler observations -> Endpoint, Role, Tenant, and Evidence relationships created.
16. Parameter locations preserved for body, query, and path.
17. Financial parameter on unconventional route -> I-02 hypothesis generated.
18. Multiple attacker/victim pairs -> distinct hypothesis IDs.
19. Observed expired hold -> POTENTIAL_INVARIANT_VIOLATION recorded on transition edge.
20. Negative refund inputs rejected.
21. Reused idempotency key with changed payload -> conflict detected.
22. Normal JSON export preserves true observation timestamps.
23. Graph traverses PRODUCES and CONSUMES relationships for BOLA paths.
24. Mermaid export produces valid syntax.
"""

import json
import pytest

from drishti.core.models import InvariantType
from drishti.discovery.crawler_models import BrowserObservation
from drishti.discovery.models import (
    CaptureCompleteness,
    ConfidenceAssessment,
    InventorySnapshot,
    NormalizedEndpoint,
    ParameterCandidate,
    ProvenanceSource,
)
from drishti.graph.engine import TravelSecurityGraph
from drishti.graph.schema import (
    AssetNode,
    BusinessObjectNode,
    EdgeType,
    EndpointNode,
    EvidenceSourceType,
    FactClassification,
    GraphEdge,
    NodeType,
    ObservationNode,
    ParameterNode,
    PrincipalNode,
    RoleNode,
    TenantNode,
    WorkflowStateNode,
)
from drishti.graph.state_machine import (
    BookingState,
    HoldState,
    IdempotencyRecord,
    PaymentState,
    QuoteState,
    RefundState,
    TransitionOutcome,
    validate_payment_idempotency,
    validate_refund_bounds,
    validate_transition,
)


@pytest.fixture
def empty_graph():
    """Initializes a fresh TravelSecurityGraph instance."""
    return TravelSecurityGraph()


# =============================================================================
# Test 1: Agency A and Agency B remain distinct
# =============================================================================
def test_1_agency_a_and_agency_b_remain_distinct(empty_graph):
    """Tenant A and Tenant B must remain strictly isolated nodes in the graph."""
    g = empty_graph
    t_a_id = g.add_tenant(TenantNode(tenant_id="TENANT-AGENCY-A", name="Agency Alpha", tenant_type="agency"))
    t_b_id = g.add_tenant(TenantNode(tenant_id="TENANT-AGENCY-B", name="Agency Beta", tenant_type="agency"))

    assert t_a_id != t_b_id
    assert g.graph.has_node("tenant:TENANT-AGENCY-A")
    assert g.graph.has_node("tenant:TENANT-AGENCY-B")

    # Add business objects owned by Agency A
    b_a_id = g.add_business_object(
        BusinessObjectNode(
            object_type="Booking",
            object_id="BK-A001",
            owner_tenant_id="TENANT-AGENCY-A",
            canary_fixture_id="canary_alpha_123",
        )
    )

    # Agency A OWNS Booking A
    edges = g.graph.get_edge_data("tenant:TENANT-AGENCY-A", b_a_id)
    assert edges is not None
    assert any(data.get("edge_type") == EdgeType.OWNS.value for data in edges.values())

    # Agency B does NOT own Booking A
    edges_b = g.graph.get_edge_data("tenant:TENANT-AGENCY-B", b_a_id)
    assert edges_b is None


# =============================================================================
# Test 2: Identical routes on different services remain distinct
# =============================================================================
def test_2_identical_routes_on_different_services_remain_distinct(empty_graph):
    """Identical paths across different assets or origins must not collide."""
    g = empty_graph
    ep1 = NormalizedEndpoint(
        method="GET",
        route_template="/api/v1/bookings/{booking_id}",
        asset_id="primary-b2b-api",
        canonical_origin="https://b2b.tbo.com",
        confidence=ConfidenceAssessment(score=1.0),
    )
    ep2 = NormalizedEndpoint(
        method="GET",
        route_template="/api/v1/bookings/{booking_id}",
        asset_id="supplier-gateway-api",
        canonical_origin="https://supplier.tbo.com",
        confidence=ConfidenceAssessment(score=1.0),
    )

    assert ep1.endpoint_identity != ep2.endpoint_identity
    g.ingest_normalized_endpoints([ep1, ep2])

    node1 = f"endpoint:{ep1.endpoint_identity}"
    node2 = f"endpoint:{ep2.endpoint_identity}"
    assert g.graph.has_node(node1)
    assert g.graph.has_node(node2)
    assert node1 != node2


# =============================================================================
# Test 3: Multiple edges and evidence sources are preserved
# =============================================================================
def test_3_multiple_edges_and_evidence_sources_preserved(empty_graph):
    """MultiDiGraph preserves multiple edges between same nodes with distinct evidence."""
    g = empty_graph
    ep_id = "primary-api:https://api.tbo.com:GET:/api/v1/bookings"
    g.add_endpoint(EndpointNode(endpoint_identity=ep_id, method="GET", route_template="/api/v1/bookings"))

    # Observation 1 from Agency Admin
    edge_key_1 = g.record_observed_request(
        principal_or_role_id="role:Agency_Admin",
        endpoint_identity=ep_id,
        evidence_id="OBS-HAR-001",
        tenant_context="TENANT-AGENCY-A",
        role_context="Agency_Admin",
    )

    # Observation 2 from Sub-Agent
    edge_key_2 = g.record_observed_request(
        principal_or_role_id="role:Sub_Agent",
        endpoint_identity=ep_id,
        evidence_id="OBS-CRAWL-002",
        tenant_context="TENANT-AGENCY-A",
        role_context="Sub_Agent",
    )

    assert edge_key_1 != edge_key_2
    edges = g.graph.get_edge_data(f"endpoint:{ep_id}", "role:Agency_Admin")
    assert edges is not None
    assert len(edges) >= 1

    edges_sub = g.graph.get_edge_data(f"endpoint:{ep_id}", "role:Sub_Agent")
    assert edges_sub is not None
    assert len(edges_sub) >= 1


# =============================================================================
# Test 4: A request attempt is not interpreted as confirmed authorization
# =============================================================================
def test_4_request_attempt_not_interpreted_as_confirmed_authorization(empty_graph):
    """An observed HTTP 200 response must not be confused with verified authorization."""
    g = empty_graph
    ep_id = "primary-api:https://api.tbo.com:GET:/api/v1/bookings/{id}"
    g.add_endpoint(EndpointNode(endpoint_identity=ep_id, method="GET", route_template="/api/v1/bookings/{id}"))

    g.record_observed_response(
        endpoint_identity=ep_id,
        recipient_id="role:Agency_Admin",
        status_code=200,
        evidence_id="OBS-ATTEMPT-01",
        tenant_context="TENANT-AGENCY-B",
        role_context="Agency_Admin",
    )

    edges = g.graph.get_edge_data(f"endpoint:{ep_id}", "role:Agency_Admin")
    assert edges is not None
    edge_types = [d.get("edge_type") for d in edges.values()]

    assert EdgeType.OBSERVED_RESPONSE_TO.value in edge_types
    assert EdgeType.AUTHORIZED_ACCESS_CONFIRMED.value not in edge_types


# =============================================================================
# Test 5: Partial captures never establish endpoint removal
# =============================================================================
def test_5_partial_captures_never_establish_endpoint_removal(empty_graph):
    """A partial capture omitting an endpoint does NOT cause its deletion."""
    g = empty_graph
    ep_existing = NormalizedEndpoint(
        method="GET",
        route_template="/api/v1/bookings/{id}",
        asset_id="primary-api",
        canonical_origin="https://api.tbo.com",
        confidence=ConfidenceAssessment(score=1.0),
    )
    g.ingest_normalized_endpoints([ep_existing])
    assert g.graph.has_node(f"endpoint:{ep_existing.endpoint_identity}")

    ep_new = NormalizedEndpoint(
        method="POST",
        route_template="/api/v1/search",
        asset_id="primary-api",
        canonical_origin="https://api.tbo.com",
        confidence=ConfidenceAssessment(score=0.9),
    )
    snapshot = InventorySnapshot(
        snapshot_id="SNAP-PARTIAL-02",
        capture_completeness=CaptureCompleteness.PARTIAL.value,
        endpoints={ep_new.endpoint_identity: ep_new},
    )
    g.ingest_inventory_snapshot(snapshot)

    assert g.graph.has_node(f"endpoint:{ep_existing.endpoint_identity}")
    assert g.graph.has_node(f"endpoint:{ep_new.endpoint_identity}")


# =============================================================================
# Test 6: Allowed transitions and observed transitions remain separate
# =============================================================================
def test_6_allowed_and_observed_transitions_remain_separate(empty_graph):
    """Specification ALLOWED transitions vs runtime OBSERVED transitions remain distinct edges."""
    g = empty_graph
    hold_active = "state:Hold:ACTIVE"
    hold_confirmed = "state:Hold:CONFIRMED"

    edges = g.graph.get_edge_data(hold_active, hold_confirmed)
    assert edges is not None
    assert any(d.get("edge_type") == EdgeType.TRANSITION_ALLOWED.value for d in edges.values())

    g.record_observed_transition("Hold", "ACTIVE", "CONFIRMED", evidence_id="OBS-HAR-CONFIRM-99")

    edges_after = g.graph.get_edge_data(hold_active, hold_confirmed)
    edge_types = [d.get("edge_type") for d in edges_after.values()]
    assert EdgeType.TRANSITION_ALLOWED.value in edge_types
    assert EdgeType.TRANSITION_OBSERVED.value in edge_types


# =============================================================================
# Test 7: An expired hold cannot transition to confirmed (Invariant I-03)
# =============================================================================
def test_7_expired_hold_cannot_transition_to_confirmed():
    """Validates Invariant I-03: Hold.EXPIRED -> Hold.CONFIRMED is strictly DENIED."""
    outcome, rationale, inv = validate_transition("Hold", HoldState.EXPIRED.value, HoldState.CONFIRMED.value)
    assert outcome == TransitionOutcome.DENIED
    assert inv == InvariantType.HOLD_EXPIRATION.value
    assert "Expired reservation hold cannot be confirmed" in rationale


# =============================================================================
# Test 8: A refund cannot exceed remaining refundable amount (Invariant I-04)
# =============================================================================
def test_8_refund_cannot_exceed_remaining_amount():
    """Validates Invariant I-04: cumulative refunds must never exceed captured amount."""
    captured = 25000  # $250.00
    prior_refunds = [10000, 5000]  # $150.00 total prior refunds ($100.00 remaining)

    ok, _ = validate_refund_bounds(captured, prior_refunds, 8000)
    assert ok is True

    ok_exceed, msg = validate_refund_bounds(captured, prior_refunds, 12000)
    assert ok_exceed is False
    assert "Refund violation (I-04)" in msg


# =============================================================================
# Test 9: Payment/refund retries preserve idempotency (Invariant I-04)
# =============================================================================
def test_9_payment_refund_retries_preserve_idempotency():
    """Validates Invariant I-04: duplicate callbacks or retries do not trigger duplicate charges."""
    seen_keys = {"IDEMP-KEY-PAYMENT-444"}
    is_replay, msg = validate_payment_idempotency("IDEMP-KEY-PAYMENT-444", seen_keys)
    assert is_replay is True
    assert "Idempotent replay detected" in msg

    is_replay_fresh, _ = validate_payment_idempotency("IDEMP-KEY-PAYMENT-555", seen_keys)
    assert is_replay_fresh is False


# =============================================================================
# Test 10: I-01 and I-02 generate candidate paths from correct relationships
# =============================================================================
def test_10_invariants_bind_correct_nodes_and_parameters(empty_graph):
    """I-01 binds to booking/identifier endpoints, and I-02 binds to pricing parameters."""
    g = empty_graph
    ep_booking = NormalizedEndpoint(
        method="GET",
        route_template="/api/v1/bookings/{booking_id}",
        asset_id="primary-api",
        canonical_origin="https://api.tbo.com",
        parameters=[ParameterCandidate(name="booking_id", location="path", semantic_type="booking_identifier")],
        confidence=ConfidenceAssessment(score=1.0),
    )
    ep_checkout = NormalizedEndpoint(
        method="POST",
        route_template="/api/v1/checkout",
        asset_id="primary-api",
        canonical_origin="https://api.tbo.com",
        parameters=[
            ParameterCandidate(name="fare_amount", location="body", semantic_type="generic_parameter"),
            ParameterCandidate(name="currency", location="body", semantic_type="currency"),
        ],
        confidence=ConfidenceAssessment(score=1.0),
    )
    g.ingest_normalized_endpoints([ep_booking, ep_checkout])
    g.bind_invariants()

    inv_i01 = f"invariant:{InvariantType.TENANT_ISOLATION.value}"
    inv_i02 = f"invariant:{InvariantType.PRICING_INTEGRITY.value}"

    edges_i01 = g.graph.get_edge_data(inv_i01, f"endpoint:{ep_booking.endpoint_identity}")
    assert edges_i01 is not None

    edges_i02 = g.graph.get_edge_data(inv_i02, f"endpoint:{ep_checkout.endpoint_identity}")
    assert edges_i02 is not None

    param_matches = [
        target for _, target, data in g.graph.out_edges(inv_i02, data=True)
        if "fare_amount" in target
    ]
    assert len(param_matches) >= 1


# =============================================================================
# Test 11: Rebuilding graph produces identical canonical digest
# =============================================================================
def test_11_rebuilding_graph_produces_identical_canonical_digest():
    """Graph construction produces identical topological canonical digest across rebuilds."""
    def _build_sample_graph():
        g = TravelSecurityGraph()
        g.add_tenant(TenantNode(tenant_id="TENANT-AGENCY-A", name="Agency Alpha"))
        g.add_tenant(TenantNode(tenant_id="TENANT-AGENCY-B", name="Agency Beta"))
        ep = NormalizedEndpoint(
            method="GET",
            route_template="/api/v1/bookings/{id}",
            asset_id="primary-api",
            canonical_origin="https://api.tbo.com",
            confidence=ConfidenceAssessment(score=1.0),
        )
        g.ingest_normalized_endpoints([ep])
        return g.canonical_digest()

    digest1 = _build_sample_graph()
    digest2 = _build_sample_graph()

    assert digest1 == digest2
    assert len(digest1) == 64


# =============================================================================
# Test 12: Every generated attack hypothesis has traceable supporting evidence
# =============================================================================
def test_12_every_generated_attack_hypothesis_has_traceable_evidence(empty_graph):
    """Every generated AttackHypothesis has traceable evidence IDs linking to observations."""
    g = empty_graph
    ep = NormalizedEndpoint(
        method="GET",
        route_template="/api/v1/bookings/{booking_id}",
        asset_id="primary-api",
        canonical_origin="https://api.tbo.com",
        provenance=[ProvenanceSource(source="HAR", observation_id="OBS-TRACE-777")],
        confidence=ConfidenceAssessment(score=0.95),
    )
    g.ingest_normalized_endpoints([ep])

    hypotheses = g.extract_attack_hypotheses(
        attacker_tenant_id="TENANT-AGENCY-B",
        victim_tenant_id="TENANT-AGENCY-A",
    )

    assert len(hypotheses) >= 1
    for hypo in hypotheses:
        assert hypo.attacker_tenant_id == "TENANT-AGENCY-B"
        assert hypo.victim_tenant_id == "TENANT-AGENCY-A"
        assert len(hypo.supporting_evidence_ids) >= 1
        assert "OBS-TRACE-777" in hypo.supporting_evidence_ids
        assert g.graph.has_node(hypo.node_id)


# =============================================================================
# Test 13: Same principal ID across two tenants -> separate nodes
# =============================================================================
def test_13_same_principal_id_across_two_tenants_remain_separate(empty_graph):
    """Principals with identical local IDs (e.g., 'admin') under different tenants must not collide."""
    g = empty_graph
    p1 = PrincipalNode(principal_id="admin", tenant_id="TENANT-AGENCY-A", roles=["Admin"])
    p2 = PrincipalNode(principal_id="admin", tenant_id="TENANT-AGENCY-B", roles=["Admin"])

    id1 = g.add_principal(p1)
    id2 = g.add_principal(p2)

    assert id1 == "principal:TENANT-AGENCY-A:admin"
    assert id2 == "principal:TENANT-AGENCY-B:admin"
    assert id1 != id2
    assert g.graph.has_node(id1)
    assert g.graph.has_node(id2)


# =============================================================================
# Test 14: Same booking ID across two tenants -> separate nodes
# =============================================================================
def test_14_same_booking_id_across_two_tenants_remain_separate(empty_graph):
    """Business objects with identical IDs (e.g., 'BK-001') under different tenants must not collide."""
    g = empty_graph
    b1 = BusinessObjectNode(object_type="Booking", object_id="BK-001", owner_tenant_id="TENANT-AGENCY-A")
    b2 = BusinessObjectNode(object_type="Booking", object_id="BK-001", owner_tenant_id="TENANT-AGENCY-B")

    id1 = g.add_business_object(b1)
    id2 = g.add_business_object(b2)

    assert id1 == "obj:TENANT-AGENCY-A:booking:BK-001"
    assert id2 == "obj:TENANT-AGENCY-B:booking:BK-001"
    assert id1 != id2
    assert g.graph.has_node(id1)
    assert g.graph.has_node(id2)


# =============================================================================
# Test 15: Crawler observation ingestion connects endpoints and evidence
# =============================================================================
def test_15_crawler_observation_ingestion_connects_endpoints_and_evidence(empty_graph):
    """Crawler observation ingestion must create endpoints, roles, and link SUPPORTED_BY."""
    g = empty_graph
    obs = BrowserObservation(
        observation_id="OBS-CRW-101",
        session_id="SESS-001",
        journey_step_id="step_search",
        role_name="Front_Desk_Agent",
        tenant_id="TENANT-AGENCY-A",
        method="GET",
        url="https://api.tbo.com/api/v1/hotels/search?city=DXB",
        status_code=200,
        latency_ms=45,
    )

    g.ingest_crawler_observations([obs], default_asset_id="b2b-portal")

    # Endpoint must be created and namespaced with default_asset_id
    ep_identity = "b2b-portal:https://api.tbo.com:GET:/api/v1/hotels/search"
    ep_node = f"endpoint:{ep_identity}"
    assert g.graph.has_node(ep_node)

    # Observation must exist
    obs_node = f"obs:{obs.observation_id}"
    assert g.graph.has_node(obs_node)

    # SUPPORTED_BY edge exists
    edges = g.graph.get_edge_data(ep_node, obs_node)
    assert edges is not None
    assert any(d.get("edge_type") == EdgeType.SUPPORTED_BY.value for d in edges.values())

    # OBSERVED_REQUESTED_BY edge exists
    role_node = f"role:{obs.role_name}:{obs.tenant_id}"
    req_edges = g.graph.get_edge_data(ep_node, role_node)
    assert req_edges is not None
    assert any(d.get("edge_type") == EdgeType.OBSERVED_REQUESTED_BY.value for d in req_edges.values())


# =============================================================================
# Test 16: Parameter locations preserved for body, query, and path
# =============================================================================
def test_16_parameter_locations_preserved(empty_graph):
    """Parameter locations (body, query, path) must be strictly preserved during ingestion."""
    g = empty_graph
    nep = NormalizedEndpoint(
        method="POST",
        route_template="/api/v1/checkout/{booking_id}",
        asset_id="primary-api",
        canonical_origin="https://api.tbo.com",
        parameters=[
            ParameterCandidate(name="booking_id", location="path", semantic_type="booking_identifier"),
            ParameterCandidate(name="amount", location="body", semantic_type="currency"),
        ],
        query_parameters=[
            ParameterCandidate(name="locale", location="query", semantic_type="generic_parameter"),
        ],
        confidence=ConfidenceAssessment(score=1.0),
    )
    g.ingest_normalized_endpoints([nep])

    p_path = f"param:{nep.endpoint_identity}:path:booking_id"
    p_body = f"param:{nep.endpoint_identity}:body:amount"
    p_query = f"param:{nep.endpoint_identity}:query:locale"

    assert g.graph.has_node(p_path)
    assert g.graph.nodes[p_path]["location"] == "path"

    assert g.graph.has_node(p_body)
    assert g.graph.nodes[p_body]["location"] == "body"

    assert g.graph.has_node(p_query)
    assert g.graph.nodes[p_query]["location"] == "query"


# =============================================================================
# Test 17: Financial parameter on unconventional route binds I-02
# =============================================================================
def test_17_financial_parameter_on_unconventional_route_binds_i02(empty_graph):
    """Any route possessing a financial parameter must be bound to I-02 pricing integrity."""
    g = empty_graph
    nep = NormalizedEndpoint(
        method="POST",
        route_template="/api/v1/agency/custom_markup_policy",  # Unconventional route without 'checkout' or 'fare'
        asset_id="primary-api",
        canonical_origin="https://api.tbo.com",
        parameters=[
            ParameterCandidate(name="markup_amount", location="body", semantic_type="currency"),
        ],
        confidence=ConfidenceAssessment(score=1.0),
    )
    g.ingest_normalized_endpoints([nep])
    g.bind_invariants()

    inv_i02 = f"invariant:{InvariantType.PRICING_INTEGRITY.value}"
    ep_node = f"endpoint:{nep.endpoint_identity}"

    edges = g.graph.get_edge_data(inv_i02, ep_node)
    assert edges is not None
    assert any(d.get("edge_type") == EdgeType.BINDS_INVARIANT.value for d in edges.values())

    hypotheses = g.extract_attack_hypotheses("TENANT-AGENCY-B", "TENANT-AGENCY-A")
    i02_hypos = [h for h in hypotheses if h.invariant_id == InvariantType.PRICING_INTEGRITY.value and h.target_endpoint_identity == nep.endpoint_identity]
    assert len(i02_hypos) >= 1


# =============================================================================
# Test 18: Multiple attacker/victim pairs -> distinct hypothesis IDs
# =============================================================================
def test_18_multiple_tenant_pairs_produce_distinct_hypothesis_ids(empty_graph):
    """Evaluating hypotheses for different tenant pairs on the same endpoint must yield distinct hypothesis IDs."""
    g = empty_graph
    nep = NormalizedEndpoint(
        method="GET",
        route_template="/api/v1/bookings/{booking_id}",
        asset_id="primary-api",
        canonical_origin="https://api.tbo.com",
        provenance=[ProvenanceSource(source="HAR", observation_id="OBS-BOLA-1")],
        confidence=ConfidenceAssessment(score=1.0),
    )
    g.ingest_normalized_endpoints([nep])

    hypos_pair1 = g.extract_attack_hypotheses(attacker_tenant_id="TENANT-B", victim_tenant_id="TENANT-A")
    hypos_pair2 = g.extract_attack_hypotheses(attacker_tenant_id="TENANT-C", victim_tenant_id="TENANT-A")

    h1 = [h for h in hypos_pair1 if h.invariant_id == InvariantType.TENANT_ISOLATION.value][0]
    h2 = [h for h in hypos_pair2 if h.invariant_id == InvariantType.TENANT_ISOLATION.value][0]

    assert h1.hypothesis_id != h2.hypothesis_id
    assert g.graph.has_node(h1.node_id)
    assert g.graph.has_node(h2.node_id)


# =============================================================================
# Test 19: Observed expired hold -> POTENTIAL_INVARIANT_VIOLATION recorded
# =============================================================================
def test_19_observed_expired_hold_evaluates_violation(empty_graph):
    """Recording an observed transition from Hold.EXPIRED to Hold.CONFIRMED must flag a potential violation."""
    g = empty_graph
    edge_key = g.record_observed_transition("Hold", "EXPIRED", "CONFIRMED", evidence_id="OBS-LEAK-999")

    edges = g.graph.get_edge_data("state:Hold:EXPIRED", "state:Hold:CONFIRMED")
    assert edges is not None
    assert edge_key in edges
    edge_meta = edges[edge_key]["metadata"]

    assert edge_meta["declared_outcome"] == TransitionOutcome.DENIED.value
    assert edge_meta["assessment"] == "POTENTIAL_INVARIANT_VIOLATION"
    assert edge_meta["potential_invariant_violation"] is True
    assert edge_meta["bound_invariant"] == InvariantType.HOLD_EXPIRATION.value


# =============================================================================
# Test 20: Negative refund inputs rejected
# =============================================================================
def test_20_negative_refund_inputs_rejected():
    """Negative captured amount or negative prior refunds must be rejected."""
    # Negative captured amount
    ok1, msg1 = validate_refund_bounds(-100, [10], 50)
    assert ok1 is False
    assert "Captured amount cannot be negative" in msg1

    # Negative prior refund
    ok2, msg2 = validate_refund_bounds(1000, [-20, 50], 50)
    assert ok2 is False
    assert "Prior refund amounts cannot be negative" in msg2


# =============================================================================
# Test 21: Reused idempotency key with changed payload detects conflict
# =============================================================================
def test_21_reused_idempotency_key_with_changed_payload_detects_conflict():
    """Reusing the same idempotency key with an altered payload or tenant context must be flagged as conflict."""
    records = {
        "IDEMP-KEY-999": IdempotencyRecord(
            idempotency_key="IDEMP-KEY-999",
            tenant_id="TENANT-AGENCY-A",
            operation="payment_capture",
            payload_hash="sha256_original_payload",
        )
    }

    # Same payload -> replay ok
    is_replay, msg_replay = validate_payment_idempotency(
        idempotency_key="IDEMP-KEY-999",
        completed_keys=records,
        tenant_id="TENANT-AGENCY-A",
        operation="payment_capture",
        payload_hash="sha256_original_payload",
    )
    assert is_replay is True
    assert "Idempotent replay detected" in msg_replay

    # Changed payload -> conflict!
    is_replay_conflict, msg_conflict = validate_payment_idempotency(
        idempotency_key="IDEMP-KEY-999",
        completed_keys=records,
        tenant_id="TENANT-AGENCY-A",
        operation="payment_capture",
        payload_hash="sha256_tampered_payload",
    )
    assert is_replay_conflict is True
    assert "Idempotency conflict (I-04)" in msg_conflict


# =============================================================================
# Test 22: Normal JSON export preserves true observation timestamps
# =============================================================================
def test_22_normal_json_export_preserves_true_observation_timestamps(empty_graph):
    """Normal JSON export must faithfully preserve actual timestamps on observation nodes."""
    g = empty_graph
    obs = ObservationNode(
        observation_id="OBS-TIME-TEST",
        source_type=EvidenceSourceType.HAR,
        timestamp="2026-11-04T22:30:00Z",
    )
    g.add_observation(obs)

    json_str = g.to_json(indent=2)
    assert "2026-11-04T22:30:00Z" in json_str


# =============================================================================
# Test 23: Graph traverses PRODUCES and CONSUMES relationships for BOLA
# =============================================================================
def test_23_graph_traverses_produces_and_consumes_for_bola(empty_graph):
    """Tests full path traversal: Tenant A OWNS Booking -> Endpoint CONSUMES Booking -> Tenant B requests."""
    g = empty_graph
    ep = NormalizedEndpoint(
        method="GET",
        route_template="/api/v1/bookings/{id}",
        asset_id="primary-api",
        canonical_origin="https://api.tbo.com",
        provenance=[ProvenanceSource(source="HAR", observation_id="OBS-TRAVERSE-1")],
        confidence=ConfidenceAssessment(score=1.0),
    )
    g.ingest_normalized_endpoints([ep])

    # Agency A creates booking
    b_node_id = g.add_business_object(
        BusinessObjectNode(
            object_type="Booking",
            object_id="BK-TARGET-99",
            owner_tenant_id="TENANT-AGENCY-A",
        )
    )

    # CONSUMES edge should link endpoint to Booking BK-TARGET-99
    consumes_edges = g.graph.get_edge_data(f"endpoint:{ep.endpoint_identity}", b_node_id)
    assert consumes_edges is not None
    assert any(d.get("edge_type") == EdgeType.CONSUMES.value for d in consumes_edges.values())

    # Agency B role requests the endpoint
    g.record_observed_request(
        principal_or_role_id="role:Sub_Agent:TENANT-AGENCY-B",
        endpoint_identity=ep.endpoint_identity,
        evidence_id="OBS-CRW-AGENCY-B",
        tenant_context="TENANT-AGENCY-B",
        role_context="Sub_Agent",
    )

    # Extract hypotheses: Agency B attacking Agency A
    hypos = g.extract_attack_hypotheses(attacker_tenant_id="TENANT-AGENCY-B", victim_tenant_id="TENANT-AGENCY-A")
    bola_hypos = [h for h in hypos if h.invariant_id == InvariantType.TENANT_ISOLATION.value]

    assert len(bola_hypos) >= 1
    assert "Graph traversal path: Tenant 'TENANT-AGENCY-B'" in bola_hypos[0].rationale
    assert "BK-TARGET-99" in bola_hypos[0].rationale


# =============================================================================
# Test 24: Mermaid export produces valid syntax
# =============================================================================
def test_24_mermaid_export_renders_valid_syntax(empty_graph):
    """Exported Mermaid diagram contains flowchart header, subgraphs, and edges."""
    g = empty_graph
    mermaid = g.export_mermaid()
    assert mermaid.startswith("flowchart TD")
    assert "subgraph Security_Invariants" in mermaid
    assert "subgraph State_Machines" in mermaid
    assert "-->" in mermaid
