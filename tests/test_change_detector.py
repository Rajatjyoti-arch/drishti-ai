"""Unit and acceptance tests for the Attack Surface Change Intelligence Engine."""

import pytest
from drishti.discovery.change_detector import ChangeDetector
from drishti.discovery.models import (
    AttackSurfaceChangeSet,
    CaptureCompleteness,
    ChangeType,
    ConfidenceAssessment,
    EndpointChange,
    InventorySnapshot,
    NormalizedEndpoint,
    ParameterCandidate,
    ParameterLocation,
    ProvenanceSource,
    SemanticType,
)


def make_endpoint(
    method: str,
    route: str,
    asset_id: str = "primary-api",
    origin: str = "https://api.tbo.com",
    params: list = None,
    query_params: list = None,
    body_digest: str = None,
    roles: list = None,
    sources: list = None,
) -> NormalizedEndpoint:
    """Helper creating a test NormalizedEndpoint with deterministic identity."""
    prov = [ProvenanceSource(source=s, observation_id=f"OBS-{i}") for i, s in enumerate(sources or ["HAR"])]
    return NormalizedEndpoint(
        method=method,
        route_template=route,
        asset_id=asset_id,
        canonical_origin=origin,
        parameters=params or [],
        query_parameters=query_params or [],
        body_schema_digest=body_digest,
        roles_observed=roles or ["agent"],
        provenance=prov,
        confidence=ConfidenceAssessment(score=0.90, signals=["test_signal"]),
    )


def test_identical_snapshots_yield_empty_changeset():
    """Acceptance Test 1: Comparing two identical inventory snapshots yields an empty change set."""
    detector = ChangeDetector()
    ep = make_endpoint("GET", "/api/v1/flights/search")

    snap1 = detector.build_snapshot("SNAP-01", [ep], deployment_id="v1.0.0")
    snap2 = detector.build_snapshot("SNAP-02", [ep], deployment_id="v1.0.0")

    changeset = detector.compare_snapshots(snap1, snap2)
    assert len(changeset.changes) == 0
    assert len(changeset.recommended_invariants) == 0


def test_endpoint_added_detection():
    """Acceptance Test 2: Detects new endpoint introduction and flags attack surface expansion."""
    detector = ChangeDetector()
    ep1 = make_endpoint("GET", "/api/v1/flights")
    ep2 = make_endpoint("POST", "/api/v1/bookings")

    snap1 = detector.build_snapshot("SNAP-01", [ep1])
    snap2 = detector.build_snapshot("SNAP-02", [ep1, ep2])

    changeset = detector.compare_snapshots(snap1, snap2)
    assert len(changeset.changes) == 1

    chg = changeset.changes[0]
    assert chg.change_type == ChangeType.ENDPOINT_ADDED.value
    assert chg.endpoint_identity == ep2.endpoint_identity


def test_missing_endpoint_in_partial_har_classified_as_not_observed():
    """Acceptance Test 3: Absence in a partial traffic capture is classified as NOT_OBSERVED, not removed."""
    detector = ChangeDetector()
    ep1 = make_endpoint("GET", "/api/v1/bookings/123")
    ep2 = make_endpoint("GET", "/api/v1/flights/search")

    # Snapshot 1 was complete; Snapshot 2 was a partial test run capture
    snap1 = detector.build_snapshot("SNAP-01", [ep1, ep2], capture_completeness=CaptureCompleteness.COMPLETE.value)
    snap2 = detector.build_snapshot("SNAP-02", [ep1], capture_completeness=CaptureCompleteness.PARTIAL.value)

    changeset = detector.compare_snapshots(snap1, snap2)
    assert len(changeset.changes) == 1

    chg = changeset.changes[0]
    # Critical invariant: absence in partial capture is NOT removal!
    assert chg.change_type == ChangeType.ENDPOINT_NOT_OBSERVED.value
    assert chg.details["capture_completeness"] == "PARTIAL"


def test_missing_endpoint_in_complete_snapshots_classified_as_removal_candidate():
    """Acceptance Test 4: Missing endpoint between two comprehensive snapshots is flagged for deprecation."""
    detector = ChangeDetector()
    ep1 = make_endpoint("GET", "/api/v1/bookings/123")
    ep2 = make_endpoint("GET", "/api/v1/deprecated/endpoint")

    snap1 = detector.build_snapshot("SNAP-01", [ep1, ep2], capture_completeness=CaptureCompleteness.COMPLETE.value)
    snap2 = detector.build_snapshot("SNAP-02", [ep1], capture_completeness=CaptureCompleteness.COMPLETE.value)

    changeset = detector.compare_snapshots(snap1, snap2)
    assert len(changeset.changes) == 1

    chg = changeset.changes[0]
    assert chg.change_type == ChangeType.ENDPOINT_REMOVED_CANDIDATE.value


def test_http_method_changed_detected():
    """Acceptance Test 5: Changing HTTP method on the same path is detected and triggers access-control review."""
    detector = ChangeDetector()
    ep_get = make_endpoint("GET", "/api/v1/checkout/confirm")
    ep_post = make_endpoint("POST", "/api/v1/checkout/confirm")

    snap1 = detector.build_snapshot("SNAP-01", [ep_get])
    snap2 = detector.build_snapshot("SNAP-02", [ep_post])

    changeset = detector.compare_snapshots(snap1, snap2)
    method_changes = [c for c in changeset.changes if c.change_type == ChangeType.METHOD_CHANGED.value]
    assert len(method_changes) == 1
    assert "I-01" in method_changes[0].recommended_invariants


def test_new_pricing_field_recommends_invariant_i02():
    """Acceptance Test 6: Introduction of price/amount field in request schema recommends I-02."""
    detector = ChangeDetector()
    ep_prev = make_endpoint(
        "POST",
        "/api/v2/checkout",
        body_digest="digest_v1",
        params=[ParameterCandidate(name="quote_id", location=ParameterLocation.BODY.value, semantic_type=SemanticType.QUOTE_ID.value)],
    )
    ep_curr = make_endpoint(
        "POST",
        "/api/v2/checkout",
        body_digest="digest_v2",
        params=[
            ParameterCandidate(name="quote_id", location=ParameterLocation.BODY.value, semantic_type=SemanticType.QUOTE_ID.value),
            ParameterCandidate(name="amount", location=ParameterLocation.BODY.value, semantic_type=SemanticType.CURRENCY.value),
            ParameterCandidate(name="markup", location=ParameterLocation.BODY.value, semantic_type=SemanticType.CURRENCY.value),
        ],
    )

    snap1 = detector.build_snapshot("SNAP-01", [ep_prev])
    snap2 = detector.build_snapshot("SNAP-02", [ep_curr])

    changeset = detector.compare_snapshots(snap1, snap2)
    schema_changes = [c for c in changeset.changes if c.change_type == ChangeType.REQUEST_SCHEMA_CHANGED.value]

    assert len(schema_changes) == 1
    assert "I-02" in schema_changes[0].recommended_invariants
    assert "I-02" in changeset.recommended_invariants


def test_new_booking_identifier_recommends_invariant_i01():
    """Acceptance Test 7: New booking/tenant ID path parameter triggers I-01 (BOLA) recommendation."""
    detector = ChangeDetector()
    ep_prev = make_endpoint("GET", "/api/v1/bookings")
    ep_curr = make_endpoint(
        "GET",
        "/api/v1/bookings/{booking_id}",
        params=[ParameterCandidate(name="booking_id", location=ParameterLocation.PATH.value, semantic_type=SemanticType.BOOKING_ID.value)],
    )

    snap1 = detector.build_snapshot("SNAP-01", [ep_prev])
    snap2 = detector.build_snapshot("SNAP-02", [ep_curr])

    changeset = detector.compare_snapshots(snap1, snap2)
    assert "I-01" in changeset.recommended_invariants


def test_role_observation_changed_triggers_authorization_reassessment():
    """Acceptance Test 8: Sub-agent accessing previously admin-restricted route triggers I-01/I-06."""
    detector = ChangeDetector()
    ep_prev = make_endpoint("GET", "/api/v1/financial/reports", roles=["admin", "auditor"])
    ep_curr = make_endpoint("GET", "/api/v1/financial/reports", roles=["admin", "auditor", "sub_agent"])

    snap1 = detector.build_snapshot("SNAP-01", [ep_prev])
    snap2 = detector.build_snapshot("SNAP-02", [ep_curr])

    changeset = detector.compare_snapshots(snap1, snap2)
    role_changes = [c for c in changeset.changes if c.change_type == ChangeType.ROLE_OBSERVATION_CHANGED.value]

    assert len(role_changes) == 1
    assert "sub_agent" in role_changes[0].details["newly_observed_roles"]
    assert "I-01" in role_changes[0].recommended_invariants
    assert "I-06" in role_changes[0].recommended_invariants


def test_same_route_on_different_assets_remain_separate_identities():
    """Acceptance Test 9: Identical routes across different asset_ids maintain separate identities."""
    detector = ChangeDetector()
    ep_booking = make_endpoint("GET", "/api/v1/status", asset_id="booking-service", origin="https://booking.tbo.com")
    ep_supplier = make_endpoint("GET", "/api/v1/status", asset_id="supplier-service", origin="https://supplier.tbo.com")

    assert ep_booking.endpoint_identity != ep_supplier.endpoint_identity
    assert "booking-service" in ep_booking.endpoint_identity
    assert "supplier-service" in ep_supplier.endpoint_identity


def test_duplicate_deployment_event_handled_idempotently():
    """Acceptance Test 10: Repeated deployment webhook with identical commit SHA produces no duplicate change set."""
    detector = ChangeDetector()
    ep = make_endpoint("GET", "/api/v1/status")

    snap1 = detector.build_snapshot("SNAP-01", [ep], deployment_id="deploy-sha-abc")
    snap2 = detector.build_snapshot("SNAP-02", [ep], deployment_id="deploy-sha-abc")

    changeset = detector.compare_snapshots(snap1, snap2)
    assert len(changeset.changes) == 0


def test_javascript_only_route_marked_as_source_only():
    """Acceptance Test 11: Route discovered exclusively in JavaScript bundles is flagged as SOURCE_ONLY_CHANGE."""
    detector = ChangeDetector()
    ep_har = make_endpoint("GET", "/api/v1/flights", sources=["HAR"])
    ep_js = make_endpoint("GET", "/api/v1/admin/internal", sources=["JS_BUNDLE"])

    snap1 = detector.build_snapshot("SNAP-01", [ep_har])
    snap2 = detector.build_snapshot("SNAP-02", [ep_har, ep_js])

    changeset = detector.compare_snapshots(snap1, snap2)
    js_change = next(c for c in changeset.changes if c.endpoint_identity == ep_js.endpoint_identity)
    assert js_change.change_type == ChangeType.SOURCE_ONLY_CHANGE.value
    assert js_change.details["is_source_only"] is True


def test_query_parameter_added_triggers_invariant_recommendation():
    """Acceptance Test 12: Adding a tenant query parameter to search triggers I-01 recommendation."""
    detector = ChangeDetector()
    ep_prev = make_endpoint("GET", "/api/v1/search")
    ep_curr = make_endpoint(
        "GET",
        "/api/v1/search",
        query_params=[ParameterCandidate(name="tenant_id", location=ParameterLocation.QUERY.value, semantic_type=SemanticType.TENANT_ID.value)],
    )

    snap1 = detector.build_snapshot("SNAP-01", [ep_prev])
    snap2 = detector.build_snapshot("SNAP-02", [ep_curr])

    changeset = detector.compare_snapshots(snap1, snap2)
    param_changes = [c for c in changeset.changes if c.change_type == ChangeType.QUERY_PARAMETER_ADDED.value]

    assert len(param_changes) == 1
    assert "tenant_id" in param_changes[0].affected_parameters
    assert "I-01" in param_changes[0].recommended_invariants


def test_schema_field_type_or_body_digest_change_detected():
    """Acceptance Test 13: Request schema digest mismatch triggers REQUEST_SCHEMA_CHANGED."""
    detector = ChangeDetector()
    ep_prev = make_endpoint("POST", "/api/v1/hold", body_digest="digest_alpha")
    ep_curr = make_endpoint("POST", "/api/v1/hold", body_digest="digest_beta")

    snap1 = detector.build_snapshot("SNAP-01", [ep_prev])
    snap2 = detector.build_snapshot("SNAP-02", [ep_curr])

    changeset = detector.compare_snapshots(snap1, snap2)
    schema_changes = [c for c in changeset.changes if c.change_type == ChangeType.REQUEST_SCHEMA_CHANGED.value]
    assert len(schema_changes) == 1
    assert schema_changes[0].previous_fingerprint == "digest_alpha"
    assert schema_changes[0].current_fingerprint == "digest_beta"


def test_corroborated_endpoint_across_har_and_js_provenance():
    """Acceptance Test 14: Endpoints with corroborated evidence from both HAR and JS maintain high confidence."""
    detector = ChangeDetector()
    ep_corroborated = make_endpoint("GET", "/api/v1/bookings/123", sources=["HAR", "JS_BUNDLE"])
    snap = detector.build_snapshot("SNAP-01", [ep_corroborated])

    assert len(snap.endpoints) == 1
    retrieved = list(snap.endpoints.values())[0]
    sources = {p.source for p in retrieved.provenance}
    assert "HAR" in sources
    assert "JS_BUNDLE" in sources


def test_role_expansion_detected_even_when_signature_changes():
    """Acceptance Test 15: Role expansion is detected independently even when contract signature changes."""
    detector = ChangeDetector()
    ep_prev = make_endpoint(
        "POST",
        "/api/v1/quotes",
        body_digest="digest_old",
        roles=["agency_admin"],
    )
    # Both body_digest and roles change simultaneously
    ep_curr = make_endpoint(
        "POST",
        "/api/v1/quotes",
        body_digest="digest_new",
        roles=["agency_admin", "sub_agent"],
    )

    snap1 = detector.build_snapshot("SNAP-01", [ep_prev])
    snap2 = detector.build_snapshot("SNAP-02", [ep_curr])

    changeset = detector.compare_snapshots(snap1, snap2)
    change_types = [c.change_type for c in changeset.changes]

    # Both the schema change AND the role expansion are detected!
    assert ChangeType.REQUEST_SCHEMA_CHANGED.value in change_types
    assert ChangeType.ROLE_OBSERVATION_CHANGED.value in change_types

    role_change = next(c for c in changeset.changes if c.change_type == ChangeType.ROLE_OBSERVATION_CHANGED.value)
    assert "sub_agent" in role_change.details["newly_observed_roles"]
    assert "I-01" in role_change.recommended_invariants


def test_multi_method_on_same_route_no_overwriting():
    """Acceptance Test 16: Multiple HTTP methods on the same route are preserved without dictionary collisions."""
    detector = ChangeDetector()
    # Route supports GET and POST initially
    ep_get = make_endpoint("GET", "/api/v1/bookings")
    ep_post = make_endpoint("POST", "/api/v1/bookings")

    # In snap2, DELETE is added to the route
    ep_delete = make_endpoint("DELETE", "/api/v1/bookings")

    snap1 = detector.build_snapshot("SNAP-01", [ep_get, ep_post])
    snap2 = detector.build_snapshot("SNAP-02", [ep_get, ep_post, ep_delete])

    changeset = detector.compare_snapshots(snap1, snap2)
    # Verify that DELETE addition is detected and GET/POST did not overwrite each other
    method_changes = [c for c in changeset.changes if c.change_type == ChangeType.METHOD_CHANGED.value]
    assert len(method_changes) == 1
    assert method_changes[0].details["added_method"] == "DELETE"
    assert "I-01" in method_changes[0].recommended_invariants


def test_parameter_semantic_shift_detected():
    """Acceptance Test 17: Parameter changing from generic to domain-recognized object ID triggers I-01."""
    detector = ChangeDetector()
    p_generic = ParameterCandidate(name="ref_id", location=ParameterLocation.PATH.value, semantic_type=SemanticType.GENERIC.value)
    p_booking = ParameterCandidate(name="ref_id", location=ParameterLocation.PATH.value, semantic_type=SemanticType.BOOKING_ID.value)

    ep_prev = make_endpoint("GET", "/api/v1/orders/{ref_id}", params=[p_generic])
    ep_curr = make_endpoint("GET", "/api/v1/orders/{ref_id}", params=[p_booking])

    snap1 = detector.build_snapshot("SNAP-01", [ep_prev])
    snap2 = detector.build_snapshot("SNAP-02", [ep_curr])

    changeset = detector.compare_snapshots(snap1, snap2)
    semantic_changes = [c for c in changeset.changes if c.change_type == ChangeType.PARAMETER_SEMANTICS_CHANGED.value]

    assert len(semantic_changes) == 1
    assert semantic_changes[0].affected_parameters == ["ref_id"]
    assert "I-01" in semantic_changes[0].recommended_invariants
