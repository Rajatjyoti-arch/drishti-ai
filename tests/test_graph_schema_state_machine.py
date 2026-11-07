"""Unit tests for typed graph schema and independent state machine lifecycles."""

import pytest
from drishti.graph.schema import (
    AssetNode,
    BusinessObjectNode,
    EdgeType,
    EndpointNode,
    EvidenceSourceType,
    FactClassification,
    GraphEdge,
    HypothesisNode,
    InvariantCategory,
    InvariantNode,
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
    PaymentState,
    QuoteState,
    RefundState,
    TransitionOutcome,
    get_lifecycle_transitions,
    validate_payment_idempotency,
    validate_refund_bounds,
    validate_transition,
)


def test_schema_node_identity_determinism():
    """Verifies that all node types produce stable, deterministic node IDs."""
    tenant = TenantNode(tenant_id="TENANT-AGENCY-A", name="Agency Alpha")
    assert tenant.node_id == "tenant:TENANT-AGENCY-A"

    principal = PrincipalNode(principal_id="user_alpha", tenant_id="TENANT-AGENCY-A", roles=["Agency_Admin"])
    assert principal.node_id == "principal:TENANT-AGENCY-A:user_alpha"

    role = RoleNode(role_name="Agency_Admin", tenant_id="TENANT-AGENCY-A")
    assert role.node_id == "role:Agency_Admin:TENANT-AGENCY-A"

    asset = AssetNode(asset_id="primary-api", canonical_origin="https://api.tbo.com")
    assert asset.node_id == "asset:primary-api"

    endpoint = EndpointNode(
        endpoint_identity="primary-api:https://api.tbo.com:GET:/api/v1/bookings/{booking_id}",
        method="GET",
        route_template="/api/v1/bookings/{booking_id}",
        asset_id="primary-api",
        canonical_origin="https://api.tbo.com",
    )
    assert endpoint.node_id == "endpoint:primary-api:https://api.tbo.com:GET:/api/v1/bookings/{booking_id}"

    param = ParameterNode(
        endpoint_identity=endpoint.endpoint_identity,
        name="booking_id",
        location="path",
        semantic_type="booking_identifier",
    )
    assert param.node_id == "param:primary-api:https://api.tbo.com:GET:/api/v1/bookings/{booking_id}:path:booking_id"

    obj = BusinessObjectNode(
        object_type="Booking",
        object_id="BK-9999",
        owner_tenant_id="TENANT-AGENCY-A",
        canary_fixture_id="canary_xyz",
    )
    assert obj.node_id == "obj:TENANT-AGENCY-A:booking:BK-9999"

    state = WorkflowStateNode(object_type="Hold", state_name="EXPIRED")
    assert state.node_id == "state:Hold:EXPIRED"


def test_schema_edge_evidence_binding():
    """Verifies typed graph edges preserve evidence metadata, role, and tenant context."""
    edge = GraphEdge(
        source_id="endpoint:primary-api:*:GET:/api/v1/bookings/{id}",
        target_id="role:Agency_Admin:TENANT-AGENCY-A",
        edge_type=EdgeType.OBSERVED_REQUESTED_BY,
        classification=FactClassification.OBSERVED,
        evidence_refs=["OBS-001", "OBS-002"],
        tenant_context="TENANT-AGENCY-A",
        role_context="Agency_Admin",
    )
    assert edge.edge_type == EdgeType.OBSERVED_REQUESTED_BY
    assert edge.classification == FactClassification.OBSERVED
    assert len(edge.evidence_refs) == 2
    assert "OBSERVED_REQUESTED_BY:OBSERVED" in edge.edge_key


def test_independent_quote_lifecycle():
    """Quote transitions allow normal flow and forbid expired/superseded acceptance."""
    assert validate_transition("Quote", QuoteState.ISSUED.value, QuoteState.ACCEPTED.value)[0] == TransitionOutcome.ALLOWED
    assert validate_transition("Quote", QuoteState.ISSUED.value, QuoteState.EXPIRED.value)[0] == TransitionOutcome.ALLOWED
    assert validate_transition("Quote", QuoteState.ISSUED.value, QuoteState.SUPERSEDED.value)[0] == TransitionOutcome.ALLOWED

    # Expired quote cannot be accepted
    outcome, _, inv = validate_transition("Quote", QuoteState.EXPIRED.value, QuoteState.ACCEPTED.value)
    assert outcome == TransitionOutcome.DENIED
    assert inv == "I-02-SERVER-AUTHORITATIVE-PRICING"


def test_independent_hold_lifecycle_i03():
    """Hold transitions strictly forbid expired hold confirmation (Invariant I-03)."""
    assert validate_transition("Hold", HoldState.ACTIVE.value, HoldState.CONFIRMED.value)[0] == TransitionOutcome.ALLOWED
    assert validate_transition("Hold", HoldState.ACTIVE.value, HoldState.EXPIRED.value)[0] == TransitionOutcome.ALLOWED

    outcome, _, inv = validate_transition("Hold", HoldState.EXPIRED.value, HoldState.CONFIRMED.value)
    assert outcome == TransitionOutcome.DENIED
    assert inv == "I-03-PERISHABLE-HOLD-EXPIRATION"

    outcome_cancel, _, _ = validate_transition("Hold", HoldState.CANCELLED.value, HoldState.CONFIRMED.value)
    assert outcome_cancel == TransitionOutcome.DENIED


def test_payment_and_refund_lifecycle_i04():
    """Payment and refund transitions enforce bounds and idempotency (Invariant I-04)."""
    # Payment transitions
    assert validate_transition("Payment", PaymentState.INITIATED.value, PaymentState.AUTHORIZED.value)[0] == TransitionOutcome.ALLOWED
    assert validate_transition("Payment", PaymentState.AUTHORIZED.value, PaymentState.CAPTURED.value)[0] == TransitionOutcome.ALLOWED
    assert validate_transition("Payment", PaymentState.FAILED.value, PaymentState.CAPTURED.value)[0] == TransitionOutcome.DENIED

    # Refund transitions
    assert validate_transition("Refund", RefundState.REQUESTED.value, RefundState.PROCESSING.value)[0] == TransitionOutcome.ALLOWED
    assert validate_transition("Refund", RefundState.PROCESSING.value, RefundState.SUCCEEDED.value)[0] == TransitionOutcome.ALLOWED
    assert validate_transition("Refund", RefundState.FAILED.value, RefundState.SUCCEEDED.value)[0] == TransitionOutcome.DENIED

    # Refund bounds check
    captured = 10000  # $100.00
    prior_refunds = [3000, 2000]  # $50.00 already refunded
    # Valid refund of $40.00
    valid_ok, _ = validate_refund_bounds(captured, prior_refunds, 4000)
    assert valid_ok is True

    # Invalid refund of $60.00 (would exceed $100.00 total)
    invalid_ok, msg = validate_refund_bounds(captured, prior_refunds, 6000)
    assert invalid_ok is False
    assert "Refund violation (I-04)" in msg

    # Payment idempotency check
    seen = {"IDEM-123", "IDEM-456"}
    is_replay, _ = validate_payment_idempotency("IDEM-123", seen)
    assert is_replay is True
    is_fresh, _ = validate_payment_idempotency("IDEM-789", seen)
    assert is_fresh is False
