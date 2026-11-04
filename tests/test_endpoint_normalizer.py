"""Unit and acceptance tests for endpoint normalization and parameter discovery."""

import pytest
from drishti.discovery.endpoint_normalizer import (
    EndpointNormalizer,
    EndpointObservation,
)
from drishti.discovery.models import (
    ParameterClassification,
    ParameterLocation,
    SemanticType,
)


def test_three_distinct_booking_ids_normalize_to_single_template():
    """Acceptance Test 1: Three distinct booking IDs collapse into one normalized template."""
    normalizer = EndpointNormalizer()

    observations = [
        EndpointObservation(
            method="GET",
            raw_url="https://api.tbo.com/api/v2/bookings/TBOH_123",
            observation_id="HAR-001",
            role="agent_a",
        ),
        EndpointObservation(
            method="GET",
            raw_url="https://api.tbo.com/api/v2/bookings/TBOH_456",
            observation_id="HAR-002",
            role="agent_a",
        ),
        EndpointObservation(
            method="GET",
            raw_url="https://api.tbo.com/api/v2/bookings/TBOH_789",
            observation_id="HAR-003",
            role="agent_b",
        ),
    ]

    results = normalizer.cluster_and_normalize(observations)
    assert len(results) == 1
    endpoint = results[0]

    assert endpoint.method == "GET"
    assert endpoint.route_template == "/api/v2/bookings/{booking_id}"
    assert len(endpoint.parameters) == 1

    param = endpoint.parameters[0]
    assert param.name == "booking_id"
    assert param.location == ParameterLocation.PATH.value
    assert param.semantic_type == SemanticType.BOOKING_ID.value
    assert param.classification == ParameterClassification.CONFIRMED.value
    assert sorted(param.observed_values) == ["TBOH_123", "TBOH_456", "TBOH_789"]

    # Provenance tracked for all 3 observations
    assert len(endpoint.provenance) == 3
    assert endpoint.roles_observed == ["agent_a", "agent_b"]
    assert endpoint.confidence.score >= 0.90
    assert "variance_clustering" in endpoint.confidence.signals


def test_static_keyword_search_is_preserved_alongside_dynamic_bookings():
    """Acceptance Test 2: Static /bookings/search is preserved, not parameterized."""
    normalizer = EndpointNormalizer()

    observations = [
        EndpointObservation(method="GET", raw_url="https://api.tbo.com/api/v2/bookings/TBOH_123"),
        EndpointObservation(method="GET", raw_url="https://api.tbo.com/api/v2/bookings/TBOH_456"),
        EndpointObservation(method="GET", raw_url="https://api.tbo.com/api/v2/bookings/search"),
    ]

    results = normalizer.cluster_and_normalize(observations)
    assert len(results) == 2

    templates = {r.route_template for r in results}
    assert "/api/v2/bookings/{booking_id}" in templates
    assert "/api/v2/bookings/search" in templates

    search_endpoint = next(r for r in results if r.route_template == "/api/v2/bookings/search")
    assert len(search_endpoint.parameters) == 0
    assert search_endpoint.confidence.score == 1.0


def test_uuid_parameter_recognition():
    """Acceptance Test 3: Standard UUID parameter is correctly recognized."""
    normalizer = EndpointNormalizer()
    obs = EndpointObservation(
        method="GET",
        raw_url="https://api.tbo.com/api/v1/orders/550e8400-e29b-41d4-a716-446655440000",
    )

    endpoint = normalizer.normalize_single(obs)
    assert endpoint.route_template == "/api/v1/orders/{order_id}"
    assert len(endpoint.parameters) == 1
    assert endpoint.parameters[0].semantic_type == SemanticType.UUID.value
    assert "uuid_pattern" in endpoint.confidence.signals


def test_unrecognized_alphanumeric_segment_preserved_as_static():
    """Acceptance Test 4: Legitimate keywords like /flights/international are kept static."""
    normalizer = EndpointNormalizer()
    obs = EndpointObservation(
        method="GET",
        raw_url="https://api.tbo.com/api/v1/flights/international",
    )

    endpoint = normalizer.normalize_single(obs)
    # "international" is in static keywords and must NEVER become a parameter
    assert endpoint.route_template == "/api/v1/flights/international"
    assert len(endpoint.parameters) == 0


def test_query_parameters_separated_and_sensitive_tokens_redacted():
    """Acceptance Test 5: Query parameters extracted separately, and sensitive tokens redacted."""
    normalizer = EndpointNormalizer()
    obs = EndpointObservation(
        method="GET",
        raw_url="https://api.tbo.com/api/v1/search?origin=DEL&destination=BOM&token=super_secret_jwt_xyz",
    )

    endpoint = normalizer.normalize_single(obs)
    # Query parameters are stripped from path template
    assert endpoint.route_template == "/api/v1/search"

    query_params = {p.name: p for p in endpoint.query_parameters}
    assert "origin" in query_params
    assert query_params["origin"].observed_values == ["DEL"]

    assert "destination" in query_params
    assert query_params["destination"].observed_values == ["BOM"]

    # Sensitive "token" query parameter must be redacted
    assert "token" in query_params
    assert query_params["token"].observed_values == ["[REDACTED]"]
    assert "super_secret_jwt_xyz" not in str(endpoint.model_dump())
