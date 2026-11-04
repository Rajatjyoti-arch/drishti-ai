"""Unit and acceptance tests for static JavaScript/TypeScript AST bundle inspector."""

import json
from pathlib import Path
import tempfile
import pytest

from drishti.discovery.bundle_inspector import (
    BundleInspector,
    DiscoveredJsRoute,
    SourceLocation,
    SourceMapResolver,
    decode_vlq_values,
)
from drishti.discovery.endpoint_normalizer import EndpointNormalizer
from drishti.discovery.models import EndpointObservation, ParameterLocation, SemanticType


def test_extract_fetch_call_with_template_literal():
    """Acceptance Test 1: Extracts fetch() with template literal into normalized route and parameter."""
    code = """
    // Booking service
    export async function getBooking(bookingId) {
        const res = await fetch(`/api/v2/bookings/${bookingId}`, {
            headers: { 'Accept': 'application/json' }
        });
        return res.json();
    }
    """
    inspector = BundleInspector()
    routes = inspector.inspect_code(code, file_path="src/api/booking.ts")

    assert len(routes) == 1
    r = routes[0]
    assert r.method == "GET"
    assert r.route_template == "/api/v2/bookings/{booking_id}"
    assert r.is_dynamic is True
    assert len(r.parameters) == 1

    param = r.parameters[0]
    assert param.name == "booking_id"
    assert param.location == ParameterLocation.PATH.value
    assert param.semantic_type == SemanticType.BOOKING_ID.value
    assert r.location.file_path == "src/api/booking.ts"
    assert r.location.line == 4
    assert "fetch" in r.location.snippet


def test_extract_axios_post_with_body_parameters():
    """Acceptance Test 2: Extracts axios.post() with structured request body keys."""
    code = """
    async function checkout(quoteId, totalFare, selectedCurrency) {
        const response = await axios.post("/api/v2/checkout", {
            quote_id: quoteId,
            amount: totalFare,
            currency: selectedCurrency
        });
        return response.data;
    }
    """
    inspector = BundleInspector()
    routes = inspector.inspect_code(code, file_path="src/pages/Checkout.jsx")

    assert len(routes) == 1
    r = routes[0]
    assert r.method == "POST"
    assert r.route_template == "/api/v2/checkout"
    assert r.is_dynamic is False

    # Check extracted body parameters
    body_params = {p.name: p for p in r.parameters if p.location == ParameterLocation.BODY.value}
    assert "quote_id" in body_params
    assert body_params["quote_id"].semantic_type == SemanticType.QUOTE_ID.value

    assert "amount" in body_params
    assert body_params["amount"].semantic_type == SemanticType.CURRENCY.value

    assert "currency" in body_params
    assert body_params["currency"].semantic_type == SemanticType.CURRENCY.value


def test_extract_base_url_resolution():
    """Acceptance Test 3: Resolves declared API_BASE variable in template literal."""
    code = """
    const API_BASE = "https://api.tbo.com/api/v1";
    const AUTH_URL = "/auth";

    export function fetchDomesticFlights() {
        return axios.get(`${API_BASE}/flights/domestic`);
    }
    """
    inspector = BundleInspector()
    routes = inspector.inspect_code(code, file_path="src/services/flightApi.js")

    assert len(routes) == 1
    r = routes[0]
    assert r.method == "GET"
    assert r.route_template == "/api/v1/flights/domestic"
    assert r.base_url_variable == "API_BASE"


def test_extract_axios_create_base_url():
    """Acceptance Test 4: Discovers baseURL configured in axios.create()."""
    code = """
    const client = axios.create({
        baseURL: "/api/v2",
        timeout: 5000
    });
    """
    inspector = BundleInspector()
    base_urls = inspector._extract_base_urls(code)
    assert base_urls.get("default_axios_base") == "/api/v2"


def test_extract_multiple_methods_and_options():
    """Acceptance Test 5: Discovers DELETE, PUT, and fetch with method options."""
    code = """
    function cancelHold(holdId) {
        return axios.delete(`/api/v2/holds/${holdId}`);
    }

    function updatePassenger(pId, data) {
        return fetch(`/api/v1/passengers/${pId}`, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }
    """
    inspector = BundleInspector()
    routes = inspector.inspect_code(code)

    assert len(routes) == 2
    by_method = {r.method: r for r in routes}

    assert "DELETE" in by_method
    assert by_method["DELETE"].route_template == "/api/v2/holds/{hold_id}"
    assert by_method["DELETE"].parameters[0].semantic_type == SemanticType.HOLD_ID.value

    assert "PUT" in by_method
    assert by_method["PUT"].route_template == "/api/v1/passengers/{p_id}"


def test_source_location_provenance_accuracy():
    """Acceptance Test 6: Computes accurate line, column, and code snippet for routes."""
    code = (
        "// Header comment\n"
        "// Line 2\n"
        "const getFares = () => axios.get('/api/v1/fares');\n"
    )
    inspector = BundleInspector()
    routes = inspector.inspect_code(code, file_path="src/fares.ts")

    assert len(routes) == 1
    loc = routes[0].location
    assert loc.file_path == "src/fares.ts"
    assert loc.line == 3
    assert loc.column > 10
    assert "axios.get('/api/v1/fares')" in loc.snippet


def test_source_map_vlq_decoding_and_remapping():
    """Acceptance Test 7: Accurately decodes Source Map v3 VLQ segments to remap position."""
    # Test raw VLQ decoder
    assert decode_vlq_values("AAAA") == [0, 0, 0, 0]
    assert decode_vlq_values("C") == [1]
    assert decode_vlq_values("D") == [-1]

    minified_code = "function a(){return fetch('/api/v1/reports')}"
    source_map = {
        "version": 3,
        "sources": ["src/modules/reporting/ReportsView.tsx"],
        "mappings": "AAAA",
    }

    inspector = BundleInspector()
    routes = inspector.inspect_code(
        minified_code,
        file_path="dist/assets/app.min.js",
        source_map=source_map,
    )

    assert len(routes) == 1
    loc = routes[0].location
    assert loc.file_path == "src/modules/reporting/ReportsView.tsx"
    assert loc.line == 1
    assert loc.column >= 1


def test_source_snippet_redaction_scrubs_secrets_and_credentials():
    """Acceptance Test 8: Scrubs sensitive bearer tokens and api keys from snippets."""
    code = """
    // Config with token
    const callApi = () => fetch("https://user:mypassword@api.tbo.com/api/v1/user?token=secret_jwt_xyz123", {
        headers: { Authorization: "Bearer eyJhbGciOi_test_jwt_secret_token" }
    });
    """
    inspector = BundleInspector()
    routes = inspector.inspect_code(code)

    assert len(routes) == 1
    loc = routes[0].location
    assert "mypassword" not in loc.snippet
    assert "secret_jwt_xyz123" not in loc.snippet
    assert "eyJhbGciOi_test_jwt_secret_token" not in loc.snippet
    assert "[REDACTED" in loc.snippet


def test_bundle_size_safety_limits():
    """Acceptance Test 9: Rejects bundle files exceeding configured size limit."""
    inspector = BundleInspector(max_bundle_size_bytes=50)

    with tempfile.NamedTemporaryFile("w", delete=False) as tf:
        tf.write("// Oversized JavaScript file content that exceeds maximum limit\n" * 10)
        tf_path = tf.name

    with pytest.raises(ValueError, match="exceeds limit"):
        inspector.inspect_file(tf_path)


def test_no_code_execution_security():
    """Acceptance Test 10: Never executes untrusted bundle code (pure static parsing)."""
    malicious_code = """
    // Attempting hostile execution if evaluated
    throw new Error("Malicious code executed!");
    while(true) {}
    process.exit(1);

    fetch('/api/v1/safe/endpoint');
    """
    inspector = BundleInspector()
    # Must not raise the JavaScript error or hang in while(true)
    routes = inspector.inspect_code(malicious_code)
    assert len(routes) == 1
    assert routes[0].route_template == "/api/v1/safe/endpoint"


def test_convert_to_normalized_endpoints():
    """Acceptance Test 11: Converts JS routes to canonical NormalizedEndpoints with identity."""
    code = "const book = (id) => fetch(`/api/v2/bookings/${id}`);"
    inspector = BundleInspector(default_asset_id="travel-portal")
    routes = inspector.inspect_code(code, file_path="src/api.js")

    endpoints = inspector.convert_to_normalized_endpoints(routes, canonical_origin="https://portal.tbo.com")
    assert len(endpoints) == 1

    ep = endpoints[0]
    assert ep.method == "GET"
    assert ep.route_template == "/api/v2/bookings/{id}"
    assert ep.asset_id == "travel-portal"
    assert ep.canonical_origin == "https://portal.tbo.com"
    assert ep.endpoint_identity == "travel-portal:https://portal.tbo.com:GET:/api/v2/bookings/{id}"
    assert len(ep.provenance) == 1
    assert ep.provenance[0].source == "JS_BUNDLE"
    assert ep.provenance[0].canonical_digest is not None
    assert ep.endpoint_signature is not None


def test_cross_discovery_reconciliation():
    """Acceptance Test 12: JS bundle route templates reconcile with HAR normalized templates."""
    js_code = "const book = (bookingId) => axios.get(`/api/v2/bookings/${bookingId}`);"
    inspector = BundleInspector(default_asset_id="tbo-core")
    js_routes = inspector.inspect_code(js_code)
    js_endpoint = inspector.convert_to_normalized_endpoints(js_routes, canonical_origin="https://api.tbo.com")[0]

    # HAR endpoint
    har_obs = EndpointObservation(
        method="GET",
        raw_url="https://api.tbo.com/api/v2/bookings/TBOH_123",
        asset_id="tbo-core",
    )
    har_endpoint = EndpointNormalizer().normalize_single(har_obs)

    # Route template and fully namespaced endpoint_identity match perfectly!
    assert js_endpoint.route_template == har_endpoint.route_template
    assert js_endpoint.endpoint_identity == har_endpoint.endpoint_identity


def test_source_map_unmapped_returns_none_instead_of_arbitrary_source():
    """Acceptance Test 13: Unmapped generated position returns None rather than arbitrarily attributing to sources[0]."""
    raw_map = {
        "version": 3,
        "sources": ["src/alpha.ts", "src/beta.ts"],
        "names": [],
        "mappings": "",  # Empty mappings -> nothing can map
    }
    resolver = SourceMapResolver(raw_map)
    # Generated line 1, column 5 has no mapping
    result = resolver.resolve(1, 5)
    # Must return None (unmapped), NOT fallback to sources[0]!
    assert result is None
