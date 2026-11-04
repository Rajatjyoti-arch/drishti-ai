"""Unit and acceptance tests for offline HAR parsing, privacy sanitization, and digest semantics."""

import json
from pathlib import Path
import tempfile
import pytest

from drishti.discovery.endpoint_normalizer import EndpointNormalizer
from drishti.discovery.har_parser import (
    HarParser,
    HarParsingError,
    compute_canonical_har_entry_digest,
    extract_json_body_schema,
    matches_domain,
    sanitize_request_url,
)
from drishti.discovery.models import ParameterClassification


def make_sample_har(entries: list, version: str = "1.2", creator: dict = None, browser: dict = None) -> dict:
    """Helper creating a valid HAR structure with optional metadata."""
    log_dict = {
        "version": version,
        "creator": creator or {"name": "Drishti Browser Agent", "version": "1.0"},
        "entries": entries,
    }
    if browser:
        log_dict["browser"] = browser
    return {"log": log_dict}


def test_parse_standard_har_1_2_entries():
    """Acceptance Test 1: Parses standard HAR 1.2 entries into typed EndpointObservations."""
    har_dict = make_sample_har([
        {
            "startedDateTime": "2026-11-05T01:00:00Z",
            "request": {
                "method": "GET",
                "url": "https://api.tbo.com/api/v1/flights/domestic",
                "headers": [
                    {"name": "Accept", "value": "application/json"},
                    {"name": "User-Agent", "value": "TestClient/1.0"},
                ],
            },
            "response": {
                "status": 200,
                "content": {"mimeType": "application/json"},
            },
        },
        {
            "startedDateTime": "2026-11-05T01:01:00Z",
            "request": {
                "method": "POST",
                "url": "https://api.tbo.com/api/v1/bookings",
                "headers": [
                    {"name": "Content-Type", "value": "application/json"},
                ],
                "postData": {
                    "mimeType": "application/json",
                    "text": json.dumps({"flight_id": "FLT-101", "passengers": 2}),
                },
            },
            "response": {
                "status": 201,
                "content": {"mimeType": "application/json"},
            },
            "comment": "agent_booking_workflow",
        },
    ])

    parser = HarParser()
    observations = parser.parse_dict(har_dict, asset_id="tbo-core")

    assert len(observations) == 2

    obs1 = observations[0]
    assert obs1.method == "GET"
    assert obs1.raw_url == "https://api.tbo.com/api/v1/flights/domestic"
    assert obs1.origin == "https://api.tbo.com"
    assert obs1.asset_id == "tbo-core"
    assert obs1.response_status == 200
    assert obs1.content_type == "application/json"
    assert obs1.canonical_digest is not None

    obs2 = observations[1]
    assert obs2.method == "POST"
    assert obs2.raw_url == "https://api.tbo.com/api/v1/bookings"
    assert obs2.response_status == 201
    assert obs2.role == "agent_booking_workflow"
    assert obs2.canonical_digest is not None


def test_security_redaction_headers_and_cookies():
    """Acceptance Test 2: Sensitive authorization headers and cookies are redacted."""
    har_dict = make_sample_har([
        {
            "request": {
                "method": "GET",
                "url": "https://api.tbo.com/api/v1/secure/profile",
                "headers": [
                    {"name": "Authorization", "value": "Bearer top_secret_jwt_token_12345"},
                    {"name": "Cookie", "value": "sessionid=secret_session_abc; tracker=1"},
                    {"name": "X-API-Key", "value": "secret_key_999"},
                    {"name": "Accept", "value": "application/json"},
                ],
            },
            "response": {"status": 200},
        }
    ])

    parser = HarParser()
    observations = parser.parse_dict(har_dict)
    assert len(observations) == 1

    # Verify secrets are NOT present anywhere in serialized observation
    obs_json = observations[0].model_dump_json()
    assert "top_secret_jwt_token_12345" not in obs_json
    assert "secret_session_abc" not in obs_json
    assert "secret_key_999" not in obs_json


def test_sensitive_query_parameters_redacted_in_url():
    """Acceptance Test 3: Sensitive query parameters in request URLs are masked."""
    har_dict = make_sample_har([
        {
            "request": {
                "method": "GET",
                "url": "https://api.tbo.com/search?origin=DEL&jwt=eyJhbGciOi...&client_secret=s3cr3t&dest=BOM",
            },
            "response": {"status": 200},
        }
    ])

    parser = HarParser()
    observations = parser.parse_dict(har_dict)
    assert len(observations) == 1

    obs = observations[0]
    assert "jwt=%5BREDACTED%5D" in obs.raw_url or "jwt=[REDACTED]" in obs.raw_url
    assert "client_secret=%5BREDACTED%5D" in obs.raw_url or "client_secret=[REDACTED]" in obs.raw_url
    assert "s3cr3t" not in obs.raw_url
    assert "origin=DEL" in obs.raw_url
    assert "dest=BOM" in obs.raw_url


def test_url_userinfo_and_fragment_stripping():
    """Acceptance Test 4: Strips URL embedded credentials (userinfo) and client-side fragments."""
    raw_url = "https://admin:super_secret_pw@api.tbo.com:8443/api/v1/bookings/123?auth_token=jwt99#access_token=oauth_frag_token"
    sanitized = sanitize_request_url(raw_url)

    assert "admin" not in sanitized
    assert "super_secret_pw" not in sanitized
    assert "@" not in sanitized
    assert "oauth_frag_token" not in sanitized
    assert "#" not in sanitized
    assert "auth_token=%5BREDACTED%5D" in sanitized or "auth_token=[REDACTED]" in sanitized
    assert sanitized.startswith("https://api.tbo.com:8443/api/v1/bookings/123")

    # Ingestion check
    har_dict = make_sample_har([
        {"request": {"method": "GET", "url": raw_url}}
    ])
    parser = HarParser()
    obs = parser.parse_dict(har_dict)[0]
    assert obs.origin == "https://api.tbo.com:8443"
    assert "super_secret_pw" not in obs.model_dump_json()
    assert "oauth_frag_token" not in obs.model_dump_json()


def test_canonical_request_digest_reproducibility():
    """Acceptance Test 5: Canonical request digest is deterministic and unaffected by header ordering."""
    entry_a = {
        "request": {
            "method": "GET",
            "url": "https://api.tbo.com/api/v1/bookings/123",
            "headers": [
                {"name": "Accept", "value": "application/json"},
                {"name": "Host", "value": "api.tbo.com"},
                {"name": "Authorization", "value": "Bearer user_token_A"},
            ],
        },
    }
    entry_b = {
        "request": {
            "method": "GET",
            "url": "https://api.tbo.com/api/v1/bookings/123",
            "headers": [
                {"name": "Authorization", "value": "Bearer user_token_DIFFERENT"},
                {"name": "Host", "value": "api.tbo.com"},
                {"name": "Accept", "value": "application/json"},
            ],
        },
    }

    parser = HarParser()
    obs_a = parser.parse_dict(make_sample_har([entry_a]))[0]
    obs_b = parser.parse_dict(make_sample_har([entry_b]))[0]

    # Because Authorization is redacted to [REDACTED] and headers are sorted canonically,
    # both observations must produce the EXACT same canonical observation_digest!
    assert obs_a.canonical_digest == obs_b.canonical_digest
    assert obs_a.observation_digest == obs_b.observation_digest


def test_body_schema_extraction_merges_across_array_elements():
    """Acceptance Test 6: JSON body schema merges keys across array elements without leaking customer data."""
    body_data = {
        "passengers": [
            {"name": "Synthetic User"},
            {"name": "Another User", "passport_number": "SYNTHETIC-123"},
        ],
        "is_priority": True,
        "amount": 2500.50,
    }

    schema = extract_json_body_schema(body_data)
    assert schema["is_priority"] == "boolean"
    assert schema["amount"] == "number"
    # Merged array elements should discover both 'name' and 'passport_number'
    assert schema["passengers"] == [{"name": "string", "passport_number": "string"}]

    # Confirm raw data is not in schema
    schema_str = json.dumps(schema)
    assert "Synthetic User" not in schema_str
    assert "SYNTHETIC-123" not in schema_str


def test_third_party_and_static_asset_filtering():
    """Acceptance Test 7: Static assets (.js, .css, .png) and tracking hosts are filtered out."""
    har_dict = make_sample_har([
        {
            "request": {"method": "GET", "url": "https://api.tbo.com/api/v1/status"},
            "response": {"status": 200},
        },
        {
            "request": {"method": "GET", "url": "https://www.google-analytics.com/collect?v=1"},
            "response": {"status": 200},
        },
        {
            "request": {"method": "GET", "url": "https://api.tbo.com/static/js/main.chunk.js"},
            "response": {"status": 200},
        },
        {
            "request": {"method": "GET", "url": "https://api.tbo.com/images/hero.webp"},
            "response": {"status": 200},
        },
    ])

    parser = HarParser(filter_static_assets=True, filter_third_party=True)
    observations = parser.parse_dict(har_dict)

    # Only the /api/v1/status endpoint should be retained
    assert len(observations) == 1
    assert observations[0].raw_url == "https://api.tbo.com/api/v1/status"


def test_dns_label_aware_domain_matching():
    """Acceptance Test 8: Substring domains like not-sentry.io.travel.com are not falsely blocked."""
    assert matches_domain("sentry.io", "sentry.io") is True
    assert matches_domain("o123.ingest.sentry.io", "sentry.io") is True
    assert matches_domain("not-sentry.io.travel.com", "sentry.io") is False
    assert matches_domain("google-analytics.com", "google-analytics.com") is True
    assert matches_domain("partner.google-analytics.com", "google-analytics.com") is True
    assert matches_domain("fakegoogle-analytics.com", "google-analytics.com") is False


def test_target_host_whitelist_filtering():
    """Acceptance Test 9: Target hosts whitelist excludes out-of-scope services."""
    har_dict = make_sample_har([
        {
            "request": {"method": "GET", "url": "https://api.tbo.com/api/v1/flights"},
        },
        {
            "request": {"method": "GET", "url": "https://unauthorized-partner.com/api/v1/leads"},
        },
    ])

    parser = HarParser(target_hosts={"api.tbo.com"})
    observations = parser.parse_dict(har_dict)

    assert len(observations) == 1
    assert observations[0].raw_url == "https://api.tbo.com/api/v1/flights"


def test_size_and_entry_safety_bounds():
    """Acceptance Test 10: Rejects files or entry counts exceeding safety limits."""
    parser = HarParser(max_file_size_bytes=100, max_entries=2)

    # 1. Test entry count limit
    oversized_entries = make_sample_har([
        {"request": {"method": "GET", "url": f"https://api.tbo.com/test/{i}"}}
        for i in range(5)
    ])
    with pytest.raises(HarParsingError, match="exceeds safety limit"):
        parser.parse_dict(oversized_entries)

    # 2. Test file size limit
    with tempfile.NamedTemporaryFile("w", delete=False) as tf:
        tf.write(json.dumps(oversized_entries))
        tf_path = tf.name

    with pytest.raises(HarParsingError, match="exceeds limit"):
        parser.parse_file(tf_path)

    # 3. Test malformed JSON
    with pytest.raises(HarParsingError, match="Malformed HAR"):
        parser.parse_json("{invalid json")

    # 4. Test missing log object
    with pytest.raises(HarParsingError, match="missing required top-level 'log'"):
        parser.parse_dict({"wrong_key": 123})


def test_har_version_validation_and_metadata_preservation():
    """Acceptance Test 11: Validates HAR versions and preserves creator/browser metadata."""
    valid_har = make_sample_har(
        entries=[{"request": {"method": "GET", "url": "https://api.tbo.com/v1/ping"}}],
        version="1.2",
        creator={"name": "Playwright-Drishti", "version": "1.40.0"},
        browser={"name": "Chromium", "version": "120.0.6099.109"},
    )

    parser = HarParser()
    observations = parser.parse_dict(valid_har)
    assert len(observations) == 1
    obs = observations[0]
    assert obs.creator == {"name": "Playwright-Drishti", "version": "1.40.0"}
    assert obs.browser == {"name": "Chromium", "version": "120.0.6099.109"}

    # Unsupported version 2.0 should raise HarParsingError
    invalid_ver_har = make_sample_har(
        entries=[{"request": {"method": "GET", "url": "https://api.tbo.com/v1/ping"}}],
        version="2.0",
    )
    with pytest.raises(HarParsingError, match="Unsupported HAR version"):
        parser.parse_dict(invalid_ver_har)


def test_observation_digest_vs_endpoint_signature_distinction():
    """Acceptance Test 12: Distinguishes between request observation_digest and contract endpoint_signature."""
    har_dict = make_sample_har([
        {
            "request": {"method": "GET", "url": "https://api.tbo.com/api/v1/bookings/TBOH_001?client_id=agent_a"},
        },
        {
            "request": {"method": "GET", "url": "https://api.tbo.com/api/v1/bookings/TBOH_002?client_id=agent_b"},
        },
    ])

    parser = HarParser()
    normalizer = EndpointNormalizer()

    observations = parser.parse_dict(har_dict)
    assert len(observations) == 2

    # Request representations have different URLs/query parameters, so distinct observation digests
    assert observations[0].observation_digest != observations[1].observation_digest

    endpoints = normalizer.cluster_and_normalize(observations)
    assert len(endpoints) == 1
    endpoint = endpoints[0]

    # But both belong to the exact same contract: endpoint_signature is identical and stable
    sig1 = endpoint.endpoint_signature
    assert sig1 is not None and len(sig1) == 64
    assert endpoint.route_template == "/api/v1/bookings/{booking_id}"


def test_end_to_end_ingest_into_normalizer():
    """Acceptance Test 13: Complete pipeline ingests HAR and outputs normalized templates."""
    har_dict = make_sample_har([
        {
            "request": {"method": "GET", "url": "https://api.tbo.com/api/v2/bookings/TBOH_1001"},
            "comment": "agent_a",
        },
        {
            "request": {"method": "GET", "url": "https://api.tbo.com/api/v2/bookings/TBOH_1002"},
            "comment": "agent_a",
        },
        {
            "request": {"method": "GET", "url": "https://api.tbo.com/api/v2/bookings/search"},
            "comment": "auditor",
        },
        {
            "request": {"method": "GET", "url": "https://api.tbo.com/api/v2/flights/domestic"},
            "comment": "agent_b",
        },
        {
            "request": {"method": "GET", "url": "https://api.tbo.com/api/v2/flights/international"},
            "comment": "agent_b",
        },
    ])

    parser = HarParser()
    normalizer = EndpointNormalizer()

    endpoints = parser.ingest_into_normalizer(har_dict, normalizer)

    # Expect:
    # 1. /api/v2/bookings/{booking_id}
    # 2. /api/v2/bookings/search
    # 3. /api/v2/flights/domestic
    # 4. /api/v2/flights/international
    assert len(endpoints) == 4

    templates = {e.route_template for e in endpoints}
    assert "/api/v2/bookings/{booking_id}" in templates
    assert "/api/v2/bookings/search" in templates
    assert "/api/v2/flights/domestic" in templates
    assert "/api/v2/flights/international" in templates

    booking_endpoint = next(e for e in endpoints if e.route_template == "/api/v2/bookings/{booking_id}")
    assert len(booking_endpoint.provenance) == 2
    assert booking_endpoint.parameters[0].classification == ParameterClassification.CONFIRMED.value
    assert booking_endpoint.provenance[0].source == "HAR"
    assert booking_endpoint.provenance[0].canonical_digest is not None
    assert booking_endpoint.endpoint_signature is not None
