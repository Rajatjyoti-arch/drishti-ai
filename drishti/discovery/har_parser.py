"""HAR 1.2 Archive Ingestion and Security Redaction Engine.

Provides deterministic, offline ingestion of HTTP Archive (HAR 1.2) traces, extracting
sanitized EndpointObservation records for route template discovery without outbound network
egress, leaking credentials, or persisting sensitive payload data.
"""

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, List, Optional, Set, Tuple, Union
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from drishti.discovery.endpoint_normalizer import EndpointNormalizer, RE_SENSITIVE_PARAM
from drishti.discovery.models import EndpointObservation, NormalizedEndpoint

# Maximum permitted HAR file size (50 Megabytes)
MAX_HAR_FILE_SIZE_BYTES: int = 50 * 1024 * 1024

# Maximum permitted entry count per HAR file to prevent algorithmic complexity exhaustion
MAX_HAR_ENTRIES: int = 5000

# Sensitive request and response headers that must ALWAYS be redacted
SENSITIVE_HEADER_NAMES: Set[str] = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "proxy-authorization",
    "x-auth-token",
    "x-access-token",
    "session-token",
    "token",
    "api-key",
    "apikey",
    "secret",
}

# Static file extensions ignored by default in API discovery
STATIC_ASSET_EXTENSIONS: Set[str] = {
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".ico",
    ".map",
    ".webp",
    ".avif",
    ".mp4",
    ".mp3",
}

# Known analytics, telemetry, and tracking hosts to filter out
DEFAULT_BLOCKED_HOST_PATTERNS: Set[str] = {
    "google-analytics.com",
    "googletagmanager.com",
    "hotjar.com",
    "datadoghq.com",
    "sentry.io",
    "segment.io",
    "newrelic.com",
    "mixpanel.com",
    "facebook.net",
}


class HarParsingError(Exception):
    """Raised when HAR archive fails structural validation or security limits."""
    pass


def extract_json_body_schema(obj: Any) -> Any:
    """Recursively abstracts a JSON structure into its schema (keys and types)

    without retaining raw customer values, passwords, or personal data.
    """
    if isinstance(obj, dict):
        return {k: extract_json_body_schema(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, list):
        if not obj:
            return []
        # Sample type structure of first element
        return [extract_json_body_schema(obj[0])]
    elif isinstance(obj, bool):
        return "boolean"
    elif isinstance(obj, (int, float)):
        return "number"
    elif isinstance(obj, str):
        return "string"
    elif obj is None:
        return "null"
    return "unknown"


def compute_canonical_har_entry_digest(
    method: str,
    sanitized_url: str,
    safe_headers: List[Tuple[str, str]],
    body_schema_digest: Optional[str],
) -> str:
    """Computes a deterministic SHA-256 digest over the canonical request representation:

    canonical_digest = sha256(canonical_json(method, sanitized_url, safe_headers, body_schema_digest))
    Strictly excludes raw authentication tokens or unredacted secrets.
    """
    canonical_payload = {
        "body_schema_digest": body_schema_digest,
        "headers": sorted(safe_headers, key=lambda h: h[0]),
        "method": method.upper(),
        "url": sanitized_url,
    }
    encoded = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class HarParser:
    """Offline, deterministic HAR 1.2 parser with security redaction and size bounds."""

    def __init__(
        self,
        max_file_size_bytes: int = MAX_HAR_FILE_SIZE_BYTES,
        max_entries: int = MAX_HAR_ENTRIES,
        filter_static_assets: bool = True,
        filter_third_party: bool = True,
        target_hosts: Optional[Set[str]] = None,
        default_asset_id: str = "primary-api",
    ):
        self.max_file_size_bytes = max_file_size_bytes
        self.max_entries = max_entries
        self.filter_static_assets = filter_static_assets
        self.filter_third_party = filter_third_party
        self.target_hosts = {h.lower() for h in target_hosts} if target_hosts else None
        self.default_asset_id = default_asset_id

    def parse_file(
        self,
        file_path: Union[str, Path],
        role: Optional[str] = None,
        asset_id: Optional[str] = None,
    ) -> List[EndpointObservation]:
        """Validates file bounds and parses a HAR 1.2 file from disk."""
        path = Path(file_path)
        if not path.is_file():
            raise HarParsingError(f"Target HAR file does not exist: {path}")

        file_size = path.stat().st_size
        if file_size > self.max_file_size_bytes:
            raise HarParsingError(
                f"HAR file size ({file_size} bytes) exceeds limit ({self.max_file_size_bytes} bytes)"
            )

        with open(path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                raise HarParsingError(f"Malformed HAR JSON structure: {e}")

        return self.parse_dict(data, role=role, asset_id=asset_id)

    def parse_json(
        self,
        json_content: str,
        role: Optional[str] = None,
        asset_id: Optional[str] = None,
    ) -> List[EndpointObservation]:
        """Parses a HAR 1.2 JSON string with length bounds check."""
        if len(json_content.encode("utf-8")) > self.max_file_size_bytes:
            raise HarParsingError("HAR JSON string exceeds maximum permitted size limit")

        try:
            data = json.loads(json_content)
        except json.JSONDecodeError as e:
            raise HarParsingError(f"Malformed HAR JSON structure: {e}")

        return self.parse_dict(data, role=role, asset_id=asset_id)

    def parse_dict(
        self,
        data: Dict[str, Any],
        role: Optional[str] = None,
        asset_id: Optional[str] = None,
    ) -> List[EndpointObservation]:
        """Parses an in-memory HAR dictionary into sanitized EndpointObservations."""
        if not isinstance(data, dict):
            raise HarParsingError("Root HAR object must be a JSON dictionary")

        log = data.get("log")
        if not isinstance(log, dict):
            raise HarParsingError("HAR missing required top-level 'log' object")

        version = log.get("version", "1.2")
        entries = log.get("entries")
        if not isinstance(entries, list):
            raise HarParsingError("HAR 'log.entries' must be a list")

        if len(entries) > self.max_entries:
            raise HarParsingError(
                f"HAR entries count ({len(entries)}) exceeds safety limit ({self.max_entries})"
            )

        effective_asset_id = asset_id or self.default_asset_id
        observations: List[EndpointObservation] = []

        for idx, entry in enumerate(entries):
            obs = self._parse_single_entry(entry, idx, role, effective_asset_id)
            if obs is not None:
                observations.append(obs)

        return observations

    def ingest_into_normalizer(
        self,
        har_source: Union[str, Path, dict],
        normalizer: EndpointNormalizer,
        role: Optional[str] = None,
        asset_id: Optional[str] = None,
    ) -> List[NormalizedEndpoint]:
        """Convenience pipeline method: parses HAR and feeds directly into EndpointNormalizer."""
        if isinstance(har_source, (str, Path)) and os.path.exists(str(har_source)):
            observations = self.parse_file(har_source, role=role, asset_id=asset_id)
        elif isinstance(har_source, str):
            observations = self.parse_json(har_source, role=role, asset_id=asset_id)
        elif isinstance(har_source, dict):
            observations = self.parse_dict(har_source, role=role, asset_id=asset_id)
        else:
            raise HarParsingError(f"Unsupported HAR source type: {type(har_source)}")

        return normalizer.cluster_and_normalize(observations)

    def _parse_single_entry(
        self,
        entry: Dict[str, Any],
        index: int,
        role: Optional[str],
        asset_id: str,
    ) -> Optional[EndpointObservation]:
        """Sanitizes and extracts a single HAR entry, or returns None if filtered out."""
        if not isinstance(entry, dict):
            return None

        request = entry.get("request")
        if not isinstance(request, dict):
            return None

        raw_url = request.get("url", "")
        method = request.get("method", "GET").upper()
        if not raw_url:
            return None

        parsed_url = urlparse(raw_url)
        hostname = (parsed_url.hostname or "").lower()
        path = parsed_url.path

        # 1. Target Host Filtering
        if self.target_hosts and hostname not in self.target_hosts:
            return None

        # 2. Third-Party Telemetry and Tracking Filtering
        if self.filter_third_party:
            if any(blocked in hostname for blocked in DEFAULT_BLOCKED_HOST_PATTERNS):
                return None

        # 3. Static Asset Filtering
        if self.filter_static_assets:
            path_lower = path.lower()
            if any(path_lower.endswith(ext) for ext in STATIC_ASSET_EXTENSIONS):
                return None

        # 4. URL Sanitization (Redact sensitive query parameters)
        sanitized_url = self._sanitize_url(raw_url)

        # 5. Header Redaction
        raw_headers = request.get("headers", [])
        safe_headers: List[Tuple[str, str]] = []
        if isinstance(raw_headers, list):
            for h in raw_headers:
                if isinstance(h, dict) and "name" in h:
                    h_name = str(h.get("name", "")).lower()
                    h_val = str(h.get("value", ""))
                    if h_name in SENSITIVE_HEADER_NAMES or RE_SENSITIVE_PARAM.search(h_name):
                        safe_headers.append((h_name, "[REDACTED]"))
                    else:
                        safe_headers.append((h_name, h_val))

        # 6. Request Body Schema Extraction
        post_data = request.get("postData")
        body_schema_digest: Optional[str] = None
        if isinstance(post_data, dict):
            mime_type = post_data.get("mimeType", "").lower()
            text = post_data.get("text", "")
            if "application/json" in mime_type and text:
                try:
                    body_json = json.loads(text)
                    schema = extract_json_body_schema(body_json)
                    schema_json = json.dumps(schema, sort_keys=True, separators=(",", ":"))
                    body_schema_digest = hashlib.sha256(schema_json.encode("utf-8")).hexdigest()
                except Exception:
                    body_schema_digest = hashlib.sha256(mime_type.encode("utf-8")).hexdigest()
            elif text:
                # Opaque non-JSON body: digest MIME type only to prevent storing raw body strings
                body_schema_digest = hashlib.sha256(mime_type.encode("utf-8")).hexdigest()

        # 7. Canonical Request Digest Computation
        canonical_digest = compute_canonical_har_entry_digest(
            method=method,
            sanitized_url=sanitized_url,
            safe_headers=safe_headers,
            body_schema_digest=body_schema_digest,
        )

        # 8. Extract Metadata from Response
        response = entry.get("response", {})
        response_status = response.get("status") if isinstance(response, dict) else None
        content_type = None
        if isinstance(response, dict):
            content = response.get("content")
            if isinstance(content, dict):
                content_type = content.get("mimeType")

        timestamp = entry.get("startedDateTime")
        origin = f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url.netloc else ""
        observation_id = f"HAR-{index + 1:04d}"

        # 9. Role attribution: entry comment or explicit parameter
        effective_role = role or entry.get("comment")

        obs_kwargs = {
            "method": method,
            "raw_url": sanitized_url,
            "observation_id": observation_id,
            "asset_id": asset_id,
            "origin": origin,
            "source": "HAR",
            "canonical_digest": canonical_digest,
            "role": effective_role,
            "response_status": response_status,
            "content_type": content_type,
        }
        if timestamp:
            obs_kwargs["timestamp"] = timestamp

        return EndpointObservation(**obs_kwargs)

    def _sanitize_url(self, raw_url: str) -> str:
        """Sanitizes query parameters in the URL, masking sensitive credentials."""
        parsed = urlparse(raw_url)
        if not parsed.query:
            return raw_url

        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        sanitized_pairs = []

        for k, v in query_pairs:
            if RE_SENSITIVE_PARAM.search(k):
                sanitized_pairs.append((k, "[REDACTED]"))
            else:
                sanitized_pairs.append((k, v))

        new_query = urlencode(sanitized_pairs)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        ))
