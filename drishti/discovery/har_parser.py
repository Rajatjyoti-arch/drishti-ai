"""HAR Archive Ingestion and Security Redaction Engine.

Provides deterministic, offline, bounded whole-file ingestion of HTTP Archive (HAR 1.1 / 1.2) traces,
extracting sanitized EndpointObservation records for route template discovery without outbound network
egress, leaking credentials, or persisting sensitive payload data.
"""

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, List, Optional, Set, Tuple, Union
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from drishti.discovery.endpoint_normalizer import EndpointNormalizer, RE_SENSITIVE_PARAM
from drishti.discovery.models import EndpointObservation, NormalizedEndpoint

# Supported HAR specification versions
SUPPORTED_HAR_VERSIONS: Set[str] = {"1.1", "1.2"}

# Maximum permitted HAR file size (50 Megabytes)
MAX_HAR_FILE_SIZE_BYTES: int = 50 * 1024 * 1024

# Maximum permitted entry count per HAR file to prevent algorithmic complexity exhaustion
MAX_HAR_ENTRIES: int = 5000

# Maximum headers evaluated per request entry
MAX_HEADERS_PER_ENTRY: int = 100

# Maximum body schema nodes to prevent memory explosion on deeply nested payloads
MAX_BODY_SCHEMA_NODES: int = 200

# Maximum array elements sampled for schema key merging
MAX_ARRAY_SCHEMA_SAMPLES: int = 5

# Maximum recursion depth for body schema extraction
MAX_SCHEMA_RECURSION_DEPTH: int = 10

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

# Known analytics, telemetry, and tracking hosts to filter out by default
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


def matches_domain(host: str, pattern: str) -> bool:
    """DNS-label-aware matching preventing false-positive substring matches.

    Matches 'sentry.io' and 'sub.sentry.io', but NOT 'not-sentry.io.example.com'.
    """
    host = host.rstrip(".").lower()
    pattern = pattern.rstrip(".").lower()
    return host == pattern or host.endswith("." + pattern)


def sanitize_request_url(raw_url: str) -> str:
    """Sanitizes URL:

    1. Preserves scheme, hostname, and approved non-standard port.
    2. Strips userinfo (username:password@) to prevent credential leakage in URL credentials.
    3. Strips URL fragments completely (preventing leakage of OAuth tokens or SPA states).
    4. Redacts sensitive query parameters matching RE_SENSITIVE_PARAM.
    """
    parsed = urlsplit(raw_url)
    hostname = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    clean_netloc = f"{hostname}{port}"

    sanitized_query = ""
    if parsed.query:
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        clean_pairs = []
        for k, v in pairs:
            if RE_SENSITIVE_PARAM.search(k):
                clean_pairs.append((k, "[REDACTED]"))
            else:
                clean_pairs.append((k, v))
        sanitized_query = urlencode(clean_pairs)

    # Always strip fragment and userinfo
    return urlunsplit((parsed.scheme, clean_netloc, parsed.path, sanitized_query, ""))


def extract_clean_origin(raw_url: str) -> str:
    """Derives clean origin (scheme://hostname[:port]) strictly without userinfo or path."""
    parsed = urlsplit(raw_url)
    if not parsed.scheme or not parsed.hostname:
        return ""
    port = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    return f"{parsed.scheme}://{parsed.hostname}{port}"


def extract_json_body_schema(
    obj: Any,
    max_depth: int = MAX_SCHEMA_RECURSION_DEPTH,
    max_array_samples: int = MAX_ARRAY_SCHEMA_SAMPLES,
    max_nodes: int = MAX_BODY_SCHEMA_NODES,
    current_depth: int = 0,
    node_counter: Optional[List[int]] = None,
) -> Any:
    """Recursively abstracts JSON into a schema of keys and types with bounds:

    - Merges keys across a sample of array elements (up to max_array_samples).
    - Enforces max recursion depth and max total schema nodes.
    - Detects type conflicts in array fields.
    - Strictly redacts all customer values, credit cards, and passwords.
    """
    if node_counter is None:
        node_counter = [0]

    node_counter[0] += 1
    if node_counter[0] > max_nodes or current_depth > max_depth:
        return "truncated"

    if isinstance(obj, dict):
        return {
            k: extract_json_body_schema(
                v,
                max_depth=max_depth,
                max_array_samples=max_array_samples,
                max_nodes=max_nodes,
                current_depth=current_depth + 1,
                node_counter=node_counter,
            )
            for k, v in sorted(obj.items())
        }
    elif isinstance(obj, list):
        if not obj:
            return []
        sample_elements = obj[:max_array_samples]

        # If any elements are dicts, merge keys across all sampled dicts
        if any(isinstance(elem, dict) for elem in sample_elements):
            merged_dict: Dict[str, Any] = {}
            key_types: Dict[str, Set[str]] = {}

            for elem in sample_elements:
                if isinstance(elem, dict):
                    for k, v in elem.items():
                        val_schema = extract_json_body_schema(
                            v,
                            max_depth=max_depth,
                            max_array_samples=max_array_samples,
                            max_nodes=max_nodes,
                            current_depth=current_depth + 1,
                            node_counter=node_counter,
                        )
                        type_repr = (
                            type(val_schema).__name__
                            if isinstance(val_schema, (dict, list))
                            else str(val_schema)
                        )
                        key_types.setdefault(k, set()).add(type_repr)
                        merged_dict[k] = val_schema

            # Mark type conflicts if heterogeneous types exist across elements
            for k, types in key_types.items():
                if len(types) > 1:
                    merged_dict[k] = " | ".join(sorted(types))
            return [merged_dict]
        else:
            # Primitive values in array: union types
            types = {
                str(
                    extract_json_body_schema(
                        elem,
                        max_depth=max_depth,
                        max_array_samples=max_array_samples,
                        max_nodes=max_nodes,
                        current_depth=current_depth + 1,
                        node_counter=node_counter,
                    )
                )
                for elem in sample_elements
            }
            return [" | ".join(sorted(types))]
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
    """Computes a deterministic SHA-256 observation digest:

    observation_digest = sha256(canonical_json(method, sanitized_url, safe_headers, body_schema_digest))
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
    """Offline, deterministic bounded whole-file HAR parser with security redaction and size bounds."""

    def __init__(
        self,
        max_file_size_bytes: int = MAX_HAR_FILE_SIZE_BYTES,
        max_entries: int = MAX_HAR_ENTRIES,
        filter_static_assets: bool = True,
        filter_third_party: bool = True,
        blocked_hosts: Optional[Set[str]] = None,
        target_hosts: Optional[Set[str]] = None,
        default_asset_id: str = "primary-api",
    ):
        self.max_file_size_bytes = max_file_size_bytes
        self.max_entries = max_entries
        self.filter_static_assets = filter_static_assets
        self.filter_third_party = filter_third_party
        self.blocked_hosts = {h.lower() for h in (blocked_hosts or DEFAULT_BLOCKED_HOST_PATTERNS)}
        self.target_hosts = {h.lower() for h in target_hosts} if target_hosts else None
        self.default_asset_id = default_asset_id

    def parse_file(
        self,
        file_path: Union[str, Path],
        role: Optional[str] = None,
        asset_id: Optional[str] = None,
    ) -> List[EndpointObservation]:
        """Validates file bounds and parses a HAR file from disk using a bounded read."""
        path = Path(file_path)
        if not path.is_file():
            raise HarParsingError(f"Target HAR file does not exist: {path}")

        file_size = path.stat().st_size
        if file_size > self.max_file_size_bytes:
            raise HarParsingError(
                f"HAR file size ({file_size} bytes) exceeds limit ({self.max_file_size_bytes} bytes)"
            )

        with open(path, "r", encoding="utf-8") as f:
            content = f.read(self.max_file_size_bytes + 1)
            if len(content.encode("utf-8")) > self.max_file_size_bytes:
                raise HarParsingError(
                    f"HAR file content exceeds limit of {self.max_file_size_bytes} bytes"
                )
            try:
                data = json.loads(content)
            except json.JSONDecodeError as e:
                raise HarParsingError(f"Malformed HAR JSON structure: {e}")

        return self.parse_dict(data, role=role, asset_id=asset_id)

    def parse_json(
        self,
        json_content: str,
        role: Optional[str] = None,
        asset_id: Optional[str] = None,
    ) -> List[EndpointObservation]:
        """Parses a HAR JSON string with length bounds check."""
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

        # Explicit HAR version validation
        version = str(log.get("version", "1.2")).strip()
        if version not in SUPPORTED_HAR_VERSIONS:
            raise HarParsingError(
                f"Unsupported HAR version: '{version}' (supported versions: {sorted(list(SUPPORTED_HAR_VERSIONS))})"
            )

        # Extract capture tool metadata
        creator_info = None
        if isinstance(log.get("creator"), dict):
            creator_info = {
                "name": str(log["creator"].get("name", "")),
                "version": str(log["creator"].get("version", "")),
            }

        browser_info = None
        if isinstance(log.get("browser"), dict):
            browser_info = {
                "name": str(log["browser"].get("name", "")),
                "version": str(log["browser"].get("version", "")),
            }

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
            obs = self._parse_single_entry(
                entry,
                idx,
                role,
                effective_asset_id,
                creator_info,
                browser_info,
            )
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
        creator: Optional[Dict[str, str]],
        browser: Optional[Dict[str, str]],
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

        parsed_url = urlsplit(raw_url)
        hostname = (parsed_url.hostname or "").lower()
        path = parsed_url.path

        # 1. Target Host Filtering
        if self.target_hosts and hostname not in self.target_hosts:
            return None

        # 2. Third-Party Telemetry and Tracking Filtering (DNS-label-aware)
        if self.filter_third_party:
            if any(matches_domain(hostname, blocked) for blocked in self.blocked_hosts):
                return None

        # 3. Static Asset Filtering
        if self.filter_static_assets:
            path_lower = path.lower()
            if any(path_lower.endswith(ext) for ext in STATIC_ASSET_EXTENSIONS):
                return None

        # 4. URL Sanitization: strip userinfo, strip fragments, redact query parameters
        sanitized_url = sanitize_request_url(raw_url)

        # 5. Clean Origin Construction (strictly without userinfo)
        clean_origin = extract_clean_origin(raw_url)

        # 6. Header Redaction and Bounded Count
        raw_headers = request.get("headers", [])
        safe_headers: List[Tuple[str, str]] = []
        if isinstance(raw_headers, list):
            for h in raw_headers[:MAX_HEADERS_PER_ENTRY]:
                if isinstance(h, dict) and "name" in h:
                    h_name = str(h.get("name", "")).lower()
                    h_val = str(h.get("value", ""))
                    if h_name in SENSITIVE_HEADER_NAMES or RE_SENSITIVE_PARAM.search(h_name):
                        safe_headers.append((h_name, "[REDACTED]"))
                    else:
                        safe_headers.append((h_name, h_val))

        # 7. Request Body Schema Extraction
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

        # 8. Canonical Request Observation Digest Computation
        observation_digest = compute_canonical_har_entry_digest(
            method=method,
            sanitized_url=sanitized_url,
            safe_headers=safe_headers,
            body_schema_digest=body_schema_digest,
        )

        # 9. Extract Metadata from Response
        response = entry.get("response", {})
        response_status = response.get("status") if isinstance(response, dict) else None
        content_type = None
        if isinstance(response, dict):
            content = response.get("content")
            if isinstance(content, dict):
                content_type = content.get("mimeType")

        timestamp = entry.get("startedDateTime")
        observation_id = f"HAR-{index + 1:04d}"

        # 10. Role attribution: entry comment or explicit parameter
        effective_role = role or entry.get("comment")

        obs_kwargs = {
            "method": method,
            "raw_url": sanitized_url,
            "observation_id": observation_id,
            "asset_id": asset_id,
            "origin": clean_origin,
            "source": "HAR",
            "canonical_digest": observation_digest,
            "role": effective_role,
            "response_status": response_status,
            "content_type": content_type,
            "creator": creator,
            "browser": browser,
        }
        if timestamp:
            obs_kwargs["timestamp"] = timestamp

        return EndpointObservation(**obs_kwargs)
