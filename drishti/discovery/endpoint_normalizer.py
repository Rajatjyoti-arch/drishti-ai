"""Deterministic endpoint path normalization and parameter discovery engine.

Analyzes raw observed API requests, extracts query parameters, detects dynamic path
segments (UUIDs, prefixed IDs, integers, positional variance), preserves static keywords,
and enforces data minimization and credential redaction.
"""

import math
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from drishti.discovery.models import (
    ConfidenceAssessment,
    EndpointObservation,
    NormalizedEndpoint,
    ParameterCandidate,
    ParameterClassification,
    ParameterLocation,
    ProvenanceSource,
    SemanticType,
)

# Static keywords that must NEVER be parameterized into dynamic variables
STATIC_KEYWORDS: Set[str] = {
    "search", "latest", "summary", "international", "domestic", "cancel",
    "confirm", "hold", "quote", "status", "health", "metrics", "export",
    "download", "reset", "book", "login", "auth", "logout", "admin",
    "agent", "sub_agent", "auditor", "users", "bookings", "flights",
    "hotels", "reports", "v1", "v2", "v3", "api", "test", "catalog",
    "pricing", "tariff", "fares", "details", "all", "active", "history",
    "overview", "profile", "settings", "passengers", "pnr", "webhook",
    "webhooks", "docs", "schema", "openapi", "swagger", "ping", "live",
    "ready", "public",
}

# Regex pattern for sensitive query parameter keys and tokens
RE_SENSITIVE_PARAM = re.compile(
    r"(?:token|jwt|secret|password|passwd|auth|session|apikey|api_key|access_token|client_secret|sig|signature|bearer)",
    re.IGNORECASE,
)

# Strict UUIDv4 pattern (RFC 4122 variant 1, version 4)
RE_UUID_V4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Generic UUID pattern (any version/variant)
RE_GENERIC_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

RE_INTEGER = re.compile(r"^\d+$")
RE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Travel-specific prefixed ID patterns
RE_BOOKING_PREFIX = re.compile(r"^(?:TBOH?|BOK|BK|b|res)[_-][0-9a-zA-Z]+$", re.IGNORECASE)
RE_HOLD_PREFIX = re.compile(r"^(?:HLD|hold|h)[_-][0-9a-zA-Z]+$", re.IGNORECASE)
RE_QUOTE_PREFIX = re.compile(r"^(?:QUO|quote|q)[_-][0-9a-zA-Z]+$", re.IGNORECASE)
RE_FLIGHT_PREFIX = re.compile(r"^(?:FLT|AI|6E|EK|UK|BA|DL|AA|LH)[_-]?[0-9]{3,4}$", re.IGNORECASE)
RE_TENANT_PREFIX = re.compile(r"^(?:AGN|agency|tenant|supplier)[_-][0-9a-zA-Z]+$", re.IGNORECASE)

MAX_OBSERVED_VALUES_SAMPLE = 3


def calculate_shannon_entropy(s: str) -> float:
    """Computes Shannon entropy of an alphanumeric segment."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


def is_recognized_dynamic_pattern(seg: str) -> bool:
    """Returns True if segment matches a recognized dynamic identifier pattern."""
    if RE_UUID_V4.match(seg) or RE_GENERIC_UUID.match(seg):
        return True
    if RE_BOOKING_PREFIX.match(seg) or RE_HOLD_PREFIX.match(seg) or RE_QUOTE_PREFIX.match(seg):
        return True
    if RE_FLIGHT_PREFIX.match(seg) or RE_TENANT_PREFIX.match(seg):
        return True
    if RE_DATE.match(seg) or RE_INTEGER.match(seg):
        return True
    return False


def mask_observed_identifier(val: str, sem_type: SemanticType) -> str:
    """Masks dynamic identifiers to prevent persistent storage of raw booking references or PII."""
    if sem_type == SemanticType.BOOKING_ID:
        prefix = val[:4] if len(val) >= 4 else "BOK"
        return f"{prefix}_***"
    elif sem_type == SemanticType.UUID:
        return "[UUID_MASKED]"
    elif sem_type == SemanticType.NUMERIC_ID:
        return "[ID_MASKED]"
    elif sem_type in (SemanticType.HOLD_ID, SemanticType.QUOTE_ID, SemanticType.FLIGHT_ID, SemanticType.TENANT_ID):
        prefix = val.split("_")[0] if "_" in val else val[:3]
        return f"{prefix}_***"
    return "[VALUE_MASKED]"


class EndpointNormalizer:
    """Deterministic Normalizer mapping dynamic paths to canonical route templates."""

    def __init__(
        self,
        static_keywords: Optional[Set[str]] = None,
        mask_observed_identifiers: bool = False,
    ):
        self.static_keywords = set(STATIC_KEYWORDS)
        if static_keywords:
            self.static_keywords.update(k.lower() for k in static_keywords)
        self.mask_observed_identifiers = mask_observed_identifiers

    def normalize_single(self, observation: EndpointObservation) -> NormalizedEndpoint:
        """Normalizes a single observed URL without multi-observation clustering."""
        parsed = urlparse(observation.raw_url)
        path = parsed.path.strip("/")
        segments = [s for s in path.split("/") if s]

        normalized_segments: List[str] = []
        path_params: List[ParameterCandidate] = []
        signals: List[str] = []
        confidence_base = 0.70

        for i, seg in enumerate(segments):
            prev_seg = segments[i - 1].lower() if i > 0 else ""
            is_param, param_name, sem_type, score_boost, signal, classification = self._classify_segment(
                seg, prev_seg
            )

            if is_param:
                normalized_segments.append(f"{{{param_name}}}")
                stored_vals = (
                    [mask_observed_identifier(seg, sem_type)]
                    if self.mask_observed_identifiers
                    else [seg]
                )
                path_params.append(
                    ParameterCandidate(
                        name=param_name,
                        location=ParameterLocation.PATH.value,
                        semantic_type=sem_type.value,
                        classification=classification,
                        observed_values=stored_vals,
                        is_masked=self.mask_observed_identifiers,
                    )
                )
                confidence_base += score_boost
                signals.append(signal)
            else:
                normalized_segments.append(seg)

        route_template = "/" + "/".join(normalized_segments)
        query_params = self._extract_query_parameters(parsed.query)

        final_score = min(max(confidence_base, 0.50), 0.95)
        if not path_params:
            final_score = 1.0
            signals.append("static_route_match")

        provenance = [
            ProvenanceSource(
                source=observation.source,
                observation_id=observation.observation_id,
                canonical_digest=observation.canonical_digest,
            )
        ]

        roles = [observation.role] if observation.role else []

        return NormalizedEndpoint(
            method=observation.method,
            route_template=route_template,
            asset_id=observation.asset_id or "primary-api",
            canonical_origin=observation.get_origin(),
            parameters=path_params,
            query_parameters=query_params,
            provenance=provenance,
            confidence=ConfidenceAssessment(score=final_score, signals=signals),
            roles_observed=roles,
        )

    def normalize(self, observations: List[EndpointObservation]) -> List[NormalizedEndpoint]:
        """Normalizes a collection of observations into clustered, canonical NormalizedEndpoints."""
        return self.cluster_and_normalize(observations)

    def cluster_and_normalize(
        self, observations: List[EndpointObservation]
    ) -> List[NormalizedEndpoint]:
        """Clusters multiple raw observations partitioned by (origin, method, static_prefix, segment_count),

        using positional variance and pattern recognition to discover route templates.
        """
        # Group observations by (origin, method, static_prefix_signature, segment_count)
        groups: Dict[Tuple[str, str, Tuple[str, ...], int], List[Tuple[EndpointObservation, List[str]]]] = {}

        for obs in observations:
            parsed = urlparse(obs.raw_url)
            origin = obs.get_origin()
            path = parsed.path.strip("/")
            segments = [s for s in path.split("/") if s]
            static_prefix = self._extract_static_prefix(segments)
            key = (origin, obs.method.upper(), static_prefix, len(segments))
            groups.setdefault(key, []).append((obs, segments))

        results: List[NormalizedEndpoint] = []

        for (origin, method, static_prefix, count), entries in groups.items():
            if not entries:
                continue

            # Partition entries by static branches to keep static alternatives separate
            partitioned = self._partition_by_static_branches(entries)

            for sub_entries in partitioned:
                normalized = self._normalize_clustered_group(method, count, sub_entries)
                results.append(normalized)

        # Sort results deterministically by endpoint key
        return sorted(results, key=lambda e: e.endpoint_key)

    def _extract_static_prefix(self, segments: List[str]) -> Tuple[str, ...]:
        """Extracts the leading sequence of static segments before any dynamic parameter."""
        prefix: List[str] = []
        for seg in segments:
            if is_recognized_dynamic_pattern(seg) or seg.lower() not in self.static_keywords:
                # First non-static or dynamic segment marks end of static prefix
                if is_recognized_dynamic_pattern(seg):
                    break
                # If it's a known static keyword, keep it in prefix
                if seg.lower() in self.static_keywords:
                    prefix.append(seg.lower())
                else:
                    prefix.append(seg.lower())
                    break
            else:
                prefix.append(seg.lower())
        return tuple(prefix)

    def _classify_segment(
        self, seg: str, prev_seg: str
    ) -> Tuple[bool, str, SemanticType, float, str, str]:
        """Classifies an individual path segment into static or parameter candidate.

        Returns (is_param, param_name, semantic_type, score_boost, signal, classification).
        """
        seg_lower = seg.lower()

        # 1. Never parameterize static keywords
        if seg_lower in self.static_keywords:
            return False, seg, SemanticType.GENERIC, 0.0, "static_keyword", ParameterClassification.CONFIRMED.value

        # 2. Strict UUIDv4 pattern
        if RE_UUID_V4.match(seg):
            param_name = f"{prev_seg.rstrip('s')}_id" if prev_seg else "uuid"
            return True, param_name, SemanticType.UUID, 0.25, "uuidv4_pattern", ParameterClassification.CONFIRMED.value

        # 3. Generic UUID pattern (non-v4)
        if RE_GENERIC_UUID.match(seg):
            param_name = f"{prev_seg.rstrip('s')}_id" if prev_seg else "uuid"
            return True, param_name, SemanticType.UUID, 0.20, "generic_uuid_pattern", ParameterClassification.INFERRED.value

        # 4. Check Travel Prefixed IDs
        if RE_BOOKING_PREFIX.match(seg) or prev_seg in ("bookings", "booking", "pnr"):
            if RE_BOOKING_PREFIX.match(seg):
                return True, "booking_id", SemanticType.BOOKING_ID, 0.25, "booking_prefix_pattern", ParameterClassification.CONFIRMED.value
        if RE_HOLD_PREFIX.match(seg) or prev_seg in ("holds", "hold"):
            if RE_HOLD_PREFIX.match(seg):
                return True, "hold_id", SemanticType.HOLD_ID, 0.25, "hold_prefix_pattern", ParameterClassification.CONFIRMED.value
        if RE_QUOTE_PREFIX.match(seg) or prev_seg in ("quotes", "quote"):
            if RE_QUOTE_PREFIX.match(seg):
                return True, "quote_id", SemanticType.QUOTE_ID, 0.25, "quote_prefix_pattern", ParameterClassification.CONFIRMED.value
        if RE_FLIGHT_PREFIX.match(seg) or prev_seg in ("flights", "flight"):
            if RE_FLIGHT_PREFIX.match(seg):
                return True, "flight_id", SemanticType.FLIGHT_ID, 0.25, "flight_prefix_pattern", ParameterClassification.CONFIRMED.value
        if RE_TENANT_PREFIX.match(seg) or prev_seg in ("agencies", "agency", "tenants"):
            if RE_TENANT_PREFIX.match(seg):
                return True, "tenant_id", SemanticType.TENANT_ID, 0.25, "tenant_prefix_pattern", ParameterClassification.CONFIRMED.value

        # 5. Check Date pattern
        if RE_DATE.match(seg):
            return True, "travel_date", SemanticType.DATE, 0.20, "date_pattern", ParameterClassification.CONFIRMED.value

        # 6. Check Pure Integer pattern
        if RE_INTEGER.match(seg):
            param_name = f"{prev_seg.rstrip('s')}_id" if prev_seg else "id"
            return True, param_name, SemanticType.NUMERIC_ID, 0.15, "integer_pattern", ParameterClassification.INFERRED.value

        # 7. High-entropy alphanumeric hash (e.g. "a1b2c3d4e5f6")
        if len(seg) >= 8 and any(c.isdigit() for c in seg) and any(c.isalpha() for c in seg):
            entropy = calculate_shannon_entropy(seg)
            if entropy >= 2.5:
                param_name = f"{prev_seg.rstrip('s')}_token" if prev_seg else "token"
                return True, param_name, SemanticType.GENERIC, 0.10, "high_entropy_alphanumeric", ParameterClassification.INFERRED.value

        # Default: preserve as static segment (avoid false positive normalization)
        return False, seg, SemanticType.GENERIC, 0.0, "unrecognized_static", ParameterClassification.UNCERTAIN.value

    def _partition_by_static_branches(
        self, entries: List[Tuple[EndpointObservation, List[str]]]
    ) -> List[List[Tuple[EndpointObservation, List[str]]]]:
        """Separates observations where a path position contains distinct static keywords or alternatives

        so that /flights/domestic and /flights/international (or /bookings/search vs /bookings/TBOH_123)
        are never collapsed together.
        """
        if not entries:
            return []
        length = len(entries[0][1])

        current_partitions = [entries]
        for pos in range(length):
            next_partitions: List[List[Tuple[EndpointObservation, List[str]]]] = []
            for partition in current_partitions:
                static_groups: Dict[str, List[Tuple[EndpointObservation, List[str]]]] = {}
                dynamic_group: List[Tuple[EndpointObservation, List[str]]] = []

                for entry in partition:
                    val = entry[1][pos].lower()
                    if val in self.static_keywords:
                        static_groups.setdefault(val, []).append(entry)
                    else:
                        dynamic_group.append(entry)

                # If there are static keywords AND (dynamic entries exist OR multiple distinct static keywords exist)
                if static_groups and (dynamic_group or len(static_groups) > 1):
                    for kw, kw_entries in static_groups.items():
                        next_partitions.append(kw_entries)
                    if dynamic_group:
                        next_partitions.append(dynamic_group)
                else:
                    next_partitions.append(partition)
            current_partitions = next_partitions

        return current_partitions

    def _normalize_clustered_group(
        self,
        method: str,
        length: int,
        entries: List[Tuple[EndpointObservation, List[str]]],
    ) -> NormalizedEndpoint:
        """Normalizes a group of observations that share the same template structure."""
        normalized_segments: List[str] = []
        path_params: List[ParameterCandidate] = []
        signals: Set[str] = set()

        all_provenance: List[ProvenanceSource] = []
        all_roles: Set[str] = set()
        all_query_params: Dict[str, ParameterCandidate] = {}

        for obs, _ in entries:
            all_provenance.append(
                ProvenanceSource(
                    source=obs.source,
                    observation_id=obs.observation_id,
                    canonical_digest=obs.canonical_digest,
                )
            )
            if obs.role:
                all_roles.add(obs.role)

            parsed = urlparse(obs.raw_url)
            for q_param in self._extract_query_parameters(parsed.query):
                all_query_params[q_param.name] = q_param

        # Analyze each position across all entries
        for pos in range(length):
            values_at_pos = [e[1][pos] for e in entries]
            distinct_values = set(values_at_pos)
            sample_val = values_at_pos[0]
            prev_seg = normalized_segments[pos - 1].strip("{}") if pos > 0 else ""

            # Check if all observations at this position are static keywords
            if all(v.lower() in self.static_keywords for v in distinct_values):
                if len(distinct_values) == 1:
                    normalized_segments.append(sample_val)
                    continue

            # If multiple distinct values observed at this position -> check variance
            if len(distinct_values) > 1:
                # Check if values match a recognized pattern
                pattern_matches = any(is_recognized_dynamic_pattern(v) for v in distinct_values)
                param_name = self._infer_param_name(sample_val, prev_seg)
                sem_type = self._infer_semantic_type(sample_val, prev_seg)
                normalized_segments.append(f"{{{param_name}}}")

                # Calibrate classification: confirmed if recognized pattern + variance, else inferred
                classification = (
                    ParameterClassification.CONFIRMED.value
                    if pattern_matches
                    else ParameterClassification.INFERRED.value
                )

                # Data minimization: sample at most MAX_OBSERVED_VALUES_SAMPLE values
                sampled_values = sorted(list(distinct_values))[:MAX_OBSERVED_VALUES_SAMPLE]
                stored_values = (
                    [mask_observed_identifier(v, sem_type) for v in sampled_values]
                    if self.mask_observed_identifiers
                    else sampled_values
                )

                path_params.append(
                    ParameterCandidate(
                        name=param_name,
                        location=ParameterLocation.PATH.value,
                        semantic_type=sem_type.value,
                        classification=classification,
                        observed_values=stored_values,
                        is_masked=self.mask_observed_identifiers,
                    )
                )
                signals.add("repeated_path_position")
                signals.add("variance_clustering")
                continue

            # Single value: evaluate using individual heuristics
            is_param, param_name, sem_type, _, sig, classification = self._classify_segment(sample_val, prev_seg)
            if is_param:
                normalized_segments.append(f"{{{param_name}}}")
                stored_single = (
                    [mask_observed_identifier(sample_val, sem_type)]
                    if self.mask_observed_identifiers
                    else [sample_val]
                )
                path_params.append(
                    ParameterCandidate(
                        name=param_name,
                        location=ParameterLocation.PATH.value,
                        semantic_type=sem_type.value,
                        classification=classification,
                        observed_values=stored_single,
                        is_masked=self.mask_observed_identifiers,
                    )
                )
                signals.add(sig)
            else:
                normalized_segments.append(sample_val)

        route_template = "/" + "/".join(normalized_segments)

        # Calibrated confidence scoring
        score = 0.80
        if "variance_clustering" in signals:
            score += 0.15
        if any("pattern" in s for s in signals):
            score += 0.05
        if not path_params:
            score = 1.0
            signals.add("static_route_match")

        final_score = min(score, 1.0)
        effective_asset_id = entries[0][0].asset_id if entries and entries[0][0].asset_id else "primary-api"
        effective_origin = entries[0][0].get_origin() if entries else ""

        return NormalizedEndpoint(
            method=method,
            route_template=route_template,
            asset_id=effective_asset_id,
            canonical_origin=effective_origin,
            parameters=path_params,
            query_parameters=list(all_query_params.values()),
            provenance=all_provenance,
            confidence=ConfidenceAssessment(score=final_score, signals=sorted(list(signals))),
            roles_observed=sorted(list(all_roles)),
        )

    def _infer_param_name(self, sample_val: str, prev_seg: str) -> str:
        """Derives a semantic parameter name from sample value and preceding segment."""
        if RE_BOOKING_PREFIX.match(sample_val) or prev_seg in ("bookings", "booking"):
            return "booking_id"
        if RE_HOLD_PREFIX.match(sample_val) or prev_seg in ("holds", "hold"):
            return "hold_id"
        if RE_QUOTE_PREFIX.match(sample_val) or prev_seg in ("quotes", "quote"):
            return "quote_id"
        if RE_FLIGHT_PREFIX.match(sample_val) or prev_seg in ("flights", "flight"):
            return "flight_id"
        if RE_TENANT_PREFIX.match(sample_val) or prev_seg in ("agencies", "agency", "tenants"):
            return "tenant_id"
        if RE_UUID_V4.match(sample_val) or RE_GENERIC_UUID.match(sample_val):
            return f"{prev_seg.rstrip('s')}_id" if prev_seg else "uuid"
        if RE_INTEGER.match(sample_val):
            return f"{prev_seg.rstrip('s')}_id" if prev_seg else "id"
        return f"{prev_seg.rstrip('s')}_id" if prev_seg else "param"

    def _infer_semantic_type(self, sample_val: str, prev_seg: str) -> SemanticType:
        """Derives a semantic type enum from sample value and preceding segment."""
        if RE_BOOKING_PREFIX.match(sample_val) or prev_seg in ("bookings", "booking"):
            return SemanticType.BOOKING_ID
        if RE_HOLD_PREFIX.match(sample_val) or prev_seg in ("holds", "hold"):
            return SemanticType.HOLD_ID
        if RE_QUOTE_PREFIX.match(sample_val) or prev_seg in ("quotes", "quote"):
            return SemanticType.QUOTE_ID
        if RE_FLIGHT_PREFIX.match(sample_val) or prev_seg in ("flights", "flight"):
            return SemanticType.FLIGHT_ID
        if RE_TENANT_PREFIX.match(sample_val) or prev_seg in ("agencies", "agency", "tenants"):
            return SemanticType.TENANT_ID
        if RE_UUID_V4.match(sample_val) or RE_GENERIC_UUID.match(sample_val):
            return SemanticType.UUID
        if RE_INTEGER.match(sample_val):
            return SemanticType.NUMERIC_ID
        return SemanticType.GENERIC

    def _extract_query_parameters(self, query_string: str) -> List[ParameterCandidate]:
        """Parses query string, redacts sensitive parameters via regex, samples observed values,

        and returns typed candidates.
        """
        if not query_string:
            return []

        parsed_qs = parse_qs(query_string, keep_blank_values=True)
        candidates: List[ParameterCandidate] = []

        for key, values in parsed_qs.items():
            is_sensitive = bool(RE_SENSITIVE_PARAM.search(key))
            clean_values = ["[REDACTED]"] if is_sensitive else values[:MAX_OBSERVED_VALUES_SAMPLE]

            # Infer semantic type
            sem_type = SemanticType.GENERIC
            if key.lower() in ("date", "travel_date", "departure_date"):
                sem_type = SemanticType.DATE
            elif key.lower() in ("currency", "curr"):
                sem_type = SemanticType.CURRENCY
            elif key.lower() in ("tenant", "tenant_id", "agency"):
                sem_type = SemanticType.TENANT_ID

            candidates.append(
                ParameterCandidate(
                    name=key,
                    location=ParameterLocation.QUERY.value,
                    semantic_type=sem_type.value,
                    classification=ParameterClassification.CONFIRMED.value,
                    observed_values=clean_values,
                )
            )

        return sorted(candidates, key=lambda c: c.name)
