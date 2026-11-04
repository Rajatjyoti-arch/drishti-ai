"""Deterministic endpoint path normalization and parameter discovery engine.

Analyzes raw observed API requests, extracts query parameters, detects dynamic path
segments (UUIDs, prefixed IDs, integers, positional variance), and preserves static keywords.
"""

import math
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from drishti.discovery.models import (
    ConfidenceAssessment,
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
}

# Sensitive query parameter keys that must be redacted
SENSITIVE_PARAM_NAMES: Set[str] = {
    "token", "api_key", "apikey", "secret", "password", "session",
    "session_id", "auth", "authorization", "key", "access_token",
}

# Regex patterns for dynamic identifier recognition
RE_UUID = re.compile(
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


def calculate_shannon_entropy(s: str) -> float:
    """Computes Shannon entropy of an alphanumeric segment."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


class EndpointObservation:
    """A raw observed HTTP request to be normalized."""

    def __init__(
        self,
        method: str,
        raw_url: str,
        observation_id: str = "OBS-001",
        source: str = "HAR",
        canonical_digest: Optional[str] = None,
        role: Optional[str] = None,
    ):
        self.method = method.upper()
        self.raw_url = raw_url
        self.observation_id = observation_id
        self.source = source
        self.canonical_digest = canonical_digest
        self.role = role


class EndpointNormalizer:
    """Deterministic Normalizer mapping dynamic paths to canonical route templates."""

    def __init__(self, static_keywords: Optional[Set[str]] = None):
        self.static_keywords = set(STATIC_KEYWORDS)
        if static_keywords:
            self.static_keywords.update(k.lower() for k in static_keywords)

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
            is_param, param_name, sem_type, score_boost, signal = self._classify_segment(
                seg, prev_seg
            )

            if is_param:
                normalized_segments.append(f"{{{param_name}}}")
                path_params.append(
                    ParameterCandidate(
                        name=param_name,
                        location=ParameterLocation.PATH.value,
                        semantic_type=sem_type.value,
                        classification=ParameterClassification.INFERRED.value,
                        observed_values=[seg],
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
            parameters=path_params,
            query_parameters=query_params,
            provenance=provenance,
            confidence=ConfidenceAssessment(score=final_score, signals=signals),
            roles_observed=roles,
        )

    def cluster_and_normalize(
        self, observations: List[EndpointObservation]
    ) -> List[NormalizedEndpoint]:
        """Clusters multiple raw observations across methods and paths, using positional

        variance to confirm dynamic parameter slots with high confidence.
        """
        # Group observations by (method, segment_count)
        groups: Dict[Tuple[str, int], List[Tuple[EndpointObservation, List[str]]]] = {}

        for obs in observations:
            parsed = urlparse(obs.raw_url)
            path = parsed.path.strip("/")
            segments = [s for s in path.split("/") if s]
            key = (obs.method, len(segments))
            groups.setdefault(key, []).append((obs, segments))

        results: List[NormalizedEndpoint] = []

        for (method, count), entries in groups.items():
            if not entries:
                continue

            # First pass: check which static routes branch off (e.g. /search)
            # Partition entries by static segments
            partitioned = self._partition_by_static_branches(entries)

            for sub_entries in partitioned:
                normalized = self._normalize_clustered_group(method, count, sub_entries)
                results.append(normalized)

        return results

    def _classify_segment(
        self, seg: str, prev_seg: str
    ) -> Tuple[bool, str, SemanticType, float, str]:
        """Classifies an individual path segment into static or parameter candidate."""
        seg_lower = seg.lower()

        # 1. Never parameterize static keywords
        if seg_lower in self.static_keywords:
            return False, seg, SemanticType.GENERIC, 0.0, "static_keyword"

        # 2. Check UUID pattern
        if RE_UUID.match(seg):
            param_name = f"{prev_seg.rstrip('s')}_id" if prev_seg else "uuid"
            return True, param_name, SemanticType.UUID, 0.20, "uuid_pattern"

        # 3. Check Travel Prefixed IDs
        if RE_BOOKING_PREFIX.match(seg) or prev_seg in ("bookings", "booking", "pnr"):
            if RE_BOOKING_PREFIX.match(seg):
                return True, "booking_id", SemanticType.BOOKING_ID, 0.25, "booking_prefix_pattern"
        if RE_HOLD_PREFIX.match(seg) or prev_seg in ("holds", "hold"):
            if RE_HOLD_PREFIX.match(seg):
                return True, "hold_id", SemanticType.HOLD_ID, 0.25, "hold_prefix_pattern"
        if RE_QUOTE_PREFIX.match(seg) or prev_seg in ("quotes", "quote"):
            if RE_QUOTE_PREFIX.match(seg):
                return True, "quote_id", SemanticType.QUOTE_ID, 0.25, "quote_prefix_pattern"
        if RE_FLIGHT_PREFIX.match(seg) or prev_seg in ("flights", "flight"):
            if RE_FLIGHT_PREFIX.match(seg):
                return True, "flight_id", SemanticType.FLIGHT_ID, 0.25, "flight_prefix_pattern"
        if RE_TENANT_PREFIX.match(seg) or prev_seg in ("agencies", "agency", "tenants"):
            if RE_TENANT_PREFIX.match(seg):
                return True, "tenant_id", SemanticType.TENANT_ID, 0.25, "tenant_prefix_pattern"

        # 4. Check Date pattern
        if RE_DATE.match(seg):
            return True, "travel_date", SemanticType.DATE, 0.20, "date_pattern"

        # 5. Check Pure Integer pattern
        if RE_INTEGER.match(seg):
            param_name = f"{prev_seg.rstrip('s')}_id" if prev_seg else "id"
            return True, param_name, SemanticType.NUMERIC_ID, 0.15, "integer_pattern"

        # 6. High-entropy alphanumeric hash (e.g. "a1b2c3d4e5f6")
        if len(seg) >= 8 and any(c.isdigit() for c in seg) and any(c.isalpha() for c in seg):
            entropy = calculate_shannon_entropy(seg)
            if entropy >= 2.5:
                param_name = f"{prev_seg.rstrip('s')}_token" if prev_seg else "token"
                return True, param_name, SemanticType.GENERIC, 0.10, "high_entropy_alphanumeric"

        # Default: preserve as static segment (avoid false positive normalization)
        return False, seg, SemanticType.GENERIC, 0.0, "unrecognized_static"

    def _partition_by_static_branches(
        self, entries: List[Tuple[EndpointObservation, List[str]]]
    ) -> List[List[Tuple[EndpointObservation, List[str]]]]:
        """Separates observations where a path position contains a known static keyword

        from entries that contain dynamic parameters at that same position.
        (e.g., separates /bookings/search from /bookings/TBOH_123).
        """
        # Find positions with static keywords
        first_segments = entries[0][1]
        length = len(first_segments)

        # Check each position for keyword vs non-keyword split
        for pos in range(length):
            keywords_found = set()
            non_keywords_found = set()

            for _, segs in entries:
                val = segs[pos].lower()
                if val in self.static_keywords:
                    keywords_found.add(val)
                else:
                    non_keywords_found.add(val)

            if keywords_found and non_keywords_found:
                # Branch into distinct subsets
                partitions: List[List[Tuple[EndpointObservation, List[str]]]] = []
                for kw in keywords_found:
                    kw_entries = [e for e in entries if e[1][pos].lower() == kw]
                    partitions.append(kw_entries)

                dynamic_entries = [e for e in entries if e[1][pos].lower() not in keywords_found]
                if dynamic_entries:
                    partitions.append(dynamic_entries)
                return partitions

        return [entries]

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

            # Check if all observations have identical static segment
            if len(distinct_values) == 1 and sample_val.lower() in self.static_keywords:
                normalized_segments.append(sample_val)
                continue

            # If multiple distinct values observed at this position -> confirmed dynamic variance!
            if len(distinct_values) > 1:
                param_name = self._infer_param_name(sample_val, prev_seg)
                sem_type = self._infer_semantic_type(sample_val, prev_seg)
                normalized_segments.append(f"{{{param_name}}}")

                path_params.append(
                    ParameterCandidate(
                        name=param_name,
                        location=ParameterLocation.PATH.value,
                        semantic_type=sem_type.value,
                        classification=ParameterClassification.CONFIRMED.value,
                        observed_values=sorted(list(distinct_values)),
                    )
                )
                signals.add("repeated_path_position")
                signals.add("variance_clustering")
                continue

            # Single value: evaluate using individual heuristics
            is_param, param_name, sem_type, _, sig = self._classify_segment(sample_val, prev_seg)
            if is_param:
                normalized_segments.append(f"{{{param_name}}}")
                path_params.append(
                    ParameterCandidate(
                        name=param_name,
                        location=ParameterLocation.PATH.value,
                        semantic_type=sem_type.value,
                        classification=ParameterClassification.INFERRED.value,
                        observed_values=[sample_val],
                    )
                )
                signals.add(sig)
            else:
                normalized_segments.append(sample_val)

        route_template = "/" + "/".join(normalized_segments)

        # Confidence score derivation
        score = 0.80
        if "variance_clustering" in signals:
            score += 0.15
        if any("pattern" in s for s in signals):
            score += 0.05
        if not path_params:
            score = 1.0
            signals.add("static_route_match")

        final_score = min(score, 1.0)

        return NormalizedEndpoint(
            method=method,
            route_template=route_template,
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
        if RE_UUID.match(sample_val):
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
        if RE_UUID.match(sample_val):
            return SemanticType.UUID
        if RE_INTEGER.match(sample_val):
            return SemanticType.NUMERIC_ID
        return SemanticType.GENERIC

    def _extract_query_parameters(self, query_string: str) -> List[ParameterCandidate]:
        """Parses query string, redacts sensitive parameters, and returns typed candidates."""
        if not query_string:
            return []

        parsed_qs = parse_qs(query_string, keep_blank_values=True)
        candidates: List[ParameterCandidate] = []

        for key, values in parsed_qs.items():
            is_sensitive = key.lower() in SENSITIVE_PARAM_NAMES
            clean_values = ["[REDACTED]"] if is_sensitive else values

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
