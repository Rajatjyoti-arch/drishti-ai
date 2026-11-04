"""Static JavaScript/TypeScript Frontend Bundle Route Inspector.

Analyzes frontend JavaScript, TypeScript, and minified bundles statically without code execution,
extracting API endpoints, fetch/Axios invocations, template literals, base URLs, request body
parameters, and Source Map v3 VLQ-remapped source locations with secret redaction.
"""

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from drishti.discovery.models import (
    ConfidenceAssessment,
    NormalizedEndpoint,
    ParameterCandidate,
    ParameterClassification,
    ParameterLocation,
    ProvenanceSource,
    SemanticType,
)

# Maximum permitted JS bundle size for static analysis (10 Megabytes)
MAX_JS_BUNDLE_SIZE_BYTES: int = 10 * 1024 * 1024

# Maximum permitted Source Map size (20 Megabytes)
MAX_SOURCE_MAP_SIZE_BYTES: int = 20 * 1024 * 1024

# Maximum number of routes extracted per bundle to prevent algorithmic runaway
MAX_DISCOVERED_ROUTES: int = 2000

# Regex patterns for detecting base URL declarations
RE_BASE_URL_CONST = re.compile(
    r"(?:const|let|var)\s+([A-Za-z0-9_]+)\s*=\s*['\"]((?:https?://[^'\"]+|/[^'\"]+))['\"]",
)
RE_AXIOS_BASE_URL = re.compile(
    r"axios\.create\s*\(\s*\{[^}]*baseURL\s*:\s*['\"]([^'\"]+)['\"]",
)

# Regex pattern for fetch calls: fetch(url ...
RE_FETCH_START = re.compile(
    r"\bfetch\s*\(\s*(`[^`]+`|'[^']+'|\"[^\"]+\")",
)

# Regex pattern for Axios method calls
RE_AXIOS_METHOD_START = re.compile(
    r"\baxios\.(get|delete|head|options)\s*\(\s*(`[^`]+`|'[^']+'|\"[^\"]+\")",
    re.IGNORECASE,
)
RE_AXIOS_MUTATE_START = re.compile(
    r"\baxios\.(post|put|patch)\s*\(\s*(`[^`]+`|'[^']+'|\"[^\"]+\")",
    re.IGNORECASE,
)
RE_AXIOS_CONFIG_START = re.compile(
    r"\baxios\s*\(\s*\{",
    re.IGNORECASE,
)

# Secret scrubbing patterns for source snippets
RE_SECRET_LITERAL = re.compile(
    r"""(?i)(['"`])(?:bearer\s+[A-Za-z0-9_\-\.]+|ey[A-Za-z0-9_\-\.]+\.[A-Za-z0-9_\-\.]+|[A-Fa-f0-9]{32,64}|(?:ghp|glpat|sk|pk)_[A-Za-z0-9_]{16,}|password\s*[:=]\s*[^'"`]+|secret\s*[:=]\s*[^'"`]+)(['"`])""",
)
RE_EMBEDDED_URL_CREDS = re.compile(r"://[^:]+:[^@]+@")

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
BASE64_MAP = {c: i for i, c in enumerate(BASE64_CHARS)}


def decode_vlq_values(segment_str: str) -> List[int]:
    """Decodes a Base64 VLQ string into a list of relative integers."""
    values = []
    shift = 0
    value = 0
    for char in segment_str:
        if char not in BASE64_MAP:
            continue
        integer = BASE64_MAP[char]
        has_continuation = (integer & 32) != 0
        digit = integer & 31
        value += digit << shift
        shift += 5
        if not has_continuation:
            is_negative = (value & 1) == 1
            decoded = -(value >> 1) if is_negative else (value >> 1)
            values.append(decoded)
            value = 0
            shift = 0
    return values


class SourceMapResolver:
    """Decodes Source Map v3 VLQ mappings to accurately resolve generated coordinates to original source files."""

    def __init__(self, source_map_data: Dict[str, Any]):
        self.sources: List[str] = [str(s) for s in source_map_data.get("sources", [])]
        self.sources_content: List[str] = [str(c) for c in source_map_data.get("sourcesContent", [])]
        self.mappings_raw: str = str(source_map_data.get("mappings", ""))
        self._parsed_mappings: Optional[Dict[int, List[Tuple[int, int, int, int]]]] = None

    def _ensure_parsed(self):
        if self._parsed_mappings is not None:
            return
        self._parsed_mappings = {}
        if not self.mappings_raw:
            return

        lines = self.mappings_raw.split(";")
        source_idx = 0
        orig_line = 0
        orig_col = 0

        for gen_line_idx, line_str in enumerate(lines):
            if not line_str:
                continue
            gen_col = 0
            segments = line_str.split(",")
            line_mappings = []

            for seg in segments:
                if not seg:
                    continue
                vals = decode_vlq_values(seg)
                if len(vals) >= 1:
                    gen_col += vals[0]
                if len(vals) >= 4:
                    source_idx += vals[1]
                    orig_line += vals[2]
                    orig_col += vals[3]
                    line_mappings.append((gen_col, source_idx, orig_line, orig_col))

            if line_mappings:
                line_mappings.sort(key=lambda m: m[0])
                self._parsed_mappings[gen_line_idx] = line_mappings

    def resolve(self, gen_line: int, gen_col: int) -> Optional[Tuple[str, int, int]]:
        """Resolves 1-based generated (line, col) to (original_file, original_line, original_col).
        Returns None if no mapping exists for the generated position.
        """
        self._ensure_parsed()
        if not self._parsed_mappings:
            return None

        gen_line_0 = gen_line - 1
        line_mappings = self._parsed_mappings.get(gen_line_0)
        if not line_mappings:
            return None

        gen_col_0 = gen_col - 1
        best = None
        for m in line_mappings:
            if m[0] <= gen_col_0:
                best = m
            else:
                break

        if best is None:
            return None

        _, s_idx, o_line, o_col = best
        if 0 <= s_idx < len(self.sources):
            orig_file = self.sources[s_idx]
            return (orig_file, o_line + 1, o_col + 1)
        return None


def sanitize_source_snippet(snippet: str, max_length: int = 120) -> str:
    """Redacts embedded credentials, secret literals, and truncates snippet length."""
    if not snippet:
        return ""
    cleaned = RE_EMBEDDED_URL_CREDS.sub("://[REDACTED]@", snippet)
    cleaned = RE_SECRET_LITERAL.sub(r"\1[REDACTED_SECRET]\2", cleaned)
    cleaned = re.sub(
        r"(token|jwt|secret|apikey|key)=([^&\s'\"]+)",
        r"\1=[REDACTED]",
        cleaned,
        flags=re.IGNORECASE,
    )
    if len(cleaned) > max_length:
        cleaned = cleaned[: max_length - 3] + "..."
    return cleaned


def camel_to_snake(name: str) -> str:
    """Converts camelCase identifier to snake_case."""
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def infer_semantic_type_from_name(param_name: str) -> SemanticType:
    """Classifies semantic type from variable name naming conventions."""
    name_lower = param_name.lower()
    if any(k in name_lower for k in ("booking", "pnr", "resid", "bookingid")):
        return SemanticType.BOOKING_ID
    if any(k in name_lower for k in ("hold", "holdid")):
        return SemanticType.HOLD_ID
    if any(k in name_lower for k in ("quote", "quoteid")):
        return SemanticType.QUOTE_ID
    if any(k in name_lower for k in ("flight", "flightid", "flightno")):
        return SemanticType.FLIGHT_ID
    if any(k in name_lower for k in ("tenant", "agency", "supplier")):
        return SemanticType.TENANT_ID
    if any(k in name_lower for k in ("user", "customer", "passenger")):
        return SemanticType.USER_ID
    if any(k in name_lower for k in ("amount", "fare", "price", "tariff")):
        return SemanticType.CURRENCY
    if any(k in name_lower for k in ("currency", "curr")):
        return SemanticType.CURRENCY
    if any(k in name_lower for k in ("uuid", "guid")):
        return SemanticType.UUID
    if any(k in name_lower for k in ("date", "departure", "arrival")):
        return SemanticType.DATE
    if name_lower.endswith("_id") or name_lower.endswith("id"):
        return SemanticType.NUMERIC_ID
    return SemanticType.GENERIC


def extract_balanced_block(s: str, start_index: int, open_char: str = "{", close_char: str = "}") -> Optional[str]:
    """Extracts a balanced delimited block starting at or after start_index."""
    pos = s.find(open_char, start_index)
    if pos == -1:
        return None
    depth = 0
    in_quote = None
    for i in range(pos, len(s)):
        ch = s[i]
        if in_quote:
            if ch == in_quote and (i == 0 or s[i - 1] != "\\"):
                in_quote = None
        elif ch in ("'", '"', '`'):
            in_quote = ch
        elif ch == open_char:
            depth += 1
        elif ch == close_char:
            depth -= 1
            if depth == 0:
                return s[pos:i + 1]
    return None


class SourceLocation:
    """Pinpoints source code location in a JavaScript/TypeScript file."""

    def __init__(self, file_path: str, line: int, column: int, snippet: str):
        self.file_path = file_path
        self.line = line
        self.column = column
        self.snippet = snippet

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
        }


class DiscoveredJsRoute:
    """An API route extracted statically from JavaScript/TypeScript source code."""

    def __init__(
        self,
        method: str,
        route_template: str,
        raw_expression: str,
        parameters: List[ParameterCandidate],
        body_parameters: List[str],
        location: SourceLocation,
        is_dynamic: bool,
        base_url_variable: Optional[str] = None,
        confidence_score: float = 0.85,
        signals: Optional[List[str]] = None,
    ):
        self.method = method.upper()
        self.route_template = route_template
        self.raw_expression = raw_expression
        self.parameters = parameters
        self.body_parameters = body_parameters
        self.location = location
        self.is_dynamic = is_dynamic
        self.base_url_variable = base_url_variable
        self.confidence_score = confidence_score
        self.signals = signals or []

    @property
    def endpoint_key(self) -> str:
        return f"{self.method}:{self.route_template}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "route_template": self.route_template,
            "raw_expression": self.raw_expression,
            "parameters": [p.model_dump() for p in self.parameters],
            "body_parameters": self.body_parameters,
            "location": self.location.to_dict(),
            "is_dynamic": self.is_dynamic,
            "base_url_variable": self.base_url_variable,
            "confidence_score": self.confidence_score,
            "signals": self.signals,
        }


class BundleInspector:
    """Static source and lexical inspector for JavaScript/TypeScript application bundles."""

    def __init__(
        self,
        max_bundle_size_bytes: int = MAX_JS_BUNDLE_SIZE_BYTES,
        max_source_map_size_bytes: int = MAX_SOURCE_MAP_SIZE_BYTES,
        default_asset_id: str = "frontend-bundle",
    ):
        self.max_bundle_size_bytes = max_bundle_size_bytes
        self.max_source_map_size_bytes = max_source_map_size_bytes
        self.default_asset_id = default_asset_id

    def inspect_file(
        self,
        file_path: Union[str, Path],
        source_map_path: Optional[Union[str, Path]] = None,
    ) -> List[DiscoveredJsRoute]:
        """Reads a JS/TS file from disk (with size bound checks) and statically extracts routes."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Target JS file not found: {path}")

        file_size = path.stat().st_size
        if file_size > self.max_bundle_size_bytes:
            raise ValueError(
                f"Bundle file ({file_size} bytes) exceeds limit ({self.max_bundle_size_bytes} bytes)"
            )

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            code = f.read(self.max_bundle_size_bytes + 1)

        source_map_data = None
        if source_map_path and os.path.exists(str(source_map_path)):
            sm_path = Path(source_map_path)
            if sm_path.stat().st_size <= self.max_source_map_size_bytes:
                with open(sm_path, "r", encoding="utf-8", errors="replace") as f:
                    try:
                        source_map_data = json.load(f)
                    except json.JSONDecodeError:
                        source_map_data = None

        return self.inspect_code(code, file_path=str(path), source_map=source_map_data)

    def inspect_code(
        self,
        code: str,
        file_path: str = "inline.js",
        source_map: Optional[Dict[str, Any]] = None,
    ) -> List[DiscoveredJsRoute]:
        """Statically inspects JavaScript code string without executing it."""
        base_urls = self._extract_base_urls(code)
        routes: List[DiscoveredJsRoute] = []
        seen_keys: Set[str] = set()

        # 1. Extract Fetch Calls
        for match in RE_FETCH_START.finditer(code):
            raw_url_expr = match.group(1).strip()
            end_match = match.end()

            options_block = ""
            comma_idx = code.find(",", end_match)
            paren_idx = code.find(")", end_match)
            if comma_idx != -1 and (paren_idx == -1 or comma_idx < paren_idx):
                opt = extract_balanced_block(code, comma_idx, "{", "}")
                if opt:
                    options_block = opt

            loc = self._compute_location(code, match.start(), file_path, source_map)
            method = self._extract_method_from_options(options_block, default="GET")
            body_params = self._extract_body_params_from_options(options_block)

            route = self._build_discovered_route(
                raw_url_expr,
                method,
                body_params,
                loc,
                base_urls,
                signals=["static_fetch_call"],
            )
            if route and route.endpoint_key not in seen_keys:
                seen_keys.add(route.endpoint_key)
                routes.append(route)
                if len(routes) >= MAX_DISCOVERED_ROUTES:
                    break

        # 2. Extract Axios GET/DELETE/etc.
        for match in RE_AXIOS_METHOD_START.finditer(code):
            method = match.group(1).upper()
            raw_url_expr = match.group(2).strip()

            loc = self._compute_location(code, match.start(), file_path, source_map)
            route = self._build_discovered_route(
                raw_url_expr,
                method,
                [],
                loc,
                base_urls,
                signals=["static_axios_call"],
            )
            if route and route.endpoint_key not in seen_keys:
                seen_keys.add(route.endpoint_key)
                routes.append(route)
                if len(routes) >= MAX_DISCOVERED_ROUTES:
                    break

        # 3. Extract Axios POST/PUT/PATCH with request body object
        for match in RE_AXIOS_MUTATE_START.finditer(code):
            method = match.group(1).upper()
            raw_url_expr = match.group(2).strip()
            end_match = match.end()

            body_params = []
            comma_idx = code.find(",", end_match)
            paren_idx = code.find(")", end_match)
            if comma_idx != -1 and (paren_idx == -1 or comma_idx < paren_idx):
                data_block = extract_balanced_block(code, comma_idx, "{", "}")
                if data_block:
                    body_params = self._extract_body_keys(data_block)

            loc = self._compute_location(code, match.start(), file_path, source_map)
            route = self._build_discovered_route(
                raw_url_expr,
                method,
                body_params,
                loc,
                base_urls,
                signals=["static_axios_mutate"],
            )
            if route and route.endpoint_key not in seen_keys:
                seen_keys.add(route.endpoint_key)
                routes.append(route)
                if len(routes) >= MAX_DISCOVERED_ROUTES:
                    break

        # 4. Extract Axios Config Objects: axios({ url: '...', method: 'POST' })
        for match in RE_AXIOS_CONFIG_START.finditer(code):
            block = extract_balanced_block(code, match.start(), "{", "}")
            if not block:
                continue

            url_m = re.search(r"url\s*:\s*(`[^`]+`|'[^']+'|\"[^\"]+\")", block)
            method_m = re.search(r"method\s*:\s*['\"]([A-Za-z]+)['\"]", block)
            if url_m:
                raw_url_expr = url_m.group(1).strip()
                method = method_m.group(1).upper() if method_m else "GET"

                body_params = []
                data_m = re.search(r"data\s*:\s*(\{[\s\S]*?\})", block)
                if data_m:
                    body_params = self._extract_body_keys(data_m.group(1))

                loc = self._compute_location(code, match.start(), file_path, source_map)
                route = self._build_discovered_route(
                    raw_url_expr,
                    method,
                    body_params,
                    loc,
                    base_urls,
                    signals=["static_axios_config"],
                )
                if route and route.endpoint_key not in seen_keys:
                    seen_keys.add(route.endpoint_key)
                    routes.append(route)
                    if len(routes) >= MAX_DISCOVERED_ROUTES:
                        break

        return routes

    def convert_to_normalized_endpoints(
        self,
        routes: List[DiscoveredJsRoute],
        asset_id: Optional[str] = None,
        canonical_origin: str = "",
    ) -> List[NormalizedEndpoint]:
        """Converts discovered JS routes into canonical NormalizedEndpoint records."""
        effective_asset_id = asset_id or self.default_asset_id
        endpoints: List[NormalizedEndpoint] = []

        for idx, r in enumerate(routes):
            digest_src = f"{r.method}:{r.route_template}:{r.location.file_path}:{r.location.line}"
            digest = hashlib.sha256(digest_src.encode("utf-8")).hexdigest()

            provenance = [
                ProvenanceSource(
                    source="JS_BUNDLE",
                    observation_id=f"JS-{idx + 1:04d}",
                    canonical_digest=digest,
                )
            ]

            endpoints.append(
                NormalizedEndpoint(
                    method=r.method,
                    route_template=r.route_template,
                    asset_id=effective_asset_id,
                    canonical_origin=canonical_origin,
                    parameters=r.parameters,
                    provenance=provenance,
                    confidence=ConfidenceAssessment(
                        score=r.confidence_score,
                        signals=r.signals,
                    ),
                    roles_observed=[],
                )
            )

        return endpoints

    def _extract_base_urls(self, code: str) -> Dict[str, str]:
        """Discovers declared API base URLs and Axios baseURLs."""
        base_urls: Dict[str, str] = {}
        for match in RE_BASE_URL_CONST.finditer(code):
            var_name = match.group(1)
            val = match.group(2)
            if any(term in var_name.lower() for term in ("api", "url", "base", "endpoint", "host")):
                base_urls[var_name] = val.rstrip("/")

        for match in RE_AXIOS_BASE_URL.finditer(code):
            val = match.group(1).rstrip("/")
            base_urls["default_axios_base"] = val

        return base_urls

    def _build_discovered_route(
        self,
        raw_url_expr: str,
        method: str,
        body_params: List[str],
        location: SourceLocation,
        base_urls: Dict[str, str],
        signals: List[str],
    ) -> Optional[DiscoveredJsRoute]:
        """Normalizes a raw JS URL expression (string literal or template literal)."""
        clean_expr = raw_url_expr.strip("'\"`")
        is_template = raw_url_expr.startswith("`") and raw_url_expr.endswith("`")

        if not (clean_expr.startswith("/") or clean_expr.startswith("http") or is_template):
            return None

        base_var: Optional[str] = None
        for var_name, base_val in base_urls.items():
            if f"${{{var_name}}}" in raw_url_expr:
                clean_expr = clean_expr.replace(f"${{{var_name}}}", base_val)
                base_var = var_name
                signals.append(f"resolved_base_url:{var_name}")

        parameters: List[ParameterCandidate] = []
        is_dynamic = False

        if "${" in clean_expr:
            is_dynamic = True
            signals.append("template_literal")

            def replace_slot(m: re.Match) -> str:
                var_content = m.group(1).strip()
                tail_id = var_content.split(".")[-1].split("[")[0].strip()
                param_name = camel_to_snake(tail_id)
                sem_type = infer_semantic_type_from_name(param_name)

                parameters.append(
                    ParameterCandidate(
                        name=param_name,
                        location=ParameterLocation.PATH.value,
                        semantic_type=sem_type.value,
                        classification=ParameterClassification.INFERRED.value,
                        observed_values=[f"${{{var_content}}}"],
                    )
                )
                return f"{{{param_name}}}"

            route_template = re.sub(r"\$\{([^}]+)\}", replace_slot, clean_expr)
        else:
            route_template = clean_expr

        if route_template.startswith("http"):
            from urllib.parse import urlparse
            parsed = urlparse(route_template)
            route_template = parsed.path or "/"

        if not route_template.startswith("/"):
            route_template = "/" + route_template

        for b_param in body_params:
            p_name = camel_to_snake(b_param)
            sem_type = infer_semantic_type_from_name(p_name)
            parameters.append(
                ParameterCandidate(
                    name=p_name,
                    location=ParameterLocation.BODY.value,
                    semantic_type=sem_type.value,
                    classification=ParameterClassification.INFERRED.value,
                    observed_values=[],
                )
            )

        confidence = 0.85
        if is_dynamic:
            confidence = 0.88
        if body_params:
            confidence = 0.90
            signals.append("extracted_body_schema")

        sanitized_raw = sanitize_source_snippet(raw_url_expr, max_length=120)

        return DiscoveredJsRoute(
            method=method,
            route_template=route_template,
            raw_expression=sanitized_raw,
            parameters=parameters,
            body_parameters=body_params,
            location=location,
            is_dynamic=is_dynamic,
            base_url_variable=base_var,
            confidence_score=confidence,
            signals=signals,
        )

    def _extract_method_from_options(self, options_block: str, default: str = "GET") -> str:
        """Extracts method: 'POST' from fetch options object."""
        if not options_block:
            return default
        m = re.search(r"method\s*:\s*['\"]([A-Za-z]+)['\"]", options_block, re.IGNORECASE)
        if m:
            return m.group(1).upper()
        return default

    def _extract_body_params_from_options(self, options_block: str) -> List[str]:
        """Extracts JSON keys from body: JSON.stringify({ ... })."""
        if not options_block or "body" not in options_block:
            return []
        m = re.search(r"body\s*:\s*(?:JSON\.stringify\s*\(\s*)?(\{[\s\S]*?\})", options_block)
        if m:
            return self._extract_body_keys(m.group(1))
        return []

    def _extract_body_keys(self, data_block: str) -> List[str]:
        """Extracts property key names from a JS object literal block."""
        if not data_block or "{" not in data_block:
            return []
        inner = data_block[data_block.find("{") + 1: data_block.rfind("}")]
        keys: List[str] = []

        parts = []
        current = []
        depth = 0
        in_quote = None
        for ch in inner:
            if in_quote:
                if ch == in_quote:
                    in_quote = None
                current.append(ch)
            elif ch in ("'", '"', '`'):
                in_quote = ch
                current.append(ch)
            elif ch in ("{", "[", "("):
                depth += 1
                current.append(ch)
            elif ch in ("}", "]", ")"):
                depth -= 1
                current.append(ch)
            elif ch == "," and depth == 0:
                parts.append("".join(current).strip())
                current = []
            else:
                current.append(ch)
        if current:
            parts.append("".join(current).strip())

        for part in parts:
            part = part.strip()
            if not part or part.startswith("//"):
                continue
            if ":" in part:
                key_part = part.split(":")[0].strip()
                key = key_part.strip("'\"`")
                if re.match(r"^[A-Za-z0-9_]+$", key) and key not in keys:
                    keys.append(key)
            else:
                key = part.split()[0].strip().strip("'\"`")
                if (
                    re.match(r"^[A-Za-z0-9_]+$", key)
                    and key not in ("const", "let", "var", "function", "return")
                    and key not in keys
                ):
                    keys.append(key)

        return keys

    def _compute_location(
        self,
        code: str,
        char_index: int,
        file_path: str,
        source_map: Optional[Dict[str, Any]],
    ) -> SourceLocation:
        """Computes line number, column number, and snippet from character offset,

        remapping via Source Map v3 VLQ decoder if available.
        """
        line = 1 + code[:char_index].count("\n")
        line_start = code.rfind("\n", 0, char_index)
        col = (char_index - line_start) if line_start != -1 else char_index + 1

        line_end = code.find("\n", char_index)
        if line_end == -1:
            snippet = code[max(0, line_start + 1):].strip()
        else:
            snippet = code[max(0, line_start + 1):line_end].strip()

        orig_file = file_path
        orig_line = line
        orig_col = col

        if source_map:
            resolver = SourceMapResolver(source_map)
            resolved = resolver.resolve(line, col)
            if resolved:
                orig_file, orig_line, orig_col = resolved

        clean_snippet = sanitize_source_snippet(snippet, max_length=120)

        return SourceLocation(
            file_path=orig_file,
            line=orig_line,
            column=orig_col,
            snippet=clean_snippet,
        )
