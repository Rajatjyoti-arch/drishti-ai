"""Drishti Discovery & Endpoint Normalization Engine."""

from drishti.discovery.bundle_inspector import (
    BundleInspector,
    DiscoveredJsRoute,
    SourceLocation,
)
from drishti.discovery.change_detector import (
    ChangeDetector,
    is_object_id_related,
    is_pricing_related,
)
from drishti.discovery.endpoint_normalizer import (
    EndpointNormalizer,
    STATIC_KEYWORDS,
)
from drishti.discovery.har_parser import (
    HarParser,
    HarParsingError,
    compute_canonical_har_entry_digest,
    extract_json_body_schema,
)
from drishti.discovery.browser_context import BrowserContextManager
from drishti.discovery.crawler import JourneyCrawler
from drishti.discovery.crawler_models import (
    ActionType,
    BrowserObservation,
    CrawlSession,
    CrawlStatus,
    JourneyPlan,
    JourneyStep,
    RoleContext,
)
from drishti.discovery.har_capture import HarCaptureExporter
from drishti.discovery.network_bridge import NetworkBridge
from drishti.discovery.models import (
    AttackSurfaceChangeSet,
    CaptureCompleteness,
    ChangeType,
    ConfidenceAssessment,
    EndpointChange,
    EndpointObservation,
    InventorySnapshot,
    NormalizedEndpoint,
    ParameterCandidate,
    ParameterClassification,
    ParameterLocation,
    ProvenanceSource,
    SemanticType,
)

__all__ = [
    "NormalizedEndpoint",
    "EndpointObservation",
    "EndpointNormalizer",
    "HarParser",
    "HarParsingError",
    "compute_canonical_har_entry_digest",
    "extract_json_body_schema",
    "STATIC_KEYWORDS",
    "BundleInspector",
    "DiscoveredJsRoute",
    "SourceLocation",
    "ChangeDetector",
    "ChangeType",
    "CaptureCompleteness",
    "InventorySnapshot",
    "EndpointChange",
    "AttackSurfaceChangeSet",
    "is_pricing_related",
    "is_object_id_related",
    "ParameterCandidate",
    "ParameterLocation",
    "ParameterClassification",
    "SemanticType",
    "ProvenanceSource",
    "ConfidenceAssessment",
    "RoleContext",
    "CrawlSession",
    "CrawlStatus",
    "JourneyStep",
    "JourneyPlan",
    "BrowserObservation",
    "ActionType",
    "NetworkBridge",
    "BrowserContextManager",
    "HarCaptureExporter",
    "JourneyCrawler",
]
