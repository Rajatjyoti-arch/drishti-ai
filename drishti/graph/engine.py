"""Living Travel Security Intelligence Graph Engine for Drishti AI.

Implements an evidence-backed NetworkX MultiDiGraph capturing multi-tenant B2B
topologies, namespaced microservice endpoints, independent entity lifecycles,
invariant bindings, and hypothesis-driven attack path extraction.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import networkx as nx

from drishti.core.models import AttackHypothesis, InvariantType
from drishti.discovery.crawler_models import BrowserObservation
from drishti.discovery.models import (
    CaptureCompleteness,
    EndpointObservation,
    InventorySnapshot,
    NormalizedEndpoint,
    ParameterCandidate,
)
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
    JourneyNode,
    NodeType,
    ObservationNode,
    ParameterNode,
    PrincipalNode,
    RoleNode,
    TenantNode,
    WorkflowStateNode,
)
from drishti.graph.state_machine import (
    TRANSITION_RULES,
    BookingState,
    HoldState,
    IdempotencyRecord,
    PaymentState,
    QuoteState,
    RefundState,
    TransitionOutcome,
    TransitionRule,
    validate_payment_idempotency,
    validate_refund_bounds,
    validate_transition,
)

logger = logging.getLogger(__name__)

# Financial and Identifier semantic keyword sets for parameter classification
FINANCIAL_KEYWORDS = {"amount", "price", "fare", "currency", "markup", "discount", "tariff", "total"}
IDENTIFIER_KEYWORDS = {"booking_id", "booking_identifier", "hold_id", "hold_identifier", "tenant_id", "tenant_identifier", "pnr", "user_id"}


class TravelSecurityGraph:
    """Living multi-tenant B2B Travel Security Intelligence Graph."""

    def __init__(self):
        self._graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self._initialize_built_in_invariants()
        self._initialize_lifecycle_rules()

    @property
    def graph(self) -> nx.MultiDiGraph:
        """Returns the underlying NetworkX MultiDiGraph."""
        return self._graph

    # =========================================================================
    # Initialization & Ground Truth Setup
    # =========================================================================

    def _initialize_built_in_invariants(self) -> None:
        """Seeds standard travel security invariants into the graph."""
        invariants = [
            InvariantNode(
                invariant_id=InvariantType.TENANT_ISOLATION.value,
                title="Cross-Tenant Multi-Tenant Isolation (BOLA / IDOR)",
                description="An identity belonging to Agency B must not view or mutate objects owned by Agency A.",
                category=InvariantCategory.BOLA,
                sub_rules=["CROSS_TENANT_READ_DISALLOWED", "CROSS_TENANT_MUTATION_DISALLOWED"],
            ),
            InvariantNode(
                invariant_id=InvariantType.PRICING_INTEGRITY.value,
                title="Server-Authoritative Pricing Integrity",
                description="Client-submitted tariffs, markups, or currencies cannot override server-authoritative quotes.",
                category=InvariantCategory.PRICING_INTEGRITY,
                sub_rules=["CLIENT_PRICE_OVERRIDE_DISALLOWED", "CURRENCY_MANIPULATION_DISALLOWED"],
            ),
            InvariantNode(
                invariant_id=InvariantType.HOLD_EXPIRATION.value,
                title="Perishable Reservation Hold Expiration",
                description="An expired or cancelled hold cannot be converted into a confirmed booking.",
                category=InvariantCategory.HOLD_LIFECYCLE,
                sub_rules=["EXPIRED_HOLD_CONFIRMATION_DISALLOWED", "CANCELLED_HOLD_CONFIRMATION_DISALLOWED"],
            ),
            InvariantNode(
                invariant_id=InvariantType.REFUND_IDEMPOTENCY.value,
                title="Payment/Refund Idempotency and Cumulative Refund Bounds",
                description="Repeated operations must be idempotent and cumulative refunds must not exceed captured amounts.",
                category=InvariantCategory.REFUND_BOUNDS,
                sub_rules=[
                    "I-04-A-PAYMENT-IDEMPOTENCY",
                    "I-04-B-REFUND-IDEMPOTENCY",
                    "I-04-C-REFUND-BOUNDS-CAP",
                ],
            ),
        ]
        for inv in invariants:
            self.add_invariant(inv)

    def _initialize_lifecycle_rules(self) -> None:
        """Seeds declared state machine lifecycle nodes and ALLOWED transition edges."""
        states = [
            ("Quote", QuoteState.ISSUED.value),
            ("Quote", QuoteState.ACCEPTED.value),
            ("Quote", QuoteState.EXPIRED.value),
            ("Quote", QuoteState.SUPERSEDED.value),
            ("Hold", HoldState.ACTIVE.value),
            ("Hold", HoldState.CONFIRMED.value),
            ("Hold", HoldState.EXPIRED.value),
            ("Hold", HoldState.CANCELLED.value),
            ("Booking", BookingState.PENDING.value),
            ("Booking", BookingState.CONFIRMED.value),
            ("Booking", BookingState.CANCELLED.value),
            ("Payment", PaymentState.INITIATED.value),
            ("Payment", PaymentState.AUTHORIZED.value),
            ("Payment", PaymentState.CAPTURED.value),
            ("Payment", PaymentState.FAILED.value),
            ("Refund", RefundState.REQUESTED.value),
            ("Refund", RefundState.PROCESSING.value),
            ("Refund", RefundState.SUCCEEDED.value),
            ("Refund", RefundState.FAILED.value),
        ]
        for obj_type, state_name in states:
            self.add_workflow_state(WorkflowStateNode(object_type=obj_type, state_name=state_name))

        for rule in TRANSITION_RULES:
            from_node = f"state:{rule.object_type}:{rule.from_state}"
            to_node = f"state:{rule.object_type}:{rule.to_state}"

            if rule.outcome == TransitionOutcome.ALLOWED:
                self.add_edge(
                    GraphEdge(
                        source_id=from_node,
                        target_id=to_node,
                        edge_type=EdgeType.TRANSITION_ALLOWED,
                        classification=FactClassification.DECLARED,
                        metadata={"rationale": rule.rationale},
                    )
                )

            # Bind invariant to transition if rule defines one
            if rule.bound_invariant:
                inv_node = f"invariant:{rule.bound_invariant}"
                if self._graph.has_node(inv_node):
                    self.add_edge(
                        GraphEdge(
                            source_id=inv_node,
                            target_id=from_node,
                            edge_type=EdgeType.BINDS_INVARIANT,
                            classification=FactClassification.DECLARED,
                            metadata={"target_transition": f"{rule.from_state}->{rule.to_state}", "rationale": rule.rationale},
                        )
                    )

    # =========================================================================
    # Node Addition Methods
    # =========================================================================

    def add_tenant(self, tenant: TenantNode) -> str:
        """Adds a tenant node (Agency A, Agency B, Supplier)."""
        node_id = tenant.node_id
        self._graph.add_node(
            node_id,
            node_type=NodeType.TENANT.value,
            tenant_id=tenant.tenant_id,
            name=tenant.name,
            tenant_type=tenant.tenant_type,
            metadata=tenant.metadata,
        )
        return node_id

    def add_principal(self, principal: PrincipalNode) -> str:
        """Adds a tenant-namespaced principal user/agent and links to its Tenant."""
        node_id = principal.node_id
        self._graph.add_node(
            node_id,
            node_type=NodeType.PRINCIPAL.value,
            principal_id=principal.principal_id,
            tenant_id=principal.tenant_id,
            roles=principal.roles,
            metadata=principal.metadata,
        )
        tenant_node = f"tenant:{principal.tenant_id}"
        if not self._graph.has_node(tenant_node):
            self.add_tenant(TenantNode(tenant_id=principal.tenant_id, name=principal.tenant_id))
        self.add_edge(
            GraphEdge(
                source_id=node_id,
                target_id=tenant_node,
                edge_type=EdgeType.BELONGS_TO_TENANT,
                classification=FactClassification.DECLARED,
                tenant_context=principal.tenant_id,
            )
        )
        return node_id

    def add_role(self, role: RoleNode) -> str:
        """Adds a role node and optionally links to tenant."""
        node_id = role.node_id
        self._graph.add_node(
            node_id,
            node_type=NodeType.ROLE.value,
            role_name=role.role_name,
            tenant_id=role.tenant_id,
            description=role.description,
        )
        if role.tenant_id:
            tenant_node = f"tenant:{role.tenant_id}"
            if not self._graph.has_node(tenant_node):
                self.add_tenant(TenantNode(tenant_id=role.tenant_id, name=role.tenant_id))
            self.add_edge(
                GraphEdge(
                    source_id=node_id,
                    target_id=tenant_node,
                    edge_type=EdgeType.BELONGS_TO_TENANT,
                    classification=FactClassification.DECLARED,
                    tenant_context=role.tenant_id,
                )
            )
        return node_id

    def add_asset(self, asset: AssetNode) -> str:
        """Adds an asset (namespaced microservice or API origin)."""
        node_id = asset.node_id
        self._graph.add_node(
            node_id,
            node_type=NodeType.ASSET.value,
            asset_id=asset.asset_id,
            canonical_origin=asset.canonical_origin,
            description=asset.description,
        )
        return node_id

    def add_endpoint(self, endpoint: EndpointNode) -> str:
        """Adds a canonical API endpoint and links to Asset."""
        node_id = endpoint.node_id
        self._graph.add_node(
            node_id,
            node_type=NodeType.ENDPOINT.value,
            endpoint_identity=endpoint.endpoint_identity,
            method=endpoint.method,
            route_template=endpoint.route_template,
            asset_id=endpoint.asset_id,
            canonical_origin=endpoint.canonical_origin,
            auth_required=endpoint.auth_required,
            roles_observed=endpoint.roles_observed,
            confidence=endpoint.confidence,
        )
        # Link to asset
        asset_node = f"asset:{endpoint.asset_id}"
        if not self._graph.has_node(asset_node):
            self.add_asset(AssetNode(asset_id=endpoint.asset_id, canonical_origin=endpoint.canonical_origin))
        self.add_edge(
            GraphEdge(
                source_id=node_id,
                target_id=asset_node,
                edge_type=EdgeType.HOSTED_ON,
                classification=FactClassification.DECLARED,
            )
        )
        return node_id

    def add_parameter(self, param: ParameterNode) -> str:
        """Adds an endpoint parameter, preserving location, and links to Endpoint."""
        node_id = param.node_id
        self._graph.add_node(
            node_id,
            node_type=NodeType.PARAMETER.value,
            endpoint_identity=param.endpoint_identity,
            name=param.name,
            location=param.location,
            semantic_type=param.semantic_type,
            is_financial=param.is_financial,
            is_identifier=param.is_identifier,
        )
        ep_node = f"endpoint:{param.endpoint_identity}"
        if self._graph.has_node(ep_node):
            self.add_edge(
                GraphEdge(
                    source_id=ep_node,
                    target_id=node_id,
                    edge_type=EdgeType.HAS_PARAMETER,
                    classification=FactClassification.DECLARED,
                )
            )
        return node_id

    def add_business_object(self, obj: BusinessObjectNode) -> str:
        """Adds a tenant-namespaced business object and links ownership and endpoint consumers."""
        node_id = obj.node_id
        self._graph.add_node(
            node_id,
            node_type=NodeType.BUSINESS_OBJECT.value,
            object_type=obj.object_type,
            object_id=obj.object_id,
            owner_tenant_id=obj.owner_tenant_id,
            canary_fixture_id=obj.canary_fixture_id,
            metadata=obj.metadata,
        )
        # OWNS relationship: Tenant OWNS BusinessObject
        tenant_node = f"tenant:{obj.owner_tenant_id}"
        if not self._graph.has_node(tenant_node):
            self.add_tenant(TenantNode(tenant_id=obj.owner_tenant_id, name=obj.owner_tenant_id))
        self.add_edge(
            GraphEdge(
                source_id=tenant_node,
                target_id=node_id,
                edge_type=EdgeType.OWNS,
                classification=FactClassification.DECLARED,
                tenant_context=obj.owner_tenant_id,
            )
        )

        # Connect PRODUCES and CONSUMES relationships from endpoints in graph
        obj_type_lower = obj.object_type.lower()
        for ep_n, ep_data in list(self._graph.nodes(data=True)):
            if ep_data.get("node_type") == NodeType.ENDPOINT.value:
                route = ep_data.get("route_template", "").lower()
                method = ep_data.get("method", "").upper()
                if f"/{obj_type_lower}s" in route or f"/{obj_type_lower}" in route:
                    if method in ("GET", "PUT", "DELETE", "PATCH"):
                        self.add_edge(
                            GraphEdge(
                                source_id=ep_n,
                                target_id=node_id,
                                edge_type=EdgeType.CONSUMES,
                                classification=FactClassification.DECLARED,
                                tenant_context=obj.owner_tenant_id,
                            )
                        )
                    elif method == "POST":
                        self.add_edge(
                            GraphEdge(
                                source_id=ep_n,
                                target_id=node_id,
                                edge_type=EdgeType.PRODUCES,
                                classification=FactClassification.DECLARED,
                                tenant_context=obj.owner_tenant_id,
                            )
                        )
        return node_id

    def add_workflow_state(self, state: WorkflowStateNode) -> str:
        """Adds an object-specific workflow state node."""
        node_id = state.node_id
        self._graph.add_node(
            node_id,
            node_type=NodeType.WORKFLOW_STATE.value,
            object_type=state.object_type,
            state_name=state.state_name,
            description=state.description,
        )
        return node_id

    def add_observation(self, obs: ObservationNode) -> str:
        """Adds an evidentiary observation node."""
        node_id = obs.node_id
        self._graph.add_node(
            node_id,
            node_type=NodeType.OBSERVATION.value,
            observation_id=obs.observation_id,
            source_type=obs.source_type.value if isinstance(obs.source_type, EvidenceSourceType) else obs.source_type,
            timestamp=obs.timestamp,
            canonical_digest=obs.canonical_digest,
            confidence=obs.confidence,
            tenant_id=obs.tenant_id,
            role_id=obs.role_id,
            session_id=obs.session_id,
            details=obs.details,
        )
        return node_id

    def add_invariant(self, inv: InvariantNode) -> str:
        """Adds a security invariant rule node."""
        node_id = inv.node_id
        self._graph.add_node(
            node_id,
            node_type=NodeType.INVARIANT.value,
            invariant_id=inv.invariant_id,
            title=inv.title,
            description=inv.description,
            category=inv.category.value if isinstance(inv.category, InvariantCategory) else inv.category,
            sub_rules=inv.sub_rules,
        )
        return node_id

    def add_hypothesis(self, hypo: HypothesisNode) -> str:
        """Adds a generated attack hypothesis node and links supporting evidence."""
        node_id = hypo.node_id
        self._graph.add_node(
            node_id,
            node_type=NodeType.HYPOTHESIS.value,
            hypothesis_id=hypo.hypothesis_id,
            invariant_id=hypo.invariant_id,
            target_endpoint_identity=hypo.target_endpoint_identity,
            attacker_tenant_id=hypo.attacker_tenant_id,
            victim_tenant_id=hypo.victim_tenant_id,
            rationale=hypo.rationale,
            risk_level=hypo.risk_level,
            supporting_evidence_ids=hypo.supporting_evidence_ids,
        )
        # Link to target endpoint
        ep_node = f"endpoint:{hypo.target_endpoint_identity}"
        if self._graph.has_node(ep_node):
            self.add_edge(
                GraphEdge(
                    source_id=node_id,
                    target_id=ep_node,
                    edge_type=EdgeType.BINDS_INVARIANT,
                    classification=FactClassification.INFERRED,
                    metadata={"invariant_id": hypo.invariant_id},
                )
            )
        # Link to supporting observations
        for ev_id in hypo.supporting_evidence_ids:
            obs_node = f"obs:{ev_id}"
            if self._graph.has_node(obs_node):
                self.add_edge(
                    GraphEdge(
                        source_id=node_id,
                        target_id=obs_node,
                        edge_type=EdgeType.SUPPORTED_BY,
                        classification=FactClassification.INFERRED,
                    )
                )
        return node_id

    # =========================================================================
    # Edge Addition & Semantic Fact Helpers
    # =========================================================================

    def add_edge(self, edge: GraphEdge) -> str:
        """Inserts an edge into the MultiDiGraph with evidence and role/tenant context."""
        if not self._graph.has_node(edge.source_id):
            logger.debug(f"Source node {edge.source_id} does not exist; creating placeholder.")
            self._graph.add_node(edge.source_id, node_type="Unknown")
        if not self._graph.has_node(edge.target_id):
            logger.debug(f"Target node {edge.target_id} does not exist; creating placeholder.")
            self._graph.add_node(edge.target_id, node_type="Unknown")

        key = edge.edge_key
        self._graph.add_edge(
            edge.source_id,
            edge.target_id,
            key=key,
            edge_type=edge.edge_type.value if isinstance(edge.edge_type, EdgeType) else edge.edge_type,
            classification=edge.classification.value if isinstance(edge.classification, FactClassification) else edge.classification,
            confidence=edge.confidence,
            timestamp=edge.timestamp,
            evidence_refs=edge.evidence_refs,
            tenant_context=edge.tenant_context,
            role_context=edge.role_context,
            metadata=edge.metadata,
        )
        return key

    def record_observed_request(
        self,
        principal_or_role_id: str,
        endpoint_identity: str,
        evidence_id: str,
        tenant_context: Optional[str] = None,
        role_context: Optional[str] = None,
    ) -> str:
        """Records that a principal or role initiated a request against an endpoint.

        Creates an OBSERVED_REQUESTED_BY edge. Does NOT declare authorization.
        """
        source = f"role:{role_context}" if role_context else principal_or_role_id
        if not source.startswith(("role:", "principal:")):
            source = f"role:{source}"

        target = f"endpoint:{endpoint_identity}"
        edge = GraphEdge(
            source_id=target,
            target_id=source,
            edge_type=EdgeType.OBSERVED_REQUESTED_BY,
            classification=FactClassification.OBSERVED,
            evidence_refs=[evidence_id],
            tenant_context=tenant_context,
            role_context=role_context,
        )
        return self.add_edge(edge)

    def record_observed_response(
        self,
        endpoint_identity: str,
        recipient_id: str,
        status_code: int,
        evidence_id: str,
        tenant_context: Optional[str] = None,
        role_context: Optional[str] = None,
    ) -> str:
        """Records an endpoint returned an HTTP response to a principal/role.

        Creates an OBSERVED_RESPONSE_TO edge. Even a 200 OK does NOT mean authorized!
        """
        source = f"endpoint:{endpoint_identity}"
        target = recipient_id if recipient_id.startswith(("role:", "principal:")) else f"role:{recipient_id}"
        edge = GraphEdge(
            source_id=source,
            target_id=target,
            edge_type=EdgeType.OBSERVED_RESPONSE_TO,
            classification=FactClassification.OBSERVED,
            evidence_refs=[evidence_id],
            tenant_context=tenant_context,
            role_context=role_context,
            metadata={"status_code": status_code},
        )
        return self.add_edge(edge)

    def record_authorized_access(
        self,
        tenant_id: str,
        endpoint_identity: str,
        evidence_id: str,
        verifier_note: str = "",
    ) -> str:
        """Records that an independent security verifier confirmed authorization."""
        source = f"tenant:{tenant_id}"
        target = f"endpoint:{endpoint_identity}"
        edge = GraphEdge(
            source_id=source,
            target_id=target,
            edge_type=EdgeType.AUTHORIZED_ACCESS_CONFIRMED,
            classification=FactClassification.CONFIRMED,
            evidence_refs=[evidence_id],
            tenant_context=tenant_id,
            metadata={"verifier_note": verifier_note},
        )
        return self.add_edge(edge)

    def record_observed_transition(
        self,
        object_type: str,
        from_state: str,
        to_state: str,
        evidence_id: str,
        tenant_context: Optional[str] = None,
    ) -> str:
        """Records runtime evidence showing a business object transitioned states.

        Evaluates declared rules: flags POTENTIAL_INVARIANT_VIOLATION if transition was prohibited.
        """
        outcome, rationale, bound_invariant = validate_transition(object_type, from_state, to_state)
        is_violation = (outcome == TransitionOutcome.DENIED)
        assessment = "POTENTIAL_INVARIANT_VIOLATION" if is_violation else (
            "CONSISTENT" if outcome == TransitionOutcome.ALLOWED else "UNDECLARED"
        )

        source = f"state:{object_type}:{from_state}"
        target = f"state:{object_type}:{to_state}"
        edge = GraphEdge(
            source_id=source,
            target_id=target,
            edge_type=EdgeType.TRANSITION_OBSERVED,
            classification=FactClassification.OBSERVED,
            evidence_refs=[evidence_id],
            tenant_context=tenant_context,
            metadata={
                "declared_outcome": outcome.value,
                "assessment": assessment,
                "potential_invariant_violation": is_violation,
                "bound_invariant": bound_invariant,
                "rationale": rationale,
            },
        )
        return self.add_edge(edge)

    # =========================================================================
    # Ingestion Methods (Discovery Artifacts)
    # =========================================================================

    def ingest_normalized_endpoints(self, endpoints: List[NormalizedEndpoint]) -> None:
        """Ingests normalized endpoints, preserving parameter locations and connecting objects."""
        for nep in endpoints:
            ep_node = EndpointNode(
                endpoint_identity=nep.endpoint_identity,
                method=nep.method,
                route_template=nep.route_template,
                asset_id=nep.asset_id,
                canonical_origin=nep.canonical_origin,
                roles_observed=nep.roles_observed,
                confidence=nep.confidence.score,
            )
            self.add_endpoint(ep_node)

            # Ingest path and body parameters preserving actual location!
            for p in nep.parameters:
                p_name_lower = p.name.lower()
                is_fin = any(k in p_name_lower for k in FINANCIAL_KEYWORDS)
                is_id = any(k in p_name_lower for k in IDENTIFIER_KEYWORDS)
                loc = p.location if getattr(p, "location", None) else "path"
                self.add_parameter(
                    ParameterNode(
                        endpoint_identity=nep.endpoint_identity,
                        name=p.name,
                        location=loc,
                        semantic_type=p.semantic_type,
                        is_financial=is_fin,
                        is_identifier=is_id,
                    )
                )

            # Ingest query parameters preserving actual location!
            for q in nep.query_parameters:
                q_name_lower = q.name.lower()
                is_fin = any(k in q_name_lower for k in FINANCIAL_KEYWORDS)
                is_id = any(k in q_name_lower for k in IDENTIFIER_KEYWORDS)
                loc = q.location if getattr(q, "location", None) else "query"
                self.add_parameter(
                    ParameterNode(
                        endpoint_identity=nep.endpoint_identity,
                        name=q.name,
                        location=loc,
                        semantic_type=q.semantic_type,
                        is_financial=is_fin,
                        is_identifier=is_id,
                    )
                )

            # Ingest provenance sources as ObservationNodes
            for prov in nep.provenance:
                obs_node = ObservationNode(
                    observation_id=prov.observation_id,
                    source_type=EvidenceSourceType.HAR if prov.source == "HAR" else EvidenceSourceType.BUNDLE_AST,
                    timestamp=prov.timestamp,
                    canonical_digest=prov.canonical_digest,
                )
                self.add_observation(obs_node)
                self.add_edge(
                    GraphEdge(
                        source_id=f"endpoint:{nep.endpoint_identity}",
                        target_id=f"obs:{prov.observation_id}",
                        edge_type=EdgeType.SUPPORTED_BY,
                        classification=FactClassification.OBSERVED,
                    )
                )

            # Link observed roles
            for role_name in nep.roles_observed:
                role_node_id = f"role:{role_name}"
                if not self._graph.has_node(role_node_id):
                    self.add_role(RoleNode(role_name=role_name))
                self.add_edge(
                    GraphEdge(
                        source_id=f"endpoint:{nep.endpoint_identity}",
                        target_id=role_node_id,
                        edge_type=EdgeType.OBSERVED_REQUESTED_BY,
                        classification=FactClassification.OBSERVED,
                    )
                )

            # Connect PRODUCES and CONSUMES relationships to existing business objects
            for n_id, n_data in list(self._graph.nodes(data=True)):
                if n_data.get("node_type") == NodeType.BUSINESS_OBJECT.value:
                    ot = n_data.get("object_type", "").lower()
                    if f"/{ot}s" in nep.route_template.lower() or f"/{ot}" in nep.route_template.lower():
                        edge_type = EdgeType.PRODUCES if nep.method.upper() == "POST" and "{" not in nep.route_template else EdgeType.CONSUMES
                        self.add_edge(
                            GraphEdge(
                                source_id=f"endpoint:{nep.endpoint_identity}",
                                target_id=n_id,
                                edge_type=edge_type,
                                classification=FactClassification.DECLARED,
                                tenant_context=n_data.get("owner_tenant_id"),
                            )
                        )

    def ingest_inventory_snapshot(self, snapshot: InventorySnapshot) -> None:
        """Ingests an InventorySnapshot.

        Preserves invariant: Partial captures never establish endpoint removal.
        Missing endpoints in a partial capture remain untouched in the graph.
        """
        self.ingest_normalized_endpoints(list(snapshot.endpoints.values()))

    def ingest_crawler_observations(
        self,
        observations: List[BrowserObservation],
        default_asset_id: str = "primary-api",
    ) -> None:
        """Ingests browser crawler observations, normalizing endpoints and linking roles, tenants, and request traces."""
        for obs in observations:
            obs_id = obs.observation_id
            body_digest = (
                hashlib.sha256(obs.request_body.encode("utf-8")).hexdigest()
                if obs.request_body
                else None
            )
            obs_node = ObservationNode(
                observation_id=obs_id,
                source_type=EvidenceSourceType.CRAWLER,
                timestamp=obs.timestamp,
                canonical_digest=body_digest,
                confidence=1.0,
                tenant_id=obs.tenant_id,
                role_id=obs.role_name,
                session_id=obs.session_id,
                details={"url": obs.url, "method": obs.method, "status": obs.status_code},
            )
            self.add_observation(obs_node)

            # Ensure tenant exists
            tenant_node_id = f"tenant:{obs.tenant_id}"
            if not self._graph.has_node(tenant_node_id):
                self.add_tenant(TenantNode(tenant_id=obs.tenant_id, name=obs.tenant_id))

            # Ensure role exists and is linked to tenant
            role_node_id = f"role:{obs.role_name}:{obs.tenant_id}"
            if not self._graph.has_node(role_node_id):
                self.add_role(RoleNode(role_name=obs.role_name, tenant_id=obs.tenant_id))

            # Derive canonical endpoint identity
            parsed = urlparse(obs.url)
            origin = ""
            if parsed.scheme and parsed.hostname:
                port_suffix = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
                origin = f"{parsed.scheme}://{parsed.hostname}{port_suffix}"
            route_template = parsed.path or "/"
            method = obs.method.upper()
            endpoint_identity = f"{default_asset_id}:{origin}:{method}:{route_template}"

            ep_node_id = f"endpoint:{endpoint_identity}"
            if not self._graph.has_node(ep_node_id):
                self.add_endpoint(
                    EndpointNode(
                        endpoint_identity=endpoint_identity,
                        method=method,
                        route_template=route_template,
                        asset_id=default_asset_id,
                        canonical_origin=origin,
                        roles_observed=[obs.role_name],
                    )
                )
            else:
                existing_roles = self._graph.nodes[ep_node_id].get("roles_observed", [])
                if obs.role_name not in existing_roles:
                    existing_roles.append(obs.role_name)
                    self._graph.nodes[ep_node_id]["roles_observed"] = existing_roles

            # 1. Link SUPPORTED_BY (Endpoint -> Observation)
            self.add_edge(
                GraphEdge(
                    source_id=ep_node_id,
                    target_id=f"obs:{obs_id}",
                    edge_type=EdgeType.SUPPORTED_BY,
                    classification=FactClassification.OBSERVED,
                    evidence_refs=[obs_id],
                    tenant_context=obs.tenant_id,
                    role_context=obs.role_name,
                )
            )

            # 2. Link OBSERVED_REQUESTED_BY (Endpoint -> Role)
            self.add_edge(
                GraphEdge(
                    source_id=ep_node_id,
                    target_id=role_node_id,
                    edge_type=EdgeType.OBSERVED_REQUESTED_BY,
                    classification=FactClassification.OBSERVED,
                    evidence_refs=[obs_id],
                    tenant_context=obs.tenant_id,
                    role_context=obs.role_name,
                )
            )

            # 3. Link OBSERVED_RESPONSE_TO (Endpoint -> Role)
            self.add_edge(
                GraphEdge(
                    source_id=ep_node_id,
                    target_id=role_node_id,
                    edge_type=EdgeType.OBSERVED_RESPONSE_TO,
                    classification=FactClassification.OBSERVED,
                    evidence_refs=[obs_id],
                    tenant_context=obs.tenant_id,
                    role_context=obs.role_name,
                    metadata={"status_code": obs.status_code},
                )
            )

    # =========================================================================
    # Invariant Binding
    # =========================================================================

    def bind_invariants(self) -> None:
        """Inspects all endpoints and parameters in the graph and binds appropriate invariants."""
        inv_i01 = f"invariant:{InvariantType.TENANT_ISOLATION.value}"
        inv_i02 = f"invariant:{InvariantType.PRICING_INTEGRITY.value}"
        inv_i03 = f"invariant:{InvariantType.HOLD_EXPIRATION.value}"
        inv_i04 = f"invariant:{InvariantType.REFUND_IDEMPOTENCY.value}"

        for node_id, data in list(self._graph.nodes(data=True)):
            ntype = data.get("node_type")

            # 1. Bind I-01 (Tenant Isolation) to endpoints with identifier params or booking paths
            if ntype == NodeType.ENDPOINT.value:
                route = data.get("route_template", "").lower()
                method = data.get("method", "").upper()

                # Bookings, Holds, Invoices, Passengers require tenant isolation
                if any(segment in route for segment in ("/bookings", "/holds", "/invoices", "/passengers")):
                    self.add_edge(
                        GraphEdge(
                            source_id=inv_i01,
                            target_id=node_id,
                            edge_type=EdgeType.BINDS_INVARIANT,
                            classification=FactClassification.DECLARED,
                            metadata={"target": "endpoint_tenant_boundary"},
                        )
                    )

                # Check if endpoint has any financial parameter!
                has_financial_param = False
                for _, param_node, pdata in self._graph.out_edges(node_id, data=True):
                    if pdata.get("edge_type") == EdgeType.HAS_PARAMETER.value:
                        if self._graph.nodes[param_node].get("is_financial"):
                            has_financial_param = True
                            break

                # Booking checkout or Quote generation requires Authoritative Pricing (I-02)
                # OR any endpoint with financial parameter (even unconventional routes)!
                if has_financial_param or any(segment in route for segment in ("/quotes", "/checkout", "/bookings", "/fare")):
                    if method in ("POST", "PUT", "PATCH") or has_financial_param:
                        self.add_edge(
                            GraphEdge(
                                source_id=inv_i02,
                                target_id=node_id,
                                edge_type=EdgeType.BINDS_INVARIANT,
                                classification=FactClassification.DECLARED,
                                metadata={"target": "authoritative_pricing_gate"},
                            )
                        )

                # Hold confirmation requires I-03
                if "/holds" in route and method in ("POST", "PUT"):
                    self.add_edge(
                        GraphEdge(
                            source_id=inv_i03,
                            target_id=node_id,
                            edge_type=EdgeType.BINDS_INVARIANT,
                            classification=FactClassification.DECLARED,
                            metadata={"target": "hold_validity_check"},
                        )
                    )

                # Payments and Refunds require I-04
                if any(segment in route for segment in ("/payments", "/refunds", "/cancel")):
                    self.add_edge(
                        GraphEdge(
                            source_id=inv_i04,
                            target_id=node_id,
                            edge_type=EdgeType.BINDS_INVARIANT,
                            classification=FactClassification.DECLARED,
                            metadata={"target": "idempotency_and_bounds"},
                        )
                    )

            # 2. Bind parameters directly
            elif ntype == NodeType.PARAMETER.value:
                p_name = data.get("name", "").lower()
                if any(k in p_name for k in FINANCIAL_KEYWORDS):
                    self.add_edge(
                        GraphEdge(
                            source_id=inv_i02,
                            target_id=node_id,
                            edge_type=EdgeType.BINDS_INVARIANT,
                            classification=FactClassification.DECLARED,
                            metadata={"param_type": "financial_amount"},
                        )
                    )
                if any(k in p_name for k in IDENTIFIER_KEYWORDS):
                    self.add_edge(
                        GraphEdge(
                            source_id=inv_i01,
                            target_id=node_id,
                            edge_type=EdgeType.BINDS_INVARIANT,
                            classification=FactClassification.DECLARED,
                            metadata={"param_type": "tenant_boundary_identifier"},
                        )
                    )

    # =========================================================================
    # Attack Path & Hypothesis Extraction
    # =========================================================================

    def extract_attack_hypotheses(
        self,
        attacker_tenant_id: str,
        victim_tenant_id: str,
    ) -> List[HypothesisNode]:
        """Extracts bounded, evidence-backed security hypotheses from graph topology differences.

        Traverses actual tenant-to-role-to-endpoint-to-business-object ownership paths:
        Attacker (Tenant) -> Role -> Endpoint -> CONSUMES -> Object -> OWNS <- Victim (Tenant).
        """
        hypotheses: List[HypothesisNode] = []
        inv_i01 = InvariantType.TENANT_ISOLATION.value
        inv_i02 = InvariantType.PRICING_INTEGRITY.value
        inv_i03 = InvariantType.HOLD_EXPIRATION.value
        inv_i04 = InvariantType.REFUND_IDEMPOTENCY.value

        # Make sure invariants are bound
        self.bind_invariants()

        # Gather supporting evidence for endpoints
        def _get_evidence_for_endpoint(ep_node_id: str) -> List[str]:
            evs = []
            for _, target, data in self._graph.out_edges(ep_node_id, data=True):
                if data.get("edge_type") == EdgeType.SUPPORTED_BY.value and target.startswith("obs:"):
                    evs.append(target.replace("obs:", ""))
                for ev_ref in data.get("evidence_refs", []):
                    evs.append(ev_ref)
            return sorted(list(set(evs)))

        def _make_hypo_id(inv_id: str, ep_identity: str, attacker: str, victim: str, variant: str = "default") -> str:
            inv_short = inv_id.split("-")[0] if "-" in inv_id else inv_id[:4]
            raw = f"{inv_id}:{ep_identity}:{attacker}:{victim}:{variant}"
            digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
            return f"HYP-{inv_short}-{digest}"

        # 1. BOLA / IDOR Hypotheses (I-01) via Graph Path Traversal
        for node_id, data in list(self._graph.nodes(data=True)):
            if data.get("node_type") == NodeType.ENDPOINT.value:
                # Check if bound to I-01
                is_i01_bound = any(
                    src == f"invariant:{inv_i01}"
                    for src, _, edge_data in self._graph.in_edges(node_id, data=True)
                    if edge_data.get("edge_type") == EdgeType.BINDS_INVARIANT.value
                )
                if is_i01_bound:
                    ep_identity = data.get("endpoint_identity")
                    ev_ids = _get_evidence_for_endpoint(node_id)

                    # Look for consumed objects owned by victim
                    consumed_victim_objects = []
                    for _, target, edge_data in self._graph.out_edges(node_id, data=True):
                        if edge_data.get("edge_type") == EdgeType.CONSUMES.value:
                            obj_data = self._graph.nodes.get(target, {})
                            if obj_data.get("owner_tenant_id") == victim_tenant_id:
                                consumed_victim_objects.append(target)

                    # Check for verified authorization between attacker and endpoint
                    has_auth_confirmed = any(
                        src == f"tenant:{attacker_tenant_id}"
                        for src, _, edge_data in self._graph.in_edges(node_id, data=True)
                        if edge_data.get("edge_type") == EdgeType.AUTHORIZED_ACCESS_CONFIRMED.value
                    )

                    if not has_auth_confirmed:
                        hypo_id = _make_hypo_id(inv_i01, ep_identity, attacker_tenant_id, victim_tenant_id, "bola")
                        target_desc = f"victim objects {consumed_victim_objects}" if consumed_victim_objects else f"'{victim_tenant_id}' resources"
                        hypo = HypothesisNode(
                            hypothesis_id=hypo_id,
                            invariant_id=inv_i01,
                            target_endpoint_identity=ep_identity,
                            attacker_tenant_id=attacker_tenant_id,
                            victim_tenant_id=victim_tenant_id,
                            rationale=(
                                f"Graph traversal path: Tenant '{attacker_tenant_id}' -> Endpoint '{ep_identity}' "
                                f"-> CONSUMES -> {target_desc} owned by '{victim_tenant_id}'. "
                                f"No AUTHORIZED_ACCESS_CONFIRMED edge exists. Test synthetic cross-tenant access."
                            ),
                            risk_level="ROUTINE",
                            supporting_evidence_ids=ev_ids,
                        )
                        hypotheses.append(hypo)
                        self.add_hypothesis(hypo)

        # 2. Pricing Integrity Hypotheses (I-02)
        for node_id, data in list(self._graph.nodes(data=True)):
            if data.get("node_type") == NodeType.ENDPOINT.value:
                is_i02_bound = any(
                    src == f"invariant:{inv_i02}"
                    for src, _, edge_data in self._graph.in_edges(node_id, data=True)
                    if edge_data.get("edge_type") == EdgeType.BINDS_INVARIANT.value
                )
                if is_i02_bound:
                    ep_identity = data.get("endpoint_identity")
                    ev_ids = _get_evidence_for_endpoint(node_id)
                    hypo_id = _make_hypo_id(inv_i02, ep_identity, attacker_tenant_id, victim_tenant_id, "pricing")
                    hypo = HypothesisNode(
                        hypothesis_id=hypo_id,
                        invariant_id=inv_i02,
                        target_endpoint_identity=ep_identity,
                        attacker_tenant_id=attacker_tenant_id,
                        victim_tenant_id=victim_tenant_id,
                        rationale=(
                            f"Endpoint '{ep_identity}' is bound to pricing integrity (I-02). "
                            f"Test if client-submitted price tampering or currency swap overrides server-authoritative quote."
                        ),
                        risk_level="ROUTINE",
                        supporting_evidence_ids=ev_ids,
                    )
                    hypotheses.append(hypo)
                    self.add_hypothesis(hypo)

        # 3. Hold Expiration Hypotheses (I-03)
        for node_id, data in list(self._graph.nodes(data=True)):
            if data.get("node_type") == NodeType.ENDPOINT.value:
                is_i03_bound = any(
                    src == f"invariant:{inv_i03}"
                    for src, _, edge_data in self._graph.in_edges(node_id, data=True)
                    if edge_data.get("edge_type") == EdgeType.BINDS_INVARIANT.value
                )
                if is_i03_bound:
                    ep_identity = data.get("endpoint_identity")
                    ev_ids = _get_evidence_for_endpoint(node_id)
                    hypo_id = _make_hypo_id(inv_i03, ep_identity, attacker_tenant_id, victim_tenant_id, "hold_expiry")
                    hypo = HypothesisNode(
                        hypothesis_id=hypo_id,
                        invariant_id=inv_i03,
                        target_endpoint_identity=ep_identity,
                        attacker_tenant_id=attacker_tenant_id,
                        victim_tenant_id=victim_tenant_id,
                        rationale=(
                            f"Endpoint '{ep_identity}' executes reservation confirmation. "
                            f"Test if confirmation succeeds when supplied an expired hold token."
                        ),
                        risk_level="ELEVATED",
                        supporting_evidence_ids=ev_ids,
                    )
                    hypotheses.append(hypo)
                    self.add_hypothesis(hypo)

        # 4. Refund Bounds & Idempotency Hypotheses (I-04)
        for node_id, data in list(self._graph.nodes(data=True)):
            if data.get("node_type") == NodeType.ENDPOINT.value:
                is_i04_bound = any(
                    src == f"invariant:{inv_i04}"
                    for src, _, edge_data in self._graph.in_edges(node_id, data=True)
                    if edge_data.get("edge_type") == EdgeType.BINDS_INVARIANT.value
                )
                if is_i04_bound:
                    ep_identity = data.get("endpoint_identity")
                    ev_ids = _get_evidence_for_endpoint(node_id)
                    hypo_id = _make_hypo_id(inv_i04, ep_identity, attacker_tenant_id, victim_tenant_id, "refund_bounds")
                    hypo = HypothesisNode(
                        hypothesis_id=hypo_id,
                        invariant_id=inv_i04,
                        target_endpoint_identity=ep_identity,
                        attacker_tenant_id=attacker_tenant_id,
                        victim_tenant_id=victim_tenant_id,
                        rationale=(
                            f"Endpoint '{ep_identity}' processes refunds or payment settlements. "
                            f"Test if concurrent/repeated requests cause double refund or exceed captured total."
                        ),
                        risk_level="HIGH",
                        supporting_evidence_ids=ev_ids,
                    )
                    hypotheses.append(hypo)
                    self.add_hypothesis(hypo)

        return hypotheses

    # =========================================================================
    # Export, Digest and Serialization
    # =========================================================================

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the graph into a dictionary, strictly preserving original timestamps."""
        sorted_nodes = []
        for n in sorted(self._graph.nodes()):
            sorted_nodes.append({"id": n, **dict(self._graph.nodes[n])})

        sorted_edges = []
        for u, v, k, data in sorted(self._graph.edges(keys=True, data=True), key=lambda x: (x[0], x[1], x[2])):
            sorted_edges.append({
                "source": u,
                "target": v,
                "key": k,
                **dict(data),
            })

        return {
            "version": "1.0.0",
            "node_count": len(sorted_nodes),
            "edge_count": len(sorted_edges),
            "nodes": sorted_nodes,
            "edges": sorted_edges,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serializes the graph into formatted JSON string, preserving true timestamps."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def canonical_digest(self) -> str:
        """Computes a deterministic cryptographic hash over the graph structure and invariants.

        Excludes volatile timestamps while verifying identical nodes, edges, invariant bindings,
        parameter locations, and state lifecycles.
        """
        stable_nodes = []
        for n in sorted(self._graph.nodes()):
            data = dict(self._graph.nodes[n])
            data.pop("timestamp", None)
            data.pop("discovered_at", None)
            data.pop("created_at", None)
            stable_nodes.append((n, data))

        stable_edges = []
        for u, v, k, data in sorted(self._graph.edges(keys=True, data=True), key=lambda x: (x[0], x[1], x[2])):
            data = dict(data)
            data.pop("timestamp", None)
            stable_edges.append((u, v, data.get("edge_type"), data.get("classification"), sorted(data.get("evidence_refs", []))))

        payload = {
            "nodes": stable_nodes,
            "edges": stable_edges,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def export_mermaid(self) -> str:
        """Exports the graph topology and state machines to a Mermaid diagram string."""
        lines = ["flowchart TD"]

        tenants = []
        endpoints = []
        invariants = []
        states = []

        for node_id, data in sorted(self._graph.nodes(data=True), key=lambda x: x[0]):
            ntype = data.get("node_type")
            sanitized_id = node_id.replace(":", "_").replace("/", "_").replace("-", "_").replace("{", "").replace("}", "")
            if ntype == NodeType.TENANT.value:
                tenants.append((sanitized_id, data.get("name", node_id)))
            elif ntype == NodeType.ENDPOINT.value:
                endpoints.append((sanitized_id, f"{data.get('method')} {data.get('route_template')}"))
            elif ntype == NodeType.INVARIANT.value:
                invariants.append((sanitized_id, data.get("title", node_id)))
            elif ntype == NodeType.WORKFLOW_STATE.value:
                states.append((sanitized_id, f"{data.get('object_type')}:{data.get('state_name')}"))

        if tenants:
            lines.append("    subgraph Tenants")
            for sid, label in tenants:
                lines.append(f'        {sid}["{label}"]')
            lines.append("    end")

        if endpoints:
            lines.append("    subgraph Endpoints")
            for sid, label in endpoints:
                lines.append(f'        {sid}["{label}"]')
            lines.append("    end")

        if invariants:
            lines.append("    subgraph Security_Invariants")
            for sid, label in invariants:
                lines.append(f'        {sid}["{label}"]')
            lines.append("    end")

        if states:
            lines.append("    subgraph State_Machines")
            for sid, label in states:
                lines.append(f'        {sid}["{label}"]')
            lines.append("    end")

        # Edges
        for u, v, _, data in sorted(self._graph.edges(keys=True, data=True), key=lambda x: (x[0], x[1])):
            u_clean = u.replace(":", "_").replace("/", "_").replace("-", "_").replace("{", "").replace("}", "")
            v_clean = v.replace(":", "_").replace("/", "_").replace("-", "_").replace("{", "").replace("}", "")
            edge_type = data.get("edge_type", "")
            lines.append(f'    {u_clean} -->|"{edge_type}"| {v_clean}')

        return "\n".join(lines)
