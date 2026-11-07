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
        """Adds a principal user/agent and links to its Tenant."""
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
        if self._graph.has_node(tenant_node):
            self.add_edge(
                GraphEdge(
                    source_id=node_id,
                    target_id=tenant_node,
                    edge_type=EdgeType.BELONGS_TO_TENANT,
                    classification=FactClassification.DECLARED,
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
            if self._graph.has_node(tenant_node):
                self.add_edge(
                    GraphEdge(
                        source_id=node_id,
                        target_id=tenant_node,
                        edge_type=EdgeType.BELONGS_TO_TENANT,
                        classification=FactClassification.DECLARED,
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
        """Adds an endpoint parameter and links to Endpoint."""
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
        """Adds a business object and links ownership to Tenant."""
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
        """Records runtime evidence showing a business object transitioned states."""
        source = f"state:{object_type}:{from_state}"
        target = f"state:{object_type}:{to_state}"
        edge = GraphEdge(
            source_id=source,
            target_id=target,
            edge_type=EdgeType.TRANSITION_OBSERVED,
            classification=FactClassification.OBSERVED,
            evidence_refs=[evidence_id],
            tenant_context=tenant_context,
        )
        return self.add_edge(edge)

    # =========================================================================
    # Ingestion Methods (Discovery Artifacts)
    # =========================================================================

    def ingest_normalized_endpoints(self, endpoints: List[NormalizedEndpoint]) -> None:
        """Ingests normalized endpoints, extracting Asset, Parameters, and Observed Roles."""
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

            # Ingest path parameters
            for p in nep.parameters:
                p_name_lower = p.name.lower()
                is_fin = any(k in p_name_lower for k in FINANCIAL_KEYWORDS)
                is_id = any(k in p_name_lower for k in IDENTIFIER_KEYWORDS)
                self.add_parameter(
                    ParameterNode(
                        endpoint_identity=nep.endpoint_identity,
                        name=p.name,
                        location="path",
                        semantic_type=p.semantic_type,
                        is_financial=is_fin,
                        is_identifier=is_id,
                    )
                )

            # Ingest query parameters
            for q in nep.query_parameters:
                q_name_lower = q.name.lower()
                is_fin = any(k in q_name_lower for k in FINANCIAL_KEYWORDS)
                is_id = any(k in q_name_lower for k in IDENTIFIER_KEYWORDS)
                self.add_parameter(
                    ParameterNode(
                        endpoint_identity=nep.endpoint_identity,
                        name=q.name,
                        location="query",
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
        """Ingests browser crawler observations, linking roles, tenants, and request traces."""
        for obs in observations:
            obs_id = obs.observation_id
            obs_node = ObservationNode(
                observation_id=obs_id,
                source_type=EvidenceSourceType.CRAWLER,
                timestamp=obs.timestamp,
                canonical_digest=obs.request_body_sha256,
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

            # Ensure role exists
            role_node_id = f"role:{obs.role_name}:{obs.tenant_id}"
            if not self._graph.has_node(role_node_id):
                self.add_role(RoleNode(role_name=obs.role_name, tenant_id=obs.tenant_id))

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
                            timestamp="2026-01-01T00:00:00Z",
                            metadata={"target": "endpoint_tenant_boundary"},
                        )
                    )

                # Booking checkout or Quote generation requires Authoritative Pricing (I-02)
                if any(segment in route for segment in ("/quotes", "/checkout", "/bookings", "/fare")):
                    if method in ("POST", "PUT", "PATCH"):
                        self.add_edge(
                            GraphEdge(
                                source_id=inv_i02,
                                target_id=node_id,
                                edge_type=EdgeType.BINDS_INVARIANT,
                                classification=FactClassification.DECLARED,
                                timestamp="2026-01-01T00:00:00Z",
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
                            timestamp="2026-01-01T00:00:00Z",
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
                            timestamp="2026-01-01T00:00:00Z",
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
                            timestamp="2026-01-01T00:00:00Z",
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
                            timestamp="2026-01-01T00:00:00Z",
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

        Does NOT declare vulnerabilities; formulates candidate test hypotheses.
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

        # 1. BOLA / IDOR Hypotheses (I-01)
        # Endpoints bound to I-01 operating on victim resources that attacker can reach
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
                    hypo_id = f"HYP-BOLA-{hashlib.sha256(ep_identity.encode('utf-8')).hexdigest()[:8]}"
                    hypo = HypothesisNode(
                        hypothesis_id=hypo_id,
                        invariant_id=inv_i01,
                        target_endpoint_identity=ep_identity,
                        attacker_tenant_id=attacker_tenant_id,
                        victim_tenant_id=victim_tenant_id,
                        rationale=(
                            f"Endpoint '{ep_identity}' accesses tenant-scoped resources. "
                            f"Test if principal of '{attacker_tenant_id}' can access synthetic canary fixture of '{victim_tenant_id}'."
                        ),
                        risk_level="ROUTINE",
                        supporting_evidence_ids=ev_ids,
                    )
                    hypotheses.append(hypo)
                    self.add_hypothesis(hypo)

        # 2. Pricing Integrity Hypotheses (I-02)
        # Endpoints with financial parameters bound to I-02
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
                    hypo_id = f"HYP-PRICE-{hashlib.sha256(ep_identity.encode('utf-8')).hexdigest()[:8]}"
                    hypo = HypothesisNode(
                        hypothesis_id=hypo_id,
                        invariant_id=inv_i02,
                        target_endpoint_identity=ep_identity,
                        attacker_tenant_id=attacker_tenant_id,
                        victim_tenant_id=victim_tenant_id,
                        rationale=(
                            f"Endpoint '{ep_identity}' accepts checkout or booking parameters. "
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
                    hypo_id = f"HYP-HOLD-{hashlib.sha256(ep_identity.encode('utf-8')).hexdigest()[:8]}"
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
                    hypo_id = f"HYP-REFUND-{hashlib.sha256(ep_identity.encode('utf-8')).hexdigest()[:8]}"
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
    # Export and Deterministic Serialization
    # =========================================================================

    def to_dict(self, deterministic: bool = True) -> Dict[str, Any]:
        """Serializes the graph into a deterministic dictionary sorted by keys."""
        sorted_nodes = []
        for n in sorted(self._graph.nodes()):
            node_data = dict(self._graph.nodes[n])
            if deterministic:
                if "timestamp" in node_data:
                    node_data["timestamp"] = "2026-01-01T00:00:00Z"
                if "discovered_at" in node_data:
                    node_data["discovered_at"] = "2026-01-01T00:00:00Z"
            sorted_nodes.append({"id": n, **node_data})

        sorted_edges = []
        for u, v, k, data in sorted(self._graph.edges(keys=True, data=True), key=lambda x: (x[0], x[1], x[2])):
            edge_data = dict(data)
            if deterministic and "timestamp" in edge_data:
                edge_data["timestamp"] = "2026-01-01T00:00:00Z"
            edge_entry = {
                "source": u,
                "target": v,
                "key": k,
                **edge_data,
            }
            sorted_edges.append(edge_entry)

        return {
            "version": "1.0.0",
            "node_count": len(sorted_nodes),
            "edge_count": len(sorted_edges),
            "nodes": sorted_nodes,
            "edges": sorted_edges,
        }

    def to_json(self, indent: int = 2, deterministic: bool = True) -> str:
        """Serializes the graph into deterministic JSON string."""
        data = self.to_dict(deterministic=deterministic)
        return json.dumps(data, indent=indent, sort_keys=True)

    def export_mermaid(self) -> str:
        """Exports the graph topology and state machines to a Mermaid diagram string."""
        lines = ["flowchart TD"]

        # Classify by node type
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
