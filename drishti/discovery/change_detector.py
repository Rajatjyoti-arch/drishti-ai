"""Attack Surface Change Intelligence Engine for B2B Travel Platforms.

Reconciles historical and current API inventory snapshots across HAR traffic captures,
JavaScript bundle analyses, and deployment metadata to detect behavioral shifts, new attack
surface, and route modifications, recommending targeted security invariant tests (I-01, I-02).
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from drishti.discovery.models import (
    AttackSurfaceChangeSet,
    CaptureCompleteness,
    ChangeType,
    EndpointChange,
    InventorySnapshot,
    NormalizedEndpoint,
    ParameterCandidate,
    ProvenanceSource,
    SemanticType,
)

# Sensitive pricing / tariff parameter tokens triggering I-02 recommendation
PRICING_PARAMETER_TOKENS: Set[str] = {
    "amount",
    "price",
    "fare",
    "total_fare",
    "base_fare",
    "markup",
    "discount",
    "currency",
    "curr",
    "tariff",
    "fee",
    "tax",
}

# Object identifier tokens triggering I-01 (BOLA) recommendation
OBJECT_ID_PARAMETER_TOKENS: Set[str] = {
    "booking_id",
    "bookingid",
    "hold_id",
    "holdid",
    "quote_id",
    "quoteid",
    "flight_id",
    "flightid",
    "tenant_id",
    "tenantid",
    "agency_id",
    "agencyid",
    "user_id",
    "userid",
    "customer_id",
    "pnr",
}


def is_pricing_related(param_name: str, semantic_type: str) -> bool:
    """Returns True if a parameter relates to currency, price, or tariff tampering."""
    if semantic_type == SemanticType.CURRENCY.value:
        return True
    name_clean = param_name.lower().replace("-", "_")
    return any(token in name_clean for token in PRICING_PARAMETER_TOKENS)


def is_object_id_related(param_name: str, semantic_type: str) -> bool:
    """Returns True if a parameter represents a business object identifier."""
    if semantic_type in (
        SemanticType.BOOKING_ID.value,
        SemanticType.HOLD_ID.value,
        SemanticType.QUOTE_ID.value,
        SemanticType.FLIGHT_ID.value,
        SemanticType.TENANT_ID.value,
        SemanticType.USER_ID.value,
        SemanticType.UUID.value,
        SemanticType.NUMERIC_ID.value,
    ):
        return True
    name_clean = param_name.lower().replace("-", "_")
    return any(token in name_clean for token in OBJECT_ID_PARAMETER_TOKENS)


class ChangeDetector:
    """Compares versioned inventory snapshots and generates actionable attack surface change sets."""

    def __init__(self, default_asset_id: str = "primary-api"):
        self.default_asset_id = default_asset_id

    def build_snapshot(
        self,
        snapshot_id: str,
        endpoints: List[NormalizedEndpoint],
        asset_id: Optional[str] = None,
        deployment_id: Optional[str] = None,
        source_types: Optional[List[str]] = None,
        capture_completeness: str = CaptureCompleteness.PARTIAL.value,
    ) -> InventorySnapshot:
        """Constructs an InventorySnapshot from normalized endpoints, calculating deterministic digest."""
        effective_asset_id = asset_id or self.default_asset_id
        effective_sources = source_types or ["HAR"]

        endpoint_map: Dict[str, NormalizedEndpoint] = {}
        for ep in endpoints:
            endpoint_map[ep.endpoint_identity] = ep

        snapshot = InventorySnapshot(
            snapshot_id=snapshot_id,
            asset_id=effective_asset_id,
            deployment_id=deployment_id,
            source_types=effective_sources,
            capture_completeness=capture_completeness,
            endpoints=endpoint_map,
        )
        snapshot.snapshot_digest = snapshot.compute_snapshot_digest()
        return snapshot

    def compare_snapshots(
        self,
        previous: InventorySnapshot,
        current: InventorySnapshot,
    ) -> AttackSurfaceChangeSet:
        """Compares historical snapshot against current snapshot, deriving categorized changes

        and recommending security invariants to verify.
        """
        changeset_id = f"CHG-{uuid.uuid4().hex[:8].upper()}"
        affected_assets: Set[str] = {previous.asset_id, current.asset_id}
        aggregated_invariants: Set[str] = set()
        changes: List[EndpointChange] = []

        # 1. Check for Duplicate / Idempotent Deployment Event
        if (
            previous.deployment_id
            and current.deployment_id
            and previous.deployment_id == current.deployment_id
            and previous.snapshot_digest == current.snapshot_digest
        ):
            return AttackSurfaceChangeSet(
                changeset_id=changeset_id,
                previous_snapshot_id=previous.snapshot_id,
                current_snapshot_id=current.snapshot_id,
                changes=[],
                affected_assets=sorted(list(affected_assets)),
                recommended_invariants=[],
            )

        prev_endpoints = previous.endpoints
        curr_endpoints = current.endpoints

        prev_keys = set(prev_endpoints.keys())
        curr_keys = set(curr_endpoints.keys())

        # 2. Detect New Endpoints (ENDPOINT_ADDED)
        added_keys = curr_keys - prev_keys
        for key in sorted(added_keys):
            ep = curr_endpoints[key]
            invariants: Set[str] = set()

            # Check if new endpoint contains sensitive parameters
            for p in ep.parameters + ep.query_parameters:
                if is_object_id_related(p.name, p.semantic_type):
                    invariants.add("I-01")
                if is_pricing_related(p.name, p.semantic_type):
                    invariants.add("I-02")

            # Check if source is only JS bundle
            is_source_only = (
                len(ep.provenance) > 0
                and all(pr.source == "JS_BUNDLE" for pr in ep.provenance)
            )

            change_type = (
                ChangeType.SOURCE_ONLY_CHANGE.value
                if is_source_only
                else ChangeType.ENDPOINT_ADDED.value
            )

            rec_invs = sorted(list(invariants))
            aggregated_invariants.update(rec_invs)

            change = EndpointChange(
                change_id=f"DELTA-{uuid.uuid4().hex[:6].upper()}",
                endpoint_identity=ep.endpoint_identity,
                change_type=change_type,
                previous_fingerprint=None,
                current_fingerprint=ep.endpoint_signature,
                affected_parameters=[p.name for p in ep.parameters + ep.query_parameters],
                provenance=ep.provenance,
                confidence=ep.confidence.score,
                recommended_invariants=rec_invs,
                details={
                    "route_template": ep.route_template,
                    "method": ep.method,
                    "is_source_only": is_source_only,
                },
            )
            changes.append(change)

        # 3. Detect Missing Endpoints (Absence is NOT immediate removal!)
        removed_keys = prev_keys - curr_keys
        for key in sorted(removed_keys):
            prev_ep = prev_endpoints[key]

            # If both snapshots are marked COMPLETE -> REMOVED_CANDIDATE
            # If either snapshot is marked PARTIAL -> NOT_OBSERVED (traffic didn't exercise it)
            if (
                previous.capture_completeness == CaptureCompleteness.COMPLETE.value
                and current.capture_completeness == CaptureCompleteness.COMPLETE.value
            ):
                chg_type = ChangeType.ENDPOINT_REMOVED_CANDIDATE.value
                confidence = 0.85
            else:
                chg_type = ChangeType.ENDPOINT_NOT_OBSERVED.value
                confidence = 0.60

            change = EndpointChange(
                change_id=f"DELTA-{uuid.uuid4().hex[:6].upper()}",
                endpoint_identity=prev_ep.endpoint_identity,
                change_type=chg_type,
                previous_fingerprint=prev_ep.endpoint_signature,
                current_fingerprint=None,
                affected_parameters=[],
                provenance=prev_ep.provenance,
                confidence=confidence,
                recommended_invariants=[],
                details={
                    "route_template": prev_ep.route_template,
                    "method": prev_ep.method,
                    "capture_completeness": current.capture_completeness,
                },
            )
            changes.append(change)

        # 4. Detect Modified Endpoints (Common keys)
        common_keys = prev_keys & curr_keys
        for key in sorted(common_keys):
            prev_ep = prev_endpoints[key]
            curr_ep = curr_endpoints[key]

            # 4a. Role observation comparison: evaluated independently of signature comparison
            prev_roles = set(prev_ep.roles_observed)
            curr_roles = set(curr_ep.roles_observed)
            new_roles = curr_roles - prev_roles
            if new_roles:
                rec_invs = ["I-01", "I-06"]
                aggregated_invariants.update(rec_invs)
                changes.append(
                    EndpointChange(
                        change_id=f"DELTA-{uuid.uuid4().hex[:6].upper()}",
                        endpoint_identity=curr_ep.endpoint_identity,
                        change_type=ChangeType.ROLE_OBSERVATION_CHANGED.value,
                        previous_fingerprint=",".join(sorted(prev_roles)),
                        current_fingerprint=",".join(sorted(curr_roles)),
                        affected_parameters=[],
                        provenance=curr_ep.provenance,
                        confidence=0.95,
                        recommended_invariants=rec_invs,
                        details={
                            "previous_roles": sorted(list(prev_roles)),
                            "newly_observed_roles": sorted(list(new_roles)),
                        },
                    )
                )

            # 4b. Parameter semantic type change detection (e.g. generic id -> BOOKING_ID)
            prev_param_types = {p.name: p.semantic_type for p in prev_ep.parameters + prev_ep.query_parameters}
            curr_param_types = {p.name: p.semantic_type for p in curr_ep.parameters + curr_ep.query_parameters}
            for p_name, curr_sem in curr_param_types.items():
                prev_sem = prev_param_types.get(p_name)
                if prev_sem and prev_sem != curr_sem:
                    invs: Set[str] = set()
                    if is_object_id_related(p_name, curr_sem):
                        invs.add("I-01")
                    if is_pricing_related(p_name, curr_sem):
                        invs.add("I-02")
                    rec_invs = sorted(list(invs))
                    aggregated_invariants.update(rec_invs)
                    changes.append(
                        EndpointChange(
                            change_id=f"DELTA-{uuid.uuid4().hex[:6].upper()}",
                            endpoint_identity=curr_ep.endpoint_identity,
                            change_type=ChangeType.PARAMETER_SEMANTICS_CHANGED.value,
                            previous_fingerprint=prev_sem,
                            current_fingerprint=curr_sem,
                            affected_parameters=[p_name],
                            provenance=curr_ep.provenance,
                            confidence=0.92,
                            recommended_invariants=rec_invs,
                            details={
                                "parameter": p_name,
                                "previous_semantic_type": prev_sem,
                                "current_semantic_type": curr_sem,
                            },
                        )
                    )

            # If contract signature has not shifted, skip parameter/schema structural diffing
            if prev_ep.endpoint_signature == curr_ep.endpoint_signature:
                continue

            # Signatures differ -> identify granular parameter or schema modifications
            prev_path_params = {p.name: p for p in prev_ep.parameters}
            curr_path_params = {p.name: p for p in curr_ep.parameters}

            prev_query_params = {p.name: p for p in prev_ep.query_parameters}
            curr_query_params = {p.name: p for p in curr_ep.query_parameters}

            # A. Path parameter added
            added_path_params = set(curr_path_params.keys()) - set(prev_path_params.keys())
            if added_path_params:
                invariants: Set[str] = set()
                for p_name in added_path_params:
                    p = curr_path_params[p_name]
                    if is_object_id_related(p.name, p.semantic_type):
                        invariants.add("I-01")
                rec_invs = sorted(list(invariants))
                aggregated_invariants.update(rec_invs)

                changes.append(
                    EndpointChange(
                        change_id=f"DELTA-{uuid.uuid4().hex[:6].upper()}",
                        endpoint_identity=curr_ep.endpoint_identity,
                        change_type=ChangeType.PATH_PARAMETER_ADDED.value,
                        previous_fingerprint=prev_ep.endpoint_signature,
                        current_fingerprint=curr_ep.endpoint_signature,
                        affected_parameters=sorted(list(added_path_params)),
                        provenance=curr_ep.provenance,
                        confidence=0.90,
                        recommended_invariants=rec_invs,
                        details={"added_path_parameters": sorted(list(added_path_params))},
                    )
                )

            # B. Query parameter added
            added_query_params = set(curr_query_params.keys()) - set(prev_query_params.keys())
            if added_query_params:
                invariants = set()
                for p_name in added_query_params:
                    p = curr_query_params[p_name]
                    if is_pricing_related(p.name, p.semantic_type):
                        invariants.add("I-02")
                    if is_object_id_related(p.name, p.semantic_type):
                        invariants.add("I-01")
                rec_invs = sorted(list(invariants))
                aggregated_invariants.update(rec_invs)

                changes.append(
                    EndpointChange(
                        change_id=f"DELTA-{uuid.uuid4().hex[:6].upper()}",
                        endpoint_identity=curr_ep.endpoint_identity,
                        change_type=ChangeType.QUERY_PARAMETER_ADDED.value,
                        previous_fingerprint=prev_ep.endpoint_signature,
                        current_fingerprint=curr_ep.endpoint_signature,
                        affected_parameters=sorted(list(added_query_params)),
                        provenance=curr_ep.provenance,
                        confidence=0.90,
                        recommended_invariants=rec_invs,
                        details={"added_query_parameters": sorted(list(added_query_params))},
                    )
                )

            # C. Request Body Schema Changed
            if prev_ep.body_schema_digest != curr_ep.body_schema_digest:
                # Check if body parameters contain pricing fields
                invariants = set()
                body_param_names = [
                    p.name for p in curr_ep.parameters if p.location == "body"
                ]
                for p_name in body_param_names:
                    p = next((x for x in curr_ep.parameters if x.name == p_name), None)
                    if p and is_pricing_related(p.name, p.semantic_type):
                        invariants.add("I-02")
                rec_invs = sorted(list(invariants))
                if not rec_invs:
                    rec_invs = ["I-02"]
                aggregated_invariants.update(rec_invs)

                changes.append(
                    EndpointChange(
                        change_id=f"DELTA-{uuid.uuid4().hex[:6].upper()}",
                        endpoint_identity=curr_ep.endpoint_identity,
                        change_type=ChangeType.REQUEST_SCHEMA_CHANGED.value,
                        previous_fingerprint=prev_ep.body_schema_digest,
                        current_fingerprint=curr_ep.body_schema_digest,
                        affected_parameters=body_param_names,
                        provenance=curr_ep.provenance,
                        confidence=0.92,
                        recommended_invariants=rec_invs,
                        details={
                            "previous_schema_digest": prev_ep.body_schema_digest,
                            "current_schema_digest": curr_ep.body_schema_digest,
                            "body_parameters": body_param_names,
                        },
                    )
                )

        # 5. Method Changed Check across method sets per route template (prevents dictionary overwriting)
        from collections import defaultdict
        prev_route_methods: Dict[Tuple[str, str, str], Dict[str, NormalizedEndpoint]] = defaultdict(dict)
        for ep in prev_endpoints.values():
            prev_route_methods[(ep.asset_id, ep.canonical_origin, ep.route_template)][ep.method.upper()] = ep

        curr_route_methods: Dict[Tuple[str, str, str], Dict[str, NormalizedEndpoint]] = defaultdict(dict)
        for ep in curr_endpoints.values():
            curr_route_methods[(ep.asset_id, ep.canonical_origin, ep.route_template)][ep.method.upper()] = ep

        all_route_keys = set(prev_route_methods.keys()) & set(curr_route_methods.keys())
        for r_key in sorted(all_route_keys):
            prev_m_dict = prev_route_methods[r_key]
            curr_m_dict = curr_route_methods[r_key]

            prev_methods = set(prev_m_dict.keys())
            curr_methods = set(curr_m_dict.keys())

            if prev_methods != curr_methods:
                added_methods = curr_methods - prev_methods
                for m in sorted(added_methods):
                    curr_ep = curr_m_dict[m]
                    rec_invs = ["I-01"]
                    aggregated_invariants.update(rec_invs)
                    changes.append(
                        EndpointChange(
                            change_id=f"DELTA-{uuid.uuid4().hex[:6].upper()}",
                            endpoint_identity=curr_ep.endpoint_identity,
                            change_type=ChangeType.METHOD_CHANGED.value,
                            previous_fingerprint=",".join(sorted(prev_methods)),
                            current_fingerprint=",".join(sorted(curr_methods)),
                            affected_parameters=[],
                            provenance=curr_ep.provenance,
                            confidence=0.95,
                            recommended_invariants=rec_invs,
                            details={
                                "route_template": r_key[2],
                                "previous_methods": sorted(list(prev_methods)),
                                "current_methods": sorted(list(curr_methods)),
                                "added_method": m,
                            },
                        )
                    )

        return AttackSurfaceChangeSet(
            changeset_id=changeset_id,
            previous_snapshot_id=previous.snapshot_id,
            current_snapshot_id=current.snapshot_id,
            changes=changes,
            affected_assets=sorted(list(affected_assets)),
            recommended_invariants=sorted(list(aggregated_invariants)),
        )
