"""Fail-closed typed read-only queries over verified RKB snapshots."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any, TypeVar

from pydantic import BaseModel, Field

from .models import EvidenceEnvelope, Fact, FactSourceKind, FreshnessStatus, Snapshot
from .read_models import (
    CapabilityRecord,
    CapabilityState,
    ExecutableModel,
    HardwareInventoryModel,
    HardwareResourceModel,
    MiddlewareEndpointModel,
    MiddlewareGraphModel,
    MiddlewareRelationshipModel,
    RobotIdentityModel,
    RuntimeStatusModel,
    Stability,
    StateSafetyModel,
    TypedQueryResult,
    UnknownValue,
)
from .validation import EvidenceValidationError, validate_envelope


class QueryResult(BaseModel):
    """Compatibility result shape retained for the RKB-1 query API."""

    status: FreshnessStatus | CapabilityState
    value: Any = None
    evidence_ids: list[str] = Field(default_factory=list)
    observed_at: datetime | None = None
    fresh_until: datetime | None = None
    limitations: list[str] = Field(default_factory=list)
    status_reason: str = ""


class SnapshotReference(BaseModel):
    """Small safe reference accepted by typed queries; never raw bundle data."""

    digest: str
    robot_id: str | None = None
    target_host_fingerprint: str | None = None


class QueryRejectedError(EvidenceValidationError):
    """Raised when a typed query cannot prove identity or freshness."""


T = TypeVar("T")


class _RobotQueries:
    def __init__(self, kb: ReadOnlyKnowledgeBase) -> None:
        self._kb = kb

    def identity(self, **kwargs: Any) -> TypedQueryResult[RobotIdentityModel]:
        return self._kb.query_identity(**kwargs)


class _OSQueries:
    def __init__(self, kb: ReadOnlyKnowledgeBase) -> None:
        self._kb = kb

    def runtime_status(self, **kwargs: Any) -> TypedQueryResult[RuntimeStatusModel]:
        return self._kb.query_runtime_status(**kwargs)

    status = runtime_status


class _HardwareQueries:
    def __init__(self, kb: ReadOnlyKnowledgeBase) -> None:
        self._kb = kb

    def inventory_scan(self, **kwargs: Any) -> TypedQueryResult[HardwareInventoryModel]:
        return self._kb.query_hardware_inventory(**kwargs)

    scan = inventory_scan


class _MiddlewareQueries:
    def __init__(self, kb: ReadOnlyKnowledgeBase) -> None:
        self._kb = kb

    def graph_snapshot(
        self, selector: str | Mapping[str, Any] | None = None, **kwargs: Any
    ) -> TypedQueryResult[MiddlewareGraphModel]:
        return self._kb.query_middleware_graph(selector=selector, **kwargs)

    snapshot = graph_snapshot

    def route_inspect(
        self, route_id: str, **kwargs: Any
    ) -> TypedQueryResult[MiddlewareEndpointModel]:
        return self._kb.query_middleware_route(route_id, **kwargs)

    inspect = route_inspect


class _ApplicationQueries:
    def __init__(self, kb: ReadOnlyKnowledgeBase) -> None:
        self._kb = kb

    def executable_inspect(
        self, executable_id: str, **kwargs: Any
    ) -> TypedQueryResult[ExecutableModel]:
        return self._kb.query_executable(executable_id, **kwargs)

    inspect = executable_inspect


class _CapabilityQueries:
    def __init__(self, kb: ReadOnlyKnowledgeBase) -> None:
        self._kb = kb

    def get(self, operation_id: str, **kwargs: Any) -> TypedQueryResult[CapabilityRecord]:
        return self._kb.query_capability(operation_id, **kwargs)


class _SafetyQueries:
    def __init__(self, kb: ReadOnlyKnowledgeBase) -> None:
        self._kb = kb

    def snapshot(self, **kwargs: Any) -> TypedQueryResult[StateSafetyModel]:
        return self._kb.query_state_safety(**kwargs)


class ReadOnlyKnowledgeBase:
    """Index verified snapshots and expose only typed read projections."""

    def __init__(self, envelopes: Sequence[EvidenceEnvelope | Snapshot] | None = None) -> None:
        self._envelopes: list[EvidenceEnvelope | Snapshot] = []
        for envelope in envelopes or ():
            self.add_verified(envelope)
        self.robot = _RobotQueries(self)
        self.os = _OSQueries(self)
        self.hw = _HardwareQueries(self)
        self.middleware = _MiddlewareQueries(self)
        self.app = _ApplicationQueries(self)
        self.capability = _CapabilityQueries(self)
        self.state_safety = _SafetyQueries(self)

    def add_verified(
        self,
        envelope: EvidenceEnvelope | Snapshot,
        *,
        now: datetime | None = None,
        hmac_secret: bytes | None = None,
    ) -> None:
        validate_envelope(envelope, now=now, require_fresh=False, hmac_secret=hmac_secret)
        self._envelopes.append(envelope)

    def reference(self, snapshot: EvidenceEnvelope | Snapshot | None = None) -> SnapshotReference:
        selected = snapshot or self._latest()
        if selected is None:
            raise QueryRejectedError("no verified snapshot available")
        return SnapshotReference(
            digest=selected.digest or selected.computed_digest(),
            robot_id=selected.identity.robot_id,
            target_host_fingerprint=selected.identity.target_host_fingerprint,
        )

    def identity(self, *, now: datetime | None = None) -> QueryResult:
        """RKB-1 compatibility query; typed callers should use ``robot.identity``."""
        if not self._envelopes:
            return QueryResult(status=FreshnessStatus.UNKNOWN, limitations=["no verified evidence"])
        envelope = self._envelopes[-1]
        return QueryResult(
            status=envelope.identity.freshness(now=now),
            value=envelope.identity.model_dump(mode="json"),
            evidence_ids=[fact.fact_id for fact in envelope.facts],
            observed_at=envelope.identity.observed_at,
            fresh_until=envelope.identity.fresh_until,
        )

    def facts(
        self,
        *,
        now: datetime | None = None,
        page: int = 1,
        page_size: int | None = None,
        offset: int = 0,
        limit: int | None = None,
    ) -> list[QueryResult]:
        if page < 1 or offset < 0 or (page_size is not None and page_size < 1):
            raise ValueError("page/page_size/offset must be positive")
        results = [
            self._fact_result(fact, now=now)
            for envelope in self._envelopes
            for fact in envelope.facts
        ]
        results.sort(
            key=lambda item: (
                item.observed_at or datetime.min.replace(tzinfo=timezone.utc),
                item.evidence_ids[0] if item.evidence_ids else "",
            )
        )
        if page_size is not None:
            offset, limit = offset + (page - 1) * page_size, page_size
        if limit is not None and limit < 0:
            raise ValueError("limit must not be negative")
        return results[offset : offset + limit if limit is not None else None]

    def get(self, fact_id: str, *, now: datetime | None = None) -> QueryResult:
        for result in self.facts(now=now):
            if fact_id in result.evidence_ids:
                return result
        return QueryResult(status=FreshnessStatus.UNKNOWN, limitations=["fact not found"])

    def query_identity(
        self,
        *,
        snapshot_ref: SnapshotReference | str | Mapping[str, Any] | None = None,
        fingerprint: str | None = None,
        now: datetime | None = None,
    ) -> TypedQueryResult[RobotIdentityModel]:
        envelope = self._select(snapshot_ref=snapshot_ref, fingerprint=fingerprint, now=now)
        value = RobotIdentityModel.model_validate(envelope.identity.model_dump(mode="json"))
        return self._typed(
            value, envelope.facts, status=FreshnessStatus.FRESH, reason="verified identity"
        )

    def query_runtime_status(
        self,
        *,
        snapshot_ref: SnapshotReference | str | Mapping[str, Any] | None = None,
        fingerprint: str | None = None,
        now: datetime | None = None,
    ) -> TypedQueryResult[RuntimeStatusModel]:
        envelope = self._select(snapshot_ref=snapshot_ref, fingerprint=fingerprint, now=now)
        facts = self._layer_facts(envelope, {"linux", "os_runtime", "runtime", "ros"})
        data = self._merge_data(facts)
        merge_limitations = self._take_merge_limitations(data)
        return self._typed(
            RuntimeStatusModel.model_validate(self._runtime_value(data)),
            facts,
            status=self._status_for(facts, now=now),
            reason="runtime observed" if facts else "runtime is UNKNOWN",
            limitations=merge_limitations,
        )

    def query_hardware_inventory(
        self,
        *,
        snapshot_ref: SnapshotReference | str | Mapping[str, Any] | None = None,
        fingerprint: str | None = None,
        now: datetime | None = None,
    ) -> TypedQueryResult[HardwareInventoryModel]:
        envelope = self._select(snapshot_ref=snapshot_ref, fingerprint=fingerprint, now=now)
        facts = self._layer_facts(envelope, {"hw", "hardware", "hardware_inventory"})
        data = self._merge_data(facts)
        merge_limitations = self._take_merge_limitations(data)
        raw_resources = self._items_from_facts(
            facts, ("resources", "devices", "inventory")
        )
        resources: list[HardwareResourceModel] = []
        for index, raw in enumerate(raw_resources):
            item = dict(raw) if isinstance(raw, Mapping) else {"name": str(raw)}
            resource_id = str(
                item.get("resource_id")
                or item.get("id")
                or item.get("serial")
                or item.get("path")
                or f"hardware:{index}"
            )
            stable_identity = any(
                item.get(key)
                for key in ("serial", "address", "provider_id", "udev_by_id", "usb_topology")
            )
            if stable_identity:
                item.setdefault("stability", Stability.STABLE)
            else:
                item.setdefault("stability", Stability.UNSTABLE)
                item.setdefault("limitations", []).append("resource identity is path-only")
            item["resource_id"] = resource_id
            resources.append(HardwareResourceModel.model_validate(item))
        return self._typed(
            HardwareInventoryModel(resources=sorted(resources, key=lambda item: item.resource_id)),
            facts,
            status=self._status_for(facts, now=now),
            reason="hardware inventory observed" if facts else "hardware inventory is UNKNOWN",
            limitations=merge_limitations,
        )

    def query_middleware_graph(
        self,
        *,
        selector: str | Mapping[str, Any] | None = None,
        snapshot_ref: SnapshotReference | str | Mapping[str, Any] | None = None,
        fingerprint: str | None = None,
        now: datetime | None = None,
    ) -> TypedQueryResult[MiddlewareGraphModel]:
        envelope = self._select(snapshot_ref=snapshot_ref, fingerprint=fingerprint, now=now)
        facts = self._layer_facts(envelope, {"ros", "middleware", "middleware_graph"})
        data = self._merge_data(facts)
        merge_limitations = self._take_merge_limitations(data)
        endpoints = self._endpoint_values(
            {"endpoints": self._items_from_facts(facts, ("endpoints", "routes", "topics"))}
        )
        relationships = self._relationship_values(
            {"relationships": self._items_from_facts(facts, ("relationships", "edges"))}
        )
        if facts:
            for endpoint in endpoints:
                endpoint.observed_at = facts[-1].observed_at
                endpoint.fresh_until = min(fact.fresh_until for fact in facts)
                if endpoint.provider is None:
                    endpoint.limitations.append("provider was not observed")
                if endpoint.runtime_revision is None:
                    endpoint.limitations.append("runtime revision was not observed")
        if selector:
            token = (
                selector
                if isinstance(selector, str)
                else str(
                    selector.get("endpoint")
                    or selector.get("node")
                    or selector.get("route_id")
                    or ""
                )
            )
            endpoints = [
                item
                for item in endpoints
                if token in (item.endpoint or "")
                or token in (item.node or "")
                or token == item.route_id
            ]
            relationships = [
                item
                for item in relationships
                if token in (item.source or "") or token in (item.target or "")
            ]
        value = MiddlewareGraphModel(
            endpoints=sorted(endpoints, key=lambda item: item.route_id),
            relationships=sorted(relationships, key=lambda item: item.relationship_id),
        )
        return self._typed(
            value,
            facts,
            status=self._status_for(facts, now=now),
            reason="middleware graph observed" if facts else "middleware graph is UNKNOWN",
            limitations=merge_limitations,
        )

    def query_middleware_route(
        self, route_id: str, **kwargs: Any
    ) -> TypedQueryResult[MiddlewareEndpointModel]:
        graph = self.query_middleware_graph(**kwargs)
        for endpoint in graph.value.endpoints if graph.value else []:
            if endpoint.route_id == route_id:
                return TypedQueryResult(
                    status=graph.status,
                    value=endpoint,
                    evidence_ids=graph.evidence_ids,
                    observed_at=graph.observed_at,
                    fresh_until=graph.fresh_until,
                    limitations=graph.limitations,
                    status_reason="route observed",
                )
        return TypedQueryResult(
            status=FreshnessStatus.UNKNOWN,
            limitations=[f"route not found: {route_id}"],
            status_reason="missing route is not success",
        )

    def query_executable(
        self,
        executable_id: str,
        *,
        snapshot_ref: SnapshotReference | str | Mapping[str, Any] | None = None,
        fingerprint: str | None = None,
        now: datetime | None = None,
    ) -> TypedQueryResult[ExecutableModel]:
        envelope = self._select(snapshot_ref=snapshot_ref, fingerprint=fingerprint, now=now)
        facts = self._layer_facts(envelope, {"application", "executable", "app"})
        data = self._merge_data(facts)
        merge_limitations = self._take_merge_limitations(data)
        items = self._items_from_facts(facts, ("executables", "applications"))
        for candidate in items:
            item = dict(candidate) if isinstance(candidate, Mapping) else {"name": str(candidate)}
            item.setdefault("name", item.get("executable") or executable_id)
            item.setdefault("executable_id", item.get("id") or item.get("name"))
            if item["executable_id"] == executable_id or item.get("name") == executable_id:
                item.setdefault("observed", True)
                item.setdefault("source_kind", "OBSERVED")
                return self._typed(
                    ExecutableModel.model_validate(item),
                    facts,
                    status=self._status_for(facts, now=now),
                    reason="executable identity observed",
                    limitations=merge_limitations,
                )
        return TypedQueryResult(
            status=FreshnessStatus.UNKNOWN,
            limitations=[f"executable not found: {executable_id}"],
            status_reason="missing executable is not success",
        )

    def query_capability(
        self,
        operation_id: str,
        *,
        snapshot_ref: SnapshotReference | str | Mapping[str, Any] | None = None,
        fingerprint: str | None = None,
        now: datetime | None = None,
    ) -> TypedQueryResult[CapabilityRecord]:
        envelope = self._select(snapshot_ref=snapshot_ref, fingerprint=fingerprint, now=now)
        facts = self._layer_facts(envelope, {"capability", "capabilities", "application"})
        data = self._merge_data(facts)
        merge_limitations = self._take_merge_limitations(data)
        items = self._items_from_facts(facts, ("capabilities", "operations"))
        for candidate in items:
            item = (
                dict(candidate)
                if isinstance(candidate, Mapping)
                else {"operation_id": str(candidate)}
            )
            item.setdefault("operation_id", item.get("id") or item.get("operation") or operation_id)
            if item["operation_id"] != operation_id:
                continue
            source = str(
                item.get("source_kind") or (facts[0].source_kind.value if facts else "OBSERVED")
            )
            requested = str(item.get("state") or item.get("status") or "UNAVAILABLE").upper()
            try:
                state = CapabilityState(requested)
            except ValueError:
                state = CapabilityState.UNAVAILABLE
            if source in {FactSourceKind.DECLARED.value, FactSourceKind.DECLARED_STATIC.value}:
                state = CapabilityState.DISCOVERED_UNVERIFIED
            if self._status_for(facts, now=now) == FreshnessStatus.STALE:
                state = CapabilityState.STALE
            reason = str(item.get("reason") or self._capability_reason(state, source))
            value = CapabilityRecord(
                operation_id=operation_id,
                state=state,
                reason=reason,
                source_kind=source,
                fingerprint=envelope.identity.target_host_fingerprint,
                limitations=list(item.get("limitations", [])),
            )
            return self._typed(
                value,
                facts,
                status=state,
                reason=reason,
                limitations=merge_limitations,
            )
        return TypedQueryResult(
            status=CapabilityState.UNAVAILABLE,
            limitations=[f"capability not found: {operation_id}"],
            status_reason="capability record is unavailable",
        )

    def query_state_safety(
        self,
        *,
        snapshot_ref: SnapshotReference | str | Mapping[str, Any] | None = None,
        fingerprint: str | None = None,
        now: datetime | None = None,
    ) -> TypedQueryResult[StateSafetyModel]:
        envelope = self._select(snapshot_ref=snapshot_ref, fingerprint=fingerprint, now=now)
        facts = self._layer_facts(envelope, {"state_safety", "safety", "state"})
        data = self._merge_data(facts)
        merge_limitations = self._take_merge_limitations(data)
        raw_observed = data.get("observed_fields", data.get("fields", {}))
        observed = dict(raw_observed) if isinstance(raw_observed, Mapping) else {}
        value = StateSafetyModel(
            state=str(data.get("state", "UNKNOWN")),
            observed_fields=observed,
            safety_status=str(data.get("safety_status", "UNKNOWN")),
        )
        limitations = self._limitations(facts) + merge_limitations
        if not facts:
            limitations.append("no state safety observation; safety remains UNKNOWN")
        elif "safety_status" not in data:
            limitations.append("safety status was not observed")
        return self._typed(
            value,
            facts,
            status=self._status_for(facts, now=now),
            reason="state safety is observation-only",
            limitations=limitations,
        )

    # Verbose aliases make the typed endpoints discoverable without requiring
    # callers to use the namespace facade (``kb.robot.identity()`` etc.).
    robot_identity = query_identity
    os_runtime_status = query_runtime_status
    hw_inventory_scan = query_hardware_inventory
    middleware_graph_snapshot = query_middleware_graph
    middleware_route_inspect = query_middleware_route
    app_executable_inspect = query_executable
    capability_get = query_capability
    state_safety_snapshot = query_state_safety

    def _latest(self) -> EvidenceEnvelope | Snapshot | None:
        return self._envelopes[-1] if self._envelopes else None

    def _select(
        self,
        *,
        snapshot_ref: SnapshotReference | str | Mapping[str, Any] | None,
        fingerprint: str | None,
        now: datetime | None,
    ) -> EvidenceEnvelope | Snapshot:
        ref = (
            SnapshotReference.model_validate(snapshot_ref)
            if isinstance(snapshot_ref, Mapping)
            else SnapshotReference(digest=snapshot_ref)
            if isinstance(snapshot_ref, str)
            else snapshot_ref
        )
        if ref is not None:
            envelope = next(
                (
                    candidate
                    for candidate in reversed(self._envelopes)
                    if (candidate.digest or candidate.computed_digest()) == ref.digest
                ),
                None,
            )
            if envelope is None:
                raise QueryRejectedError("snapshot reference does not match any verified snapshot")
        else:
            envelope = self._latest()
        if envelope is None:
            raise QueryRejectedError("no verified snapshot available")
        digest = envelope.digest or envelope.computed_digest()
        if ref is not None and (
            ref.digest != digest
            or (ref.robot_id and ref.robot_id != envelope.identity.robot_id)
            or (
                ref.target_host_fingerprint
                and ref.target_host_fingerprint != envelope.identity.target_host_fingerprint
            )
        ):
            raise QueryRejectedError("snapshot reference does not match the selected snapshot")
        if fingerprint and fingerprint != envelope.identity.target_host_fingerprint:
            raise QueryRejectedError("snapshot fingerprint mismatch")
        try:
            # Validate the snapshot envelope and identity at query time, but
            # defer fact freshness to the selected layer.  A 30-second ROS
            # fact must not invalidate an otherwise usable 10-minute hardware
            # projection.
            validate_envelope(envelope, now=now, require_fresh=False, clock_skew=timedelta(0))
            from .validation import validate_identity

            validate_identity(
                envelope.identity,
                now=now,
                require_fresh=True,
                clock_skew=timedelta(0),
            )
        except EvidenceValidationError as exc:
            raise QueryRejectedError(str(exc)) from exc
        return envelope

    @staticmethod
    def _layer_facts(envelope: EvidenceEnvelope | Snapshot, layers: set[str]) -> list[Fact]:
        return sorted(
            [
                fact
                for fact in envelope.facts
                if isinstance(fact.value, Mapping)
                and str(fact.value.get("layer", "")).lower() in layers
            ],
            key=lambda fact: (fact.observed_at, fact.fact_id),
        )

    @staticmethod
    def _merge_data(facts: Sequence[Fact]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        limitations: list[str] = []
        for fact in facts:
            value = fact.value if isinstance(fact.value, Mapping) else {}
            data = value.get("data", value)
            if isinstance(data, Mapping):
                for key, raw in data.items():
                    if key not in result:
                        result[key] = list(raw) if isinstance(raw, list) else raw
                    elif isinstance(result[key], list) and isinstance(raw, list):
                        result[key].extend(list(raw))
                    elif result[key] != raw:
                        limitations.append(
                            f"conflicting observations for {key}; latest value selected"
                        )
                        result[key] = raw
        if limitations:
            result["_rkb_merge_limitations"] = sorted(set(limitations))
        return result

    @staticmethod
    def _take_merge_limitations(data: dict[str, Any]) -> list[str]:
        raw = data.pop("_rkb_merge_limitations", [])
        return [str(item) for item in raw] if isinstance(raw, list) else []

    @staticmethod
    def _items_from_facts(facts: Sequence[Fact], keys: Sequence[str]) -> list[Any]:
        items: list[Any] = []
        for fact in facts:
            value = fact.value if isinstance(fact.value, Mapping) else {}
            data = value.get("data", value)
            if not isinstance(data, Mapping):
                continue
            for key in keys:
                raw = data.get(key)
                if isinstance(raw, Mapping):
                    items.extend(raw.values())
                    break
                if isinstance(raw, list):
                    items.extend(raw)
                    break
        return items

    @staticmethod
    def _status_for(facts: Sequence[Fact], *, now: datetime | None = None) -> FreshnessStatus:
        if not facts:
            return FreshnessStatus.UNKNOWN
        statuses = [fact.freshness(now=now or _utc_now()) for fact in facts]
        if FreshnessStatus.STALE in statuses:
            return FreshnessStatus.STALE
        if FreshnessStatus.UNKNOWN in statuses:
            return FreshnessStatus.UNKNOWN
        return FreshnessStatus.FRESH

    @staticmethod
    def _limitations(facts: Sequence[Fact]) -> list[str]:
        return sorted({item for fact in facts for item in fact.limitations})

    @classmethod
    def _typed(
        cls,
        value: T,
        facts: Sequence[Fact],
        *,
        status: FreshnessStatus | CapabilityState,
        reason: str,
        limitations: Sequence[str] = (),
    ) -> TypedQueryResult[T]:
        return TypedQueryResult(
            status=status,
            value=None if status == FreshnessStatus.STALE else value,
            evidence_ids=sorted({fact.fact_id for fact in facts}),
            observed_at=min((fact.observed_at for fact in facts), default=None),
            fresh_until=min((fact.fresh_until for fact in facts), default=None),
            limitations=sorted(set(limitations) | set(cls._limitations(facts))),
            status_reason=reason,
        )

    @staticmethod
    def _fact_result(fact: Fact, *, now: datetime | None) -> QueryResult:
        return QueryResult(
            status=fact.freshness(now=now),
            value=fact.value,
            evidence_ids=[fact.fact_id],
            observed_at=fact.observed_at,
            fresh_until=fact.fresh_until,
            limitations=fact.limitations,
        )

    @staticmethod
    def _runtime_value(data: Mapping[str, Any]) -> dict[str, Any]:
        host = data.get("host") if isinstance(data.get("host"), Mapping) else {}
        os_release = (
            host.get("os_release") if isinstance(host.get("os_release"), Mapping) else {}
        )
        environment = (
            data.get("environment")
            if isinstance(data.get("environment"), Mapping)
            else {}
        )
        value = {
            "os_name": host.get("system") or data.get("os_name") or data.get("os"),
            "os_version": host.get("release") or data.get("os_version") or data.get("version"),
            "kernel": host.get("version") or data.get("kernel") or data.get("kernel_release"),
            "architecture": host.get("architecture")
            or data.get("architecture")
            or data.get("arch"),
            "hostname": host.get("hostname") or data.get("hostname"),
            "ros_distro": environment.get("ROS_DISTRO") or data.get("ros_distro"),
            "ros_version": environment.get("ROS_VERSION") or data.get("ros_version"),
            "ros_domain_id": environment.get("ROS_DOMAIN_ID")
            or data.get("ros_domain_id")
            or data.get("domain_id"),
            "rmw_implementation": environment.get("RMW_IMPLEMENTATION")
            or data.get("rmw_implementation")
            or data.get("rmw"),
        }
        if not value["os_version"] and os_release:
            value["os_version"] = os_release.get("VERSION_ID") or os_release.get("PRETTY_NAME")
        value = {key: raw for key, raw in value.items() if raw is not None}
        value.setdefault("state", "UNKNOWN")
        if value.get("ros_domain_id") is None:
            value["ros_domain_id"] = UnknownValue()
        if value.get("rmw_implementation") is None:
            value["rmw_implementation"] = UnknownValue()
        return value

    @classmethod
    def _endpoint_values(cls, data: Mapping[str, Any]) -> list[MiddlewareEndpointModel]:
        raw = data.get("endpoints", data.get("routes", data.get("topics", [])))
        raw = list(raw.values()) if isinstance(raw, Mapping) else raw
        result: list[MiddlewareEndpointModel] = []
        for index, candidate in enumerate(raw if isinstance(raw, list) else []):
            item = (
                dict(candidate) if isinstance(candidate, Mapping) else {"endpoint": str(candidate)}
            )
            endpoint = str(item.get("endpoint") or item.get("name") or item.get("topic") or "")
            item.setdefault("endpoint", endpoint)
            item.setdefault("route_id", item.get("id") or f"ros:{endpoint or index}")
            item.setdefault("interface", item.get("interface_type") or item.get("schema"))
            item.setdefault("stability", Stability.UNKNOWN)
            if not item.get("schema") and not item.get("interface"):
                item.setdefault("limitations", []).append("interface schema was not observed")
            result.append(MiddlewareEndpointModel.model_validate(item))
        return result

    @staticmethod
    def _relationship_values(data: Mapping[str, Any]) -> list[MiddlewareRelationshipModel]:
        raw = data.get("relationships", data.get("edges", []))
        raw = list(raw.values()) if isinstance(raw, Mapping) else raw
        result: list[MiddlewareRelationshipModel] = []
        for index, candidate in enumerate(raw if isinstance(raw, list) else []):
            item = dict(candidate) if isinstance(candidate, Mapping) else {"source": str(candidate)}
            item.setdefault("relationship_id", item.get("id") or f"relationship:{index}")
            result.append(MiddlewareRelationshipModel.model_validate(item))
        return result

    @staticmethod
    def _capability_reason(state: CapabilityState, source: str) -> str:
        if state == CapabilityState.DISCOVERED_UNVERIFIED:
            return "static/declared source is not sufficient for eligibility"
        if state == CapabilityState.STALE:
            return "snapshot freshness or fingerprint changed"
        if state == CapabilityState.UNAVAILABLE:
            return "capability observation is unavailable"
        return f"capability state observed from {source}"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
