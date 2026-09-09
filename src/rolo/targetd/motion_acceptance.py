"""Fail-closed, zero-motion acceptance orchestration for physical providers.

This module performs a signed control-plane rehearsal only.  Its target
interface contains no velocity, motor, or generic provider invocation method.
A successful receipt proves that the rehearsal completed with zero provider
calls; it is deliberately not an authorization to move hardware.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .motion_safety import (
    MotionSafetyAdmissionRequest,
    MotionSafetyIntent,
    MotionSafetyPolicy,
    MotionSafetyTrustStore,
    compute_direct_motor_fence_digest,
    compute_motion_payload_digest,
    evaluate_motion_safety,
)

_IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_IDENTITY = r"^/?[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,254}$"
_ROUTE = r"^/[A-Za-z0-9_./-]{1,126}$"
_INTERFACE = r"^[A-Za-z][A-Za-z0-9_]*/[A-Za-z][A-Za-z0-9_]*/[A-Za-z][A-Za-z0-9_]*$"
_SHA256 = r"^sha256:[0-9a-f]{64}$"
_HMAC_SHA256 = r"^hmac-sha256:[0-9a-f]{64}$"
_GID = r"^[0-9A-Fa-f][0-9A-Fa-f.:-]{7,254}$"
_REQUIRED_COMMAND_ROUTE = "/cmd_vel"
_REQUIRED_COMPETING_COMMAND_ROUTE = "/controller/cmd_vel"
_REQUIRED_COMMAND_SUBSCRIBER = "/odom_publisher"
_REQUIRED_COMMAND_PUBLISHER = "/rolo_bounded_twist"
_REQUIRED_DIRECT_MOTOR_ROUTE = "/ros_robot_controller/set_motor"
_REQUIRED_DIRECT_MOTOR_PUBLISHER = "/odom_publisher"

ZeroMotionArtifactKind = Literal[
    "LIVE_ISOLATION_SNAPSHOT",
    "LIVE_FENCE_CAS",
    "ZERO_MOTION_START_ACK",
    "ZERO_MOTION_STOP_ACK",
    "ZERO_MOTION_ABORT_ACK",
    "DEBUG_USER_ATTESTED_ADMISSION",
    "LIVE_FENCE_RELEASE",
    "PROVIDER_GATE_CHALLENGE",
    "PROVIDER_GATE_CONSUMED",
]
ZeroMotionAcceptanceStatus = Literal["BLOCKED", "READY_FOR_PROVIDER_GATE"]
ProviderGateConsumptionStatus = Literal["BLOCKED", "CONSUMED"]
IsolationPhase = Literal["PRE_CAS", "POST_STOP"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _require_aware(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must include timezone")


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(_SHA256, value) is not None


def _is_exact_int(value: object, *, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def compute_armed_zero_provider_identity_digest(
    *,
    call_id: str,
    session_id: str,
    execution_subject_digest: str,
    publisher_identity: str,
    publisher_gid: str,
    provider_pid: int,
    provider_start_time_ticks: int,
    provider_runtime_sha256: str,
    provider_cmdline_sha256: str,
) -> str:
    """Bind one pre-armed process instance to its exact ROS publisher endpoint."""

    return compute_motion_payload_digest(
        {
            "schema_version": "rolo-landerpi-armed-zero-provider-identity/v1",
            "call_id": call_id,
            "session_id": session_id,
            "execution_subject_digest": execution_subject_digest,
            "publisher_identity": publisher_identity,
            "publisher_gid": publisher_gid,
            "provider_pid": provider_pid,
            "provider_start_time_ticks": provider_start_time_ticks,
            "provider_runtime_sha256": provider_runtime_sha256,
            "provider_cmdline_sha256": provider_cmdline_sha256,
        }
    )


class ArmedZeroProviderBinding(_StrictModel):
    schema_version: Literal["rolo-landerpi-armed-zero-provider-binding/v1"] = "rolo-landerpi-armed-zero-provider-binding/v1"
    call_id: str = Field(pattern=_IDENTIFIER)
    session_id: str = Field(pattern=_IDENTIFIER)
    execution_subject_digest: str = Field(pattern=_SHA256)
    publisher_identity: str = Field(pattern=_IDENTITY)
    publisher_gid: str = Field(pattern=_GID)
    provider_pid: int = Field(ge=1, le=2_147_483_647)
    provider_start_time_ticks: int = Field(ge=1, le=(1 << 63) - 1)
    provider_runtime_sha256: str = Field(pattern=_SHA256)
    provider_cmdline_sha256: str = Field(pattern=_SHA256)
    provider_runtime_identity_digest: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_runtime_identity(self) -> ArmedZeroProviderBinding:
        expected = compute_armed_zero_provider_identity_digest(
            call_id=self.call_id,
            session_id=self.session_id,
            execution_subject_digest=self.execution_subject_digest,
            publisher_identity=self.publisher_identity,
            publisher_gid=self.publisher_gid,
            provider_pid=self.provider_pid,
            provider_start_time_ticks=self.provider_start_time_ticks,
            provider_runtime_sha256=self.provider_runtime_sha256,
            provider_cmdline_sha256=self.provider_cmdline_sha256,
        )
        if self.provider_runtime_identity_digest != expected:
            raise ValueError("armed-zero provider runtime identity digest mismatch")
        return self


class ZeroMotionAcceptanceRequest(_StrictModel):
    """One exact static admission request plus a unique rehearsal identity."""

    schema_version: Literal["rolo-targetd-zero-motion-acceptance-request/v1"] = "rolo-targetd-zero-motion-acceptance-request/v1"
    acceptance_id: str = Field(pattern=_IDENTIFIER)
    admission: MotionSafetyAdmissionRequest

    @model_validator(mode="after")
    def validate_canonical_bounds(self) -> ZeroMotionAcceptanceRequest:
        try:
            compute_motion_payload_digest(self.model_dump(mode="python"))
        except (TypeError, ValueError) as exc:
            raise ValueError("zero-motion acceptance request exceeds canonical limits") from exc
        return self


class SignedZeroMotionArtifact(_StrictModel):
    """Signed, bounded target artifact bound to one exact call and rehearsal."""

    schema_version: Literal["rolo-targetd-zero-motion-artifact/v1"] = "rolo-targetd-zero-motion-artifact/v1"
    artifact_id: str = Field(pattern=_IDENTIFIER)
    kind: ZeroMotionArtifactKind
    issuer_id: str = Field(pattern=_IDENTITY)
    acceptance_id: str = Field(pattern=_IDENTIFIER)
    call_id: str = Field(pattern=_IDENTIFIER)
    session_id: str = Field(pattern=_IDENTIFIER)
    target_id: str = Field(pattern=_IDENTIFIER)
    target_identity: str = Field(pattern=_IDENTITY)
    operator_id: str = Field(pattern=_IDENTITY)
    execution_subject_digest: str = Field(pattern=_SHA256)
    ros_graph_digest: str = Field(pattern=_SHA256)
    command_route: str = Field(pattern=_ROUTE)
    command_interface: str = Field(pattern=_INTERFACE)
    publisher_identity: str = Field(pattern=_IDENTITY)
    direct_motor_route: str = Field(pattern=_ROUTE)
    direct_motor_interface: str = Field(pattern=_INTERFACE)
    direct_motor_publisher_identity: str = Field(pattern=_IDENTITY)
    issued_at: datetime
    expires_at: datetime
    claims: dict[str, Any] = Field(max_length=32)
    payload_sha256: str = Field(pattern=_SHA256)
    signature_hmac_sha256: str = Field(pattern=_HMAC_SHA256)

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="python",
            exclude={"payload_sha256", "signature_hmac_sha256"},
        )

    @model_validator(mode="after")
    def validate_integrity(self) -> SignedZeroMotionArtifact:
        _require_aware(self.issued_at, "issued_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ValueError("artifact expiry must be after issue time")
        try:
            expected = compute_motion_payload_digest(self.unsigned_payload())
        except (TypeError, ValueError) as exc:
            raise ValueError("zero-motion artifact payload is not canonical JSON") from exc
        if not hmac.compare_digest(expected, self.payload_sha256):
            raise ValueError("zero-motion artifact payload digest mismatch")
        return self

    @classmethod
    def build(
        cls,
        *,
        artifact_id: str,
        kind: ZeroMotionArtifactKind,
        issuer_id: str,
        acceptance_id: str,
        intent: MotionSafetyIntent,
        issued_at: datetime,
        expires_at: datetime,
        claims: dict[str, Any],
        signing_key: bytes,
    ) -> SignedZeroMotionArtifact:
        """Build a fixture or adapter artifact; production keys stay target-side."""

        if not isinstance(signing_key, bytes) or not 32 <= len(signing_key) <= 4096:
            raise ValueError("zero-motion artifact signing key size is outside safe bounds")
        unsigned: dict[str, Any] = {
            "schema_version": "rolo-targetd-zero-motion-artifact/v1",
            "artifact_id": artifact_id,
            "kind": kind,
            "issuer_id": issuer_id,
            "acceptance_id": acceptance_id,
            "call_id": intent.call_id,
            "session_id": intent.session_id,
            "target_id": intent.target_id,
            "target_identity": intent.target_identity,
            "operator_id": intent.operator_id,
            "execution_subject_digest": intent.execution_subject_digest,
            "ros_graph_digest": intent.ros_graph_digest,
            "command_route": intent.command_route,
            "command_interface": intent.command_interface,
            "publisher_identity": intent.publisher_identity,
            "direct_motor_route": intent.direct_motor_route,
            "direct_motor_interface": intent.direct_motor_interface,
            "direct_motor_publisher_identity": intent.direct_motor_publisher_identity,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "claims": claims,
        }
        payload_sha256 = compute_motion_payload_digest(unsigned)
        signature = hmac.new(
            signing_key,
            payload_sha256.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return cls.model_validate(
            {
                **unsigned,
                "payload_sha256": payload_sha256,
                "signature_hmac_sha256": f"hmac-sha256:{signature}",
            }
        )


class ZeroMotionArtifactDigests(_StrictModel):
    pre_isolation_snapshot: str | None = Field(default=None, pattern=_SHA256)
    fence_cas: str | None = Field(default=None, pattern=_SHA256)
    start_ack: str | None = Field(default=None, pattern=_SHA256)
    stop_ack: str | None = Field(default=None, pattern=_SHA256)
    post_stop_isolation_snapshot: str | None = Field(default=None, pattern=_SHA256)
    fence_release: str | None = Field(default=None, pattern=_SHA256)
    provider_gate_challenge: str | None = Field(default=None, pattern=_SHA256)

    def complete(self) -> bool:
        return all(
            value is not None
            for value in (
                self.pre_isolation_snapshot,
                self.fence_cas,
                self.start_ack,
                self.stop_ack,
                self.post_stop_isolation_snapshot,
                self.fence_release,
                self.provider_gate_challenge,
            )
        )


class ZeroMotionAcceptanceReceipt(_StrictModel):
    """Outcome of a rehearsal.  Even success never grants physical motion."""

    schema_version: Literal["rolo-targetd-zero-motion-acceptance-receipt/v1"] = "rolo-targetd-zero-motion-acceptance-receipt/v1"
    status: ZeroMotionAcceptanceStatus = "BLOCKED"
    reasons: tuple[str, ...] = ("ZERO_MOTION_ACCEPTANCE_REQUIRED",)
    evaluated_at: datetime
    acceptance_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    call_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    session_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    target_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    target_identity: str | None = Field(default=None, pattern=_IDENTITY)
    operator_id: str | None = Field(default=None, pattern=_IDENTITY)
    execution_subject_digest: str | None = Field(default=None, pattern=_SHA256)
    ros_graph_digest: str | None = Field(default=None, pattern=_SHA256)
    command_route: str | None = Field(default=None, pattern=_ROUTE)
    command_interface: str | None = Field(default=None, pattern=_INTERFACE)
    publisher_identity: str | None = Field(default=None, pattern=_IDENTITY)
    direct_motor_route: str | None = Field(default=None, pattern=_ROUTE)
    direct_motor_interface: str | None = Field(default=None, pattern=_INTERFACE)
    direct_motor_publisher_identity: str | None = Field(default=None, pattern=_IDENTITY)
    static_decision_digest: str | None = Field(default=None, pattern=_SHA256)
    static_evidence_digests: tuple[str, ...] = ()
    artifacts: ZeroMotionArtifactDigests = Field(default_factory=ZeroMotionArtifactDigests)
    provider_gate: SignedZeroMotionArtifact | None = None
    provider_invocation_count: Literal[0] = 0
    motion_command_emitted: Literal[False] = False
    motion_authorized: Literal[False] = False
    requires_live_provider_cas: Literal[True] = True

    @model_validator(mode="after")
    def validate_receipt(self) -> ZeroMotionAcceptanceReceipt:
        _require_aware(self.evaluated_at, "evaluated_at")
        if self.status == "READY_FOR_PROVIDER_GATE":
            if self.reasons:
                raise ValueError("ready zero-motion receipt cannot contain blockers")
            if None in (
                self.acceptance_id,
                self.call_id,
                self.session_id,
                self.target_id,
                self.target_identity,
                self.operator_id,
                self.execution_subject_digest,
                self.ros_graph_digest,
                self.command_route,
                self.command_interface,
                self.publisher_identity,
                self.direct_motor_route,
                self.direct_motor_interface,
                self.direct_motor_publisher_identity,
                self.static_decision_digest,
            ):
                raise ValueError("ready zero-motion receipt must retain exact identity")
            if len(self.static_evidence_digests) != 7:
                raise ValueError("ready zero-motion receipt requires all static evidence")
            if not self.artifacts.complete():
                raise ValueError("ready zero-motion receipt requires every live artifact")
            if self.provider_gate is None or self.provider_gate.kind != "PROVIDER_GATE_CHALLENGE":
                raise ValueError("ready zero-motion receipt requires a signed provider gate")
            if self.artifacts.provider_gate_challenge != self.provider_gate.payload_sha256:
                raise ValueError("ready zero-motion receipt provider gate digest mismatch")
        elif not self.reasons:
            raise ValueError("blocked zero-motion receipt requires at least one reason")
        try:
            compute_motion_payload_digest(self.model_dump(mode="python"))
        except (TypeError, ValueError) as exc:
            raise ValueError("zero-motion receipt exceeds canonical limits") from exc
        return self

    @property
    def ready_for_provider_gate(self) -> bool:
        return self.status == "READY_FOR_PROVIDER_GATE"


class ProviderGateConsumptionReceipt(_StrictModel):
    """One-shot fresh-CAS result that may precede exactly one provider call."""

    schema_version: Literal["rolo-targetd-provider-gate-consumption/v1"] = "rolo-targetd-provider-gate-consumption/v1"
    status: ProviderGateConsumptionStatus = "BLOCKED"
    reasons: tuple[str, ...] = ("PROVIDER_GATE_CHALLENGE_REQUIRED",)
    evaluated_at: datetime
    acceptance_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    call_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    session_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    target_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    target_identity: str | None = Field(default=None, pattern=_IDENTITY)
    operator_id: str | None = Field(default=None, pattern=_IDENTITY)
    execution_subject_digest: str | None = Field(default=None, pattern=_SHA256)
    ros_graph_digest: str | None = Field(default=None, pattern=_SHA256)
    command_route: str | None = Field(default=None, pattern=_ROUTE)
    command_interface: str | None = Field(default=None, pattern=_INTERFACE)
    publisher_identity: str | None = Field(default=None, pattern=_IDENTITY)
    direct_motor_route: str | None = Field(default=None, pattern=_ROUTE)
    direct_motor_interface: str | None = Field(default=None, pattern=_INTERFACE)
    direct_motor_publisher_identity: str | None = Field(default=None, pattern=_IDENTITY)
    challenge_artifact_digest: str | None = Field(default=None, pattern=_SHA256)
    provider_fence_digest: str | None = Field(default=None, pattern=_SHA256)
    consume_artifact: SignedZeroMotionArtifact | None = None
    provider_boundary_open: bool = False
    provider_invocation_limit: Literal[1] = 1
    motion_authorized: Literal[False] = False

    @model_validator(mode="after")
    def validate_consumption(self) -> ProviderGateConsumptionReceipt:
        _require_aware(self.evaluated_at, "evaluated_at")
        if self.status == "CONSUMED":
            if self.reasons or self.provider_boundary_open is not True:
                raise ValueError("consumed provider gate must be open without blockers")
            if None in (
                self.acceptance_id,
                self.call_id,
                self.session_id,
                self.target_id,
                self.target_identity,
                self.operator_id,
                self.execution_subject_digest,
                self.ros_graph_digest,
                self.command_route,
                self.command_interface,
                self.publisher_identity,
                self.direct_motor_route,
                self.direct_motor_interface,
                self.direct_motor_publisher_identity,
                self.challenge_artifact_digest,
                self.provider_fence_digest,
                self.consume_artifact,
            ):
                raise ValueError("consumed provider gate must retain exact identity and artifact")
            assert self.consume_artifact is not None
            if self.consume_artifact.kind != "PROVIDER_GATE_CONSUMED":
                raise ValueError("provider gate consume artifact kind is invalid")
        elif not self.reasons or self.provider_boundary_open:
            raise ValueError("blocked provider gate must stay closed with a reason")
        try:
            compute_motion_payload_digest(self.model_dump(mode="python"))
        except (TypeError, ValueError) as exc:
            raise ValueError("provider gate consumption exceeds canonical limits") from exc
        return self

    @property
    def consumed(self) -> bool:
        return self.status == "CONSUMED" and self.provider_boundary_open


class Ros2TopicEndpointSnapshot(_StrictModel):
    """Bounded endpoint identities parsed from one read-only ROS2 query."""

    schema_version: Literal["rolo-ros2-topic-endpoint-snapshot/v1"] = "rolo-ros2-topic-endpoint-snapshot/v1"
    route: str = Field(pattern=_ROUTE)
    interface: str = Field(pattern=_INTERFACE)
    publisher_count: int = Field(ge=0, le=64)
    publisher_identities: tuple[str, ...] = Field(max_length=64)
    publisher_gids: tuple[str, ...] = Field(max_length=64)
    subscriber_count: int = Field(ge=0, le=64)
    subscriber_identities: tuple[str, ...] = Field(max_length=64)
    subscriber_gids: tuple[str, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def validate_counts(self) -> Ros2TopicEndpointSnapshot:
        if self.publisher_count != len(self.publisher_identities):
            raise ValueError("ROS2 publisher count does not match endpoint records")
        if self.publisher_count != len(self.publisher_gids):
            raise ValueError("ROS2 publisher count does not match endpoint GIDs")
        if self.subscriber_count != len(self.subscriber_identities):
            raise ValueError("ROS2 subscriber count does not match endpoint records")
        if self.subscriber_count != len(self.subscriber_gids):
            raise ValueError("ROS2 subscriber count does not match endpoint GIDs")
        for identity in (*self.publisher_identities, *self.subscriber_identities):
            if re.fullmatch(_IDENTITY, identity) is None:
                raise ValueError("ROS2 endpoint identity is invalid")
        gids = (*self.publisher_gids, *self.subscriber_gids)
        if any(re.fullmatch(_GID, gid) is None for gid in gids) or len(gids) != len(set(gids)):
            raise ValueError("ROS2 endpoint GID is invalid or duplicated")
        return self


class LanderPiIsolationObservation(_StrictModel):
    """Read-only snapshot of every known LanderPi drive-control ingress."""

    schema_version: Literal["rolo-landerpi-isolation-observation/v1"] = "rolo-landerpi-isolation-observation/v1"
    target_id: str = Field(pattern=_IDENTIFIER)
    target_identity: str = Field(pattern=_IDENTITY)
    observed_at: datetime
    command: Ros2TopicEndpointSnapshot
    competing_command: Ros2TopicEndpointSnapshot
    direct_motor: Ros2TopicEndpointSnapshot
    graph_revision: str = Field(pattern=_SHA256)
    live_isolation_digest: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_observation(self) -> LanderPiIsolationObservation:
        _require_aware(self.observed_at, "observed_at")
        if self.command.route != _REQUIRED_COMMAND_ROUTE:
            raise ValueError("controlled command route is not the LanderPi route")
        if self.competing_command.route != _REQUIRED_COMPETING_COMMAND_ROUTE:
            raise ValueError("competing command route is not the LanderPi route")
        if self.direct_motor.route != _REQUIRED_DIRECT_MOTOR_ROUTE:
            raise ValueError("direct motor route is not the LanderPi route")
        all_gids = tuple(gid for snapshot in (self.command, self.competing_command, self.direct_motor) for gid in (*snapshot.publisher_gids, *snapshot.subscriber_gids))
        if len(all_gids) != len(set(all_gids)):
            raise ValueError("LanderPi graph contains a duplicated endpoint GID")
        expected_revision = _compute_graph_revision(
            target_id=self.target_id,
            target_identity=self.target_identity,
            snapshots=(self.command, self.competing_command, self.direct_motor),
        )
        if self.graph_revision != expected_revision:
            raise ValueError("LanderPi graph revision digest mismatch")
        expected_live = compute_zero_motion_isolation_digest(
            target_id=self.target_id,
            target_identity=self.target_identity,
            observed_at=self.observed_at,
            command_route=self.command.route,
            command_interface=self.command.interface,
            publisher_identities=self.command.publisher_identities,
            subscriber_identities=self.command.subscriber_identities,
            competing_command_route=self.competing_command.route,
            competing_command_interface=self.competing_command.interface,
            competing_publisher_identities=self.competing_command.publisher_identities,
            competing_subscriber_identities=self.competing_command.subscriber_identities,
            direct_motor_route=self.direct_motor.route,
            direct_motor_interface=self.direct_motor.interface,
            direct_motor_publisher_identities=self.direct_motor.publisher_identities,
            command_publisher_gids=self.command.publisher_gids,
            command_subscriber_gids=self.command.subscriber_gids,
            competing_publisher_gids=self.competing_command.publisher_gids,
            competing_subscriber_gids=self.competing_command.subscriber_gids,
            direct_motor_publisher_gids=self.direct_motor.publisher_gids,
        )
        if self.live_isolation_digest != expected_live:
            raise ValueError("LanderPi live isolation digest mismatch")
        return self

    def artifact_claims(
        self,
        *,
        phase: IsolationPhase,
        fence_epoch: int,
        active_fence_digest: str,
        fence_owner_call_id: str,
    ) -> dict[str, Any]:
        """Return the exact claim shape accepted by the signed orchestrator."""

        return {
            "phase": phase,
            "command_route": self.command.route,
            "command_interface": self.command.interface,
            "publisher_identities": list(self.command.publisher_identities),
            "publisher_gids": list(self.command.publisher_gids),
            "subscriber_identities": list(self.command.subscriber_identities),
            "subscriber_gids": list(self.command.subscriber_gids),
            "competing_command_route": self.competing_command.route,
            "competing_command_interface": self.competing_command.interface,
            "competing_publisher_identities": list(self.competing_command.publisher_identities),
            "competing_publisher_gids": list(self.competing_command.publisher_gids),
            "competing_subscriber_identities": list(self.competing_command.subscriber_identities),
            "competing_subscriber_gids": list(self.competing_command.subscriber_gids),
            "direct_motor_route": self.direct_motor.route,
            "direct_motor_interface": self.direct_motor.interface,
            "direct_motor_publisher_identities": list(self.direct_motor.publisher_identities),
            "direct_motor_publisher_gids": list(self.direct_motor.publisher_gids),
            "graph_revision": self.graph_revision,
            "live_ros_graph_digest": self.live_isolation_digest,
            "fence_epoch": fence_epoch,
            "active_fence_digest": active_fence_digest,
            "fence_owner_call_id": fence_owner_call_id,
            "motion_enabled": False,
            "provider_invocation_count": 0,
        }


class ZeroMotionTarget(Protocol):
    """Narrow target SPI.  Implementations must never publish or call a provider."""

    def observe_isolation(
        self,
        *,
        acceptance_id: str,
        intent: MotionSafetyIntent,
        policy: MotionSafetyPolicy,
        phase: IsolationPhase,
        fence_binding_digest: str | None,
    ) -> SignedZeroMotionArtifact | Mapping[str, Any]: ...

    def compare_and_set_fence(
        self,
        *,
        acceptance_id: str,
        intent: MotionSafetyIntent,
        policy: MotionSafetyPolicy,
        snapshot_artifact_digest: str,
    ) -> SignedZeroMotionArtifact | Mapping[str, Any]: ...

    def acknowledge_zero_motion_start(
        self,
        *,
        acceptance_id: str,
        intent: MotionSafetyIntent,
        fence_cas_artifact_digest: str,
    ) -> SignedZeroMotionArtifact | Mapping[str, Any]: ...

    def acknowledge_zero_motion_stop(
        self,
        *,
        acceptance_id: str,
        intent: MotionSafetyIntent,
        fence_cas_artifact_digest: str,
        start_ack_artifact_digest: str,
    ) -> SignedZeroMotionArtifact | Mapping[str, Any]: ...

    def release_fence(
        self,
        *,
        acceptance_id: str,
        intent: MotionSafetyIntent,
        fence_cas_artifact_digest: str,
        stop_ack_artifact_digest: str,
        post_snapshot_artifact_digest: str,
    ) -> SignedZeroMotionArtifact | Mapping[str, Any]: ...

    def issue_provider_gate_challenge(
        self,
        *,
        acceptance_id: str,
        intent: MotionSafetyIntent,
        release_artifact_digest: str,
        post_snapshot_artifact_digest: str,
        released_fence_digest: str,
        released_fence_epoch: int,
        expected_graph_revision: str,
    ) -> SignedZeroMotionArtifact | Mapping[str, Any]: ...

    def compare_and_set_provider_gate(
        self,
        *,
        acceptance_id: str,
        intent: MotionSafetyIntent,
        policy: MotionSafetyPolicy,
        challenge_artifact_digest: str,
        consume_token_digest: str,
    ) -> SignedZeroMotionArtifact | Mapping[str, Any]:
        """Atomically consume once, compare live graph/fence, and install a short fence.

        Implementations must perform all state changes target-side and must not
        call the provider or publish a command as part of this operation.
        """
        ...

    def abort_zero_motion(
        self,
        *,
        acceptance_id: str,
        intent: MotionSafetyIntent,
    ) -> None: ...


def compute_zero_motion_fence_lease_digest(
    *,
    acceptance_id: str,
    intent: MotionSafetyIntent,
    snapshot_artifact_digest: str,
    live_ros_graph_digest: str,
    graph_revision: str,
    expected_fence_digest: str,
    fence_epoch: int,
) -> str:
    """Digest the one-call lease produced by the target-side live CAS."""

    return compute_motion_payload_digest(
        {
            "schema_version": "rolo-zero-motion-fence-lease/v1",
            "acceptance_id": acceptance_id,
            "call_id": intent.call_id,
            "session_id": intent.session_id,
            "target_id": intent.target_id,
            "target_identity": intent.target_identity,
            "operator_id": intent.operator_id,
            "execution_subject_digest": intent.execution_subject_digest,
            "baseline_ros_graph_digest": intent.ros_graph_digest,
            "command_route": intent.command_route,
            "command_interface": intent.command_interface,
            "publisher_identity": intent.publisher_identity,
            "direct_motor_route": intent.direct_motor_route,
            "direct_motor_interface": intent.direct_motor_interface,
            "direct_motor_publisher_identity": intent.direct_motor_publisher_identity,
            "snapshot_artifact_digest": snapshot_artifact_digest,
            "live_ros_graph_digest": live_ros_graph_digest,
            "graph_revision": graph_revision,
            "expected_fence_digest": expected_fence_digest,
            "fence_epoch": fence_epoch,
        }
    )


def compute_zero_motion_isolation_digest(
    *,
    target_id: str,
    target_identity: str,
    observed_at: datetime,
    command_route: str,
    command_interface: str,
    publisher_identities: list[str] | tuple[str, ...],
    subscriber_identities: list[str] | tuple[str, ...],
    competing_command_route: str,
    competing_command_interface: str,
    competing_publisher_identities: list[str] | tuple[str, ...],
    competing_subscriber_identities: list[str] | tuple[str, ...],
    direct_motor_route: str,
    direct_motor_interface: str,
    direct_motor_publisher_identities: list[str] | tuple[str, ...],
    command_publisher_gids: list[str] | tuple[str, ...] = (),
    command_subscriber_gids: list[str] | tuple[str, ...] = (),
    competing_publisher_gids: list[str] | tuple[str, ...] = (),
    competing_subscriber_gids: list[str] | tuple[str, ...] = (),
    direct_motor_publisher_gids: list[str] | tuple[str, ...] = (),
) -> str:
    """Digest all live LanderPi paths that can reach physical drive output."""

    return compute_motion_payload_digest(
        {
            "schema_version": "rolo-zero-motion-isolation-snapshot/v1",
            "target_id": target_id,
            "target_identity": target_identity,
            "observed_at": observed_at,
            "command_route": command_route,
            "command_interface": command_interface,
            "publisher_identities": sorted(publisher_identities),
            "subscriber_identities": sorted(subscriber_identities),
            "competing_command_route": competing_command_route,
            "competing_command_interface": competing_command_interface,
            "competing_publisher_identities": sorted(competing_publisher_identities),
            "competing_subscriber_identities": sorted(competing_subscriber_identities),
            "direct_motor_route": direct_motor_route,
            "direct_motor_interface": direct_motor_interface,
            "direct_motor_publisher_identities": sorted(direct_motor_publisher_identities),
            "command_publisher_gids": sorted(command_publisher_gids),
            "command_subscriber_gids": sorted(command_subscriber_gids),
            "competing_publisher_gids": sorted(competing_publisher_gids),
            "competing_subscriber_gids": sorted(competing_subscriber_gids),
            "direct_motor_publisher_gids": sorted(direct_motor_publisher_gids),
        }
    )


def _compute_graph_revision(
    *,
    target_id: str,
    target_identity: str,
    snapshots: tuple[Ros2TopicEndpointSnapshot, ...],
) -> str:
    return compute_motion_payload_digest(
        {
            "schema_version": "rolo-landerpi-drive-graph-revision/v1",
            "target_id": target_id,
            "target_identity": target_identity,
            "topics": [snapshot.model_dump(mode="python") for snapshot in snapshots],
        }
    )


def _ros_node_identity(name: str, namespace: str) -> str:
    clean_name = name.strip().strip("/")
    clean_namespace = namespace.strip()
    if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,127}", clean_name) is None:
        raise ValueError("ROS2 endpoint node name is invalid")
    if re.fullmatch(r"/(?:[A-Za-z0-9_][A-Za-z0-9_-]*/?)*", clean_namespace) is None:
        raise ValueError("ROS2 endpoint node namespace is invalid")
    prefix = clean_namespace.rstrip("/")
    identity = f"{prefix}/{clean_name}" if prefix else f"/{clean_name}"
    if re.fullmatch(_IDENTITY, identity) is None:
        raise ValueError("ROS2 endpoint identity is invalid")
    return identity


def parse_ros2_topic_info_verbose(
    output: str,
    *,
    route: str,
    expected_interface: str,
) -> Ros2TopicEndpointSnapshot:
    """Parse bounded ``ros2 topic info --verbose`` text without guessing."""

    if not isinstance(output, str) or not output or len(output.encode("utf-8")) > 64 * 1024:
        raise ValueError("ROS2 topic info output is missing or oversized")
    if "\x00" in output:
        raise ValueError("ROS2 topic info output contains a NUL byte")
    if re.fullmatch(_ROUTE, route) is None or re.fullmatch(_INTERFACE, expected_interface) is None:
        raise ValueError("ROS2 topic route or interface is invalid")
    lines = output.splitlines()
    if len(lines) > 2048 or any(len(line.encode("utf-8")) > 4096 for line in lines):
        raise ValueError("ROS2 topic info output exceeds line bounds")

    types = re.findall(r"(?m)^Type:\s*(\S+)\s*$", output)
    publisher_counts = re.findall(r"(?m)^Publisher count:\s*(\d+)\s*$", output)
    subscriber_counts = re.findall(r"(?m)^Subscription count:\s*(\d+)\s*$", output)
    if len(types) != 1 or types[0] != expected_interface:
        raise ValueError("ROS2 topic interface is missing or mismatched")
    if len(publisher_counts) != 1 or len(subscriber_counts) != 1:
        raise ValueError("ROS2 endpoint counts are missing or ambiguous")
    publisher_count = int(publisher_counts[0])
    subscriber_count = int(subscriber_counts[0])
    if publisher_count > 64 or subscriber_count > 64:
        raise ValueError("ROS2 endpoint count exceeds safe bounds")

    records: list[dict[str, str]] = []
    current: dict[str, str] | None = None

    def finish_record() -> None:
        nonlocal current
        if current is None:
            return
        if set(current) != {"name", "namespace", "endpoint_type", "gid"}:
            raise ValueError("ROS2 endpoint record is incomplete")
        records.append(current)
        current = None

    for raw_line in lines:
        line = raw_line.strip()
        if line.startswith("Node name:"):
            finish_record()
            current = {"name": line.partition(":")[2].strip()}
        elif line.startswith("Node namespace:") and current is not None:
            if "namespace" in current:
                raise ValueError("ROS2 endpoint namespace is duplicated")
            current["namespace"] = line.partition(":")[2].strip()
        elif line.startswith("Endpoint type:") and current is not None:
            if "endpoint_type" in current:
                raise ValueError("ROS2 endpoint type is duplicated")
            current["endpoint_type"] = line.partition(":")[2].strip().upper()
        elif line.startswith("GID:") and current is not None:
            if "gid" in current:
                raise ValueError("ROS2 endpoint GID is duplicated")
            current["gid"] = line.partition(":")[2].strip()
    finish_record()

    publishers: list[str] = []
    subscribers: list[str] = []
    publisher_gids: list[str] = []
    subscriber_gids: list[str] = []
    for record in records:
        identity = _ros_node_identity(record["name"], record["namespace"])
        if record["endpoint_type"] == "PUBLISHER":
            publishers.append(identity)
            publisher_gids.append(record["gid"])
        elif record["endpoint_type"] == "SUBSCRIPTION":
            subscribers.append(identity)
            subscriber_gids.append(record["gid"])
        else:
            raise ValueError("ROS2 endpoint type is unsupported")
    if len(publishers) != publisher_count or len(subscribers) != subscriber_count:
        raise ValueError("ROS2 endpoint records do not match declared counts")
    return Ros2TopicEndpointSnapshot(
        route=route,
        interface=expected_interface,
        publisher_count=publisher_count,
        publisher_identities=tuple(sorted(publishers)),
        publisher_gids=tuple(sorted(publisher_gids)),
        subscriber_count=subscriber_count,
        subscriber_identities=tuple(sorted(subscribers)),
        subscriber_gids=tuple(sorted(subscriber_gids)),
    )


def capture_landerpi_isolation_observation(
    run_read_only: Callable[[tuple[str, ...]], str],
    *,
    policy: MotionSafetyPolicy,
    observed_at: datetime | None = None,
) -> LanderPiIsolationObservation:
    """Capture all three drive paths using only ROS2 graph-info commands.

    ``run_read_only`` may wrap local execution or SSH, but must return stdout
    for the exact argv supplied.  No default runner exists, so importing or
    testing this module can never contact a robot.
    """

    if not callable(run_read_only):
        raise ValueError("read-only ROS2 command runner is required")
    point = _point(observed_at)
    if point is None:
        raise ValueError("observation time must include timezone")
    if (
        policy.command_route != _REQUIRED_COMMAND_ROUTE
        or policy.allowed_publisher_identity != _REQUIRED_COMMAND_PUBLISHER
        or policy.direct_motor_route != _REQUIRED_DIRECT_MOTOR_ROUTE
        or policy.allowed_direct_motor_publisher_identity != _REQUIRED_DIRECT_MOTOR_PUBLISHER
    ):
        raise ValueError("policy does not name the fixed LanderPi drive topology")
    topic_specs = (
        (_REQUIRED_COMMAND_ROUTE, policy.command_interface),
        (_REQUIRED_COMPETING_COMMAND_ROUTE, policy.command_interface),
        (_REQUIRED_DIRECT_MOTOR_ROUTE, policy.direct_motor_interface),
    )
    snapshots = tuple(
        parse_ros2_topic_info_verbose(
            run_read_only(("ros2", "topic", "info", route, "--verbose")),
            route=route,
            expected_interface=interface,
        )
        for route, interface in topic_specs
    )
    revision = _compute_graph_revision(
        target_id=policy.target_id,
        target_identity=policy.target_identity,
        snapshots=snapshots,
    )
    command, competing, direct = snapshots
    live_digest = compute_zero_motion_isolation_digest(
        target_id=policy.target_id,
        target_identity=policy.target_identity,
        observed_at=point,
        command_route=command.route,
        command_interface=command.interface,
        publisher_identities=command.publisher_identities,
        subscriber_identities=command.subscriber_identities,
        competing_command_route=competing.route,
        competing_command_interface=competing.interface,
        competing_publisher_identities=competing.publisher_identities,
        competing_subscriber_identities=competing.subscriber_identities,
        direct_motor_route=direct.route,
        direct_motor_interface=direct.interface,
        direct_motor_publisher_identities=direct.publisher_identities,
        command_publisher_gids=command.publisher_gids,
        command_subscriber_gids=command.subscriber_gids,
        competing_publisher_gids=competing.publisher_gids,
        competing_subscriber_gids=competing.subscriber_gids,
        direct_motor_publisher_gids=direct.publisher_gids,
    )
    return LanderPiIsolationObservation(
        target_id=policy.target_id,
        target_identity=policy.target_identity,
        observed_at=point,
        command=command,
        competing_command=competing,
        direct_motor=direct,
        graph_revision=revision,
        live_isolation_digest=live_digest,
    )


def compute_provider_gate_consume_token_digest(
    *,
    acceptance_id: str,
    intent: MotionSafetyIntent,
    release_artifact_digest: str,
    post_snapshot_artifact_digest: str,
    expected_fence_digest: str,
    expected_fence_epoch: int,
    expected_graph_revision: str,
    expires_at: datetime,
) -> str:
    """Bind the target-issued, one-shot provider-gate consume operation."""

    return compute_motion_payload_digest(
        {
            "schema_version": "rolo-provider-gate-consume-token/v1",
            "acceptance_id": acceptance_id,
            "call_id": intent.call_id,
            "session_id": intent.session_id,
            "target_id": intent.target_id,
            "target_identity": intent.target_identity,
            "operator_id": intent.operator_id,
            "execution_subject_digest": intent.execution_subject_digest,
            "baseline_ros_graph_digest": intent.ros_graph_digest,
            "command_route": intent.command_route,
            "command_interface": intent.command_interface,
            "publisher_identity": intent.publisher_identity,
            "direct_motor_route": intent.direct_motor_route,
            "direct_motor_interface": intent.direct_motor_interface,
            "direct_motor_publisher_identity": intent.direct_motor_publisher_identity,
            "release_artifact_digest": release_artifact_digest,
            "post_snapshot_artifact_digest": post_snapshot_artifact_digest,
            "expected_fence_digest": expected_fence_digest,
            "expected_fence_epoch": expected_fence_epoch,
            "expected_graph_revision": expected_graph_revision,
            "expires_at": expires_at,
        }
    )


def compute_provider_fence_digest(
    *,
    acceptance_id: str,
    intent: MotionSafetyIntent,
    challenge_artifact_digest: str,
    consume_token_digest: str,
    live_isolation_digest: str,
    graph_revision: str,
    expected_fence_digest: str,
    fence_epoch: int,
) -> str:
    """Digest the fresh one-shot fence installed at the provider boundary."""

    return compute_motion_payload_digest(
        {
            "schema_version": "rolo-provider-boundary-fence/v1",
            "acceptance_id": acceptance_id,
            "call_id": intent.call_id,
            "session_id": intent.session_id,
            "target_id": intent.target_id,
            "target_identity": intent.target_identity,
            "operator_id": intent.operator_id,
            "execution_subject_digest": intent.execution_subject_digest,
            "baseline_ros_graph_digest": intent.ros_graph_digest,
            "command_route": intent.command_route,
            "command_interface": intent.command_interface,
            "publisher_identity": intent.publisher_identity,
            "direct_motor_route": intent.direct_motor_route,
            "direct_motor_interface": intent.direct_motor_interface,
            "direct_motor_publisher_identity": intent.direct_motor_publisher_identity,
            "challenge_artifact_digest": challenge_artifact_digest,
            "consume_token_digest": consume_token_digest,
            "live_isolation_digest": live_isolation_digest,
            "graph_revision": graph_revision,
            "expected_fence_digest": expected_fence_digest,
            "fence_epoch": fence_epoch,
        }
    )


def _call_fence_digest(intent: MotionSafetyIntent, fence_epoch: int) -> str:
    return compute_direct_motor_fence_digest(
        execution_subject_digest=intent.execution_subject_digest,
        call_id=intent.call_id,
        session_id=intent.session_id,
        target_id=intent.target_id,
        target_identity=intent.target_identity,
        ros_graph_digest=intent.ros_graph_digest,
        command_route=intent.command_route,
        publisher_identity=intent.publisher_identity,
        direct_motor_route=intent.direct_motor_route,
        direct_motor_interface=intent.direct_motor_interface,
        direct_motor_publisher_identity=intent.direct_motor_publisher_identity,
        fence_epoch=fence_epoch,
    )


def _point(now: datetime | None) -> datetime | None:
    point = datetime.now(timezone.utc) if now is None else now
    if not isinstance(point, datetime) or point.tzinfo is None or point.utcoffset() is None:
        return None
    return point.astimezone(timezone.utc)


def _request_identity(request: ZeroMotionAcceptanceRequest | None) -> dict[str, Any]:
    if request is None:
        return {}
    intent = request.admission.intent
    return {
        "acceptance_id": request.acceptance_id,
        "call_id": intent.call_id,
        "session_id": intent.session_id,
        "target_id": intent.target_id,
        "target_identity": intent.target_identity,
        "operator_id": intent.operator_id,
        "execution_subject_digest": intent.execution_subject_digest,
        "ros_graph_digest": intent.ros_graph_digest,
        "command_route": intent.command_route,
        "command_interface": intent.command_interface,
        "publisher_identity": intent.publisher_identity,
        "direct_motor_route": intent.direct_motor_route,
        "direct_motor_interface": intent.direct_motor_interface,
        "direct_motor_publisher_identity": intent.direct_motor_publisher_identity,
    }


def _blocked(
    point: datetime,
    reasons: list[str] | tuple[str, ...],
    *,
    request: ZeroMotionAcceptanceRequest | None = None,
    static_decision_digest: str | None = None,
    static_evidence_digests: tuple[str, ...] = (),
    artifact_digests: Mapping[str, str] | None = None,
) -> ZeroMotionAcceptanceReceipt:
    artifacts = ZeroMotionArtifactDigests.model_validate(artifact_digests or {})
    return ZeroMotionAcceptanceReceipt(
        status="BLOCKED",
        reasons=tuple(dict.fromkeys(reasons)) or ("ZERO_MOTION_ACCEPTANCE_BLOCKED",),
        evaluated_at=point,
        static_decision_digest=static_decision_digest,
        static_evidence_digests=static_evidence_digests,
        artifacts=artifacts,
        **_request_identity(request),
    )


def _parse_artifact(
    raw: object,
    *,
    kind: ZeroMotionArtifactKind,
    issuer_id: str,
    request: ZeroMotionAcceptanceRequest,
    trust_store: MotionSafetyTrustStore,
    point: datetime,
    max_age_s: int,
    seen_artifact_ids: set[str],
    label: str,
) -> tuple[SignedZeroMotionArtifact | None, list[str]]:
    reasons: list[str] = []
    try:
        payload = raw.model_dump(mode="python") if isinstance(raw, BaseModel) else raw
        if not isinstance(payload, Mapping):
            raise ValueError("artifact must be an object")
        compute_motion_payload_digest(payload)
        artifact = SignedZeroMotionArtifact.model_validate(payload)
    except Exception:
        return None, [f"{label}_INVALID"]

    intent = request.admission.intent
    if artifact.kind != kind:
        reasons.append(f"{label}_KIND_MISMATCH")
    if artifact.issuer_id != issuer_id:
        reasons.append(f"{label}_ISSUER_MISMATCH")
    if not trust_store.verify_payload_signature(
        issuer_id=artifact.issuer_id,
        payload_sha256=artifact.payload_sha256,
        signature_hmac_sha256=artifact.signature_hmac_sha256,
    ):
        reasons.append(f"{label}_SIGNATURE_INVALID")
    expected_identity = {
        "acceptance_id": request.acceptance_id,
        "call_id": intent.call_id,
        "session_id": intent.session_id,
        "target_id": intent.target_id,
        "target_identity": intent.target_identity,
        "operator_id": intent.operator_id,
        "execution_subject_digest": intent.execution_subject_digest,
        "ros_graph_digest": intent.ros_graph_digest,
        "command_route": intent.command_route,
        "command_interface": intent.command_interface,
        "publisher_identity": intent.publisher_identity,
        "direct_motor_route": intent.direct_motor_route,
        "direct_motor_interface": intent.direct_motor_interface,
        "direct_motor_publisher_identity": intent.direct_motor_publisher_identity,
    }
    for field, expected in expected_identity.items():
        if getattr(artifact, field) != expected:
            reasons.append(f"{label}_{field.upper()}_MISMATCH")
    issued = artifact.issued_at.astimezone(timezone.utc)
    expires = artifact.expires_at.astimezone(timezone.utc)
    age = (point - issued).total_seconds()
    if age < 0:
        reasons.append(f"{label}_NOT_YET_VALID")
    elif age > max_age_s or point >= expires:
        reasons.append(f"{label}_STALE")
    if (expires - issued).total_seconds() > max_age_s:
        reasons.append(f"{label}_FRESHNESS_WINDOW_TOO_WIDE")
    if artifact.artifact_id in seen_artifact_ids:
        reasons.append("ZERO_MOTION_ARTIFACT_ID_REUSED")
    else:
        seen_artifact_ids.add(artifact.artifact_id)
    return artifact, reasons


_FRESH_ZERO_CLAIMS = {
    "last_command_is_zero",
    "motor_output_zero",
    "motors_stopped",
    "zero_velocity_verified",
    "fresh_zero_evidence_digest",
    "fresh_zero_evidence",
}
_FRESH_ZERO_EVIDENCE_KEYS = {
    "schema_version",
    "window_started_at",
    "window_ended_at",
    "command_sample_count",
    "command_latest_sample_at",
    "command_max_abs_component",
    "command_samples_digest",
    "motor_sample_count",
    "motor_latest_sample_at",
    "motor_value_count",
    "motor_max_abs_rps",
    "motor_samples_digest",
    "imu_stream",
    "imu_sample_count",
    "imu_latest_sample_at",
    "imu_sample_rate_hz",
    "imu_max_abs_angular_z_rad_s",
    "imu_max_abs_z_bias_residual_rad_s",
    "imu_samples_digest",
    "evidence_sha256",
}


def _claim_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        candidate = value
    elif isinstance(value, str):
        try:
            candidate = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return candidate.astimezone(timezone.utc) if candidate.tzinfo is not None and candidate.utcoffset() is not None else None


def _validate_fresh_zero_claims(
    claims: Mapping[str, Any],
    *,
    artifact: SignedZeroMotionArtifact,
    label: str,
) -> list[str]:
    if any(claims.get(field) is not True for field in ("last_command_is_zero", "motor_output_zero", "motors_stopped", "zero_velocity_verified")):
        return [f"{label}_FRESH_ZERO_NOT_VERIFIED"]
    evidence = claims.get("fresh_zero_evidence")
    if not isinstance(evidence, Mapping) or set(evidence) != _FRESH_ZERO_EVIDENCE_KEYS:
        return [f"{label}_FRESH_ZERO_EVIDENCE_INVALID"]
    evidence = dict(evidence)
    evidence_digest = evidence.get("evidence_sha256")
    unsigned = {key: value for key, value in evidence.items() if key != "evidence_sha256"}
    try:
        expected_digest = compute_motion_payload_digest(unsigned)
    except Exception:
        return [f"{label}_FRESH_ZERO_EVIDENCE_INVALID"]
    started = _claim_datetime(evidence.get("window_started_at"))
    ended = _claim_datetime(evidence.get("window_ended_at"))
    command_latest = _claim_datetime(evidence.get("command_latest_sample_at"))
    motor_latest = _claim_datetime(evidence.get("motor_latest_sample_at"))
    imu_latest = _claim_datetime(evidence.get("imu_latest_sample_at"))
    numeric_bounds = (
        (evidence.get("command_max_abs_component"), 0.0, 1e-9),
        (evidence.get("motor_max_abs_rps"), 0.0, 1e-6),
        (evidence.get("imu_sample_rate_hz"), 5.0, 1000.0),
        (evidence.get("imu_max_abs_angular_z_rad_s"), 0.0, 0.03),
        (evidence.get("imu_max_abs_z_bias_residual_rad_s"), 0.0, 0.01),
    )
    invalid_numeric = any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not lower <= value <= upper for value, lower, upper in numeric_bounds)
    if (
        evidence.get("schema_version") != "rolo-landerpi-fresh-zero-motion-evidence/v1"
        or evidence_digest != expected_digest
        or claims.get("fresh_zero_evidence_digest") != evidence_digest
        or not _is_sha256(evidence_digest)
        or any(not _is_sha256(evidence.get(field)) for field in ("command_samples_digest", "motor_samples_digest", "imu_samples_digest"))
        or not _is_exact_int(evidence.get("command_sample_count"), minimum=2)
        or not _is_exact_int(evidence.get("motor_sample_count"), minimum=2)
        or not _is_exact_int(evidence.get("motor_value_count"), minimum=1)
        or not _is_exact_int(evidence.get("imu_sample_count"), minimum=3)
        or evidence.get("imu_stream") not in {"/imu", "/imu_corrected", "/ros_robot_controller/imu_raw"}
        or invalid_numeric
        or None in (started, ended, command_latest, motor_latest, imu_latest)
    ):
        return [f"{label}_FRESH_ZERO_EVIDENCE_INVALID"]
    duration = (ended - started).total_seconds()
    artifact_age = (artifact.issued_at.astimezone(timezone.utc) - ended).total_seconds()
    if not 0.2 <= duration <= 1 or artifact_age < 0 or artifact_age > 1:
        return [f"{label}_FRESH_ZERO_EVIDENCE_STALE"]
    if any(latest < started or latest > ended or (ended - latest).total_seconds() > 0.2 for latest in (command_latest, motor_latest, imu_latest)):
        return [f"{label}_FRESH_ZERO_SAMPLE_STALE"]
    return []


_SNAPSHOT_CLAIMS = {
    "phase",
    "command_route",
    "command_interface",
    "publisher_identities",
    "publisher_gids",
    "subscriber_identities",
    "subscriber_gids",
    "competing_command_route",
    "competing_command_interface",
    "competing_publisher_identities",
    "competing_publisher_gids",
    "competing_subscriber_identities",
    "competing_subscriber_gids",
    "direct_motor_route",
    "direct_motor_interface",
    "direct_motor_publisher_identities",
    "direct_motor_publisher_gids",
    "graph_revision",
    "live_ros_graph_digest",
    "fence_epoch",
    "active_fence_digest",
    "fence_owner_call_id",
    "motion_enabled",
    "provider_invocation_count",
} | _FRESH_ZERO_CLAIMS


def _validate_snapshot(
    artifact: SignedZeroMotionArtifact,
    *,
    phase: IsolationPhase,
    request: ZeroMotionAcceptanceRequest,
    policy: MotionSafetyPolicy,
    expected_fence_digest: str,
    expected_fence_epoch: int | None = None,
    expected_graph_revision: str | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    label = "PRE_ISOLATION_SNAPSHOT" if phase == "PRE_CAS" else "POST_STOP_ISOLATION_SNAPSHOT"
    claims = artifact.claims
    reasons: list[str] = []
    if set(claims) != _SNAPSHOT_CLAIMS:
        return None, [f"{label}_CLAIMS_INVALID"]
    publishers = claims["publisher_identities"]
    publisher_gids = claims["publisher_gids"]
    subscribers = claims["subscriber_identities"]
    subscriber_gids = claims["subscriber_gids"]
    competing_publishers = claims["competing_publisher_identities"]
    competing_publisher_gids = claims["competing_publisher_gids"]
    competing_subscribers = claims["competing_subscriber_identities"]
    competing_subscriber_gids = claims["competing_subscriber_gids"]
    direct_publishers = claims["direct_motor_publisher_identities"]
    direct_publisher_gids = claims["direct_motor_publisher_gids"]
    if claims["phase"] != phase:
        reasons.append(f"{label}_PHASE_MISMATCH")
    if claims["command_route"] != _REQUIRED_COMMAND_ROUTE or claims["command_route"] != policy.command_route:
        reasons.append("COMMAND_ROUTE_MISMATCH")
    if claims["command_interface"] != policy.command_interface:
        reasons.append("COMMAND_INTERFACE_MISMATCH")
    if publishers != [policy.allowed_publisher_identity]:
        reasons.append("COMMAND_ROUTE_NOT_ISOLATED")
    if not isinstance(publisher_gids, list) or len(publisher_gids) != 1:
        reasons.append("COMMAND_ROUTE_ENDPOINT_GID_NOT_EXCLUSIVE")
    if subscribers != [_REQUIRED_COMMAND_SUBSCRIBER]:
        reasons.append("COMMAND_ROUTE_SUBSCRIBER_MISMATCH")
    if not isinstance(subscriber_gids, list) or len(subscriber_gids) != 1:
        reasons.append("COMMAND_ROUTE_SUBSCRIBER_GID_NOT_EXCLUSIVE")
    if claims["competing_command_route"] != _REQUIRED_COMPETING_COMMAND_ROUTE:
        reasons.append("COMPETING_COMMAND_ROUTE_MISMATCH")
    if claims["competing_command_interface"] != policy.command_interface:
        reasons.append("COMPETING_COMMAND_INTERFACE_MISMATCH")
    if competing_publishers != []:
        reasons.append("COMPETING_COMMAND_ROUTE_NOT_ISOLATED")
    if competing_publisher_gids != []:
        reasons.append("COMPETING_COMMAND_ROUTE_GID_NOT_ISOLATED")
    if competing_subscribers != [_REQUIRED_COMMAND_SUBSCRIBER]:
        reasons.append("COMPETING_COMMAND_ROUTE_SUBSCRIBER_MISMATCH")
    if not isinstance(competing_subscriber_gids, list) or len(competing_subscriber_gids) != 1:
        reasons.append("COMPETING_COMMAND_ROUTE_SUBSCRIBER_GID_NOT_EXCLUSIVE")
    if claims["direct_motor_route"] != policy.direct_motor_route:
        reasons.append("DIRECT_MOTOR_ROUTE_MISMATCH")
    if claims["direct_motor_interface"] != policy.direct_motor_interface:
        reasons.append("DIRECT_MOTOR_INTERFACE_MISMATCH")
    if direct_publishers != [policy.allowed_direct_motor_publisher_identity]:
        reasons.append("DIRECT_MOTOR_ROUTE_NOT_ISOLATED")
    if not isinstance(direct_publisher_gids, list) or len(direct_publisher_gids) != 1:
        reasons.append("DIRECT_MOTOR_ROUTE_ENDPOINT_GID_NOT_EXCLUSIVE")
    graph_revision = claims["graph_revision"]
    live_graph_digest = claims["live_ros_graph_digest"]
    fence_epoch = claims["fence_epoch"]
    if not _is_sha256(graph_revision):
        reasons.append(f"{label}_GRAPH_REVISION_INVALID")
    if not _is_sha256(live_graph_digest):
        reasons.append(f"{label}_GRAPH_DIGEST_INVALID")
    if not _is_exact_int(fence_epoch, minimum=1):
        reasons.append(f"{label}_FENCE_EPOCH_INVALID")
    if claims["active_fence_digest"] != expected_fence_digest:
        reasons.append(f"{label}_FENCE_MISMATCH")
    if claims["fence_owner_call_id"] != request.admission.intent.call_id:
        reasons.append(f"{label}_FENCE_OWNER_MISMATCH")
    if claims["motion_enabled"] is not False:
        reasons.append(f"{label}_MOTION_ENABLED")
    if not _is_exact_int(claims["provider_invocation_count"]) or claims["provider_invocation_count"] != 0:
        reasons.append(f"{label}_PROVIDER_INVOKED")
    reasons.extend(_validate_fresh_zero_claims(claims, artifact=artifact, label=label))
    if expected_fence_epoch is not None and fence_epoch != expected_fence_epoch:
        reasons.append(f"{label}_FENCE_EPOCH_MISMATCH")
    if expected_graph_revision is not None and graph_revision != expected_graph_revision:
        reasons.append(f"{label}_GRAPH_REVISION_CHANGED")
    identity_lists = (
        publishers,
        subscribers,
        competing_publishers,
        competing_subscribers,
        direct_publishers,
        publisher_gids,
        subscriber_gids,
        competing_publisher_gids,
        competing_subscriber_gids,
        direct_publisher_gids,
    )
    if all(isinstance(items, list) and all(isinstance(item, str) for item in items) for items in identity_lists):
        expected_live_digest = compute_zero_motion_isolation_digest(
            target_id=request.admission.intent.target_id,
            target_identity=request.admission.intent.target_identity,
            observed_at=artifact.issued_at,
            command_route=claims["command_route"],
            command_interface=claims["command_interface"],
            publisher_identities=publishers,
            subscriber_identities=subscribers,
            competing_command_route=claims["competing_command_route"],
            competing_command_interface=claims["competing_command_interface"],
            competing_publisher_identities=competing_publishers,
            competing_subscriber_identities=competing_subscribers,
            direct_motor_route=claims["direct_motor_route"],
            direct_motor_interface=claims["direct_motor_interface"],
            direct_motor_publisher_identities=direct_publishers,
            command_publisher_gids=publisher_gids,
            command_subscriber_gids=subscriber_gids,
            competing_publisher_gids=competing_publisher_gids,
            competing_subscriber_gids=competing_subscriber_gids,
            direct_motor_publisher_gids=direct_publisher_gids,
        )
        if live_graph_digest != expected_live_digest:
            reasons.append(f"{label}_GRAPH_DIGEST_MISMATCH")
    else:
        reasons.append(f"{label}_PUBLISHERS_INVALID")
    gids: list[object] = []
    for group in (
        publisher_gids,
        subscriber_gids,
        competing_publisher_gids,
        competing_subscriber_gids,
        direct_publisher_gids,
    ):
        if isinstance(group, list):
            gids.extend(group)
    if any(not isinstance(gid, str) or re.fullmatch(_GID, gid) is None for gid in gids) or len(gids) != len(set(gids)):
        reasons.append(f"{label}_ENDPOINT_GIDS_INVALID")
    if reasons:
        return None, reasons
    return {
        "graph_revision": graph_revision,
        "live_ros_graph_digest": live_graph_digest,
        "fence_epoch": fence_epoch,
    }, []


_CAS_CLAIMS = {
    "acquired",
    "snapshot_artifact_digest",
    "live_ros_graph_digest",
    "graph_revision",
    "expected_fence_digest",
    "expected_fence_epoch",
    "fence_epoch",
    "fence_lease_digest",
    "lease_owner_call_id",
    "motion_enabled",
    "provider_invocation_count",
}


def _validate_cas(
    artifact: SignedZeroMotionArtifact,
    *,
    request: ZeroMotionAcceptanceRequest,
    snapshot_digest: str,
    snapshot_state: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, list[str]]:
    claims = artifact.claims
    if set(claims) != _CAS_CLAIMS:
        return None, ["LIVE_FENCE_CAS_CLAIMS_INVALID"]
    intent = request.admission.intent
    expected_epoch = snapshot_state["fence_epoch"]
    fence_epoch = claims["fence_epoch"]
    reasons: list[str] = []
    if claims["acquired"] is not True:
        reasons.append("LIVE_FENCE_CAS_NOT_ACQUIRED")
    if claims["snapshot_artifact_digest"] != snapshot_digest:
        reasons.append("LIVE_FENCE_CAS_SNAPSHOT_MISMATCH")
    if claims["live_ros_graph_digest"] != snapshot_state["live_ros_graph_digest"]:
        reasons.append("LIVE_FENCE_CAS_GRAPH_DIGEST_MISMATCH")
    if claims["graph_revision"] != snapshot_state["graph_revision"]:
        reasons.append("LIVE_FENCE_CAS_GRAPH_REVISION_MISMATCH")
    if claims["expected_fence_digest"] != intent.direct_motor_fence_digest:
        reasons.append("LIVE_FENCE_CAS_EXPECTED_FENCE_MISMATCH")
    if claims["expected_fence_epoch"] != expected_epoch:
        reasons.append("LIVE_FENCE_CAS_EXPECTED_EPOCH_MISMATCH")
    if not _is_exact_int(fence_epoch, minimum=2) or fence_epoch != expected_epoch + 1:
        reasons.append("LIVE_FENCE_CAS_EPOCH_MISMATCH")
    if claims["lease_owner_call_id"] != intent.call_id:
        reasons.append("LIVE_FENCE_CAS_OWNER_MISMATCH")
    if claims["motion_enabled"] is not False:
        reasons.append("LIVE_FENCE_CAS_MOTION_ENABLED")
    if not _is_exact_int(claims["provider_invocation_count"]) or claims["provider_invocation_count"] != 0:
        reasons.append("LIVE_FENCE_CAS_PROVIDER_INVOKED")
    expected_lease = None
    if not reasons or _is_exact_int(fence_epoch, minimum=1):
        try:
            expected_lease = compute_zero_motion_fence_lease_digest(
                acceptance_id=request.acceptance_id,
                intent=intent,
                snapshot_artifact_digest=snapshot_digest,
                live_ros_graph_digest=snapshot_state["live_ros_graph_digest"],
                graph_revision=snapshot_state["graph_revision"],
                expected_fence_digest=intent.direct_motor_fence_digest,
                fence_epoch=fence_epoch,
            )
        except (TypeError, ValueError):
            pass
    if not _is_sha256(claims["fence_lease_digest"]) or claims["fence_lease_digest"] != expected_lease:
        reasons.append("LIVE_FENCE_CAS_LEASE_MISMATCH")
    if reasons:
        return None, reasons
    return {
        "fence_epoch": fence_epoch,
        "fence_lease_digest": expected_lease,
        "graph_revision": snapshot_state["graph_revision"],
    }, []


_START_ACK_CLAIMS = {
    "acknowledged",
    "phase",
    "snapshot_artifact_digest",
    "cas_artifact_digest",
    "fence_lease_digest",
    "graph_revision",
    "zero_velocity_verified",
    "motors_stopped",
    "motion_command_emitted",
    "provider_invocation_count",
} | _FRESH_ZERO_CLAIMS
_STOP_ACK_CLAIMS = _START_ACK_CLAIMS | {"start_ack_artifact_digest"}


def _validate_ack(
    artifact: SignedZeroMotionArtifact,
    *,
    phase: Literal["START", "STOP"],
    snapshot_digest: str,
    cas_digest: str,
    cas_state: Mapping[str, Any],
    start_ack_digest: str | None = None,
) -> list[str]:
    claims = artifact.claims
    label = f"ZERO_MOTION_{phase}_ACK"
    expected_keys = _START_ACK_CLAIMS if phase == "START" else _STOP_ACK_CLAIMS
    if set(claims) != expected_keys:
        return [f"{label}_CLAIMS_INVALID"]
    reasons: list[str] = []
    if claims["acknowledged"] is not True or claims["phase"] != phase:
        reasons.append(f"{label}_NOT_ACKNOWLEDGED")
    if claims["snapshot_artifact_digest"] != snapshot_digest:
        reasons.append(f"{label}_SNAPSHOT_MISMATCH")
    if claims["cas_artifact_digest"] != cas_digest:
        reasons.append(f"{label}_CAS_MISMATCH")
    if claims["fence_lease_digest"] != cas_state["fence_lease_digest"]:
        reasons.append(f"{label}_FENCE_MISMATCH")
    if claims["graph_revision"] != cas_state["graph_revision"]:
        reasons.append(f"{label}_GRAPH_REVISION_MISMATCH")
    if claims["zero_velocity_verified"] is not True or claims["motors_stopped"] is not True:
        reasons.append(f"{label}_ZERO_MOTION_NOT_VERIFIED")
    if claims["motion_command_emitted"] is not False:
        reasons.append(f"{label}_MOTION_COMMAND_EMITTED")
    if not _is_exact_int(claims["provider_invocation_count"]) or claims["provider_invocation_count"] != 0:
        reasons.append(f"{label}_PROVIDER_INVOKED")
    if phase == "STOP" and claims["start_ack_artifact_digest"] != start_ack_digest:
        reasons.append("ZERO_MOTION_STOP_ACK_START_MISMATCH")
    reasons.extend(_validate_fresh_zero_claims(claims, artifact=artifact, label=label))
    return reasons


_RELEASE_CLAIMS = {
    "released",
    "cas_artifact_digest",
    "stop_ack_artifact_digest",
    "post_snapshot_artifact_digest",
    "released_fence_lease_digest",
    "restored_fence_digest",
    "restored_fence_epoch",
    "direct_access_blocked",
    "motion_enabled",
    "provider_invocation_count",
}


def _validate_release(
    artifact: SignedZeroMotionArtifact,
    *,
    request: ZeroMotionAcceptanceRequest,
    cas_digest: str,
    cas_state: Mapping[str, Any],
    stop_digest: str,
    post_snapshot_digest: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    claims = artifact.claims
    if set(claims) != _RELEASE_CLAIMS:
        return None, ["LIVE_FENCE_RELEASE_CLAIMS_INVALID"]
    reasons: list[str] = []
    if claims["released"] is not True:
        reasons.append("LIVE_FENCE_NOT_RELEASED")
    if claims["cas_artifact_digest"] != cas_digest:
        reasons.append("LIVE_FENCE_RELEASE_CAS_MISMATCH")
    if claims["stop_ack_artifact_digest"] != stop_digest:
        reasons.append("LIVE_FENCE_RELEASE_STOP_MISMATCH")
    if claims["post_snapshot_artifact_digest"] != post_snapshot_digest:
        reasons.append("LIVE_FENCE_RELEASE_SNAPSHOT_MISMATCH")
    if claims["released_fence_lease_digest"] != cas_state["fence_lease_digest"]:
        reasons.append("LIVE_FENCE_RELEASE_LEASE_MISMATCH")
    restored_epoch = claims["restored_fence_epoch"]
    expected_restored_epoch = cas_state["fence_epoch"] + 1
    expected_restored_digest = None
    if _is_exact_int(restored_epoch, minimum=1):
        try:
            expected_restored_digest = _call_fence_digest(request.admission.intent, restored_epoch)
        except (TypeError, ValueError):
            pass
    if claims["restored_fence_digest"] != expected_restored_digest:
        reasons.append("LIVE_FENCE_RELEASE_RESTORED_FENCE_MISMATCH")
    if restored_epoch != expected_restored_epoch:
        reasons.append("LIVE_FENCE_RELEASE_RESTORED_EPOCH_MISMATCH")
    if claims["direct_access_blocked"] is not True:
        reasons.append("LIVE_FENCE_RELEASE_DIRECT_ACCESS_OPEN")
    if claims["motion_enabled"] is not False:
        reasons.append("LIVE_FENCE_RELEASE_MOTION_ENABLED")
    if not _is_exact_int(claims["provider_invocation_count"]) or claims["provider_invocation_count"] != 0:
        reasons.append("LIVE_FENCE_RELEASE_PROVIDER_INVOKED")
    if reasons:
        return None, reasons
    return {
        "fence_digest": expected_restored_digest,
        "fence_epoch": restored_epoch,
    }, []


_PROVIDER_GATE_CLAIMS = {
    "one_shot",
    "consumed",
    "release_artifact_digest",
    "post_snapshot_artifact_digest",
    "expected_fence_digest",
    "expected_fence_epoch",
    "expected_graph_revision",
    "consume_token_digest",
    "motion_enabled",
    "provider_invocation_count",
} | _FRESH_ZERO_CLAIMS
_ARMED_PROVIDER_BINDING_CLAIM = "armed_zero_provider_binding"


def _parse_armed_provider_binding(
    claims: Mapping[str, Any],
    *,
    intent: MotionSafetyIntent,
    label: str,
) -> tuple[ArmedZeroProviderBinding | None, list[str]]:
    raw = claims.get(_ARMED_PROVIDER_BINDING_CLAIM)
    if raw is None:
        return None, []
    try:
        binding = ArmedZeroProviderBinding.model_validate(raw)
    except Exception:
        return None, [f"{label}_ARMED_PROVIDER_BINDING_INVALID"]
    if (
        binding.call_id != intent.call_id
        or binding.session_id != intent.session_id
        or binding.execution_subject_digest != intent.execution_subject_digest
        or binding.publisher_identity != intent.publisher_identity
    ):
        return None, [f"{label}_ARMED_PROVIDER_BINDING_MISMATCH"]
    return binding, []


def _validate_provider_gate(
    artifact: SignedZeroMotionArtifact,
    *,
    request: ZeroMotionAcceptanceRequest,
    release_digest: str,
    post_snapshot_digest: str,
    released_fence_digest: str,
    released_fence_epoch: int,
    graph_revision: str,
) -> list[str]:
    claims = artifact.claims
    if set(claims) not in (
        _PROVIDER_GATE_CLAIMS,
        _PROVIDER_GATE_CLAIMS | {_ARMED_PROVIDER_BINDING_CLAIM},
    ):
        return ["PROVIDER_GATE_CHALLENGE_CLAIMS_INVALID"]
    reasons: list[str] = []
    if claims["one_shot"] is not True:
        reasons.append("PROVIDER_GATE_CHALLENGE_NOT_ONE_SHOT")
    if claims["consumed"] is not False:
        reasons.append("PROVIDER_GATE_CHALLENGE_ALREADY_CONSUMED")
    if claims["release_artifact_digest"] != release_digest:
        reasons.append("PROVIDER_GATE_CHALLENGE_RELEASE_MISMATCH")
    if claims["post_snapshot_artifact_digest"] != post_snapshot_digest:
        reasons.append("PROVIDER_GATE_CHALLENGE_SNAPSHOT_MISMATCH")
    if claims["expected_fence_digest"] != released_fence_digest:
        reasons.append("PROVIDER_GATE_CHALLENGE_FENCE_MISMATCH")
    if claims["expected_fence_epoch"] != released_fence_epoch:
        reasons.append("PROVIDER_GATE_CHALLENGE_EPOCH_MISMATCH")
    if claims["expected_graph_revision"] != graph_revision:
        reasons.append("PROVIDER_GATE_CHALLENGE_GRAPH_REVISION_MISMATCH")
    expected_consume_token = compute_provider_gate_consume_token_digest(
        acceptance_id=request.acceptance_id,
        intent=request.admission.intent,
        release_artifact_digest=release_digest,
        post_snapshot_artifact_digest=post_snapshot_digest,
        expected_fence_digest=released_fence_digest,
        expected_fence_epoch=released_fence_epoch,
        expected_graph_revision=graph_revision,
        expires_at=artifact.expires_at,
    )
    if claims["consume_token_digest"] != expected_consume_token:
        reasons.append("PROVIDER_GATE_CHALLENGE_TOKEN_MISMATCH")
    if claims["motion_enabled"] is not False:
        reasons.append("PROVIDER_GATE_CHALLENGE_MOTION_ENABLED")
    if not _is_exact_int(claims["provider_invocation_count"]) or claims["provider_invocation_count"] != 0:
        reasons.append("PROVIDER_GATE_CHALLENGE_PROVIDER_INVOKED")
    _, binding_reasons = _parse_armed_provider_binding(
        claims,
        intent=request.admission.intent,
        label="PROVIDER_GATE_CHALLENGE",
    )
    reasons.extend(binding_reasons)
    reasons.extend(_validate_fresh_zero_claims(claims, artifact=artifact, label="PROVIDER_GATE_CHALLENGE"))
    return reasons


_TARGET_METHODS = (
    "observe_isolation",
    "compare_and_set_fence",
    "acknowledge_zero_motion_start",
    "acknowledge_zero_motion_stop",
    "release_fence",
    "issue_provider_gate_challenge",
    "compare_and_set_provider_gate",
    "abort_zero_motion",
)


def run_zero_motion_acceptance(
    request: ZeroMotionAcceptanceRequest | Mapping[str, Any] | None = None,
    *,
    policy: MotionSafetyPolicy | Mapping[str, Any] | None = None,
    trust_store: MotionSafetyTrustStore | None = None,
    target: ZeroMotionTarget | None = None,
    now: datetime | None = None,
    clock: Callable[[], datetime] | None = None,
) -> ZeroMotionAcceptanceReceipt:
    """Run one signed rehearsal without exposing any physical-motion operation."""

    try:
        initial_time = now if now is not None else (clock() if clock is not None else None)
    except Exception:
        return _blocked(datetime.now(timezone.utc), ["EVALUATION_TIME_INVALID"])
    initial_point = _point(initial_time)
    if initial_point is None:
        return _blocked(datetime.now(timezone.utc), ["EVALUATION_TIME_INVALID"])
    if request is None:
        return _blocked(initial_point, ["ZERO_MOTION_ACCEPTANCE_REQUEST_REQUIRED"])
    try:
        raw_request = request.model_dump(mode="python") if isinstance(request, BaseModel) else request
        if not isinstance(raw_request, Mapping):
            raise ValueError("request must be an object")
        compute_motion_payload_digest(raw_request)
        parsed_request = ZeroMotionAcceptanceRequest.model_validate(raw_request)
    except Exception:
        return _blocked(initial_point, ["ZERO_MOTION_ACCEPTANCE_REQUEST_INVALID"])
    intent = parsed_request.admission.intent

    decision = evaluate_motion_safety(
        parsed_request.admission,
        policy=policy,
        trust_store=trust_store,
        now=initial_point,
    )
    static_decision_digest = compute_motion_payload_digest(decision.model_dump(mode="python"))
    if not decision.admitted:
        return _blocked(
            initial_point,
            ["STATIC_MOTION_SAFETY_BLOCKED", *decision.reasons],
            request=parsed_request,
            static_decision_digest=static_decision_digest,
            static_evidence_digests=decision.evidence_digests,
        )
    try:
        parsed_policy = MotionSafetyPolicy.model_validate(policy.model_dump(mode="python") if isinstance(policy, BaseModel) else policy)
    except Exception:
        return _blocked(
            initial_point,
            ["MOTION_SAFETY_POLICY_INVALID"],
            request=parsed_request,
            static_decision_digest=static_decision_digest,
            static_evidence_digests=decision.evidence_digests,
        )
    if (
        parsed_policy.command_route != _REQUIRED_COMMAND_ROUTE
        or intent.command_route != _REQUIRED_COMMAND_ROUTE
        or parsed_policy.allowed_publisher_identity != _REQUIRED_COMMAND_PUBLISHER
        or intent.publisher_identity != _REQUIRED_COMMAND_PUBLISHER
    ):
        return _blocked(
            initial_point,
            ["LANDERPI_CONTROLLED_COMMAND_TOPOLOGY_REQUIRED"],
            request=parsed_request,
            static_decision_digest=static_decision_digest,
            static_evidence_digests=decision.evidence_digests,
        )
    if (
        parsed_policy.direct_motor_route != _REQUIRED_DIRECT_MOTOR_ROUTE
        or intent.direct_motor_route != _REQUIRED_DIRECT_MOTOR_ROUTE
        or parsed_policy.allowed_direct_motor_publisher_identity != _REQUIRED_DIRECT_MOTOR_PUBLISHER
        or intent.direct_motor_publisher_identity != _REQUIRED_DIRECT_MOTOR_PUBLISHER
    ):
        return _blocked(
            initial_point,
            ["LANDERPI_DIRECT_MOTOR_TOPOLOGY_REQUIRED"],
            request=parsed_request,
            static_decision_digest=static_decision_digest,
            static_evidence_digests=decision.evidence_digests,
        )
    if trust_store is None or not isinstance(trust_store, MotionSafetyTrustStore):
        return _blocked(
            initial_point,
            ["MOTION_SAFETY_TRUST_STORE_REQUIRED"],
            request=parsed_request,
            static_decision_digest=static_decision_digest,
            static_evidence_digests=decision.evidence_digests,
        )
    if target is None:
        return _blocked(
            initial_point,
            ["ZERO_MOTION_TARGET_ADAPTER_REQUIRED"],
            request=parsed_request,
            static_decision_digest=static_decision_digest,
            static_evidence_digests=decision.evidence_digests,
        )
    missing_methods = [name for name in _TARGET_METHODS if not callable(getattr(target, name, None))]
    if missing_methods:
        return _blocked(
            initial_point,
            [f"ZERO_MOTION_TARGET_{name.upper()}_REQUIRED" for name in missing_methods],
            request=parsed_request,
            static_decision_digest=static_decision_digest,
            static_evidence_digests=decision.evidence_digests,
        )
    production_peer_check = getattr(target, "production_peer_verified", None)
    try:
        production_peer_ready = callable(production_peer_check) and production_peer_check() is True
    except Exception:
        production_peer_ready = False
    if not production_peer_ready:
        return _blocked(
            initial_point,
            ["PRODUCTION_PINNED_TARGET_PEER_REQUIRED"],
            request=parsed_request,
            static_decision_digest=static_decision_digest,
            static_evidence_digests=decision.evidence_digests,
        )

    target_clock = getattr(target, "clock", None)
    live_clock = clock if clock is not None else (target_clock if callable(target_clock) else None)
    fixed_point = initial_point if live_clock is None else None

    def current_point() -> datetime | None:
        if fixed_point is not None:
            return fixed_point
        try:
            return _point(live_clock())
        except Exception:
            return None

    first_live_point = current_point()
    if first_live_point is None or abs((first_live_point - initial_point).total_seconds()) > 1:
        return _blocked(
            initial_point,
            ["TARGET_EVALUATION_TIME_MISMATCH"],
            request=parsed_request,
            static_decision_digest=static_decision_digest,
            static_evidence_digests=decision.evidence_digests,
        )

    artifact_digests: dict[str, str] = {}
    seen_artifact_ids: set[str] = set()
    cas_attempted = False

    def abort_if_needed() -> None:
        if not cas_attempted:
            return
        try:
            target.abort_zero_motion(
                acceptance_id=parsed_request.acceptance_id,
                intent=intent,
            )
        except Exception:
            pass

    def blocked_live(reasons: list[str]) -> ZeroMotionAcceptanceReceipt:
        abort_if_needed()
        observed_point = current_point()
        point = observed_point or initial_point
        if observed_point is None:
            reasons = [*reasons, "EVALUATION_TIME_INVALID"]
        return _blocked(
            point,
            reasons,
            request=parsed_request,
            static_decision_digest=static_decision_digest,
            static_evidence_digests=decision.evidence_digests,
            artifact_digests=artifact_digests,
        )

    def parse_target_artifact(
        raw: object,
        *,
        kind: ZeroMotionArtifactKind,
        issuer_id: str,
        label: str,
    ) -> tuple[SignedZeroMotionArtifact | None, list[str]]:
        point = current_point()
        if point is None:
            return None, ["EVALUATION_TIME_INVALID"]
        return _parse_artifact(
            raw,
            kind=kind,
            issuer_id=issuer_id,
            request=parsed_request,
            trust_store=trust_store,
            point=point,
            max_age_s=parsed_policy.max_graph_age_s,
            seen_artifact_ids=seen_artifact_ids,
            label=label,
        )

    try:
        raw_pre = target.observe_isolation(
            acceptance_id=parsed_request.acceptance_id,
            intent=intent,
            policy=parsed_policy,
            phase="PRE_CAS",
            fence_binding_digest=None,
        )
    except Exception:
        return blocked_live(["PRE_ISOLATION_SNAPSHOT_UNAVAILABLE"])
    pre, reasons = parse_target_artifact(
        raw_pre,
        kind="LIVE_ISOLATION_SNAPSHOT",
        issuer_id=parsed_policy.graph_authority_id,
        label="PRE_ISOLATION_SNAPSHOT",
    )
    if pre is None or reasons:
        return blocked_live(reasons or ["PRE_ISOLATION_SNAPSHOT_INVALID"])
    pre_state, reasons = _validate_snapshot(
        pre,
        phase="PRE_CAS",
        request=parsed_request,
        policy=parsed_policy,
        expected_fence_digest=intent.direct_motor_fence_digest,
    )
    if pre_state is None or reasons:
        return blocked_live(reasons or ["PRE_ISOLATION_SNAPSHOT_INVALID"])
    artifact_digests["pre_isolation_snapshot"] = pre.payload_sha256

    cas_attempted = True
    try:
        raw_cas = target.compare_and_set_fence(
            acceptance_id=parsed_request.acceptance_id,
            intent=intent,
            policy=parsed_policy,
            snapshot_artifact_digest=pre.payload_sha256,
        )
    except Exception:
        return blocked_live(["LIVE_FENCE_CAS_UNAVAILABLE"])
    cas, reasons = parse_target_artifact(
        raw_cas,
        kind="LIVE_FENCE_CAS",
        issuer_id=parsed_policy.target_authority_id,
        label="LIVE_FENCE_CAS",
    )
    if cas is None or reasons:
        return blocked_live(reasons or ["LIVE_FENCE_CAS_INVALID"])
    cas_state, reasons = _validate_cas(
        cas,
        request=parsed_request,
        snapshot_digest=pre.payload_sha256,
        snapshot_state=pre_state,
    )
    if cas_state is None or reasons:
        return blocked_live(reasons or ["LIVE_FENCE_CAS_INVALID"])
    artifact_digests["fence_cas"] = cas.payload_sha256

    try:
        raw_start = target.acknowledge_zero_motion_start(
            acceptance_id=parsed_request.acceptance_id,
            intent=intent,
            fence_cas_artifact_digest=cas.payload_sha256,
        )
    except Exception:
        return blocked_live(["ZERO_MOTION_START_ACK_UNAVAILABLE"])
    start, reasons = parse_target_artifact(
        raw_start,
        kind="ZERO_MOTION_START_ACK",
        issuer_id=parsed_policy.target_authority_id,
        label="ZERO_MOTION_START_ACK",
    )
    if start is None or reasons:
        return blocked_live(reasons or ["ZERO_MOTION_START_ACK_INVALID"])
    reasons = _validate_ack(
        start,
        phase="START",
        snapshot_digest=pre.payload_sha256,
        cas_digest=cas.payload_sha256,
        cas_state=cas_state,
    )
    if reasons:
        return blocked_live(reasons)
    artifact_digests["start_ack"] = start.payload_sha256

    try:
        raw_stop = target.acknowledge_zero_motion_stop(
            acceptance_id=parsed_request.acceptance_id,
            intent=intent,
            fence_cas_artifact_digest=cas.payload_sha256,
            start_ack_artifact_digest=start.payload_sha256,
        )
    except Exception:
        return blocked_live(["ZERO_MOTION_STOP_ACK_UNAVAILABLE"])
    stop, reasons = parse_target_artifact(
        raw_stop,
        kind="ZERO_MOTION_STOP_ACK",
        issuer_id=parsed_policy.target_authority_id,
        label="ZERO_MOTION_STOP_ACK",
    )
    if stop is None or reasons:
        return blocked_live(reasons or ["ZERO_MOTION_STOP_ACK_INVALID"])
    reasons = _validate_ack(
        stop,
        phase="STOP",
        snapshot_digest=pre.payload_sha256,
        cas_digest=cas.payload_sha256,
        cas_state=cas_state,
        start_ack_digest=start.payload_sha256,
    )
    if reasons:
        return blocked_live(reasons)
    artifact_digests["stop_ack"] = stop.payload_sha256

    try:
        raw_post = target.observe_isolation(
            acceptance_id=parsed_request.acceptance_id,
            intent=intent,
            policy=parsed_policy,
            phase="POST_STOP",
            fence_binding_digest=cas_state["fence_lease_digest"],
        )
    except Exception:
        return blocked_live(["POST_STOP_ISOLATION_SNAPSHOT_UNAVAILABLE"])
    post, reasons = parse_target_artifact(
        raw_post,
        kind="LIVE_ISOLATION_SNAPSHOT",
        issuer_id=parsed_policy.graph_authority_id,
        label="POST_STOP_ISOLATION_SNAPSHOT",
    )
    if post is None or reasons:
        return blocked_live(reasons or ["POST_STOP_ISOLATION_SNAPSHOT_INVALID"])
    post_state, reasons = _validate_snapshot(
        post,
        phase="POST_STOP",
        request=parsed_request,
        policy=parsed_policy,
        expected_fence_digest=cas_state["fence_lease_digest"],
        expected_fence_epoch=cas_state["fence_epoch"],
        expected_graph_revision=cas_state["graph_revision"],
    )
    if post_state is None or reasons:
        return blocked_live(reasons or ["POST_STOP_ISOLATION_SNAPSHOT_INVALID"])
    artifact_digests["post_stop_isolation_snapshot"] = post.payload_sha256

    try:
        raw_release = target.release_fence(
            acceptance_id=parsed_request.acceptance_id,
            intent=intent,
            fence_cas_artifact_digest=cas.payload_sha256,
            stop_ack_artifact_digest=stop.payload_sha256,
            post_snapshot_artifact_digest=post.payload_sha256,
        )
    except Exception:
        return blocked_live(["LIVE_FENCE_RELEASE_UNAVAILABLE"])
    release, reasons = parse_target_artifact(
        raw_release,
        kind="LIVE_FENCE_RELEASE",
        issuer_id=parsed_policy.target_authority_id,
        label="LIVE_FENCE_RELEASE",
    )
    if release is None or reasons:
        return blocked_live(reasons or ["LIVE_FENCE_RELEASE_INVALID"])
    release_state, reasons = _validate_release(
        release,
        request=parsed_request,
        cas_digest=cas.payload_sha256,
        cas_state=cas_state,
        stop_digest=stop.payload_sha256,
        post_snapshot_digest=post.payload_sha256,
    )
    if release_state is None or reasons:
        return blocked_live(reasons)
    artifact_digests["fence_release"] = release.payload_sha256

    try:
        raw_provider_gate = target.issue_provider_gate_challenge(
            acceptance_id=parsed_request.acceptance_id,
            intent=intent,
            release_artifact_digest=release.payload_sha256,
            post_snapshot_artifact_digest=post.payload_sha256,
            released_fence_digest=release_state["fence_digest"],
            released_fence_epoch=release_state["fence_epoch"],
            expected_graph_revision=post_state["graph_revision"],
        )
    except Exception:
        return blocked_live(["PROVIDER_GATE_CHALLENGE_UNAVAILABLE"])
    provider_gate, reasons = parse_target_artifact(
        raw_provider_gate,
        kind="PROVIDER_GATE_CHALLENGE",
        issuer_id=parsed_policy.target_authority_id,
        label="PROVIDER_GATE_CHALLENGE",
    )
    if provider_gate is None or reasons:
        return blocked_live(reasons or ["PROVIDER_GATE_CHALLENGE_INVALID"])
    reasons = _validate_provider_gate(
        provider_gate,
        request=parsed_request,
        release_digest=release.payload_sha256,
        post_snapshot_digest=post.payload_sha256,
        released_fence_digest=release_state["fence_digest"],
        released_fence_epoch=release_state["fence_epoch"],
        graph_revision=post_state["graph_revision"],
    )
    if reasons:
        return blocked_live(reasons)
    artifact_digests["provider_gate_challenge"] = provider_gate.payload_sha256

    final_point = current_point()
    if final_point is None:
        return blocked_live(["EVALUATION_TIME_INVALID"])
    return ZeroMotionAcceptanceReceipt(
        status="READY_FOR_PROVIDER_GATE",
        reasons=(),
        evaluated_at=final_point,
        static_decision_digest=static_decision_digest,
        static_evidence_digests=decision.evidence_digests,
        artifacts=ZeroMotionArtifactDigests.model_validate(artifact_digests),
        provider_gate=provider_gate,
        **_request_identity(parsed_request),
    )


_PROVIDER_CONSUMED_CLAIMS = {
    "consumed",
    "one_shot",
    "challenge_artifact_digest",
    "consume_token_digest",
    "expected_fence_digest",
    "expected_fence_epoch",
    "expected_graph_revision",
    "observed_fence_digest",
    "observed_fence_epoch",
    "observed_graph_revision",
    "live_isolation_digest",
    "graph_compare_and_set",
    "fence_compare_and_set",
    "provider_fence_digest",
    "provider_fence_epoch",
    "motion_enabled",
    "provider_invocation_count",
} | _FRESH_ZERO_CLAIMS


def _blocked_consumption(
    point: datetime,
    reasons: list[str] | tuple[str, ...],
    *,
    request: ZeroMotionAcceptanceRequest | None = None,
    challenge_digest: str | None = None,
) -> ProviderGateConsumptionReceipt:
    return ProviderGateConsumptionReceipt(
        status="BLOCKED",
        reasons=tuple(dict.fromkeys(reasons)) or ("PROVIDER_GATE_BLOCKED",),
        evaluated_at=point,
        challenge_artifact_digest=challenge_digest,
        **_request_identity(request),
    )


def _validate_consumed_provider_gate(
    artifact: SignedZeroMotionArtifact,
    *,
    request: ZeroMotionAcceptanceRequest,
    challenge: SignedZeroMotionArtifact,
) -> tuple[str | None, list[str]]:
    claims = artifact.claims
    if set(claims) not in (
        _PROVIDER_CONSUMED_CLAIMS,
        _PROVIDER_CONSUMED_CLAIMS | {_ARMED_PROVIDER_BINDING_CLAIM},
    ):
        return None, ["PROVIDER_GATE_CONSUMED_CLAIMS_INVALID"]
    challenge_claims = challenge.claims
    intent = request.admission.intent
    expected_fence = challenge_claims["expected_fence_digest"]
    expected_epoch = challenge_claims["expected_fence_epoch"]
    expected_revision = challenge_claims["expected_graph_revision"]
    provider_epoch = claims["provider_fence_epoch"]
    reasons: list[str] = []
    if claims["consumed"] is not True or claims["one_shot"] is not True:
        reasons.append("PROVIDER_GATE_NOT_CONSUMED_ONCE")
    if claims["challenge_artifact_digest"] != challenge.payload_sha256:
        reasons.append("PROVIDER_GATE_CONSUMED_CHALLENGE_MISMATCH")
    if claims["consume_token_digest"] != challenge_claims["consume_token_digest"]:
        reasons.append("PROVIDER_GATE_CONSUMED_TOKEN_MISMATCH")
    if claims["expected_fence_digest"] != expected_fence or claims["observed_fence_digest"] != expected_fence:
        reasons.append("PROVIDER_GATE_FRESH_FENCE_COMPARE_FAILED")
    if claims["expected_fence_epoch"] != expected_epoch or claims["observed_fence_epoch"] != expected_epoch:
        reasons.append("PROVIDER_GATE_FRESH_EPOCH_COMPARE_FAILED")
    if claims["expected_graph_revision"] != expected_revision or claims["observed_graph_revision"] != expected_revision:
        reasons.append("PROVIDER_GATE_FRESH_GRAPH_COMPARE_FAILED")
    if claims["graph_compare_and_set"] is not True:
        reasons.append("PROVIDER_GATE_GRAPH_CAS_NOT_VERIFIED")
    if claims["fence_compare_and_set"] is not True:
        reasons.append("PROVIDER_GATE_FENCE_CAS_NOT_VERIFIED")
    live_isolation_digest = claims["live_isolation_digest"]
    if not _is_sha256(live_isolation_digest):
        reasons.append("PROVIDER_GATE_LIVE_ISOLATION_DIGEST_INVALID")
    if not _is_exact_int(provider_epoch, minimum=2) or provider_epoch != expected_epoch + 1:
        reasons.append("PROVIDER_GATE_FENCE_EPOCH_MISMATCH")
    expected_provider_fence = None
    if _is_sha256(live_isolation_digest) and _is_exact_int(provider_epoch, minimum=1):
        try:
            expected_provider_fence = compute_provider_fence_digest(
                acceptance_id=request.acceptance_id,
                intent=intent,
                challenge_artifact_digest=challenge.payload_sha256,
                consume_token_digest=challenge_claims["consume_token_digest"],
                live_isolation_digest=live_isolation_digest,
                graph_revision=expected_revision,
                expected_fence_digest=expected_fence,
                fence_epoch=provider_epoch,
            )
        except (TypeError, ValueError):
            pass
    if claims["provider_fence_digest"] != expected_provider_fence:
        reasons.append("PROVIDER_GATE_FENCE_DIGEST_MISMATCH")
    if claims["motion_enabled"] is not False:
        reasons.append("PROVIDER_GATE_CONSUME_ENABLED_MOTION")
    if not _is_exact_int(claims["provider_invocation_count"]) or claims["provider_invocation_count"] != 0:
        reasons.append("PROVIDER_GATE_CONSUME_INVOKED_PROVIDER")
    challenge_binding, binding_reasons = _parse_armed_provider_binding(
        challenge_claims,
        intent=intent,
        label="PROVIDER_GATE_CHALLENGE",
    )
    consumed_binding, consumed_binding_reasons = _parse_armed_provider_binding(
        claims,
        intent=intent,
        label="PROVIDER_GATE_CONSUMED",
    )
    reasons.extend(binding_reasons)
    reasons.extend(consumed_binding_reasons)
    if challenge_binding != consumed_binding:
        reasons.append("PROVIDER_GATE_ARMED_PROVIDER_BINDING_CHANGED")
    reasons.extend(_validate_fresh_zero_claims(claims, artifact=artifact, label="PROVIDER_GATE_CONSUMED"))
    return (expected_provider_fence if not reasons else None), reasons


def consume_provider_gate_challenge(
    request: ZeroMotionAcceptanceRequest | Mapping[str, Any] | None,
    receipt: ZeroMotionAcceptanceReceipt | Mapping[str, Any] | None,
    *,
    policy: MotionSafetyPolicy | Mapping[str, Any] | None = None,
    trust_store: MotionSafetyTrustStore | None = None,
    target: ZeroMotionTarget | None = None,
    now: datetime | None = None,
    clock: Callable[[], datetime] | None = None,
) -> ProviderGateConsumptionReceipt:
    """Consume READY via a fresh target-owned graph-and-fence CAS.

    The returned ``provider_boundary_open`` flag permits at most one immediate
    provider invocation.  It does not bypass the provider's own live topology,
    motion-bound, stop, or independent-feedback checks.
    """

    point = _point(now)
    if point is None:
        return _blocked_consumption(datetime.now(timezone.utc), ["EVALUATION_TIME_INVALID"])
    if request is None or receipt is None:
        return _blocked_consumption(point, ["PROVIDER_GATE_REQUEST_AND_RECEIPT_REQUIRED"])
    try:
        raw_request = request.model_dump(mode="python") if isinstance(request, BaseModel) else request
        raw_receipt = receipt.model_dump(mode="python") if isinstance(receipt, BaseModel) else receipt
        if not isinstance(raw_request, Mapping) or not isinstance(raw_receipt, Mapping):
            raise ValueError("request and receipt must be objects")
        compute_motion_payload_digest(raw_request)
        compute_motion_payload_digest(raw_receipt)
        parsed_request = ZeroMotionAcceptanceRequest.model_validate(raw_request)
        parsed_receipt = ZeroMotionAcceptanceReceipt.model_validate(raw_receipt)
    except Exception:
        return _blocked_consumption(point, ["PROVIDER_GATE_REQUEST_OR_RECEIPT_INVALID"])
    if not parsed_receipt.ready_for_provider_gate or parsed_receipt.provider_gate is None:
        return _blocked_consumption(
            point,
            ["ZERO_MOTION_ACCEPTANCE_NOT_READY"],
            request=parsed_request,
        )
    expected_identity = _request_identity(parsed_request)
    identity_reasons = [f"PROVIDER_GATE_{field.upper()}_MISMATCH" for field, expected in expected_identity.items() if getattr(parsed_receipt, field) != expected]
    if identity_reasons:
        return _blocked_consumption(
            point,
            identity_reasons,
            request=parsed_request,
            challenge_digest=parsed_receipt.provider_gate.payload_sha256,
        )
    try:
        parsed_policy = MotionSafetyPolicy.model_validate(policy.model_dump(mode="python") if isinstance(policy, BaseModel) else policy)
    except Exception:
        return _blocked_consumption(
            point,
            ["MOTION_SAFETY_POLICY_INVALID"],
            request=parsed_request,
            challenge_digest=parsed_receipt.provider_gate.payload_sha256,
        )
    intent = parsed_request.admission.intent
    if (
        parsed_policy.command_route != _REQUIRED_COMMAND_ROUTE
        or intent.command_route != _REQUIRED_COMMAND_ROUTE
        or parsed_policy.allowed_publisher_identity != _REQUIRED_COMMAND_PUBLISHER
        or intent.publisher_identity != _REQUIRED_COMMAND_PUBLISHER
        or parsed_policy.direct_motor_route != _REQUIRED_DIRECT_MOTOR_ROUTE
        or intent.direct_motor_route != _REQUIRED_DIRECT_MOTOR_ROUTE
        or parsed_policy.allowed_direct_motor_publisher_identity != _REQUIRED_DIRECT_MOTOR_PUBLISHER
        or intent.direct_motor_publisher_identity != _REQUIRED_DIRECT_MOTOR_PUBLISHER
    ):
        return _blocked_consumption(
            point,
            ["LANDERPI_PROVIDER_TOPOLOGY_REQUIRED"],
            request=parsed_request,
            challenge_digest=parsed_receipt.provider_gate.payload_sha256,
        )
    if trust_store is None or not isinstance(trust_store, MotionSafetyTrustStore):
        return _blocked_consumption(
            point,
            ["MOTION_SAFETY_TRUST_STORE_REQUIRED"],
            request=parsed_request,
            challenge_digest=parsed_receipt.provider_gate.payload_sha256,
        )
    decision = evaluate_motion_safety(
        parsed_request.admission,
        policy=parsed_policy,
        trust_store=trust_store,
        now=point,
    )
    if not decision.admitted or decision.evidence_digests != parsed_receipt.static_evidence_digests:
        return _blocked_consumption(
            point,
            ["STATIC_MOTION_SAFETY_NO_LONGER_VALID", *decision.reasons],
            request=parsed_request,
            challenge_digest=parsed_receipt.provider_gate.payload_sha256,
        )
    challenge = parsed_receipt.provider_gate
    seen_ids: set[str] = set()
    parsed_challenge, reasons = _parse_artifact(
        challenge,
        kind="PROVIDER_GATE_CHALLENGE",
        issuer_id=parsed_policy.target_authority_id,
        request=parsed_request,
        trust_store=trust_store,
        point=point,
        max_age_s=parsed_policy.max_graph_age_s,
        seen_artifact_ids=seen_ids,
        label="PROVIDER_GATE_CHALLENGE",
    )
    if parsed_challenge is None or reasons:
        return _blocked_consumption(
            point,
            reasons or ["PROVIDER_GATE_CHALLENGE_INVALID"],
            request=parsed_request,
            challenge_digest=challenge.payload_sha256,
        )
    baseline_fence = parsed_request.admission.evidence.direct_motor_fence
    if baseline_fence is None:
        return _blocked_consumption(
            point,
            ["DIRECT_MOTOR_FENCE_REQUIRED"],
            request=parsed_request,
            challenge_digest=challenge.payload_sha256,
        )
    baseline_epoch = baseline_fence.claims.get("fence_epoch")
    if not _is_exact_int(baseline_epoch, minimum=1):
        return _blocked_consumption(
            point,
            ["DIRECT_MOTOR_FENCE_EPOCH_INVALID"],
            request=parsed_request,
            challenge_digest=challenge.payload_sha256,
        )
    release_digest = parsed_receipt.artifacts.fence_release
    post_digest = parsed_receipt.artifacts.post_stop_isolation_snapshot
    if release_digest is None or post_digest is None:
        return _blocked_consumption(
            point,
            ["PROVIDER_GATE_RECEIPT_ARTIFACTS_INCOMPLETE"],
            request=parsed_request,
            challenge_digest=challenge.payload_sha256,
        )
    graph_revision = parsed_challenge.claims.get("expected_graph_revision")
    if not _is_sha256(graph_revision):
        return _blocked_consumption(
            point,
            ["PROVIDER_GATE_CHALLENGE_GRAPH_REVISION_INVALID"],
            request=parsed_request,
            challenge_digest=challenge.payload_sha256,
        )
    released_fence_epoch = baseline_epoch + 2
    released_fence_digest = _call_fence_digest(parsed_request.admission.intent, released_fence_epoch)
    reasons = _validate_provider_gate(
        parsed_challenge,
        request=parsed_request,
        release_digest=release_digest,
        post_snapshot_digest=post_digest,
        released_fence_digest=released_fence_digest,
        released_fence_epoch=released_fence_epoch,
        graph_revision=graph_revision,
    )
    if reasons:
        return _blocked_consumption(
            point,
            reasons,
            request=parsed_request,
            challenge_digest=challenge.payload_sha256,
        )
    if target is None or not callable(getattr(target, "compare_and_set_provider_gate", None)):
        return _blocked_consumption(
            point,
            ["PROVIDER_GATE_TARGET_CAS_REQUIRED"],
            request=parsed_request,
            challenge_digest=challenge.payload_sha256,
        )
    target_clock = getattr(target, "clock", None)
    live_clock = clock if clock is not None else (target_clock if callable(target_clock) else None)

    def current_point() -> datetime | None:
        if live_clock is None:
            return point
        try:
            return _point(live_clock())
        except Exception:
            return None

    pre_cas_point = current_point()
    if pre_cas_point is None or abs((pre_cas_point - point).total_seconds()) > 1:
        return _blocked_consumption(
            point,
            ["PROVIDER_GATE_TARGET_TIME_MISMATCH"],
            request=parsed_request,
            challenge_digest=challenge.payload_sha256,
        )
    cas_attempted = False

    def abort() -> None:
        if not cas_attempted or not callable(getattr(target, "abort_zero_motion", None)):
            return
        try:
            target.abort_zero_motion(
                acceptance_id=parsed_request.acceptance_id,
                intent=parsed_request.admission.intent,
            )
        except Exception:
            pass

    try:
        cas_attempted = True
        raw_consumed = target.compare_and_set_provider_gate(
            acceptance_id=parsed_request.acceptance_id,
            intent=parsed_request.admission.intent,
            policy=parsed_policy,
            challenge_artifact_digest=parsed_challenge.payload_sha256,
            consume_token_digest=parsed_challenge.claims["consume_token_digest"],
        )
    except Exception:
        abort()
        return _blocked_consumption(
            point,
            ["PROVIDER_GATE_FRESH_CAS_UNAVAILABLE"],
            request=parsed_request,
            challenge_digest=challenge.payload_sha256,
        )
    consumed_point = current_point()
    if consumed_point is None:
        abort()
        return _blocked_consumption(
            point,
            ["EVALUATION_TIME_INVALID"],
            request=parsed_request,
            challenge_digest=challenge.payload_sha256,
        )
    consumed_artifact, reasons = _parse_artifact(
        raw_consumed,
        kind="PROVIDER_GATE_CONSUMED",
        issuer_id=parsed_policy.target_authority_id,
        request=parsed_request,
        trust_store=trust_store,
        point=consumed_point,
        max_age_s=parsed_policy.max_graph_age_s,
        seen_artifact_ids=seen_ids,
        label="PROVIDER_GATE_CONSUMED",
    )
    if consumed_artifact is None or reasons:
        abort()
        return _blocked_consumption(
            consumed_point,
            reasons or ["PROVIDER_GATE_CONSUMED_INVALID"],
            request=parsed_request,
            challenge_digest=challenge.payload_sha256,
        )
    provider_fence_digest, reasons = _validate_consumed_provider_gate(
        consumed_artifact,
        request=parsed_request,
        challenge=parsed_challenge,
    )
    if provider_fence_digest is None or reasons:
        abort()
        return _blocked_consumption(
            consumed_point,
            reasons or ["PROVIDER_GATE_FRESH_CAS_INVALID"],
            request=parsed_request,
            challenge_digest=challenge.payload_sha256,
        )
    return ProviderGateConsumptionReceipt(
        status="CONSUMED",
        reasons=(),
        evaluated_at=consumed_point,
        challenge_artifact_digest=challenge.payload_sha256,
        provider_fence_digest=provider_fence_digest,
        consume_artifact=consumed_artifact,
        provider_boundary_open=True,
        **_request_identity(parsed_request),
    )


__all__ = [
    "ArmedZeroProviderBinding",
    "IsolationPhase",
    "LanderPiIsolationObservation",
    "ProviderGateConsumptionReceipt",
    "ProviderGateConsumptionStatus",
    "Ros2TopicEndpointSnapshot",
    "SignedZeroMotionArtifact",
    "ZeroMotionAcceptanceReceipt",
    "ZeroMotionAcceptanceRequest",
    "ZeroMotionAcceptanceStatus",
    "ZeroMotionArtifactDigests",
    "ZeroMotionArtifactKind",
    "ZeroMotionTarget",
    "capture_landerpi_isolation_observation",
    "compute_armed_zero_provider_identity_digest",
    "compute_provider_fence_digest",
    "compute_provider_gate_consume_token_digest",
    "compute_zero_motion_isolation_digest",
    "compute_zero_motion_fence_lease_digest",
    "consume_provider_gate_challenge",
    "parse_ros2_topic_info_verbose",
    "run_zero_motion_acceptance",
]
