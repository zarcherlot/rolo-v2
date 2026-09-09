"""Target-owned LanderPi implementation of the zero-motion acceptance SPI.

The driver has no velocity, motor-message, or provider execution API.  It
talks only to a pinned, key-authenticated observation RPC and an atomic local
state/artifact store.  The process that owns the ROS publisher is expected to
be created once in an ARMED_ZERO state before the signed rehearsal begins.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import stat
import subprocess
import tempfile
import threading
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .motion_acceptance import (
    ArmedZeroProviderBinding,
    IsolationPhase,
    LanderPiIsolationObservation,
    SignedZeroMotionArtifact,
    ZeroMotionArtifactDigests,
    ZeroMotionArtifactKind,
    capture_landerpi_isolation_observation,
    compute_armed_zero_provider_identity_digest,
    compute_provider_fence_digest,
    compute_provider_gate_consume_token_digest,
    compute_zero_motion_fence_lease_digest,
    parse_ros2_topic_info_verbose,
)
from .motion_safety import (
    MotionSafetyIntent,
    MotionSafetyPolicy,
    MotionSafetyTrustStore,
    compute_direct_motor_fence_digest,
    compute_motion_payload_digest,
)

_IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_IDENTITY = r"^/?[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,254}$"
_SHA256 = r"^sha256:[0-9a-f]{64}$"
_HMAC_SHA256 = r"^hmac-sha256:[0-9a-f]{64}$"
_SSH_HOST = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\])$")
_MAX_STATE_BYTES = 64 * 1024
_CONTROLLED_ROUTE = "/cmd_vel"
_COMPETING_ROUTE = "/controller/cmd_vel"
_DIRECT_MOTOR_ROUTE = "/ros_robot_controller/set_motor"
_PROVIDER_IDENTITY = "/rolo_bounded_twist"
_ODOM_IDENTITY = "/odom_publisher"
_MAX_ARMED_ZERO_GATE_S = 60.0

TargetMotionPhase = Literal[
    "SAFE_BASELINE",
    "DEBUG_ATTESTED",
    "REHEARSAL_OBSERVED",
    "REHEARSAL_LEASE",
    "REHEARSAL_STARTED",
    "REHEARSAL_STOPPED",
    "REHEARSAL_POST_OBSERVED",
    "REHEARSAL_RELEASED",
    "CHALLENGE_PENDING",
    "PROVIDER_FENCE",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _aware(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must include timezone")


def _point(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if not isinstance(value, datetime):
        raise RuntimeError("LANDERPI_TARGET_CLOCK_INVALID")
    _aware(value, "target clock")
    return value.astimezone(timezone.utc)


class PinnedLanderPiRpcSecurity(_StrictModel):
    schema_version: Literal["rolo-landerpi-pinned-rpc-security/v1"] = "rolo-landerpi-pinned-rpc-security/v1"
    mode: Literal["SSH_KEY_ONLY_PINNED"] = "SSH_KEY_ONLY_PINNED"
    target_id: str = Field(pattern=_IDENTIFIER)
    target_identity: str = Field(pattern=_IDENTITY)
    pinned_host_key_sha256: str = Field(pattern=_SHA256)
    observed_host_key_sha256: str = Field(pattern=_SHA256)
    public_key_auth_verified: Literal[True] = True
    host_key_verified: Literal[True] = True
    password_used: Literal[False] = False
    keyboard_interactive_used: Literal[False] = False
    batch_mode: Literal[True] = True
    strict_host_key_checking: Literal[True] = True
    shell_used: Literal[False] = False
    peer_provenance: Literal["PRODUCTION_AUTHORITY_VERIFIED", "DEBUG_ONLY_FIXED_PEER"] = "PRODUCTION_AUTHORITY_VERIFIED"
    production_peer_verified: bool = True

    @model_validator(mode="after")
    def validate_pin(self) -> PinnedLanderPiRpcSecurity:
        if self.pinned_host_key_sha256 != self.observed_host_key_sha256:
            raise ValueError("observed LanderPi host key does not match the pin")
        if (self.peer_provenance == "PRODUCTION_AUTHORITY_VERIFIED") != self.production_peer_verified:
            raise ValueError("pinned peer provenance and production assurance disagree")
        return self


class FreshZeroMotionEvidence(_StrictModel):
    """Fresh read-only proof that the armed publisher and chassis stayed at zero."""

    schema_version: Literal["rolo-landerpi-fresh-zero-motion-evidence/v1"] = "rolo-landerpi-fresh-zero-motion-evidence/v1"
    window_started_at: datetime
    window_ended_at: datetime
    command_sample_count: int = Field(ge=2, le=512)
    command_latest_sample_at: datetime
    command_max_abs_component: float = Field(ge=0, le=1e-9)
    command_samples_digest: str = Field(pattern=_SHA256)
    motor_sample_count: int = Field(ge=2, le=512)
    motor_latest_sample_at: datetime
    motor_value_count: int = Field(ge=1, le=4096)
    motor_max_abs_rps: float = Field(ge=0, le=1e-6)
    motor_samples_digest: str = Field(pattern=_SHA256)
    imu_stream: Literal["/imu", "/imu_corrected", "/ros_robot_controller/imu_raw"]
    imu_sample_count: int = Field(ge=3, le=1024)
    imu_latest_sample_at: datetime
    imu_sample_rate_hz: float = Field(ge=5, le=1000)
    imu_max_abs_angular_z_rad_s: float = Field(ge=0, le=0.03)
    imu_max_abs_z_bias_residual_rad_s: float = Field(ge=0, le=0.01)
    imu_samples_digest: str = Field(pattern=_SHA256)
    evidence_sha256: str = Field(pattern=_SHA256)

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="python", exclude={"evidence_sha256"})

    @model_validator(mode="after")
    def validate_evidence(self) -> FreshZeroMotionEvidence:
        for field in (
            "window_started_at",
            "window_ended_at",
            "command_latest_sample_at",
            "motor_latest_sample_at",
            "imu_latest_sample_at",
        ):
            _aware(getattr(self, field), field)
        started = self.window_started_at.astimezone(timezone.utc)
        ended = self.window_ended_at.astimezone(timezone.utc)
        duration = (ended - started).total_seconds()
        if not 0.2 <= duration <= 1:
            raise ValueError("fresh-zero sampling window must be between 0.2 and 1 second")
        for field in (
            "command_latest_sample_at",
            "motor_latest_sample_at",
            "imu_latest_sample_at",
        ):
            latest = getattr(self, field).astimezone(timezone.utc)
            if latest < started or latest > ended or (ended - latest).total_seconds() > 0.2:
                raise ValueError(f"{field} is not fresh in the sampling window")
        finite = (
            self.command_max_abs_component,
            self.motor_max_abs_rps,
            self.imu_sample_rate_hz,
            self.imu_max_abs_angular_z_rad_s,
            self.imu_max_abs_z_bias_residual_rad_s,
        )
        if not all(math.isfinite(value) for value in finite):
            raise ValueError("fresh-zero metrics must be finite")
        if self.evidence_sha256 != compute_motion_payload_digest(self.unsigned_payload()):
            raise ValueError("fresh-zero evidence digest mismatch")
        return self


class LanderPiZeroMotionStatus(_StrictModel):
    schema_version: Literal["rolo-landerpi-zero-motion-status/v1"] = "rolo-landerpi-zero-motion-status/v1"
    observed_at: datetime
    provider_process_state: Literal["ABSENT", "ARMED_ZERO"]
    publisher_identity: str | None = Field(default=None, pattern=_IDENTITY)
    publisher_gid: str | None = Field(default=None, pattern=r"^[0-9A-Fa-f][0-9A-Fa-f.:-]{7,254}$")
    call_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    session_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    execution_subject_digest: str | None = Field(default=None, pattern=_SHA256)
    provider_pid: int | None = Field(default=None, ge=1, le=2_147_483_647)
    provider_start_time_ticks: int | None = Field(default=None, ge=1, le=(1 << 63) - 1)
    provider_runtime_sha256: str | None = Field(default=None, pattern=_SHA256)
    provider_cmdline_sha256: str | None = Field(default=None, pattern=_SHA256)
    provider_runtime_identity_digest: str | None = Field(default=None, pattern=_SHA256)
    motion_enabled: Literal[False] = False
    last_command_is_zero: Literal[True] | None = None
    motor_output_zero: Literal[True] | None = None
    motors_stopped: Literal[True] | None = None
    zero_velocity_verified: Literal[True] | None = None
    fresh_zero_evidence: FreshZeroMotionEvidence | None = None
    fresh_zero_evidence_digest: str | None = Field(default=None, pattern=_SHA256)
    motion_command_emitted: Literal[False] = False
    provider_invocation_count: Literal[0] = 0

    @model_validator(mode="after")
    def validate_status(self) -> LanderPiZeroMotionStatus:
        _aware(self.observed_at, "observed_at")
        binding_values = (
            self.publisher_gid,
            self.call_id,
            self.session_id,
            self.execution_subject_digest,
            self.provider_pid,
            self.provider_start_time_ticks,
            self.provider_runtime_sha256,
            self.provider_cmdline_sha256,
            self.provider_runtime_identity_digest,
        )
        zero_values = (
            self.last_command_is_zero,
            self.motor_output_zero,
            self.motors_stopped,
            self.zero_velocity_verified,
            self.fresh_zero_evidence,
            self.fresh_zero_evidence_digest,
        )
        if self.provider_process_state == "ABSENT":
            if self.publisher_identity is not None or any(value is not None for value in binding_values + zero_values):
                raise ValueError("absent zero-motion process cannot retain a provider binding")
        else:
            if self.publisher_identity != _PROVIDER_IDENTITY or any(value is None for value in binding_values + zero_values):
                raise ValueError("armed-zero process must expose its exact provider binding")
            ArmedZeroProviderBinding.model_validate(self.binding().model_dump(mode="python"))
            if self.fresh_zero_evidence_digest != self.fresh_zero_evidence.evidence_sha256:
                raise ValueError("armed-zero status does not bind its fresh-zero evidence")
        return self

    def binding(self) -> ArmedZeroProviderBinding:
        if self.provider_process_state != "ARMED_ZERO":
            raise ValueError("absent zero-motion process has no provider binding")
        return ArmedZeroProviderBinding(
            call_id=self.call_id,
            session_id=self.session_id,
            execution_subject_digest=self.execution_subject_digest,
            publisher_identity=self.publisher_identity,
            publisher_gid=self.publisher_gid,
            provider_pid=self.provider_pid,
            provider_start_time_ticks=self.provider_start_time_ticks,
            provider_runtime_sha256=self.provider_runtime_sha256,
            provider_cmdline_sha256=self.provider_cmdline_sha256,
            provider_runtime_identity_digest=self.provider_runtime_identity_digest,
        )


class DebugOnlyUserAttestedAdmission(_StrictModel):
    """Explicitly non-production, session-scoped user safety attestation."""

    schema_version: Literal["rolo-debug-only-user-attested-admission/v1"] = "rolo-debug-only-user-attested-admission/v1"
    attestation_id: str = Field(pattern=_IDENTIFIER)
    acceptance_id: str = Field(pattern=_IDENTIFIER)
    basis: Literal["USER_EXPLICIT_SESSION_ATTESTATION"] = "USER_EXPLICIT_SESSION_ATTESTATION"
    basis_digest: str = Field(pattern=_SHA256)
    call_id: str = Field(pattern=_IDENTIFIER)
    session_id: str = Field(pattern=_IDENTIFIER)
    target_id: str = Field(pattern=_IDENTIFIER)
    target_identity: str = Field(pattern=_IDENTITY)
    operator_id: str = Field(pattern=_IDENTITY)
    execution_subject_digest: str = Field(pattern=_SHA256)
    site_id: str = Field(pattern=_IDENTITY)
    safe_zone_id: str = Field(pattern=_IDENTITY)
    requested_rotation_degrees: float = Field(ge=-1.0, le=1.0)
    requested_linear_meters: float = Field(ge=-0.03, le=0.03)
    max_abs_rotation_degrees: Literal[1.0] = 1.0
    max_abs_linear_meters: Literal[0.03] = 0.03
    onsite_operator_asserted: Literal[True] = True
    independent_estop_available_asserted: Literal[True] = True
    safe_zone_clear_asserted: Literal[True] = True
    production_authority_verified: Literal[False] = False
    fresh_estop_challenge_verified: Literal[False] = False
    one_shot: Literal[True] = True
    issued_at: datetime
    expires_at: datetime
    payload_sha256: str = Field(pattern=_SHA256)

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="python", exclude={"payload_sha256"})

    @model_validator(mode="after")
    def validate_debug_boundary(self) -> DebugOnlyUserAttestedAdmission:
        _aware(self.issued_at, "issued_at")
        _aware(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at or (self.expires_at - self.issued_at).total_seconds() > 30:
            raise ValueError("debug user attestation expiry must be within 30 seconds")
        if not math.isfinite(self.requested_rotation_degrees) or not math.isfinite(self.requested_linear_meters):
            raise ValueError("debug motion bounds must be finite")
        expected = compute_motion_payload_digest(self.unsigned_payload())
        if self.payload_sha256 != expected:
            raise ValueError("debug user attestation payload digest mismatch")
        return self

    @classmethod
    def build(
        cls,
        *,
        attestation_id: str,
        acceptance_id: str,
        intent: MotionSafetyIntent,
        policy: MotionSafetyPolicy,
        basis_text: str,
        requested_rotation_degrees: float,
        requested_linear_meters: float,
        issued_at: datetime,
        expires_at: datetime,
    ) -> DebugOnlyUserAttestedAdmission:
        if not isinstance(basis_text, str) or not basis_text.strip() or len(basis_text.encode("utf-8")) > 4096:
            raise ValueError("debug user attestation basis text is missing or oversized")
        basis_digest = compute_motion_payload_digest(
            {
                "schema_version": "rolo-debug-user-attestation-basis/v1",
                "basis_text": basis_text,
            }
        )
        unsigned: dict[str, Any] = {
            "schema_version": "rolo-debug-only-user-attested-admission/v1",
            "attestation_id": attestation_id,
            "acceptance_id": acceptance_id,
            "basis": "USER_EXPLICIT_SESSION_ATTESTATION",
            "basis_digest": basis_digest,
            "call_id": intent.call_id,
            "session_id": intent.session_id,
            "target_id": intent.target_id,
            "target_identity": intent.target_identity,
            "operator_id": intent.operator_id,
            "execution_subject_digest": intent.execution_subject_digest,
            "site_id": policy.site_id,
            "safe_zone_id": policy.safe_zone_id,
            "requested_rotation_degrees": requested_rotation_degrees,
            "requested_linear_meters": requested_linear_meters,
            "max_abs_rotation_degrees": 1.0,
            "max_abs_linear_meters": 0.03,
            "onsite_operator_asserted": True,
            "independent_estop_available_asserted": True,
            "safe_zone_clear_asserted": True,
            "production_authority_verified": False,
            "fresh_estop_challenge_verified": False,
            "one_shot": True,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        return cls.model_validate(
            {
                **unsigned,
                "payload_sha256": compute_motion_payload_digest(unsigned),
            }
        )


DebugAcceptanceStatus = Literal["DEBUG_BLOCKED", "DEBUG_ACCEPTED"]
DebugConsumptionStatus = Literal["DEBUG_BLOCKED", "DEBUG_CONSUMED"]


class DebugUserAttestedAcceptanceReceipt(_StrictModel):
    schema_version: Literal["rolo-debug-user-attested-zero-motion-acceptance/v1"] = "rolo-debug-user-attested-zero-motion-acceptance/v1"
    status: DebugAcceptanceStatus
    report_status: Literal["DEBUG_BLOCKED", "PASS_WITH_USER_ATTESTED_SITE_SAFETY"]
    reasons: tuple[str, ...]
    evaluated_at: datetime
    acceptance_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    call_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    session_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    target_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    target_identity: str | None = Field(default=None, pattern=_IDENTITY)
    operator_id: str | None = Field(default=None, pattern=_IDENTITY)
    execution_subject_digest: str | None = Field(default=None, pattern=_SHA256)
    debug_admission_digest: str | None = Field(default=None, pattern=_SHA256)
    debug_attestation_artifact: SignedZeroMotionArtifact | None = None
    artifacts: ZeroMotionArtifactDigests = Field(default_factory=ZeroMotionArtifactDigests)
    provider_gate: SignedZeroMotionArtifact | None = None
    debug_gate_ready: bool = False
    production_ready: Literal[False] = False
    production_authority_verified: Literal[False] = False
    fresh_estop_challenge_verified: Literal[False] = False
    motion_authorized: Literal[False] = False
    provider_boundary_open: Literal[False] = False
    max_abs_rotation_degrees: Literal[1.0] = 1.0
    max_abs_linear_meters: Literal[0.03] = 0.03
    one_shot: Literal[True] = True

    @model_validator(mode="after")
    def validate_result(self) -> DebugUserAttestedAcceptanceReceipt:
        _aware(self.evaluated_at, "evaluated_at")
        if self.status == "DEBUG_ACCEPTED":
            if self.report_status != "PASS_WITH_USER_ATTESTED_SITE_SAFETY" or self.reasons:
                raise ValueError("debug accepted receipt has inconsistent status")
            if not self.debug_gate_ready or None in (
                self.call_id,
                self.acceptance_id,
                self.session_id,
                self.target_id,
                self.target_identity,
                self.operator_id,
                self.execution_subject_digest,
                self.debug_admission_digest,
                self.debug_attestation_artifact,
                self.provider_gate,
            ):
                raise ValueError("debug accepted receipt is incomplete")
        elif self.report_status != "DEBUG_BLOCKED" or not self.reasons or self.debug_gate_ready:
            raise ValueError("debug blocked receipt has inconsistent status")
        return self


class DebugUserAttestedProviderGateReceipt(_StrictModel):
    schema_version: Literal["rolo-debug-user-attested-provider-gate/v1"] = "rolo-debug-user-attested-provider-gate/v1"
    status: DebugConsumptionStatus
    report_status: Literal["DEBUG_BLOCKED", "PASS_WITH_USER_ATTESTED_SITE_SAFETY"]
    reasons: tuple[str, ...]
    evaluated_at: datetime
    acceptance_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    call_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    session_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    target_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    target_identity: str | None = Field(default=None, pattern=_IDENTITY)
    operator_id: str | None = Field(default=None, pattern=_IDENTITY)
    execution_subject_digest: str | None = Field(default=None, pattern=_SHA256)
    debug_admission_digest: str | None = Field(default=None, pattern=_SHA256)
    challenge_artifact_digest: str | None = Field(default=None, pattern=_SHA256)
    debug_attestation_artifact: SignedZeroMotionArtifact | None = None
    challenge_artifact: SignedZeroMotionArtifact | None = None
    consume_artifact: SignedZeroMotionArtifact | None = None
    debug_provider_boundary_open: bool = False
    production_provider_boundary_open: Literal[False] = False
    production_ready: Literal[False] = False
    production_authority_verified: Literal[False] = False
    fresh_estop_challenge_verified: Literal[False] = False
    debug_motion_authorized: bool = False
    provider_invocation_limit: int = Field(default=0, ge=0, le=1)
    max_abs_rotation_degrees: Literal[1.0] = 1.0
    max_abs_linear_meters: Literal[0.03] = 0.03
    one_shot: Literal[True] = True

    @model_validator(mode="after")
    def validate_result(self) -> DebugUserAttestedProviderGateReceipt:
        _aware(self.evaluated_at, "evaluated_at")
        if self.status == "DEBUG_CONSUMED":
            if (
                self.report_status != "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
                or self.reasons
                or not self.debug_provider_boundary_open
                or not self.debug_motion_authorized
                or self.provider_invocation_limit != 1
                or None
                in (
                    self.call_id,
                    self.acceptance_id,
                    self.session_id,
                    self.target_id,
                    self.target_identity,
                    self.operator_id,
                    self.execution_subject_digest,
                    self.debug_admission_digest,
                    self.challenge_artifact_digest,
                    self.debug_attestation_artifact,
                    self.challenge_artifact,
                    self.consume_artifact,
                )
            ):
                raise ValueError("debug consumed receipt is incomplete")
        elif self.report_status != "DEBUG_BLOCKED" or not self.reasons or self.debug_provider_boundary_open or self.debug_motion_authorized or self.provider_invocation_limit != 0:
            raise ValueError("debug blocked receipt has inconsistent status")
        return self


class DebugProviderGateValidationReceipt(_StrictModel):
    """Detached service-facing validation result for the explicit debug union arm."""

    schema_version: Literal["rolo-debug-user-attested-provider-gate-validation/v1"] = "rolo-debug-user-attested-provider-gate-validation/v1"
    status: Literal["VALID"] = "VALID"
    report_status: Literal["PASS_WITH_USER_ATTESTED_SITE_SAFETY"] = "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
    validated_at: datetime
    expires_at: datetime
    acceptance_id: str = Field(pattern=_IDENTIFIER)
    call_id: str = Field(pattern=_IDENTIFIER)
    session_id: str = Field(pattern=_IDENTIFIER)
    target_id: str = Field(pattern=_IDENTIFIER)
    target_identity: str = Field(pattern=_IDENTITY)
    operator_id: str = Field(pattern=_IDENTITY)
    execution_subject_digest: str = Field(pattern=_SHA256)
    debug_admission_digest: str = Field(pattern=_SHA256)
    debug_attestation_artifact_digest: str = Field(pattern=_SHA256)
    challenge_artifact_digest: str = Field(pattern=_SHA256)
    consume_artifact_digest: str = Field(pattern=_SHA256)
    provider_gate_receipt_digest: str = Field(pattern=_SHA256)
    armed_zero_provider_binding: ArmedZeroProviderBinding
    requested_rotation_degrees: float = Field(ge=-1, le=1)
    requested_linear_meters: float = Field(ge=-0.03, le=0.03)
    max_abs_rotation_degrees: Literal[1.0] = 1.0
    max_abs_linear_meters: Literal[0.03] = 0.03
    debug_provider_boundary_open: Literal[True] = True
    debug_motion_authorized: Literal[True] = True
    provider_invocation_limit: Literal[1] = 1
    production_provider_boundary_open: Literal[False] = False
    production_ready: Literal[False] = False
    production_authority_verified: Literal[False] = False
    fresh_estop_challenge_verified: Literal[False] = False
    one_shot: Literal[True] = True

    @model_validator(mode="after")
    def validate_window(self) -> DebugProviderGateValidationReceipt:
        _aware(self.validated_at, "validated_at")
        _aware(self.expires_at, "expires_at")
        if self.validated_at >= self.expires_at:
            raise ValueError("debug provider gate validation is expired")
        return self


class LanderPiTargetMotionState(_StrictModel):
    schema_version: Literal["rolo-landerpi-target-motion-state/v1"] = "rolo-landerpi-target-motion-state/v1"
    target_id: str = Field(pattern=_IDENTIFIER)
    target_identity: str = Field(pattern=_IDENTITY)
    state_revision: int = Field(ge=0)
    phase: TargetMotionPhase
    fence_epoch: int = Field(ge=1)
    fence_digest: str = Field(pattern=_SHA256)
    acceptance_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    call_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    session_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    execution_subject_digest: str | None = Field(default=None, pattern=_SHA256)
    graph_revision: str | None = Field(default=None, pattern=_SHA256)
    pre_snapshot_digest: str | None = Field(default=None, pattern=_SHA256)
    rehearsal_cas_digest: str | None = Field(default=None, pattern=_SHA256)
    start_ack_digest: str | None = Field(default=None, pattern=_SHA256)
    stop_ack_digest: str | None = Field(default=None, pattern=_SHA256)
    post_snapshot_digest: str | None = Field(default=None, pattern=_SHA256)
    release_artifact_digest: str | None = Field(default=None, pattern=_SHA256)
    challenge_artifact_digest: str | None = Field(default=None, pattern=_SHA256)
    consume_token_digest: str | None = Field(default=None, pattern=_SHA256)
    consume_artifact_digest: str | None = Field(default=None, pattern=_SHA256)
    debug_admission_digest: str | None = Field(default=None, pattern=_SHA256)
    debug_attestation_artifact_digest: str | None = Field(default=None, pattern=_SHA256)
    armed_provider_binding: ArmedZeroProviderBinding | None = None
    last_artifact_digest: str | None = Field(default=None, pattern=_SHA256)
    updated_at: datetime

    @model_validator(mode="after")
    def validate_state(self) -> LanderPiTargetMotionState:
        _aware(self.updated_at, "updated_at")
        bound = (
            self.acceptance_id,
            self.call_id,
            self.session_id,
            self.execution_subject_digest,
        )
        if self.phase == "SAFE_BASELINE":
            if any(value is not None for value in bound) or self.armed_provider_binding is not None or self.debug_admission_digest is not None or self.debug_attestation_artifact_digest is not None:
                raise ValueError("safe baseline cannot retain an acceptance owner")
        else:
            if any(value is None for value in bound):
                raise ValueError("active motion state must retain exact acceptance identity")
            if self.phase != "DEBUG_ATTESTED" and self.armed_provider_binding is None:
                raise ValueError("active motion state must retain the pre-armed provider binding")
            if self.phase == "DEBUG_ATTESTED" and None in (
                self.debug_admission_digest,
                self.debug_attestation_artifact_digest,
            ):
                raise ValueError("debug-attested state must retain its one-shot admission digest")
        if self.phase in {"CHALLENGE_PENDING", "PROVIDER_FENCE"}:
            if self.challenge_artifact_digest is None or self.consume_token_digest is None:
                raise ValueError("provider challenge state is incomplete")
        if self.phase == "PROVIDER_FENCE" and self.consume_artifact_digest is None:
            raise ValueError("provider fence must retain its consume artifact")
        compute_motion_payload_digest(self.model_dump(mode="python"))
        return self

    @classmethod
    def initial(
        cls,
        intent: MotionSafetyIntent,
        *,
        fence_epoch: int,
        now: datetime,
    ) -> LanderPiTargetMotionState:
        expected = _fence_digest(intent, fence_epoch)
        if intent.direct_motor_fence_digest != expected:
            raise ValueError("initial intent fence does not match its epoch")
        return cls(
            target_id=intent.target_id,
            target_identity=intent.target_identity,
            state_revision=0,
            phase="SAFE_BASELINE",
            fence_epoch=fence_epoch,
            fence_digest=expected,
            updated_at=now,
        )


class PinnedLanderPiMotionRpc(Protocol):
    """Narrow RPC surface; implementations may wrap a pinned SSH transport."""

    def security_context(self) -> PinnedLanderPiRpcSecurity | Mapping[str, Any]: ...

    def topic_info_verbose(self, *, route: str, expected_interface: str) -> str: ...

    def zero_motion_status(self) -> LanderPiZeroMotionStatus | Mapping[str, Any]: ...


class LanderPiMotionStateStore(Protocol):
    def load(self) -> LanderPiTargetMotionState: ...

    def compare_and_set(
        self,
        *,
        expected: LanderPiTargetMotionState,
        replacement: LanderPiTargetMotionState,
        artifact: SignedZeroMotionArtifact,
    ) -> bool: ...

    def get_artifact(self, payload_sha256: str) -> SignedZeroMotionArtifact | None: ...

    def reserve_debug_admission(self, payload_sha256: str) -> bool: ...


class TargetSigningKey:
    """Redacted signing material accepted only from memory, a file, or an FD."""

    __slots__ = ("_key",)

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes) or not 32 <= len(key) <= 4096:
            raise ValueError("target signing key size is outside safe bounds")
        self._key = bytes(key)

    @classmethod
    def from_bytes(cls, key: bytes) -> TargetSigningKey:
        return cls(key)

    @classmethod
    def from_fd(cls, fd: int) -> TargetSigningKey:
        if not isinstance(fd, int) or isinstance(fd, bool) or fd < 0:
            raise ValueError("target signing key file descriptor is invalid")
        duplicate = os.dup(fd)
        try:
            with os.fdopen(duplicate, "rb", closefd=True) as stream:
                key = stream.read(4097)
        except Exception as exc:
            raise ValueError("target signing key file descriptor is unreadable") from exc
        return cls(key)

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> TargetSigningKey:
        source = Path(path)
        try:
            metadata = source.lstat()
        except OSError as exc:
            raise ValueError("target signing key file is unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("target signing key must be a regular non-symlink file")
        if os.name != "nt" and metadata.st_mode & 0o077:
            raise ValueError("target signing key file permissions are too broad")
        try:
            with source.open("rb") as stream:
                key = stream.read(4097)
        except OSError as exc:
            raise ValueError("target signing key file is unreadable") from exc
        return cls(key)

    def _material(self) -> bytes:
        return self._key

    def __repr__(self) -> str:
        return "TargetSigningKey(<redacted>)"


class DebugPinnedTargetdPeerBootstrapReceipt(_StrictModel):
    """Short-lived outer-channel proof for the explicit field-debug composition.

    This receipt is deliberately not a production authority assertion.  The
    signing key is an ephemeral bootstrap secret delivered through the already
    pinned SSH stdio channel; it must never be an SSH private key or a controller
    authority private key.
    """

    schema_version: Literal["rolo-debug-pinned-targetd-peer-bootstrap/v1"] = "rolo-debug-pinned-targetd-peer-bootstrap/v1"
    status: Literal["DEBUG_ONLY_FIXED_PINNED_SSH_PEER"] = "DEBUG_ONLY_FIXED_PINNED_SSH_PEER"
    capability_id: str = Field(pattern=_IDENTIFIER)
    bootstrap_authority_id: str = Field(pattern=_IDENTITY)
    target_id: str = Field(pattern=_IDENTIFIER)
    target_identity: str = Field(pattern=_IDENTITY)
    call_id: str = Field(pattern=_IDENTIFIER)
    session_id: str = Field(pattern=_IDENTIFIER)
    execution_subject_digest: str = Field(pattern=_SHA256)
    ssh_host: str = Field(min_length=1, max_length=255)
    ssh_port: int = Field(ge=1, le=65535)
    ssh_username: Literal["pi"] = "pi"
    pinned_host_key_sha256: str = Field(pattern=_SHA256)
    observed_host_key_sha256: str = Field(pattern=_SHA256)
    client_public_key_sha256: str = Field(pattern=_SHA256)
    known_hosts_sha256: str = Field(pattern=_SHA256)
    channel_binding_sha256: str = Field(pattern=_SHA256)
    bootstrap_nonce_sha256: str = Field(pattern=_SHA256)
    public_key_auth_verified: Literal[True] = True
    host_key_verified: Literal[True] = True
    password_used: Literal[False] = False
    keyboard_interactive_used: Literal[False] = False
    batch_mode: Literal[True] = True
    strict_host_key_checking: Literal[True] = True
    local_subprocess_shell_used: Literal[False] = False
    remote_login_shell_used: Literal[True] = True
    production_peer_verified: Literal[False] = False
    one_shot: Literal[True] = True
    issued_at: datetime
    expires_at: datetime
    payload_sha256: str = Field(pattern=_SHA256)
    signature_hmac_sha256: str = Field(pattern=_HMAC_SHA256)

    @model_validator(mode="before")
    @classmethod
    def validate_shell_semantics(cls, value: Any) -> Any:
        if isinstance(value, Mapping) and (
            value.get("local_subprocess_shell_used") is not False
            or value.get("remote_login_shell_used") is not True
        ):
            raise ValueError(
                "debug pinned peer proof must record local shell=False and remote login shell=True"
            )
        return value

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="python",
            exclude={"payload_sha256", "signature_hmac_sha256"},
        )

    @model_validator(mode="after")
    def validate_bootstrap(self) -> DebugPinnedTargetdPeerBootstrapReceipt:
        _aware(self.issued_at, "issued_at")
        _aware(self.expires_at, "expires_at")
        if _SSH_HOST.fullmatch(self.ssh_host) is None:
            raise ValueError("debug pinned peer SSH host is invalid")
        if self.pinned_host_key_sha256 != self.observed_host_key_sha256:
            raise ValueError("debug pinned peer host key does not match the configured pin")
        lifetime = (self.expires_at - self.issued_at).total_seconds()
        if not 0 < lifetime <= 60:
            raise ValueError("debug pinned peer bootstrap lifetime must be at most 60 seconds")
        if self.payload_sha256 != compute_motion_payload_digest(self.unsigned_payload()):
            raise ValueError("debug pinned peer bootstrap digest mismatch")
        return self

    @classmethod
    def build(
        cls,
        *,
        capability_id: str,
        bootstrap_authority_id: str,
        target_id: str,
        target_identity: str,
        call_id: str,
        session_id: str,
        execution_subject_digest: str,
        ssh_host: str,
        ssh_port: int,
        pinned_host_key_sha256: str,
        client_public_key_sha256: str,
        known_hosts_sha256: str,
        channel_binding_sha256: str,
        bootstrap_nonce: bytes,
        issued_at: datetime,
        expires_at: datetime,
        signing_key: TargetSigningKey,
    ) -> DebugPinnedTargetdPeerBootstrapReceipt:
        if not isinstance(bootstrap_nonce, bytes) or len(bootstrap_nonce) != 32:
            raise ValueError("debug pinned peer bootstrap nonce must contain exactly 32 bytes")
        if not isinstance(signing_key, TargetSigningKey):
            raise ValueError("typed ephemeral bootstrap signing key is required")
        unsigned: dict[str, Any] = {
            "schema_version": "rolo-debug-pinned-targetd-peer-bootstrap/v1",
            "status": "DEBUG_ONLY_FIXED_PINNED_SSH_PEER",
            "capability_id": capability_id,
            "bootstrap_authority_id": bootstrap_authority_id,
            "target_id": target_id,
            "target_identity": target_identity,
            "call_id": call_id,
            "session_id": session_id,
            "execution_subject_digest": execution_subject_digest,
            "ssh_host": ssh_host,
            "ssh_port": ssh_port,
            "ssh_username": "pi",
            "pinned_host_key_sha256": pinned_host_key_sha256,
            "observed_host_key_sha256": pinned_host_key_sha256,
            "client_public_key_sha256": client_public_key_sha256,
            "known_hosts_sha256": known_hosts_sha256,
            "channel_binding_sha256": channel_binding_sha256,
            "bootstrap_nonce_sha256": "sha256:" + hashlib.sha256(bootstrap_nonce).hexdigest(),
            "public_key_auth_verified": True,
            "host_key_verified": True,
            "password_used": False,
            "keyboard_interactive_used": False,
            "batch_mode": True,
            "strict_host_key_checking": True,
            # OpenSSH itself is launched directly, while its fixed remote command
            # is necessarily evaluated by the account's remote login shell.
            "local_subprocess_shell_used": False,
            "remote_login_shell_used": True,
            "production_peer_verified": False,
            "one_shot": True,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        payload_sha256 = compute_motion_payload_digest(unsigned)
        signature = hmac.new(
            signing_key._material(),
            payload_sha256.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return cls.model_validate(
            {
                **unsigned,
                "payload_sha256": payload_sha256,
                "signature_hmac_sha256": "hmac-sha256:" + signature,
            }
        )


class DebugPinnedPeerBootstrapReplayStore:
    """Durably burns a verified bootstrap digest before creating a capability."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        requested = Path(root)
        if not requested.is_absolute():
            raise ValueError("debug pinned peer replay root must be absolute")
        self.root = requested.resolve()
        self._lock = threading.Lock()

    def reserve(self, payload_sha256: str) -> bool:
        if re.fullmatch(_SHA256, payload_sha256) is None:
            raise ValueError("debug pinned peer bootstrap digest is invalid")
        self.root.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(self.root, 0o700)
        marker = self.root / (payload_sha256.removeprefix("sha256:") + ".consumed")
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        with self._lock:
            try:
                descriptor = os.open(marker, flags, 0o600)
            except FileExistsError:
                return False
            try:
                payload = (payload_sha256 + "\n").encode("ascii")
                if os.write(descriptor, payload) != len(payload):
                    raise OSError("short write while reserving debug peer bootstrap")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return True


_PEER_CAPABILITY_TOKEN = object()


class PinnedTargetdPeerCapability:
    """Opaque in-process capability produced only after bootstrap verification."""

    __slots__ = ("_receipt", "_claimed", "_lock")

    def __init__(
        self,
        token: object,
        receipt: DebugPinnedTargetdPeerBootstrapReceipt,
    ) -> None:
        if token is not _PEER_CAPABILITY_TOKEN:
            raise TypeError("PinnedTargetdPeerCapability is factory-only")
        self._receipt = receipt
        self._claimed = False
        self._lock = threading.Lock()

    def _claim_for_local_transport(self) -> PinnedLanderPiRpcSecurity:
        with self._lock:
            if self._claimed:
                raise RuntimeError("DEBUG_PINNED_TARGETD_PEER_CAPABILITY_ALREADY_CONSUMED")
            self._claimed = True
        return PinnedLanderPiRpcSecurity(
            target_id=self._receipt.target_id,
            target_identity=self._receipt.target_identity,
            pinned_host_key_sha256=self._receipt.pinned_host_key_sha256,
            observed_host_key_sha256=self._receipt.observed_host_key_sha256,
            peer_provenance="DEBUG_ONLY_FIXED_PEER",
            production_peer_verified=False,
        )

    @property
    def bootstrap_receipt_digest(self) -> str:
        return self._receipt.payload_sha256

    def __repr__(self) -> str:
        return "PinnedTargetdPeerCapability(<verified, one-shot>)"


def consume_debug_pinned_targetd_peer_bootstrap(
    receipt: DebugPinnedTargetdPeerBootstrapReceipt | Mapping[str, Any],
    *,
    verification_key: TargetSigningKey,
    replay_store: DebugPinnedPeerBootstrapReplayStore,
    expected_bootstrap_authority_id: str,
    expected_target_id: str,
    expected_target_identity: str,
    expected_call_id: str,
    expected_session_id: str,
    expected_execution_subject_digest: str,
    expected_ssh_host: str,
    expected_ssh_port: int,
    expected_pinned_host_key_sha256: str,
    expected_client_public_key_sha256: str,
    expected_known_hosts_sha256: str,
    expected_channel_binding_sha256: str,
    at: datetime,
) -> PinnedTargetdPeerCapability:
    """Verify and burn a debug outer-channel receipt on the targetd host."""

    if not isinstance(verification_key, TargetSigningKey):
        raise ValueError("typed ephemeral bootstrap verification key is required")
    if not isinstance(replay_store, DebugPinnedPeerBootstrapReplayStore):
        raise ValueError("typed debug pinned peer replay store is required")
    parsed = DebugPinnedTargetdPeerBootstrapReceipt.model_validate(receipt.model_dump(mode="python") if isinstance(receipt, BaseModel) else receipt)
    point = _point(lambda: at)
    exact = (
        (parsed.bootstrap_authority_id, expected_bootstrap_authority_id),
        (parsed.target_id, expected_target_id),
        (parsed.target_identity, expected_target_identity),
        (parsed.call_id, expected_call_id),
        (parsed.session_id, expected_session_id),
        (parsed.execution_subject_digest, expected_execution_subject_digest),
        (parsed.ssh_host, expected_ssh_host),
        (parsed.ssh_port, expected_ssh_port),
        (parsed.pinned_host_key_sha256, expected_pinned_host_key_sha256),
        (parsed.client_public_key_sha256, expected_client_public_key_sha256),
        (parsed.known_hosts_sha256, expected_known_hosts_sha256),
        (parsed.channel_binding_sha256, expected_channel_binding_sha256),
    )
    if any(observed != expected for observed, expected in exact):
        raise RuntimeError("DEBUG_PINNED_TARGETD_PEER_IDENTITY_MISMATCH")
    if point < parsed.issued_at.astimezone(timezone.utc) or point >= parsed.expires_at.astimezone(timezone.utc):
        raise RuntimeError("DEBUG_PINNED_TARGETD_PEER_BOOTSTRAP_EXPIRED")
    expected_signature = (
        "hmac-sha256:"
        + hmac.new(
            verification_key._material(),
            parsed.payload_sha256.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
    )
    if not hmac.compare_digest(parsed.signature_hmac_sha256, expected_signature):
        raise RuntimeError("DEBUG_PINNED_TARGETD_PEER_BOOTSTRAP_SIGNATURE_INVALID")
    if not replay_store.reserve(parsed.payload_sha256):
        raise RuntimeError("DEBUG_PINNED_TARGETD_PEER_BOOTSTRAP_REPLAYED")
    return PinnedTargetdPeerCapability(_PEER_CAPABILITY_TOKEN, parsed)


class LanderPiArmedRegistrySnapshot(_StrictModel):
    """Raw, bounded target-side re-observation returned by the narrow RPC."""

    schema_version: Literal["rolo-landerpi-armed-registry-snapshot/v1"] = "rolo-landerpi-armed-registry-snapshot/v1"
    observed_at: datetime
    registry_present: bool
    registry_auth_verified: Literal[True] = True
    process_match_count: int = Field(ge=0, le=1)
    registry_json: str | None = Field(default=None, max_length=65_536)
    live_pid: int | None = Field(default=None, ge=1, le=2_147_483_647)
    live_start_time_ticks: int | None = Field(default=None, ge=1, le=(1 << 63) - 1)
    live_cmdline_base64: str | None = Field(default=None, max_length=16_384)
    live_runtime_sha256: str | None = Field(default=None, pattern=_SHA256)
    command_topic_info_verbose: str | None = Field(default=None, max_length=65_536)
    competing_topic_info_verbose: str | None = Field(default=None, max_length=65_536)
    direct_motor_topic_info_verbose: str | None = Field(default=None, max_length=65_536)
    fresh_zero_evidence: FreshZeroMotionEvidence | None = None
    shell_used: Literal[False] = False

    @model_validator(mode="after")
    def validate_snapshot_shape(self) -> LanderPiArmedRegistrySnapshot:
        _aware(self.observed_at, "observed_at")
        live = (
            self.registry_json,
            self.live_pid,
            self.live_start_time_ticks,
            self.live_cmdline_base64,
            self.live_runtime_sha256,
            self.command_topic_info_verbose,
            self.competing_topic_info_verbose,
            self.direct_motor_topic_info_verbose,
            self.fresh_zero_evidence,
        )
        if self.registry_present:
            if self.process_match_count != 1 or any(value is None for value in live):
                raise ValueError("armed registry snapshot must contain one complete live process")
        elif self.process_match_count != 0 or any(value is not None for value in live):
            raise ValueError("absent registry snapshot cannot retain live process data")
        return self


class PinnedLanderPiReadControlTransport(Protocol):
    """Narrow transport: no generic command, shell, provider, motor, or publish API."""

    def security_context(self) -> PinnedLanderPiRpcSecurity | Mapping[str, Any]: ...

    def read_topic_info_verbose(self, *, route: str, expected_interface: str) -> str: ...

    def read_isolation_topic_info_bundle(self) -> Mapping[str, str]: ...

    def read_and_verify_armed_registry_snapshot(self) -> LanderPiArmedRegistrySnapshot | Mapping[str, Any]: ...


class TargetPhysicalWorkerRegistryRecord(_StrictModel):
    """The one wire record emitted by ``physical_worker``; never translated."""

    schema_version: Literal["rolo-targetd-physical-worker-registry/v1"]
    state: Literal["ACTIVE", "TERMINAL"]
    arm_receipt: dict[str, Any] = Field(max_length=64)
    updated_at_epoch_s: float
    zero_refresh_count: int = Field(ge=0)
    last_zero_at_epoch_s: float
    terminal_reason: str | None = Field(default=None, max_length=128)
    registry_auth_tag: str = Field(pattern=_HMAC_SHA256)

    @model_validator(mode="after")
    def validate_record(self) -> TargetPhysicalWorkerRegistryRecord:
        if (
            not math.isfinite(self.updated_at_epoch_s)
            or self.updated_at_epoch_s <= 0
            or not math.isfinite(self.last_zero_at_epoch_s)
            or self.last_zero_at_epoch_s <= 0
            or self.last_zero_at_epoch_s > self.updated_at_epoch_s
        ):
            raise ValueError("physical worker registry update time is invalid")
        if self.state == "ACTIVE" and self.terminal_reason is not None:
            raise ValueError("active physical worker registry cannot have a terminal reason")
        if self.state == "TERMINAL" and not self.terminal_reason:
            raise ValueError("terminal physical worker registry requires a reason")
        return self


def _loads_unique_object(raw: str) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > 65_536 or "\x00" in raw:
        raise ValueError("JSON object is missing or oversized")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("JSON object contains a duplicate key")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("JSON value must be an object")
    return value


def _canonical_gid(value: str) -> str:
    return re.sub(r"[.:-]", "", value).lower()


_TARGET_SIDE_MOTION_SNAPSHOT_SUFFIX = r"""
import base64 as _zb, datetime as _zdt, hashlib as _zh, json as _zj, math as _zm, os as _zo, statistics as _zst, sys as _zs, time as _zt

def _zidentity(info):
    name = str(getattr(info, 'node_name', '')).strip().strip('/')
    namespace = str(getattr(info, 'node_namespace', '')).strip().rstrip('/')
    if not name: raise RuntimeError('GRAPH_NODE_NAME_INVALID')
    return (namespace + '/' + name) if namespace else ('/' + name)

def _zgid(info):
    value = bytes(getattr(info, 'endpoint_gid', b'')).hex()
    if len(value) < 16: raise RuntimeError('GRAPH_ENDPOINT_GID_INVALID')
    return value

def _ztopic_node(node, route, interface):
    pubs = node.get_publishers_info_by_topic(route); subs = node.get_subscriptions_info_by_topic(route)
    def records(values, endpoint_type):
        result = []
        for item in values:
            topic_type = str(getattr(item, 'topic_type', ''))
            if topic_type != interface: raise RuntimeError('GRAPH_INTERFACE_MISMATCH')
            identity = _zidentity(item); namespace, _, name = identity.rpartition('/')
            result.append((identity, name, namespace or '/', endpoint_type, _zgid(item)))
        result.sort(key=lambda item:(item[0], item[4]))
        return result
    publishers = records(pubs, 'PUBLISHER'); subscribers = records(subs, 'SUBSCRIPTION')
    lines = ['Type: ' + interface, 'Publisher count: ' + str(len(publishers))]
    for _, name, namespace, endpoint_type, gid in publishers:
        lines += ['Node name: ' + name, 'Node namespace: ' + namespace, 'Endpoint type: ' + endpoint_type, 'GID: ' + gid]
    lines += ['Subscription count: ' + str(len(subscribers))]
    for _, name, namespace, endpoint_type, gid in subscribers:
        lines += ['Node name: ' + name, 'Node namespace: ' + namespace, 'Endpoint type: ' + endpoint_type, 'GID: ' + gid]
    return '\n'.join(lines) + '\n'

def _ztopic(route, interface):
    import rclpy as _zr
    _zr.init(args=None); node = _zr.create_node('rolo_targetd_motion_snapshot_%d' % _zo.getpid())
    try: return _ztopic_node(node, route, interface)
    finally: node.destroy_node(); _zr.shutdown()

def _zgraph_bundle(node):
    return {
        '/cmd_vel':_ztopic_node(node, '/cmd_vel', 'geometry_msgs/msg/Twist'),
        '/controller/cmd_vel':_ztopic_node(node, '/controller/cmd_vel', 'geometry_msgs/msg/Twist'),
        '/ros_robot_controller/set_motor':_ztopic_node(node, '/ros_robot_controller/set_motor', 'ros_robot_controller_msgs/msg/MotorsState'),
    }

def _zgraph_ready(outputs):
    combined = ''.join(outputs.values())
    odom_subscription = 'Node name: odom_publisher\nNode namespace: /\nEndpoint type: SUBSCRIPTION\n'
    odom_publisher = 'Node name: odom_publisher\nNode namespace: /\nEndpoint type: PUBLISHER\n'
    command = outputs['/cmd_vel']; competing = outputs['/controller/cmd_vel']; direct = outputs['/ros_robot_controller/set_motor']
    command_publishers_valid = (
        'Publisher count: 0\n' in command
        or (
            'Publisher count: 1\n' in command
            and 'Node name: rolo_bounded_twist\nNode namespace: /\nEndpoint type: PUBLISHER\n' in command
        )
    )
    return (
        '_NODE_NAME_UNKNOWN_' not in combined
        and '_NODE_NAMESPACE_UNKNOWN_' not in combined
        and command_publishers_valid
        and odom_subscription in command
        and 'Publisher count: 0\n' in competing
        and odom_subscription in competing
        and 'Publisher count: 1\n' in direct
        and odom_publisher in direct
    )

def _zwait_graph(node):
    import rclpy as _zr
    started = _zt.monotonic(); deadline = started + 4.0; previous = None; stable_since = None
    while _zt.monotonic() < deadline:
        _zr.spin_once(node, timeout_sec=0.05)
        outputs = _zgraph_bundle(node)
        if _zgraph_ready(outputs):
            current = _zt.monotonic()
            stable_since = stable_since if outputs == previous else current
            if current - started >= 1.25 and current - stable_since >= 0.5:
                return outputs
        else: stable_since = None
        previous = outputs
    raise RuntimeError('GRAPH_DISCOVERY_TIMEOUT')

def _ziso(value):
    return _zdt.datetime.fromtimestamp(value, _zdt.timezone.utc).isoformat().replace('+00:00', 'Z')

def _zdigest(value):
    raw = _zj.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')
    return 'sha256:' + _zh.sha256(raw).hexdigest()

def _zfresh_zero(node):
    import rclpy as _zr
    from geometry_msgs.msg import Twist as _zTwist
    from sensor_msgs.msg import Imu as _zImu
    from ros_robot_controller_msgs.msg import MotorsState as _zMotorsState
    from rclpy.qos import DurabilityPolicy as _zDur, QoSProfile as _zQoS, ReliabilityPolicy as _zRel
    qos = _zQoS(depth=20, reliability=_zRel.RELIABLE, durability=_zDur.VOLATILE)
    command = []; motor = []; imus = {'/imu':[], '/imu_corrected':[], '/ros_robot_controller/imu_raw':[]}
    def finite(value):
        result = float(value)
        if not _zm.isfinite(result): raise RuntimeError('ZERO_SAMPLE_NONFINITE')
        return result
    def on_command(message):
        command.append([_zt.time(), finite(message.linear.x), finite(message.linear.y), finite(message.linear.z), finite(message.angular.x), finite(message.angular.y), finite(message.angular.z)])
    def on_motor(message):
        values = getattr(message, 'data', None) or getattr(message, 'motors', None)
        if not values: raise RuntimeError('MOTOR_ZERO_SAMPLE_EMPTY')
        motor.append([_zt.time(), *[finite(getattr(item, 'rps')) for item in values]])
    def on_imu(message, topic):
        imus[topic].append([_zt.time(), finite(message.angular_velocity.z)])
    subscriptions = [
        node.create_subscription(_zTwist, '/cmd_vel', on_command, qos),
        node.create_subscription(_zMotorsState, '/ros_robot_controller/set_motor', on_motor, qos),
    ]
    for topic in imus:
        subscriptions.append(node.create_subscription(_zImu, topic, lambda message, selected=topic: on_imu(message, selected), qos))
    started = _zt.time(); deadline = _zt.monotonic() + 0.4
    while _zt.monotonic() < deadline: _zr.spin_once(node, timeout_sec=0.02)
    ended = _zt.time()
    selected = max(imus, key=lambda topic: len(imus[topic])); imu = imus[selected]
    all_imu = [item for stream in imus.values() for item in stream]
    imu_values = [item[1] for item in all_imu]
    bias = _zst.median(imu_values) if imu_values else 0.0
    span = (imu[-1][0] - imu[0][0]) if len(imu) >= 2 else 0.0
    evidence = {
        'schema_version':'rolo-landerpi-fresh-zero-motion-evidence/v1',
        'window_started_at':_ziso(started),'window_ended_at':_ziso(ended),
        'command_sample_count':len(command),'command_latest_sample_at':_ziso(command[-1][0] if command else started),
        'command_max_abs_component':max((abs(value) for item in command for value in item[1:]), default=1.0),
        'command_samples_digest':_zdigest(command),
        'motor_sample_count':len(motor),'motor_latest_sample_at':_ziso(motor[-1][0] if motor else started),
        'motor_value_count':sum(len(item)-1 for item in motor),
        'motor_max_abs_rps':max((abs(value) for item in motor for value in item[1:]), default=1.0),
        'motor_samples_digest':_zdigest(motor),
        'imu_stream':selected,'imu_sample_count':len(imu),'imu_latest_sample_at':_ziso(imu[-1][0] if imu else started),
        'imu_sample_rate_hz':((len(imu)-1)/span if span > 0 else 0.0),
        'imu_max_abs_angular_z_rad_s':max((abs(value) for value in imu_values), default=1.0),
        'imu_max_abs_z_bias_residual_rad_s':max((abs(value-bias) for value in imu_values), default=1.0),
        'imu_samples_digest':_zdigest(imus),
    }
    evidence['evidence_sha256'] = _zdigest(evidence)
    return evidence

def _zproc(pid):
    proc_root = '/proc/' + str(pid)
    with open(proc_root + '/stat', 'rb') as stream: stat_raw = stream.read(8193)
    if len(stat_raw) > 8192: raise RuntimeError('PROC_STAT_TOO_LARGE')
    close = stat_raw.rfind(b')')
    if close < 0: raise RuntimeError('PROC_STAT_INVALID')
    fields = stat_raw[close + 2:].split()
    if len(fields) <= 19: raise RuntimeError('PROC_STAT_INVALID')
    live_ticks = int(fields[19])
    with open(proc_root + '/cmdline', 'rb') as stream: cmdline = stream.read(8193)
    if not cmdline or len(cmdline) > 8192: raise RuntimeError('PROC_CMDLINE_INVALID')
    argv = [part for part in cmdline.split(b'\0') if part]
    try: code_index = argv.index(b'-c') + 1; runtime_source = argv[code_index]
    except Exception as exc: raise RuntimeError('PROC_RUNTIME_SOURCE_UNAVAILABLE') from exc
    return live_ticks, cmdline, 'sha256:' + _zh.sha256(runtime_source).hexdigest()

def _zemit(value):
    raw = _zj.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(',', ':'))
    if len(raw.encode('ascii')) > 65536: raise RuntimeError('SNAPSHOT_TOO_LARGE')
    print(raw, flush=True)

mode = _zs.argv[1]
if mode == 'topic':
    route = _zs.argv[2]; interface = _zs.argv[3]
    allowed = {'/cmd_vel':'geometry_msgs/msg/Twist','/controller/cmd_vel':'geometry_msgs/msg/Twist','/ros_robot_controller/set_motor':'ros_robot_controller_msgs/msg/MotorsState'}
    if allowed.get(route) != interface: raise RuntimeError('TOPIC_OUTSIDE_ALLOWLIST')
    _zemit({'schema_version':'rolo-targetd-fixed-topic-read/v1','route':route,'interface':interface,'output':_ztopic(route, interface)})
elif mode == 'graph':
    import rclpy as _zr
    _zr.init(args=None); node = _zr.create_node('rolo_targetd_graph_snapshot_%d' % _zo.getpid())
    try: outputs = _zwait_graph(node)
    finally:
        node.destroy_node(); _zr.shutdown()
    _zemit({'schema_version':'rolo-targetd-fixed-isolation-graph/v1','outputs':outputs})
elif mode == 'registry':
    now = _zt.time()
    try: record = registry_read_active()
    except FileNotFoundError:
        _zemit({'schema_version':'rolo-targetd-armed-live-snapshot/v1','observed_at_epoch_s':now,'registry_present':False,'registry_auth_verified':True,'process_match_count':0})
        raise SystemExit(0)
    if record.get('state') != 'ACTIVE' or record.get('terminal_reason') is not None: raise RuntimeError('REGISTRY_NOT_ACTIVE')
    arm = record.get('arm_receipt'); identity = arm.get('inner_process_identity', {}) if isinstance(arm, dict) else {}
    pid = identity.get('pid'); expected_ticks = identity.get('start_ticks')
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0 or not isinstance(expected_ticks, int) or isinstance(expected_ticks, bool):
        raise RuntimeError('REGISTRY_PROCESS_IDENTITY_INVALID')
    live_ticks, cmdline, runtime_sha = _zproc(pid)
    import rclpy as _zr
    _zr.init(args=None); node = _zr.create_node('rolo_targetd_armed_snapshot_%d' % _zo.getpid())
    try:
        graph_outputs = _zwait_graph(node)
        command_info = graph_outputs['/cmd_vel']
        competing_info = graph_outputs['/controller/cmd_vel']
        motor_info = graph_outputs['/ros_robot_controller/set_motor']
        fresh_zero = _zfresh_zero(node)
    finally:
        node.destroy_node(); _zr.shutdown()
    refreshed = registry_read_active()
    if refreshed.get('state') != 'ACTIVE' or refreshed.get('arm_receipt') != arm: raise RuntimeError('REGISTRY_CHANGED_DURING_SNAPSHOT')
    final_ticks, final_cmdline, final_runtime_sha = _zproc(pid)
    if (final_ticks, final_cmdline, final_runtime_sha) != (live_ticks, cmdline, runtime_sha): raise RuntimeError('PROCESS_CHANGED_DURING_SNAPSHOT')
    now = _zt.time()
    _zemit({
        'schema_version':'rolo-targetd-armed-live-snapshot/v1','observed_at_epoch_s':now,
        'registry_present':True,'registry_auth_verified':True,'process_match_count':1,
        'registry_json':_rcanonical(refreshed).decode('ascii'),'live_pid':pid,
        'live_start_time_ticks':live_ticks,'live_cmdline_base64':_zb.b64encode(cmdline).decode('ascii'),
        'live_runtime_sha256':runtime_sha,
        'command_topic_info_verbose':command_info,'competing_topic_info_verbose':competing_info,
        'direct_motor_topic_info_verbose':motor_info,'fresh_zero_evidence':fresh_zero,
    })
else:
    raise RuntimeError('SNAPSHOT_MODE_INVALID')
""".strip()


def _target_side_motion_snapshot_helper() -> str:
    """Compose the target verifier from the worker's single registry implementation."""

    from .physical_worker import _TARGET_REGISTRY_LIBRARY

    return f"exec({_TARGET_REGISTRY_LIBRARY!r}, globals())\n{_TARGET_SIDE_MOTION_SNAPSHOT_SUFFIX}"


_TARGETD_ROS_CONTAINER_EXEC_WRAPPER = (
    "set -e; export HOME=/home/ubuntu; "
    ". /opt/ros/humble/setup.bash; "
    ". /home/ubuntu/ros2_ws/install/setup.bash; "
    ". /home/ubuntu/ros2_ws/.robotrc >/dev/null; "
    'set -u; exec "$@"'
)


class TargetdDockerPinnedReadControlTransport:
    """Fixed local Docker adapter, gated by a verified outer-peer capability."""

    _PREFIX = (
        "docker",
        "exec",
        "--user",
        "ubuntu",
        "-i",
        "MentorPi",
        "/bin/bash",
        "--noprofile",
        "--norc",
        "-c",
        _TARGETD_ROS_CONTAINER_EXEC_WRAPPER,
        "rolo-targetd-read-control",
        "/usr/bin/python3",
        "-c",
    )

    def __init__(
        self,
        *,
        peer_capability: PinnedTargetdPeerCapability,
        timeout_s: float = 3.0,
    ) -> None:
        if not isinstance(peer_capability, PinnedTargetdPeerCapability):
            raise ValueError("verified pinned targetd peer capability is required")
        if not isinstance(timeout_s, (int, float)) or isinstance(timeout_s, bool) or not math.isfinite(timeout_s) or not 0.1 <= timeout_s <= 10:
            raise ValueError("target-side snapshot timeout is outside safe bounds")
        self._security = peer_capability._claim_for_local_transport()
        self.bootstrap_receipt_digest = peer_capability.bootstrap_receipt_digest
        self.timeout_s = float(timeout_s)
        self._helper = _target_side_motion_snapshot_helper()

    def security_context(self) -> PinnedLanderPiRpcSecurity:
        return self._security

    def _execute(self, mode: Literal["topic", "graph", "registry"], *arguments: str) -> dict[str, Any]:
        argv = (*self._PREFIX, self._helper, mode, *arguments)
        try:
            completed = subprocess.run(
                argv,
                input=b"",
                capture_output=True,
                timeout=self.timeout_s,
                check=False,
                shell=False,
            )
        except Exception as exc:
            raise RuntimeError("LANDERPI_TARGET_READ_CONTROL_UNAVAILABLE") from exc
        if completed.returncode != 0 or len(completed.stdout) > 65_536 or len(completed.stderr) > 8_192:
            raise RuntimeError("LANDERPI_TARGET_READ_CONTROL_FAILED")
        try:
            raw = completed.stdout.decode("ascii")
        except UnicodeDecodeError as exc:
            raise RuntimeError("LANDERPI_TARGET_READ_CONTROL_OUTPUT_INVALID") from exc
        return _loads_unique_object(raw)

    def read_topic_info_verbose(self, *, route: str, expected_interface: str) -> str:
        allowed = {
            _CONTROLLED_ROUTE: "geometry_msgs/msg/Twist",
            _COMPETING_ROUTE: "geometry_msgs/msg/Twist",
            _DIRECT_MOTOR_ROUTE: "ros_robot_controller_msgs/msg/MotorsState",
        }
        if allowed.get(route) != expected_interface:
            raise RuntimeError("LANDERPI_TOPIC_READ_OUTSIDE_FIXED_ALLOWLIST")
        result = self._execute("topic", route, expected_interface)
        if (
            set(result) != {"schema_version", "route", "interface", "output"}
            or result.get("schema_version") != "rolo-targetd-fixed-topic-read/v1"
            or result.get("route") != route
            or result.get("interface") != expected_interface
        ):
            raise RuntimeError("LANDERPI_TARGET_TOPIC_READ_INVALID")
        output = result.get("output")
        parse_ros2_topic_info_verbose(output, route=route, expected_interface=expected_interface)
        return output

    def read_and_verify_armed_registry_snapshot(self) -> LanderPiArmedRegistrySnapshot:
        result = self._execute("registry")
        if result.get("schema_version") != "rolo-targetd-armed-live-snapshot/v1":
            raise RuntimeError("LANDERPI_TARGET_REGISTRY_READ_INVALID")
        try:
            observed_at = datetime.fromtimestamp(result.pop("observed_at_epoch_s"), timezone.utc)
            result.pop("schema_version")
            return LanderPiArmedRegistrySnapshot(observed_at=observed_at, **result)
        except Exception as exc:
            raise RuntimeError("LANDERPI_TARGET_REGISTRY_READ_INVALID") from exc

    def read_isolation_topic_info_bundle(self) -> dict[str, str]:
        result = self._execute("graph")
        outputs = result.get("outputs")
        expected = {
            _CONTROLLED_ROUTE: "geometry_msgs/msg/Twist",
            _COMPETING_ROUTE: "geometry_msgs/msg/Twist",
            _DIRECT_MOTOR_ROUTE: "ros_robot_controller_msgs/msg/MotorsState",
        }
        if set(result) != {"schema_version", "outputs"} or result.get("schema_version") != "rolo-targetd-fixed-isolation-graph/v1" or not isinstance(outputs, dict) or set(outputs) != set(expected):
            raise RuntimeError("LANDERPI_TARGET_ISOLATION_GRAPH_INVALID")
        for route, interface in expected.items():
            parse_ros2_topic_info_verbose(outputs[route], route=route, expected_interface=interface)
        return dict(outputs)


class PinnedKeyOnlyLanderPiMotionRpc:
    """Concrete strict parser over an injected pinned, key-only read/control transport."""

    def __init__(
        self,
        *,
        policy: MotionSafetyPolicy,
        transport: PinnedLanderPiReadControlTransport,
        expected_call_key_digest: str,
        expected_request_digest: str,
        expected_call_id: str,
        expected_session_id: str,
        expected_execution_subject_digest: str,
        manifest_provider_runtime_sha256: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.policy = MotionSafetyPolicy.model_validate(policy.model_dump(mode="python"))
        if (
            re.fullmatch(r"[0-9a-f]{64}", expected_call_key_digest) is None
            or re.fullmatch(r"[0-9a-f]{64}", expected_request_digest) is None
            or re.fullmatch(_IDENTIFIER, expected_call_id) is None
            or re.fullmatch(_IDENTIFIER, expected_session_id) is None
            or re.fullmatch(_SHA256, expected_execution_subject_digest) is None
            or re.fullmatch(_SHA256, manifest_provider_runtime_sha256) is None
        ):
            raise ValueError("physical worker registry expectations are invalid")
        if not all(
            callable(getattr(transport, name, None))
            for name in (
                "security_context",
                "read_topic_info_verbose",
                "read_and_verify_armed_registry_snapshot",
            )
        ):
            raise ValueError("pinned LanderPi read/control transport is incomplete")
        self.transport = transport
        self.expected_call_key_digest = expected_call_key_digest
        self.expected_request_digest = expected_request_digest
        self.expected_call_id = expected_call_id
        self.expected_session_id = expected_session_id
        self.expected_execution_subject_digest = expected_execution_subject_digest
        self.manifest_provider_runtime_sha256 = manifest_provider_runtime_sha256
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def security_context(self) -> PinnedLanderPiRpcSecurity:
        try:
            raw = self.transport.security_context()
            context = PinnedLanderPiRpcSecurity.model_validate(raw.model_dump(mode="python") if isinstance(raw, BaseModel) else raw)
        except Exception as exc:
            raise RuntimeError("LANDERPI_PINNED_KEY_ONLY_TRANSPORT_REQUIRED") from exc
        if context.target_id != self.policy.target_id or context.target_identity != self.policy.target_identity:
            raise RuntimeError("LANDERPI_TRANSPORT_TARGET_IDENTITY_MISMATCH")
        return context

    def topic_info_verbose(self, *, route: str, expected_interface: str) -> str:
        self.security_context()
        allowed = {
            _CONTROLLED_ROUTE: self.policy.command_interface,
            _COMPETING_ROUTE: self.policy.command_interface,
            _DIRECT_MOTOR_ROUTE: self.policy.direct_motor_interface,
        }
        if allowed.get(route) != expected_interface:
            raise RuntimeError("LANDERPI_TOPIC_READ_OUTSIDE_FIXED_ALLOWLIST")
        output = self.transport.read_topic_info_verbose(
            route=route,
            expected_interface=expected_interface,
        )
        parse_ros2_topic_info_verbose(output, route=route, expected_interface=expected_interface)
        return output

    def isolation_topic_info_bundle(self) -> dict[str, str]:
        self.security_context()
        reader = getattr(self.transport, "read_isolation_topic_info_bundle", None)
        if not callable(reader):
            raise RuntimeError("LANDERPI_ISOLATION_GRAPH_BUNDLE_UNAVAILABLE")
        try:
            outputs = reader()
        except Exception as exc:
            raise RuntimeError("LANDERPI_ISOLATION_GRAPH_BUNDLE_INVALID") from exc
        expected = {
            _CONTROLLED_ROUTE: self.policy.command_interface,
            _COMPETING_ROUTE: self.policy.command_interface,
            _DIRECT_MOTOR_ROUTE: self.policy.direct_motor_interface,
        }
        if not isinstance(outputs, Mapping) or set(outputs) != set(expected):
            raise RuntimeError("LANDERPI_ISOLATION_GRAPH_BUNDLE_INVALID")
        result = dict(outputs)
        for route, interface in expected.items():
            parse_ros2_topic_info_verbose(result[route], route=route, expected_interface=interface)
        return result

    def zero_motion_status(self) -> LanderPiZeroMotionStatus:
        self.security_context()
        try:
            raw = self.transport.read_and_verify_armed_registry_snapshot()
            snapshot = LanderPiArmedRegistrySnapshot.model_validate(raw.model_dump(mode="python") if isinstance(raw, BaseModel) else raw)
        except Exception as exc:
            raise RuntimeError("LANDERPI_ARMED_REGISTRY_SNAPSHOT_INVALID") from exc
        point = _point(self.clock)
        age = (point - snapshot.observed_at.astimezone(timezone.utc)).total_seconds()
        if age < 0 or age > 1:
            raise RuntimeError("LANDERPI_ARMED_REGISTRY_SNAPSHOT_STALE")
        if not snapshot.registry_present:
            return LanderPiZeroMotionStatus(
                observed_at=snapshot.observed_at,
                provider_process_state="ABSENT",
            )
        try:
            record = TargetPhysicalWorkerRegistryRecord.model_validate(_loads_unique_object(snapshot.registry_json))
        except Exception as exc:
            raise RuntimeError("LANDERPI_ARMED_REGISTRY_RECORD_INVALID") from exc
        if (
            record.state != "ACTIVE"
            or record.terminal_reason is not None
            or record.updated_at_epoch_s > point.timestamp() + 1
            or point.timestamp() - record.updated_at_epoch_s > 0.5
            or record.last_zero_at_epoch_s > point.timestamp() + 1
            or point.timestamp() - record.last_zero_at_epoch_s > 0.25
            or record.zero_refresh_count < 1
        ):
            raise RuntimeError("LANDERPI_ARMED_REGISTRY_IDENTITY_OR_EXPIRY_MISMATCH")
        try:
            from .physical_worker import parse_physical_worker_armed_zero

            armed = parse_physical_worker_armed_zero(
                record.arm_receipt,
                expected_call_key_digest=self.expected_call_key_digest,
                expected_request_digest=self.expected_request_digest,
                expected_execution_subject_digest=self.expected_execution_subject_digest,
                expected_runtime_sha256=self.manifest_provider_runtime_sha256.removeprefix("sha256:"),
                expected_target_id=self.policy.target_id,
                expected_call_id=self.expected_call_id,
                expected_session_id=self.expected_session_id,
            )
        except Exception as exc:
            raise RuntimeError("LANDERPI_ARMED_REGISTRY_RECORD_INVALID") from exc
        armed_age = point.timestamp() - armed.registry_issued_at_epoch_s
        if armed_age < 0 or armed_age > _MAX_ARMED_ZERO_GATE_S or point.timestamp() >= armed.registry_expires_at_epoch_s:
            raise RuntimeError("LANDERPI_ARMED_REGISTRY_IDENTITY_OR_EXPIRY_MISMATCH")
        try:
            cmdline = base64.b64decode(snapshot.live_cmdline_base64, validate=True)
        except Exception as exc:
            raise RuntimeError("LANDERPI_LIVE_CMDLINE_INVALID") from exc
        if not cmdline or len(cmdline) > 8192 or b"\x00" not in cmdline:
            raise RuntimeError("LANDERPI_LIVE_CMDLINE_INVALID")
        live_cmdline_sha256 = "sha256:" + hashlib.sha256(cmdline).hexdigest()
        command = parse_ros2_topic_info_verbose(
            snapshot.command_topic_info_verbose,
            route=self.policy.command_route,
            expected_interface=self.policy.command_interface,
        )
        competing = parse_ros2_topic_info_verbose(
            snapshot.competing_topic_info_verbose,
            route=_COMPETING_ROUTE,
            expected_interface=self.policy.command_interface,
        )
        direct_motor = parse_ros2_topic_info_verbose(
            snapshot.direct_motor_topic_info_verbose,
            route=self.policy.direct_motor_route,
            expected_interface=self.policy.direct_motor_interface,
        )
        evidence = snapshot.fresh_zero_evidence
        evidence_age = (snapshot.observed_at - evidence.window_ended_at).total_seconds()
        binding = armed.provider_binding()
        if (
            snapshot.live_pid != binding.provider_pid
            or snapshot.live_start_time_ticks != binding.provider_start_time_ticks
            or live_cmdline_sha256 != binding.provider_cmdline_sha256
            or snapshot.live_runtime_sha256 != binding.provider_runtime_sha256
            or snapshot.live_runtime_sha256 != self.manifest_provider_runtime_sha256
            or command.publisher_count != 1
            or command.publisher_identities != (binding.publisher_identity,)
            or tuple(_canonical_gid(gid) for gid in command.publisher_gids) != (_canonical_gid(binding.publisher_gid),)
            or competing.publisher_count != 0
            or direct_motor.publisher_count != 1
            or direct_motor.publisher_identities != (self.policy.allowed_direct_motor_publisher_identity,)
            or evidence.imu_stream not in armed.independent_stationary_sources
            or evidence_age < 0
            or evidence_age > 0.2
        ):
            raise RuntimeError("LANDERPI_ARMED_REGISTRY_LIVE_REVALIDATION_FAILED")
        recomputed = compute_armed_zero_provider_identity_digest(
            call_id=binding.call_id,
            session_id=binding.session_id,
            execution_subject_digest=binding.execution_subject_digest,
            publisher_identity=binding.publisher_identity,
            publisher_gid=binding.publisher_gid,
            provider_pid=snapshot.live_pid,
            provider_start_time_ticks=snapshot.live_start_time_ticks,
            provider_runtime_sha256=snapshot.live_runtime_sha256,
            provider_cmdline_sha256=live_cmdline_sha256,
        )
        if recomputed != binding.provider_runtime_identity_digest:
            raise RuntimeError("LANDERPI_ARMED_REGISTRY_RUNTIME_IDENTITY_MISMATCH")
        return LanderPiZeroMotionStatus(
            observed_at=snapshot.observed_at,
            provider_process_state="ARMED_ZERO",
            publisher_identity=binding.publisher_identity,
            publisher_gid=binding.publisher_gid,
            call_id=binding.call_id,
            session_id=binding.session_id,
            execution_subject_digest=binding.execution_subject_digest,
            provider_pid=binding.provider_pid,
            provider_start_time_ticks=binding.provider_start_time_ticks,
            provider_runtime_sha256=binding.provider_runtime_sha256,
            provider_cmdline_sha256=binding.provider_cmdline_sha256,
            provider_runtime_identity_digest=binding.provider_runtime_identity_digest,
            last_command_is_zero=True,
            motor_output_zero=True,
            motors_stopped=True,
            zero_velocity_verified=True,
            fresh_zero_evidence=evidence,
            fresh_zero_evidence_digest=evidence.evidence_sha256,
        )


class AtomicLanderPiMotionStateStore:
    """Durable target-local CAS store with an append-only artifact directory."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        requested = Path(root)
        if not requested.is_absolute():
            raise ValueError("motion state root must be absolute")
        self.root = requested.resolve()
        self.state_path = self.root / "state.json"
        self.lock_path = self.root / "state.lock"
        self.artifact_root = self.root / "artifacts"
        self.debug_admission_root = self.root / "debug-admissions"
        self._thread_lock = threading.Lock()

    @staticmethod
    def _encode(model: BaseModel) -> bytes:
        encoded = json.dumps(
            model.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > _MAX_STATE_BYTES:
            raise ValueError("motion state payload exceeds safe bounds")
        return encoded

    @staticmethod
    def _write_atomic(path: Path, payload: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
        temporary = Path(temporary_name)
        try:
            if os.name != "nt":
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    @contextmanager
    def _locked(self):
        self.root.mkdir(parents=True, exist_ok=True)
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self.debug_admission_root.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(self.root, 0o700)
            os.chmod(self.artifact_root, 0o700)
            os.chmod(self.debug_admission_root, 0o700)
        with self._thread_lock:
            descriptor = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                if os.name == "nt":
                    import msvcrt

                    if os.fstat(descriptor).st_size == 0:
                        os.write(descriptor, b"\0")
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
                else:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                try:
                    if os.name == "nt":
                        import msvcrt

                        os.lseek(descriptor, 0, os.SEEK_SET)
                        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)

    def _load_unlocked(self) -> LanderPiTargetMotionState:
        try:
            payload = self.state_path.read_bytes()
        except OSError as exc:
            raise RuntimeError("LANDERPI_MOTION_STATE_REQUIRED") from exc
        if not payload or len(payload) > _MAX_STATE_BYTES:
            raise RuntimeError("LANDERPI_MOTION_STATE_INVALID")
        try:
            return LanderPiTargetMotionState.model_validate_json(payload)
        except Exception as exc:
            raise RuntimeError("LANDERPI_MOTION_STATE_INVALID") from exc

    def provision(self, state: LanderPiTargetMotionState) -> None:
        parsed = LanderPiTargetMotionState.model_validate(state.model_dump(mode="python"))
        with self._locked():
            if self.state_path.exists():
                raise RuntimeError("LANDERPI_MOTION_STATE_ALREADY_PROVISIONED")
            self._write_atomic(self.state_path, self._encode(parsed))

    def load(self) -> LanderPiTargetMotionState:
        with self._locked():
            return self._load_unlocked()

    def compare_and_set(
        self,
        *,
        expected: LanderPiTargetMotionState,
        replacement: LanderPiTargetMotionState,
        artifact: SignedZeroMotionArtifact,
    ) -> bool:
        expected = LanderPiTargetMotionState.model_validate(expected.model_dump(mode="python"))
        replacement = LanderPiTargetMotionState.model_validate(replacement.model_dump(mode="python"))
        artifact = SignedZeroMotionArtifact.model_validate(artifact.model_dump(mode="python"))
        if replacement.state_revision != expected.state_revision + 1:
            raise ValueError("replacement state revision must advance exactly once")
        if replacement.last_artifact_digest != artifact.payload_sha256:
            raise ValueError("replacement state does not bind the persisted artifact")
        with self._locked():
            current = self._load_unlocked()
            if current != expected:
                return False
            artifact_name = artifact.payload_sha256.removeprefix("sha256:") + ".json"
            artifact_path = self.artifact_root / artifact_name
            artifact_payload = self._encode(artifact)
            if artifact_path.exists():
                if artifact_path.read_bytes() != artifact_payload:
                    raise RuntimeError("LANDERPI_ARTIFACT_DIGEST_COLLISION")
            else:
                self._write_atomic(artifact_path, artifact_payload)
            self._write_atomic(self.state_path, self._encode(replacement))
            return True

    def get_artifact(self, payload_sha256: str) -> SignedZeroMotionArtifact | None:
        if re.fullmatch(_SHA256, payload_sha256) is None:
            return None
        path = self.artifact_root / (payload_sha256.removeprefix("sha256:") + ".json")
        with self._locked():
            try:
                payload = path.read_bytes()
            except OSError:
                return None
            if not payload or len(payload) > _MAX_STATE_BYTES:
                return None
            try:
                artifact = SignedZeroMotionArtifact.model_validate_json(payload)
            except Exception:
                return None
            return artifact if artifact.payload_sha256 == payload_sha256 else None

    def reserve_debug_admission(self, payload_sha256: str) -> bool:
        """Burn a debug admission digest before use so it cannot be replayed."""

        if re.fullmatch(_SHA256, payload_sha256) is None:
            raise ValueError("debug admission digest is invalid")
        marker = self.debug_admission_root / (payload_sha256.removeprefix("sha256:") + ".json")
        payload = json.dumps(
            {
                "schema_version": "rolo-debug-admission-reservation/v1",
                "debug_admission_digest": payload_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        with self._locked():
            if marker.exists():
                return False
            self._write_atomic(marker, payload)
            return True


def _fence_digest(intent: MotionSafetyIntent, fence_epoch: int) -> str:
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


def _artifact_id(acceptance_id: str, kind: str, revision: int) -> str:
    digest = compute_motion_payload_digest(
        {
            "acceptance_id": acceptance_id,
            "kind": kind,
            "state_revision": revision,
        }
    ).removeprefix("sha256:")
    return f"zm-{digest[:32]}"


class LanderPiZeroMotionTarget:
    """Persistent, signed ZeroMotionTarget implementation for LanderPi."""

    def __init__(
        self,
        *,
        policy: MotionSafetyPolicy,
        rpc: PinnedLanderPiMotionRpc,
        store: LanderPiMotionStateStore,
        graph_signing_key: TargetSigningKey,
        target_signing_key: TargetSigningKey,
        clock: Callable[[], datetime] | None = None,
        artifact_ttl_s: int | None = None,
    ) -> None:
        self.policy = MotionSafetyPolicy.model_validate(policy.model_dump(mode="python"))
        if (
            self.policy.command_route != _CONTROLLED_ROUTE
            or self.policy.allowed_publisher_identity != _PROVIDER_IDENTITY
            or self.policy.direct_motor_route != _DIRECT_MOTOR_ROUTE
            or self.policy.allowed_direct_motor_publisher_identity != _ODOM_IDENTITY
        ):
            raise ValueError("policy does not match the fixed LanderPi topology")
        if not all(callable(getattr(rpc, name, None)) for name in ("security_context", "topic_info_verbose", "zero_motion_status")):
            raise ValueError("pinned LanderPi motion RPC is incomplete")
        if not all(callable(getattr(store, name, None)) for name in ("load", "compare_and_set", "get_artifact")):
            raise ValueError("LanderPi motion state store is incomplete")
        if not isinstance(graph_signing_key, TargetSigningKey) or not isinstance(target_signing_key, TargetSigningKey):
            raise ValueError("typed target signing keys are required")
        ttl = self.policy.max_graph_age_s if artifact_ttl_s is None else artifact_ttl_s
        if not isinstance(ttl, int) or isinstance(ttl, bool) or not 1 <= ttl <= self.policy.max_graph_age_s:
            raise ValueError("artifact TTL is outside the graph-freshness window")
        self.rpc = rpc
        self.store = store
        self.graph_signing_key = graph_signing_key
        self.target_signing_key = target_signing_key
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.artifact_ttl_s = ttl

    def _security(self) -> PinnedLanderPiRpcSecurity:
        try:
            context = PinnedLanderPiRpcSecurity.model_validate(self.rpc.security_context())
        except Exception as exc:
            raise RuntimeError("LANDERPI_PINNED_KEY_ONLY_RPC_REQUIRED") from exc
        if context.target_id != self.policy.target_id or context.target_identity != self.policy.target_identity:
            raise RuntimeError("LANDERPI_RPC_TARGET_IDENTITY_MISMATCH")
        return context

    def production_peer_verified(self) -> bool:
        """Expose peer provenance so the production acceptance path can fail closed."""

        return self._security().production_peer_verified

    def _status(
        self,
        *,
        expected_process_state: Literal["ABSENT", "ARMED_ZERO"],
        intent: MotionSafetyIntent | None = None,
    ) -> LanderPiZeroMotionStatus:
        self._security()
        try:
            status = LanderPiZeroMotionStatus.model_validate(self.rpc.zero_motion_status())
        except Exception as exc:
            raise RuntimeError("LANDERPI_ZERO_MOTION_STATUS_INVALID") from exc
        point = _point(self.clock)
        age = (point - status.observed_at.astimezone(timezone.utc)).total_seconds()
        if age < 0 or age > 1 or status.provider_process_state != expected_process_state:
            raise RuntimeError("LANDERPI_ZERO_MOTION_STATUS_NOT_CURRENT")
        if expected_process_state == "ARMED_ZERO":
            if intent is None:
                raise RuntimeError("LANDERPI_ZERO_MOTION_INTENT_REQUIRED")
            binding = status.binding()
            if (
                binding.call_id != intent.call_id
                or binding.session_id != intent.session_id
                or binding.execution_subject_digest != intent.execution_subject_digest
                or binding.publisher_identity != intent.publisher_identity
            ):
                raise RuntimeError("LANDERPI_ARMED_ZERO_CALL_IDENTITY_MISMATCH")
        return status

    def _observation(self) -> LanderPiIsolationObservation:
        self._security()

        bundle_reader = getattr(self.rpc, "isolation_topic_info_bundle", None)
        bundle: Mapping[str, str] | None = None
        if callable(bundle_reader):
            try:
                candidate = bundle_reader()
                if not isinstance(candidate, Mapping) or set(candidate) != {
                    _CONTROLLED_ROUTE,
                    _COMPETING_ROUTE,
                    _DIRECT_MOTOR_ROUTE,
                }:
                    raise ValueError("isolation graph bundle shape is invalid")
                bundle = dict(candidate)
            except Exception as exc:
                raise RuntimeError("LANDERPI_ISOLATION_GRAPH_BUNDLE_INVALID") from exc

        def read_only(argv: tuple[str, ...]) -> str:
            route = argv[3]
            interface = self.policy.direct_motor_interface if route == _DIRECT_MOTOR_ROUTE else self.policy.command_interface
            if bundle is not None:
                return bundle[route]
            return self.rpc.topic_info_verbose(route=route, expected_interface=interface)

        return capture_landerpi_isolation_observation(
            read_only,
            policy=self.policy,
            observed_at=_point(self.clock),
        )

    @staticmethod
    def _assert_fixed_graph(observation: LanderPiIsolationObservation, *, armed: bool) -> None:
        expected_command = (_PROVIDER_IDENTITY,) if armed else ()
        command = observation.command
        competing = observation.competing_command
        direct = observation.direct_motor
        if (
            command.publisher_identities != expected_command
            or command.publisher_count != len(expected_command)
            or len(command.publisher_gids) != len(expected_command)
            or command.subscriber_identities != (_ODOM_IDENTITY,)
            or command.subscriber_count != 1
            or len(command.subscriber_gids) != 1
            or competing.publisher_identities != ()
            or competing.publisher_count != 0
            or competing.publisher_gids != ()
            or competing.subscriber_identities != (_ODOM_IDENTITY,)
            or competing.subscriber_count != 1
            or len(competing.subscriber_gids) != 1
            or direct.publisher_identities != (_ODOM_IDENTITY,)
            or direct.publisher_count != 1
            or len(direct.publisher_gids) != 1
        ):
            raise RuntimeError("LANDERPI_CONTROL_GRAPH_NOT_ISOLATED")

    @staticmethod
    def _assert_status_graph_binding(
        observation: LanderPiIsolationObservation,
        status: LanderPiZeroMotionStatus,
    ) -> ArmedZeroProviderBinding:
        binding = status.binding()
        if tuple(_canonical_gid(gid) for gid in observation.command.publisher_gids) != (_canonical_gid(binding.publisher_gid),):
            raise RuntimeError("LANDERPI_ARMED_ZERO_PUBLISHER_GID_MISMATCH")
        return binding

    @staticmethod
    def _fresh_zero_claims(status: LanderPiZeroMotionStatus) -> dict[str, Any]:
        if status.provider_process_state != "ARMED_ZERO" or status.fresh_zero_evidence is None:
            raise RuntimeError("LANDERPI_FRESH_ZERO_EVIDENCE_REQUIRED")
        return {
            "last_command_is_zero": True,
            "motor_output_zero": True,
            "motors_stopped": True,
            "zero_velocity_verified": True,
            "fresh_zero_evidence_digest": status.fresh_zero_evidence_digest,
            "fresh_zero_evidence": status.fresh_zero_evidence.model_dump(mode="json"),
        }

    def verify_initial_isolation(self) -> LanderPiIsolationObservation:
        """Verify the zero-publisher graph before the one allowed pre-arm spawn."""

        observation = self._observation()
        self._assert_fixed_graph(observation, armed=False)
        self._status(expected_process_state="ABSENT")
        return observation

    def _load(self, intent: MotionSafetyIntent) -> LanderPiTargetMotionState:
        state = self.store.load()
        if state.target_id != intent.target_id or state.target_identity != intent.target_identity:
            raise RuntimeError("LANDERPI_MOTION_STATE_TARGET_MISMATCH")
        return state

    @staticmethod
    def _assert_owner(state: LanderPiTargetMotionState, acceptance_id: str, intent: MotionSafetyIntent) -> None:
        if state.acceptance_id != acceptance_id or state.call_id != intent.call_id or state.session_id != intent.session_id or state.execution_subject_digest != intent.execution_subject_digest:
            raise RuntimeError("LANDERPI_MOTION_STATE_OWNER_MISMATCH")

    def _artifact(
        self,
        *,
        state: LanderPiTargetMotionState,
        acceptance_id: str,
        intent: MotionSafetyIntent,
        kind: ZeroMotionArtifactKind,
        claims: dict[str, Any],
        issuer: Literal["graph", "target"],
    ) -> SignedZeroMotionArtifact:
        point = _point(self.clock)
        key = self.graph_signing_key if issuer == "graph" else self.target_signing_key
        issuer_id = self.policy.graph_authority_id if issuer == "graph" else self.policy.target_authority_id
        return SignedZeroMotionArtifact.build(
            artifact_id=_artifact_id(acceptance_id, kind, state.state_revision + 1),
            kind=kind,
            issuer_id=issuer_id,
            acceptance_id=acceptance_id,
            intent=intent,
            issued_at=point,
            expires_at=point + timedelta(seconds=self.artifact_ttl_s),
            claims=claims,
            signing_key=key._material(),
        )

    @staticmethod
    def _replacement(state: LanderPiTargetMotionState, artifact: SignedZeroMotionArtifact, **updates: Any) -> LanderPiTargetMotionState:
        payload = state.model_dump(mode="python")
        payload.update(updates)
        payload["state_revision"] = state.state_revision + 1
        payload["last_artifact_digest"] = artifact.payload_sha256
        payload["updated_at"] = artifact.issued_at
        return LanderPiTargetMotionState.model_validate(payload)

    def _commit(
        self,
        state: LanderPiTargetMotionState,
        artifact: SignedZeroMotionArtifact,
        **updates: Any,
    ) -> LanderPiTargetMotionState:
        replacement = self._replacement(state, artifact, **updates)
        if not self.store.compare_and_set(expected=state, replacement=replacement, artifact=artifact):
            raise RuntimeError("LANDERPI_MOTION_STATE_CAS_CONFLICT")
        return replacement

    def accept_debug_user_attestation(
        self,
        admission: DebugOnlyUserAttestedAdmission,
        *,
        intent: MotionSafetyIntent,
        policy: MotionSafetyPolicy,
    ) -> SignedZeroMotionArtifact:
        """Persist one explicit debug-only admission without impersonating an authority."""

        if policy != self.policy:
            raise RuntimeError("LANDERPI_MOTION_POLICY_MISMATCH")
        parsed = DebugOnlyUserAttestedAdmission.model_validate(admission.model_dump(mode="python"))
        if (
            parsed.call_id != intent.call_id
            or parsed.session_id != intent.session_id
            or parsed.target_id != intent.target_id
            or parsed.target_identity != intent.target_identity
            or parsed.operator_id != intent.operator_id
            or parsed.execution_subject_digest != intent.execution_subject_digest
            or parsed.site_id != policy.site_id
            or parsed.safe_zone_id != policy.safe_zone_id
        ):
            raise RuntimeError("DEBUG_USER_ATTESTATION_IDENTITY_MISMATCH")
        point = _point(self.clock)
        issued = parsed.issued_at.astimezone(timezone.utc)
        expires = parsed.expires_at.astimezone(timezone.utc)
        if issued > point or point >= expires:
            raise RuntimeError("DEBUG_USER_ATTESTATION_NOT_CURRENT")
        state = self._load(intent)
        if state.phase != "SAFE_BASELINE" or state.fence_digest != intent.direct_motor_fence_digest:
            raise RuntimeError("DEBUG_USER_ATTESTATION_STATE_MISMATCH")
        reserve = getattr(self.store, "reserve_debug_admission", None)
        if not callable(reserve):
            raise RuntimeError("DEBUG_USER_ATTESTATION_DURABLE_RESERVATION_REQUIRED")
        if not reserve(parsed.payload_sha256):
            raise RuntimeError("DEBUG_USER_ATTESTATION_ALREADY_USED")
        artifact = SignedZeroMotionArtifact.build(
            artifact_id=_artifact_id(parsed.acceptance_id, "DEBUG_USER_ATTESTED_ADMISSION", state.state_revision + 1),
            kind="DEBUG_USER_ATTESTED_ADMISSION",
            issuer_id=self.policy.target_authority_id,
            acceptance_id=parsed.acceptance_id,
            intent=intent,
            issued_at=point,
            expires_at=min(expires, point + timedelta(seconds=self.artifact_ttl_s)),
            claims={
                "debug_only": True,
                "report_status": "PASS_WITH_USER_ATTESTED_SITE_SAFETY",
                "debug_admission_digest": parsed.payload_sha256,
                "basis": parsed.basis,
                "basis_digest": parsed.basis_digest,
                "site_id": parsed.site_id,
                "safe_zone_id": parsed.safe_zone_id,
                "requested_rotation_degrees": parsed.requested_rotation_degrees,
                "requested_linear_meters": parsed.requested_linear_meters,
                "max_abs_rotation_degrees": parsed.max_abs_rotation_degrees,
                "max_abs_linear_meters": parsed.max_abs_linear_meters,
                "onsite_operator_asserted": True,
                "independent_estop_available_asserted": True,
                "safe_zone_clear_asserted": True,
                "production_authority_verified": False,
                "fresh_estop_challenge_verified": False,
                "production_ready": False,
                "one_shot": True,
                "motion_enabled": False,
                "provider_invocation_count": 0,
            },
            signing_key=self.target_signing_key._material(),
        )
        self._commit(
            state,
            artifact,
            phase="DEBUG_ATTESTED",
            acceptance_id=parsed.acceptance_id,
            call_id=intent.call_id,
            session_id=intent.session_id,
            execution_subject_digest=intent.execution_subject_digest,
            debug_admission_digest=parsed.payload_sha256,
            debug_attestation_artifact_digest=artifact.payload_sha256,
        )
        return artifact

    def observe_isolation(
        self,
        *,
        acceptance_id: str,
        intent: MotionSafetyIntent,
        policy: MotionSafetyPolicy,
        phase: IsolationPhase,
        fence_binding_digest: str | None,
    ) -> SignedZeroMotionArtifact:
        if policy != self.policy:
            raise RuntimeError("LANDERPI_MOTION_POLICY_MISMATCH")
        observation = self._observation()
        self._assert_fixed_graph(observation, armed=True)
        status = self._status(expected_process_state="ARMED_ZERO", intent=intent)
        binding = self._assert_status_graph_binding(observation, status)
        state = self._load(intent)
        if phase == "PRE_CAS":
            if state.phase not in {"SAFE_BASELINE", "DEBUG_ATTESTED"} or state.fence_digest != intent.direct_motor_fence_digest or fence_binding_digest is not None:
                raise RuntimeError("LANDERPI_PRE_CAS_STATE_MISMATCH")
            if state.phase == "DEBUG_ATTESTED":
                self._assert_owner(state, acceptance_id, intent)
                if state.debug_admission_digest is None or (state.armed_provider_binding is not None and binding != state.armed_provider_binding):
                    raise RuntimeError("DEBUG_USER_ATTESTATION_BINDING_CHANGED")
            observation_claims = observation.artifact_claims(
                phase="PRE_CAS",
                fence_epoch=state.fence_epoch,
                active_fence_digest=state.fence_digest,
                fence_owner_call_id=intent.call_id,
            )
            observation_claims.update(self._fresh_zero_claims(status))
            artifact = self._artifact(
                state=state,
                acceptance_id=acceptance_id,
                intent=intent,
                kind="LIVE_ISOLATION_SNAPSHOT",
                claims=observation_claims,
                issuer="graph",
            )
            self._commit(
                state,
                artifact,
                phase="REHEARSAL_OBSERVED",
                acceptance_id=acceptance_id,
                call_id=intent.call_id,
                session_id=intent.session_id,
                execution_subject_digest=intent.execution_subject_digest,
                armed_provider_binding=binding,
                graph_revision=observation.graph_revision,
                pre_snapshot_digest=artifact.payload_sha256,
            )
            return artifact
        self._assert_owner(state, acceptance_id, intent)
        if binding != state.armed_provider_binding:
            raise RuntimeError("LANDERPI_ARMED_ZERO_PROVIDER_CHANGED")
        if state.phase != "REHEARSAL_STOPPED" or fence_binding_digest != state.fence_digest or observation.graph_revision != state.graph_revision:
            raise RuntimeError("LANDERPI_POST_STOP_STATE_MISMATCH")
        observation_claims = observation.artifact_claims(
            phase="POST_STOP",
            fence_epoch=state.fence_epoch,
            active_fence_digest=state.fence_digest,
            fence_owner_call_id=intent.call_id,
        )
        observation_claims.update(self._fresh_zero_claims(status))
        artifact = self._artifact(
            state=state,
            acceptance_id=acceptance_id,
            intent=intent,
            kind="LIVE_ISOLATION_SNAPSHOT",
            claims=observation_claims,
            issuer="graph",
        )
        self._commit(state, artifact, phase="REHEARSAL_POST_OBSERVED", post_snapshot_digest=artifact.payload_sha256)
        return artifact

    def compare_and_set_fence(
        self,
        *,
        acceptance_id: str,
        intent: MotionSafetyIntent,
        policy: MotionSafetyPolicy,
        snapshot_artifact_digest: str,
    ) -> SignedZeroMotionArtifact:
        if policy != self.policy:
            raise RuntimeError("LANDERPI_MOTION_POLICY_MISMATCH")
        state = self._load(intent)
        self._assert_owner(state, acceptance_id, intent)
        if state.phase != "REHEARSAL_OBSERVED" or state.pre_snapshot_digest != snapshot_artifact_digest:
            raise RuntimeError("LANDERPI_REHEARSAL_SNAPSHOT_MISMATCH")
        snapshot = self.store.get_artifact(snapshot_artifact_digest)
        if snapshot is None:
            raise RuntimeError("LANDERPI_REHEARSAL_SNAPSHOT_ARTIFACT_REQUIRED")
        fence_epoch = state.fence_epoch + 1
        lease_digest = compute_zero_motion_fence_lease_digest(
            acceptance_id=acceptance_id,
            intent=intent,
            snapshot_artifact_digest=snapshot_artifact_digest,
            live_ros_graph_digest=snapshot.claims["live_ros_graph_digest"],
            graph_revision=state.graph_revision,
            expected_fence_digest=state.fence_digest,
            fence_epoch=fence_epoch,
        )
        artifact = self._artifact(
            state=state,
            acceptance_id=acceptance_id,
            intent=intent,
            kind="LIVE_FENCE_CAS",
            claims={
                "acquired": True,
                "snapshot_artifact_digest": snapshot_artifact_digest,
                "live_ros_graph_digest": snapshot.claims["live_ros_graph_digest"],
                "graph_revision": state.graph_revision,
                "expected_fence_digest": state.fence_digest,
                "expected_fence_epoch": state.fence_epoch,
                "fence_epoch": fence_epoch,
                "fence_lease_digest": lease_digest,
                "lease_owner_call_id": intent.call_id,
                "motion_enabled": False,
                "provider_invocation_count": 0,
            },
            issuer="target",
        )
        self._commit(
            state,
            artifact,
            phase="REHEARSAL_LEASE",
            fence_epoch=fence_epoch,
            fence_digest=lease_digest,
            rehearsal_cas_digest=artifact.payload_sha256,
        )
        return artifact

    def _ack_claims(
        self,
        state: LanderPiTargetMotionState,
        *,
        intent: MotionSafetyIntent,
        phase: Literal["START", "STOP"],
        start_ack_artifact_digest: str | None = None,
    ) -> dict[str, Any]:
        status = self._status(expected_process_state="ARMED_ZERO", intent=intent)
        if status.binding() != state.armed_provider_binding:
            raise RuntimeError("LANDERPI_ARMED_ZERO_PROVIDER_CHANGED")
        claims: dict[str, Any] = {
            "acknowledged": True,
            "phase": phase,
            "snapshot_artifact_digest": state.pre_snapshot_digest,
            "cas_artifact_digest": state.rehearsal_cas_digest,
            "fence_lease_digest": state.fence_digest,
            "graph_revision": state.graph_revision,
            "zero_velocity_verified": True,
            "motors_stopped": True,
            "motion_command_emitted": False,
            "provider_invocation_count": 0,
            **self._fresh_zero_claims(status),
        }
        if phase == "STOP":
            claims["start_ack_artifact_digest"] = start_ack_artifact_digest
        return claims

    def acknowledge_zero_motion_start(
        self,
        *,
        acceptance_id: str,
        intent: MotionSafetyIntent,
        fence_cas_artifact_digest: str,
    ) -> SignedZeroMotionArtifact:
        state = self._load(intent)
        self._assert_owner(state, acceptance_id, intent)
        if state.phase != "REHEARSAL_LEASE" or state.rehearsal_cas_digest != fence_cas_artifact_digest:
            raise RuntimeError("LANDERPI_REHEARSAL_CAS_MISMATCH")
        artifact = self._artifact(
            state=state,
            acceptance_id=acceptance_id,
            intent=intent,
            kind="ZERO_MOTION_START_ACK",
            claims=self._ack_claims(state, intent=intent, phase="START"),
            issuer="target",
        )
        self._commit(state, artifact, phase="REHEARSAL_STARTED", start_ack_digest=artifact.payload_sha256)
        return artifact

    def acknowledge_zero_motion_stop(
        self,
        *,
        acceptance_id: str,
        intent: MotionSafetyIntent,
        fence_cas_artifact_digest: str,
        start_ack_artifact_digest: str,
    ) -> SignedZeroMotionArtifact:
        state = self._load(intent)
        self._assert_owner(state, acceptance_id, intent)
        if state.phase != "REHEARSAL_STARTED" or state.rehearsal_cas_digest != fence_cas_artifact_digest or state.start_ack_digest != start_ack_artifact_digest:
            raise RuntimeError("LANDERPI_REHEARSAL_START_MISMATCH")
        artifact = self._artifact(
            state=state,
            acceptance_id=acceptance_id,
            intent=intent,
            kind="ZERO_MOTION_STOP_ACK",
            claims=self._ack_claims(
                state,
                intent=intent,
                phase="STOP",
                start_ack_artifact_digest=start_ack_artifact_digest,
            ),
            issuer="target",
        )
        self._commit(state, artifact, phase="REHEARSAL_STOPPED", stop_ack_digest=artifact.payload_sha256)
        return artifact

    def release_fence(
        self,
        *,
        acceptance_id: str,
        intent: MotionSafetyIntent,
        fence_cas_artifact_digest: str,
        stop_ack_artifact_digest: str,
        post_snapshot_artifact_digest: str,
    ) -> SignedZeroMotionArtifact:
        state = self._load(intent)
        self._assert_owner(state, acceptance_id, intent)
        if (
            state.phase != "REHEARSAL_POST_OBSERVED"
            or state.rehearsal_cas_digest != fence_cas_artifact_digest
            or state.stop_ack_digest != stop_ack_artifact_digest
            or state.post_snapshot_digest != post_snapshot_artifact_digest
        ):
            raise RuntimeError("LANDERPI_REHEARSAL_RELEASE_MISMATCH")
        released_epoch = state.fence_epoch + 1
        released_digest = _fence_digest(intent, released_epoch)
        artifact = self._artifact(
            state=state,
            acceptance_id=acceptance_id,
            intent=intent,
            kind="LIVE_FENCE_RELEASE",
            claims={
                "released": True,
                "cas_artifact_digest": fence_cas_artifact_digest,
                "stop_ack_artifact_digest": stop_ack_artifact_digest,
                "post_snapshot_artifact_digest": post_snapshot_artifact_digest,
                "released_fence_lease_digest": state.fence_digest,
                "restored_fence_digest": released_digest,
                "restored_fence_epoch": released_epoch,
                "direct_access_blocked": True,
                "motion_enabled": False,
                "provider_invocation_count": 0,
            },
            issuer="target",
        )
        self._commit(
            state,
            artifact,
            phase="REHEARSAL_RELEASED",
            fence_epoch=released_epoch,
            fence_digest=released_digest,
            release_artifact_digest=artifact.payload_sha256,
        )
        return artifact

    def _debug_gate_binding(self, state: LanderPiTargetMotionState) -> dict[str, Any] | None:
        if state.debug_admission_digest is None:
            return None
        if state.debug_attestation_artifact_digest is None:
            raise RuntimeError("DEBUG_USER_ATTESTATION_ARTIFACT_REQUIRED")
        artifact = self.store.get_artifact(state.debug_attestation_artifact_digest)
        if artifact is None or artifact.kind != "DEBUG_USER_ATTESTED_ADMISSION" or artifact.claims.get("debug_admission_digest") != state.debug_admission_digest:
            raise RuntimeError("DEBUG_USER_ATTESTATION_ARTIFACT_INVALID")
        claims = artifact.claims
        return {
            "debug_admission_digest": state.debug_admission_digest,
            "debug_attestation_artifact_digest": artifact.payload_sha256,
            "basis_digest": claims["basis_digest"],
            "requested_rotation_degrees": claims["requested_rotation_degrees"],
            "requested_linear_meters": claims["requested_linear_meters"],
            "max_abs_rotation_degrees": claims["max_abs_rotation_degrees"],
            "max_abs_linear_meters": claims["max_abs_linear_meters"],
            "production_authority_verified": False,
            "fresh_estop_challenge_verified": False,
            "production_ready": False,
            "report_status": "PASS_WITH_USER_ATTESTED_SITE_SAFETY",
        }

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
    ) -> SignedZeroMotionArtifact:
        state = self._load(intent)
        self._assert_owner(state, acceptance_id, intent)
        if (
            state.phase != "REHEARSAL_RELEASED"
            or state.release_artifact_digest != release_artifact_digest
            or state.post_snapshot_digest != post_snapshot_artifact_digest
            or state.fence_digest != released_fence_digest
            or state.fence_epoch != released_fence_epoch
            or state.graph_revision != expected_graph_revision
        ):
            raise RuntimeError("LANDERPI_PROVIDER_CHALLENGE_STATE_MISMATCH")
        point = _point(self.clock)
        status = self._status(expected_process_state="ARMED_ZERO", intent=intent)
        if status.binding() != state.armed_provider_binding:
            raise RuntimeError("LANDERPI_ARMED_ZERO_PROVIDER_CHANGED")
        expires_at = point + timedelta(seconds=self.artifact_ttl_s)
        consume_token = compute_provider_gate_consume_token_digest(
            acceptance_id=acceptance_id,
            intent=intent,
            release_artifact_digest=release_artifact_digest,
            post_snapshot_artifact_digest=post_snapshot_artifact_digest,
            expected_fence_digest=state.fence_digest,
            expected_fence_epoch=state.fence_epoch,
            expected_graph_revision=state.graph_revision,
            expires_at=expires_at,
        )
        claims: dict[str, Any] = {
            "one_shot": True,
            "consumed": False,
            "release_artifact_digest": release_artifact_digest,
            "post_snapshot_artifact_digest": post_snapshot_artifact_digest,
            "expected_fence_digest": state.fence_digest,
            "expected_fence_epoch": state.fence_epoch,
            "expected_graph_revision": state.graph_revision,
            "consume_token_digest": consume_token,
            "armed_zero_provider_binding": state.armed_provider_binding.model_dump(mode="json"),
            "motion_enabled": False,
            "provider_invocation_count": 0,
            **self._fresh_zero_claims(status),
        }
        debug_binding = self._debug_gate_binding(state)
        if debug_binding is not None:
            claims["debug_gate_binding"] = debug_binding
        artifact = SignedZeroMotionArtifact.build(
            artifact_id=_artifact_id(acceptance_id, "PROVIDER_GATE_CHALLENGE", state.state_revision + 1),
            kind="PROVIDER_GATE_CHALLENGE",
            issuer_id=self.policy.target_authority_id,
            acceptance_id=acceptance_id,
            intent=intent,
            issued_at=point,
            expires_at=expires_at,
            claims=claims,
            signing_key=self.target_signing_key._material(),
        )
        self._commit(
            state,
            artifact,
            phase="CHALLENGE_PENDING",
            challenge_artifact_digest=artifact.payload_sha256,
            consume_token_digest=consume_token,
        )
        return artifact

    def compare_and_set_provider_gate(
        self,
        *,
        acceptance_id: str,
        intent: MotionSafetyIntent,
        policy: MotionSafetyPolicy,
        challenge_artifact_digest: str,
        consume_token_digest: str,
    ) -> SignedZeroMotionArtifact:
        if policy != self.policy:
            raise RuntimeError("LANDERPI_MOTION_POLICY_MISMATCH")
        state = self._load(intent)
        self._assert_owner(state, acceptance_id, intent)
        if state.phase != "CHALLENGE_PENDING" or state.challenge_artifact_digest != challenge_artifact_digest or state.consume_token_digest != consume_token_digest:
            raise RuntimeError("LANDERPI_PROVIDER_CHALLENGE_ALREADY_USED_OR_INVALID")
        challenge = self.store.get_artifact(challenge_artifact_digest)
        point = _point(self.clock)
        if challenge is None or point >= challenge.expires_at.astimezone(timezone.utc):
            raise RuntimeError("LANDERPI_PROVIDER_CHALLENGE_EXPIRED")
        observation = self._observation()
        self._assert_fixed_graph(observation, armed=True)
        status = self._status(expected_process_state="ARMED_ZERO", intent=intent)
        binding = self._assert_status_graph_binding(observation, status)
        if binding != state.armed_provider_binding:
            raise RuntimeError("LANDERPI_ARMED_ZERO_PROVIDER_CHANGED")
        if observation.graph_revision != state.graph_revision:
            raise RuntimeError("LANDERPI_PROVIDER_GRAPH_CHANGED")
        provider_epoch = state.fence_epoch + 1
        provider_fence = compute_provider_fence_digest(
            acceptance_id=acceptance_id,
            intent=intent,
            challenge_artifact_digest=challenge_artifact_digest,
            consume_token_digest=consume_token_digest,
            live_isolation_digest=observation.live_isolation_digest,
            graph_revision=observation.graph_revision,
            expected_fence_digest=state.fence_digest,
            fence_epoch=provider_epoch,
        )
        consumed_claims: dict[str, Any] = {
            "consumed": True,
            "one_shot": True,
            "challenge_artifact_digest": challenge_artifact_digest,
            "consume_token_digest": consume_token_digest,
            "expected_fence_digest": state.fence_digest,
            "expected_fence_epoch": state.fence_epoch,
            "expected_graph_revision": state.graph_revision,
            "observed_fence_digest": state.fence_digest,
            "observed_fence_epoch": state.fence_epoch,
            "observed_graph_revision": observation.graph_revision,
            "live_isolation_digest": observation.live_isolation_digest,
            "graph_compare_and_set": True,
            "fence_compare_and_set": True,
            "provider_fence_digest": provider_fence,
            "provider_fence_epoch": provider_epoch,
            "armed_zero_provider_binding": binding.model_dump(mode="json"),
            "motion_enabled": False,
            "provider_invocation_count": 0,
            **self._fresh_zero_claims(status),
        }
        debug_binding = self._debug_gate_binding(state)
        if debug_binding is not None:
            consumed_claims["debug_gate_binding"] = debug_binding
        artifact = self._artifact(
            state=state,
            acceptance_id=acceptance_id,
            intent=intent,
            kind="PROVIDER_GATE_CONSUMED",
            claims=consumed_claims,
            issuer="target",
        )
        self._commit(
            state,
            artifact,
            phase="PROVIDER_FENCE",
            fence_epoch=provider_epoch,
            fence_digest=provider_fence,
            consume_artifact_digest=artifact.payload_sha256,
        )
        return artifact

    def abort_zero_motion(self, *, acceptance_id: str, intent: MotionSafetyIntent) -> None:
        state = self._load(intent)
        if state.acceptance_id not in {None, acceptance_id}:
            raise RuntimeError("LANDERPI_ABORT_OWNER_MISMATCH")
        next_epoch = state.fence_epoch + 1
        safe_digest = _fence_digest(intent, next_epoch)
        artifact = self._artifact(
            state=state,
            acceptance_id=acceptance_id,
            intent=intent,
            kind="ZERO_MOTION_ABORT_ACK",
            claims={
                "aborted": True,
                "previous_phase": state.phase,
                "previous_fence_digest": state.fence_digest,
                "safe_fence_digest": safe_digest,
                "safe_fence_epoch": next_epoch,
                "motion_enabled": False,
                "provider_invocation_count": 0,
            },
            issuer="target",
        )
        self._commit(
            state,
            artifact,
            phase="SAFE_BASELINE",
            fence_epoch=next_epoch,
            fence_digest=safe_digest,
            acceptance_id=None,
            call_id=None,
            session_id=None,
            execution_subject_digest=None,
            graph_revision=None,
            pre_snapshot_digest=None,
            rehearsal_cas_digest=None,
            start_ack_digest=None,
            stop_ack_digest=None,
            post_snapshot_digest=None,
            release_artifact_digest=None,
            challenge_artifact_digest=None,
            consume_token_digest=None,
            consume_artifact_digest=None,
            debug_admission_digest=None,
            debug_attestation_artifact_digest=None,
            armed_provider_binding=None,
        )


def _debug_identity(admission: DebugOnlyUserAttestedAdmission) -> dict[str, Any]:
    return {
        "acceptance_id": admission.acceptance_id,
        "call_id": admission.call_id,
        "session_id": admission.session_id,
        "target_id": admission.target_id,
        "target_identity": admission.target_identity,
        "operator_id": admission.operator_id,
        "execution_subject_digest": admission.execution_subject_digest,
        "debug_admission_digest": admission.payload_sha256,
    }


def _debug_acceptance_blocked(
    point: datetime,
    reason: str,
    admission: DebugOnlyUserAttestedAdmission | None = None,
) -> DebugUserAttestedAcceptanceReceipt:
    return DebugUserAttestedAcceptanceReceipt(
        status="DEBUG_BLOCKED",
        report_status="DEBUG_BLOCKED",
        reasons=(reason,),
        evaluated_at=point,
        **(_debug_identity(admission) if admission is not None else {}),
    )


def _debug_consumption_blocked(
    point: datetime,
    reason: str,
    admission: DebugOnlyUserAttestedAdmission | None = None,
    *,
    challenge_artifact_digest: str | None = None,
) -> DebugUserAttestedProviderGateReceipt:
    return DebugUserAttestedProviderGateReceipt(
        status="DEBUG_BLOCKED",
        report_status="DEBUG_BLOCKED",
        reasons=(reason,),
        evaluated_at=point,
        challenge_artifact_digest=challenge_artifact_digest,
        **(_debug_identity(admission) if admission is not None else {}),
    )


def _verify_persisted_artifact(
    artifact: SignedZeroMotionArtifact,
    *,
    kind: ZeroMotionArtifactKind,
    issuer_id: str,
    admission: DebugOnlyUserAttestedAdmission,
    intent: MotionSafetyIntent,
    trust_store: MotionSafetyTrustStore,
    target: LanderPiZeroMotionTarget,
    point: datetime,
) -> bool:
    try:
        parsed = SignedZeroMotionArtifact.model_validate(artifact.model_dump(mode="python"))
    except Exception:
        return False
    expected_identity = {
        "acceptance_id": admission.acceptance_id,
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
    if (
        parsed.kind != kind
        or parsed.issuer_id != issuer_id
        or any(getattr(parsed, field) != expected for field, expected in expected_identity.items())
        or parsed.issued_at.astimezone(timezone.utc) > point
        or point >= parsed.expires_at.astimezone(timezone.utc)
        or target.store.get_artifact(parsed.payload_sha256) != parsed
    ):
        return False
    return trust_store.verify_payload_signature(
        issuer_id=parsed.issuer_id,
        payload_sha256=parsed.payload_sha256,
        signature_hmac_sha256=parsed.signature_hmac_sha256,
    )


def run_debug_user_attested_zero_motion_acceptance(
    admission: DebugOnlyUserAttestedAdmission | Mapping[str, Any] | None,
    *,
    intent: MotionSafetyIntent | Mapping[str, Any] | None,
    policy: MotionSafetyPolicy | Mapping[str, Any] | None,
    trust_store: MotionSafetyTrustStore | None,
    target: LanderPiZeroMotionTarget | None,
    now: datetime | None,
) -> DebugUserAttestedAcceptanceReceipt:
    """Run a real target-owned zero-motion gate under an explicit debug-only basis."""

    try:
        point = _point(lambda: now)
    except Exception:
        return _debug_acceptance_blocked(datetime.now(timezone.utc), "DEBUG_EVALUATION_TIME_INVALID")
    try:
        raw_admission = admission.model_dump(mode="python") if isinstance(admission, BaseModel) else admission
        raw_intent = intent.model_dump(mode="python") if isinstance(intent, BaseModel) else intent
        raw_policy = policy.model_dump(mode="python") if isinstance(policy, BaseModel) else policy
        parsed_admission = DebugOnlyUserAttestedAdmission.model_validate(raw_admission)
        parsed_intent = MotionSafetyIntent.model_validate(raw_intent)
        parsed_policy = MotionSafetyPolicy.model_validate(raw_policy)
    except Exception:
        return _debug_acceptance_blocked(point, "DEBUG_USER_ATTESTED_ADMISSION_INVALID")
    if not isinstance(trust_store, MotionSafetyTrustStore) or not isinstance(target, LanderPiZeroMotionTarget):
        return _debug_acceptance_blocked(point, "DEBUG_LIVE_TARGET_AND_TRUST_REQUIRED", parsed_admission)
    try:
        live_point = _point(target.clock)
    except Exception:
        return _debug_acceptance_blocked(point, "DEBUG_TARGET_TIME_INVALID", parsed_admission)
    if abs((live_point - point).total_seconds()) > 1:
        return _debug_acceptance_blocked(point, "DEBUG_TARGET_TIME_MISMATCH", parsed_admission)
    state_changed = False
    try:
        debug_artifact = target.accept_debug_user_attestation(
            parsed_admission,
            intent=parsed_intent,
            policy=parsed_policy,
        )
        state_changed = True
        if not _verify_persisted_artifact(
            debug_artifact,
            kind="DEBUG_USER_ATTESTED_ADMISSION",
            issuer_id=parsed_policy.target_authority_id,
            admission=parsed_admission,
            intent=parsed_intent,
            trust_store=trust_store,
            target=target,
            point=_point(target.clock),
        ):
            raise RuntimeError("debug admission artifact verification failed")
        pre = target.observe_isolation(
            acceptance_id=parsed_admission.acceptance_id,
            intent=parsed_intent,
            policy=parsed_policy,
            phase="PRE_CAS",
            fence_binding_digest=None,
        )
        cas = target.compare_and_set_fence(
            acceptance_id=parsed_admission.acceptance_id,
            intent=parsed_intent,
            policy=parsed_policy,
            snapshot_artifact_digest=pre.payload_sha256,
        )
        start = target.acknowledge_zero_motion_start(
            acceptance_id=parsed_admission.acceptance_id,
            intent=parsed_intent,
            fence_cas_artifact_digest=cas.payload_sha256,
        )
        stop = target.acknowledge_zero_motion_stop(
            acceptance_id=parsed_admission.acceptance_id,
            intent=parsed_intent,
            fence_cas_artifact_digest=cas.payload_sha256,
            start_ack_artifact_digest=start.payload_sha256,
        )
        post = target.observe_isolation(
            acceptance_id=parsed_admission.acceptance_id,
            intent=parsed_intent,
            policy=parsed_policy,
            phase="POST_STOP",
            fence_binding_digest=cas.claims["fence_lease_digest"],
        )
        release = target.release_fence(
            acceptance_id=parsed_admission.acceptance_id,
            intent=parsed_intent,
            fence_cas_artifact_digest=cas.payload_sha256,
            stop_ack_artifact_digest=stop.payload_sha256,
            post_snapshot_artifact_digest=post.payload_sha256,
        )
        challenge = target.issue_provider_gate_challenge(
            acceptance_id=parsed_admission.acceptance_id,
            intent=parsed_intent,
            release_artifact_digest=release.payload_sha256,
            post_snapshot_artifact_digest=post.payload_sha256,
            released_fence_digest=release.claims["restored_fence_digest"],
            released_fence_epoch=release.claims["restored_fence_epoch"],
            expected_graph_revision=post.claims["graph_revision"],
        )
        sequence = (
            (pre, "LIVE_ISOLATION_SNAPSHOT", parsed_policy.graph_authority_id),
            (cas, "LIVE_FENCE_CAS", parsed_policy.target_authority_id),
            (start, "ZERO_MOTION_START_ACK", parsed_policy.target_authority_id),
            (stop, "ZERO_MOTION_STOP_ACK", parsed_policy.target_authority_id),
            (post, "LIVE_ISOLATION_SNAPSHOT", parsed_policy.graph_authority_id),
            (release, "LIVE_FENCE_RELEASE", parsed_policy.target_authority_id),
            (challenge, "PROVIDER_GATE_CHALLENGE", parsed_policy.target_authority_id),
        )
        for artifact, kind, issuer_id in sequence:
            if not _verify_persisted_artifact(
                artifact,
                kind=kind,
                issuer_id=issuer_id,
                admission=parsed_admission,
                intent=parsed_intent,
                trust_store=trust_store,
                target=target,
                point=_point(target.clock),
            ):
                raise RuntimeError("debug live artifact verification failed")
        state = target.store.load()
        if state.phase != "CHALLENGE_PENDING" or state.debug_admission_digest != parsed_admission.payload_sha256 or state.challenge_artifact_digest != challenge.payload_sha256:
            raise RuntimeError("debug target state is not challenge-pending")
        evaluated_at = _point(target.clock)
        if evaluated_at >= parsed_admission.expires_at.astimezone(timezone.utc):
            raise RuntimeError("debug admission expired during live acceptance")
    except Exception:
        if state_changed:
            try:
                target.abort_zero_motion(
                    acceptance_id=parsed_admission.acceptance_id,
                    intent=parsed_intent,
                )
            except Exception:
                pass
        return _debug_acceptance_blocked(point, "DEBUG_USER_ATTESTED_LIVE_GATE_FAILED", parsed_admission)
    return DebugUserAttestedAcceptanceReceipt(
        status="DEBUG_ACCEPTED",
        report_status="PASS_WITH_USER_ATTESTED_SITE_SAFETY",
        reasons=(),
        evaluated_at=evaluated_at,
        debug_attestation_artifact=debug_artifact,
        artifacts=ZeroMotionArtifactDigests(
            pre_isolation_snapshot=pre.payload_sha256,
            fence_cas=cas.payload_sha256,
            start_ack=start.payload_sha256,
            stop_ack=stop.payload_sha256,
            post_stop_isolation_snapshot=post.payload_sha256,
            fence_release=release.payload_sha256,
            provider_gate_challenge=challenge.payload_sha256,
        ),
        provider_gate=challenge,
        debug_gate_ready=True,
        **_debug_identity(parsed_admission),
    )


def consume_debug_user_attested_provider_gate(
    admission: DebugOnlyUserAttestedAdmission | Mapping[str, Any] | None,
    receipt: DebugUserAttestedAcceptanceReceipt | Mapping[str, Any] | None,
    *,
    intent: MotionSafetyIntent | Mapping[str, Any] | None,
    policy: MotionSafetyPolicy | Mapping[str, Any] | None,
    trust_store: MotionSafetyTrustStore | None,
    target: LanderPiZeroMotionTarget | None,
    now: datetime | None,
) -> DebugUserAttestedProviderGateReceipt:
    """Consume one debug-only challenge via a fresh target-owned graph/fence CAS."""

    try:
        point = _point(lambda: now)
    except Exception:
        return _debug_consumption_blocked(datetime.now(timezone.utc), "DEBUG_EVALUATION_TIME_INVALID")
    try:
        raw_admission = admission.model_dump(mode="python") if isinstance(admission, BaseModel) else admission
        raw_receipt = receipt.model_dump(mode="python") if isinstance(receipt, BaseModel) else receipt
        raw_intent = intent.model_dump(mode="python") if isinstance(intent, BaseModel) else intent
        raw_policy = policy.model_dump(mode="python") if isinstance(policy, BaseModel) else policy
        parsed_admission = DebugOnlyUserAttestedAdmission.model_validate(raw_admission)
        parsed_receipt = DebugUserAttestedAcceptanceReceipt.model_validate(raw_receipt)
        parsed_intent = MotionSafetyIntent.model_validate(raw_intent)
        parsed_policy = MotionSafetyPolicy.model_validate(raw_policy)
    except Exception:
        return _debug_consumption_blocked(point, "DEBUG_PROVIDER_GATE_INPUT_INVALID")
    challenge = parsed_receipt.provider_gate
    challenge_digest = challenge.payload_sha256 if challenge is not None else None
    if (
        parsed_receipt.status != "DEBUG_ACCEPTED"
        or not parsed_receipt.debug_gate_ready
        or parsed_receipt.debug_admission_digest != parsed_admission.payload_sha256
        or any(getattr(parsed_receipt, field) != value for field, value in _debug_identity(parsed_admission).items())
        or point < parsed_admission.issued_at.astimezone(timezone.utc)
        or point >= parsed_admission.expires_at.astimezone(timezone.utc)
    ):
        return _debug_consumption_blocked(
            point,
            "DEBUG_PROVIDER_GATE_IDENTITY_OR_EXPIRY_MISMATCH",
            parsed_admission,
            challenge_artifact_digest=challenge_digest,
        )
    if not isinstance(trust_store, MotionSafetyTrustStore) or not isinstance(target, LanderPiZeroMotionTarget) or challenge is None:
        return _debug_consumption_blocked(
            point,
            "DEBUG_LIVE_TARGET_CHALLENGE_AND_TRUST_REQUIRED",
            parsed_admission,
            challenge_artifact_digest=challenge_digest,
        )
    try:
        live_point = _point(target.clock)
    except Exception:
        return _debug_consumption_blocked(
            point,
            "DEBUG_TARGET_TIME_INVALID",
            parsed_admission,
            challenge_artifact_digest=challenge_digest,
        )
    if abs((live_point - point).total_seconds()) > 1:
        return _debug_consumption_blocked(
            point,
            "DEBUG_TARGET_TIME_MISMATCH",
            parsed_admission,
            challenge_artifact_digest=challenge_digest,
        )
    if not _verify_persisted_artifact(
        parsed_receipt.debug_attestation_artifact,
        kind="DEBUG_USER_ATTESTED_ADMISSION",
        issuer_id=parsed_policy.target_authority_id,
        admission=parsed_admission,
        intent=parsed_intent,
        trust_store=trust_store,
        target=target,
        point=live_point,
    ) or not _verify_persisted_artifact(
        challenge,
        kind="PROVIDER_GATE_CHALLENGE",
        issuer_id=parsed_policy.target_authority_id,
        admission=parsed_admission,
        intent=parsed_intent,
        trust_store=trust_store,
        target=target,
        point=live_point,
    ):
        return _debug_consumption_blocked(
            point,
            "DEBUG_PROVIDER_GATE_ARTIFACT_INVALID",
            parsed_admission,
            challenge_artifact_digest=challenge_digest,
        )
    try:
        state = target.store.load()
        if state.debug_admission_digest != parsed_admission.payload_sha256:
            raise RuntimeError("debug admission state mismatch")
        consumed = target.compare_and_set_provider_gate(
            acceptance_id=parsed_admission.acceptance_id,
            intent=parsed_intent,
            policy=parsed_policy,
            challenge_artifact_digest=challenge.payload_sha256,
            consume_token_digest=challenge.claims["consume_token_digest"],
        )
    except Exception:
        return _debug_consumption_blocked(
            point,
            "DEBUG_PROVIDER_GATE_FRESH_CAS_UNAVAILABLE",
            parsed_admission,
            challenge_artifact_digest=challenge_digest,
        )
    evaluated_at = _point(target.clock)
    if not _verify_persisted_artifact(
        consumed,
        kind="PROVIDER_GATE_CONSUMED",
        issuer_id=parsed_policy.target_authority_id,
        admission=parsed_admission,
        intent=parsed_intent,
        trust_store=trust_store,
        target=target,
        point=evaluated_at,
    ) or not isinstance(consumed.claims.get("armed_zero_provider_binding"), Mapping):
        try:
            target.abort_zero_motion(acceptance_id=parsed_admission.acceptance_id, intent=parsed_intent)
        except Exception:
            pass
        return _debug_consumption_blocked(
            point,
            "DEBUG_PROVIDER_GATE_CONSUMED_ARTIFACT_INVALID",
            parsed_admission,
            challenge_artifact_digest=challenge_digest,
        )
    return DebugUserAttestedProviderGateReceipt(
        status="DEBUG_CONSUMED",
        report_status="PASS_WITH_USER_ATTESTED_SITE_SAFETY",
        reasons=(),
        evaluated_at=evaluated_at,
        challenge_artifact_digest=challenge.payload_sha256,
        debug_attestation_artifact=parsed_receipt.debug_attestation_artifact,
        challenge_artifact=challenge,
        consume_artifact=consumed,
        debug_provider_boundary_open=True,
        debug_motion_authorized=True,
        provider_invocation_limit=1,
        **_debug_identity(parsed_admission),
    )


def revalidate_debug_user_attested_provider_gate(
    admission: DebugOnlyUserAttestedAdmission | Mapping[str, Any],
    receipt: DebugUserAttestedProviderGateReceipt | Mapping[str, Any],
    *,
    intent: MotionSafetyIntent | Mapping[str, Any],
    policy: MotionSafetyPolicy | Mapping[str, Any],
    trust_store: MotionSafetyTrustStore,
    at: datetime,
) -> DebugProviderGateValidationReceipt:
    """Validate the detached debug union arm at the service persistence boundary.

    This never returns a production receipt.  Any malformed, expired, unsigned,
    replayable, or identity-drifted input raises a stable fail-closed error.
    """

    try:
        parsed_admission = DebugOnlyUserAttestedAdmission.model_validate(admission.model_dump(mode="python") if isinstance(admission, BaseModel) else admission)
        parsed_receipt = DebugUserAttestedProviderGateReceipt.model_validate(receipt.model_dump(mode="python") if isinstance(receipt, BaseModel) else receipt)
        parsed_intent = MotionSafetyIntent.model_validate(intent.model_dump(mode="python") if isinstance(intent, BaseModel) else intent)
        parsed_policy = MotionSafetyPolicy.model_validate(policy.model_dump(mode="python") if isinstance(policy, BaseModel) else policy)
        _aware(at, "at")
        point = at.astimezone(timezone.utc)
    except Exception as exc:
        raise ValueError("DEBUG_PROVIDER_GATE_VALIDATION_INPUT_INVALID") from exc
    if not isinstance(trust_store, MotionSafetyTrustStore):
        raise ValueError("DEBUG_PROVIDER_GATE_VALIDATION_TRUST_REQUIRED")
    expected_identity = _debug_identity(parsed_admission)
    if (
        parsed_receipt.status != "DEBUG_CONSUMED"
        or parsed_receipt.report_status != "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
        or parsed_receipt.reasons
        or not parsed_receipt.debug_provider_boundary_open
        or not parsed_receipt.debug_motion_authorized
        or parsed_receipt.provider_invocation_limit != 1
        or any(getattr(parsed_receipt, field) != value for field, value in expected_identity.items())
        or parsed_admission.call_id != parsed_intent.call_id
        or parsed_admission.session_id != parsed_intent.session_id
        or parsed_admission.target_id != parsed_intent.target_id
        or parsed_admission.target_identity != parsed_intent.target_identity
        or parsed_admission.operator_id != parsed_intent.operator_id
        or parsed_admission.execution_subject_digest != parsed_intent.execution_subject_digest
        or parsed_admission.site_id != parsed_policy.site_id
        or parsed_admission.safe_zone_id != parsed_policy.safe_zone_id
        or parsed_policy.target_id != parsed_intent.target_id
        or parsed_policy.target_identity != parsed_intent.target_identity
        or point < parsed_admission.issued_at.astimezone(timezone.utc)
        or point >= parsed_admission.expires_at.astimezone(timezone.utc)
    ):
        raise ValueError("DEBUG_PROVIDER_GATE_VALIDATION_IDENTITY_OR_EXPIRY_MISMATCH")
    debug_artifact = parsed_receipt.debug_attestation_artifact
    challenge = parsed_receipt.challenge_artifact
    consumed = parsed_receipt.consume_artifact
    if debug_artifact is None or challenge is None or consumed is None:
        raise ValueError("DEBUG_PROVIDER_GATE_VALIDATION_ARTIFACTS_REQUIRED")
    artifact_kinds = (
        (debug_artifact, "DEBUG_USER_ATTESTED_ADMISSION"),
        (challenge, "PROVIDER_GATE_CHALLENGE"),
        (consumed, "PROVIDER_GATE_CONSUMED"),
    )
    common_identity = {
        "acceptance_id": parsed_admission.acceptance_id,
        "call_id": parsed_intent.call_id,
        "session_id": parsed_intent.session_id,
        "target_id": parsed_intent.target_id,
        "target_identity": parsed_intent.target_identity,
        "operator_id": parsed_intent.operator_id,
        "execution_subject_digest": parsed_intent.execution_subject_digest,
        "ros_graph_digest": parsed_intent.ros_graph_digest,
        "command_route": parsed_intent.command_route,
        "command_interface": parsed_intent.command_interface,
        "publisher_identity": parsed_intent.publisher_identity,
        "direct_motor_route": parsed_intent.direct_motor_route,
        "direct_motor_interface": parsed_intent.direct_motor_interface,
        "direct_motor_publisher_identity": parsed_intent.direct_motor_publisher_identity,
    }
    for artifact, kind in artifact_kinds:
        if (
            artifact.kind != kind
            or artifact.issuer_id != parsed_policy.target_authority_id
            or any(getattr(artifact, field) != value for field, value in common_identity.items())
            or artifact.issued_at.astimezone(timezone.utc) > point
            or point >= artifact.expires_at.astimezone(timezone.utc)
            or not trust_store.verify_payload_signature(
                issuer_id=artifact.issuer_id,
                payload_sha256=artifact.payload_sha256,
                signature_hmac_sha256=artifact.signature_hmac_sha256,
            )
        ):
            raise ValueError("DEBUG_PROVIDER_GATE_VALIDATION_ARTIFACT_INVALID")
    expected_debug_binding = {
        "debug_admission_digest": parsed_admission.payload_sha256,
        "debug_attestation_artifact_digest": debug_artifact.payload_sha256,
        "basis_digest": parsed_admission.basis_digest,
        "requested_rotation_degrees": parsed_admission.requested_rotation_degrees,
        "requested_linear_meters": parsed_admission.requested_linear_meters,
        "max_abs_rotation_degrees": 1.0,
        "max_abs_linear_meters": 0.03,
        "production_authority_verified": False,
        "fresh_estop_challenge_verified": False,
        "production_ready": False,
        "report_status": "PASS_WITH_USER_ATTESTED_SITE_SAFETY",
    }
    debug_claims = debug_artifact.claims
    if (
        debug_claims.get("debug_only") is not True
        or debug_claims.get("debug_admission_digest") != parsed_admission.payload_sha256
        or debug_claims.get("basis_digest") != parsed_admission.basis_digest
        or debug_claims.get("requested_rotation_degrees") != parsed_admission.requested_rotation_degrees
        or debug_claims.get("requested_linear_meters") != parsed_admission.requested_linear_meters
        or debug_claims.get("production_authority_verified") is not False
        or debug_claims.get("fresh_estop_challenge_verified") is not False
        or debug_claims.get("production_ready") is not False
        or debug_claims.get("one_shot") is not True
        or parsed_receipt.debug_admission_digest != parsed_admission.payload_sha256
        or parsed_receipt.challenge_artifact_digest != challenge.payload_sha256
        or challenge.claims.get("debug_gate_binding") != expected_debug_binding
        or consumed.claims.get("debug_gate_binding") != expected_debug_binding
        or challenge.claims.get("one_shot") is not True
        or challenge.claims.get("consumed") is not False
        or consumed.claims.get("one_shot") is not True
        or consumed.claims.get("consumed") is not True
        or consumed.claims.get("challenge_artifact_digest") != challenge.payload_sha256
        or consumed.claims.get("consume_token_digest") != challenge.claims.get("consume_token_digest")
        or consumed.claims.get("graph_compare_and_set") is not True
        or consumed.claims.get("fence_compare_and_set") is not True
        or consumed.claims.get("motion_enabled") is not False
        or consumed.claims.get("provider_invocation_count") != 0
    ):
        raise ValueError("DEBUG_PROVIDER_GATE_VALIDATION_DEBUG_BINDING_INVALID")
    try:
        challenge_binding = ArmedZeroProviderBinding.model_validate(challenge.claims.get("armed_zero_provider_binding"))
        consumed_binding = ArmedZeroProviderBinding.model_validate(consumed.claims.get("armed_zero_provider_binding"))
        challenge_zero = FreshZeroMotionEvidence.model_validate(challenge.claims.get("fresh_zero_evidence"))
        consumed_zero = FreshZeroMotionEvidence.model_validate(consumed.claims.get("fresh_zero_evidence"))
    except Exception as exc:
        raise ValueError("DEBUG_PROVIDER_GATE_VALIDATION_LIVE_BINDING_INVALID") from exc
    if (
        challenge_binding != consumed_binding
        or challenge.claims.get("fresh_zero_evidence_digest") != challenge_zero.evidence_sha256
        or consumed.claims.get("fresh_zero_evidence_digest") != consumed_zero.evidence_sha256
    ):
        raise ValueError("DEBUG_PROVIDER_GATE_VALIDATION_LIVE_BINDING_INVALID")
    expires_at = min(
        parsed_admission.expires_at,
        debug_artifact.expires_at,
        challenge.expires_at,
        consumed.expires_at,
    ).astimezone(timezone.utc)
    return DebugProviderGateValidationReceipt(
        validated_at=point,
        expires_at=expires_at,
        acceptance_id=parsed_admission.acceptance_id,
        call_id=parsed_admission.call_id,
        session_id=parsed_admission.session_id,
        target_id=parsed_admission.target_id,
        target_identity=parsed_admission.target_identity,
        operator_id=parsed_admission.operator_id,
        execution_subject_digest=parsed_admission.execution_subject_digest,
        debug_admission_digest=parsed_admission.payload_sha256,
        debug_attestation_artifact_digest=debug_artifact.payload_sha256,
        challenge_artifact_digest=challenge.payload_sha256,
        consume_artifact_digest=consumed.payload_sha256,
        provider_gate_receipt_digest=compute_motion_payload_digest(parsed_receipt.model_dump(mode="python")),
        armed_zero_provider_binding=consumed_binding,
        requested_rotation_degrees=parsed_admission.requested_rotation_degrees,
        requested_linear_meters=parsed_admission.requested_linear_meters,
    )


def compose_landerpi_zero_motion_target(
    *,
    policy: MotionSafetyPolicy,
    rpc: PinnedLanderPiMotionRpc,
    state_root: str | os.PathLike[str],
    graph_signing_key: TargetSigningKey,
    target_signing_key: TargetSigningKey,
    clock: Callable[[], datetime] | None = None,
    artifact_ttl_s: int | None = None,
) -> LanderPiZeroMotionTarget:
    """Compose the production driver around a durable target-local store."""

    return LanderPiZeroMotionTarget(
        policy=policy,
        rpc=rpc,
        store=AtomicLanderPiMotionStateStore(state_root),
        graph_signing_key=graph_signing_key,
        target_signing_key=target_signing_key,
        clock=clock,
        artifact_ttl_s=artifact_ttl_s,
    )


__all__ = [
    "ArmedZeroProviderBinding",
    "AtomicLanderPiMotionStateStore",
    "DebugAcceptanceStatus",
    "DebugConsumptionStatus",
    "DebugOnlyUserAttestedAdmission",
    "DebugPinnedPeerBootstrapReplayStore",
    "DebugPinnedTargetdPeerBootstrapReceipt",
    "DebugProviderGateValidationReceipt",
    "DebugUserAttestedAcceptanceReceipt",
    "DebugUserAttestedProviderGateReceipt",
    "FreshZeroMotionEvidence",
    "LanderPiMotionStateStore",
    "LanderPiArmedRegistrySnapshot",
    "LanderPiTargetMotionState",
    "LanderPiZeroMotionStatus",
    "LanderPiZeroMotionTarget",
    "PinnedLanderPiMotionRpc",
    "PinnedLanderPiReadControlTransport",
    "PinnedLanderPiRpcSecurity",
    "PinnedTargetdPeerCapability",
    "PinnedKeyOnlyLanderPiMotionRpc",
    "TargetMotionPhase",
    "TargetPhysicalWorkerRegistryRecord",
    "TargetSigningKey",
    "TargetdDockerPinnedReadControlTransport",
    "compose_landerpi_zero_motion_target",
    "consume_debug_pinned_targetd_peer_bootstrap",
    "consume_debug_user_attested_provider_gate",
    "compute_armed_zero_provider_identity_digest",
    "run_debug_user_attested_zero_motion_acceptance",
    "revalidate_debug_user_attested_provider_gate",
]
