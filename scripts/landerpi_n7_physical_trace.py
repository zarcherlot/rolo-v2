"""Fail-closed N7 physical Trace orchestration for the LanderPi.

The module deliberately separates three authorities:

* a pinned, public-key-only SSH channel owns process isolation and restoration;
* ``run_zero_motion_acceptance`` produces a signed rehearsal receipt but never
  authorizes motion;
* ``ReleaseBoundTrace`` owns the single durable CALL and may reconcile an
  ambiguous outcome only with ``QUERY_CALL``.

The live composition is intentionally explicit.  Import this module and pass
the already-bound acceptance and Release-bound Trace drivers to
``N7PhysicalTraceRunner``.  Running this file directly never moves hardware.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import io
import json
import math
import os
import queue
import re
import stat
import subprocess
import tarfile
import threading
import time
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Protocol

from rolo.dsl.admission import (
    MappingAdmissionIdentity,
    MappingAdmissionScope,
    MappingConfirmationReceipt,
    MappingConfirmationStore,
    mapping_digest,
)
from rolo.dsl.parser import loads_unique_json
from rolo.mvp import CatalogTool, DurableTraceRequestStore, TargetCatalog, ToolState
from rolo.mvp.artifacts import ArtifactIndex, build_artifact_index
from rolo.mvp.certify import write_new_artifact
from rolo.mvp.contracts import SessionState, TraceCall, TraceSessionRequest
from rolo.mvp.trace_plan import (
    TargetdTraceAdapter,
    TargetdTraceReceiptSidecar,
    TargetdTraceResponse,
    TracePlan,
)
from rolo.releases import ReleaseBoundTrace, ToolRelease, tool_release_digest
from rolo.targetd.landerpi_motion_target import (
    DebugOnlyUserAttestedAdmission,
    DebugPinnedTargetdPeerBootstrapReceipt,
    DebugUserAttestedAcceptanceReceipt,
    DebugUserAttestedProviderGateReceipt,
    FreshZeroMotionEvidence,
    TargetSigningKey,
)
from rolo.targetd.lifecycle import WorkerCallKey, WorkerLeaseRecord
from rolo.targetd.motion_acceptance import (
    Ros2TopicEndpointSnapshot,
    ZeroMotionAcceptanceReceipt,
    compute_provider_fence_digest,
    compute_provider_gate_consume_token_digest,
)
from rolo.targetd.motion_safety import (
    MotionSafetyAdmissionRequest,
    MotionSafetyEvidenceBundle,
    MotionSafetyIntent,
    MotionSafetyPolicy,
    MotionSafetyTrustStore,
    compute_direct_motor_fence_digest,
    compute_motion_payload_digest,
    compute_ros_graph_digest,
    compute_stop_action_digest,
)
from rolo.targetd.physical_acceptance import DebugPhysicalAcceptanceSidecar
from rolo.targetd.physical_gate import (
    PhysicalProviderGateReference,
    PhysicalProviderGateSidecar,
)
from rolo.targetd.physical_worker import (
    PhysicalWorkerArmedZero,
    landerpi_bounded_twist_runtime_sha256,
    parse_physical_worker_armed_zero,
    validate_landerpi_rotate_process_call,
)
from rolo.targetd.protocol import (
    ExecutionBundleManifest,
    ExecutionRequestV3,
    FrameKind,
    JourneyPhase,
    JourneySession,
    ProtocolFrame,
    TargetdCallReceipt,
    TargetdExecutionAuthority,
    decode_frame,
    encode_frame,
    execution_subject_digest,
    provider_fence_digest,
)
from rolo.targetd.transport import JourneySessionClient
from rolo.targets.executor import quote_remote_argv

SCHEMA_VERSION = "rolo-landerpi-n7-physical-trace/v1"
TARGET_ID = "mentorpi"
CONTAINER = "MentorPi"
COMMAND_ROUTE = "/cmd_vel"
COMPETING_COMMAND_ROUTE = "/controller/cmd_vel"
DIRECT_MOTOR_ROUTE = "/ros_robot_controller/set_motor"
COMMAND_INTERFACE = "geometry_msgs/msg/Twist"
DIRECT_MOTOR_INTERFACE = "ros_robot_controller_msgs/msg/MotorsState"
TOOL_ID = "app.base.rotate"
ROLO_PUBLISHER = "/rolo_bounded_twist"
DEFAULT_ANGLE_DEGREES = 1.0
DEFAULT_MAX_SPEED_RAD_S = 0.03
MAX_ANGLE_DEGREES = 5.0
MAX_SPEED_RAD_S = 0.05
SENSOR_SAMPLE_WINDOW_S = 3.0
SENSOR_MAX_SAMPLE_AGE_S = 0.5
SENSOR_MIN_SAMPLE_COUNT = 2
SENSOR_MIN_RATE_HZ = 1.0

SENSOR_HEALTH_ROUTES: Mapping[str, str] = {
    "/ros_robot_controller/imu_raw": "sensor_msgs/msg/Imu",
    "/imu": "sensor_msgs/msg/Imu",
    "/odom_raw": "nav_msgs/msg/Odometry",
    "/odom": "nav_msgs/msg/Odometry",
}
BRINGUP_MEMBER_EXECUTABLE_PREFIXES = (
    "/usr/bin/python3",
    "python3",
    "/opt/ros/humble/",
    "/home/ubuntu/ros2_ws/install/",
    "/home/ubuntu/third_party_ros2/install/",
    "/home/ubuntu/third_party_ros2/third_party_ws/install/",
    # GLib may autolaunch this one-shot helper from a ROS node.  It remains
    # in the launcher's process group after daemonizing, so exact group
    # capture must recognize both argv[0] forms before a safe restore can
    # signal the old bringup group.
    "dbus-launch",
    "/usr/bin/dbus-launch",
)

CONTROLLED_SUBSCRIBERS = ("/odom_publisher",)
COMPETING_SUBSCRIBERS = ("/odom_publisher",)
DIRECT_MOTOR_SUBSCRIBERS = ("/ros_robot_controller",)
BASELINE_COMPETING_PUBLISHERS = (
    "/hand_gesture",
    "/joystick_control",
    "/lidar_app",
    "/line_following",
    "/object_tracking",
    "/robot_api",
)
BASELINE_DIRECT_MOTOR_PUBLISHERS = ("/hand_gesture", "/odom_publisher")
ISOLATED_DIRECT_MOTOR_PUBLISHERS = ("/odom_publisher",)

# Only these exact installed entry points may be stopped.  PID alone is never
# accepted: every mutation also binds /proc start time and the full cmdline
# digest captured immediately before isolation.
PUBLISHER_PROCESS_ALLOWLIST: Mapping[str, str] = {
    "/robot_api": "/home/ubuntu/ros2_ws/install/robot_api/lib/robot_api/robot_api",
    "/lidar_app": "/home/ubuntu/ros2_ws/install/app/lib/app/lidar_controller",
    "/line_following": "/home/ubuntu/ros2_ws/install/app/lib/app/line_following",
    "/object_tracking": "/home/ubuntu/ros2_ws/install/app/lib/app/object_tracking",
    "/hand_gesture": "/home/ubuntu/ros2_ws/install/app/lib/app/hand_gesture",
    "/joystick_control": "/home/ubuntu/ros2_ws/install/peripherals/lib/peripherals/joystick_control",
}

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:%-]{0,254}$")
_USER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_STAGE = re.compile(r"^/dev/shm/rolo-n7-physical-[0-9a-f]{20}$")
_HOST_TARGETD_STAGE = re.compile(
    r"^/dev/shm/rolo-n7-targetd-[0-9a-f]{20}$"
)
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_ENDPOINT_GID = re.compile(r"^[0-9a-f]{16,128}$")
_TARGETD_ERROR_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_MAX_RPC_BYTES = 256 * 1024
_MAX_REMOTE_DIAGNOSTIC_CHARS = 512
_MAX_HOST_ARCHIVE_BYTES = 8 * 1024 * 1024
_MAX_HOST_EXPANDED_BYTES = 8 * 1024 * 1024
_MAX_HOST_ARCHIVE_MEMBERS = 1024
_MAX_HOST_BOOTSTRAP_BYTES = 512 * 1024

_ROS_CONTAINER_EXEC_WRAPPER = (
    'set -e; export HOME=/home/ubuntu; . /opt/ros/humble/setup.bash; '
    '. /home/ubuntu/ros2_ws/install/setup.bash; '
    '. /home/ubuntu/ros2_ws/.robotrc >/dev/null; set -u; exec "$@"'
)

PhysicalAcceptanceReceipt = (
    ZeroMotionAcceptanceReceipt | DebugUserAttestedAcceptanceReceipt
)


class N7PhysicalBlocked(RuntimeError):
    """Stable, non-sensitive fail-closed diagnostic."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
            default=_json_default,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_CANONICAL_JSON_INVALID",
            "an N7 control or evidence record is not bounded canonical JSON",
        ) from exc


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise TypeError("naive datetime")
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, Path):
        return str(value)
    raise TypeError(type(value).__name__)


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _parse_time(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise N7PhysicalBlocked("N7_PHYSICAL_SNAPSHOT_INVALID", f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise N7PhysicalBlocked("N7_PHYSICAL_SNAPSHOT_INVALID", f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise N7PhysicalBlocked("N7_PHYSICAL_SNAPSHOT_INVALID", f"{label} is not timezone-aware")
    return parsed.astimezone(timezone.utc)


def _safe_tuple(value: object, *, label: str, limit: int = 32) -> tuple[str, ...]:
    if (
        not isinstance(value, (list, tuple))
        or len(value) > limit
        or any(
            not isinstance(item, str)
            or not item.startswith("/")
            or len(item) > 256
            for item in value
        )
    ):
        raise N7PhysicalBlocked("N7_PHYSICAL_SNAPSHOT_INVALID", f"{label} is invalid")
    items = tuple(sorted(value))
    if len(items) != len(set(items)):
        raise N7PhysicalBlocked("N7_PHYSICAL_SNAPSHOT_INVALID", f"{label} contains duplicates")
    return items


def _safe_endpoint_pairs(
    identities_value: object,
    gids_value: object,
    *,
    identities_label: str,
    gids_label: str,
    limit: int = 32,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Validate and canonicalize endpoint identities without losing GID binding."""

    if (
        not isinstance(identities_value, (list, tuple))
        or not isinstance(gids_value, (list, tuple))
        or len(identities_value) != len(gids_value)
        or len(identities_value) > limit
        or any(
            not isinstance(item, str)
            or not item.startswith("/")
            or len(item) > 256
            for item in identities_value
        )
        or any(
            not isinstance(item, str) or _ENDPOINT_GID.fullmatch(item) is None
            for item in gids_value
        )
    ):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_SNAPSHOT_INVALID",
            f"{identities_label}/{gids_label} endpoint pairs are invalid",
        )
    pairs = tuple(sorted(zip(identities_value, gids_value, strict=True)))
    identities = tuple(str(identity) for identity, _gid in pairs)
    gids = tuple(str(gid) for _identity, gid in pairs)
    if len(identities) != len(set(identities)):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_SNAPSHOT_INVALID",
            f"{identities_label} contains duplicates",
        )
    if len(gids) != len(set(gids)):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_SNAPSHOT_INVALID",
            f"{gids_label} contains duplicates",
        )
    return identities, gids


def stage_root_for(run_id: str) -> str:
    """Derive one exact tmpfs root without exposing the run id remotely."""

    if not isinstance(run_id, str) or _ID.fullmatch(run_id) is None:
        raise N7PhysicalBlocked("N7_PHYSICAL_RUN_ID_INVALID", "run id is not protocol-safe")
    suffix = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:20]
    return f"/dev/shm/rolo-n7-physical-{suffix}"


def host_targetd_stage_root_for(run_id: str) -> str:
    """Derive the independent Pi-host targetd stage for one run."""

    if not isinstance(run_id, str) or _ID.fullmatch(run_id) is None:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_RUN_ID_INVALID",
            "run id is not protocol-safe",
        )
    suffix = hashlib.sha256(
        ("targetd-host:" + run_id).encode("utf-8")
    ).hexdigest()[:20]
    return f"/dev/shm/rolo-n7-targetd-{suffix}"


@dataclass(frozen=True)
class HostTargetdSourceArchive:
    """Bounded deterministic source archive staged to the Pi host."""

    payload: bytes = field(repr=False)
    expanded_bytes: int
    member_count: int
    sha256: str


def build_host_targetd_source_archive(
    package_root: Path,
) -> HostTargetdSourceArchive:
    """Archive only ``src/rolo`` and the spawn-safe host launcher.

    The archive is link-free, reproducible, and rooted at ``repo`` so a child
    created with the multiprocessing ``spawn`` method can import both Rolo and
    ``scripts.landerpi_n7_targetd_host`` from disk.
    """

    try:
        root = Path(package_root).expanduser().resolve(strict=True)
    except OSError as exc:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_HOST_SOURCE_ROOT_INVALID",
            "host targetd source root is unavailable",
        ) from exc
    source_root = root / "src" / "rolo"
    launcher = root / "scripts" / "landerpi_n7_targetd_host.py"
    if (
        _is_link_or_reparse(root)
        or _is_link_or_reparse(source_root)
        or not source_root.is_dir()
        or _is_link_or_reparse(launcher)
        or not launcher.is_file()
    ):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_HOST_SOURCE_ROOT_INVALID",
            "host source must contain regular Rolo and launcher files",
        )
    candidates: list[tuple[Path, PurePosixPath]] = []
    expanded = 0
    try:
        for path in sorted(
            source_root.rglob("*.py"),
            key=lambda item: item.relative_to(source_root).as_posix(),
        ):
            if _is_link_or_reparse(path) or not path.is_file():
                raise OSError("untrusted source entry")
            relative = PurePosixPath(
                "repo",
                "src",
                "rolo",
                *path.relative_to(source_root).parts,
            )
            candidates.append((path, relative))
            expanded += path.stat().st_size
        candidates.append(
            (
                launcher,
                PurePosixPath(
                    "repo",
                    "scripts",
                    "landerpi_n7_targetd_host.py",
                ),
            )
        )
        expanded += launcher.stat().st_size
    except OSError as exc:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_HOST_SOURCE_CHANGED",
            "host targetd source changed while it was enumerated",
        ) from exc
    if (
        not candidates
        or len(candidates) > _MAX_HOST_ARCHIVE_MEMBERS
        or not 0 < expanded <= _MAX_HOST_EXPANDED_BYTES
    ):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_HOST_SOURCE_LIMIT",
            "host targetd source exceeds its fixed file or byte budget",
        )
    output = io.BytesIO()
    try:
        with tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as archive:
            directories = {
                PurePosixPath("repo"),
                PurePosixPath("repo", "src"),
                PurePosixPath("repo", "src", "rolo"),
                PurePosixPath("repo", "scripts"),
            }
            for _path, relative in candidates:
                directories.update(relative.parents)
            for directory in sorted(
                (item for item in directories if str(item) not in {".", ""}),
                key=lambda item: (len(item.parts), item.as_posix()),
            ):
                info = tarfile.TarInfo(directory.as_posix())
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.mtime = info.uid = info.gid = 0
                info.uname = info.gname = ""
                archive.addfile(info)
            for path, relative in candidates:
                payload = path.read_bytes()
                if len(payload) != path.stat().st_size:
                    raise OSError("source entry changed")
                info = tarfile.TarInfo(relative.as_posix())
                info.mode = 0o644
                info.mtime = info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
    except (OSError, tarfile.TarError) as exc:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_HOST_SOURCE_CHANGED",
            "host targetd source could not be archived exactly",
        ) from exc
    payload = output.getvalue()
    if not payload or len(payload) > _MAX_HOST_ARCHIVE_BYTES:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_HOST_ARCHIVE_LIMIT",
            "host targetd archive exceeds its fixed byte budget",
        )
    return HostTargetdSourceArchive(
        payload=payload,
        expanded_bytes=expanded,
        member_count=len(candidates),
        sha256="sha256:" + hashlib.sha256(payload).hexdigest(),
    )


@dataclass(frozen=True)
class HostTargetdBootstrapKeys:
    """Ephemeral in-memory HMAC material sent only over the pinned channel."""

    targetd_signing: bytes = field(repr=False)
    bundle_verification: bytes = field(repr=False)
    graph_signing: bytes = field(repr=False)
    target_signing: bytes = field(repr=False)
    peer_bootstrap_verification: bytes = field(repr=False)

    def __post_init__(self) -> None:
        for value in (
            self.targetd_signing,
            self.bundle_verification,
            self.graph_signing,
            self.target_signing,
            self.peer_bootstrap_verification,
        ):
            if not isinstance(value, bytes) or not 32 <= len(value) <= 4096:
                raise ValueError("host targetd bootstrap keys must contain 32-4096 bytes")

    @classmethod
    def generate(
        cls,
        *,
        bundle_verification: bytes,
        targetd_signing: bytes | None = None,
    ) -> HostTargetdBootstrapKeys:
        """Generate per-run keys without serializing them into the descriptor."""

        return cls(
            targetd_signing=targetd_signing or os.urandom(32),
            bundle_verification=bundle_verification,
            graph_signing=os.urandom(32),
            target_signing=os.urandom(32),
            peer_bootstrap_verification=os.urandom(32),
        )

    def encoded(self) -> dict[str, str]:
        return {
            "targetd_signing_base64": base64.b64encode(
                self.targetd_signing
            ).decode("ascii"),
            "bundle_verification_base64": base64.b64encode(
                self.bundle_verification
            ).decode("ascii"),
            "graph_signing_base64": base64.b64encode(
                self.graph_signing
            ).decode("ascii"),
            "target_signing_base64": base64.b64encode(
                self.target_signing
            ).decode("ascii"),
            "peer_bootstrap_verification_base64": base64.b64encode(
                self.peer_bootstrap_verification
            ).decode("ascii"),
        }


def build_host_targetd_bootstrap(
    channel: PinnedHostTargetdStdioChannel,
    *,
    request: ExecutionRequestV3,
    manifest: ExecutionBundleManifest,
    bundle_source: bytes,
    policy: Any,
    mapping_confirmation_receipt: Any,
    keys: HostTargetdBootstrapKeys,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build the strict host bootstrap from independently validated inputs.

    The complete v3 request is included because host composition must
    provision state before PREPARE while still revalidating the exact request
    at the protocol boundary.  ``expected_peer`` is derived independently
    from the real SSH configuration/channel and never from the signed peer
    receipt it is used to verify.
    """

    # Keep heavyweight mapping/policy types out of module import paths used by
    # Pi-host dependency smoke tests.
    from rolo.dsl.admission import MappingConfirmationReceipt
    from rolo.targetd.motion_safety import MotionSafetyPolicy

    if (
        not isinstance(channel, PinnedHostTargetdStdioChannel)
        or channel.stage_receipt is None
        or channel.ready_receipt is not None
        or not isinstance(request, ExecutionRequestV3)
        or not isinstance(manifest, ExecutionBundleManifest)
        or not isinstance(bundle_source, bytes)
        or not isinstance(keys, HostTargetdBootstrapKeys)
    ):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_HOST_BOOTSTRAP_INPUT_INVALID",
            "host targetd bootstrap inputs are incomplete or out of sequence",
        )
    try:
        parsed_request = ExecutionRequestV3.model_validate(
            request.model_dump(mode="python")
        )
        parsed_manifest = ExecutionBundleManifest.model_validate(
            manifest.model_dump(mode="python")
        )
        parsed_policy = MotionSafetyPolicy.model_validate(
            policy.model_dump(mode="python")
            if callable(getattr(policy, "model_dump", None))
            else policy
        )
        mapping_receipt = MappingConfirmationReceipt.model_validate(
            mapping_confirmation_receipt.model_dump(mode="python")
            if callable(getattr(mapping_confirmation_receipt, "model_dump", None))
            else mapping_confirmation_receipt
        )
        parsed_manifest.verify_signature(keys.bundle_verification)
    except Exception as exc:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_HOST_BOOTSTRAP_INPUT_INVALID",
            "host bootstrap policy, Mapping receipt, or bundle signature is invalid",
        ) from exc
    request = parsed_request
    manifest = parsed_manifest
    point = now or datetime.now(timezone.utc)
    if point.tzinfo is None or point.utcoffset() is None:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_CLOCK_INVALID",
            "host bootstrap clock must be timezone-aware",
        )
    point = point.astimezone(timezone.utc)
    call_key = WorkerCallKey.from_request(request)
    authority = request.authority
    runtime = manifest.observation_contract.get("provider_runtime_sha256")
    if (
        request.bundle_digest != manifest.bundle_digest
        or request.target_id != TARGET_ID
        or request.provider_id != "ros-container"
        or request.provider_operation != "base.rotate"
        or request.arguments != MotionSpec().arguments()
        or request.deadline <= point + timedelta(seconds=5)
        or authority.mapping_admission != mapping_receipt.admission_identity()
        or authority.mapping_confirmation_receipt_digest
        != mapping_receipt.receipt_digest
        or mapping_receipt.decision != "CONFIRMED"
        or mapping_receipt.expires_at is None
        or mapping_receipt.expires_at <= request.deadline
        or parsed_policy.target_id != request.target_id
        or parsed_policy.target_identity
        != authority.mapping_admission.target_identity_digest
        or parsed_policy.command_route != COMMAND_ROUTE
        or parsed_policy.command_interface != COMMAND_INTERFACE
        or parsed_policy.allowed_publisher_identity != ROLO_PUBLISHER
        or parsed_policy.direct_motor_route != DIRECT_MOTOR_ROUTE
        or parsed_policy.allowed_direct_motor_publisher_identity
        != ISOLATED_DIRECT_MOTOR_PUBLISHERS[0]
        or parsed_policy.graph_authority_id
        == parsed_policy.target_authority_id
        or request.motion_safety_admission.intent.command_route != COMMAND_ROUTE
        or request.motion_safety_admission.intent.publisher_identity
        != ROLO_PUBLISHER
        or request.motion_safety_admission.intent.direct_motor_route
        != DIRECT_MOTOR_ROUTE
        or not isinstance(runtime, str)
        or re.fullmatch(r"[0-9a-f]{64}", runtime) is None
        or hashlib.sha256(bundle_source).hexdigest() != manifest.source_digest
    ):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_HOST_BOOTSTRAP_IDENTITY_MISMATCH",
            "host bootstrap does not bind the exact debug request and LanderPi route",
        )
    config = channel.config
    expected_peer = {
        "bootstrap_authority_id": "debug-controller:n7",
        "ssh_host": config.host,
        "ssh_port": config.port,
        "ssh_username": config.user,
        "pinned_host_key_sha256": config.pinned_host_key_fingerprint,
        "client_public_key_sha256": config.public_key_fingerprint,
        "known_hosts_sha256": config.known_hosts_digest,
        "channel_binding_sha256": channel.channel_binding_sha256,
    }
    peer_nonce = os.urandom(32)
    # The controller and Pi use independent wall clocks.  Start the signed
    # validity window five seconds early so a small, measured negative skew on
    # the Pi cannot make a freshly issued one-shot capability appear to come
    # from the future.  Its total signed lifetime remains below the model's
    # hard 60-second ceiling and its post-creation lifetime remains 45 seconds.
    peer_issued_at = point - timedelta(seconds=5)
    peer_receipt = DebugPinnedTargetdPeerBootstrapReceipt.build(
        capability_id=f"n7-peer-{call_key.digest()[:20]}",
        bootstrap_authority_id=str(expected_peer["bootstrap_authority_id"]),
        target_id=request.target_id,
        target_identity=authority.mapping_admission.target_identity_digest,
        call_id=request.idempotency_key,
        session_id=request.session_id,
        execution_subject_digest=request.execution_subject_digest,
        ssh_host=config.host,
        ssh_port=config.port,
        pinned_host_key_sha256=config.pinned_host_key_fingerprint,
        client_public_key_sha256=config.public_key_fingerprint,
        known_hosts_sha256=config.known_hosts_digest,
        channel_binding_sha256=channel.channel_binding_sha256,
        bootstrap_nonce=peer_nonce,
        issued_at=peer_issued_at,
        expires_at=min(point + timedelta(seconds=45), request.deadline),
        signing_key=TargetSigningKey.from_bytes(
            keys.peer_bootstrap_verification
        ),
    )
    payload: dict[str, Any] = {
        "schema_version": "rolo-n7-targetd-host-bootstrap/v1",
        "run_id": channel.run_id,
        "stage_root": channel.stage_root,
        "stage_nonce": channel.stage_nonce,
        "target_id": request.target_id,
        "target_identity": authority.mapping_admission.target_identity_digest,
        "expected_call": {
            "id": request.idempotency_key,
            "session": request.session_id,
            "execution_subject_digest": request.execution_subject_digest,
            "motion_fence_epoch": request.authority.fence_epoch,
            "request_digest": request.request_digest(),
            "call_key_digest": call_key.digest(),
        },
        "execution_request": request.model_dump(mode="json"),
        "motion_intent": request.motion_safety_admission.intent.model_dump(
            mode="json"
        ),
        "policy": parsed_policy.model_dump(mode="json"),
        "authority": authority.model_dump(mode="json"),
        "mapping_confirmation_receipt": mapping_receipt.model_dump(mode="json"),
        "manifest": manifest.model_dump(mode="json"),
        "bundle_source_base64": base64.b64encode(bundle_source).decode("ascii"),
        "keys": keys.encoded(),
        "peer_bootstrap_receipt": peer_receipt.model_dump(mode="json"),
        "provider_runtime_sha256": runtime,
        "expected_peer": expected_peer,
    }
    payload["payload_sha256"] = _digest(payload)
    return payload


def validate_host_targetd_bootstrap_payload(
    channel: PinnedHostTargetdStdioChannel,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate every duplicated bootstrap identity before it crosses SSH."""

    from rolo.dsl.admission import MappingConfirmationReceipt
    from rolo.targetd.motion_safety import MotionSafetyIntent, MotionSafetyPolicy

    top_level = {
        "schema_version",
        "run_id",
        "stage_root",
        "stage_nonce",
        "payload_sha256",
        "target_id",
        "target_identity",
        "expected_call",
        "execution_request",
        "motion_intent",
        "policy",
        "authority",
        "mapping_confirmation_receipt",
        "manifest",
        "bundle_source_base64",
        "keys",
        "peer_bootstrap_receipt",
        "provider_runtime_sha256",
        "expected_peer",
    }
    expected_call_fields = {
        "id",
        "session",
        "execution_subject_digest",
        "motion_fence_epoch",
        "request_digest",
        "call_key_digest",
    }
    expected_peer_fields = {
        "bootstrap_authority_id",
        "ssh_host",
        "ssh_port",
        "ssh_username",
        "pinned_host_key_sha256",
        "client_public_key_sha256",
        "known_hosts_sha256",
        "channel_binding_sha256",
    }
    key_fields = {
        "targetd_signing_base64",
        "bundle_verification_base64",
        "graph_signing_base64",
        "target_signing_base64",
        "peer_bootstrap_verification_base64",
    }
    try:
        value = dict(payload)
        if set(value) != top_level:
            raise ValueError("bootstrap keys differ")
        unsigned = dict(value)
        claimed_digest = unsigned.pop("payload_sha256")
        if claimed_digest != _digest(unsigned):
            raise ValueError("bootstrap digest differs")
        if (
            value["schema_version"]
            != "rolo-n7-targetd-host-bootstrap/v1"
            or value["run_id"] != channel.run_id
            or value["stage_root"] != channel.stage_root
            or value["stage_nonce"] != channel.stage_nonce
        ):
            raise ValueError("bootstrap stage differs")
        request = ExecutionRequestV3.model_validate(value["execution_request"])
        manifest = ExecutionBundleManifest.model_validate(value["manifest"])
        authority = TargetdExecutionAuthority.model_validate(value["authority"])
        intent = MotionSafetyIntent.model_validate(value["motion_intent"])
        policy = MotionSafetyPolicy.model_validate(value["policy"])
        mapping_receipt = MappingConfirmationReceipt.model_validate(
            value["mapping_confirmation_receipt"]
        )
        expected_call = value["expected_call"]
        expected_peer = value["expected_peer"]
        encoded_keys = value["keys"]
        if (
            not isinstance(expected_call, Mapping)
            or set(expected_call) != expected_call_fields
            or not isinstance(expected_peer, Mapping)
            or set(expected_peer) != expected_peer_fields
            or not isinstance(encoded_keys, Mapping)
            or set(encoded_keys) != key_fields
        ):
            raise ValueError("bootstrap nested keys differ")

        def decode(value: object) -> bytes:
            if not isinstance(value, str) or not value:
                raise ValueError("bootstrap key is missing")
            raw = base64.b64decode(value.encode("ascii"), validate=True)
            if not 32 <= len(raw) <= 4096:
                raise ValueError("bootstrap key size differs")
            if base64.b64encode(raw).decode("ascii") != value:
                raise ValueError("bootstrap key encoding is not canonical")
            return raw

        decoded_keys = {name: decode(encoded_keys[name]) for name in key_fields}
        source = base64.b64decode(
            str(value["bundle_source_base64"]).encode("ascii"),
            validate=True,
        )
        peer = DebugPinnedTargetdPeerBootstrapReceipt.model_validate(
            value["peer_bootstrap_receipt"]
        )
        actual_peer = {
            "bootstrap_authority_id": "debug-controller:n7",
            "ssh_host": channel.config.host,
            "ssh_port": channel.config.port,
            "ssh_username": channel.config.user,
            "pinned_host_key_sha256": (
                channel.config.pinned_host_key_fingerprint
            ),
            "client_public_key_sha256": (
                channel.config.public_key_fingerprint
            ),
            "known_hosts_sha256": channel.config.known_hosts_digest,
            "channel_binding_sha256": channel.channel_binding_sha256,
        }
        exact_call = {
            "id": request.idempotency_key,
            "session": request.session_id,
            "execution_subject_digest": request.execution_subject_digest,
            "motion_fence_epoch": request.authority.fence_epoch,
            "request_digest": request.request_digest(),
            "call_key_digest": WorkerCallKey.from_request(request).digest(),
        }
        peer_key = decoded_keys["peer_bootstrap_verification_base64"]
        expected_peer_signature = "hmac-sha256:" + hmac.new(
            peer_key,
            peer.payload_sha256.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        runtime = manifest.observation_contract.get(
            "provider_runtime_sha256"
        )
        if (
            dict(expected_call) != exact_call
            or dict(expected_peer) != actual_peer
            or request.authority != authority
            or request.motion_safety_admission.intent != intent
            or request.target_id != value["target_id"]
            or intent.target_identity != value["target_identity"]
            or authority.mapping_admission.target_identity_digest
            != value["target_identity"]
            or request.motion_safety_admission.intent.call_id
            != expected_call["id"]
            or request.motion_safety_admission.intent.session_id
            != expected_call["session"]
            or request.motion_safety_admission.intent.execution_subject_digest
            != expected_call["execution_subject_digest"]
            or request.authority.fence_epoch
            != expected_call["motion_fence_epoch"]
            or mapping_receipt.receipt_digest
            != request.mapping_confirmation_receipt_digest
            or mapping_receipt.admission_identity()
            != request.authority.mapping_admission
            or request.bundle_digest != manifest.bundle_digest
            or request.binding_digest != manifest.binding_digest
            or hashlib.sha256(source).hexdigest() != manifest.source_digest
            or value["provider_runtime_sha256"] != runtime
            or policy.target_id != request.target_id
            or policy.target_identity != intent.target_identity
            or policy.graph_authority_id == policy.target_authority_id
            or decoded_keys["graph_signing_base64"]
            == decoded_keys["target_signing_base64"]
            or peer.bootstrap_authority_id
            != expected_peer["bootstrap_authority_id"]
            or peer.target_id != request.target_id
            or peer.target_identity != intent.target_identity
            or peer.call_id != request.idempotency_key
            or peer.session_id != request.session_id
            or peer.execution_subject_digest
            != request.execution_subject_digest
            or peer.ssh_host != expected_peer["ssh_host"]
            or peer.ssh_port != expected_peer["ssh_port"]
            or peer.ssh_username != expected_peer["ssh_username"]
            or peer.pinned_host_key_sha256
            != expected_peer["pinned_host_key_sha256"]
            or peer.client_public_key_sha256
            != expected_peer["client_public_key_sha256"]
            or peer.known_hosts_sha256
            != expected_peer["known_hosts_sha256"]
            or peer.channel_binding_sha256
            != expected_peer["channel_binding_sha256"]
            or not hmac.compare_digest(
                peer.signature_hmac_sha256,
                expected_peer_signature,
            )
        ):
            raise ValueError("bootstrap identities differ")
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_HOST_BOOTSTRAP_PAYLOAD_INVALID",
            "host bootstrap payload is not an exact authenticated v3 call",
        ) from exc
    return value


def build_host_targetd_finalize_payload(
    channel: PinnedHostTargetdStdioChannel,
    *,
    request: ExecutionRequestV3,
    terminal_receipt: TargetdCallReceipt,
    final_zero_verified: bool,
    stop_acknowledged: bool,
    provider_terminated: bool,
    post_isolated: ControlGraphSnapshot,
    provider_invocation_count: int,
    signing_key: bytes,
) -> dict[str, Any]:
    """Authenticate the exact safe terminal proof consumed by host cleanup."""

    if (
        channel.ready_receipt is None
        or channel.finalize_receipt is not None
        or not isinstance(request, ExecutionRequestV3)
        or not isinstance(terminal_receipt, TargetdCallReceipt)
        or terminal_receipt.idempotency_key != request.idempotency_key
        or terminal_receipt.session_id != request.session_id
        or terminal_receipt.target_id != request.target_id
        or terminal_receipt.request_digest != request.request_digest()
        or terminal_receipt.status
        not in {"SUCCEEDED", "FAILED", "STOPPED", "CANCELLED"}
        or not all(
            (final_zero_verified, stop_acknowledged, provider_terminated)
        )
        or not isinstance(post_isolated, ControlGraphSnapshot)
        or provider_invocation_count not in {0, 1}
        or not isinstance(signing_key, bytes)
        or not 32 <= len(signing_key) <= 4096
    ):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_HOST_FINALIZE_PROOF_INVALID",
            "host finalization requires exact terminal, zero, stop, exit, and isolation proof",
        )
    post_isolated.require_isolated()
    target_identity = (
        request.authority.mapping_admission.target_identity_digest
    )
    ready = channel.ready_receipt
    assert ready is not None
    unsigned = {
        "schema_version": "rolo-n7-targetd-host-finalize/v1",
        "run_id": channel.run_id,
        "stage_root": channel.stage_root,
        "bootstrap_payload_sha256": ready.get("bootstrap_payload_sha256"),
        "stage_nonce_sha256": "sha256:"
        + hashlib.sha256(channel.stage_nonce.encode("ascii")).hexdigest(),
        "target_id": request.target_id,
        "session_id": request.session_id,
        "call_id": request.idempotency_key,
        "request_digest": request.request_digest(),
        "call_key_digest": WorkerCallKey.from_request(request).digest(),
        "terminal_receipt_digest": _digest(
            terminal_receipt.model_dump(mode="json")
        ),
        "terminal_status": terminal_receipt.status,
        "final_zero_verified": True,
        "stop_acknowledged": True,
        "provider_terminated": True,
        "post_isolated": True,
        "post_isolated_graph_revision": (
            target_compatible_graph_revision(
                post_isolated,
                target_id=request.target_id,
                target_identity=target_identity,
                direct_motor_interface=(
                    request.motion_safety_admission.intent.direct_motor_interface
                ),
            )
        ),
        "post_isolated_topology_digest": post_isolated.topology_digest(),
        "provider_invocation_count": provider_invocation_count,
    }
    payload_digest = _digest(unsigned)
    tag = hmac.new(
        signing_key,
        payload_digest.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return {
        **unsigned,
        "finalize_payload_sha256": payload_digest,
        "finalize_auth_tag": "hmac-sha256:" + tag,
    }


def verify_host_targetd_finalize_receipt(
    receipt: Mapping[str, Any],
    *,
    request_payload: Mapping[str, Any],
    signing_key: bytes,
) -> dict[str, Any]:
    """Verify a SAFE_TO_CLEANUP host receipt before either stage is removed."""

    value = dict(receipt)
    tag = value.pop("receipt_auth_tag", None)
    digest = value.pop("receipt_payload_sha256", None)
    computed = _digest(value)
    expected = "hmac-sha256:" + hmac.new(
        signing_key,
        computed.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    exact = {
        name: request_payload.get(name)
        for name in (
            "run_id",
            "stage_root",
            "bootstrap_payload_sha256",
            "stage_nonce_sha256",
            "target_id",
            "session_id",
            "call_id",
            "request_digest",
            "call_key_digest",
            "terminal_receipt_digest",
            "terminal_status",
            "final_zero_verified",
            "stop_acknowledged",
            "provider_terminated",
            "post_isolated",
            "post_isolated_graph_revision",
            "post_isolated_topology_digest",
            "provider_invocation_count",
        )
    }
    response_fields = {
        "schema_version",
        "status",
        *exact,
        "worker_terminal_revalidated",
        "stage_cleanup_authorized",
        "receipt_payload_sha256",
        "receipt_auth_tag",
    }
    if (
        set(receipt) != response_fields
        or
        value.get("schema_version")
        != "rolo-n7-targetd-host-finalize-receipt/v1"
        or value.get("status") != "SAFE_TO_CLEANUP"
        or any(value.get(name) != expected_value for name, expected_value in exact.items())
        or value.get("worker_terminal_revalidated") is not True
        or value.get("stage_cleanup_authorized") is not True
        or digest != computed
        or not isinstance(tag, str)
        or not hmac.compare_digest(tag, expected)
    ):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_HOST_FINALIZE_RECEIPT_INVALID",
            "Pi-host finalization receipt is not an authenticated exact safe terminal",
        )
    return dict(receipt)


@dataclass(frozen=True)
class MotionSpec:
    """The only motion requested by this acceptance slice."""

    angle_degrees: float = DEFAULT_ANGLE_DEGREES
    max_speed_rad_s: float = DEFAULT_MAX_SPEED_RAD_S

    def __post_init__(self) -> None:
        if (
            isinstance(self.angle_degrees, bool)
            or not isinstance(self.angle_degrees, (int, float))
            or not math.isfinite(float(self.angle_degrees))
            or float(self.angle_degrees) == 0
            or abs(float(self.angle_degrees)) > MAX_ANGLE_DEGREES
        ):
            raise ValueError(f"angle_degrees must be non-zero and at most {MAX_ANGLE_DEGREES}")
        if (
            isinstance(self.max_speed_rad_s, bool)
            or not isinstance(self.max_speed_rad_s, (int, float))
            or not math.isfinite(float(self.max_speed_rad_s))
            or not 0 < float(self.max_speed_rad_s) <= MAX_SPEED_RAD_S
        ):
            raise ValueError(f"max_speed_rad_s must be in (0, {MAX_SPEED_RAD_S}]")

    def arguments(self) -> dict[str, float]:
        return {
            "angle_degrees": float(self.angle_degrees),
            "max_speed_rad_s": float(self.max_speed_rad_s),
        }


@dataclass(frozen=True)
class PublisherProcessIdentity:
    node_id: str
    executable: str
    launch_argv_prefix: tuple[str, ...]
    pid: int
    start_ticks: int
    argv_sha256: str

    @classmethod
    def parse(cls, value: object) -> PublisherProcessIdentity:
        if not isinstance(value, Mapping):
            raise N7PhysicalBlocked("N7_PHYSICAL_PROCESS_IDENTITY_INVALID", "process identity is missing")
        node_id = value.get("node_id")
        executable = value.get("executable")
        launch_argv_prefix = value.get("launch_argv_prefix")
        pid = value.get("pid")
        start_ticks = value.get("start_ticks")
        argv_sha256 = value.get("argv_sha256")
        if (
            node_id not in PUBLISHER_PROCESS_ALLOWLIST
            or executable != PUBLISHER_PROCESS_ALLOWLIST.get(str(node_id))
            or not isinstance(launch_argv_prefix, list)
            or launch_argv_prefix
            not in ([str(executable)], ["/usr/bin/python3", str(executable)])
            or isinstance(pid, bool)
            or not isinstance(pid, int)
            or pid <= 1
            or isinstance(start_ticks, bool)
            or not isinstance(start_ticks, int)
            or start_ticks <= 0
            or not isinstance(argv_sha256, str)
            or _SHA256.fullmatch(argv_sha256) is None
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PROCESS_IDENTITY_INVALID",
                "publisher process does not match the exact allowlist identity",
            )
        return cls(
            str(node_id),
            str(executable),
            tuple(launch_argv_prefix),
            pid,
            start_ticks,
            argv_sha256,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "node_id": self.node_id,
            "executable": self.executable,
            "launch_argv_prefix": list(self.launch_argv_prefix),
            "pid": self.pid,
            "start_ticks": self.start_ticks,
            "argv_sha256": self.argv_sha256,
        }


@dataclass(frozen=True)
class ControlGraphSnapshot:
    phase: str
    observed_at: datetime
    command_publishers: tuple[str, ...]
    command_publisher_gids: tuple[str, ...]
    command_subscribers: tuple[str, ...]
    command_subscriber_gids: tuple[str, ...]
    competing_publishers: tuple[str, ...]
    competing_publisher_gids: tuple[str, ...]
    competing_subscribers: tuple[str, ...]
    competing_subscriber_gids: tuple[str, ...]
    direct_motor_publishers: tuple[str, ...]
    direct_motor_publisher_gids: tuple[str, ...]
    direct_motor_subscribers: tuple[str, ...]
    direct_motor_subscriber_gids: tuple[str, ...]
    processes: tuple[PublisherProcessIdentity, ...]
    graph_revision: str

    @classmethod
    def parse(cls, value: object, *, phase: str) -> ControlGraphSnapshot:
        if not isinstance(value, Mapping) or value.get("schema_version") != "rolo-n7-control-graph/v1":
            raise N7PhysicalBlocked("N7_PHYSICAL_SNAPSHOT_INVALID", "control graph receipt is invalid")
        if value.get("phase") != phase:
            raise N7PhysicalBlocked("N7_PHYSICAL_SNAPSHOT_INVALID", "control graph phase differs")
        if (
            value.get("command_route") != COMMAND_ROUTE
            or value.get("competing_command_route") != COMPETING_COMMAND_ROUTE
            or value.get("direct_motor_route") != DIRECT_MOTOR_ROUTE
            or value.get("command_interface") != COMMAND_INTERFACE
        ):
            raise N7PhysicalBlocked("N7_PHYSICAL_ROUTE_IDENTITY_MISMATCH", "control route identity differs")
        raw_processes = value.get("processes")
        if not isinstance(raw_processes, list) or len(raw_processes) > len(PUBLISHER_PROCESS_ALLOWLIST):
            raise N7PhysicalBlocked("N7_PHYSICAL_PROCESS_IDENTITY_INVALID", "process set is invalid")
        processes = tuple(sorted((PublisherProcessIdentity.parse(item) for item in raw_processes), key=lambda item: item.node_id))
        if len({item.node_id for item in processes}) != len(processes):
            raise N7PhysicalBlocked("N7_PHYSICAL_PROCESS_IDENTITY_INVALID", "process node identity is duplicated")
        revision = value.get("graph_revision")
        if not isinstance(revision, str) or _SHA256.fullmatch(revision) is None:
            raise N7PhysicalBlocked("N7_PHYSICAL_SNAPSHOT_INVALID", "graph revision is invalid")
        command_publishers, command_publisher_gids = _safe_endpoint_pairs(
            value.get("command_publishers"),
            value.get("command_publisher_gids"),
            identities_label="command_publishers",
            gids_label="command_publisher_gids",
        )
        command_subscribers, command_subscriber_gids = _safe_endpoint_pairs(
            value.get("command_subscribers"),
            value.get("command_subscriber_gids"),
            identities_label="command_subscribers",
            gids_label="command_subscriber_gids",
        )
        competing_publishers, competing_publisher_gids = _safe_endpoint_pairs(
            value.get("competing_publishers"),
            value.get("competing_publisher_gids"),
            identities_label="competing_publishers",
            gids_label="competing_publisher_gids",
        )
        competing_subscribers, competing_subscriber_gids = _safe_endpoint_pairs(
            value.get("competing_subscribers"),
            value.get("competing_subscriber_gids"),
            identities_label="competing_subscribers",
            gids_label="competing_subscriber_gids",
        )
        direct_motor_publishers, direct_motor_publisher_gids = _safe_endpoint_pairs(
            value.get("direct_motor_publishers"),
            value.get("direct_motor_publisher_gids"),
            identities_label="direct_motor_publishers",
            gids_label="direct_motor_publisher_gids",
        )
        direct_motor_subscribers, direct_motor_subscriber_gids = _safe_endpoint_pairs(
            value.get("direct_motor_subscribers"),
            value.get("direct_motor_subscriber_gids"),
            identities_label="direct_motor_subscribers",
            gids_label="direct_motor_subscriber_gids",
        )
        all_gids = (
            *command_publisher_gids,
            *command_subscriber_gids,
            *competing_publisher_gids,
            *competing_subscriber_gids,
            *direct_motor_publisher_gids,
            *direct_motor_subscriber_gids,
        )
        if len(all_gids) != len(set(all_gids)):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_SNAPSHOT_INVALID",
                "ROS endpoint GIDs are not globally unique",
            )
        return cls(
            phase=phase,
            observed_at=_parse_time(value.get("observed_at"), label="observed_at"),
            command_publishers=command_publishers,
            command_publisher_gids=command_publisher_gids,
            command_subscribers=command_subscribers,
            command_subscriber_gids=command_subscriber_gids,
            competing_publishers=competing_publishers,
            competing_publisher_gids=competing_publisher_gids,
            competing_subscribers=competing_subscribers,
            competing_subscriber_gids=competing_subscriber_gids,
            direct_motor_publishers=direct_motor_publishers,
            direct_motor_publisher_gids=direct_motor_publisher_gids,
            direct_motor_subscribers=direct_motor_subscribers,
            direct_motor_subscriber_gids=direct_motor_subscriber_gids,
            processes=processes,
            graph_revision=revision,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "rolo-n7-control-graph/v1",
            "phase": self.phase,
            "observed_at": self.observed_at,
            "command_route": COMMAND_ROUTE,
            "command_interface": COMMAND_INTERFACE,
            "command_publishers": list(self.command_publishers),
            "command_publisher_gids": list(self.command_publisher_gids),
            "command_subscribers": list(self.command_subscribers),
            "command_subscriber_gids": list(self.command_subscriber_gids),
            "competing_command_route": COMPETING_COMMAND_ROUTE,
            "competing_publishers": list(self.competing_publishers),
            "competing_publisher_gids": list(self.competing_publisher_gids),
            "competing_subscribers": list(self.competing_subscribers),
            "competing_subscriber_gids": list(self.competing_subscriber_gids),
            "direct_motor_route": DIRECT_MOTOR_ROUTE,
            "direct_motor_publishers": list(self.direct_motor_publishers),
            "direct_motor_publisher_gids": list(self.direct_motor_publisher_gids),
            "direct_motor_subscribers": list(self.direct_motor_subscribers),
            "direct_motor_subscriber_gids": list(self.direct_motor_subscriber_gids),
            "processes": [item.as_dict() for item in self.processes],
            "graph_revision": self.graph_revision,
        }

    def require_baseline(self) -> None:
        expected_nodes = tuple(sorted(PUBLISHER_PROCESS_ALLOWLIST))
        actual_nodes = tuple(item.node_id for item in self.processes)
        if (
            self.command_publishers != ()
            or self.command_subscribers != CONTROLLED_SUBSCRIBERS
            or self.competing_publishers != BASELINE_COMPETING_PUBLISHERS
            or self.competing_subscribers != COMPETING_SUBSCRIBERS
            or self.direct_motor_publishers != BASELINE_DIRECT_MOTOR_PUBLISHERS
            or self.direct_motor_subscribers != DIRECT_MOTOR_SUBSCRIBERS
            or actual_nodes != expected_nodes
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_BASELINE_TOPOLOGY_MISMATCH",
                "live publisher graph or exact process allowlist differs from the accepted LanderPi baseline",
            )

    def require_isolated(self) -> None:
        if (
            self.command_publishers != ()
            or self.command_subscribers != CONTROLLED_SUBSCRIBERS
            or self.competing_publishers != ()
            or self.competing_subscribers != COMPETING_SUBSCRIBERS
            or self.direct_motor_publishers != ISOLATED_DIRECT_MOTOR_PUBLISHERS
            or self.direct_motor_subscribers != DIRECT_MOTOR_SUBSCRIBERS
            or self.processes != ()
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_CONTROL_GRAPH_NOT_ISOLATED",
                "the provider boundary is not isolated from competing command publishers",
            )

    def require_prearmed(self) -> None:
        """Require one dormant Rolo publisher and no competing source."""

        if (
            self.command_publishers != (ROLO_PUBLISHER,)
            or self.command_subscribers != CONTROLLED_SUBSCRIBERS
            or self.competing_publishers != ()
            or self.competing_subscribers != COMPETING_SUBSCRIBERS
            or self.direct_motor_publishers != ISOLATED_DIRECT_MOTOR_PUBLISHERS
            or self.direct_motor_subscribers != DIRECT_MOTOR_SUBSCRIBERS
            or self.processes != ()
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PREARM_TOPOLOGY_INVALID",
                "pre-arm must expose exactly one dormant Rolo publisher and no competing source",
            )

    def topology_digest(self) -> str:
        return _control_topology_digest(self.as_dict())


def target_compatible_graph_revision(
    snapshot: ControlGraphSnapshot,
    *,
    target_id: str,
    target_identity: str,
    direct_motor_interface: str = DIRECT_MOTOR_INTERFACE,
) -> str:
    """Project a runner graph into the target's stable revision domain.

    ``ControlGraphSnapshot.graph_revision`` also binds observation time,
    phase, and process identities.  The Pi target deliberately uses a
    different, stable digest over three typed ROS endpoint snapshots.  This
    helper prevents a caller from comparing those two unrelated digests at
    finalization.
    """

    if not isinstance(snapshot, ControlGraphSnapshot):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_SNAPSHOT_INVALID",
            "target graph revision requires a parsed control snapshot",
        )

    def topic(
        route: str,
        interface: str,
        publisher_identities: tuple[str, ...],
        publisher_gids: tuple[str, ...],
        subscriber_identities: tuple[str, ...],
        subscriber_gids: tuple[str, ...],
    ) -> Ros2TopicEndpointSnapshot:
        return Ros2TopicEndpointSnapshot(
            route=route,
            interface=interface,
            publisher_count=len(publisher_identities),
            publisher_identities=publisher_identities,
            publisher_gids=publisher_gids,
            subscriber_count=len(subscriber_identities),
            subscriber_identities=subscriber_identities,
            subscriber_gids=subscriber_gids,
        )

    topics = (
        topic(
            COMMAND_ROUTE,
            COMMAND_INTERFACE,
            snapshot.command_publishers,
            snapshot.command_publisher_gids,
            snapshot.command_subscribers,
            snapshot.command_subscriber_gids,
        ),
        topic(
            COMPETING_COMMAND_ROUTE,
            COMMAND_INTERFACE,
            snapshot.competing_publishers,
            snapshot.competing_publisher_gids,
            snapshot.competing_subscribers,
            snapshot.competing_subscriber_gids,
        ),
        topic(
            DIRECT_MOTOR_ROUTE,
            direct_motor_interface,
            snapshot.direct_motor_publishers,
            snapshot.direct_motor_publisher_gids,
            snapshot.direct_motor_subscribers,
            snapshot.direct_motor_subscriber_gids,
        ),
    )
    return compute_motion_payload_digest(
        {
            "schema_version": "rolo-landerpi-drive-graph-revision/v1",
            "target_id": target_id,
            "target_identity": target_identity,
            "topics": [item.model_dump(mode="python") for item in topics],
        }
    )


def _control_topology_digest(snapshot: Mapping[str, Any]) -> str:
    fields = (
        "command_route",
        "command_interface",
        "command_publishers",
        "command_publisher_gids",
        "command_subscribers",
        "command_subscriber_gids",
        "competing_command_route",
        "competing_publishers",
        "competing_publisher_gids",
        "competing_subscribers",
        "competing_subscriber_gids",
        "direct_motor_route",
        "direct_motor_publishers",
        "direct_motor_publisher_gids",
        "direct_motor_subscribers",
        "direct_motor_subscriber_gids",
        "processes",
    )
    if any(field not in snapshot for field in fields):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_SNAPSHOT_INVALID",
            "control topology digest input is incomplete",
        )
    return _digest({field: snapshot[field] for field in fields})


@dataclass(frozen=True)
class SensorTopicHealth:
    route: str
    interface: str
    publisher_identities: tuple[str, ...]
    publisher_gids: tuple[str, ...]
    sample_count: int
    first_sample_at: datetime | None
    last_sample_at: datetime | None
    sample_rate_hz: float
    max_gap_s: float | None
    last_sample_age_s: float | None
    arrival_digest: str

    @classmethod
    def parse(cls, value: object) -> SensorTopicHealth:
        expected = {
            "route",
            "interface",
            "publisher_identities",
            "publisher_gids",
            "sample_count",
            "first_sample_at",
            "last_sample_at",
            "sample_rate_hz",
            "max_gap_s",
            "last_sample_age_s",
            "arrival_digest",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_SENSOR_HEALTH_INVALID",
                "sensor health topic record has an invalid shape",
            )
        route = value.get("route")
        interface = value.get("interface")
        identities, gids = _safe_endpoint_pairs(
            value.get("publisher_identities"),
            value.get("publisher_gids"),
            identities_label="sensor publisher identities",
            gids_label="sensor publisher gids",
        )
        count = value.get("sample_count")
        rate = value.get("sample_rate_hz")
        max_gap = value.get("max_gap_s")
        last_age = value.get("last_sample_age_s")
        first = value.get("first_sample_at")
        last = value.get("last_sample_at")
        if (
            route not in SENSOR_HEALTH_ROUTES
            or interface != SENSOR_HEALTH_ROUTES.get(str(route))
            or ROLO_PUBLISHER in identities
            or isinstance(count, bool)
            or not isinstance(count, int)
            or not 0 <= count <= 100_000
            or isinstance(rate, bool)
            or not isinstance(rate, (int, float))
            or not math.isfinite(float(rate))
            or not 0 <= float(rate) <= 10_000
            or not isinstance(value.get("arrival_digest"), str)
            or _SHA256.fullmatch(str(value.get("arrival_digest"))) is None
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_SENSOR_HEALTH_INVALID",
                "sensor health topic identity or metrics are invalid",
            )
        if count == 0:
            if first is not None or last is not None or float(rate) != 0 or max_gap is not None or last_age is not None:
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_SENSOR_HEALTH_INVALID",
                    "empty sensor stream retained sample metrics",
                )
            parsed_first = parsed_last = None
        else:
            parsed_first = _parse_time(first, label="sensor first_sample_at")
            parsed_last = _parse_time(last, label="sensor last_sample_at")
            if parsed_last < parsed_first:
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_SENSOR_HEALTH_INVALID",
                    "sensor sample timestamps are reversed",
                )
            for number in (max_gap, last_age):
                if isinstance(number, bool) or not isinstance(number, (int, float)) or not math.isfinite(float(number)) or float(number) < 0:
                    raise N7PhysicalBlocked(
                        "N7_PHYSICAL_SENSOR_HEALTH_INVALID",
                        "sensor sample gap or age is invalid",
                    )
            if count == 1 and (float(rate) != 0 or float(max_gap) != 0):
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_SENSOR_HEALTH_INVALID",
                    "single sensor sample has an impossible rate",
                )
        return cls(
            route=str(route),
            interface=str(interface),
            publisher_identities=identities,
            publisher_gids=gids,
            sample_count=count,
            first_sample_at=parsed_first,
            last_sample_at=parsed_last,
            sample_rate_hz=float(rate),
            max_gap_s=None if max_gap is None else float(max_gap),
            last_sample_age_s=None if last_age is None else float(last_age),
            arrival_digest=str(value["arrival_digest"]),
        )

    @property
    def healthy(self) -> bool:
        return (
            bool(self.publisher_identities)
            and self.sample_count >= SENSOR_MIN_SAMPLE_COUNT
            and math.isfinite(self.sample_rate_hz)
            and self.sample_rate_hz >= SENSOR_MIN_RATE_HZ
            and self.sample_rate_hz <= 10_000
            and self.max_gap_s is not None
            and math.isfinite(self.max_gap_s)
            and 0 <= self.max_gap_s <= 5.25
            and self.last_sample_age_s is not None
            and math.isfinite(self.last_sample_age_s)
            and 0 <= self.last_sample_age_s <= SENSOR_MAX_SAMPLE_AGE_S
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "route": self.route,
            "interface": self.interface,
            "publisher_identities": list(self.publisher_identities),
            "publisher_gids": list(self.publisher_gids),
            "sample_count": self.sample_count,
            "first_sample_at": self.first_sample_at,
            "last_sample_at": self.last_sample_at,
            "sample_rate_hz": self.sample_rate_hz,
            "max_gap_s": self.max_gap_s,
            "last_sample_age_s": self.last_sample_age_s,
            "arrival_digest": self.arrival_digest,
        }


@dataclass(frozen=True)
class FreshSensorHealthReceipt:
    phase: Literal["BASELINE", "PREARMED"]
    stage_root: str
    window_started_at: datetime
    window_ended_at: datetime
    sample_window_s: float
    graph_topology_digest: str
    pre_sample_graph_revision: str
    post_sample_graph_revision: str
    topics: tuple[SensorTopicHealth, ...]
    healthy: bool
    evidence_digest: str

    @classmethod
    def parse(
        cls,
        value: object,
        *,
        phase: Literal["BASELINE", "PREARMED"],
        stage_root: str,
        graph_topology_digest: str,
    ) -> FreshSensorHealthReceipt:
        expected = {
            "schema_version",
            "ok",
            "phase",
            "stage_root",
            "window_started_at",
            "window_ended_at",
            "sample_window_s",
            "graph_topology_digest",
            "pre_sample_graph_revision",
            "post_sample_graph_revision",
            "topics",
            "healthy",
            "evidence_digest",
        }
        if (
            not isinstance(value, Mapping)
            or set(value) != expected
            or value.get("schema_version") != "rolo-n7-fresh-sensor-health/v1"
            or value.get("ok") is not True
            or value.get("phase") != phase
            or value.get("stage_root") != stage_root
            or value.get("graph_topology_digest") != graph_topology_digest
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_SENSOR_HEALTH_INVALID",
                "fresh sensor health receipt is not bound to this graph snapshot",
            )
        started = _parse_time(value.get("window_started_at"), label="sensor window_started_at")
        ended = _parse_time(value.get("window_ended_at"), label="sensor window_ended_at")
        window = value.get("sample_window_s")
        raw_topics = value.get("topics")
        if (
            ended <= started
            or isinstance(window, bool)
            or not isinstance(window, (int, float))
            or not math.isfinite(float(window))
            or not 0.5 <= float(window) <= 5.0
            or abs((ended - started).total_seconds() - float(window)) > 0.25
            or not isinstance(raw_topics, list)
            or len(raw_topics) != len(SENSOR_HEALTH_ROUTES)
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_SENSOR_HEALTH_INVALID",
                "fresh sensor sampling window is invalid",
            )
        topics = tuple(SensorTopicHealth.parse(item) for item in raw_topics)
        if tuple(item.route for item in topics) != tuple(SENSOR_HEALTH_ROUTES):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_SENSOR_HEALTH_INVALID",
                "fresh sensor routes are incomplete or reordered",
            )
        all_gids = tuple(gid for item in topics for gid in item.publisher_gids)
        for topic in topics:
            if topic.sample_count == 0:
                continue
            if (
                topic.first_sample_at is None
                or topic.last_sample_at is None
                or topic.last_sample_age_s is None
                or topic.max_gap_s is None
                or not (
                    started
                    <= topic.first_sample_at
                    <= topic.last_sample_at
                    <= ended
                )
                or abs(
                    (ended - topic.last_sample_at).total_seconds()
                    - topic.last_sample_age_s
                )
                > 0.25
                or topic.max_gap_s > float(window) + 0.25
            ):
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_SENSOR_HEALTH_INVALID",
                    "sensor samples are not bound to the monotonic sampling window",
                )
        revisions = (
            value.get("pre_sample_graph_revision"),
            value.get("post_sample_graph_revision"),
        )
        derived_health = all(item.healthy for item in topics)
        if (
            len(all_gids) != len(set(all_gids))
            or any(not isinstance(item, str) or _SHA256.fullmatch(item) is None for item in revisions)
            or value.get("healthy") is not derived_health
            or not isinstance(value.get("evidence_digest"), str)
            or _SHA256.fullmatch(str(value.get("evidence_digest"))) is None
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_SENSOR_HEALTH_INVALID",
                "fresh sensor health evidence is internally inconsistent",
            )
        receipt = cls(
            phase=phase,
            stage_root=stage_root,
            window_started_at=started,
            window_ended_at=ended,
            sample_window_s=float(window),
            graph_topology_digest=graph_topology_digest,
            pre_sample_graph_revision=str(revisions[0]),
            post_sample_graph_revision=str(revisions[1]),
            topics=topics,
            healthy=derived_health,
            evidence_digest=str(value["evidence_digest"]),
        )
        if receipt.evidence_digest != _digest(receipt._unsigned_payload()):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_SENSOR_HEALTH_INVALID",
                "fresh sensor health evidence digest does not verify",
            )
        return receipt

    def _unsigned_payload(self) -> dict[str, Any]:
        return {
            "schema_version": "rolo-n7-fresh-sensor-health/v1",
            "ok": True,
            "phase": self.phase,
            "stage_root": self.stage_root,
            "window_started_at": self.window_started_at,
            "window_ended_at": self.window_ended_at,
            "sample_window_s": self.sample_window_s,
            "graph_topology_digest": self.graph_topology_digest,
            "pre_sample_graph_revision": self.pre_sample_graph_revision,
            "post_sample_graph_revision": self.post_sample_graph_revision,
            "topics": [item.as_dict() for item in self.topics],
            "healthy": self.healthy,
        }

    def as_dict(self) -> dict[str, Any]:
        return {**self._unsigned_payload(), "evidence_digest": self.evidence_digest}

    def require_healthy(self) -> None:
        if not self.healthy:
            missing = ",".join(item.route for item in self.topics if not item.healthy)
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_SENSOR_STREAMS_NOT_FRESH",
                f"required target sensor streams are not fresh: {missing}",
            )


class LanderPiControlChannel(Protocol):
    channel_id: str

    def stage(self, *, run_id: str, stage_root: str) -> Mapping[str, Any]: ...

    def snapshot(self, *, stage_root: str, phase: str) -> Mapping[str, Any]: ...

    def sample_health(
        self,
        *,
        stage_root: str,
        phase: Literal["BASELINE", "PREARMED"],
        graph_topology_digest: str,
    ) -> Mapping[str, Any]: ...

    def restart_bringup_once(
        self,
        *,
        stage_root: str,
        expected_processes: tuple[PublisherProcessIdentity, ...],
    ) -> Mapping[str, Any]: ...

    def isolate(
        self,
        *,
        stage_root: str,
        expected_processes: tuple[PublisherProcessIdentity, ...],
    ) -> Mapping[str, Any]: ...

    def restore(self, *, stage_root: str) -> Mapping[str, Any]: ...

    def cleanup(self, *, stage_root: str) -> Mapping[str, Any]: ...


class ZeroMotionAcceptanceDriver(Protocol):
    def run(self) -> PhysicalAcceptanceReceipt | Mapping[str, Any]: ...


@dataclass(frozen=True)
class TraceAttempt:
    """Sanitized summary from one ReleaseBoundTrace attempt or QUERY reconcile."""

    status: Literal["SUCCEEDED", "BLOCKED", "FAILED", "UNKNOWN"]
    session_id: str
    call_id: str
    call_attempt_count: int
    query_attempt_count: int
    provider_invocation_count: int
    provider_gate_consumed: bool
    provider_gate_receipt: Mapping[str, Any] | None
    controlled_publisher_identities: tuple[str, ...]
    final_zero_verified: bool
    stop_acknowledged: bool
    provider_terminated: bool
    trace_artifacts: Mapping[str, Path] = field(default_factory=dict)
    result: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        artifacts = {
            label: {
                "path": str(path.resolve()),
                "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for label, path in sorted(self.trace_artifacts.items())
            if path.is_file() and not path.is_symlink()
        }
        return {
            "schema_version": "rolo-n7-release-bound-trace-attempt/v1",
            "status": self.status,
            "session_id": self.session_id,
            "call_id": self.call_id,
            "call_attempt_count": self.call_attempt_count,
            "query_attempt_count": self.query_attempt_count,
            "provider_invocation_count": self.provider_invocation_count,
            "provider_gate_consumed": self.provider_gate_consumed,
            "provider_gate_receipt": self.provider_gate_receipt,
            "controlled_publisher_identities": list(self.controlled_publisher_identities),
            "final_zero_verified": self.final_zero_verified,
            "stop_acknowledged": self.stop_acknowledged,
            "provider_terminated": self.provider_terminated,
            "trace_artifacts": artifacts,
            "result": dict(self.result),
        }


class PhysicalTraceDriver(Protocol):
    def prepare_zero_motion(self, spec: MotionSpec) -> PrearmedProviderReceipt: ...

    def preflight_provider_gate(self, receipt: PhysicalAcceptanceReceipt) -> None: ...

    def start_once(self, receipt: PhysicalAcceptanceReceipt, spec: MotionSpec) -> TraceAttempt: ...

    def query_once(self, call_id: str) -> TraceAttempt: ...

    def stop_once(self, call_id: str) -> AuthenticatedStopReceipt: ...


@dataclass(frozen=True)
class AuthenticatedStopReceipt:
    """Target-owned proof required before vendor publishers are restored."""

    status: Literal["STOPPED", "ALREADY_TERMINAL", "UNKNOWN", "BLOCKED"]
    session_id: str
    call_id: str
    stop_request_count: int
    control_auth_verified: bool
    final_zero_verified: bool
    target_stop_acknowledged: bool
    provider_terminated: bool
    receipt_digest: str
    receipt: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def parse(cls, value: AuthenticatedStopReceipt | Mapping[str, Any]) -> AuthenticatedStopReceipt:
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise N7PhysicalBlocked("N7_PHYSICAL_STOP_RECEIPT_INVALID", "authenticated STOP receipt is missing")
        try:
            result = cls(
                status=str(value["status"]),  # type: ignore[arg-type]
                session_id=str(value["session_id"]),
                call_id=str(value["call_id"]),
                stop_request_count=value["stop_request_count"],  # type: ignore[arg-type]
                control_auth_verified=value["control_auth_verified"] is True,
                final_zero_verified=value["final_zero_verified"] is True,
                target_stop_acknowledged=value["target_stop_acknowledged"] is True,
                provider_terminated=value["provider_terminated"] is True,
                receipt_digest=str(value["receipt_digest"]),
                receipt=dict(value.get("receipt") or {}),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_STOP_RECEIPT_INVALID",
                "authenticated STOP receipt is invalid",
            ) from exc
        if (
            result.status not in {"STOPPED", "ALREADY_TERMINAL", "UNKNOWN", "BLOCKED"}
            or not _ID.fullmatch(result.session_id)
            or not _ID.fullmatch(result.call_id)
            or isinstance(result.stop_request_count, bool)
            or result.stop_request_count != 1
            or _SHA256.fullmatch(result.receipt_digest) is None
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_STOP_RECEIPT_INVALID",
                "authenticated STOP receipt identity or request budget is invalid",
            )
        return result

    @property
    def safe_to_restore(self) -> bool:
        return (
            self.status in {"STOPPED", "ALREADY_TERMINAL"}
            and self.control_auth_verified
            and self.final_zero_verified
            and self.target_stop_acknowledged
            and self.provider_terminated
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "rolo-n7-authenticated-stop-receipt/v1",
            "status": self.status,
            "session_id": self.session_id,
            "call_id": self.call_id,
            "stop_request_count": self.stop_request_count,
            "control_auth_verified": self.control_auth_verified,
            "final_zero_verified": self.final_zero_verified,
            "target_stop_acknowledged": self.target_stop_acknowledged,
            "provider_terminated": self.provider_terminated,
            "receipt_digest": self.receipt_digest,
            "receipt": dict(self.receipt),
        }


@dataclass(frozen=True)
class PrearmedProviderReceipt:
    """Target-owned dormant worker receipt; it is not a provider START."""

    session_id: str
    call_id: str
    publisher_identities: tuple[str, ...]
    provider_invocation_count: int
    motion_command_emitted: bool
    motion_enabled: bool
    worker_lease_digest: str
    receipt_digest: str
    receipt: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def parse(cls, value: PrearmedProviderReceipt | Mapping[str, Any]) -> PrearmedProviderReceipt:
        if isinstance(value, cls):
            result = value
        elif isinstance(value, Mapping):
            try:
                publishers = value["publisher_identities"]
                if not isinstance(publishers, (list, tuple)):
                    raise TypeError
                result = cls(
                    session_id=str(value["session_id"]),
                    call_id=str(value["call_id"]),
                    publisher_identities=tuple(str(item) for item in publishers),
                    provider_invocation_count=value["provider_invocation_count"],  # type: ignore[arg-type]
                    motion_command_emitted=value["motion_command_emitted"] is True,
                    motion_enabled=value["motion_enabled"] is True,
                    worker_lease_digest=str(value["worker_lease_digest"]),
                    receipt_digest=str(value["receipt_digest"]),
                    receipt=dict(value.get("receipt") or {}),
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_PREARM_RECEIPT_INVALID",
                    "pre-arm receipt is invalid",
                ) from exc
        else:
            raise N7PhysicalBlocked("N7_PHYSICAL_PREARM_RECEIPT_INVALID", "pre-arm receipt is missing")
        if (
            _ID.fullmatch(result.session_id) is None
            or _ID.fullmatch(result.call_id) is None
            or result.publisher_identities != (ROLO_PUBLISHER,)
            or isinstance(result.provider_invocation_count, bool)
            or result.provider_invocation_count != 0
            or result.motion_command_emitted
            or result.motion_enabled
            or _SHA256.fullmatch(result.worker_lease_digest) is None
            or _SHA256.fullmatch(result.receipt_digest) is None
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PREARM_RECEIPT_INVALID",
                "pre-arm receipt does not prove a dormant, zero-provider worker",
            )
        return result

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "rolo-n7-prearmed-provider-receipt/v1",
            "session_id": self.session_id,
            "call_id": self.call_id,
            "publisher_identities": list(self.publisher_identities),
            "provider_invocation_count": self.provider_invocation_count,
            "motion_command_emitted": self.motion_command_emitted,
            "motion_enabled": self.motion_enabled,
            "worker_lease_digest": self.worker_lease_digest,
            "receipt_digest": self.receipt_digest,
            "receipt": dict(self.receipt),
        }

    @classmethod
    def from_armed_zero(
        cls,
        armed: PhysicalWorkerArmedZero,
        *,
        request: ExecutionRequestV3,
        expected_runtime_sha256: str,
    ) -> PrearmedProviderReceipt:
        """Bind the authenticated worker ARM receipt to one exact v3 call."""

        if not isinstance(armed, PhysicalWorkerArmedZero):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PREARM_RECEIPT_INVALID",
                "production pre-arm must return PhysicalWorkerArmedZero",
            )
        call_key = WorkerCallKey.from_request(request)
        try:
            parsed = parse_physical_worker_armed_zero(
                armed.as_dict(),
                expected_call_key_digest=call_key.digest(),
                expected_request_digest=request.request_digest(),
                expected_execution_subject_digest=request.execution_subject_digest,
                expected_runtime_sha256=expected_runtime_sha256,
                expected_target_id=request.target_id,
                expected_call_id=request.idempotency_key,
                expected_session_id=request.session_id,
            )
        except Exception as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PREARM_RECEIPT_INVALID",
                "authenticated worker ARM receipt failed strict runtime, digest, and identity validation",
            ) from exc
        if (
            parsed != armed
            or armed.call_key_digest != call_key.digest()
            or armed.request_digest != request.request_digest()
            or armed.execution_subject_digest != request.execution_subject_digest
            or armed.command_endpoint != COMMAND_ROUTE
            or armed.publisher_identity != ROLO_PUBLISHER
            or len(armed.publisher_endpoint_gids) != 1
            or _ENDPOINT_GID.fullmatch(armed.publisher_endpoint_gids[0]) is None
            or armed.competing_publisher_count != 0
            or armed.direct_motor_publisher_identities != ISOLATED_DIRECT_MOTOR_PUBLISHERS
            or armed.zeros_published < 5
            or re.fullmatch(r"[0-9a-f]{64}", armed.arm_receipt_digest) is None
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PREARM_RECEIPT_INVALID",
                "authenticated worker ARM proof differs from the exact v3 call or graph",
            )
        return cls(
            session_id=request.session_id,
            call_id=request.idempotency_key,
            publisher_identities=(armed.publisher_identity,),
            provider_invocation_count=0,
            motion_command_emitted=False,
            motion_enabled=False,
            worker_lease_digest="sha256:" + call_key.digest(),
            receipt_digest="sha256:" + armed.arm_receipt_digest,
            receipt=armed.as_dict(),
        )


_PROVIDER_GATE_CHALLENGE_CLAIMS = frozenset(
    {
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
        "armed_zero_provider_binding",
        "last_command_is_zero",
        "motor_output_zero",
        "motors_stopped",
        "zero_velocity_verified",
        "fresh_zero_evidence_digest",
        "fresh_zero_evidence",
    }
)
_PROVIDER_GATE_CONSUMED_CLAIMS = frozenset(
    {
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
        "armed_zero_provider_binding",
        "last_command_is_zero",
        "motor_output_zero",
        "motors_stopped",
        "zero_velocity_verified",
        "fresh_zero_evidence_digest",
        "fresh_zero_evidence",
    }
)
_DEBUG_GATE_BINDING_CLAIMS = frozenset(
    {
        "debug_admission_digest",
        "debug_attestation_artifact_digest",
        "basis_digest",
        "requested_rotation_degrees",
        "requested_linear_meters",
        "max_abs_rotation_degrees",
        "max_abs_linear_meters",
        "production_authority_verified",
        "fresh_estop_challenge_verified",
        "production_ready",
        "report_status",
    }
)


class TargetdPhysicalProofVerifier:
    """Re-read and cryptographically bind all target-owned physical proofs.

    The callbacks are read/transport seams only.  They return strict targetd
    models; booleans supplied by a composition callback are never accepted as
    proof of provider-gate consumption, terminal motion, or STOP.
    """

    typed_targetd_physical_proof_verifier = True

    def __init__(
        self,
        request: ExecutionRequestV3,
        *,
        manifest: ExecutionBundleManifest,
        manifest_verification_key: bytes,
        trust_store: MotionSafetyTrustStore,
        target_authority_id: str,
        query_physical_remote: Callable[
            [str, str, str | None, str | None], TargetdTraceResponse
        ],
        load_lease: Callable[[WorkerCallKey], WorkerLeaseRecord | None],
        stop_remote: Callable[[str, str], TargetdTraceResponse],
        stop_query_budget: int = 3,
        stop_poll_interval_s: float = 0.3,
        stop_poll_sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        try:
            self.request = ExecutionRequestV3.model_validate(
                request.model_dump(mode="python")
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("physical proof verifier requires ExecutionRequestV3") from exc
        try:
            self.manifest = ExecutionBundleManifest.model_validate(
                manifest.model_dump(mode="python")
            )
            self.manifest.verify_signature(manifest_verification_key)
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("physical proof verifier manifest is not signed and valid") from exc
        runtime_sha256 = self.manifest.observation_contract.get(
            "provider_runtime_sha256"
        )
        if (
            self.manifest.bundle_digest != self.request.bundle_digest
            or self.manifest.binding_digest != self.request.binding_digest
            or self.manifest.tool_id != TOOL_ID
            or not isinstance(runtime_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", runtime_sha256) is None
        ):
            raise ValueError("physical proof verifier manifest/request identity differs")
        if not isinstance(trust_store, MotionSafetyTrustStore):
            raise ValueError("physical proof verifier trust store is invalid")
        if not isinstance(target_authority_id, str) or not 1 <= len(target_authority_id) <= 256:
            raise ValueError("physical proof verifier target authority is invalid")
        if any(
            not callable(value)
            for value in (query_physical_remote, load_lease, stop_remote)
        ):
            raise ValueError("physical proof verifier I/O seams must be callable")
        if (
            isinstance(stop_query_budget, bool)
            or not isinstance(stop_query_budget, int)
            or not 0 <= stop_query_budget <= 8
        ):
            raise ValueError("physical STOP query budget must be between zero and eight")
        if (
            isinstance(stop_poll_interval_s, bool)
            or not isinstance(stop_poll_interval_s, (int, float))
            or not math.isfinite(float(stop_poll_interval_s))
            or not 0.05 <= float(stop_poll_interval_s) <= 2.0
            or not callable(stop_poll_sleeper)
        ):
            raise ValueError(
                "physical STOP poll interval must be finite and between 0.05 and 2 seconds"
            )
        self.trust_store = trust_store
        self.target_authority_id = target_authority_id
        self.runtime_sha256 = runtime_sha256
        self.query_physical_remote = query_physical_remote
        self.load_lease = load_lease
        self.stop_remote = stop_remote
        self.stop_query_budget = stop_query_budget
        self.stop_poll_interval_s = float(stop_poll_interval_s)
        self.stop_poll_sleeper = stop_poll_sleeper
        self.call_key = WorkerCallKey.from_request(self.request)
        # Set only after the complete typed terminal proof has passed.  Host
        # finalization must never be authorized from a status flag or an
        # unverified transport response.
        self.latest_terminal_receipt: TargetdCallReceipt | None = None

    def verify_trace(
        self,
        session: Any,
        paths: Mapping[str, Path],
        *,
        acceptance: PhysicalAcceptanceReceipt,
        armed_zero: PhysicalWorkerArmedZero,
        query_count: int,
    ) -> TraceAttempt:
        """Verify a Trace snapshot and fresh target stores without trusting result flags."""

        self._require_armed_zero(armed_zero)
        state = self._session_state(session)
        session_id = str(getattr(session, "session_id", ""))
        if session_id != self.request.session_id:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TRACE_IDENTITY_MISMATCH",
                "Trace session differs from the signed physical request",
            )
        sidecar = self._load_trace_sidecar(paths)
        if sidecar is None:
            if state != "UNKNOWN":
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_TRACE_RECEIPT_MISSING",
                    "terminal Trace has no immutable targetd receipt sidecar",
                )
            return TraceAttempt(
                status="UNKNOWN",
                session_id=session_id,
                call_id=self.request.idempotency_key,
                call_attempt_count=1,
                query_attempt_count=query_count,
                provider_invocation_count=0,
                provider_gate_consumed=False,
                provider_gate_receipt=None,
                controlled_publisher_identities=(),
                final_zero_verified=False,
                stop_acknowledged=False,
                provider_terminated=False,
                trace_artifacts=dict(paths),
                result={},
            )
        receipt = sidecar.receipt
        self._require_receipt_identity(receipt)
        self._require_trace_plan(paths, sidecar)
        expected_statuses = {
            "COMPLETED": {"SUCCEEDED"},
            "BLOCKED": {"FAILED", "NOT_ACCEPTED"},
            "CANCELLED": {"CANCELLED"},
            "STOPPED": {"STOPPED"},
            "UNKNOWN": {"UNKNOWN"},
        }.get(state)
        if expected_statuses is not None and receipt.status not in expected_statuses:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TRACE_RECEIPT_STATUS_MISMATCH",
                "Trace state differs from the exact targetd receipt",
            )
        result = dict(receipt.result or {})
        gate_reference: PhysicalProviderGateReference | None = None
        if receipt.evidence_refs:
            if len(receipt.evidence_refs) != 2:
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_PROVIDER_GATE_REFERENCE_INVALID",
                    "targetd receipt does not carry the exact gate artifact pair",
                )
            gate_reference = self._query_gate_reference(
                receipt,
                gate_uri=receipt.evidence_refs[0],
                gate_digest_uri=receipt.evidence_refs[1],
            )
            self._verify_gate_reference(
                gate_reference,
                receipt,
                acceptance,
                armed_zero,
            )
        elif receipt.status not in {"NOT_ACCEPTED", "UNKNOWN"}:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PROVIDER_GATE_REFERENCE_MISSING",
                "started physical receipt has no durable provider-gate sidecar",
            )

        lease = self._load_exact_lease(required=gate_reference is not None)
        provider_count = self._verified_provider_count(result, gate_reference)
        final_zero, stop_acknowledged, provider_terminated = self._verify_terminal_result(
            receipt,
            lease,
            result,
            armed_zero,
        )
        if (
            receipt.status in {"SUCCEEDED", "FAILED", "STOPPED", "CANCELLED"}
            and final_zero
            and stop_acknowledged
            and provider_terminated
        ):
            self.latest_terminal_receipt = receipt
        status = {
            "SUCCEEDED": "SUCCEEDED",
            "NOT_ACCEPTED": "BLOCKED",
            "UNKNOWN": "UNKNOWN",
        }.get(receipt.status, "FAILED")
        return TraceAttempt(
            status=status,  # type: ignore[arg-type]
            session_id=session_id,
            call_id=self.request.idempotency_key,
            call_attempt_count=1,
            query_attempt_count=query_count,
            provider_invocation_count=provider_count,
            provider_gate_consumed=gate_reference is not None,
            provider_gate_receipt=(
                gate_reference.sidecar.provider_gate.model_dump(mode="python")
                if gate_reference is not None
                else None
            ),
            controlled_publisher_identities=(
                (ROLO_PUBLISHER,) if gate_reference is not None else ()
            ),
            final_zero_verified=final_zero,
            stop_acknowledged=stop_acknowledged,
            provider_terminated=provider_terminated,
            trace_artifacts=dict(paths),
            result=result,
        )

    def authenticated_stop(self, call_id: str) -> AuthenticatedStopReceipt:
        """Issue exactly one authenticated STOP, then only bounded QUERY_CALL reads."""

        if call_id != self.request.idempotency_key:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_STOP_IDENTITY_INVALID",
                "STOP call id differs from the signed physical request",
            )
        response = self.stop_remote(call_id, self.request.request_digest())
        receipt, interrupt_disposition = self._parse_control_response(
            response,
            expected_kind=FrameKind.STOP,
        )
        query_count = 0
        while receipt.status not in {"STOPPED", "SUCCEEDED", "FAILED", "CANCELLED"}:
            if query_count >= self.stop_query_budget:
                return self._unsafe_stop_receipt(receipt, query_count=query_count)
            # The physical worker publishes final zero and reconciles its
            # inner process asynchronously.  Never hammer an immediate QUERY
            # loop: wait once before every bounded observational read.
            self.stop_poll_sleeper(self.stop_poll_interval_s)
            query_count += 1
            receipt, _ = self._parse_control_response(
                self.query_physical_remote(
                    call_id,
                    self.request.request_digest(),
                    None,
                    None,
                ),
                expected_kind=FrameKind.QUERY_CALL,
            )
        lease = self._load_exact_lease(required=True)
        result = dict(receipt.result or {})
        stopped = receipt.status == "STOPPED"
        acknowledgement = lease.stop_acknowledgement if lease is not None else None
        if interrupt_disposition == "ALREADY_TERMINAL":
            try:
                armed_zero = parse_physical_worker_armed_zero(
                    lease.armed_zero if lease is not None else None,
                    expected_call_key_digest=self.call_key.digest(),
                    expected_request_digest=self.request.request_digest(),
                    expected_execution_subject_digest=(
                        self.request.execution_subject_digest
                    ),
                    expected_runtime_sha256=self.runtime_sha256,
                    expected_target_id=self.request.target_id,
                    expected_call_id=self.request.idempotency_key,
                    expected_session_id=self.request.session_id,
                )
                self._require_armed_zero(armed_zero)
                final_zero, stop_acknowledged, provider_terminated = (
                    self._verify_terminal_result(
                        receipt,
                        lease,
                        result,
                        armed_zero,
                    )
                )
            except N7PhysicalBlocked:
                raise
            except Exception as exc:
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_ALREADY_TERMINAL_PROOF_INVALID",
                    "already-terminal STOP lacks the exact durable worker proof",
                ) from exc
            target_ack = stop_acknowledged
            safe = final_zero and target_ack and provider_terminated
            safe_status = "ALREADY_TERMINAL" if safe else "UNKNOWN"
        else:
            final_zero = self._safe_stop_result(result)
            target_ack = (
                stopped
                and acknowledgement is not None
                and acknowledgement.intent == "STOP"
                and acknowledgement.call_key == self.call_key
                and acknowledgement.disposition
                in {"NOT_STARTED", "WORKER_CONFIRMED"}
            )
            provider_terminated = (
                lease is not None
                and lease.state == "STOPPED"
                and lease.finished_at is not None
                and (
                    acknowledgement is not None
                    and (
                        acknowledgement.disposition == "NOT_STARTED"
                        or self._result_proves_inner_exit(result)
                    )
                )
            )
            safe = (
                stopped
                and interrupt_disposition == "STOP_REQUESTED"
                and final_zero
                and target_ack
                and provider_terminated
            )
            safe_status = "STOPPED" if safe else "UNKNOWN"
        if safe:
            self.latest_terminal_receipt = receipt
        return AuthenticatedStopReceipt(
            status=safe_status,
            session_id=self.request.session_id,
            call_id=call_id,
            stop_request_count=1,
            control_auth_verified=(
                interrupt_disposition in {"STOP_REQUESTED", "ALREADY_TERMINAL"}
            ),
            final_zero_verified=final_zero,
            target_stop_acknowledged=target_ack,
            provider_terminated=provider_terminated,
            receipt_digest=_digest(receipt.model_dump(mode="json")),
            receipt={
                "targetd_receipt": receipt.model_dump(mode="python"),
                "worker_lease": lease.model_dump(mode="python") if lease is not None else None,
                "stop_query_count": query_count,
            },
        )

    def _unsafe_stop_receipt(
        self,
        receipt: TargetdCallReceipt,
        *,
        query_count: int,
    ) -> AuthenticatedStopReceipt:
        return AuthenticatedStopReceipt(
            status="UNKNOWN",
            session_id=self.request.session_id,
            call_id=self.request.idempotency_key,
            stop_request_count=1,
            control_auth_verified=True,
            final_zero_verified=False,
            target_stop_acknowledged=False,
            provider_terminated=False,
            receipt_digest=_digest(receipt.model_dump(mode="json")),
            receipt={
                "targetd_receipt": receipt.model_dump(mode="python"),
                "stop_query_count": query_count,
            },
        )

    def _parse_control_response(
        self,
        response: TargetdTraceResponse,
        *,
        expected_kind: FrameKind,
    ) -> tuple[TargetdCallReceipt, Literal["NONE", "STOP_REQUESTED", "ALREADY_TERMINAL"]]:
        if not isinstance(response, TargetdTraceResponse) or response.sequence_correlated is not True:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_STOP_RESPONSE_UNCORRELATED",
                "targetd STOP/QUERY response lacks sequence correlation",
            )
        try:
            frame = ProtocolFrame.model_validate(response.frame.model_dump(mode="python"))
        except (AttributeError, TypeError, ValueError) as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_STOP_RECEIPT_INVALID",
                "targetd STOP/QUERY response is invalid",
            ) from exc
        if (
            frame.kind != FrameKind.RESULT
            or frame.session_id != self.request.session_id
            or frame.run_id is not None
            or frame.payload.get("request_kind") != expected_kind.value
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_STOP_RESPONSE_IDENTITY_MISMATCH",
                "targetd STOP/QUERY response identity differs",
            )
        if frame.payload.get("ok") is not True:
            error = frame.payload.get("error")
            if (
                frame.payload.get("ok") is False
                and isinstance(error, str)
                and _TARGETD_ERROR_CODE.fullmatch(error) is not None
            ):
                raise N7PhysicalBlocked(
                    error,
                    f"targetd rejected {expected_kind.value}: {error}",
                )
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_STOP_RECEIPT_INVALID",
                "targetd STOP/QUERY error response is invalid",
            )
        try:
            receipt = TargetdCallReceipt.model_validate(frame.payload.get("receipt"))
        except (TypeError, ValueError) as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_STOP_RECEIPT_INVALID",
                "targetd STOP/QUERY receipt is invalid",
            ) from exc
        self._require_receipt_identity(receipt)
        if expected_kind == FrameKind.STOP:
            interrupt = frame.payload.get("interrupt")
            if not isinstance(interrupt, Mapping) or interrupt.get("intent") != "STOP":
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_STOP_NOT_ACCEPTED",
                    "targetd did not acknowledge the authenticated STOP request",
                )
            if (
                interrupt.get("status") == "ALREADY_TERMINAL"
                and interrupt.get("requested") is False
                and interrupt.get("acknowledged") is True
                and receipt.status in {"SUCCEEDED", "FAILED", "STOPPED", "CANCELLED"}
                and interrupt.get("lease_state") == receipt.status
            ):
                return receipt, "ALREADY_TERMINAL"
            if (
                interrupt.get("requested") is True
                and interrupt.get("lease_state") in {"STOP_REQUESTED", "STOPPED"}
            ):
                return receipt, "STOP_REQUESTED"
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_STOP_NOT_ACCEPTED",
                "targetd did not acknowledge the authenticated STOP request",
            )
        return receipt, "NONE"

    def _query_gate_reference(
        self,
        expected_receipt: TargetdCallReceipt,
        *,
        gate_uri: str,
        gate_digest_uri: str,
    ) -> PhysicalProviderGateReference:
        """Use only targetd's authenticated physical-gate read-back seam."""

        try:
            response = self.query_physical_remote(
                self.request.idempotency_key,
                self.request.request_digest(),
                gate_uri,
                gate_digest_uri,
            )
            if (
                not isinstance(response, TargetdTraceResponse)
                or response.sequence_correlated is not True
            ):
                raise ValueError("uncorrelated")
            frame = ProtocolFrame.model_validate(response.frame.model_dump(mode="python"))
            receipt = TargetdCallReceipt.model_validate(frame.payload.get("receipt"))
            raw = frame.payload.get("physical_provider_gate")
            if not isinstance(raw, Mapping) or set(raw) != {
                "uri",
                "digest_uri",
                "sidecar",
            }:
                raise ValueError("physical gate payload")
            reference = PhysicalProviderGateReference(
                uri=str(raw["uri"]),
                digest_uri=str(raw["digest_uri"]),
                sidecar=PhysicalProviderGateSidecar.model_validate(raw["sidecar"]),
            )
        except Exception as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PROVIDER_GATE_QUERY_INVALID",
                "authenticated targetd physical-gate query could not be revalidated",
            ) from exc
        if (
            frame.kind != FrameKind.RESULT
            or frame.session_id != self.request.session_id
            or frame.run_id is not None
            or frame.payload.get("request_kind") != FrameKind.QUERY_CALL.value
            or frame.payload.get("ok") is not True
            or receipt != expected_receipt
            or reference.uri != gate_uri
            or reference.digest_uri != gate_digest_uri
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PROVIDER_GATE_QUERY_IDENTITY_MISMATCH",
                "authenticated targetd gate read-back differs from the Trace receipt",
            )
        self._require_receipt_identity(receipt)
        return reference

    def _verify_gate_reference(
        self,
        reference: PhysicalProviderGateReference,
        receipt: TargetdCallReceipt,
        acceptance: PhysicalAcceptanceReceipt,
        armed_zero: PhysicalWorkerArmedZero,
    ) -> None:
        if not isinstance(reference, PhysicalProviderGateReference):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PROVIDER_GATE_SIDECAR_INVALID",
                "provider-gate resolver returned no typed durable reference",
            )
        sidecar = reference.sidecar
        gate = sidecar.provider_gate
        artifact = gate.consume_artifact
        challenge = acceptance.provider_gate
        intent = self.request.motion_safety_admission.intent
        invalid = (
            sidecar.call_key != self.call_key
            or sidecar.armed_zero != armed_zero.as_dict()
            or receipt.evidence_refs != [reference.uri, reference.digest_uri]
            or challenge is None
            or acceptance.call_id != self.request.idempotency_key
            or acceptance.session_id != self.request.session_id
            or acceptance.target_id != self.request.target_id
            or acceptance.execution_subject_digest != self.request.execution_subject_digest
            or acceptance.target_identity != intent.target_identity
            or acceptance.operator_id != intent.operator_id
            or gate.acceptance_id != acceptance.acceptance_id
            or gate.call_id != self.request.idempotency_key
            or gate.session_id != self.request.session_id
            or gate.target_id != self.request.target_id
            or gate.execution_subject_digest != self.request.execution_subject_digest
            or gate.target_identity != intent.target_identity
            or gate.operator_id != intent.operator_id
            or gate.challenge_artifact_digest != challenge.payload_sha256
            or artifact is None
            or artifact.kind != "PROVIDER_GATE_CONSUMED"
            or artifact.issuer_id != self.target_authority_id
            or challenge.issuer_id != self.target_authority_id
            or not self._verify_signature(challenge)
            or not self._verify_signature(artifact)
            or not (
                challenge.issued_at <= gate.evaluated_at < challenge.expires_at
                and artifact.issued_at <= sidecar.persisted_at < artifact.expires_at
            )
            or challenge.call_id != self.request.idempotency_key
            or challenge.session_id != self.request.session_id
            or challenge.target_id != self.request.target_id
            or challenge.execution_subject_digest
            != self.request.execution_subject_digest
            or challenge.ros_graph_digest != intent.ros_graph_digest
            or challenge.target_identity != intent.target_identity
            or challenge.operator_id != intent.operator_id
            or challenge.command_route != intent.command_route
            or challenge.command_interface != intent.command_interface
            or challenge.publisher_identity != intent.publisher_identity
            or challenge.direct_motor_route != intent.direct_motor_route
            or challenge.direct_motor_interface != intent.direct_motor_interface
            or challenge.direct_motor_publisher_identity
            != intent.direct_motor_publisher_identity
        )
        if isinstance(acceptance, DebugUserAttestedAcceptanceReceipt):
            debug_artifact = acceptance.debug_attestation_artifact
            invalid = invalid or (
                not isinstance(gate, DebugUserAttestedProviderGateReceipt)
                or gate.status != "DEBUG_CONSUMED"
                or gate.report_status
                != "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
                or gate.reasons != ()
                or gate.debug_admission_digest
                != acceptance.debug_admission_digest
                or gate.debug_provider_boundary_open is not True
                or gate.production_provider_boundary_open is not False
                or gate.production_ready is not False
                or gate.production_authority_verified is not False
                or gate.fresh_estop_challenge_verified is not False
                or gate.debug_motion_authorized is not True
                or gate.provider_invocation_limit != 1
                or gate.max_abs_rotation_degrees != 1.0
                or gate.max_abs_linear_meters != 0.03
                or debug_artifact is None
                or debug_artifact.kind != "DEBUG_USER_ATTESTED_ADMISSION"
                or debug_artifact.issuer_id != self.target_authority_id
                or debug_artifact.claims.get("debug_admission_digest")
                != acceptance.debug_admission_digest
                or debug_artifact.claims.get("production_ready") is not False
                or not self._verify_signature(debug_artifact)
            )
        else:
            invalid = invalid or (
                isinstance(gate, DebugUserAttestedProviderGateReceipt)
                or acceptance.ros_graph_digest != intent.ros_graph_digest
                or gate.ros_graph_digest != intent.ros_graph_digest
                or gate.command_route != intent.command_route
                or gate.command_interface != intent.command_interface
                or gate.publisher_identity != intent.publisher_identity
                or gate.direct_motor_route != intent.direct_motor_route
                or gate.direct_motor_interface != intent.direct_motor_interface
                or gate.direct_motor_publisher_identity
                != intent.direct_motor_publisher_identity
            )
        if invalid:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PROVIDER_GATE_SIDECAR_INVALID",
                "signed provider-gate sidecar does not bind the exact call",
            )
        challenge_claims = challenge.claims
        claims = artifact.claims
        armed_binding = armed_zero.provider_binding().model_dump(mode="json")
        expected_challenge_claims = _PROVIDER_GATE_CHALLENGE_CLAIMS
        expected_consumed_claims = _PROVIDER_GATE_CONSUMED_CLAIMS
        if isinstance(acceptance, DebugUserAttestedAcceptanceReceipt):
            expected_challenge_claims = expected_challenge_claims | {
                "debug_gate_binding"
            }
            expected_consumed_claims = expected_consumed_claims | {
                "debug_gate_binding"
            }
            debug_binding = challenge_claims.get("debug_gate_binding")
            consumed_debug_binding = claims.get("debug_gate_binding")
            debug_artifact = acceptance.debug_attestation_artifact
            if (
                not isinstance(debug_binding, Mapping)
                or frozenset(debug_binding) != _DEBUG_GATE_BINDING_CLAIMS
                or debug_artifact is None
                or debug_binding.get("debug_admission_digest")
                != acceptance.debug_admission_digest
                or debug_binding.get("debug_attestation_artifact_digest")
                != debug_artifact.payload_sha256
                or debug_binding.get("basis_digest")
                != debug_artifact.claims.get("basis_digest")
                or debug_binding.get("requested_rotation_degrees") != 1.0
                or debug_binding.get("max_abs_rotation_degrees") != 1.0
                or debug_binding.get("max_abs_linear_meters") != 0.03
                or debug_binding.get("production_authority_verified") is not False
                or debug_binding.get("fresh_estop_challenge_verified") is not False
                or debug_binding.get("production_ready") is not False
                or debug_binding.get("report_status")
                != "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
                or consumed_debug_binding != debug_binding
            ):
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_DEBUG_GATE_BINDING_INVALID",
                    "debug-only challenge does not bind the exact user attestation and motion budget",
                )
        if (
            frozenset(challenge_claims) != expected_challenge_claims
            or frozenset(claims) != expected_consumed_claims
            or challenge_claims["one_shot"] is not True
            or challenge_claims["consumed"] is not False
            or challenge_claims["motion_enabled"] is not False
            or challenge_claims["provider_invocation_count"] != 0
            or challenge_claims["armed_zero_provider_binding"] != armed_binding
            or claims["one_shot"] is not True
            or claims["consumed"] is not True
            or claims["motion_enabled"] is not False
            or claims["provider_invocation_count"] != 0
            or claims["armed_zero_provider_binding"] != armed_binding
            or claims["graph_compare_and_set"] is not True
            or claims["fence_compare_and_set"] is not True
            or claims["challenge_artifact_digest"] != challenge.payload_sha256
            or claims["consume_token_digest"] != challenge_claims["consume_token_digest"]
            or claims["expected_fence_digest"] != challenge_claims["expected_fence_digest"]
            or claims["observed_fence_digest"] != challenge_claims["expected_fence_digest"]
            or claims["expected_fence_epoch"] != challenge_claims["expected_fence_epoch"]
            or claims["observed_fence_epoch"] != challenge_claims["expected_fence_epoch"]
            or claims["expected_graph_revision"] != challenge_claims["expected_graph_revision"]
            or claims["observed_graph_revision"] != challenge_claims["expected_graph_revision"]
            or isinstance(claims["provider_fence_epoch"], bool)
            or not isinstance(claims["provider_fence_epoch"], int)
            or claims["provider_fence_epoch"] != claims["expected_fence_epoch"] + 1
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PROVIDER_GATE_CAS_INVALID",
                "provider-gate challenge/consume CAS claims differ",
            )
        self._verify_fresh_zero_claims(
            challenge_claims,
            artifact_issued_at=challenge.issued_at,
        )
        self._verify_fresh_zero_claims(
            claims,
            artifact_issued_at=artifact.issued_at,
        )
        expected_token = compute_provider_gate_consume_token_digest(
            acceptance_id=str(acceptance.acceptance_id),
            intent=intent,
            release_artifact_digest=str(challenge_claims["release_artifact_digest"]),
            post_snapshot_artifact_digest=str(challenge_claims["post_snapshot_artifact_digest"]),
            expected_fence_digest=str(challenge_claims["expected_fence_digest"]),
            expected_fence_epoch=int(challenge_claims["expected_fence_epoch"]),
            expected_graph_revision=str(challenge_claims["expected_graph_revision"]),
            expires_at=challenge.expires_at,
        )
        expected_provider_fence = compute_provider_fence_digest(
            acceptance_id=str(acceptance.acceptance_id),
            intent=intent,
            challenge_artifact_digest=challenge.payload_sha256,
            consume_token_digest=expected_token,
            live_isolation_digest=str(claims["live_isolation_digest"]),
            graph_revision=str(claims["expected_graph_revision"]),
            expected_fence_digest=str(claims["expected_fence_digest"]),
            fence_epoch=int(claims["provider_fence_epoch"]),
        )
        if (
            challenge_claims["consume_token_digest"] != expected_token
            or claims["provider_fence_digest"] != expected_provider_fence
            or (
                not isinstance(gate, DebugUserAttestedProviderGateReceipt)
                and gate.provider_fence_digest != expected_provider_fence
            )
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PROVIDER_GATE_DIGEST_MISMATCH",
                "provider-gate token or fresh fence digest does not recompute",
            )

    @staticmethod
    def _verify_fresh_zero_claims(
        claims: Mapping[str, Any],
        *,
        artifact_issued_at: datetime,
    ) -> FreshZeroMotionEvidence:
        try:
            evidence = FreshZeroMotionEvidence.model_validate(
                claims.get("fresh_zero_evidence")
            )
        except Exception as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_FRESH_ZERO_EVIDENCE_INVALID",
                "provider-gate fresh-zero evidence is invalid",
            ) from exc
        issued = artifact_issued_at.astimezone(timezone.utc)
        ended = evidence.window_ended_at.astimezone(timezone.utc)
        if (
            claims.get("last_command_is_zero") is not True
            or claims.get("motor_output_zero") is not True
            or claims.get("motors_stopped") is not True
            or claims.get("zero_velocity_verified") is not True
            or claims.get("fresh_zero_evidence_digest")
            != evidence.evidence_sha256
            or ended > issued
            or (issued - ended).total_seconds() > 2.0
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_FRESH_ZERO_EVIDENCE_INVALID",
                "provider gate is not bound to a current independent zero sample window",
            )
        return evidence

    def _verify_terminal_result(
        self,
        receipt: TargetdCallReceipt,
        lease: WorkerLeaseRecord | None,
        result: Mapping[str, Any],
        armed_zero: PhysicalWorkerArmedZero,
    ) -> tuple[bool, bool, bool]:
        if lease is None:
            return False, False, False
        if (
            lease.call_key != self.call_key
            or lease.call_key_digest != self.call_key.digest()
            or lease.state != receipt.status
            or lease.prepared_status != receipt.status
            or lease.prepared_result != dict(result)
            or lease.prepared_result_digest is None
            or lease.result_prepared_at is None
            or lease.result_committed_at is None
            or lease.finished_at is None
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_WORKER_RECEIPT_MISMATCH",
                "targetd receipt differs from the committed worker lease",
            )
        if result.get("request_digest") != self.request.request_digest() or result.get(
            "execution_subject_digest"
        ) != self.request.execution_subject_digest:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_WORKER_RESULT_IDENTITY_MISMATCH",
                "worker result differs from the signed v3 request",
            )
        if (
            result.get("worker_call_key_digest") != self.call_key.digest()
            or result.get("armed_zero_receipt_digest") != armed_zero.arm_receipt_digest
            or result.get("runtime_sha256") != self.runtime_sha256
            or result.get("provider_runtime_sha256")
            != armed_zero.provider_runtime_sha256
            or result.get("provider_cmdline_sha256")
            != armed_zero.provider_cmdline_sha256
            or result.get("provider_runtime_identity_digest")
            != armed_zero.provider_runtime_identity_digest
            or result.get("provider_process_identity")
            != armed_zero.inner_process_identity.as_dict()
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_WORKER_RESULT_IDENTITY_MISMATCH",
                "worker result differs from the retained pre-arm process",
            )
        final_zero = self._safe_stop_result(result)
        stop_acknowledged = result.get("stop_acknowledged") is True and final_zero
        provider_terminated = self._result_proves_inner_exit(result)
        if receipt.status == "SUCCEEDED":
            evidence = result.get("independent_motion_evidence")
            if (
                result.get("status") != "SUCCEEDED"
                or result.get("target_status") != "SUCCEEDED"
                or result.get("motion_started") is not True
                or result.get("angle_accuracy_verified") is not True
                or not isinstance(evidence, Mapping)
                or evidence.get("independent_of_odom") is not True
                or evidence.get("settled") is not True
                or not (final_zero and stop_acknowledged and provider_terminated)
            ):
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_SUCCESS_EVIDENCE_INCOMPLETE",
                    "committed success lacks independent angle, final-zero, or exit proof",
                )
        return final_zero, stop_acknowledged, provider_terminated

    def _verified_provider_count(
        self,
        result: Mapping[str, Any],
        gate_reference: PhysicalProviderGateReference | None,
    ) -> int:
        raw = result.get("provider_invocation_count", 0)
        count = _exact_count(raw, maximum=1)
        if gate_reference is not None and count != 1:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PROVIDER_COUNT_INVALID",
                "consumed one-shot gate does not have exactly one provider invocation",
            )
        if gate_reference is None and count != 0:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PROVIDER_COUNT_INVALID",
                "provider count is nonzero without a durable consumed gate",
            )
        return count

    def _load_exact_lease(self, *, required: bool) -> WorkerLeaseRecord | None:
        try:
            raw = self.load_lease(self.call_key)
            lease = (
                WorkerLeaseRecord.model_validate(raw.model_dump(mode="python"))
                if isinstance(raw, WorkerLeaseRecord)
                else None
            )
        except Exception as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_WORKER_LEASE_INVALID",
                "fresh worker lease could not be revalidated",
            ) from exc
        if required and lease is None:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_WORKER_LEASE_MISSING",
                "started physical call has no durable worker lease",
            )
        if lease is not None and lease.call_key != self.call_key:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_WORKER_LEASE_INVALID",
                "worker lease belongs to another call",
            )
        return lease

    def _require_armed_zero(self, armed: PhysicalWorkerArmedZero) -> None:
        PrearmedProviderReceipt.from_armed_zero(
            armed,
            request=self.request,
            expected_runtime_sha256=self.runtime_sha256,
        )

    def _require_receipt_identity(self, receipt: TargetdCallReceipt) -> None:
        request = self.request
        expected = {
            "idempotency_key": request.idempotency_key,
            "session_id": request.session_id,
            "target_id": request.target_id,
            "bundle_digest": request.bundle_digest,
            "request_digest": request.request_digest(),
            "release_digest": request.release_digest,
            "context_digest": request.context_digest,
            "mapping_confirmation_receipt_digest": request.mapping_confirmation_receipt_digest,
            "authority_head_digest": request.authority_head_digest,
            "fence_epoch": request.fence_epoch,
            "provider_id": request.provider_id,
            "provider_operation": request.provider_operation,
            "provider_fence_digest": provider_fence_digest(request),
        }
        if any(getattr(receipt, field) != expected_value for field, expected_value in expected.items()):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TARGETD_RECEIPT_IDENTITY_MISMATCH",
                "targetd receipt differs from the signed physical request",
            )

    def _load_trace_sidecar(
        self,
        paths: Mapping[str, Path],
    ) -> TargetdTraceReceiptSidecar | None:
        candidates = [
            Path(path)
            for label, path in paths.items()
            if label == f"receipt:{self.request.idempotency_key}"
            or Path(path).name.startswith("targetd-receipt-")
        ]
        unique = {str(path.resolve()): path for path in candidates}
        matches: list[TargetdTraceReceiptSidecar] = []
        for path in unique.values():
            raw = self._read_bounded_json(path, label="Trace receipt")
            try:
                sidecar = TargetdTraceReceiptSidecar.model_validate(raw)
            except (TypeError, ValueError) as exc:
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_TRACE_RECEIPT_INVALID",
                    "immutable targetd Trace receipt sidecar is invalid",
                ) from exc
            if sidecar.idempotency_key == self.request.idempotency_key:
                matches.append(sidecar)
        if len(matches) > 1:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TRACE_RECEIPT_DUPLICATE",
                "Trace snapshot contains duplicate receipts for the physical call",
            )
        if matches:
            self._require_indexed_path(paths, unique, matches[0])
        return matches[0] if matches else None

    def _require_trace_plan(
        self,
        paths: Mapping[str, Path],
        sidecar: TargetdTraceReceiptSidecar,
    ) -> None:
        path = paths.get("plan")
        if path is None:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TRACE_PLAN_MISSING",
                "Trace snapshot has no immutable plan",
            )
        try:
            plan = TracePlan.model_validate(
                self._read_bounded_json(Path(path), label="Trace plan")
            )
        except (TypeError, ValueError) as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TRACE_PLAN_INVALID",
                "immutable Trace plan is invalid",
            ) from exc
        calls = [
            call
            for call in plan.calls
            if call.idempotency_key == self.request.idempotency_key
        ]
        if (
            plan.plan_digest != sidecar.plan_digest
            or plan.session_id != self.request.session_id
            or plan.target_id != self.request.target_id
            or len(calls) != 1
            or calls[0].call_digest != sidecar.call_digest
            or calls[0].tool_id != TOOL_ID
            or calls[0].arguments != self.request.arguments
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TRACE_PLAN_IDENTITY_MISMATCH",
                "Trace plan/receipt differs from the signed physical request",
            )

    def _require_indexed_path(
        self,
        paths: Mapping[str, Path],
        candidates: Mapping[str, Path],
        sidecar: TargetdTraceReceiptSidecar,
    ) -> None:
        index_path = paths.get("index")
        if index_path is None:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TRACE_INDEX_MISSING",
                "Trace receipt is not covered by an immutable artifact index",
            )
        try:
            index = ArtifactIndex.model_validate(
                self._read_bounded_json(Path(index_path), label="Trace index")
            )
            index.verify()
        except (TypeError, ValueError) as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TRACE_INDEX_INVALID",
                "Trace artifact index is invalid",
            ) from exc
        receipt_paths = [
            path
            for path in candidates.values()
            if TargetdTraceReceiptSidecar.model_validate(
                self._read_bounded_json(path, label="Trace receipt")
            ).sidecar_digest
            == sidecar.sidecar_digest
        ]
        if len(receipt_paths) != 1:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TRACE_RECEIPT_DUPLICATE",
                "Trace receipt path identity is ambiguous",
            )
        receipt_path = receipt_paths[0]
        try:
            relative = receipt_path.resolve().relative_to(Path(index_path).resolve().parent).as_posix()
        except ValueError as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TRACE_INDEX_PATH_INVALID",
                "Trace receipt escapes its snapshot directory",
            ) from exc
        digest = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        if {"path": relative, "sha256": digest} not in index.artifacts:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TRACE_RECEIPT_NOT_INDEXED",
                "Trace receipt is not covered by the artifact index",
            )

    @staticmethod
    def _read_bounded_json(path: Path, *, label: str) -> Any:
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
                raise ValueError
            return loads_unique_json(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TRACE_ARTIFACT_INVALID",
                f"{label} artifact is unsafe or invalid",
            ) from exc

    def _verify_signature(self, artifact: Any) -> bool:
        return self.trust_store.verify_payload_signature(
            issuer_id=artifact.issuer_id,
            payload_sha256=artifact.payload_sha256,
            signature_hmac_sha256=artifact.signature_hmac_sha256,
        )

    @staticmethod
    def _safe_stop_result(result: Mapping[str, Any]) -> bool:
        evidence = result.get("independent_motion_evidence")
        return (
            result.get("final_zero_verified") is True
            and result.get("stop_acknowledged") is True
            and result.get("stop_published") is True
            and result.get("physical_stop_verified") is True
            and result.get("stopped_observed") is True
            and result.get("control_graph_isolated") is True
            and isinstance(evidence, Mapping)
            and evidence.get("independent_of_odom") is True
            and evidence.get("settled") is True
        )

    @staticmethod
    def _result_proves_inner_exit(result: Mapping[str, Any]) -> bool:
        acknowledgement = result.get("stop_acknowledgement")
        return (
            isinstance(acknowledgement, Mapping)
            and acknowledgement.get("verified") is True
            and acknowledgement.get("inner_process_gone") is True
        )

    @staticmethod
    def _session_state(session: Any) -> str:
        state = getattr(session, "state", "UNKNOWN")
        return state.value if isinstance(state, SessionState) else str(state)


class PreparedPhysicalTraceLifecycleClient(Protocol):
    """Authenticated two-phase targetd client used by the Trace bridge."""

    def prepare_physical_call_remote(
        self,
        request: ExecutionRequestV3,
    ) -> ProtocolFrame: ...

    def accept_debug_zero_motion_remote(
        self,
        *,
        call_id: str,
        request_digest: str,
        armed_zero_receipt_digest: str,
        debug_admission: DebugOnlyUserAttestedAdmission | Mapping[str, object],
    ) -> ProtocolFrame: ...

    def start_prepared_physical_call_remote(
        self,
        *,
        call_id: str,
        request_digest: str,
        armed_zero_receipt_digest: str,
        provider_gate: Mapping[str, object],
    ) -> ProtocolFrame: ...

    def query_physical_gate_remote(
        self,
        call_id: str,
        request_digest: str,
        *,
        gate_uri: str | None = None,
        gate_digest_uri: str | None = None,
    ) -> ProtocolFrame: ...


@dataclass(frozen=True)
class PreparedPhysicalTraceDispatch:
    """The real START frame plus the terminal authenticated QUERY frame."""

    start_response: TargetdTraceResponse | None
    terminal_response: TargetdTraceResponse


class PreparedPhysicalTraceBridge:
    """Map one formal Trace TOOL_CALL to one authenticated prepared START.

    ``TargetdTraceAdapter`` still owns durable request materialization and the
    immutable Trace receipt sidecar.  Its CALL callback is replaced only at
    the transport boundary: PREPARE happens before acceptance, the first and
    only TOOL_CALL sends ``START_PREPARED_CALL``, and all uncertainty is read
    back through authenticated physical ``QUERY_CALL``.  No code path calls
    generic ``JourneySessionClient.call_remote`` or ``query_call``.
    """

    prepared_physical_trace_bridge = True

    def __init__(
        self,
        request: ExecutionRequestV3,
        manifest: ExecutionBundleManifest,
        client: PreparedPhysicalTraceLifecycleClient,
        *,
        gate_payload_factory: Callable[
            [PhysicalAcceptanceReceipt, PhysicalWorkerArmedZero],
            Mapping[str, object],
        ]
        | None = None,
        terminal_query_budget: int = 240,
        poll_interval_s: float = 0.25,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(request, ExecutionRequestV3):
            raise TypeError("prepared physical Trace requires ExecutionRequestV3")
        if not isinstance(manifest, ExecutionBundleManifest):
            raise TypeError("prepared physical Trace requires a sealed manifest")
        if gate_payload_factory is not None and (
            not callable(gate_payload_factory)
            or getattr(
                gate_payload_factory,
                "sealed_physical_gate_payload_factory",
                False,
            )
            is not True
        ):
            raise ValueError("prepared physical Trace requires a sealed gate payload factory")
        if (
            isinstance(terminal_query_budget, bool)
            or not isinstance(terminal_query_budget, int)
            or not 1 <= terminal_query_budget <= 300
            or isinstance(poll_interval_s, bool)
            or not isinstance(poll_interval_s, (int, float))
            or not math.isfinite(float(poll_interval_s))
            or not 0 <= float(poll_interval_s) <= 1
            or float(poll_interval_s) * terminal_query_budget > 75
        ):
            raise ValueError("prepared physical Trace polling budget is invalid")
        runtime = manifest.observation_contract.get("provider_runtime_sha256")
        if (
            request.bundle_digest != manifest.bundle_digest
            or not isinstance(runtime, str)
            or re.fullmatch(r"[0-9a-f]{64}", runtime) is None
        ):
            raise ValueError("prepared physical Trace manifest binding is invalid")
        self.request = ExecutionRequestV3.model_validate(
            request.model_dump(mode="python")
        )
        self.manifest = ExecutionBundleManifest.model_validate(
            manifest.model_dump(mode="python")
        )
        self.client = client
        self.gate_payload_factory = gate_payload_factory
        self.terminal_query_budget = terminal_query_budget
        self.poll_interval_s = float(poll_interval_s)
        self.sleeper = sleeper
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._prepare_dispatched = False
        self._start_dispatched = False
        self._trace_query_dispatched = False
        self._debug_acceptance_dispatched = False
        self._armed_zero: PhysicalWorkerArmedZero | None = None
        self._debug_acceptance: DebugUserAttestedAcceptanceReceipt | None = None
        self._provider_gate_payload: dict[str, object] | None = None
        self._provider_gate_bound = False
        self._latest_worker_lease: WorkerLeaseRecord | None = None
        self.physical_query_count = 0

    def prepare_zero_motion(self, spec: MotionSpec) -> PhysicalWorkerArmedZero:
        if self._prepare_dispatched or self._start_dispatched:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PREPARE_REPLAY_BLOCKED",
                "PREPARE_PHYSICAL_CALL is one-shot",
            )
        if spec.arguments() != self.request.arguments:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PREPARE_IDENTITY_MISMATCH",
                "pre-arm motion arguments differ from the signed request",
            )
        self._prepare_dispatched = True
        frame = self.client.prepare_physical_call_remote(self.request)
        receipt = self._parse_response(
            frame,
            expected_kind=FrameKind.PREPARE_PHYSICAL_CALL,
            expected_run_id=self.request.run_id,
        )
        if (
            receipt.status != "ACCEPTED"
            or frame.payload.get("prepared") is not True
            or frame.payload.get("provider_invocation_count") not in {None, 0}
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PREPARE_NOT_ARMED",
                "targetd did not retain a zero-motion prepared worker",
            )
        try:
            armed = parse_physical_worker_armed_zero(
                frame.payload.get("armed_zero"),
                expected_call_key_digest=WorkerCallKey.from_request(
                    self.request
                ).digest(),
                expected_request_digest=self.request.request_digest(),
                expected_execution_subject_digest=(
                    self.request.execution_subject_digest
                ),
                expected_runtime_sha256=str(
                    self.manifest.observation_contract[
                        "provider_runtime_sha256"
                    ]
                ),
                expected_target_id=self.request.target_id,
                expected_call_id=self.request.idempotency_key,
                expected_session_id=self.request.session_id,
            )
        except Exception as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PREPARE_ARM_RECEIPT_INVALID",
                "targetd PREPARE returned no exact typed ARMED_ZERO receipt",
            ) from exc
        self._armed_zero = armed
        return armed

    def accept_debug_zero_motion(
        self,
        admission: DebugOnlyUserAttestedAdmission,
    ) -> DebugUserAttestedAcceptanceReceipt:
        """Run the rehearsal on targetd host and bind its durable reference.

        No caller-supplied acceptance or gate object can cross START.  If the
        ACCEPT response is lost, the only recovery action is an authenticated
        physical query; ACCEPT itself is never replayed by this bridge.
        """

        if (
            self._armed_zero is None
            or not self._prepare_dispatched
            or self._debug_acceptance_dispatched
            or self._start_dispatched
            or self.gate_payload_factory is not None
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_DEBUG_ACCEPTANCE_SEQUENCE_INVALID",
                "debug acceptance requires one prepared worker and no caller gate factory",
            )
        try:
            parsed = DebugOnlyUserAttestedAdmission.model_validate(
                admission.model_dump(mode="python")
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_DEBUG_ADMISSION_INVALID",
                "debug admission is not a typed bounded receipt",
            ) from exc
        point = self.clock().astimezone(timezone.utc)
        if (
            parsed.call_id != self.request.idempotency_key
            or parsed.session_id != self.request.session_id
            or parsed.target_id != self.request.target_id
            or parsed.execution_subject_digest
            != self.request.execution_subject_digest
            or parsed.requested_rotation_degrees
            != self.request.arguments.get("angle_degrees")
            or parsed.requested_linear_meters != 0.0
            or parsed.max_abs_rotation_degrees != 1.0
            or parsed.max_abs_linear_meters != 0.03
            or parsed.production_authority_verified is not False
            or parsed.one_shot is not True
            or not (parsed.issued_at <= point < parsed.expires_at)
            or parsed.expires_at > self.request.deadline
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_DEBUG_ADMISSION_IDENTITY_MISMATCH",
                "debug admission differs from the exact prepared call or deadline",
            )
        self._debug_acceptance_dispatched = True
        try:
            frame = self.client.accept_debug_zero_motion_remote(
                call_id=self.request.idempotency_key,
                request_digest=self.request.request_digest(),
                armed_zero_receipt_digest=self._armed_zero.arm_receipt_digest,
                debug_admission=parsed,
            )
            expected_kind = FrameKind.ACCEPT_DEBUG_ZERO_MOTION
        except Exception:
            # The target may already have persisted the rehearsal.  Never
            # replay it: recover only through the authenticated physical read.
            frame = self.client.query_physical_gate_remote(
                self.request.idempotency_key,
                self.request.request_digest(),
                gate_uri=None,
                gate_digest_uri=None,
            )
            expected_kind = FrameKind.QUERY_CALL
        return self._bind_debug_acceptance_frame(
            frame,
            admission=parsed,
            expected_kind=expected_kind,
        )

    def bind_provider_gate(self, receipt: PhysicalAcceptanceReceipt) -> None:
        if self._armed_zero is None or not self._prepare_dispatched:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PROVIDER_GATE_BEFORE_PREPARE",
                "provider gate cannot be bound before ARMED_ZERO",
            )
        if self._provider_gate_bound or self._start_dispatched:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PROVIDER_GATE_REUSED",
                "provider gate payload is one-shot",
            )
        if isinstance(receipt, DebugUserAttestedAcceptanceReceipt):
            if (
                self._debug_acceptance is None
                or receipt != self._debug_acceptance
                or self._provider_gate_payload is None
            ):
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_DEBUG_ACCEPTANCE_REFERENCE_REQUIRED",
                    "debug START requires the exact target-owned acceptance reference",
                )
            self._provider_gate_bound = True
            return
        if self._provider_gate_payload is not None:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PROVIDER_GATE_REUSED",
                "provider gate payload is one-shot",
            )
        if self.gate_payload_factory is None:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PROVIDER_GATE_FACTORY_MISSING",
                "production provider gate payload factory is unavailable",
            )
        payload = self.gate_payload_factory(receipt, self._armed_zero)
        if not isinstance(payload, Mapping):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PROVIDER_GATE_PAYLOAD_INVALID",
                "sealed provider gate payload factory returned no object",
            )
        encoded = _canonical_bytes(payload)
        if len(encoded) > _MAX_RPC_BYTES:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PROVIDER_GATE_PAYLOAD_INVALID",
                "sealed provider gate payload exceeds the bounded wire size",
            )
        restored = loads_unique_json(encoded.decode("ascii"))
        if not isinstance(restored, dict):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PROVIDER_GATE_PAYLOAD_INVALID",
                "sealed provider gate payload is not canonical JSON",
            )
        self._provider_gate_payload = restored
        self._provider_gate_bound = True

    def _bind_debug_acceptance_frame(
        self,
        frame: ProtocolFrame,
        *,
        admission: DebugOnlyUserAttestedAdmission,
        expected_kind: FrameKind,
    ) -> DebugUserAttestedAcceptanceReceipt:
        lifecycle_receipt = self._parse_response(
            frame,
            expected_kind=expected_kind,
            expected_run_id=None,
        )
        payload = frame.payload
        reference = payload.get("debug_acceptance")
        start = payload.get("provider_gate_start")
        acceptance_payload = payload.get("acceptance_receipt")
        if (
            payload.get("accepted") is not True
            or payload.get("start_eligible") is not True
            or not isinstance(reference, Mapping)
            or set(reference) != {"uri", "digest_uri", "sidecar"}
            or not isinstance(start, Mapping)
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_DEBUG_ACCEPTANCE_RESPONSE_INVALID",
                "targetd returned no start-eligible durable debug acceptance",
            )
        try:
            sidecar = DebugPhysicalAcceptanceSidecar.model_validate(
                reference.get("sidecar")
            )
            acceptance_receipt = DebugUserAttestedAcceptanceReceipt.model_validate(
                acceptance_payload
            )
        except (TypeError, ValueError) as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_DEBUG_ACCEPTANCE_SIDECAR_INVALID",
                "targetd debug acceptance sidecar is invalid",
            ) from exc
        call_key = WorkerCallKey.from_request(self.request)
        armed = self._armed_zero
        assert armed is not None
        sidecar_digest_hex = sidecar.sidecar_digest.removeprefix("sha256:")
        expected_uri = (
            "artifact://targetd/debug-physical-acceptances/"
            f"{call_key.digest()}/{sidecar_digest_hex}"
        )
        expected_digest_uri = f"digest://sha256/{sidecar_digest_hex}"
        expected_start = {
            "schema_version": "rolo-targetd-debug-zero-motion-acceptance-reference/v1",
            "authority_class": "DEBUG_ONLY_USER_ATTESTED",
            "production_authority": False,
            "target_id": self.request.target_id,
            "session_id": self.request.session_id,
            "call_id": self.request.idempotency_key,
            "request_digest": self.request.request_digest(),
            "armed_zero_receipt_digest": armed.arm_receipt_digest,
            "debug_admission_digest": admission.payload_sha256,
            "acceptance_uri": reference.get("uri"),
            "acceptance_digest_uri": reference.get("digest_uri"),
            "acceptance_sidecar_digest": sidecar.sidecar_digest,
        }
        if (
            lifecycle_receipt.status != "ACCEPTED"
            or sidecar.call_key != call_key
            or sidecar.armed_zero != armed.as_dict()
            or sidecar.debug_admission != admission
            or sidecar.acceptance_receipt != acceptance_receipt
            or reference.get("uri") != expected_uri
            or reference.get("digest_uri") != expected_digest_uri
            or start != expected_start
            or lifecycle_receipt.artifact_refs.count(str(reference.get("uri"))) != 1
            or lifecycle_receipt.artifact_refs.count(str(reference.get("digest_uri")))
            != 1
            or any(
                item in lifecycle_receipt.evidence_refs
                for item in (reference.get("uri"), reference.get("digest_uri"))
            )
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_DEBUG_ACCEPTANCE_BINDING_INVALID",
                "targetd acceptance, ARMED_ZERO, request, or durable reference differs",
            )
        receipt = sidecar.acceptance_receipt
        if (
            receipt.status != "DEBUG_ACCEPTED"
            or receipt.provider_boundary_open is not False
            or receipt.production_ready is not False
            or receipt.debug_admission_digest != admission.payload_sha256
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_DEBUG_ACCEPTANCE_BLOCKED",
                "target-owned debug rehearsal did not produce a closed-boundary acceptance",
            )
        self._debug_acceptance = receipt
        self._provider_gate_payload = dict(start)
        return receipt

    def call_for_trace(
        self,
        request: ExecutionRequestV3,
    ) -> PreparedPhysicalTraceDispatch:
        """Dispatch exactly one START_PREPARED for one durable TOOL_CALL."""

        if self._start_dispatched:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_CALL_REPLAY_BLOCKED",
                "START_PREPARED_CALL was already dispatched",
            )
        self._require_request(request)
        if (
            self._armed_zero is None
            or self._provider_gate_payload is None
            or not self._provider_gate_bound
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PREPARED_GATE_MISSING",
                "START_PREPARED requires ARMED_ZERO and a sealed gate payload",
            )
        self._start_dispatched = True
        start_response: TargetdTraceResponse | None = None
        try:
            frame = self.client.start_prepared_physical_call_remote(
                call_id=self.request.idempotency_key,
                request_digest=self.request.request_digest(),
                armed_zero_receipt_digest=self._armed_zero.arm_receipt_digest,
                provider_gate=self._provider_gate_payload,
            )
            receipt = self._parse_response(
                frame,
                expected_kind=FrameKind.START_PREPARED_CALL,
                expected_run_id=None,
            )
            if (
                frame.payload.get("call_started") is not True
                or frame.payload.get("provider_invocation_count") not in {None, 1}
                or receipt.status != "STARTED"
            ):
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_PREPARED_START_NOT_ACKNOWLEDGED",
                    "targetd did not acknowledge the exact prepared start",
                )
            start_response = TargetdTraceResponse(
                frame=frame,
                sequence_correlated=True,
            )
        except Exception:
            # START may have crossed the boundary.  Never resend it: only
            # authenticated physical QUERY can disambiguate the outcome.
            return PreparedPhysicalTraceDispatch(
                start_response=None,
                terminal_response=self._poll_terminal_response(),
            )
        return PreparedPhysicalTraceDispatch(
            start_response=start_response,
            terminal_response=self._poll_terminal_response(),
        )

    def query_for_trace(self, call_id: str) -> TargetdTraceResponse:
        """Trace resume seam: one authenticated physical read, never generic query."""

        if (
            not self._start_dispatched
            or self._trace_query_dispatched
            or call_id != self.request.idempotency_key
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_QUERY_INVALID",
                "physical Trace reconciliation query identity or budget is invalid",
            )
        self._trace_query_dispatched = True
        return self._physical_query()

    def _poll_terminal_response(self) -> TargetdTraceResponse:
        last_error: Exception | None = None
        for attempt in range(self.terminal_query_budget):
            if self.clock().astimezone(timezone.utc) >= self.request.deadline:
                break
            try:
                response = self._physical_query()
                receipt = self._parse_response(
                    response.frame,
                    expected_kind=FrameKind.QUERY_CALL,
                    expected_run_id=None,
                )
                if receipt.status in {
                    "SUCCEEDED",
                    "FAILED",
                    "STOPPED",
                    "CANCELLED",
                    "UNKNOWN",
                    "NOT_ACCEPTED",
                }:
                    return response
            except Exception as exc:  # read-only retry within the fixed budget
                last_error = exc
            if attempt + 1 < self.terminal_query_budget and self.poll_interval_s:
                self.sleeper(self.poll_interval_s)
        raise TimeoutError("TARGETD_PHYSICAL_PREPARED_OUTCOME_UNKNOWN") from last_error

    def _physical_query(self) -> TargetdTraceResponse:
        self.physical_query_count += 1
        frame = self.client.query_physical_gate_remote(
            self.request.idempotency_key,
            self.request.request_digest(),
            gate_uri=None,
            gate_digest_uri=None,
        )
        raw_lease = frame.payload.get("physical_worker_lease")
        if raw_lease is not None:
            self._cache_worker_lease(raw_lease)
        return TargetdTraceResponse(frame=frame, sequence_correlated=True)

    def load_worker_lease(self, call_key: WorkerCallKey) -> WorkerLeaseRecord | None:
        """Expose only the exact typed lease learned over authenticated QUERY."""

        if not isinstance(call_key, WorkerCallKey):
            return None
        lease = self._latest_worker_lease
        return lease if lease is not None and lease.call_key == call_key else None

    def _cache_worker_lease(self, raw: object) -> None:
        try:
            lease = WorkerLeaseRecord.model_validate(raw)
        except (TypeError, ValueError) as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_WORKER_LEASE_INVALID",
                "authenticated physical QUERY returned an invalid worker lease",
            ) from exc
        armed = self._armed_zero
        expected_runtime = "sha256:" + str(
            self.manifest.observation_contract["provider_runtime_sha256"]
        )
        if (
            lease.call_key != WorkerCallKey.from_request(self.request)
            or lease.physical_execution_subject_digest
            != self.request.execution_subject_digest
            or lease.physical_runtime_sha256 != expected_runtime
            or (armed is not None and lease.armed_zero != armed.as_dict())
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_WORKER_LEASE_IDENTITY_MISMATCH",
                "authenticated physical QUERY worker lease differs from the prepared call",
            )
        self._latest_worker_lease = lease

    def _parse_response(
        self,
        frame: ProtocolFrame,
        *,
        expected_kind: FrameKind,
        expected_run_id: str | None,
    ) -> TargetdCallReceipt:
        try:
            parsed = ProtocolFrame.model_validate(frame.model_dump(mode="python"))
        except (AttributeError, TypeError, ValueError) as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_LIFECYCLE_RESPONSE_INVALID",
                "targetd physical lifecycle response is invalid",
            ) from exc
        if (
            parsed.kind != FrameKind.RESULT
            or parsed.session_id != self.request.session_id
            or parsed.run_id != expected_run_id
            or parsed.payload.get("request_kind") != expected_kind.value
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_LIFECYCLE_RESPONSE_IDENTITY_MISMATCH",
                "targetd physical lifecycle response identity differs",
            )
        if parsed.payload.get("ok") is not True:
            error = parsed.payload.get("error")
            if (
                parsed.payload.get("ok") is False
                and isinstance(error, str)
                and _TARGETD_ERROR_CODE.fullmatch(error) is not None
            ):
                raise N7PhysicalBlocked(
                    error,
                    f"targetd rejected {expected_kind.value}: {error}",
                )
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_LIFECYCLE_RESPONSE_INVALID",
                "targetd physical lifecycle error response is invalid",
            )
        try:
            receipt = TargetdCallReceipt.model_validate(
                parsed.payload.get("receipt")
            )
        except (TypeError, ValueError) as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_LIFECYCLE_RESPONSE_INVALID",
                "targetd physical lifecycle receipt is invalid",
            ) from exc
        self._require_receipt_identity(receipt)
        return receipt

    def _require_receipt_identity(self, receipt: TargetdCallReceipt) -> None:
        request = self.request
        expected = {
            "idempotency_key": request.idempotency_key,
            "session_id": request.session_id,
            "target_id": request.target_id,
            "bundle_digest": request.bundle_digest,
            "request_digest": request.request_digest(),
            "release_digest": request.release_digest,
            "context_digest": request.context_digest,
            "mapping_confirmation_receipt_digest": (
                request.mapping_confirmation_receipt_digest
            ),
            "authority_head_digest": request.authority_head_digest,
            "fence_epoch": request.fence_epoch,
            "provider_id": request.provider_id,
            "provider_operation": request.provider_operation,
            "provider_fence_digest": provider_fence_digest(request),
        }
        if any(getattr(receipt, field) != value for field, value in expected.items()):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_LIFECYCLE_RECEIPT_IDENTITY_MISMATCH",
                "targetd lifecycle receipt differs from the signed request",
            )

    def _require_request(self, request: ExecutionRequestV3) -> None:
        try:
            parsed = ExecutionRequestV3.model_validate(
                request.model_dump(mode="python")
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TRACE_REQUEST_INVALID",
                "Trace did not dispatch a valid physical v3 request",
            ) from exc
        if parsed != self.request:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TRACE_REQUEST_IDENTITY_MISMATCH",
                "Trace v3 request differs from the prepared worker",
            )

class PreparedPhysicalTargetdTraceAdapter(TargetdTraceAdapter):
    """Targetd Trace adapter whose write seam is sealed to prepared START."""

    prepared_physical_targetd_adapter = True

    def __init__(
        self,
        authority: TargetdExecutionAuthority,
        bridge: PreparedPhysicalTraceBridge,
        *,
        authority_resolver: Callable[[str], TargetdExecutionAuthority],
        request_store: Any,
        physical_request_factory: Callable[[Any, Any, Any, datetime], ExecutionRequestV3],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if bridge.request.authority != authority:
            raise ValueError("prepared bridge and targetd authority differ")
        self.prepared_bridge = bridge
        super().__init__(
            authority,
            authority_resolver=authority_resolver,
            call=bridge.call_for_trace,
            query=bridge.query_for_trace,
            clock=clock,
            request_store=request_store,
            physical_request_factory=physical_request_factory,
        )

    def __call__(
        self,
        tool_id: str,
        arguments: Mapping[str, Any],
        session_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        plan, call = self._context(
            tool_id,
            arguments,
            session_id,
            idempotency_key,
        )
        request = self._request_for(plan, call)
        if not isinstance(request, ExecutionRequestV3):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TRACE_REQUEST_INVALID",
                "prepared physical adapter received a non-v3 request",
            )
        try:
            dispatch = self.prepared_bridge.call_for_trace(request)
            if dispatch.start_response is not None:
                start_receipt = self.prepared_bridge._parse_response(
                    dispatch.start_response.frame,
                    expected_kind=FrameKind.START_PREPARED_CALL,
                    expected_run_id=None,
                )
                if start_receipt.status != "STARTED":
                    raise N7PhysicalBlocked(
                        "N7_PHYSICAL_PREPARED_START_NOT_ACKNOWLEDGED",
                        "prepared START response is not STARTED",
                    )
            receipt = self._receipt(
                dispatch.terminal_response,
                request,
                expected_kind=FrameKind.QUERY_CALL,
            )
        except Exception as exc:
            raise TimeoutError("TARGETD_TRACE_OUTCOME_UNKNOWN") from exc
        sidecar = TargetdTraceReceiptSidecar.build(plan, call, receipt)
        if self._receipt_sink is None:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TRACE_RECEIPT_SINK_REQUIRED",
                "formal Trace receipt sink is not bound",
            )
        self._receipt_sink(plan, sidecar)
        return self._safe_result(receipt)


class ReleaseBoundPhysicalTraceDriver:
    """Production adapter around formal Trace plus typed targetd proof reads."""

    def __init__(
        self,
        trace: Any,
        request: TraceSessionRequest,
        call: TraceCall,
        *,
        prepare_provider: Callable[[MotionSpec], PhysicalWorkerArmedZero],
        proof_verifier: TargetdPhysicalProofVerifier,
        provider_gate_preflight: Callable[[PhysicalAcceptanceReceipt], None] | None = None,
    ) -> None:
        if call.idempotency_key is None:
            raise ValueError("physical Trace requires an explicit idempotency key")
        if not isinstance(proof_verifier, TargetdPhysicalProofVerifier):
            raise ValueError("physical Trace requires the typed targetd proof verifier")
        execution_request = proof_verifier.request
        if (
            request.session_id != execution_request.session_id
            or request.target_id != execution_request.target_id
            or call.idempotency_key != execution_request.idempotency_key
            or call.tool_id != TOOL_ID
            or call.arguments != execution_request.arguments
        ):
            raise ValueError("Trace and physical ExecutionRequestV3 identity differ")
        targetd_adapter_resolver = getattr(trace, "_targetd_adapter", None)
        if callable(targetd_adapter_resolver):
            adapter = targetd_adapter_resolver()
            prepare_owner = getattr(prepare_provider, "__self__", None)
            preflight_owner = getattr(provider_gate_preflight, "__self__", None)
            if (
                not isinstance(adapter, PreparedPhysicalTargetdTraceAdapter)
                or not isinstance(prepare_owner, PreparedPhysicalTraceBridge)
                or preflight_owner is not prepare_owner
                or adapter.prepared_bridge is not prepare_owner
                or getattr(adapter.call, "__self__", None) is not prepare_owner
                or getattr(adapter.query, "__self__", None) is not prepare_owner
            ):
                raise ValueError(
                    "ReleaseBoundTrace physical dispatch must use the sealed "
                    "PREPARE/START_PREPARED adapter"
                )
        self.trace = trace
        self.request = request
        self.call = call
        self.prepare_provider = prepare_provider
        self.proof_verifier = proof_verifier
        self.provider_gate_preflight = provider_gate_preflight or _default_provider_gate_preflight
        self._started = False
        self._prepared = False
        self._queried = False
        self._stopped = False
        self._acceptance: PhysicalAcceptanceReceipt | None = None
        self._armed_zero: PhysicalWorkerArmedZero | None = None
        self._last_session: Any | None = None
        self._last_paths: Mapping[str, Path] = {}

    def prepare_zero_motion(self, spec: MotionSpec) -> PrearmedProviderReceipt:
        if self._prepared or self._started:
            raise N7PhysicalBlocked("N7_PHYSICAL_PREARM_REUSED", "physical worker was already pre-armed")
        self._prepared = True
        armed = self.prepare_provider(spec)
        self.proof_verifier._require_armed_zero(armed)
        self._armed_zero = armed
        return PrearmedProviderReceipt.from_armed_zero(
            armed,
            request=self.proof_verifier.request,
            expected_runtime_sha256=self.proof_verifier.runtime_sha256,
        )

    def preflight_provider_gate(self, receipt: PhysicalAcceptanceReceipt) -> None:
        self.provider_gate_preflight(receipt)

    def start_once(self, receipt: PhysicalAcceptanceReceipt, spec: MotionSpec) -> TraceAttempt:
        if self._started or not self._prepared:
            raise N7PhysicalBlocked("N7_PHYSICAL_CALL_REPLAY_BLOCKED", "physical CALL was already submitted")
        if self.call.idempotency_key != receipt.call_id or self.call.arguments != spec.arguments():
            raise N7PhysicalBlocked("N7_PHYSICAL_TRACE_IDENTITY_MISMATCH", "Trace call differs from acceptance")
        receipt_type = type(receipt)
        if receipt_type not in {
            ZeroMotionAcceptanceReceipt,
            DebugUserAttestedAcceptanceReceipt,
        }:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_ACCEPTANCE_RECEIPT_INVALID",
                "physical acceptance must be a supported typed target receipt",
            )
        self._acceptance = receipt_type.model_validate(receipt.model_dump(mode="python"))
        self._started = True
        session, paths = self.trace.run(self.request, [self.call])
        self._last_session = session
        self._last_paths = dict(paths)
        return self._summarize(session, paths, query_count=0)

    def query_once(self, call_id: str) -> TraceAttempt:
        if not self._started or self._queried or call_id != self.call.idempotency_key:
            raise N7PhysicalBlocked("N7_PHYSICAL_QUERY_INVALID", "QUERY_CALL identity or budget is invalid")
        if self._last_session is None or _tool_call_count(self._last_session, call_id) != 1:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_QUERY_WITHOUT_DURABLE_CALL",
                "an ambiguous Trace may be queried only after one durable TOOL_CALL event",
            )
        self._queried = True
        session, paths = self.trace.resume(self.request.session_id or self._last_session.session_id)
        self._last_session = session
        self._last_paths = dict(paths)
        if _tool_call_count(session, call_id) != 1:
            raise N7PhysicalBlocked("N7_PHYSICAL_CALL_REPLAY_DETECTED", "reconciliation replayed a physical CALL")
        return self._summarize(session, paths, query_count=1)

    def stop_once(self, call_id: str) -> AuthenticatedStopReceipt:
        if not self._prepared or self._stopped or call_id != self.call.idempotency_key:
            raise N7PhysicalBlocked("N7_PHYSICAL_STOP_IDENTITY_INVALID", "STOP does not match the submitted CALL")
        self._stopped = True
        return self.proof_verifier.authenticated_stop(call_id)

    def _summarize(self, session: Any, paths: Mapping[str, Path], *, query_count: int) -> TraceAttempt:
        if _tool_call_count(session, self.call.idempotency_key or "") > 1:
            raise N7PhysicalBlocked("N7_PHYSICAL_CALL_REPLAY_DETECTED", "Trace contains duplicate physical CALL events")
        if self._acceptance is None or self._armed_zero is None:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TYPED_PROOF_CONTEXT_MISSING",
                "Trace proof context was not durably prepared",
            )
        return self.proof_verifier.verify_trace(
            session,
            paths,
            acceptance=self._acceptance,
            armed_zero=self._armed_zero,
            query_count=query_count,
        )


def _default_provider_gate_preflight(receipt: PhysicalAcceptanceReceipt) -> None:
    """Require the targetd one-shot consume API before any physical CALL."""

    if isinstance(receipt, DebugUserAttestedAcceptanceReceipt):
        try:
            from rolo.targetd import landerpi_motion_target

            consumer = landerpi_motion_target.consume_debug_user_attested_provider_gate
        except (AttributeError, ImportError) as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_DEBUG_PROVIDER_GATE_API_UNAVAILABLE",
                "targetd does not expose the debug-only provider-boundary consume API",
            ) from exc
        ready = (
            receipt.status == "DEBUG_ACCEPTED"
            and receipt.debug_gate_ready
            and receipt.production_ready is False
            and receipt.production_authority_verified is False
            and receipt.provider_boundary_open is False
        )
    else:
        try:
            from rolo.targetd import motion_acceptance

            consumer = motion_acceptance.consume_provider_gate_challenge
        except (AttributeError, ImportError) as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_PROVIDER_GATE_API_UNAVAILABLE",
                "targetd does not expose the one-shot provider-boundary consume API",
            ) from exc
        ready = receipt.ready_for_provider_gate
    if not callable(consumer) or not ready:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_PROVIDER_GATE_API_UNAVAILABLE",
            "provider gate consumption is unavailable or acceptance is not ready",
        )


def _tool_call_count(session: Any, call_id: str) -> int:
    return sum(
        1
        for event in getattr(session, "events", ())
        if getattr(event, "event", None) == "TOOL_CALL"
        and getattr(event, "idempotency_key", None) == call_id
    )


def _last_trace_result(session: Any, call_id: str) -> dict[str, Any]:
    matches = [
        getattr(event, "result", None)
        for event in getattr(session, "events", ())
        if getattr(event, "idempotency_key", None) == call_id
        and getattr(event, "event", None) in {"TOOL_RESULT", "TOOL_RESULT_RECONCILED"}
    ]
    if not matches or not isinstance(matches[-1], Mapping):
        return {}
    return dict(matches[-1])


def _exact_count(value: object, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise N7PhysicalBlocked("N7_PHYSICAL_PROVIDER_COUNT_INVALID", "provider invocation count is invalid")
    return value


@dataclass(frozen=True)
class N7PhysicalTraceInputs:
    run_id: str
    session_id: str
    call_id: str
    user_attestation: str
    target_id: str = TARGET_ID
    spec: MotionSpec = field(default_factory=MotionSpec)

    def __post_init__(self) -> None:
        for value in (self.run_id, self.session_id, self.call_id, self.target_id):
            if not isinstance(value, str) or _ID.fullmatch(value) is None:
                raise ValueError("N7 physical Trace identity is invalid")
        if self.target_id != TARGET_ID:
            raise ValueError("N7 physical Trace target must be mentorpi")
        if (
            not isinstance(self.user_attestation, str)
            or not self.user_attestation.strip()
            or len(self.user_attestation.encode("utf-8")) > 4096
            or "\x00" in self.user_attestation
        ):
            raise ValueError("N7 field-debug user attestation is invalid")


class N7PhysicalTraceRunner:
    """Orchestrate one bounded physical Trace and immutable evidence set."""

    _ARTIFACT_NAMES = (
        "stage.json",
        "user-attestation.json",
        "baseline.json",
        "baseline-liveness-initial.json",
        "baseline-after-restart.json",
        "bringup-preflight-restart.json",
        "baseline-liveness.json",
        "isolation.json",
        "prearm.json",
        "prearm-graph.json",
        "prearm-liveness.json",
        "zero-motion-acceptance.json",
        "trace-attempt.json",
        "post-trace.json",
        "authenticated-stop.json",
        "post-stop.json",
        "host-finalize.json",
        "restore.json",
        "cleanup.json",
        "outcome.json",
        "artifact-index.json",
    )

    def __init__(
        self,
        artifact_root: Path,
        *,
        artifact_signing_key: bytes,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(artifact_signing_key, bytes) or not 32 <= len(artifact_signing_key) <= 4096:
            raise ValueError("N7 artifact signing key must contain 32-4096 bytes")
        self.artifact_root = Path(os.path.abspath(os.fspath(artifact_root)))
        self.artifact_signing_key = artifact_signing_key
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def run(
        self,
        inputs: N7PhysicalTraceInputs,
        *,
        channel: LanderPiControlChannel,
        acceptance: ZeroMotionAcceptanceDriver | Callable[[], ZeroMotionAcceptanceReceipt | Mapping[str, Any]],
        trace: PhysicalTraceDriver,
    ) -> dict[str, Any]:
        run_dir = self._create_run_directory(inputs.run_id)
        stage_root = stage_root_for(inputs.run_id)
        files: list[Path] = []
        stage_possible = False
        restore_required = False
        trace_submitted = False
        worker_armed = False
        query_count = 0
        post_trace_isolated = False
        report: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "status": "BLOCKED",
            "run_id": inputs.run_id,
            "session_id": inputs.session_id,
            "call_id": inputs.call_id,
            "target_id": inputs.target_id,
            "motion": inputs.spec.arguments(),
            "authority_class": "DEBUG_ONLY_USER_ATTESTED",
            "production_authority": False,
            "fresh_estop_challenge_verified": False,
            "onsite_safety_drill_performed": False,
            "stage_root": stage_root,
            "channel_id": channel.channel_id,
            "call_attempt_count": 0,
            "query_attempt_count": 0,
            "provider_invocation_count": 0,
            "started_at": self._now(),
            "completed_at": None,
            "blockers": [],
        }
        failure: N7PhysicalBlocked | None = None
        attempt: TraceAttempt | None = None
        authenticated_stop: AuthenticatedStopReceipt | None = None
        safe_post: ControlGraphSnapshot | None = None
        try:
            attestation = {
                "schema_version": "rolo-n7-debug-user-attestation/v1",
                "authority_class": "DEBUG_ONLY_USER_ATTESTED",
                "production_authority": False,
                "session_id": inputs.session_id,
                "call_id": inputs.call_id,
                "target_id": inputs.target_id,
                "motion": inputs.spec.arguments(),
                "statement": inputs.user_attestation,
                "recorded_at": report["started_at"],
                "onsite_safety_drill_performed": False,
            }
            attestation["attestation_digest"] = _digest(attestation)
            report["user_attestation_digest"] = attestation["attestation_digest"]
            files.append(self._write(run_dir, "user-attestation.json", attestation))

            stage_possible = True
            stage = dict(channel.stage(run_id=inputs.run_id, stage_root=stage_root))
            self._validate_stage(stage, inputs=inputs, stage_root=stage_root)
            files.append(self._write(run_dir, "stage.json", stage))

            baseline_raw = dict(channel.snapshot(stage_root=stage_root, phase="BASELINE"))
            baseline = ControlGraphSnapshot.parse(baseline_raw, phase="BASELINE")
            baseline.require_baseline()
            files.append(self._write(run_dir, "baseline.json", baseline.as_dict()))

            baseline_health = FreshSensorHealthReceipt.parse(
                channel.sample_health(
                    stage_root=stage_root,
                    phase="BASELINE",
                    graph_topology_digest=baseline.topology_digest(),
                ),
                phase="BASELINE",
                stage_root=stage_root,
                graph_topology_digest=baseline.topology_digest(),
            )
            if not baseline_health.healthy:
                files.append(
                    self._write(
                        run_dir,
                        "baseline-liveness-initial.json",
                        baseline_health.as_dict(),
                    )
                )
                restart = dict(
                    channel.restart_bringup_once(
                        stage_root=stage_root,
                        expected_processes=baseline.processes,
                    )
                )
                self._validate_preflight_restart(restart, stage_root=stage_root)
                files.append(
                    self._write(
                        run_dir,
                        "bringup-preflight-restart.json",
                        restart,
                    )
                )
                baseline = ControlGraphSnapshot.parse(
                    restart.get("snapshot"),
                    phase="BASELINE",
                )
                baseline.require_baseline()
                files.append(
                    self._write(
                        run_dir,
                        "baseline-after-restart.json",
                        baseline.as_dict(),
                    )
                )
                baseline_health = FreshSensorHealthReceipt.parse(
                    channel.sample_health(
                        stage_root=stage_root,
                        phase="BASELINE",
                        graph_topology_digest=baseline.topology_digest(),
                    ),
                    phase="BASELINE",
                    stage_root=stage_root,
                    graph_topology_digest=baseline.topology_digest(),
                )
            files.append(
                self._write(
                    run_dir,
                    "baseline-liveness.json",
                    baseline_health.as_dict(),
                )
            )
            baseline_health.require_healthy()

            # The response may be lost after SIGTERM.  From this point onward
            # restoration is mandatory even when isolation returns no receipt.
            restore_required = True
            isolation = dict(
                channel.isolate(
                    stage_root=stage_root,
                    expected_processes=baseline.processes,
                )
            )
            isolated_raw = isolation.get("snapshot")
            isolated = ControlGraphSnapshot.parse(isolated_raw, phase="ISOLATED")
            isolated.require_isolated()
            terminated = isolation.get("terminated_processes")
            if not isinstance(terminated, list) or tuple(
                sorted((PublisherProcessIdentity.parse(item) for item in terminated), key=lambda item: item.node_id)
            ) != baseline.processes:
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_ISOLATION_RECEIPT_INVALID",
                    "isolation did not bind every exact publisher process identity",
                )
            files.append(self._write(run_dir, "isolation.json", isolation))

            # Static and live motion evidence requires the intended Rolo ROS
            # identity to exist.  Pre-arm creates that one dormant publisher
            # while keeping provider count and command emission at zero.
            # Treat a lost pre-arm response as an active worker until an
            # authenticated STOP proves otherwise.
            worker_armed = True
            prearm = PrearmedProviderReceipt.parse(trace.prepare_zero_motion(inputs.spec))
            if prearm.session_id != inputs.session_id or prearm.call_id != inputs.call_id:
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_PREARM_IDENTITY_MISMATCH",
                    "pre-arm worker does not belong to this Trace call",
                )
            files.append(self._write(run_dir, "prearm.json", prearm.as_dict()))
            prearm_graph_raw = dict(channel.snapshot(stage_root=stage_root, phase="PREARMED"))
            prearm_graph = ControlGraphSnapshot.parse(prearm_graph_raw, phase="PREARMED")
            prearm_graph.require_prearmed()
            files.append(self._write(run_dir, "prearm-graph.json", prearm_graph.as_dict()))
            prearm_health = FreshSensorHealthReceipt.parse(
                channel.sample_health(
                    stage_root=stage_root,
                    phase="PREARMED",
                    graph_topology_digest=prearm_graph.topology_digest(),
                ),
                phase="PREARMED",
                stage_root=stage_root,
                graph_topology_digest=prearm_graph.topology_digest(),
            )
            files.append(
                self._write(
                    run_dir,
                    "prearm-liveness.json",
                    prearm_health.as_dict(),
                )
            )
            prearm_health.require_healthy()

            raw_acceptance = acceptance.run() if hasattr(acceptance, "run") else acceptance()
            payload = (
                raw_acceptance.model_dump(mode="python")
                if isinstance(
                    raw_acceptance,
                    (
                        ZeroMotionAcceptanceReceipt,
                        DebugUserAttestedAcceptanceReceipt,
                    ),
                )
                else raw_acceptance
            )
            try:
                if not isinstance(payload, Mapping):
                    raise TypeError("receipt must be an object")
                if (
                    payload.get("schema_version")
                    == "rolo-debug-user-attested-zero-motion-acceptance/v1"
                ):
                    receipt: PhysicalAcceptanceReceipt = (
                        DebugUserAttestedAcceptanceReceipt.model_validate(payload)
                    )
                elif (
                    payload.get("schema_version")
                    == "rolo-targetd-zero-motion-acceptance-receipt/v1"
                ):
                    receipt = ZeroMotionAcceptanceReceipt.model_validate(payload)
                else:
                    raise ValueError("unsupported acceptance schema")
            except (TypeError, ValueError) as exc:
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_ACCEPTANCE_RECEIPT_INVALID",
                    "zero-motion acceptance receipt is invalid",
                ) from exc
            self._validate_acceptance(receipt, inputs)
            files.append(
                self._write(
                    run_dir,
                    "zero-motion-acceptance.json",
                    receipt.model_dump(mode="python"),
                )
            )

            # Feature-detect the one-shot targetd consume path *before* CALL.
            # Consumption itself remains at the provider boundary.
            trace.preflight_provider_gate(receipt)
            trace_submitted = True
            attempt = trace.start_once(receipt, inputs.spec)
            self._validate_attempt(attempt, inputs=inputs, expected_queries=0)
            if attempt.status == "UNKNOWN":
                # Exactly one target receipt query is permitted.  This is not
                # a CALL retry and the driver must prove the durable TOOL_CALL.
                query_count = 1
                attempt = trace.query_once(inputs.call_id)
                self._validate_attempt(attempt, inputs=inputs, expected_queries=1)
            files.append(self._write(run_dir, "trace-attempt.json", attempt.as_dict()))

            post_raw = dict(channel.snapshot(stage_root=stage_root, phase="POST_TRACE"))
            post = ControlGraphSnapshot.parse(post_raw, phase="POST_TRACE")
            post.require_isolated()
            post_trace_isolated = True
            safe_post = post
            files.append(self._write(run_dir, "post-trace.json", post.as_dict()))

            report.update(
                {
                    "status": (
                        "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
                        if attempt.status == "SUCCEEDED"
                        else attempt.status
                    ),
                    "report_status": (
                        "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
                        if attempt.status == "SUCCEEDED"
                        else attempt.status
                    ),
                    "call_attempt_count": attempt.call_attempt_count,
                    "query_attempt_count": attempt.query_attempt_count,
                    "provider_invocation_count": attempt.provider_invocation_count,
                    "provider_gate_consumed": attempt.provider_gate_consumed,
                    "controlled_publisher_identities": list(attempt.controlled_publisher_identities),
                    "final_zero_verified": attempt.final_zero_verified,
                    "stop_acknowledged": attempt.stop_acknowledged,
                    "provider_terminated": attempt.provider_terminated,
                }
            )
            if attempt.status == "SUCCEEDED" and not (
                attempt.call_attempt_count == 1
                and attempt.provider_invocation_count == 1
                and attempt.provider_gate_consumed
                and attempt.controlled_publisher_identities == (ROLO_PUBLISHER,)
                and attempt.final_zero_verified
                and attempt.stop_acknowledged
                and attempt.provider_terminated
            ):
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_SUCCESS_EVIDENCE_INCOMPLETE",
                    "successful motion lacks one-shot gate, final zero, stop, or provider-count proof",
                )
        except N7PhysicalBlocked as exc:
            failure = exc
        except Exception as exc:  # noqa: BLE001 - sanitize at the field-debug boundary
            failure = N7PhysicalBlocked(
                "N7_PHYSICAL_UNEXPECTED_FAILURE",
                f"unexpected fail-closed boundary: {type(exc).__name__}",
            )
        finally:
            safe_to_restore = (
                not worker_armed
                or (
                    attempt is not None
                    and attempt.status in {"SUCCEEDED", "BLOCKED", "FAILED"}
                    and attempt.final_zero_verified
                    and attempt.stop_acknowledged
                    and attempt.provider_terminated
                    and post_trace_isolated
                )
            )
            if worker_armed and not safe_to_restore:
                try:
                    authenticated_stop = AuthenticatedStopReceipt.parse(
                        trace.stop_once(inputs.call_id)
                    )
                    files.append(
                        self._write(
                            run_dir,
                            "authenticated-stop.json",
                            authenticated_stop.as_dict(),
                        )
                    )
                    report["authenticated_stop"] = authenticated_stop.as_dict()
                    if not authenticated_stop.safe_to_restore:
                        raise N7PhysicalBlocked(
                            "N7_PHYSICAL_STOP_NOT_VERIFIED",
                            "authenticated STOP did not prove final zero, target acknowledgement, and provider exit",
                        )
                    post_stop_raw = dict(channel.snapshot(stage_root=stage_root, phase="POST_STOP"))
                    post_stop = ControlGraphSnapshot.parse(post_stop_raw, phase="POST_STOP")
                    post_stop.require_isolated()
                    safe_post = post_stop
                    files.append(self._write(run_dir, "post-stop.json", post_stop.as_dict()))
                    safe_to_restore = True
                except Exception as exc:  # noqa: BLE001 - unsafe means preserve isolation
                    safe_to_restore = False
                    prior = failure.code if failure is not None else None
                    failure = (
                        exc
                        if isinstance(exc, N7PhysicalBlocked)
                        else N7PhysicalBlocked(
                            "N7_PHYSICAL_STOP_NOT_VERIFIED",
                            f"authenticated STOP could not be proven: {type(exc).__name__}",
                        )
                    )
                    if prior is not None and prior != failure.code:
                        report["prior_blocker"] = prior

            preserve_stage = restore_required and not safe_to_restore
            if restore_required and safe_to_restore:
                try:
                    finalize = getattr(channel, "finalize_before_restore", None)
                    if callable(finalize):
                        if safe_post is None:
                            raise N7PhysicalBlocked(
                                "N7_PHYSICAL_HOST_FINALIZE_PROOF_INVALID",
                                "host finalization has no isolated post-terminal graph",
                            )
                        host_finalize = dict(
                            finalize(
                                stage_root=stage_root,
                                inputs=inputs,
                                attempt=attempt,
                                authenticated_stop=authenticated_stop,
                                post_snapshot=safe_post,
                            )
                        )
                        self._validate_host_finalize_before_restore(
                            host_finalize,
                            inputs=inputs,
                            stage_root=stage_root,
                            post_snapshot=safe_post,
                        )
                        files.append(
                            self._write(
                                run_dir,
                                "host-finalize.json",
                                host_finalize,
                            )
                        )
                        report["host_finalize_verified"] = True
                    restored = dict(channel.restore(stage_root=stage_root))
                    self._validate_restore(restored, stage_root=stage_root)
                    restored_graph = ControlGraphSnapshot.parse(restored.get("snapshot"), phase="RESTORED")
                    restored_graph.require_baseline()
                    files.append(self._write(run_dir, "restore.json", restored))
                    report["restore_verified"] = True
                except Exception as exc:  # noqa: BLE001 - cleanup evidence must still publish
                    report["restore_verified"] = False
                    preserve_stage = True
                    prior = failure.code if failure is not None else None
                    failure = (
                        exc
                        if isinstance(exc, N7PhysicalBlocked)
                        else N7PhysicalBlocked(
                            "N7_PHYSICAL_RESTORE_NOT_VERIFIED",
                            "bringup restoration was not verified: "
                            f"{type(exc).__name__}",
                        )
                    )
                    if prior is not None and prior != failure.code:
                        report["prior_blocker"] = prior
            elif restore_required:
                report["restore_verified"] = False
                report["control_publishers_left_isolated"] = True
                report["manual_intervention_required"] = True
            if stage_possible and not preserve_stage:
                try:
                    cleanup = dict(channel.cleanup(stage_root=stage_root))
                    if (
                        cleanup.get("schema_version") != "rolo-n7-stage-cleanup/v1"
                        or cleanup.get("stage_root") != stage_root
                        or cleanup.get("residual_count") != 0
                    ):
                        raise ValueError("cleanup receipt mismatch")
                    files.append(self._write(run_dir, "cleanup.json", cleanup))
                    report["stage_cleanup_verified"] = True
                except Exception as exc:  # noqa: BLE001 - preserve primary failure if present
                    report["stage_cleanup_verified"] = False
                    if failure is None:
                        failure = N7PhysicalBlocked(
                            "N7_PHYSICAL_STAGE_CLEANUP_NOT_VERIFIED",
                            f"exact tmpfs stage cleanup was not verified: {type(exc).__name__}",
                        )
            elif stage_possible:
                report["stage_cleanup_verified"] = False
                report["stage_preserved_for_recovery"] = True

        report["call_attempt_count"] = (
            attempt.call_attempt_count if attempt is not None else (1 if trace_submitted else 0)
        )
        report["query_attempt_count"] = attempt.query_attempt_count if attempt is not None else query_count
        report["provider_invocation_count"] = attempt.provider_invocation_count if attempt is not None else 0
        if failure is not None:
            report["status"] = (
                "UNKNOWN"
                if trace_submitted or report.get("manual_intervention_required") is True
                else "BLOCKED"
            )
            report["blockers"] = [failure.code]
            report["message"] = failure.message
        report["completed_at"] = self._now()
        files.append(self._write(run_dir, "outcome.json", report))
        index = build_artifact_index(
            run_id=inputs.run_id,
            target_id=inputs.target_id,
            files=files,
            root=run_dir,
            secret=self.artifact_signing_key,
        )
        index.verify(self.artifact_signing_key)
        index_path = self._write(run_dir, "artifact-index.json", index.model_dump(mode="python"))
        report["artifact_index"] = str(index_path.resolve())
        report["artifact_index_manifest"] = index.manifest_sha256
        return report

    def _create_run_directory(self, run_id: str) -> Path:
        stage_root_for(run_id)
        for ancestor in (self.artifact_root, *self.artifact_root.parents):
            if ancestor.exists() and (_is_link_or_reparse(ancestor) or not ancestor.is_dir()):
                raise N7PhysicalBlocked("N7_PHYSICAL_ARTIFACT_ROOT_UNSAFE", "artifact root is unsafe")
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        run_dir = self.artifact_root / run_id
        try:
            run_dir.mkdir(mode=0o700, exist_ok=False)
        except FileExistsError as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_ARTIFACT_RUN_EXISTS",
                "run artifacts are immutable and this run id already exists",
            ) from exc
        return run_dir

    def _write(self, run_dir: Path, name: str, value: Any) -> Path:
        if name not in self._ARTIFACT_NAMES:
            raise N7PhysicalBlocked("N7_PHYSICAL_ARTIFACT_NAME_INVALID", "artifact name is not fixed")
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
            default=_json_default,
        ) + "\n"
        if len(encoded.encode("utf-8")) > 4 * 1024 * 1024:
            raise N7PhysicalBlocked("N7_PHYSICAL_ARTIFACT_TOO_LARGE", "artifact exceeds 4 MiB")
        path = run_dir / name
        write_new_artifact(path, encoded)
        return path

    def _now(self) -> datetime:
        point = self.clock()
        if not isinstance(point, datetime) or point.tzinfo is None or point.utcoffset() is None:
            raise N7PhysicalBlocked("N7_PHYSICAL_CLOCK_INVALID", "clock must be timezone-aware")
        return point.astimezone(timezone.utc)

    @staticmethod
    def _validate_stage(stage: Mapping[str, Any], *, inputs: N7PhysicalTraceInputs, stage_root: str) -> None:
        if (
            stage.get("schema_version") != "rolo-n7-stage-receipt/v1"
            or stage.get("ok") is not True
            or stage.get("run_id") != inputs.run_id
            or stage.get("stage_root") != stage_root
            or stage.get("container") != CONTAINER
            or not isinstance(stage.get("stage_nonce_digest"), str)
            or _SHA256.fullmatch(str(stage.get("stage_nonce_digest"))) is None
        ):
            raise N7PhysicalBlocked("N7_PHYSICAL_STAGE_RECEIPT_INVALID", "exact tmpfs stage was not proven")

    @staticmethod
    def _validate_preflight_restart(restart: Mapping[str, Any], *, stage_root: str) -> None:
        if (
            restart.get("schema_version") != "rolo-n7-bringup-preflight-restart/v1"
            or restart.get("ok") is not True
            or restart.get("stage_root") != stage_root
            or restart.get("restart_count") != 1
            or not isinstance(restart.get("previous_group"), Mapping)
            or not isinstance(restart.get("replacement_group"), Mapping)
            or not isinstance(restart.get("snapshot"), Mapping)
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_BRINGUP_RESTART_INVALID",
                "one-time preflight bringup restart receipt is invalid",
            )
        previous = N7PhysicalTraceRunner._validate_bringup_group(restart["previous_group"])
        replacement = N7PhysicalTraceRunner._validate_bringup_group(restart["replacement_group"])
        if previous == replacement or restart.get("stop_signal") not in {"SIGINT", "SIGINT_THEN_SIGTERM"}:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_BRINGUP_RESTART_INVALID",
                "preflight restart did not replace the exact bringup process group",
            )

    @staticmethod
    def _validate_restore(restored: Mapping[str, Any], *, stage_root: str) -> None:
        if (
            restored.get("schema_version") != "rolo-n7-bringup-restore/v1"
            or restored.get("ok") is not True
            or restored.get("stage_root") != stage_root
            or not isinstance(restored.get("snapshot"), Mapping)
            or restored.get("stop_signal") not in {"SIGINT", "SIGINT_THEN_SIGTERM"}
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_RESTORE_RECEIPT_INVALID",
                "bringup restoration receipt is incomplete",
            )
        previous = N7PhysicalTraceRunner._validate_bringup_group(
            restored.get("previous_group")
        )
        replacement = N7PhysicalTraceRunner._validate_bringup_group(
            restored.get("replacement_group")
        )
        if previous == replacement:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_RESTORE_RECEIPT_INVALID",
                "bringup restoration reused the prior process group identity",
            )

    @staticmethod
    def _validate_host_finalize_before_restore(
        receipt: Mapping[str, Any],
        *,
        inputs: N7PhysicalTraceInputs,
        stage_root: str,
        post_snapshot: ControlGraphSnapshot,
    ) -> None:
        if (
            receipt.get("schema_version")
            != "rolo-n7-targetd-host-finalize-receipt/v1"
            or receipt.get("status") != "SAFE_TO_CLEANUP"
            or receipt.get("run_id") != inputs.run_id
            or receipt.get("stage_root") is None
            or receipt.get("target_id") != inputs.target_id
            or receipt.get("session_id") != inputs.session_id
            or receipt.get("call_id") != inputs.call_id
            or receipt.get("final_zero_verified") is not True
            or receipt.get("stop_acknowledged") is not True
            or receipt.get("provider_terminated") is not True
            or receipt.get("post_isolated") is not True
            or receipt.get("post_isolated_topology_digest")
            != post_snapshot.topology_digest()
            or receipt.get("worker_terminal_revalidated") is not True
            or receipt.get("stage_cleanup_authorized") is not True
            or _SHA256.fullmatch(
                str(receipt.get("post_isolated_graph_revision"))
            )
            is None
            or _SHA256.fullmatch(str(receipt.get("receipt_payload_sha256")))
            is None
            or not isinstance(receipt.get("receipt_auth_tag"), str)
            or re.fullmatch(
                r"hmac-sha256:[0-9a-f]{64}",
                str(receipt.get("receipt_auth_tag")),
            )
            is None
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_FINALIZE_RECEIPT_INVALID",
                "host targetd did not prove safe finalization before restore",
            )
    @staticmethod
    def _validate_bringup_group(value: object) -> str:
        expected_group = {"leader_pid", "pgid", "sid", "members", "group_digest"}
        expected_member = {
            "pid",
            "start_ticks",
            "argv_sha256",
            "executable",
            "pgid",
            "sid",
        }
        if not isinstance(value, Mapping) or set(value) != expected_group:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_BRINGUP_GROUP_INVALID",
                "bringup process group receipt has an invalid shape",
            )
        leader = value.get("leader_pid")
        pgid = value.get("pgid")
        sid = value.get("sid")
        members = value.get("members")
        if (
            isinstance(leader, bool)
            or not isinstance(leader, int)
            or leader <= 1
            or pgid != leader
            or sid != leader
            or not isinstance(members, list)
            or not 1 <= len(members) <= 128
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_BRINGUP_GROUP_INVALID",
                "bringup process group leader or cardinality is invalid",
            )
        pids: list[int] = []
        for member in members:
            if not isinstance(member, Mapping) or set(member) != expected_member:
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_BRINGUP_GROUP_INVALID",
                    "bringup process group member has an invalid shape",
                )
            pid = member.get("pid")
            start = member.get("start_ticks")
            executable = member.get("executable")
            if (
                isinstance(pid, bool)
                or not isinstance(pid, int)
                or pid <= 1
                or isinstance(start, bool)
                or not isinstance(start, int)
                or start <= 0
                or member.get("pgid") != pgid
                or member.get("sid") != sid
                or not isinstance(executable, str)
                or not any(
                    executable == prefix or (prefix.endswith("/") and executable.startswith(prefix))
                    for prefix in BRINGUP_MEMBER_EXECUTABLE_PREFIXES
                )
                or not isinstance(member.get("argv_sha256"), str)
                or _SHA256.fullmatch(str(member.get("argv_sha256"))) is None
            ):
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_BRINGUP_GROUP_INVALID",
                    "bringup process group member identity is invalid",
                )
            pids.append(pid)
        digest_value = value.get("group_digest")
        unsigned = {field: value[field] for field in ("leader_pid", "pgid", "sid", "members")}
        if (
            len(pids) != len(set(pids))
            or leader not in pids
            or not isinstance(digest_value, str)
            or digest_value != _digest(unsigned)
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_BRINGUP_GROUP_INVALID",
                "bringup process group digest does not verify",
            )
        return digest_value

    @staticmethod
    def _validate_acceptance(
        receipt: PhysicalAcceptanceReceipt,
        inputs: N7PhysicalTraceInputs,
    ) -> None:
        if isinstance(receipt, DebugUserAttestedAcceptanceReceipt):
            gate = receipt.provider_gate
            attestation = receipt.debug_attestation_artifact
            expected_basis_digest = compute_motion_payload_digest(
                {
                    "schema_version": "rolo-debug-user-attestation-basis/v1",
                    "basis_text": inputs.user_attestation,
                }
            )
            if (
                receipt.status != "DEBUG_ACCEPTED"
                or receipt.report_status
                != "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
                or receipt.call_id != inputs.call_id
                or receipt.session_id != inputs.session_id
                or receipt.target_id != inputs.target_id
                or not receipt.debug_gate_ready
                or receipt.production_ready is not False
                or receipt.production_authority_verified is not False
                or receipt.fresh_estop_challenge_verified is not False
                or receipt.motion_authorized is not False
                or receipt.provider_boundary_open is not False
                or receipt.max_abs_rotation_degrees != 1.0
                or receipt.max_abs_linear_meters != 0.03
                or inputs.spec.angle_degrees != 1.0
                or inputs.spec.max_speed_rad_s != 0.03
                or gate is None
                or gate.claims.get("one_shot") is not True
                or gate.claims.get("consumed") is not False
                or attestation is None
                or attestation.claims.get("basis_digest")
                != expected_basis_digest
                or attestation.claims.get("production_ready") is not False
            ):
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_DEBUG_ACCEPTANCE_BLOCKED",
                    "debug acceptance is not the exact bounded, user-attested, unconsumed target gate",
                )
            TargetdPhysicalProofVerifier._verify_fresh_zero_claims(
                gate.claims,
                artifact_issued_at=gate.issued_at,
            )
            return
        if (
            receipt.status != "READY_FOR_PROVIDER_GATE"
            or receipt.call_id != inputs.call_id
            or receipt.session_id != inputs.session_id
            or receipt.target_id != inputs.target_id
            or receipt.motion_authorized is not False
            or receipt.motion_command_emitted is not False
            or receipt.provider_invocation_count != 0
            or receipt.requires_live_provider_cas is not True
            or receipt.command_route != COMMAND_ROUTE
            or receipt.command_interface != COMMAND_INTERFACE
            or receipt.publisher_identity != "/rolo_bounded_twist"
            or receipt.direct_motor_route != DIRECT_MOTOR_ROUTE
            or receipt.direct_motor_publisher_identity != "/odom_publisher"
            or receipt.provider_gate is None
            or receipt.provider_gate.claims.get("one_shot") is not True
            or receipt.provider_gate.claims.get("consumed") is not False
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_ZERO_MOTION_ACCEPTANCE_BLOCKED",
                "zero-motion acceptance is not an exact, unconsumed provider-gate challenge",
            )
        TargetdPhysicalProofVerifier._verify_fresh_zero_claims(
            receipt.provider_gate.claims,
            artifact_issued_at=receipt.provider_gate.issued_at,
        )

    @staticmethod
    def _validate_attempt(attempt: TraceAttempt, *, inputs: N7PhysicalTraceInputs, expected_queries: int) -> None:
        if (
            not isinstance(attempt, TraceAttempt)
            or attempt.session_id != inputs.session_id
            or attempt.call_id != inputs.call_id
            or attempt.call_attempt_count != 1
            or attempt.query_attempt_count != expected_queries
            or isinstance(attempt.provider_invocation_count, bool)
            or not 0 <= attempt.provider_invocation_count <= 1
            or len(attempt.controlled_publisher_identities)
            != len(set(attempt.controlled_publisher_identities))
            or (
                attempt.status == "SUCCEEDED"
                and attempt.controlled_publisher_identities != (ROLO_PUBLISHER,)
            )
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TRACE_RECEIPT_INVALID",
                "ReleaseBoundTrace did not retain the exact single-call identity",
            )


def _is_link_or_reparse(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except FileNotFoundError:
        return False
    return path.is_symlink() or bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


@dataclass(frozen=True)
class _RpcResult:
    returncode: int
    stdout: bytes
    stderr: bytes


RpcRunner = Callable[[list[str], bytes, float], _RpcResult]
PublicKeyDeriver = Callable[[Path], bytes | str]


def _subprocess_rpc(argv: list[str], payload: bytes, timeout_s: float) -> _RpcResult:
    completed = subprocess.run(
        argv,
        input=payload,
        capture_output=True,
        check=False,
        shell=False,
        timeout=timeout_s,
    )
    return _RpcResult(completed.returncode, completed.stdout, completed.stderr)


def _derive_ssh_public_key(identity_file: Path) -> bytes:
    """Derive the key SSH will actually use without invoking a shell."""

    try:
        completed = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(identity_file)],
            input=b"",
            capture_output=True,
            check=False,
            shell=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("SSH private-key public identity could not be derived") from exc
    if completed.returncode != 0 or not completed.stdout or len(completed.stdout) > 16 * 1024:
        raise ValueError("SSH private-key public identity could not be derived")
    return completed.stdout


def _normalize_openssh_public_key(value: bytes | str) -> tuple[bytes, bytes]:
    """Return canonical ``type blob`` bytes and the decoded SSH key blob."""

    try:
        raw = value.encode("ascii") if isinstance(value, str) else bytes(value)
        text = raw.decode("ascii")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise ValueError("OpenSSH public key is invalid") from exc
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 1 or not 32 <= len(lines[0].encode("ascii")) <= 16 * 1024:
        raise ValueError("OpenSSH public key is invalid")
    fields = lines[0].split()
    if (
        len(fields) < 2
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@._+-]{2,127}", fields[0]) is None
        or re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", fields[1]) is None
    ):
        raise ValueError("OpenSSH public key is invalid")
    try:
        blob = base64.b64decode(fields[1].encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("OpenSSH public key is invalid") from exc
    if not 16 <= len(blob) <= 16 * 1024:
        raise ValueError("OpenSSH public key is invalid")
    canonical = f"{fields[0]} {base64.b64encode(blob).decode('ascii')}".encode("ascii")
    return canonical, blob


def _parse_known_hosts_pin(
    value: bytes,
    *,
    host: str,
    port: int,
) -> tuple[bytes, bytes]:
    """Resolve one literal known-hosts entry for the exact SSH endpoint.

    The live debug peer receipt must describe the key that OpenSSH is actually
    configured to enforce.  Hashed hosts, patterns, markers, revoked entries,
    and multiple matching keys are intentionally rejected because they cannot
    be represented as one exact ``target:port -> key blob`` binding.
    """

    try:
        text = value.decode("ascii")
    except UnicodeError as exc:
        raise ValueError("known-hosts pin is invalid") from exc
    literal_names = {f"[{host}]:{port}"}
    if port == 22:
        literal_names.add(host)
    matches: list[tuple[bytes, bytes]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 3 or fields[0].startswith("@"):
            continue
        names = fields[0].split(",")
        if any(
            not name
            or name.startswith(("|", "!"))
            or any(character in name for character in "*?")
            for name in names
        ):
            continue
        if not literal_names.intersection(names):
            continue
        matches.append(
            _normalize_openssh_public_key(f"{fields[1]} {fields[2]}")
        )
    if len(matches) != 1:
        raise ValueError("known-hosts pin must contain one exact endpoint key")
    return matches[0]


@dataclass(frozen=True)
class PinnedSshConfiguration:
    host: str
    user: str
    known_hosts: Path
    identity_file: Path
    public_key_file: Path | None = None
    port: int = 22
    timeout_s: float = 60.0
    public_key_deriver: PublicKeyDeriver = field(
        default=_derive_ssh_public_key,
        repr=False,
        compare=False,
    )
    _canonical_public_key: bytes = field(init=False, repr=False, compare=False)
    _public_key_blob: bytes = field(init=False, repr=False, compare=False)
    _known_hosts_bytes: bytes = field(init=False, repr=False, compare=False)
    _host_key_blob: bytes = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        known_hosts = Path(self.known_hosts).expanduser().resolve()
        identity_file = Path(self.identity_file).expanduser().resolve()
        public_key_file = (
            Path(self.public_key_file).expanduser().resolve()
            if self.public_key_file is not None
            else identity_file.with_suffix(identity_file.suffix + ".pub")
        )
        if (
            _HOST.fullmatch(self.host) is None
            or self.host.startswith("-")
            or _USER.fullmatch(self.user) is None
            or self.user.startswith("-")
            or isinstance(self.port, bool)
            or not 1 <= self.port <= 65535
            or not 5 <= self.timeout_s <= 120
            or not known_hosts.is_file()
            or known_hosts.is_symlink()
            or not 32 <= known_hosts.stat().st_size <= 64 * 1024
            or not identity_file.is_file()
            or identity_file.is_symlink()
            or not 1 <= identity_file.stat().st_size <= 64 * 1024
            or not public_key_file.is_file()
            or public_key_file.is_symlink()
            or not 32 <= public_key_file.stat().st_size <= 16 * 1024
            or not callable(self.public_key_deriver)
        ):
            raise ValueError("pinned public-key SSH configuration is invalid")
        try:
            known_hosts_bytes = known_hosts.read_bytes()
            _, host_key_blob = _parse_known_hosts_pin(
                known_hosts_bytes,
                host=self.host,
                port=self.port,
            )
        except (OSError, ValueError) as exc:
            raise ValueError("pinned known-hosts endpoint key is invalid") from exc
        try:
            actual_key, actual_blob = _normalize_openssh_public_key(
                self.public_key_deriver(identity_file)
            )
            declared_key, declared_blob = _normalize_openssh_public_key(
                public_key_file.read_bytes()
            )
        except (OSError, ValueError) as exc:
            raise ValueError("pinned public-key SSH configuration is invalid") from exc
        if actual_key != declared_key or actual_blob != declared_blob:
            raise ValueError("SSH private/public key identity mismatch")
        object.__setattr__(self, "known_hosts", known_hosts)
        object.__setattr__(self, "identity_file", identity_file)
        object.__setattr__(self, "public_key_file", public_key_file)
        object.__setattr__(self, "_canonical_public_key", actual_key)
        object.__setattr__(self, "_public_key_blob", actual_blob)
        object.__setattr__(self, "_known_hosts_bytes", known_hosts_bytes)
        object.__setattr__(self, "_host_key_blob", host_key_blob)

    @property
    def public_key_fingerprint(self) -> str:
        return "sha256:" + hashlib.sha256(self._public_key_blob).hexdigest()

    @property
    def pinned_host_key_fingerprint(self) -> str:
        return "sha256:" + hashlib.sha256(self._host_key_blob).hexdigest()

    @property
    def known_hosts_digest(self) -> str:
        return "sha256:" + hashlib.sha256(self._known_hosts_bytes).hexdigest()

    def argv(self, remote_argv: list[str]) -> list[str]:
        if not remote_argv or any(not item or "\x00" in item for item in remote_argv):
            raise ValueError("remote argv is invalid")
        return [
            "ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ChallengeResponseAuthentication=no",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "PubkeyAuthentication=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-i",
            str(self.identity_file),
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "GlobalKnownHostsFile=none",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            f"ConnectTimeout={min(int(self.timeout_s), 120)}",
            "-p",
            str(self.port),
            "--",
            f"{self.user}@{self.host}",
            *quote_remote_argv(remote_argv),
        ]


class PinnedLanderPiSshChannel:
    """Execute fixed JSON RPC actions inside MentorPi through pinned SSH."""

    def __init__(self, config: PinnedSshConfiguration, *, runner: RpcRunner | None = None) -> None:
        self.config = config
        self.runner = runner or _subprocess_rpc
        public_identity = {
            "host": config.host,
            "user": config.user,
            "port": config.port,
            "known_hosts_digest": config.known_hosts_digest,
            "pinned_host_key_fingerprint": config.pinned_host_key_fingerprint,
            "identity_public_fingerprint": config.public_key_fingerprint,
        }
        self.channel_id = "ssh-publickey:" + hashlib.sha256(_canonical_bytes(public_identity)).hexdigest()
        self._nonce: str | None = None
        self._stage_root: str | None = None
        self._preflight_restart_used = False

    def stage(self, *, run_id: str, stage_root: str) -> Mapping[str, Any]:
        if self._stage_root is not None or stage_root != stage_root_for(run_id):
            raise N7PhysicalBlocked("N7_PHYSICAL_STAGE_IDENTITY_INVALID", "stage identity is invalid or reused")
        self._nonce = os.urandom(32).hex()
        self._stage_root = stage_root
        return self._rpc("STAGE", {"run_id": run_id, "stage_root": stage_root, "nonce": self._nonce})

    def snapshot(self, *, stage_root: str, phase: str) -> Mapping[str, Any]:
        return self._rpc("SNAPSHOT", self._bound(stage_root, phase=phase))

    def sample_health(
        self,
        *,
        stage_root: str,
        phase: Literal["BASELINE", "PREARMED"],
        graph_topology_digest: str,
    ) -> Mapping[str, Any]:
        if phase not in {"BASELINE", "PREARMED"} or _SHA256.fullmatch(graph_topology_digest) is None:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_SENSOR_HEALTH_INVALID",
                "sensor health request is not bound to an accepted graph",
            )
        return self._rpc(
            "SAMPLE_HEALTH",
            self._bound(
                stage_root,
                phase=phase,
                graph_topology_digest=graph_topology_digest,
                sample_window_s=SENSOR_SAMPLE_WINDOW_S,
            ),
        )

    def restart_bringup_once(
        self,
        *,
        stage_root: str,
        expected_processes: tuple[PublisherProcessIdentity, ...],
    ) -> Mapping[str, Any]:
        if self._preflight_restart_used:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_BRINGUP_RESTART_REPLAY",
                "preflight bringup restart is one-shot",
            )
        self._preflight_restart_used = True
        return self._rpc(
            "PREFLIGHT_RESTART",
            self._bound(
                stage_root,
                expected_processes=[item.as_dict() for item in expected_processes],
            ),
        )

    def isolate(
        self,
        *,
        stage_root: str,
        expected_processes: tuple[PublisherProcessIdentity, ...],
    ) -> Mapping[str, Any]:
        return self._rpc(
            "ISOLATE",
            self._bound(
                stage_root,
                expected_processes=[item.as_dict() for item in expected_processes],
            ),
        )

    def restore(self, *, stage_root: str) -> Mapping[str, Any]:
        return self._rpc("RESTORE", self._bound(stage_root))

    def cleanup(self, *, stage_root: str) -> Mapping[str, Any]:
        result = self._rpc("CLEANUP", self._bound(stage_root))
        self._stage_root = None
        self._nonce = None
        self._preflight_restart_used = False
        return result

    def _bound(self, stage_root: str, **values: Any) -> dict[str, Any]:
        if stage_root != self._stage_root or self._nonce is None:
            raise N7PhysicalBlocked("N7_PHYSICAL_STAGE_IDENTITY_INVALID", "RPC is not bound to the exact stage")
        return {"stage_root": stage_root, "nonce": self._nonce, **values}

    def _rpc(self, action: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        request = _canonical_bytes({"action": action, **dict(payload)})
        if len(request) > 64 * 1024:
            raise N7PhysicalBlocked("N7_PHYSICAL_RPC_LIMIT", "remote control request exceeds 64 KiB")
        encoded_source = base64.b64encode(
            zlib.compress(_REMOTE_CONTROL_SOURCE.encode("utf-8"), level=9)
        ).decode("ascii")
        remote_loader = (
            "import base64,zlib;exec(compile(zlib.decompress(base64.b64decode("
            f"'{encoded_source}',validate=True)),"
            "'<rolo-n7-control>','exec'))"
        )
        remote = [
            "docker",
            "exec",
            "-i",
            "-u",
            "ubuntu",
            CONTAINER,
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            _ROS_CONTAINER_EXEC_WRAPPER,
            "rolo-n7-physical",
            "python3",
            "-u",
            "-c",
            remote_loader,
        ]
        try:
            result = self.runner(self.config.argv(remote), request, self.config.timeout_s)
        except subprocess.TimeoutExpired as exc:
            raise N7PhysicalBlocked("N7_PHYSICAL_SSH_TIMEOUT", "pinned SSH RPC timed out") from exc
        if (
            not isinstance(result, _RpcResult)
            or len(result.stdout) > _MAX_RPC_BYTES
            or len(result.stderr) > _MAX_RPC_BYTES
        ):
            raise N7PhysicalBlocked("N7_PHYSICAL_SSH_RESPONSE_INVALID", "pinned SSH RPC result is invalid")
        try:
            response = json.loads(result.stdout.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            if result.returncode != 0:
                diagnostic = _bounded_remote_diagnostic(result.stderr)
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_SSH_REMOTE_EXIT",
                    f"pinned SSH RPC exited rc={result.returncode}; stderr={diagnostic}",
                ) from exc
            raise N7PhysicalBlocked("N7_PHYSICAL_SSH_RESPONSE_INVALID", "pinned SSH response is not JSON") from exc
        if result.returncode != 0 or not isinstance(response, Mapping) or response.get("ok") is not True:
            code = response.get("error") if isinstance(response, Mapping) else None
            if not isinstance(code, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", code) is None:
                code = "N7_PHYSICAL_REMOTE_BLOCKED"
            raise N7PhysicalBlocked(code, "pinned target control action failed closed")
        return dict(response)


def _bounded_remote_diagnostic(stderr: bytes) -> str:
    """Retain a bounded printable diagnostic without trusting remote formatting."""

    digest = hashlib.sha256(stderr).hexdigest()
    decoded = stderr.decode("utf-8", errors="replace")
    printable = "".join(character if 0x20 <= ord(character) <= 0x7E else " " for character in decoded)
    compact = re.sub(r"\s+", " ", printable).strip()
    if len(compact) > _MAX_REMOTE_DIAGNOSTIC_CHARS:
        compact = compact[:_MAX_REMOTE_DIAGNOSTIC_CHARS] + "..."
    if not compact:
        compact = "<empty>"
    return f"{compact} [sha256:{digest}]"


def _encode_host_control_record(value: Mapping[str, Any]) -> bytes:
    encoded = _canonical_bytes(dict(value))
    if not 2 <= len(encoded) <= _MAX_HOST_BOOTSTRAP_BYTES:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_HOST_RECORD_LIMIT",
            "host targetd control record exceeds its fixed byte budget",
        )
    return len(encoded).to_bytes(4, "big") + encoded


class PinnedHostTargetdStdioChannel:
    """One pinned SSH process for stage, bootstrap, and targetd frames.

    A successful stage receipt proves that the same StrictHostKeyChecking and
    public-key-only OpenSSH process has reached the Pi host.  The process is
    then ``exec``-replaced by the disk-backed launcher; no second targetd SSH
    connection and no generic remote command endpoint exists.
    """

    def __init__(
        self,
        config: PinnedSshConfiguration,
        *,
        run_id: str,
        archive: HostTargetdSourceArchive,
        popen_factory: Callable[..., Any] | None = None,
        io_timeout_s: float = 30.0,
    ) -> None:
        stage_root = host_targetd_stage_root_for(run_id)
        if (
            not isinstance(config, PinnedSshConfiguration)
            or not isinstance(archive, HostTargetdSourceArchive)
            or _SHA256.fullmatch(archive.sha256) is None
            or archive.sha256
            != "sha256:" + hashlib.sha256(archive.payload).hexdigest()
            or not 0 < len(archive.payload) <= _MAX_HOST_ARCHIVE_BYTES
            or not 0 < archive.expanded_bytes <= _MAX_HOST_EXPANDED_BYTES
            or not 0 < archive.member_count <= _MAX_HOST_ARCHIVE_MEMBERS
            or isinstance(io_timeout_s, bool)
            or not isinstance(io_timeout_s, (int, float))
            or not 1 <= float(io_timeout_s) <= 120
        ):
            raise ValueError("pinned host targetd channel configuration is invalid")
        self.config = config
        self.run_id = run_id
        self.stage_root = stage_root
        self.archive = archive
        self.io_timeout_s = float(io_timeout_s)
        self._popen_factory = popen_factory or subprocess.Popen
        self._process: Any | None = None
        self._records: queue.Queue[bytes | BaseException] = queue.Queue(maxsize=32)
        self._stderr = bytearray()
        self._stdout_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._write_lock = threading.Lock()
        self._stage_nonce = os.urandom(32).hex()
        self._stage_receipt: dict[str, Any] | None = None
        self._ready_receipt: dict[str, Any] | None = None
        self._finalize_receipt: dict[str, Any] | None = None
        self._poisoned = False

    @property
    def channel_binding_sha256(self) -> str:
        identity = {
            "schema_version": "rolo-n7-targetd-host-channel-binding/v1",
            "run_id": self.run_id,
            "stage_root": self.stage_root,
            "stage_nonce_sha256": (
                "sha256:"
                + hashlib.sha256(self._stage_nonce.encode("ascii")).hexdigest()
            ),
            "ssh_host": self.config.host,
            "ssh_port": self.config.port,
            "ssh_username": self.config.user,
            "pinned_host_key_sha256": (
                self.config.pinned_host_key_fingerprint
            ),
            "client_public_key_sha256": self.config.public_key_fingerprint,
            "known_hosts_sha256": self.config.known_hosts_digest,
            "source_archive_sha256": self.archive.sha256,
        }
        return _digest(identity)

    @property
    def stage_nonce(self) -> str:
        return self._stage_nonce

    @property
    def stage_receipt(self) -> Mapping[str, Any] | None:
        return self._stage_receipt

    @property
    def ready_receipt(self) -> Mapping[str, Any] | None:
        return self._ready_receipt

    @property
    def finalize_receipt(self) -> Mapping[str, Any] | None:
        return self._finalize_receipt

    def open_stage(self) -> Mapping[str, Any]:
        if self._process is not None or self._poisoned:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_CHANNEL_REUSED",
                "host targetd SSH process is one-shot",
            )
        remote = [
            "/usr/bin/python3",
            "-u",
            "-c",
            _HOST_TARGETD_STAGE_SOURCE,
            self.stage_root,
        ]
        try:
            self._process = self._popen_factory(
                self.config.argv(remote),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
            self._start_drains()
            request = {
                "schema_version": "rolo-n7-targetd-host-stage-request/v1",
                "run_id": self.run_id,
                "stage_root": self.stage_root,
                "stage_nonce": self._stage_nonce,
                "archive_sha256": self.archive.sha256,
                "archive_bytes": len(self.archive.payload),
                "expanded_bytes": self.archive.expanded_bytes,
                "archive_member_count": self.archive.member_count,
            }
            self._write_bytes(
                _encode_host_control_record(request) + self.archive.payload
            )
            receipt = self._read_json_record()
        except Exception:
            self._poisoned = True
            raise
        nonce_digest = "sha256:" + hashlib.sha256(
            self._stage_nonce.encode("ascii")
        ).hexdigest()
        expected = {
            "schema_version": "rolo-n7-targetd-host-stage-receipt/v1",
            "status": "STAGED",
            "ok": True,
            "run_id": self.run_id,
            "stage_root": self.stage_root,
            "stage_nonce_sha256": nonce_digest,
            "archive_sha256": self.archive.sha256,
            "archive_bytes": len(self.archive.payload),
            "expanded_bytes": self.archive.expanded_bytes,
            "archive_member_count": self.archive.member_count,
            "launcher": "repo/scripts/landerpi_n7_targetd_host.py",
        }
        if receipt != expected:
            self._poisoned = True
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_STAGE_RECEIPT_INVALID",
                "Pi-host stage receipt differs from the exact source archive",
            )
        self._stage_receipt = dict(receipt)
        return dict(receipt)

    def bootstrap(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        if (
            self._stage_receipt is None
            or self._ready_receipt is not None
            or self._poisoned
            or not isinstance(payload, Mapping)
            or payload.get("stage_root") != self.stage_root
            or payload.get("stage_nonce") != self._stage_nonce
            or payload.get("run_id") != self.run_id
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_BOOTSTRAP_SEQUENCE_INVALID",
                "host bootstrap is not bound to the successful one-shot stage",
            )
        payload = validate_host_targetd_bootstrap_payload(self, payload)
        try:
            self._write_bytes(_encode_host_control_record(payload))
            ready = self._read_json_record()
        except Exception:
            self._poisoned = True
            raise
        if (
            ready.get("schema_version")
            != "rolo-n7-targetd-host-ready/v1"
            or ready.get("status") != "READY"
            or ready.get("run_id") != self.run_id
            or ready.get("stage_root") != self.stage_root
            or ready.get("target_id") != payload.get("target_id")
            or ready.get("call_id")
            != (payload.get("expected_call") or {}).get("id")
            or ready.get("session_id")
            != (payload.get("expected_call") or {}).get("session")
            or ready.get("bootstrap_payload_sha256")
            != payload.get("payload_sha256")
            or ready.get("initial_isolation")
            != "PENDING_PREPARE_AFTER_RUNNER_ISOLATION"
            or ready.get("provider_runtime_sha256")
            != payload.get("provider_runtime_sha256")
            or ready.get("peer_bootstrap_receipt_digest")
            != (payload.get("peer_bootstrap_receipt") or {}).get(
                "payload_sha256"
            )
            or ready.get("provider_invocation_count") != 0
            or ready.get("protocol") != "rolo-targetd/v1"
        ):
            self._poisoned = True
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_READY_RECEIPT_INVALID",
                "Pi-host targetd READY receipt differs from the sealed bootstrap",
            )
        self._ready_receipt = dict(ready)
        return dict(ready)

    def send(self, frame: ProtocolFrame) -> None:
        if self._ready_receipt is None or self._poisoned:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_CHANNEL_NOT_READY",
                "targetd frame cannot cross an unready host channel",
            )
        try:
            self._write_bytes(encode_frame(frame))
        except Exception:
            self._poisoned = True
            raise

    def receive(self) -> ProtocolFrame:
        if self._ready_receipt is None or self._poisoned:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_CHANNEL_NOT_READY",
                "targetd frame cannot be read from an unready host channel",
            )
        try:
            return decode_frame(self._read_raw_record())
        except Exception:
            self._poisoned = True
            raise

    def exchange_finalize_record(
        self,
        payload: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        if (
            self._ready_receipt is None
            or self._finalize_receipt is not None
            or self._poisoned
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_FINALIZE_SEQUENCE_INVALID",
                "host finalize footer is out of sequence",
            )
        try:
            self._write_bytes(_encode_host_control_record(payload))
            receipt = self._read_json_record()
        except Exception:
            self._poisoned = True
            raise
        self._finalize_receipt = dict(receipt)
        return dict(receipt)

    def close(self) -> None:
        """Close only a finalized channel; ambiguity remains isolated."""

        if self._finalize_receipt is None:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_FINALIZE_REQUIRED",
                "host targetd channel cannot close before signed finalization",
            )
        process = self._process
        if process is None:
            return
        if process.stdin is not None:
            process.stdin.close()
        try:
            returncode = process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_EXIT_NOT_VERIFIED",
                "finalized host targetd process did not exit",
            ) from exc
        if returncode != 0:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_EXIT_NOT_VERIFIED",
                "finalized host targetd process exited unsuccessfully",
            )
        self._process = None

    def abort_preserve(self) -> None:
        """Deliver EOF for the host watchdog without claiming safe recovery."""

        self._poisoned = True
        process = self._process
        if process is None:
            return
        try:
            if process.stdin is not None:
                process.stdin.close()
            process.wait(timeout=5)
        except Exception:
            # Do not kill an SSH/launcher process whose physical lease state is
            # unknown.  The outer runner consequently keeps both stages and
            # all competing publishers isolated for manual reconciliation.
            pass

    def _start_drains(self) -> None:
        process = self._process
        if process is None or process.stdout is None or process.stderr is None:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_CHANNEL_INVALID",
                "host targetd SSH process has no stdio streams",
            )

        def stdout_worker() -> None:
            try:
                while True:
                    header = _read_exact_bytes(process.stdout, 4)
                    if not header:
                        raise EOFError("host targetd stdout closed")
                    if len(header) != 4:
                        raise EOFError("host targetd record header truncated")
                    size = int.from_bytes(header, "big")
                    if not 2 <= size <= 4 * 1024 * 1024:
                        raise ValueError("host targetd record size invalid")
                    body = _read_exact_bytes(process.stdout, size)
                    if len(body) != size:
                        raise EOFError("host targetd record body truncated")
                    self._records.put(header + body)
            except BaseException as exc:  # terminal reader signal
                self._records.put(exc)

        def stderr_worker() -> None:
            while len(self._stderr) <= _MAX_RPC_BYTES:
                chunk = process.stderr.read(4096)
                if not chunk:
                    return
                self._stderr.extend(chunk)

        self._stdout_thread = threading.Thread(
            target=stdout_worker,
            name="rolo-n7-host-targetd-stdout",
            daemon=True,
        )
        self._stderr_thread = threading.Thread(
            target=stderr_worker,
            name="rolo-n7-host-targetd-stderr",
            daemon=True,
        )
        self._stdout_thread.start()
        self._stderr_thread.start()

    def _write_bytes(self, payload: bytes) -> None:
        process = self._process
        if process is None or process.stdin is None:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_CHANNEL_INVALID",
                "host targetd SSH stdin is unavailable",
            )
        with self._write_lock:
            written = process.stdin.write(payload)
            if written is not None and written != len(payload):
                raise OSError("short host targetd write")
            process.stdin.flush()

    def _read_raw_record(self) -> bytes:
        try:
            item = self._records.get(timeout=self.io_timeout_s)
        except queue.Empty as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_RESPONSE_TIMEOUT",
                "host targetd response exceeded its fixed timeout",
            ) from exc
        if isinstance(item, BaseException):
            diagnostic = _bounded_remote_diagnostic(bytes(self._stderr))
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_CHANNEL_CLOSED",
                f"host targetd channel closed; stderr={diagnostic}",
            ) from item
        return item

    def _read_json_record(self) -> dict[str, Any]:
        record = self._read_raw_record()
        try:
            value = loads_unique_json(record[4:].decode("utf-8"))
        except (UnicodeError, ValueError, TypeError) as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_RESPONSE_INVALID",
                "host targetd control response is not strict JSON",
            ) from exc
        if not isinstance(value, dict):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_RESPONSE_INVALID",
                "host targetd control response is not an object",
            )
        if value.get("ok") is False:
            code = value.get("error")
            if not isinstance(code, str) or re.fullmatch(
                r"[A-Z][A-Z0-9_]{1,127}",
                code,
            ) is None:
                code = "N7_PHYSICAL_HOST_BLOCKED"
            raise N7PhysicalBlocked(code, "Pi-host targetd action failed closed")
        return value


def _read_exact_bytes(stream: Any, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(bytes(chunk))
        remaining -= len(chunk)
    return b"".join(chunks)


_HOST_TARGETD_STAGE_SOURCE = r'''
import hashlib
import json
import os
import pathlib
import re
import shutil
import sys
import tarfile

STAGE = re.compile(r"^/dev/shm/rolo-n7-targetd-[0-9a-f]{20}$")
IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
MAX_RECORD = 512 * 1024
MAX_ARCHIVE = 8 * 1024 * 1024
MAX_EXPANDED = 8 * 1024 * 1024
MAX_MEMBERS = 1024

class Blocked(Exception):
    pass

def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")

def read_exact(size):
    chunks = []
    remaining = size
    while remaining:
        chunk = sys.stdin.buffer.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)

def strict_object_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value

def read_record():
    header = read_exact(4)
    if len(header) != 4:
        raise Blocked("N7_PHYSICAL_HOST_STAGE_REQUEST_TRUNCATED")
    size = int.from_bytes(header, "big")
    if not 2 <= size <= MAX_RECORD:
        raise Blocked("N7_PHYSICAL_HOST_STAGE_REQUEST_LIMIT")
    payload = read_exact(size)
    if len(payload) != size:
        raise Blocked("N7_PHYSICAL_HOST_STAGE_REQUEST_TRUNCATED")
    try:
        value = json.loads(payload.decode("ascii"), object_pairs_hook=strict_object_pairs)
    except Exception:
        raise Blocked("N7_PHYSICAL_HOST_STAGE_REQUEST_INVALID")
    if not isinstance(value, dict):
        raise Blocked("N7_PHYSICAL_HOST_STAGE_REQUEST_INVALID")
    return value

def emit(value):
    payload = canonical(value)
    if len(payload) > MAX_RECORD:
        raise Blocked("N7_PHYSICAL_HOST_STAGE_RESPONSE_LIMIT")
    sys.stdout.buffer.write(len(payload).to_bytes(4, "big") + payload)
    sys.stdout.buffer.flush()

def write_exclusive(path, payload, mode):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        if os.write(descriptor, payload) != len(payload):
            raise OSError("short write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

def safe_member(member):
    name = member.name
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "repo":
        return False
    if path.parts[:3] == ("repo", "src", "rolo"):
        return member.isdir() or (member.isreg() and name.endswith(".py"))
    if member.isdir():
        return name in {"repo", "repo/src", "repo/scripts"}
    return member.isreg() and name == "repo/scripts/landerpi_n7_targetd_host.py"

def extract(root, archive_path, expected_expanded, expected_members):
    expanded = 0
    files = 0
    with tarfile.open(archive_path, mode="r:") as package:
        members = package.getmembers()
        if len(members) > MAX_MEMBERS:
            raise Blocked("N7_PHYSICAL_HOST_ARCHIVE_MEMBER_LIMIT")
        for member in members:
            if not safe_member(member) or not (member.isdir() or member.isreg()):
                raise Blocked("N7_PHYSICAL_HOST_ARCHIVE_MEMBER_INVALID")
            destination = root.joinpath(*pathlib.PurePosixPath(member.name).parts)
            if member.isdir():
                destination.mkdir(mode=0o755, parents=True, exist_ok=True)
                continue
            files += 1
            expanded += member.size
            if expanded > MAX_EXPANDED:
                raise Blocked("N7_PHYSICAL_HOST_ARCHIVE_EXPANDED_LIMIT")
            destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            source = package.extractfile(member)
            if source is None:
                raise Blocked("N7_PHYSICAL_HOST_ARCHIVE_MEMBER_INVALID")
            payload = source.read(member.size + 1)
            if len(payload) != member.size:
                raise Blocked("N7_PHYSICAL_HOST_ARCHIVE_MEMBER_INVALID")
            write_exclusive(destination, payload, 0o644)
    if expanded != expected_expanded or files != expected_members:
        raise Blocked("N7_PHYSICAL_HOST_ARCHIVE_ACCOUNTING_MISMATCH")

stage = None
try:
    if len(sys.argv) != 2 or STAGE.fullmatch(sys.argv[1]) is None:
        raise Blocked("N7_PHYSICAL_HOST_STAGE_ROOT_INVALID")
    request = read_record()
    if set(request) != {
        "schema_version", "run_id", "stage_root", "stage_nonce", "archive_sha256",
        "archive_bytes", "expanded_bytes", "archive_member_count"
    }:
        raise Blocked("N7_PHYSICAL_HOST_STAGE_REQUEST_INVALID")
    run_id = request["run_id"]
    nonce = request["stage_nonce"]
    archive_bytes = request["archive_bytes"]
    expanded_bytes = request["expanded_bytes"]
    member_count = request["archive_member_count"]
    if (
        request["schema_version"] != "rolo-n7-targetd-host-stage-request/v1"
        or request["stage_root"] != sys.argv[1]
        or not isinstance(run_id, str) or IDENTITY.fullmatch(run_id) is None
        or not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None
        or not isinstance(request["archive_sha256"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", request["archive_sha256"]) is None
        or isinstance(archive_bytes, bool) or not isinstance(archive_bytes, int) or not 0 < archive_bytes <= MAX_ARCHIVE
        or isinstance(expanded_bytes, bool) or not isinstance(expanded_bytes, int) or not 0 < expanded_bytes <= MAX_EXPANDED
        or isinstance(member_count, bool) or not isinstance(member_count, int) or not 0 < member_count <= MAX_MEMBERS
    ):
        raise Blocked("N7_PHYSICAL_HOST_STAGE_REQUEST_INVALID")
    archive = read_exact(archive_bytes)
    if len(archive) != archive_bytes or "sha256:" + hashlib.sha256(archive).hexdigest() != request["archive_sha256"]:
        raise Blocked("N7_PHYSICAL_HOST_ARCHIVE_DIGEST_MISMATCH")
    stage = pathlib.Path(sys.argv[1])
    if stage.parent != pathlib.Path("/dev/shm"):
        raise Blocked("N7_PHYSICAL_HOST_STAGE_ROOT_INVALID")
    stage.mkdir(mode=0o700, exist_ok=False)
    marker = {
        "schema_version": "rolo-n7-targetd-host-stage/v1",
        "stage_root": str(stage),
        "run_id": run_id,
        "nonce_sha256": "sha256:" + hashlib.sha256(nonce.encode("ascii")).hexdigest(),
    }
    write_exclusive(stage / ".rolo-n7-targetd-owner", canonical(marker), 0o600)
    archive_path = stage / ".source.tar"
    write_exclusive(archive_path, archive, 0o600)
    extract(stage, archive_path, expanded_bytes, member_count)
    archive_path.unlink()
    launcher = stage / "repo" / "scripts" / "landerpi_n7_targetd_host.py"
    if launcher.is_symlink() or not launcher.is_file():
        raise Blocked("N7_PHYSICAL_HOST_LAUNCHER_MISSING")
    receipt = {
        "schema_version": "rolo-n7-targetd-host-stage-receipt/v1",
        "status": "STAGED",
        "ok": True,
        "run_id": run_id,
        "stage_root": str(stage),
        "stage_nonce_sha256": marker["nonce_sha256"],
        "archive_sha256": request["archive_sha256"],
        "archive_bytes": archive_bytes,
        "expanded_bytes": expanded_bytes,
        "archive_member_count": member_count,
        "launcher": "repo/scripts/landerpi_n7_targetd_host.py",
    }
    emit(receipt)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(stage / "repo" / "src") + ":" + str(stage / "repo")
    argv = [
        "/usr/bin/python3", "-m", "scripts.landerpi_n7_targetd_host",
        "--serve-stdio", "--stage-root", str(stage),
    ]
    os.execve("/usr/bin/python3", argv, environment)
except Exception as exc:
    code = str(exc)
    if re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", code) is None:
        code = "N7_PHYSICAL_HOST_STAGE_BLOCKED"
    try:
        emit({"schema_version": "rolo-n7-targetd-host-error/v1", "ok": False, "error": code})
    except Exception:
        pass
    raise SystemExit(2)
'''


# This source is passed as one quoted argv token and accepts only bounded JSON
# on stdin.  It intentionally contains no generic command execution endpoint.
_REMOTE_CONTROL_SOURCE = r'''
import hashlib
import json
import math
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

STAGE = re.compile(r"^/dev/shm/rolo-n7-physical-[0-9a-f]{20}$")
ALLOW = {
    "/robot_api": "/home/ubuntu/ros2_ws/install/robot_api/lib/robot_api/robot_api",
    "/lidar_app": "/home/ubuntu/ros2_ws/install/app/lib/app/lidar_controller",
    "/line_following": "/home/ubuntu/ros2_ws/install/app/lib/app/line_following",
    "/object_tracking": "/home/ubuntu/ros2_ws/install/app/lib/app/object_tracking",
    "/hand_gesture": "/home/ubuntu/ros2_ws/install/app/lib/app/hand_gesture",
    "/joystick_control": "/home/ubuntu/ros2_ws/install/peripherals/lib/peripherals/joystick_control",
}
BASELINE = {
    "command_publishers": [],
    "command_subscribers": ["/odom_publisher"],
    "competing_publishers": sorted(ALLOW),
    "competing_subscribers": ["/odom_publisher"],
    "direct_motor_publishers": ["/hand_gesture", "/odom_publisher"],
    "direct_motor_subscribers": ["/ros_robot_controller"],
}
ISOLATED = {
    "command_publishers": [],
    "command_subscribers": ["/odom_publisher"],
    "competing_publishers": [],
    "competing_subscribers": ["/odom_publisher"],
    "direct_motor_publishers": ["/odom_publisher"],
    "direct_motor_subscribers": ["/ros_robot_controller"],
}
PREARMED = {
    **ISOLATED,
    "command_publishers": ["/rolo_bounded_twist"],
}
BRINGUP = ["/usr/bin/python3", "/opt/ros/humble/bin/ros2", "launch", "bringup", "bringup.launch.py"]
BRINGUP_ENV = (
    "set -e; export HOME=/home/ubuntu; . /opt/ros/humble/setup.bash; "
    ". /home/ubuntu/ros2_ws/install/setup.bash; . /home/ubuntu/ros2_ws/.robotrc >/dev/null; "
    "set -u; exec ros2 launch bringup bringup.launch.py"
)
BRINGUP_MEMBER_EXECUTABLE_PREFIXES = (
    "/usr/bin/python3",
    "python3",
    "/opt/ros/humble/",
    "/home/ubuntu/ros2_ws/install/",
    "/home/ubuntu/third_party_ros2/install/",
    "/home/ubuntu/third_party_ros2/third_party_ws/install/",
    "dbus-launch",
)
SENSOR_ROUTES = {
    "/ros_robot_controller/imu_raw": "sensor_msgs/msg/Imu",
    "/imu": "sensor_msgs/msg/Imu",
    "/odom_raw": "nav_msgs/msg/Odometry",
    "/odom": "nav_msgs/msg/Odometry",
}

class Blocked(Exception):
    pass

def emit(value):
    encoded = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("ascii")) > 256 * 1024:
        raise Blocked("N7_PHYSICAL_REMOTE_RESPONSE_LIMIT")
    sys.stdout.write(encoded)
    sys.stdout.flush()

def digest(value):
    encoded = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()

def stage_path(value):
    if not isinstance(value, str) or STAGE.fullmatch(value) is None:
        raise Blocked("N7_PHYSICAL_STAGE_ROOT_INVALID")
    path = pathlib.Path(value)
    if path.parent != pathlib.Path("/dev/shm"):
        raise Blocked("N7_PHYSICAL_STAGE_ROOT_INVALID")
    return path

def verify_stage(request):
    path = stage_path(request.get("stage_root"))
    nonce = request.get("nonce")
    if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
        raise Blocked("N7_PHYSICAL_STAGE_NONCE_INVALID")
    if not path.is_dir() or path.is_symlink() or path.resolve() != path:
        raise Blocked("N7_PHYSICAL_STAGE_MISSING")
    marker = path / ".rolo-n7-owner"
    if marker.is_symlink() or not marker.is_file() or marker.read_text(encoding="ascii") != nonce:
        raise Blocked("N7_PHYSICAL_STAGE_OWNER_MISMATCH")
    return path, nonce

def proc_stat(pid):
    text = pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    close = text.rfind(")")
    if close < 0:
        raise ValueError("stat")
    fields = text[close + 2:].split()
    return int(fields[19])

def exact_stopped_zombie(entry, expected):
    try:
        text = (entry / "stat").read_text(encoding="ascii")
        close = text.rfind(")")
        fields = text[close + 2:].split()
        expected_start = (
            expected.get("start_ticks") if isinstance(expected, dict) else None
        )
        return (
            close >= 0
            and fields[0] == "Z"
            and (expected_start is None or int(fields[19]) == expected_start)
        )
    except (OSError, ValueError, IndexError):
        return False

def publisher_processes():
    found = []
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
            argv = [part.decode("utf-8", "strict") for part in raw.rstrip(b"\0").split(b"\0") if part]
            if not argv:
                continue
            matches = []
            for node, executable in ALLOW.items():
                if argv[0] == executable:
                    matches.append((node, executable, [executable]))
                elif len(argv) >= 2 and argv[0] == "/usr/bin/python3" and argv[1] == executable:
                    matches.append((node, executable, ["/usr/bin/python3", executable]))
            if not matches:
                continue
            if len(matches) != 1:
                raise Blocked("N7_PHYSICAL_PROCESS_ALLOWLIST_AMBIGUOUS")
            node, executable, launch_argv_prefix = matches[0]
            found.append({
                "node_id": node,
                "executable": executable,
                "launch_argv_prefix": launch_argv_prefix,
                "pid": int(entry.name),
                "start_ticks": proc_stat(entry.name),
                "argv_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
            })
        except (FileNotFoundError, ProcessLookupError, PermissionError, UnicodeDecodeError):
            continue
    found.sort(key=lambda item: item["node_id"])
    return found

def node_id(info):
    namespace = str(info.node_namespace or "/")
    name = str(info.node_name)
    return (namespace.rstrip("/") + "/" + name) if namespace != "/" else "/" + name

def graph_snapshot(node, phase):
    def endpoints(topic, publishers):
        infos = node.get_publishers_info_by_topic(topic) if publishers else node.get_subscriptions_info_by_topic(topic)
        # Preserve endpoint cardinality and the exact node/GID pairing.
        records = sorted(
            (node_id(info), bytes(info.endpoint_gid).hex())
            for info in infos
        )
        return [record[0] for record in records], [record[1] for record in records]
    command_publishers, command_publisher_gids = endpoints("/cmd_vel", True)
    command_subscribers, command_subscriber_gids = endpoints("/cmd_vel", False)
    competing_publishers, competing_publisher_gids = endpoints("/controller/cmd_vel", True)
    competing_subscribers, competing_subscriber_gids = endpoints("/controller/cmd_vel", False)
    direct_motor_publishers, direct_motor_publisher_gids = endpoints("/ros_robot_controller/set_motor", True)
    direct_motor_subscribers, direct_motor_subscriber_gids = endpoints("/ros_robot_controller/set_motor", False)
    snapshot = {
        "schema_version": "rolo-n7-control-graph/v1",
        "phase": phase,
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "command_route": "/cmd_vel",
        "command_interface": "geometry_msgs/msg/Twist",
        "command_publishers": command_publishers,
        "command_publisher_gids": command_publisher_gids,
        "command_subscribers": command_subscribers,
        "command_subscriber_gids": command_subscriber_gids,
        "competing_command_route": "/controller/cmd_vel",
        "competing_publishers": competing_publishers,
        "competing_publisher_gids": competing_publisher_gids,
        "competing_subscribers": competing_subscribers,
        "competing_subscriber_gids": competing_subscriber_gids,
        "direct_motor_route": "/ros_robot_controller/set_motor",
        "direct_motor_publishers": direct_motor_publishers,
        "direct_motor_publisher_gids": direct_motor_publisher_gids,
        "direct_motor_subscribers": direct_motor_subscribers,
        "direct_motor_subscriber_gids": direct_motor_subscriber_gids,
        "processes": publisher_processes(),
    }
    snapshot["graph_revision"] = digest(snapshot)
    return snapshot

def topology_relation(snapshot, expected, require_processes):
    exact = True
    for key, wanted in expected.items():
        observed = snapshot.get(key)
        if not isinstance(observed, list) or len(observed) != len(set(observed)):
            return "CHANGED"
        if any(item not in wanted for item in observed):
            return "CHANGED"
        exact = exact and observed == wanted
    processes = snapshot.get("processes")
    if not isinstance(processes, list):
        return "CHANGED"
    nodes = [item.get("node_id") for item in processes if isinstance(item, dict)]
    if len(nodes) != len(processes) or len(nodes) != len(set(nodes)):
        return "CHANGED"
    wanted_nodes = sorted(ALLOW) if require_processes else []
    if any(node not in wanted_nodes for node in nodes):
        return "CHANGED"
    exact = exact and nodes == wanted_nodes
    return "EXACT" if exact else "INCOMPLETE"

def wait_expected_graph_node(node, phase, expected, require_processes, timeout, expected_topology=None):
    import rclpy
    deadline = time.monotonic() + timeout
    last_relation = "INCOMPLETE"
    stable_digest = None
    stable_hits = 0
    while time.monotonic() < deadline:
        rclpy.spin_once(node, timeout_sec=min(0.2, max(0.0, deadline - time.monotonic())))
        observed = graph_snapshot(node, phase)
        last_relation = topology_relation(observed, expected, require_processes)
        observed_digest = topology_digest(observed)
        if last_relation == "EXACT" and (
            expected_topology is None or observed_digest == expected_topology
        ):
            if stable_digest == observed_digest:
                stable_hits += 1
            else:
                stable_digest = observed_digest
                stable_hits = 1
            if stable_hits >= 2:
                return observed
        else:
            if last_relation == "EXACT":
                last_relation = "CHANGED"
            stable_digest = None
            stable_hits = 0
    if last_relation == "CHANGED":
        raise Blocked("N7_PHYSICAL_SENSOR_GRAPH_CHANGED" if expected_topology is not None else "N7_PHYSICAL_GRAPH_CHANGED")
    raise Blocked("N7_PHYSICAL_GRAPH_DISCOVERY_TIMEOUT")

def graph(phase, expected, require_processes, timeout, expected_topology=None):
    import rclpy
    rclpy.init(args=[])
    node = rclpy.create_node("rolo_n7_gate_inspector", enable_rosout=False, start_parameter_services=False)
    try:
        return wait_expected_graph_node(
            node,
            phase,
            expected,
            require_processes,
            timeout,
            expected_topology,
        )
    finally:
        node.destroy_node()
        rclpy.shutdown()

def topology_digest(snapshot):
    fields = (
        "command_route", "command_interface", "command_publishers", "command_publisher_gids",
        "command_subscribers", "command_subscriber_gids", "competing_command_route",
        "competing_publishers", "competing_publisher_gids", "competing_subscribers",
        "competing_subscriber_gids", "direct_motor_route", "direct_motor_publishers",
        "direct_motor_publisher_gids", "direct_motor_subscribers", "direct_motor_subscriber_gids",
        "processes",
    )
    return digest({field:snapshot[field] for field in fields})

def iso_from_ns(value):
    return datetime.fromtimestamp(value / 1_000_000_000, timezone.utc).isoformat().replace("+00:00", "Z")

def sensor_liveness(phase, stage_root, expected_topology, sample_window_s):
    if phase not in {"BASELINE", "PREARMED"}:
        raise Blocked("N7_PHYSICAL_SENSOR_PHASE_INVALID")
    if not isinstance(expected_topology, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", expected_topology) is None:
        raise Blocked("N7_PHYSICAL_SENSOR_GRAPH_BINDING_INVALID")
    if not isinstance(sample_window_s, (int, float)) or isinstance(sample_window_s, bool) or not 0.5 <= float(sample_window_s) <= 5.0:
        raise Blocked("N7_PHYSICAL_SENSOR_WINDOW_INVALID")
    import rclpy
    from nav_msgs.msg import Odometry
    from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy
    from sensor_msgs.msg import Imu

    message_types = {
        "/ros_robot_controller/imu_raw": Imu,
        "/imu": Imu,
        "/odom_raw": Odometry,
        "/odom": Odometry,
    }
    arrivals = {route:[] for route in SENSOR_ROUTES}
    publishers = {}
    expected = BASELINE if phase == "BASELINE" else PREARMED
    require_processes = phase == "BASELINE"
    rclpy.init(args=[])
    node = rclpy.create_node("rolo_n7_sensor_liveness", enable_rosout=False, start_parameter_services=False)
    qos = QoSProfile(depth=64, reliability=ReliabilityPolicy.BEST_EFFORT, durability=DurabilityPolicy.VOLATILE)
    subscriptions = []
    try:
        pre = wait_expected_graph_node(
            node,
            "SENSOR_PRE",
            expected,
            require_processes,
            10.0,
            expected_topology,
        )
        for route, message_type in message_types.items():
            subscriptions.append(node.create_subscription(
                message_type,
                route,
                lambda _message, bound_route=route: arrivals[bound_route].append(
                    (time.time_ns(), time.monotonic_ns())
                ),
                qos,
            ))
        started_wall_ns = time.time_ns()
        started_mono_ns = time.monotonic_ns()
        deadline_ns = started_mono_ns + int(float(sample_window_s) * 1_000_000_000)
        while time.monotonic_ns() < deadline_ns:
            remaining_s = max(0.0, (deadline_ns - time.monotonic_ns()) / 1_000_000_000)
            rclpy.spin_once(node, timeout_sec=min(0.05, remaining_s))
        ended_mono_ns = time.monotonic_ns()
        ended_wall_ns = time.time_ns()
        elapsed_mono_ns = ended_mono_ns - started_mono_ns
        elapsed_wall_ns = ended_wall_ns - started_wall_ns
        if (
            elapsed_mono_ns <= 0
            or elapsed_wall_ns <= 0
            or abs(elapsed_wall_ns - elapsed_mono_ns) > 250_000_000
        ):
            raise Blocked("N7_PHYSICAL_SENSOR_CLOCK_CHANGED")
        report_started_wall_ns = ended_wall_ns - elapsed_mono_ns
        for route in SENSOR_ROUTES:
            records = sorted(
                (node_id(info), bytes(info.endpoint_gid).hex())
                for info in node.get_publishers_info_by_topic(route)
            )
            publishers[route] = records
        for subscription in subscriptions:
            node.destroy_subscription(subscription)
        subscriptions.clear()
        post = wait_expected_graph_node(
            node,
            "SENSOR_POST",
            expected,
            require_processes,
            10.0,
            expected_topology,
        )
    finally:
        for subscription in subscriptions:
            node.destroy_subscription(subscription)
        node.destroy_node()
        rclpy.shutdown()
    topics = []
    for route, interface in SENSOR_ROUTES.items():
        samples = arrivals[route]
        mono_stamps = [item[1] for item in samples]
        gaps = [(right-left)/1_000_000_000 for left, right in zip(mono_stamps, mono_stamps[1:])]
        span = (mono_stamps[-1]-mono_stamps[0])/1_000_000_000 if len(mono_stamps) > 1 else 0.0
        first_report_ns = (
            ended_wall_ns - (ended_mono_ns - mono_stamps[0])
            if mono_stamps else None
        )
        last_report_ns = (
            ended_wall_ns - (ended_mono_ns - mono_stamps[-1])
            if mono_stamps else None
        )
        identities = [item[0] for item in publishers[route]]
        gids = [item[1] for item in publishers[route]]
        topics.append({
            "route":route,
            "interface":interface,
            "publisher_identities":identities,
            "publisher_gids":gids,
            "sample_count":len(samples),
            "first_sample_at":iso_from_ns(first_report_ns) if first_report_ns is not None else None,
            "last_sample_at":iso_from_ns(last_report_ns) if last_report_ns is not None else None,
            "sample_rate_hz":((len(samples)-1)/span) if span > 0 else 0.0,
            "max_gap_s":max(gaps) if gaps else (0.0 if samples else None),
            "last_sample_age_s":((ended_mono_ns-mono_stamps[-1])/1_000_000_000) if samples else None,
            "arrival_digest":digest({"route":route,"arrival_clocks_ns":samples}),
        })
    healthy = all(
        item["publisher_identities"]
        and item["sample_count"] >= 2
        and isinstance(item["sample_rate_hz"], (int, float))
        and math.isfinite(item["sample_rate_hz"])
        and item["sample_rate_hz"] >= 1.0
        and item["sample_rate_hz"] <= 10000.0
        and isinstance(item["max_gap_s"], (int, float))
        and math.isfinite(item["max_gap_s"])
        and 0.0 <= item["max_gap_s"] <= float(sample_window_s) + 0.25
        and isinstance(item["last_sample_age_s"], (int, float))
        and math.isfinite(item["last_sample_age_s"])
        and 0.0 <= item["last_sample_age_s"] <= 0.5
        for item in topics
    )
    unsigned = {
        "schema_version":"rolo-n7-fresh-sensor-health/v1",
        "ok":True,
        "phase":phase,
        "stage_root":stage_root,
        "window_started_at":iso_from_ns(report_started_wall_ns),
        "window_ended_at":iso_from_ns(ended_wall_ns),
        "sample_window_s":elapsed_mono_ns/1_000_000_000,
        "graph_topology_digest":expected_topology,
        "pre_sample_graph_revision":pre["graph_revision"],
        "post_sample_graph_revision":post["graph_revision"],
        "topics":topics,
        "healthy":bool(healthy),
    }
    return {**unsigned,"evidence_digest":digest(unsigned)}

def exact_topology(snapshot, expected, *, require_processes):
    for key, value in expected.items():
        if snapshot.get(key) != value:
            return False
    nodes = [item["node_id"] for item in snapshot["processes"]]
    return nodes == sorted(ALLOW) if require_processes else nodes == []

def wait_graph(phase, expected, require_processes, timeout):
    return graph(phase, expected, require_processes, timeout)

def process_identity(entry):
    raw = (entry / "cmdline").read_bytes()
    argv = [part.decode("utf-8", "strict") for part in raw.rstrip(b"\0").split(b"\0") if part]
    if not argv:
        raise ValueError("empty cmdline")
    pid = int(entry.name)
    return {
        "pid":pid,
        "start_ticks":proc_stat(pid),
        "argv_sha256":"sha256:" + hashlib.sha256(raw).hexdigest(),
        "executable":argv[0],
        "pgid":os.getpgid(pid),
        "sid":os.getsid(pid),
        "argv":argv,
    }

def bringup_launchers():
    result = []
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            identity = process_identity(entry)
            if identity["argv"][:len(BRINGUP)] == BRINGUP:
                result.append(identity)
        except (FileNotFoundError, PermissionError, UnicodeDecodeError, ValueError):
            continue
    return result

def allowed_bringup_member(identity):
    executable = identity["executable"]
    return any(
        executable == prefix or (prefix.endswith("/") and executable.startswith(prefix))
        for prefix in BRINGUP_MEMBER_EXECUTABLE_PREFIXES
    )

def capture_bringup_group():
    launchers = bringup_launchers()
    if len(launchers) != 1:
        raise Blocked("N7_PHYSICAL_BRINGUP_IDENTITY_NOT_UNIQUE")
    leader = launchers[0]
    if leader["pid"] != leader["pgid"] or leader["pid"] != leader["sid"]:
        raise Blocked("N7_PHYSICAL_BRINGUP_GROUP_IDENTITY_INVALID")
    members = []
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            identity = process_identity(entry)
            if identity["pgid"] == leader["pgid"] or identity["sid"] == leader["sid"]:
                if identity["pgid"] != leader["pgid"] or identity["sid"] != leader["sid"]:
                    raise Blocked("N7_PHYSICAL_BRINGUP_GROUP_BOUNDARY_INVALID")
                if not allowed_bringup_member(identity):
                    raise Blocked("N7_PHYSICAL_BRINGUP_GROUP_MEMBER_NOT_ALLOWED")
                identity.pop("argv")
                members.append(identity)
        except (FileNotFoundError, PermissionError, UnicodeDecodeError, ProcessLookupError, ValueError):
            continue
    members.sort(key=lambda item:item["pid"])
    if not members or len(members) > 128 or leader["pid"] not in {item["pid"] for item in members}:
        raise Blocked("N7_PHYSICAL_BRINGUP_GROUP_MEMBERS_INVALID")
    unsigned = {
        "leader_pid":leader["pid"],
        "pgid":leader["pgid"],
        "sid":leader["sid"],
        "members":members,
    }
    return {**unsigned,"group_digest":digest(unsigned)}

def revalidate_group_member(expected):
    try:
        current = process_identity(pathlib.Path(f"/proc/{expected['pid']}"))
    except (FileNotFoundError, PermissionError, UnicodeDecodeError, ProcessLookupError, ValueError):
        return False
    current.pop("argv")
    if current != expected or not allowed_bringup_member(current):
        raise Blocked("N7_PHYSICAL_BRINGUP_GROUP_MEMBER_CHANGED")
    return True

def wait_group_gone(group, timeout):
    deadline = time.monotonic() + timeout
    expected_members = {item["pid"]: item for item in group["members"]}
    while time.monotonic() < deadline:
        present = [item for item in group["members"] if revalidate_group_member(item)]
        if not present:
            for entry in pathlib.Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    pid = int(entry.name)
                    if os.getpgid(pid) == group["pgid"] or os.getsid(pid) == group["sid"]:
                        if exact_stopped_zombie(entry, expected_members.get(pid)):
                            continue
                        raise Blocked("N7_PHYSICAL_BRINGUP_GROUP_RESIDUAL")
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    continue
            return True
        time.sleep(0.1)
    return False

def stop_bringup_group(group):
    current = capture_bringup_group()
    if current != group:
        raise Blocked("N7_PHYSICAL_BRINGUP_GROUP_CHANGED")
    for member in group["members"]:
        if not revalidate_group_member(member):
            raise Blocked("N7_PHYSICAL_BRINGUP_GROUP_MEMBER_MISSING")
    os.killpg(group["pgid"], signal.SIGINT)
    if wait_group_gone(group, 15.0):
        return "SIGINT"
    pending = [item for item in group["members"] if revalidate_group_member(item)]
    if not pending:
        return "SIGINT"
    for member in pending:
        revalidate_group_member(member)
    os.killpg(group["pgid"], signal.SIGTERM)
    if not wait_group_gone(group, 15.0):
        raise Blocked("N7_PHYSICAL_BRINGUP_GROUP_STOP_TIMEOUT")
    return "SIGINT_THEN_SIGTERM"

def launch_bringup():
    subprocess.Popen(
        [
            "/bin/bash", "--noprofile", "--norc", "-c",
            BRINGUP_ENV,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )

def terminate_exact(processes, timeout=12.0):
    for item in processes:
        pid = item["pid"] if isinstance(item, dict) else item[0]
        expected_start = item["start_ticks"] if isinstance(item, dict) else item[1]
        try:
            raw = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes()
            argv = [part.decode("utf-8", "strict") for part in raw.rstrip(b"\0").split(b"\0") if part]
            current_start = proc_stat(pid)
            current_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        except (FileNotFoundError, PermissionError, UnicodeDecodeError):
            raise Blocked("N7_PHYSICAL_PROCESS_IDENTITY_CHANGED")
        expected_digest = item["argv_sha256"] if isinstance(item, dict) else item[2]
        expected_argv = item["launch_argv_prefix"] if isinstance(item, dict) else BRINGUP
        if isinstance(item, dict) and expected_argv not in (
            [item["executable"]],
            ["/usr/bin/python3", item["executable"]],
        ):
            raise Blocked("N7_PHYSICAL_PROCESS_LAUNCH_IDENTITY_INVALID")
        if (
            current_start != expected_start
            or current_digest != expected_digest
            or argv[:len(expected_argv)] != expected_argv
        ):
            raise Blocked("N7_PHYSICAL_PROCESS_REUSED")
        os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + timeout
    pending = {item["pid"] if isinstance(item, dict) else item[0] for item in processes}
    while pending and time.monotonic() < deadline:
        for pid in tuple(pending):
            if not pathlib.Path(f"/proc/{pid}").exists():
                pending.remove(pid)
        time.sleep(0.1)
    if pending:
        raise Blocked("N7_PHYSICAL_PROCESS_STOP_TIMEOUT")

def main(request):
    action = request.get("action")
    if action == "STAGE":
        path = stage_path(request.get("stage_root"))
        nonce = request.get("nonce")
        run_id = request.get("run_id")
        if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None or not isinstance(run_id, str):
            raise Blocked("N7_PHYSICAL_STAGE_REQUEST_INVALID")
        path.mkdir(mode=0o700, exist_ok=False)
        marker = path / ".rolo-n7-owner"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(marker, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(nonce)
            handle.flush()
            os.fsync(handle.fileno())
        return {
            "schema_version": "rolo-n7-stage-receipt/v1",
            "ok": True,
            "run_id": run_id,
            "container": "MentorPi",
            "stage_root": str(path),
            "stage_nonce_digest": "sha256:" + hashlib.sha256(nonce.encode("ascii")).hexdigest(),
        }
    path, nonce = verify_stage(request)
    if action == "SNAPSHOT":
        phase = request.get("phase")
        if phase not in {"BASELINE", "PREARMED", "POST_TRACE", "POST_STOP"}:
            raise Blocked("N7_PHYSICAL_SNAPSHOT_PHASE_INVALID")
        expected = BASELINE if phase == "BASELINE" else PREARMED if phase == "PREARMED" else ISOLATED
        result = graph(
            phase,
            expected,
            phase == "BASELINE",
            15.0,
        )
        return {"ok": True, **result}
    if action == "SAMPLE_HEALTH":
        return sensor_liveness(
            request.get("phase"),
            str(path),
            request.get("graph_topology_digest"),
            request.get("sample_window_s"),
        )
    if action == "PREFLIGHT_RESTART":
        marker = path / ".rolo-n7-preflight-restart-used"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(marker, flags, 0o600)
        except FileExistsError:
            raise Blocked("N7_PHYSICAL_BRINGUP_RESTART_REPLAY")
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(nonce)
            handle.flush()
            os.fsync(handle.fileno())
        expected = request.get("expected_processes")
        fresh = graph("PREFLIGHT_RESTART", BASELINE, True, 15.0)
        if not exact_topology(fresh, BASELINE, require_processes=True):
            raise Blocked("N7_PHYSICAL_BASELINE_TOPOLOGY_MISMATCH")
        if not isinstance(expected, list) or expected != fresh["processes"]:
            raise Blocked("N7_PHYSICAL_PROCESS_IDENTITY_CHANGED")
        previous_group = capture_bringup_group()
        stop_signal = stop_bringup_group(previous_group)
        launch_bringup()
        restored = wait_graph("BASELINE", BASELINE, True, 45.0)
        replacement_group = capture_bringup_group()
        if replacement_group["group_digest"] == previous_group["group_digest"]:
            raise Blocked("N7_PHYSICAL_BRINGUP_RESTART_IDENTITY_REUSED")
        return {
            "schema_version":"rolo-n7-bringup-preflight-restart/v1",
            "ok":True,
            "stage_root":str(path),
            "restart_count":1,
            "stop_signal":stop_signal,
            "previous_group":previous_group,
            "replacement_group":replacement_group,
            "snapshot":restored,
        }
    if action == "ISOLATE":
        expected = request.get("expected_processes")
        fresh = graph("PRE_ISOLATION", BASELINE, True, 15.0)
        if not exact_topology(fresh, BASELINE, require_processes=True):
            raise Blocked("N7_PHYSICAL_BASELINE_TOPOLOGY_MISMATCH")
        if not isinstance(expected, list) or expected != fresh["processes"]:
            raise Blocked("N7_PHYSICAL_PROCESS_IDENTITY_CHANGED")
        terminate_exact(fresh["processes"])
        isolated = wait_graph("ISOLATED", ISOLATED, False, 15.0)
        return {
            "schema_version": "rolo-n7-isolation-receipt/v1",
            "ok": True,
            "stage_root": str(path),
            "terminated_processes": fresh["processes"],
            "snapshot": isolated,
        }
    if action == "RESTORE":
        previous_group = capture_bringup_group()
        stop_signal = stop_bringup_group(previous_group)
        launch_bringup()
        restored = wait_graph("RESTORED", BASELINE, True, 45.0)
        replacement_group = capture_bringup_group()
        if replacement_group["group_digest"] == previous_group["group_digest"]:
            raise Blocked("N7_PHYSICAL_BRINGUP_RESTORE_IDENTITY_REUSED")
        return {
            "schema_version": "rolo-n7-bringup-restore/v1",
            "ok": True,
            "stage_root": str(path),
            "stop_signal":stop_signal,
            "previous_group":previous_group,
            "replacement_group":replacement_group,
            "snapshot": restored,
        }
    if action == "CLEANUP":
        marker = path / ".rolo-n7-owner"
        marker.unlink()
        # The owner marker is removed first and no other action can pass
        # verify_stage after this point.  Delete only the exact regex-bound root.
        shutil.rmtree(path)
        return {
            "schema_version": "rolo-n7-stage-cleanup/v1",
            "ok": True,
            "stage_root": str(path),
            "residual_count": int(path.exists()),
        }
    raise Blocked("N7_PHYSICAL_RPC_ACTION_UNSUPPORTED")

try:
    raw = sys.stdin.buffer.read(64 * 1024 + 1)
    if not raw or len(raw) > 64 * 1024:
        raise Blocked("N7_PHYSICAL_RPC_REQUEST_LIMIT")
    request = json.loads(raw.decode("ascii"))
    if not isinstance(request, dict):
        raise Blocked("N7_PHYSICAL_RPC_REQUEST_INVALID")
    emit(main(request))
except Exception as exc:
    code = str(exc)
    if re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", code) is None:
        code = "N7_PHYSICAL_REMOTE_BLOCKED"
    emit({"schema_version": "rolo-n7-remote-error/v1", "ok": False, "error": code})
    raise SystemExit(2)
'''


_LIVE_DESCRIPTOR_SCHEMA = "rolo-n7-sealed-live-composition/v1"
_LIVE_DESCRIPTOR_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "session_id",
        "call_id",
        "target_id",
        "user_attestation",
        "created_at",
        "expires_at",
        "artifact_root",
        "bundle_verification_key_path",
        "bundle_verification_key_sha256",
        "artifact_signing_key_path",
        "artifact_signing_key_sha256",
        "bundle_source_base64",
        "execution_request",
        "manifest",
        "policy",
        "mapping_confirmation_receipt",
        "release",
        "release_digest",
        "catalog",
        "ssh_binding",
        "descriptor_sha256",
    }
)
_LIVE_SSH_BINDING_KEYS = frozenset(
    {
        "ssh_host",
        "ssh_port",
        "ssh_username",
        "pinned_host_key_sha256",
        "client_public_key_sha256",
        "known_hosts_sha256",
    }
)
_LIVE_BUNDLE_SOURCE = (
    b"def execute(arguments, provider):\n"
    b"    raise RuntimeError('N7 physical execution requires the sealed process worker')\n"
)
_DEFAULT_USER_ATTESTATION = (
    "不用演练现场急停、人员、安全区，现场已经妥善安排，仅剩完成实现上真机调试；"
)


@dataclass(frozen=True)
class SealedLiveComposition:
    """Strict, secret-minimal local descriptor for one N7 debug call."""

    descriptor_path: Path
    descriptor_sha256: str
    run_id: str
    session_id: str
    call_id: str
    target_id: str
    user_attestation: str
    created_at: datetime
    expires_at: datetime
    artifact_root: Path
    bundle_verification_key_path: Path
    bundle_verification_key: bytes = field(repr=False)
    artifact_signing_key_path: Path
    artifact_signing_key: bytes = field(repr=False)
    bundle_source: bytes = field(repr=False)
    request: ExecutionRequestV3
    manifest: ExecutionBundleManifest
    policy: MotionSafetyPolicy
    mapping_confirmation_receipt: MappingConfirmationReceipt
    release: ToolRelease
    release_digest: str
    catalog: TargetCatalog
    ssh_binding: Mapping[str, object]


def _live_ssh_binding(config: PinnedSshConfiguration) -> dict[str, object]:
    return {
        "ssh_host": config.host,
        "ssh_port": config.port,
        "ssh_username": config.user,
        "pinned_host_key_sha256": config.pinned_host_key_fingerprint,
        "client_public_key_sha256": config.public_key_fingerprint,
        "known_hosts_sha256": config.known_hosts_digest,
    }


def _write_private_bytes(path: Path, payload: bytes) -> None:
    path = Path(os.path.abspath(os.fspath(path)))
    path.parent.mkdir(parents=True, exist_ok=True)
    if any(
        ancestor.exists() and _is_link_or_reparse(ancestor)
        for ancestor in (path.parent, *path.parent.parents)
    ):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_DESCRIPTOR_PATH_UNSAFE",
            "sealed composition key path crosses a link or reparse point",
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            written = handle.write(payload)
            if written != len(payload):
                raise OSError("short private-key write")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(path, 0o600)
    except FileExistsError as exc:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_DESCRIPTOR_KEY_EXISTS",
            "sealed composition never overwrites a key file",
        ) from exc


def _read_private_bytes(path_value: object, *, digest: object, label: str) -> tuple[Path, bytes]:
    if not isinstance(path_value, str) or not path_value:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_DESCRIPTOR_KEY_INVALID",
            f"{label} key path is missing",
        )
    path = Path(path_value)
    try:
        absolute = path.resolve(strict=True)
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as exc:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_DESCRIPTOR_KEY_INVALID",
            f"{label} key is unavailable",
        ) from exc
    if (
        not path.is_absolute()
        or absolute != path
        or _is_link_or_reparse(path)
        or not stat.S_ISREG(metadata.st_mode)
        or not 32 <= len(payload) <= 4096
        or (os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o600)
        or digest != "sha256:" + hashlib.sha256(payload).hexdigest()
    ):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_DESCRIPTOR_KEY_INVALID",
            f"{label} key identity, mode, or digest is invalid",
        )
    return path, payload


def _write_live_descriptor(path: Path, payload: Mapping[str, object]) -> Path:
    target = Path(os.path.abspath(os.fspath(path)))
    target.parent.mkdir(parents=True, exist_ok=True)
    if any(
        ancestor.exists() and _is_link_or_reparse(ancestor)
        for ancestor in (target.parent, *target.parent.parents)
    ):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_DESCRIPTOR_PATH_UNSAFE",
            "sealed composition descriptor path crosses a link or reparse point",
        )
    encoded = json.dumps(
        dict(payload),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    ) + "\n"
    if len(encoded.encode("ascii")) > _MAX_HOST_BOOTSTRAP_BYTES:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_DESCRIPTOR_LIMIT",
            "sealed composition descriptor exceeds 512 KiB",
        )
    try:
        write_new_artifact(target, encoded)
    except FileExistsError as exc:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_DESCRIPTOR_EXISTS",
            "sealed composition descriptors are immutable",
        ) from exc
    return target


def create_sealed_live_composition_descriptor(
    config: PinnedSshConfiguration,
    *,
    output_path: Path,
    key_root: Path,
    artifact_root: Path,
    run_id: str,
    session_id: str,
    call_id: str,
    user_attestation: str = _DEFAULT_USER_ATTESTATION,
    now: datetime | None = None,
    bundle_signing_key: bytes | None = None,
    artifact_signing_key: bytes | None = None,
) -> SealedLiveComposition:
    """Generate and persist one fresh debug-only Release-bound descriptor.

    Only the bundle-verification and controller artifact keys are persisted,
    as exact mode-0600 files named by this run.  Session resume material and
    the four targetd/graph/target/peer bootstrap keys are generated later in
    memory and never appear in this descriptor.
    """

    if not isinstance(config, PinnedSshConfiguration):
        raise TypeError("sealed composition requires pinned SSH configuration")
    inputs = N7PhysicalTraceInputs(
        run_id=run_id,
        session_id=session_id,
        call_id=call_id,
        user_attestation=user_attestation,
    )
    point = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if now is not None and (now.tzinfo is None or now.utcoffset() is None):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_CLOCK_INVALID",
            "descriptor clock must be timezone-aware",
        )
    bundle_key = bundle_signing_key or os.urandom(32)
    artifact_key = artifact_signing_key or os.urandom(32)
    if (
        not isinstance(bundle_key, bytes)
        or not isinstance(artifact_key, bytes)
        or not 32 <= len(bundle_key) <= 4096
        or not 32 <= len(artifact_key) <= 4096
        or hmac.compare_digest(bundle_key, artifact_key)
    ):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_DESCRIPTOR_KEY_ROLE_COLLISION",
            "bundle and artifact keys must be independent 32-4096 byte values",
        )
    key_directory = Path(os.path.abspath(os.fspath(key_root)))
    bundle_key_path = key_directory / f"{run_id}.bundle-verification.key"
    artifact_key_path = key_directory / f"{run_id}.artifact-signing.key"
    created_keys: list[Path] = []
    try:
        _write_private_bytes(bundle_key_path, bundle_key)
        created_keys.append(bundle_key_path)
        _write_private_bytes(artifact_key_path, artifact_key)
        created_keys.append(artifact_key_path)

        target_fingerprint = hashlib.sha256(
            _canonical_bytes(
                {
                    "schema_version": "rolo-n7-debug-target-fingerprint/v1",
                    **_live_ssh_binding(config),
                }
            )
        ).hexdigest()
        surface_digest = hashlib.sha256(
            _canonical_bytes(
                {
                    "schema_version": "rolo-n7-debug-surface/v1",
                    "target_id": TARGET_ID,
                    "command_route": COMMAND_ROUTE,
                    "competing_command_route": COMPETING_COMMAND_ROUTE,
                    "direct_motor_route": DIRECT_MOTOR_ROUTE,
                }
            )
        ).hexdigest()
        binding_digest = hashlib.sha256(
            _canonical_bytes(
                {
                    "schema_version": "rolo-n7-bounded-rotation-binding/v1",
                    "tool_id": TOOL_ID,
                    "operation": "base.rotate",
                    "motion": inputs.spec.arguments(),
                }
            )
        ).hexdigest()
        runtime_sha256 = landerpi_bounded_twist_runtime_sha256()
        manifest = ExecutionBundleManifest.build(
            tool_id=TOOL_ID,
            source=_LIVE_BUNDLE_SOURCE,
            binding_digest=binding_digest,
            signer_key_id="debug-controller:n7-bundle",
            signing_key=bundle_key,
            observation_contract={
                "provider": "ros-container",
                "operation": "base.rotate",
                "command_endpoint": COMMAND_ROUTE,
                "feedback_endpoints": ["/odom_raw", "/odom"],
                "independent_feedback_endpoints": [
                    "/imu",
                    "/imu_corrected",
                    "/ros_robot_controller/imu_raw",
                ],
                "interface_type": COMMAND_INTERFACE,
                "stop_strategy": "zero_velocity",
                "provider_runtime_sha256": runtime_sha256,
            },
            limits={"max_duration_s": 75, "max_output_bytes": 65_536},
            release_version="n7-debug-user-attested",
        )
        catalog = TargetCatalog(
            target_id=TARGET_ID,
            target_fingerprint=target_fingerprint,
            snapshot_digest=hashlib.sha256(
                _canonical_bytes(
                    {
                        "schema_version": "rolo-n7-debug-catalog-snapshot/v1",
                        "target_fingerprint": target_fingerprint,
                        "bundle_digest": manifest.bundle_digest,
                    }
                )
            ).hexdigest(),
            surface_digest=surface_digest,
            generated_at=point,
            freshness="fresh",
            tools=[
                CatalogTool(
                    tool_id=TOOL_ID,
                    target_id=TARGET_ID,
                    state=ToolState.CALLABLE,
                    agent_callable=True,
                    access="experimental_write",
                    experimental_write=True,
                    descriptor_digest=binding_digest,
                    source="n7-debug-sealed-composition",
                    evidence_ids=["DEBUG_ONLY_USER_ATTESTED"],
                    parameters={
                        "angle_degrees": {"required": True, "exact": 1.0},
                        "max_speed_rad_s": {"required": True, "exact": 0.03},
                    },
                    # The targetd adapter persists ``created_at`` and requires
                    # request.deadline == created_at + this timeout.  Bind the
                    # full sealed request window so materialization uses the
                    # descriptor creation instant, never a fabricated future
                    # controller clock.  The physical worker remains bounded
                    # independently by manifest.max_duration_s == 75.
                    timeout_s=300.0,
                    limitations=[
                        "DEBUG_ONLY_USER_ATTESTED",
                        "production_authority=false",
                        "fresh_estop_challenge_verified=false",
                    ],
                )
            ],
        ).with_digest()
        assert catalog.digest is not None
        context_digest = mapping_digest(
            {"schema_version": "rolo-n7-debug-context/v1", "surface_digest": surface_digest}
        )
        evidence_digest = mapping_digest(
            {
                "schema_version": "rolo-n7-debug-evidence/v1",
                "authority_class": "DEBUG_ONLY_USER_ATTESTED",
                "user_attestation_digest": compute_motion_payload_digest(
                    {
                        "schema_version": "rolo-debug-user-attestation-basis/v1",
                        "basis_text": user_attestation,
                    }
                ),
            }
        )
        scope = MappingAdmissionScope(
            tool_id=TOOL_ID,
            operation_kind="EXECUTE",
            operations=("base.rotate",),
            access="experimental_write",
            risk="R3",
        )
        mapping_identity = MappingAdmissionIdentity.build(
            journey_session_id=session_id,
            target_id=TARGET_ID,
            target_fingerprint=target_fingerprint,
            candidate_index_digest=mapping_digest(
                {"schema_version": "rolo-n7-debug-candidate-index/v1", "tool_id": TOOL_ID}
            ),
            candidate_digest=mapping_digest(
                {"schema_version": "rolo-n7-debug-candidate/v1", "binding_digest": binding_digest}
            ),
            proposal_digest=mapping_digest(
                {"schema_version": "rolo-n7-debug-proposal/v1", "session_id": session_id}
            ),
            dsl_digest=mapping_digest(
                {"schema_version": "rolo-n7-debug-dsl/v1", "tool_id": TOOL_ID}
            ),
            context_digest=context_digest,
            evidence_digest=evidence_digest,
            available_tool_catalog_digest="sha256:" + catalog.digest,
            scope=scope,
        )
        mapping_receipt = MappingConfirmationReceipt.build(
            mapping_identity,
            sequence=1,
            decision_id=f"n7-map-{hashlib.sha256(run_id.encode('ascii')).hexdigest()[:20]}",
            actor_id="user-explicit-session-attestation",
            decision="CONFIRMED",
            decided_at=point,
            expires_at=point + timedelta(seconds=600),
            supersedes_receipt_digest=None,
            previous_receipt_digest=None,
        )
        release = ToolRelease(
            tool_id=TOOL_ID,
            target_id=TARGET_ID,
            operation_kind="EXECUTE",
            dsl_digest=mapping_identity.dsl_digest,
            ir_digest=mapping_digest(
                {"schema_version": "rolo-n7-debug-ir/v1", "binding_digest": binding_digest}
            ),
            probe_evidence_digest=evidence_digest,
            mhs_manifest_digests=(),
            compiler_version="n7-debug-sealed/v1",
            generated_bundle_digest="sha256:" + manifest.bundle_digest,
            conformance_digest=mapping_digest(
                {"schema_version": "rolo-n7-debug-conformance/v1", "runtime": runtime_sha256}
            ),
            target_fingerprint=target_fingerprint,
            compile_context_digest=context_digest,
            route_digest=None,
            target_conformance_digest=mapping_digest(
                {"schema_version": "rolo-n7-debug-target-conformance/v1", "target": TARGET_ID}
            ),
            mapping_confirmation_receipt_digest=mapping_receipt.receipt_digest,
            mapping_admission=mapping_identity,
            status="PUBLISHED",
            agent_callable=True,
        )
        release_digest = tool_release_digest(release)
        catalog_head_digest = _digest(
            {
                "schema_version": "rolo-n7-debug-catalog-head/v1",
                "catalog_digest": catalog.digest,
            }
        )
        authority = TargetdExecutionAuthority.build(
            tool_id=TOOL_ID,
            target_id=TARGET_ID,
            target_fingerprint=target_fingerprint,
            bundle_digest=manifest.bundle_digest,
            binding_digest=manifest.binding_digest,
            surface_digest=surface_digest,
            release_digest=release_digest,
            context_digest=context_digest,
            mapping_confirmation_receipt_digest=mapping_receipt.receipt_digest,
            mapping_admission=mapping_identity,
            catalog_head_digest=catalog_head_digest,
            provider_id="ros-container",
            provider_operation="base.rotate",
            mode="SUPERVISED_FIELD_DEBUG",
            fence_epoch=1,
        )
        deadline = point + timedelta(seconds=300)
        subject_payload = {
            "schema_version": "rolo-execution-request/v3",
            # A formal Trace plan id is its journey session id.  Keeping the
            # targetd run id equal prevents a hidden controller-side alias.
            "run_id": session_id,
            "session_id": session_id,
            "target_id": TARGET_ID,
            "idempotency_key": call_id,
            "bundle_digest": manifest.bundle_digest,
            "binding_digest": manifest.binding_digest,
            "surface_digest": surface_digest,
            "release_digest": release_digest,
            "context_digest": context_digest,
            "mapping_confirmation_receipt_digest": mapping_receipt.receipt_digest,
            "authority_head_digest": authority.authority_head_digest,
            "fence_epoch": authority.fence_epoch,
            "provider_id": authority.provider_id,
            "provider_operation": authority.provider_operation,
            "authority": authority,
            "arguments": inputs.spec.arguments(),
            "mode": authority.mode,
            "deadline": deadline,
        }
        subject_digest = execution_subject_digest(subject_payload)
        target_identity = mapping_identity.target_identity_digest
        graph_digest = compute_ros_graph_digest(
            target_id=TARGET_ID,
            target_identity=target_identity,
            observed_at=point,
            command_route=COMMAND_ROUTE,
            command_interface=COMMAND_INTERFACE,
            publisher_identities=[ROLO_PUBLISHER],
            direct_motor_route=DIRECT_MOTOR_ROUTE,
            direct_motor_interface=DIRECT_MOTOR_INTERFACE,
            direct_motor_publisher_identities=[ISOLATED_DIRECT_MOTOR_PUBLISHERS[0]],
        )
        direct_fence_digest = compute_direct_motor_fence_digest(
            execution_subject_digest=subject_digest,
            call_id=call_id,
            session_id=session_id,
            target_id=TARGET_ID,
            target_identity=target_identity,
            ros_graph_digest=graph_digest,
            command_route=COMMAND_ROUTE,
            publisher_identity=ROLO_PUBLISHER,
            direct_motor_route=DIRECT_MOTOR_ROUTE,
            direct_motor_interface=DIRECT_MOTOR_INTERFACE,
            direct_motor_publisher_identity=ISOLATED_DIRECT_MOTOR_PUBLISHERS[0],
            fence_epoch=authority.fence_epoch,
        )
        intent = MotionSafetyIntent(
            call_id=call_id,
            session_id=session_id,
            target_id=TARGET_ID,
            target_identity=target_identity,
            operator_id="operator:n7-onsite-user-attested",
            execution_subject_digest=subject_digest,
            requested_at=point,
            ros_graph_digest=graph_digest,
            command_route=COMMAND_ROUTE,
            command_interface=COMMAND_INTERFACE,
            publisher_identity=ROLO_PUBLISHER,
            direct_motor_route=DIRECT_MOTOR_ROUTE,
            direct_motor_interface=DIRECT_MOTOR_INTERFACE,
            direct_motor_publisher_identity=ISOLATED_DIRECT_MOTOR_PUBLISHERS[0],
            direct_motor_fence_digest=direct_fence_digest,
            stop_action_digest=compute_stop_action_digest(
                execution_subject_digest=subject_digest,
                call_id=call_id,
                session_id=session_id,
                target_id=TARGET_ID,
                target_identity=target_identity,
                ros_graph_digest=graph_digest,
                command_route=COMMAND_ROUTE,
                publisher_identity=ROLO_PUBLISHER,
                direct_motor_route=DIRECT_MOTOR_ROUTE,
                direct_motor_interface=DIRECT_MOTOR_INTERFACE,
                direct_motor_publisher_identity=ISOLATED_DIRECT_MOTOR_PUBLISHERS[0],
                direct_motor_fence_digest=direct_fence_digest,
            ),
        )
        request = ExecutionRequestV3.model_validate(
            {
                **subject_payload,
                "execution_subject_digest": subject_digest,
                "motion_safety_admission": MotionSafetyAdmissionRequest(
                    intent=intent,
                    evidence=MotionSafetyEvidenceBundle(),
                ),
            }
        )
        policy = MotionSafetyPolicy(
            target_id=TARGET_ID,
            target_identity=target_identity,
            site_id="site:landerpi-field-debug",
            safe_zone_id="zone:landerpi-bounded-pad",
            command_route=COMMAND_ROUTE,
            command_interface=COMMAND_INTERFACE,
            allowed_publisher_identity=ROLO_PUBLISHER,
            direct_motor_route=DIRECT_MOTOR_ROUTE,
            direct_motor_interface=DIRECT_MOTOR_INTERFACE,
            allowed_direct_motor_publisher_identity=ISOLATED_DIRECT_MOTOR_PUBLISHERS[0],
            operator_authority_id="authority:n7-debug-operator",
            presence_authority_id="authority:n7-debug-presence",
            safety_authority_id="authority:n7-debug-safety",
            graph_authority_id="authority:n7-debug-graph",
            target_authority_id="authority:n7-debug-target",
        )
        validate_landerpi_rotate_process_call(request, manifest)
        artifact_directory = Path(os.path.abspath(os.fspath(artifact_root)))
        unsigned: dict[str, object] = {
            "schema_version": _LIVE_DESCRIPTOR_SCHEMA,
            "run_id": run_id,
            "session_id": session_id,
            "call_id": call_id,
            "target_id": TARGET_ID,
            "user_attestation": user_attestation,
            "created_at": point,
            "expires_at": point + timedelta(seconds=180),
            "artifact_root": str(artifact_directory),
            "bundle_verification_key_path": str(bundle_key_path),
            "bundle_verification_key_sha256": "sha256:" + hashlib.sha256(bundle_key).hexdigest(),
            "artifact_signing_key_path": str(artifact_key_path),
            "artifact_signing_key_sha256": "sha256:" + hashlib.sha256(artifact_key).hexdigest(),
            "bundle_source_base64": base64.b64encode(_LIVE_BUNDLE_SOURCE).decode("ascii"),
            "execution_request": request.model_dump(mode="json"),
            "manifest": manifest.model_dump(mode="json"),
            "policy": policy.model_dump(mode="json"),
            "mapping_confirmation_receipt": mapping_receipt.model_dump(mode="json"),
            "release": release.model_dump(mode="json"),
            "release_digest": release_digest,
            "catalog": catalog.model_dump(mode="json"),
            "ssh_binding": _live_ssh_binding(config),
        }
        payload = {**unsigned, "descriptor_sha256": _digest(unsigned)}
        descriptor_path = _write_live_descriptor(output_path, payload)
        return load_sealed_live_composition_descriptor(
            descriptor_path,
            config=config,
            expected_run_id=run_id,
            now=point,
        )
    except Exception:
        # These exact files were created in this call and have not been
        # published as a usable descriptor.  Removing only them avoids a
        # misleading half-created authority pack.
        if not Path(output_path).exists():
            for created in reversed(created_keys):
                try:
                    created.unlink()
                except OSError:
                    pass
        raise


def load_sealed_live_composition_descriptor(
    descriptor_path: Path,
    *,
    config: PinnedSshConfiguration,
    expected_run_id: str,
    now: datetime | None = None,
) -> SealedLiveComposition:
    """Load and fully revalidate a descriptor before any live channel opens."""

    path = Path(os.path.abspath(os.fspath(descriptor_path)))
    point = now or datetime.now(timezone.utc)
    if point.tzinfo is None or point.utcoffset() is None:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_CLOCK_INVALID",
            "descriptor loader clock must be timezone-aware",
        )
    point = point.astimezone(timezone.utc)
    try:
        if (
            _is_link_or_reparse(path)
            or not path.is_file()
            or path.stat().st_size > _MAX_HOST_BOOTSTRAP_BYTES
        ):
            raise ValueError("descriptor path")
        raw = loads_unique_json(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_COMPOSITION_DESCRIPTOR_INVALID",
            "sealed composition descriptor is unsafe or invalid JSON",
        ) from exc
    if not isinstance(raw, dict) or set(raw) != _LIVE_DESCRIPTOR_KEYS:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_COMPOSITION_DESCRIPTOR_INVALID",
            "sealed composition descriptor fields differ from v1",
        )
    unsigned = dict(raw)
    claimed_descriptor_digest = unsigned.pop("descriptor_sha256", None)
    if (
        raw.get("schema_version") != _LIVE_DESCRIPTOR_SCHEMA
        or claimed_descriptor_digest != _digest(unsigned)
        or raw.get("run_id") != expected_run_id
        or raw.get("target_id") != TARGET_ID
        or not isinstance(raw.get("ssh_binding"), Mapping)
        or set(raw["ssh_binding"]) != _LIVE_SSH_BINDING_KEYS
        or dict(raw["ssh_binding"]) != _live_ssh_binding(config)
    ):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_COMPOSITION_DESCRIPTOR_IDENTITY_MISMATCH",
            "sealed composition digest, run, target, or pinned SSH identity differs",
        )
    try:
        created_at = _parse_time(raw.get("created_at"), label="descriptor created_at")
        expires_at = _parse_time(raw.get("expires_at"), label="descriptor expires_at")
        request = ExecutionRequestV3.model_validate(raw.get("execution_request"))
        manifest = ExecutionBundleManifest.model_validate(raw.get("manifest"))
        policy = MotionSafetyPolicy.model_validate(raw.get("policy"))
        mapping_receipt = MappingConfirmationReceipt.model_validate(
            raw.get("mapping_confirmation_receipt")
        )
        release = ToolRelease.model_validate(raw.get("release"))
        catalog = TargetCatalog.model_validate(raw.get("catalog"))
        if not isinstance(raw.get("bundle_source_base64"), str):
            raise ValueError("source")
        source = base64.b64decode(
            str(raw["bundle_source_base64"]).encode("ascii"),
            validate=True,
        )
        if base64.b64encode(source).decode("ascii") != raw["bundle_source_base64"]:
            raise ValueError("source encoding")
    except (TypeError, ValueError, binascii.Error) as exc:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_COMPOSITION_DESCRIPTOR_INVALID",
            "sealed composition typed payload is invalid",
        ) from exc
    bundle_key_path, bundle_key = _read_private_bytes(
        raw.get("bundle_verification_key_path"),
        digest=raw.get("bundle_verification_key_sha256"),
        label="bundle verification",
    )
    artifact_key_path, artifact_key = _read_private_bytes(
        raw.get("artifact_signing_key_path"),
        digest=raw.get("artifact_signing_key_sha256"),
        label="artifact signing",
    )
    try:
        artifact_root_value = raw.get("artifact_root")
        if not isinstance(artifact_root_value, str):
            raise ValueError("artifact root")
        artifact_root = Path(artifact_root_value)
        if not artifact_root.is_absolute() or artifact_root != artifact_root.resolve():
            raise ValueError("artifact root")
        for ancestor in (artifact_root, *artifact_root.parents):
            if ancestor.exists() and (
                _is_link_or_reparse(ancestor) or not ancestor.is_dir()
            ):
                raise ValueError("artifact root")
        manifest.verify_signature(bundle_key)
        validate_landerpi_rotate_process_call(request, manifest)
    except Exception as exc:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_COMPOSITION_DESCRIPTOR_BINDING_INVALID",
            "descriptor artifact root, bundle signature, or physical profile is invalid",
        ) from exc
    inputs = N7PhysicalTraceInputs(
        run_id=str(raw.get("run_id")),
        session_id=str(raw.get("session_id")),
        call_id=str(raw.get("call_id")),
        user_attestation=str(raw.get("user_attestation")),
    )
    authority = request.authority
    intent = request.motion_safety_admission.intent
    target_identity = authority.mapping_admission.target_identity_digest
    expected_graph_digest = compute_ros_graph_digest(
        target_id=TARGET_ID,
        target_identity=target_identity,
        observed_at=intent.requested_at,
        command_route=COMMAND_ROUTE,
        command_interface=COMMAND_INTERFACE,
        publisher_identities=[ROLO_PUBLISHER],
        direct_motor_route=DIRECT_MOTOR_ROUTE,
        direct_motor_interface=DIRECT_MOTOR_INTERFACE,
        direct_motor_publisher_identities=[ISOLATED_DIRECT_MOTOR_PUBLISHERS[0]],
    )
    expected_fence = compute_direct_motor_fence_digest(
        execution_subject_digest=request.execution_subject_digest,
        call_id=request.idempotency_key,
        session_id=request.session_id,
        target_id=request.target_id,
        target_identity=target_identity,
        ros_graph_digest=expected_graph_digest,
        command_route=COMMAND_ROUTE,
        publisher_identity=ROLO_PUBLISHER,
        direct_motor_route=DIRECT_MOTOR_ROUTE,
        direct_motor_interface=DIRECT_MOTOR_INTERFACE,
        direct_motor_publisher_identity=ISOLATED_DIRECT_MOTOR_PUBLISHERS[0],
        fence_epoch=authority.fence_epoch,
    )
    expected_stop = compute_stop_action_digest(
        execution_subject_digest=request.execution_subject_digest,
        call_id=request.idempotency_key,
        session_id=request.session_id,
        target_id=request.target_id,
        target_identity=target_identity,
        ros_graph_digest=expected_graph_digest,
        command_route=COMMAND_ROUTE,
        publisher_identity=ROLO_PUBLISHER,
        direct_motor_route=DIRECT_MOTOR_ROUTE,
        direct_motor_interface=DIRECT_MOTOR_INTERFACE,
        direct_motor_publisher_identity=ISOLATED_DIRECT_MOTOR_PUBLISHERS[0],
        direct_motor_fence_digest=expected_fence,
    )
    exact_tool = [item for item in catalog.tools if item.tool_id == TOOL_ID]
    catalog_head = _digest(
        {
            "schema_version": "rolo-n7-debug-catalog-head/v1",
            "catalog_digest": catalog.digest,
        }
    )
    runtime_sha256 = landerpi_bounded_twist_runtime_sha256()
    mapping_ttl = (
        (mapping_receipt.expires_at - mapping_receipt.decided_at).total_seconds()
        if mapping_receipt.expires_at is not None
        else math.nan
    )
    if (
        not (created_at <= point < expires_at <= request.deadline)
        or (point - created_at).total_seconds() < -5
        or request.deadline <= point + timedelta(seconds=10)
        or inputs.session_id != request.session_id
        or inputs.call_id != request.idempotency_key
        or request.run_id != request.session_id
        or request.target_id != TARGET_ID
        or request.arguments != MotionSpec().arguments()
        or request.mode != "SUPERVISED_FIELD_DEBUG"
        or request.provider_id != "ros-container"
        or request.provider_operation != "base.rotate"
        or request.motion_safety_admission.evidence != MotionSafetyEvidenceBundle()
        or intent.ros_graph_digest != expected_graph_digest
        or intent.direct_motor_fence_digest != expected_fence
        or intent.stop_action_digest != expected_stop
        or intent.operator_id != "operator:n7-onsite-user-attested"
        or policy.target_id != TARGET_ID
        or policy.target_identity != target_identity
        or policy.command_route != COMMAND_ROUTE
        or policy.command_interface != COMMAND_INTERFACE
        or policy.allowed_publisher_identity != ROLO_PUBLISHER
        or policy.direct_motor_route != DIRECT_MOTOR_ROUTE
        or policy.direct_motor_interface != DIRECT_MOTOR_INTERFACE
        or policy.allowed_direct_motor_publisher_identity
        != ISOLATED_DIRECT_MOTOR_PUBLISHERS[0]
        or policy.graph_authority_id == policy.target_authority_id
        or len(
            {
                policy.operator_authority_id,
                policy.presence_authority_id,
                policy.safety_authority_id,
                policy.graph_authority_id,
                policy.target_authority_id,
            }
        )
        != 5
        or mapping_receipt.decision != "CONFIRMED"
        or mapping_receipt.sequence != 1
        or mapping_receipt.previous_receipt_digest is not None
        or mapping_receipt.supersedes_receipt_digest is not None
        or not math.isfinite(mapping_ttl)
        or int(mapping_ttl) != mapping_ttl
        or not 1 <= int(mapping_ttl) <= 86_400
        or mapping_receipt.expires_at is None
        or mapping_receipt.expires_at <= request.deadline
        or mapping_receipt.admission_identity() != authority.mapping_admission
        or mapping_receipt.receipt_digest
        != authority.mapping_confirmation_receipt_digest
        or release.mapping_admission != authority.mapping_admission
        or release.mapping_confirmation_receipt_digest
        != mapping_receipt.receipt_digest
        or release.target_id != TARGET_ID
        or release.tool_id != TOOL_ID
        or release.operation_kind != "EXECUTE"
        or release.status != "PUBLISHED"
        or release.agent_callable is not True
        or release.target_fingerprint != authority.target_fingerprint
        or release.compile_context_digest != authority.context_digest
        or release.probe_evidence_digest
        != authority.mapping_admission.evidence_digest
        or release.generated_bundle_digest != "sha256:" + manifest.bundle_digest
        or raw.get("release_digest") != tool_release_digest(release)
        or authority.release_digest != raw.get("release_digest")
        or authority.bundle_digest != manifest.bundle_digest
        or authority.binding_digest != manifest.binding_digest
        or authority.surface_digest != catalog.surface_digest
        or authority.catalog_head_digest != catalog_head
        or manifest.release_version != "n7-debug-user-attested"
        or manifest.observation_contract.get("provider_runtime_sha256")
        != runtime_sha256
        or hashlib.sha256(source).hexdigest() != manifest.source_digest
        or source != _LIVE_BUNDLE_SOURCE
        or catalog.digest is None
        or catalog.target_id != TARGET_ID
        or catalog.target_fingerprint != authority.target_fingerprint
        or catalog.freshness != "fresh"
        or len(exact_tool) != 1
        or exact_tool[0].state != ToolState.CALLABLE
        or exact_tool[0].agent_callable is not True
        or exact_tool[0].access != "experimental_write"
        or exact_tool[0].experimental_write is not True
        or exact_tool[0].timeout_s != 300.0
        or exact_tool[0].descriptor_digest != manifest.binding_digest
        or hmac.compare_digest(bundle_key, artifact_key)
    ):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_COMPOSITION_DESCRIPTOR_BINDING_INVALID",
            "sealed descriptor Release, Mapping, request, policy, or key roles differ",
        )
    return SealedLiveComposition(
        descriptor_path=path,
        descriptor_sha256=str(claimed_descriptor_digest),
        run_id=inputs.run_id,
        session_id=inputs.session_id,
        call_id=inputs.call_id,
        target_id=inputs.target_id,
        user_attestation=inputs.user_attestation,
        created_at=created_at,
        expires_at=expires_at,
        artifact_root=artifact_root,
        bundle_verification_key_path=bundle_key_path,
        bundle_verification_key=bundle_key,
        artifact_signing_key_path=artifact_key_path,
        artifact_signing_key=artifact_key,
        bundle_source=source,
        request=request,
        manifest=manifest,
        policy=policy,
        mapping_confirmation_receipt=mapping_receipt,
        release=release,
        release_digest=str(raw["release_digest"]),
        catalog=catalog,
        ssh_binding=dict(raw["ssh_binding"]),
    )


class _SealedReleasePublisher:
    """Minimal one-release current-head view used only by this debug slice."""

    def __init__(
        self,
        root: Path,
        *,
        confirmation_store: MappingConfirmationStore,
        release_digest: str,
        release: ToolRelease,
    ) -> None:
        self.root = root
        self.confirmation_store = confirmation_store
        self._release_digest = release_digest
        self._release = release

    def current(self, tool_id: str) -> tuple[str, ToolRelease] | None:
        if tool_id != self._release.tool_id:
            return None
        return self._release_digest, self._release


def _reproduce_local_mapping_receipt(
    root: Path,
    receipt: MappingConfirmationReceipt,
) -> MappingConfirmationStore:
    if receipt.expires_at is None:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_MAPPING_RECEIPT_INVALID",
            "debug Mapping receipt has no expiry",
        )
    ttl = (receipt.expires_at - receipt.decided_at).total_seconds()
    if not math.isfinite(ttl) or int(ttl) != ttl or not 1 <= int(ttl) <= 86_400:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_MAPPING_RECEIPT_INVALID",
            "debug Mapping receipt TTL is not reproducible",
        )
    store = MappingConfirmationStore(root)
    reproduced = store.confirm(
        receipt.admission_identity(),
        decision_id=receipt.decision_id,
        actor_id=receipt.actor_id,
        ttl_s=int(ttl),
        decided_at=receipt.decided_at,
    )
    if reproduced != receipt or store.resolve(receipt.receipt_digest) != receipt:
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_MAPPING_RECEIPT_REPRODUCTION_FAILED",
            "controller Mapping ledger differs from the sealed receipt",
        )
    return store


class SealedLiveLanderPiChannel:
    """Bind container control and one persistent Pi-host targetd stdio.

    The graph/process RPC remains the separately pinned, exact command
    channel already used by the runner.  All targetd lifecycle operations use
    one and only one persistent SSH stdio process.  Its final signed footer is
    consumed before publisher restoration; a poisoned stream can only be
    handed to the host watchdog through :meth:`abort_preserve`.
    """

    def __init__(
        self,
        composition: SealedLiveComposition,
        config: PinnedSshConfiguration,
        *,
        bootstrap_keys: HostTargetdBootstrapKeys,
        repository_root: Path,
        container_channel: LanderPiControlChannel | None = None,
        host_channel: PinnedHostTargetdStdioChannel | Any | None = None,
        client_factory: Callable[[Any, JourneySession], JourneySessionClient] = JourneySessionClient,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            not isinstance(composition, SealedLiveComposition)
            or not isinstance(config, PinnedSshConfiguration)
            or not isinstance(bootstrap_keys, HostTargetdBootstrapKeys)
            or not callable(client_factory)
        ):
            raise ValueError("sealed live channel inputs are invalid")
        key_values = (
            bootstrap_keys.targetd_signing,
            bootstrap_keys.bundle_verification,
            bootstrap_keys.graph_signing,
            bootstrap_keys.target_signing,
            bootstrap_keys.peer_bootstrap_verification,
            composition.artifact_signing_key,
        )
        if len(set(key_values)) != len(key_values):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_BOOTSTRAP_KEY_ROLE_COLLISION",
                "every controller and targetd signing role must use a distinct key",
            )
        self.composition = composition
        self.config = config
        self.bootstrap_keys = bootstrap_keys
        self.container = container_channel or PinnedLanderPiSshChannel(config)
        self.host = host_channel or PinnedHostTargetdStdioChannel(
            config,
            run_id=composition.run_id,
            archive=build_host_targetd_source_archive(repository_root),
        )
        self.client_factory = client_factory
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        point = self._now()
        session_ttl = math.ceil(
            (composition.request.deadline - point).total_seconds()
        ) + 60
        if not 61 <= session_ttl <= 86_400:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_JOURNEY_WINDOW_INVALID",
                "journey lifetime does not cover the sealed request",
            )
        self.session = JourneySession(
            session_id=composition.session_id,
            target_id=composition.target_id,
            profile_id="landerpi-n7-debug",
            phase=JourneyPhase.BOOTSTRAP,
            surface_digest=composition.request.surface_digest,
            created_at=point,
            expires_at=point + timedelta(seconds=session_ttl),
            closed=False,
        )
        self.client: JourneySessionClient | None = None
        self.proof_verifier: TargetdPhysicalProofVerifier | None = None
        self._bootstrap_payload: dict[str, Any] | None = None
        self._lifecycle_receipts: dict[str, Any] = {}
        self._host_finalized = False
        self._restored = False
        self._aborted = False

    @property
    def channel_id(self) -> str:
        return _digest(
            {
                "schema_version": "rolo-n7-composed-channel/v1",
                "container_channel_id": self.container.channel_id,
                "host_targetd_channel_binding": self.host.channel_binding_sha256,
            }
        )

    def _now(self) -> datetime:
        point = self.clock()
        if not isinstance(point, datetime) or point.tzinfo is None or point.utcoffset() is None:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_CLOCK_INVALID",
                "live composition clock must be timezone-aware",
            )
        return point.astimezone(timezone.utc)

    def _client(self) -> JourneySessionClient:
        if self.client is None or self._aborted:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TARGETD_SESSION_NOT_OPEN",
                "the one-shot targetd journey is unavailable",
            )
        return self.client

    def _require_result(
        self,
        frame: ProtocolFrame,
        *,
        kind: FrameKind,
        run_id: str | None = None,
    ) -> ProtocolFrame:
        try:
            parsed = ProtocolFrame.model_validate(frame.model_dump(mode="python"))
        except (AttributeError, TypeError, ValueError) as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TARGETD_LIFECYCLE_INVALID",
                "targetd lifecycle response is invalid",
            ) from exc
        if (
            parsed.kind != FrameKind.RESULT
            or parsed.session_id != self.session.session_id
            or parsed.run_id != run_id
            or parsed.payload.get("request_kind") != kind.value
            or parsed.payload.get("ok") is not True
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TARGETD_LIFECYCLE_INVALID",
                f"targetd {kind.value} response identity differs",
            )
        self._lifecycle_receipts[kind.value] = {
            "response_frame_digest": parsed.frame_digest,
            "request_kind": kind.value,
            "run_id": run_id,
        }
        return parsed

    def stage(self, *, run_id: str, stage_root: str) -> Mapping[str, Any]:
        if (
            run_id != self.composition.run_id
            or stage_root != stage_root_for(run_id)
            or self.client is not None
            or self._aborted
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_LIVE_STAGE_SEQUENCE_INVALID",
                "live stage identity or sequence is invalid",
            )
        container_receipt = dict(
            self.container.stage(run_id=run_id, stage_root=stage_root)
        )
        host_stage = dict(self.host.open_stage())
        bootstrap = build_host_targetd_bootstrap(
            self.host,
            request=self.composition.request,
            manifest=self.composition.manifest,
            bundle_source=self.composition.bundle_source,
            policy=self.composition.policy,
            mapping_confirmation_receipt=(
                self.composition.mapping_confirmation_receipt
            ),
            keys=self.bootstrap_keys,
            now=self._now(),
        )
        self._bootstrap_payload = bootstrap
        ready = dict(self.host.bootstrap(bootstrap))
        self.client = self.client_factory(self.host, self.session)

        opened = self._require_result(
            self._client().exchange(
                FrameKind.OPEN_JOURNEY,
                {
                    "target_id": self.session.target_id,
                    "profile_id": self.session.profile_id,
                    "resume_token": self.session.resume_token,
                    "surface_digest": self.session.surface_digest,
                },
            ),
            kind=FrameKind.OPEN_JOURNEY,
        )
        try:
            remote_session = JourneySession.model_validate(
                opened.payload.get("session")
            )
        except (TypeError, ValueError) as exc:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TARGETD_OPEN_INVALID",
                "targetd OPEN returned no typed journey session",
            ) from exc
        if (
            remote_session.session_id != self.session.session_id
            or remote_session.target_id != self.session.target_id
            or remote_session.profile_id != self.session.profile_id
            or remote_session.resume_token != self.session.resume_token
            or remote_session.surface_digest != self.session.surface_digest
            or remote_session.phase != JourneyPhase.BOOTSTRAP
            or remote_session.closed
            or remote_session.expires_at <= self.composition.request.deadline
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TARGETD_OPEN_INVALID",
                "targetd OPEN session does not cover the exact sealed request",
            )
        self._require_result(
            self._client().exchange(
                FrameKind.BOOTSTRAP,
                {"session_id": self.session.session_id},
            ),
            kind=FrameKind.BOOTSTRAP,
        )
        handoff = self._require_result(
            self._client().handoff("PROBE"),
            kind=FrameKind.HANDOFF,
        )
        if handoff.payload.get("phase") != JourneyPhase.PROBE.value:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TARGETD_HANDOFF_INVALID",
                "targetd journey did not enter PROBE",
            )
        trace_phase = self._require_result(
            self._client().exchange(
                FrameKind.PHASE_CHANGE,
                {"phase": JourneyPhase.TRACE.value},
            ),
            kind=FrameKind.PHASE_CHANGE,
        )
        if trace_phase.payload.get("phase") != JourneyPhase.TRACE.value:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TARGETD_PHASE_INVALID",
                "targetd journey did not enter TRACE",
            )
        put = self._require_result(
            self._client().put_bundle(
                self.composition.manifest,
                self.composition.bundle_source,
            ),
            kind=FrameKind.PUT,
        )
        if (
            put.payload.get("present") is not True
            or put.payload.get("bundle_digest")
            != self.composition.manifest.bundle_digest
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TARGETD_BUNDLE_INVALID",
                "targetd did not retain the exact signed bundle",
            )
        return {
            **container_receipt,
            "host_targetd": {
                "stage": host_stage,
                "ready": ready,
                "bootstrap_payload_sha256": bootstrap["payload_sha256"],
                "descriptor_sha256": self.composition.descriptor_sha256,
                "ssh_binding": dict(self.composition.ssh_binding),
                "session": {
                    "session_id": remote_session.session_id,
                    "target_id": remote_session.target_id,
                    "profile_id": remote_session.profile_id,
                    "surface_digest": remote_session.surface_digest,
                    "created_at": remote_session.created_at,
                    "expires_at": remote_session.expires_at,
                    "closed": remote_session.closed,
                },
                "lifecycle": dict(self._lifecycle_receipts),
            },
        }

    def snapshot(self, *, stage_root: str, phase: str) -> Mapping[str, Any]:
        return self.container.snapshot(stage_root=stage_root, phase=phase)

    def sample_health(
        self,
        *,
        stage_root: str,
        phase: str,
        graph_topology_digest: str,
    ) -> Mapping[str, Any]:
        return self.container.sample_health(
            stage_root=stage_root,
            phase=phase,
            graph_topology_digest=graph_topology_digest,
        )

    def restart_bringup_once(
        self,
        *,
        stage_root: str,
        expected_processes: tuple[PublisherProcessIdentity, ...],
    ) -> Mapping[str, Any]:
        return self.container.restart_bringup_once(
            stage_root=stage_root,
            expected_processes=expected_processes,
        )

    def isolate(
        self,
        *,
        stage_root: str,
        expected_processes: tuple[PublisherProcessIdentity, ...],
    ) -> Mapping[str, Any]:
        return self.container.isolate(
            stage_root=stage_root,
            expected_processes=expected_processes,
        )

    # These are the only lifecycle write/read seams exposed to the prepared
    # bridge.  There is intentionally no call_remote or generic query_call.
    def prepare_physical_call_remote(self, request: ExecutionRequestV3) -> ProtocolFrame:
        return self._client().prepare_physical_call_remote(request)

    def accept_debug_zero_motion_remote(
        self,
        *,
        call_id: str,
        request_digest: str,
        armed_zero_receipt_digest: str,
        debug_admission: Mapping[str, object] | object,
    ) -> ProtocolFrame:
        return self._client().accept_debug_zero_motion_remote(
            call_id=call_id,
            request_digest=request_digest,
            armed_zero_receipt_digest=armed_zero_receipt_digest,
            debug_admission=debug_admission,
        )

    def start_prepared_physical_call_remote(
        self,
        *,
        call_id: str,
        request_digest: str,
        armed_zero_receipt_digest: str,
        provider_gate: Mapping[str, object] | object,
    ) -> ProtocolFrame:
        return self._client().start_prepared_physical_call_remote(
            call_id=call_id,
            request_digest=request_digest,
            armed_zero_receipt_digest=armed_zero_receipt_digest,
            provider_gate=provider_gate,
        )

    def query_physical_gate_remote(
        self,
        call_id: str,
        request_digest: str,
        *,
        gate_uri: str | None = None,
        gate_digest_uri: str | None = None,
    ) -> ProtocolFrame:
        return self._client().query_physical_gate_remote(
            call_id,
            request_digest,
            gate_uri=gate_uri,
            gate_digest_uri=gate_digest_uri,
        )

    def interrupt_process_remote(
        self,
        call_id: str,
        request_digest: str,
        *,
        intent: str,
    ) -> ProtocolFrame:
        return self._client().interrupt_process_remote(
            call_id,
            request_digest,
            intent=intent,
        )

    def finalize_before_restore(
        self,
        *,
        stage_root: str,
        inputs: N7PhysicalTraceInputs,
        attempt: TraceAttempt | None,
        authenticated_stop: AuthenticatedStopReceipt | None,
        post_snapshot: ControlGraphSnapshot,
    ) -> Mapping[str, Any]:
        if (
            self._host_finalized
            or self._bootstrap_payload is None
            or stage_root != stage_root_for(self.composition.run_id)
            or inputs.run_id != self.composition.run_id
            or inputs.session_id != self.composition.session_id
            or inputs.call_id != self.composition.call_id
            or self.proof_verifier is None
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_FINALIZE_SEQUENCE_INVALID",
                "host finalization identity or sequence is invalid",
            )
        terminal_receipt = self.proof_verifier.latest_terminal_receipt
        if terminal_receipt is None:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_TERMINAL_RECEIPT_MISSING",
                "host finalization has no fully verified targetd terminal receipt",
            )
        post_snapshot.require_isolated()
        result = dict(terminal_receipt.result or {})
        provider_count = _exact_count(
            result.get("provider_invocation_count"),
            maximum=1,
        )
        if attempt is not None and attempt.provider_invocation_count != provider_count:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_PROVIDER_COUNT_MISMATCH",
                "host terminal receipt differs from the Trace provider count",
            )
        final_zero = (
            bool(attempt and attempt.final_zero_verified)
            or bool(authenticated_stop and authenticated_stop.final_zero_verified)
        )
        stop_ack = (
            bool(attempt and attempt.stop_acknowledged)
            or bool(authenticated_stop and authenticated_stop.target_stop_acknowledged)
        )
        terminated = (
            bool(attempt and attempt.provider_terminated)
            or bool(authenticated_stop and authenticated_stop.provider_terminated)
        )
        closed = self._require_result(
            self._client().exchange(
                FrameKind.CLOSE_SESSION,
                {"session_id": self.session.session_id},
            ),
            kind=FrameKind.CLOSE_SESSION,
        )
        if closed.payload.get("closed") is not True:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TARGETD_CLOSE_INVALID",
                "targetd did not acknowledge CLOSE_SESSION",
            )
        finalize_payload = build_host_targetd_finalize_payload(
            self.host,
            request=self.composition.request,
            terminal_receipt=terminal_receipt,
            final_zero_verified=final_zero,
            stop_acknowledged=stop_ack,
            provider_terminated=terminated,
            post_isolated=post_snapshot,
            provider_invocation_count=provider_count,
            signing_key=self.bootstrap_keys.targetd_signing,
        )
        receipt = verify_host_targetd_finalize_receipt(
            self.host.exchange_finalize_record(finalize_payload),
            request_payload=finalize_payload,
            signing_key=self.bootstrap_keys.targetd_signing,
        )
        # A zero exit proves the staged host removed only its exact owner-
        # marked tmpfs root after the authenticated receipt was delivered.
        self.host.close()
        self._host_finalized = True
        return receipt

    def restore(self, *, stage_root: str) -> Mapping[str, Any]:
        if not self._host_finalized or self._restored:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_RESTORE_BEFORE_HOST_FINALIZE",
                "publisher restoration requires completed host finalization",
            )
        receipt = self.container.restore(stage_root=stage_root)
        self._restored = True
        return receipt

    def cleanup(self, *, stage_root: str) -> Mapping[str, Any]:
        if not self._host_finalized or not self._restored:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_CLEANUP_BEFORE_HOST_FINALIZE",
                "stage cleanup requires host finalization and publisher restoration",
            )
        receipt = dict(self.container.cleanup(stage_root=stage_root))
        receipt["host_targetd_cleanup"] = {
            "stage_root": self.host.stage_root,
            "residual_count": 0,
            "exit_verified": True,
            "finalize_receipt_digest": (
                (self.host.finalize_receipt or {}).get("receipt_payload_sha256")
            ),
        }
        return receipt

    def abort_preserve(self) -> None:
        if self._aborted or self._host_finalized:
            return
        self._aborted = True
        self.host.abort_preserve()


class _FreshDebugAcceptanceDriver:
    def __init__(
        self,
        composition: SealedLiveComposition,
        bridge: PreparedPhysicalTraceBridge,
        *,
        clock: Callable[[], datetime],
    ) -> None:
        self.composition = composition
        self.bridge = bridge
        self.clock = clock
        self._used = False

    def run(self) -> DebugUserAttestedAcceptanceReceipt:
        if self._used:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_DEBUG_ACCEPTANCE_REPLAY_BLOCKED",
                "debug acceptance is one-shot",
            )
        self._used = True
        point = self.clock().astimezone(timezone.utc)
        admission = DebugOnlyUserAttestedAdmission.build(
            attestation_id=(
                "n7-attestation-"
                + hashlib.sha256(self.composition.run_id.encode("ascii")).hexdigest()[:20]
            ),
            acceptance_id=(
                "n7-acceptance-"
                + hashlib.sha256(self.composition.call_id.encode("ascii")).hexdigest()[:20]
            ),
            intent=self.composition.request.motion_safety_admission.intent,
            policy=self.composition.policy,
            basis_text=self.composition.user_attestation,
            requested_rotation_degrees=DEFAULT_ANGLE_DEGREES,
            requested_linear_meters=0.0,
            issued_at=point,
            expires_at=min(point + timedelta(seconds=20), self.composition.request.deadline),
        )
        return self.bridge.accept_debug_zero_motion(admission)


def run_read_only_live_preflight(
    channel: LanderPiControlChannel,
    *,
    run_id: str,
) -> dict[str, Any]:
    """Run exactly STAGE -> BASELINE -> SAMPLE_HEALTH -> CLEANUP.

    This path has no isolation, pre-arm, acceptance, provider, or motion
    capability.  Cleanup is attempted once after a successful STAGE and its
    zero-residual receipt is part of the returned evidence.
    """

    preflight_id = "preflight-" + hashlib.sha256(run_id.encode("ascii")).hexdigest()[:20]
    inputs = N7PhysicalTraceInputs(
        run_id=run_id,
        session_id=preflight_id,
        call_id=preflight_id,
        user_attestation="READ_ONLY_PREFLIGHT_NO_MOTION",
    )
    stage_root = stage_root_for(run_id)
    staged = False
    cleanup: Mapping[str, Any] | None = None
    try:
        stage = dict(channel.stage(run_id=run_id, stage_root=stage_root))
        staged = True
        N7PhysicalTraceRunner._validate_stage(
            stage,
            inputs=inputs,
            stage_root=stage_root,
        )
        baseline = ControlGraphSnapshot.parse(
            channel.snapshot(stage_root=stage_root, phase="BASELINE"),
            phase="BASELINE",
        )
        baseline.require_baseline()
        health = FreshSensorHealthReceipt.parse(
            channel.sample_health(
                stage_root=stage_root,
                phase="BASELINE",
                graph_topology_digest=baseline.topology_digest(),
            ),
            phase="BASELINE",
            stage_root=stage_root,
            graph_topology_digest=baseline.topology_digest(),
        )
        health.require_healthy()
        result = {
            "schema_version": "rolo-landerpi-n7-read-only-preflight/v1",
            "status": "PASS",
            "motion_capability_present": False,
            "run_id": run_id,
            "target_id": TARGET_ID,
            "channel_id": channel.channel_id,
            "stage_root": stage_root,
            "stage": stage,
            "baseline": baseline.as_dict(),
            "sensor_health": health.as_dict(),
        }
    finally:
        if staged:
            cleanup = dict(channel.cleanup(stage_root=stage_root))
            if (
                cleanup.get("schema_version") != "rolo-n7-stage-cleanup/v1"
                or cleanup.get("ok") is not True
                or cleanup.get("stage_root") != stage_root
                or cleanup.get("residual_count") != 0
            ):
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_STAGE_CLEANUP_NOT_VERIFIED",
                    "read-only preflight did not prove zero stage residuals",
                )
    result["cleanup"] = dict(cleanup or {})
    result["evidence_digest"] = _digest(result)
    return result


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="N7 physical Trace composition boundary")
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--describe",
        action="store_true",
        help="print the bounded default plan; never connect",
    )
    action.add_argument(
        "--preflight-only",
        action="store_true",
        help="run one read-only graph and sensor preflight; never isolate or move",
    )
    action.add_argument(
        "--execute-once",
        action="store_true",
        help="explicitly authorize one sealed 1 degree debug Trace",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="allow a selected live action to open the pinned SSH connection",
    )
    parser.add_argument("--target", help="pinned LanderPi SSH host")
    parser.add_argument("--known-hosts", type=Path)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--identity-public", type=Path)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--run-id")
    parser.add_argument(
        "--composition",
        type=Path,
        help="sealed N7 live-composition descriptor for --execute-once",
    )
    return parser.parse_args(argv)


def _live_ssh_configuration(args: argparse.Namespace) -> PinnedSshConfiguration:
    if (
        not args.live
        or not args.target
        or args.known_hosts is None
        or args.identity is None
        or args.identity_public is None
        or not args.run_id
    ):
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_LIVE_OPT_IN_REQUIRED",
            "live mode requires --live, target, pinned host/key files, and run id",
        )
    return PinnedSshConfiguration(
        host=args.target,
        user="pi",
        known_hosts=args.known_hosts,
        identity_file=args.identity,
        public_key_file=args.identity_public,
        port=args.port,
    )


def _describe_payload() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "DESCRIBE_ONLY",
        "direct_execution": False,
        "default_motion": MotionSpec().arguments(),
        "authority_class": "DEBUG_ONLY_USER_ATTESTED",
        "production_authority": False,
        "required_control_topology": {
            "baseline_competing_publishers": list(BASELINE_COMPETING_PUBLISHERS),
            "isolated_competing_publishers": [],
            "isolated_direct_motor_publishers": list(
                ISOLATED_DIRECT_MOTOR_PUBLISHERS
            ),
        },
        "live_actions": ["--preflight-only", "--execute-once"],
    }


def execute_sealed_live_composition_once(
    config: PinnedSshConfiguration,
    *,
    descriptor_path: Path,
    run_id: str,
    clock: Callable[[], datetime] | None = None,
    container_channel_factory: Callable[[PinnedSshConfiguration], LanderPiControlChannel]
    | None = None,
    host_channel_factory: Callable[
        [PinnedSshConfiguration, str, HostTargetdSourceArchive], Any
    ]
    | None = None,
    source_archive_factory: Callable[[Path], HostTargetdSourceArchive]
    | None = None,
) -> dict[str, Any]:
    """Execute exactly one sealed, debug-only physical Trace.

    Descriptor verification finishes before either live channel is
    constructed.  PREPARE and ACCEPT happen before the formal Trace TOOL_CALL;
    that sole TOOL_CALL maps to START_PREPARED.  Any ambiguous transport state
    is handed to the host watchdog and leaves both tmpfs stages plus publisher
    isolation intact for manual reconciliation.
    """

    effective_clock = clock or (lambda: datetime.now(timezone.utc))
    composition = load_sealed_live_composition_descriptor(
        descriptor_path,
        config=config,
        expected_run_id=run_id,
        now=effective_clock(),
    )
    repository_root = Path(__file__).resolve().parents[1]
    archive_builder = source_archive_factory or build_host_targetd_source_archive
    archive = archive_builder(repository_root)
    container = (
        container_channel_factory(config)
        if container_channel_factory is not None
        else PinnedLanderPiSshChannel(config)
    )
    host = (
        host_channel_factory(config, run_id, archive)
        if host_channel_factory is not None
        else PinnedHostTargetdStdioChannel(
            config,
            run_id=run_id,
            archive=archive,
        )
    )
    bootstrap_keys = HostTargetdBootstrapKeys.generate(
        bundle_verification=composition.bundle_verification_key,
    )
    channel = SealedLiveLanderPiChannel(
        composition,
        config,
        bootstrap_keys=bootstrap_keys,
        repository_root=repository_root,
        container_channel=container,
        host_channel=host,
        clock=effective_clock,
    )

    state_root = composition.artifact_root / ".n7-live-controller" / run_id
    confirmation_store = _reproduce_local_mapping_receipt(
        state_root / "mapping-confirmations",
        composition.mapping_confirmation_receipt,
    )
    publisher = _SealedReleasePublisher(
        state_root / "release-current",
        confirmation_store=confirmation_store,
        release_digest=composition.release_digest,
        release=composition.release,
    )
    bridge = PreparedPhysicalTraceBridge(
        composition.request,
        composition.manifest,
        channel,
        terminal_query_budget=240,
        poll_interval_s=0.25,
        clock=effective_clock,
    )
    proof_verifier = TargetdPhysicalProofVerifier(
        composition.request,
        manifest=composition.manifest,
        manifest_verification_key=composition.bundle_verification_key,
        trust_store=MotionSafetyTrustStore(
            {
                composition.policy.graph_authority_id: bootstrap_keys.graph_signing,
                composition.policy.target_authority_id: bootstrap_keys.target_signing,
            }
        ),
        target_authority_id=composition.policy.target_authority_id,
        query_physical_remote=lambda call_id, request_digest, uri, digest_uri: (
            TargetdTraceResponse(
                frame=channel.query_physical_gate_remote(
                    call_id,
                    request_digest,
                    gate_uri=uri,
                    gate_digest_uri=digest_uri,
                ),
                sequence_correlated=True,
            )
        ),
        load_lease=bridge.load_worker_lease,
        stop_remote=lambda call_id, request_digest: TargetdTraceResponse(
            frame=channel.interrupt_process_remote(
                call_id,
                request_digest,
                intent="STOP",
            ),
            sequence_correlated=True,
        ),
        stop_query_budget=3,
    )
    channel.proof_verifier = proof_verifier
    tool_descriptor = next(
        item for item in composition.catalog.tools if item.tool_id == TOOL_ID
    )
    materialization_time = composition.request.deadline - timedelta(
        seconds=tool_descriptor.timeout_s
    )

    def physical_request_factory(
        plan: Any,
        planned_call: Any,
        authority: TargetdExecutionAuthority,
        now: datetime,
    ) -> ExecutionRequestV3:
        if (
            plan.session_id != composition.session_id
            or planned_call.idempotency_key != composition.call_id
            or planned_call.tool_id != TOOL_ID
            or planned_call.arguments != MotionSpec().arguments()
            or authority != composition.request.authority
            or now != materialization_time
        ):
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_TRACE_REQUEST_FACTORY_MISMATCH",
                "formal Trace plan differs from the sealed physical request",
            )
        return composition.request

    adapter = PreparedPhysicalTargetdTraceAdapter(
        composition.request.authority,
        bridge,
        authority_resolver=lambda tool_id: (
            composition.request.authority
            if tool_id == TOOL_ID
            else (_ for _ in ()).throw(KeyError(tool_id))
        ),
        request_store=DurableTraceRequestStore(
            state_root / "durable-targetd-requests"
        ),
        physical_request_factory=physical_request_factory,
        clock=lambda: materialization_time,
    )
    release_trace = ReleaseBoundTrace(
        composition.catalog,
        publisher,  # type: ignore[arg-type]
        release_digest=composition.release_digest,
        target_fingerprint=composition.release.target_fingerprint,
        evidence_digest=composition.release.probe_evidence_digest,
        compile_context_digest=composition.release.compile_context_digest,
        invoker=adapter,
        artifact_root=state_root / "trace-artifacts",
    )
    remaining = (
        composition.request.deadline - effective_clock().astimezone(timezone.utc)
    ).total_seconds()
    if not math.isfinite(remaining) or remaining <= 10:
        channel.abort_preserve()
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_REQUEST_DEADLINE_EXPIRED",
            "sealed request no longer has a safe execution window",
        )
    # The formal plan must outlive the targetd request.  Use an integral,
    # bounded TTL so clock fractions cannot shorten the sealed deadline.
    trace_ttl_s = min(86_400, math.ceil(remaining) + 30)
    trace_request = TraceSessionRequest(
        target_id=composition.target_id,
        catalog_digest=str(composition.catalog.digest),
        task="Execute one user-attested N7 bounded one-degree rotation",
        mode="SUPERVISED_FIELD_DEBUG",
        ttl_s=trace_ttl_s,
        max_calls=1,
        operator_id=composition.request.motion_safety_admission.intent.operator_id,
        safety_confirmed=True,
        session_id=composition.session_id,
    )
    trace_call = TraceCall(
        tool_id=TOOL_ID,
        arguments=MotionSpec().arguments(),
        idempotency_key=composition.call_id,
    )
    driver = ReleaseBoundPhysicalTraceDriver(
        release_trace,
        trace_request,
        trace_call,
        prepare_provider=bridge.prepare_zero_motion,
        proof_verifier=proof_verifier,
        provider_gate_preflight=bridge.bind_provider_gate,
    )
    acceptance = _FreshDebugAcceptanceDriver(
        composition,
        bridge,
        clock=effective_clock,
    )
    runner = N7PhysicalTraceRunner(
        composition.artifact_root,
        artifact_signing_key=composition.artifact_signing_key,
        clock=effective_clock,
    )
    try:
        report = runner.run(
            N7PhysicalTraceInputs(
                run_id=composition.run_id,
                session_id=composition.session_id,
                call_id=composition.call_id,
                user_attestation=composition.user_attestation,
            ),
            channel=channel,
            acceptance=acceptance,
            trace=driver,
        )
    except Exception as exc:
        channel.abort_preserve()
        if isinstance(exc, N7PhysicalBlocked):
            raise
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_LIVE_COMPOSITION_FAILED",
            f"sealed live composition failed closed: {type(exc).__name__}",
        ) from exc
    if report.get("status") != "PASS_WITH_USER_ATTESTED_SITE_SAFETY":
        channel.abort_preserve()
    elif not (
        report.get("host_finalize_verified") is True
        and report.get("restore_verified") is True
        and report.get("stage_cleanup_verified") is True
    ):
        channel.abort_preserve()
        raise N7PhysicalBlocked(
            "N7_PHYSICAL_LIVE_COMPLETION_PROOF_INVALID",
            "successful debug report lacks finalize, restore, or cleanup proof",
        )
    return report


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if not args.preflight_only and not args.execute_once:
        print(
            json.dumps(
                _describe_payload(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    try:
        config = _live_ssh_configuration(args)
        if args.preflight_only:
            payload = run_read_only_live_preflight(
                PinnedLanderPiSshChannel(config),
                run_id=args.run_id,
            )
            code = 0
        else:
            if args.composition is None:
                raise N7PhysicalBlocked(
                    "N7_PHYSICAL_COMPOSITION_DESCRIPTOR_REQUIRED",
                    "--execute-once requires one sealed composition descriptor",
                )
            payload = execute_sealed_live_composition_once(
                config,
                descriptor_path=args.composition,
                run_id=args.run_id,
            )
            code = (
                0
                if payload.get("status")
                == "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
                else 2
            )
    except N7PhysicalBlocked as exc:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "status": "BLOCKED",
            "code": exc.code,
            "message": exc.message,
            "production_authority": False,
        }
        code = 2
    print(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=_json_default,
        )
    )
    return code


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "BASELINE_COMPETING_PUBLISHERS",
    "ControlGraphSnapshot",
    "HostTargetdBootstrapKeys",
    "MotionSpec",
    "N7PhysicalBlocked",
    "N7PhysicalTraceInputs",
    "N7PhysicalTraceRunner",
    "PinnedLanderPiSshChannel",
    "PinnedSshConfiguration",
    "PublisherProcessIdentity",
    "ReleaseBoundPhysicalTraceDriver",
    "SealedLiveComposition",
    "SealedLiveLanderPiChannel",
    "TraceAttempt",
    "create_sealed_live_composition_descriptor",
    "execute_sealed_live_composition_once",
    "host_targetd_stage_root_for",
    "load_sealed_live_composition_descriptor",
    "stage_root_for",
]
