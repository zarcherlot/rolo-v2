"""One-shot Pi-host composition for the N7 debug physical acceptance.

This module is imported only by ``scripts.landerpi_n7_targetd_host`` after
that launcher has authenticated its exact tmpfs stage and bootstrap record.
It intentionally exposes no generic command surface: one validated v3
``base.rotate`` request is provisioned, one physical worker may be prepared,
and cleanup is authorized only after targetd revalidates the durable terminal
receipt, the exact inner-process exit, and the final isolated control graph.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import os
import re
import shutil
import threading
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rolo.core.persistence import atomic_write_text
from rolo.dsl.admission import (
    MappingAdmissionGate,
    MappingConfirmationReceipt,
    MappingConfirmationStore,
)
from rolo.targetd.daemon import TargetdDaemon
from rolo.targetd.landerpi_motion_target import (
    DebugOnlyUserAttestedAdmission,
    DebugPinnedPeerBootstrapReplayStore,
    DebugPinnedTargetdPeerBootstrapReceipt,
    DebugUserAttestedAcceptanceReceipt,
    LanderPiTargetMotionState,
    PinnedKeyOnlyLanderPiMotionRpc,
    TargetdDockerPinnedReadControlTransport,
    TargetSigningKey,
    compose_landerpi_zero_motion_target,
    consume_debug_pinned_targetd_peer_bootstrap,
    run_debug_user_attested_zero_motion_acceptance,
)
from rolo.targetd.lifecycle import WorkerCallKey, WorkerLeaseRecord, WorkerLeaseStore
from rolo.targetd.motion_acceptance import LanderPiIsolationObservation
from rolo.targetd.motion_safety import (
    MotionSafetyIntent,
    MotionSafetyPolicy,
    MotionSafetyTrustStore,
)
from rolo.targetd.physical_acceptance import DebugPhysicalAcceptanceReceiptStore
from rolo.targetd.physical_gate import (
    DebugUserAttestedPhysicalProviderGate,
    PhysicalProviderGateReceiptStore,
)
from rolo.targetd.physical_worker import (
    LanderPiRotateProcessWorker,
    cleanup_terminal_registry,
    landerpi_bounded_twist_runtime_sha256,
    parse_physical_worker_armed_zero,
    read_target_physical_worker_terminal_registry,
    recover_persisted_armed_zero,
    validate_landerpi_rotate_process_call,
)
from rolo.targetd.process_worker import LeasedProcessWorkerRuntime
from rolo.targetd.protocol import (
    ExecutionBundleManifest,
    ExecutionRequestV3,
    ProtocolError,
    TargetdCallReceipt,
    TargetdExecutionAuthority,
    TargetdExecutionAuthorityStore,
)
from rolo.targetd.service import TargetdService
from rolo.targetd.worker import RosContainerProvider

_BOOTSTRAP_SCHEMA = "rolo-n7-targetd-host-bootstrap/v1"
_READY_SCHEMA = "rolo-n7-targetd-host-ready/v1"
_FINALIZE_SCHEMA = "rolo-n7-targetd-host-finalize/v1"
_FINALIZE_RECEIPT_SCHEMA = "rolo-n7-targetd-host-finalize-receipt/v1"
_RECOVERY_SCHEMA = "rolo-n7-targetd-host-recovery/v1"
_STAGE_ROOT = re.compile(r"^/dev/shm/rolo-n7-targetd-[0-9a-f]{20}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_RAW_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HMAC_SHA256 = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_TERMINAL_STATES = frozenset({"SUCCEEDED", "FAILED", "STOPPED", "CANCELLED"})
_ACTIVE_STATES = frozenset({"CLAIMED", "RUNNING", "CANCEL_REQUESTED", "STOP_REQUESTED"})
_MAX_SOURCE_BYTES = 256 * 1024
_OWNER_MARKER = ".rolo-n7-targetd-owner"

_FINALIZE_CORE_KEYS = (
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
_FINALIZE_KEYS = {
    "schema_version",
    *_FINALIZE_CORE_KEYS,
    "finalize_payload_sha256",
    "finalize_auth_tag",
}


class N7HostCompositionError(RuntimeError):
    """Stable internal fail-closed condition for the staged composition."""


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
            default=_json_default,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise N7HostCompositionError("N7_TARGETD_CANONICAL_JSON_INVALID") from exc


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise TypeError("naive datetime")
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    raise TypeError(type(value).__name__)


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _decode_base64(value: object, *, label: str, maximum: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > (maximum * 2) + 16:
        raise N7HostCompositionError(f"N7_TARGETD_{label}_INVALID")
    try:
        result = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeError, binascii.Error, ValueError) as exc:
        raise N7HostCompositionError(f"N7_TARGETD_{label}_INVALID") from exc
    if not result or len(result) > maximum:
        raise N7HostCompositionError(f"N7_TARGETD_{label}_INVALID")
    return result


def _decode_key(value: object, *, label: str) -> bytes:
    key = _decode_base64(value, label=label, maximum=4096)
    if len(key) < 32:
        raise N7HostCompositionError(f"N7_TARGETD_{label}_INVALID")
    return key


def _require_stage_root(stage_root: Path, bootstrap: Mapping[str, object]) -> Path:
    root = Path(stage_root)
    if (
        not root.is_absolute()
        or _STAGE_ROOT.fullmatch(str(root)) is None
        or root.resolve() != root
        or bootstrap.get("stage_root") != str(root)
    ):
        raise N7HostCompositionError("N7_TARGETD_STAGE_ROOT_INVALID")
    try:
        metadata = root.lstat()
        marker = (root / _OWNER_MARKER).lstat()
    except OSError as exc:
        raise N7HostCompositionError("N7_TARGETD_STAGE_ROOT_INVALID") from exc
    if (
        not root.is_dir()
        or root.is_symlink()
        or not (root / _OWNER_MARKER).is_file()
        or (root / _OWNER_MARKER).is_symlink()
        or (os.name != "nt" and (metadata.st_mode & 0o777) != 0o700)
        or (os.name != "nt" and (marker.st_mode & 0o777) != 0o600)
    ):
        raise N7HostCompositionError("N7_TARGETD_STAGE_ROOT_INVALID")
    return root


def _bootstrap_digest(bootstrap: Mapping[str, object]) -> str:
    unsigned = dict(bootstrap)
    unsigned.pop("payload_sha256", None)
    return _digest(unsigned)


def _parse_bootstrap(
    bootstrap: Mapping[str, object],
    *,
    stage_root: Path,
) -> tuple[
    ExecutionRequestV3,
    ExecutionBundleManifest,
    bytes,
    MotionSafetyPolicy,
    MotionSafetyIntent,
    TargetdExecutionAuthority,
    MappingConfirmationReceipt,
    DebugPinnedTargetdPeerBootstrapReceipt,
    dict[str, Any],
    dict[str, bytes],
]:
    if not isinstance(bootstrap, Mapping) or bootstrap.get("schema_version") != _BOOTSTRAP_SCHEMA:
        raise N7HostCompositionError("N7_TARGETD_BOOTSTRAP_INVALID")
    _require_stage_root(stage_root, bootstrap)
    if bootstrap.get("payload_sha256") != _bootstrap_digest(bootstrap):
        raise N7HostCompositionError("N7_TARGETD_BOOTSTRAP_DIGEST_INVALID")
    try:
        request = ExecutionRequestV3.model_validate(bootstrap.get("execution_request"))
        manifest = ExecutionBundleManifest.model_validate(bootstrap.get("manifest"))
        policy = MotionSafetyPolicy.model_validate(bootstrap.get("policy"))
        intent = MotionSafetyIntent.model_validate(bootstrap.get("motion_intent"))
        authority = TargetdExecutionAuthority.model_validate(bootstrap.get("authority"))
        mapping_receipt = MappingConfirmationReceipt.model_validate(
            bootstrap.get("mapping_confirmation_receipt")
        )
        peer_receipt = DebugPinnedTargetdPeerBootstrapReceipt.model_validate(
            bootstrap.get("peer_bootstrap_receipt")
        )
    except Exception as exc:
        raise N7HostCompositionError("N7_TARGETD_BOOTSTRAP_MODEL_INVALID") from exc

    expected_call = bootstrap.get("expected_call")
    expected_peer = bootstrap.get("expected_peer")
    raw_keys = bootstrap.get("keys")
    if not isinstance(expected_call, Mapping) or not isinstance(expected_peer, Mapping) or not isinstance(raw_keys, Mapping):
        raise N7HostCompositionError("N7_TARGETD_BOOTSTRAP_IDENTITY_INVALID")
    call_key = WorkerCallKey.from_request(request)
    request_digest = request.request_digest()
    now = _now()
    if (
        request.deadline <= now
        or request.target_id != bootstrap.get("target_id")
        or request.authority != authority
        or request.motion_safety_admission.intent != intent
        or request.bundle_digest != manifest.bundle_digest
        or request.binding_digest != manifest.binding_digest
        or request.provider_id != "ros-container"
        or request.provider_operation != "base.rotate"
        or request.arguments != {"angle_degrees": 1.0, "max_speed_rad_s": 0.03}
        or authority.mapping_admission != mapping_receipt.admission_identity()
        or authority.mapping_confirmation_receipt_digest != mapping_receipt.receipt_digest
        or authority.fence_epoch != expected_call.get("motion_fence_epoch")
        or authority.target_id != request.target_id
        or authority.provider_id != request.provider_id
        or authority.provider_operation != request.provider_operation
        or authority.mode != request.mode
        or authority.bundle_digest != manifest.bundle_digest
        or authority.binding_digest != manifest.binding_digest
        or bootstrap.get("target_identity")
        != authority.mapping_admission.target_identity_digest
        or policy.target_id != request.target_id
        or policy.target_identity != bootstrap.get("target_identity")
        or intent.target_id != request.target_id
        or intent.target_identity != bootstrap.get("target_identity")
        or intent.call_id != request.idempotency_key
        or intent.session_id != request.session_id
        or intent.execution_subject_digest != request.execution_subject_digest
        or expected_call.get("id") != request.idempotency_key
        or expected_call.get("session") != request.session_id
        or expected_call.get("execution_subject_digest")
        != request.execution_subject_digest
        or expected_call.get("request_digest") != request_digest
        or expected_call.get("call_key_digest") != call_key.digest()
        or bootstrap.get("provider_runtime_sha256")
        != manifest.observation_contract.get("provider_runtime_sha256")
    ):
        raise N7HostCompositionError("N7_TARGETD_BOOTSTRAP_IDENTITY_INVALID")

    if (
        mapping_receipt.decision != "CONFIRMED"
        or mapping_receipt.sequence != 1
        or mapping_receipt.previous_receipt_digest is not None
        or mapping_receipt.supersedes_receipt_digest is not None
        or mapping_receipt.expires_at is None
        or mapping_receipt.expires_at.astimezone(timezone.utc) <= request.deadline
    ):
        raise N7HostCompositionError("N7_TARGETD_MAPPING_RECEIPT_INVALID")

    source = _decode_base64(
        bootstrap.get("bundle_source_base64"),
        label="BUNDLE_SOURCE",
        maximum=_MAX_SOURCE_BYTES,
    )
    if hashlib.sha256(source).hexdigest() != manifest.source_digest:
        raise N7HostCompositionError("N7_TARGETD_BUNDLE_SOURCE_INVALID")
    keys = {
        "targetd": _decode_key(raw_keys.get("targetd_signing_base64"), label="TARGETD_KEY"),
        "bundle": _decode_key(raw_keys.get("bundle_verification_base64"), label="BUNDLE_KEY"),
        "graph": _decode_key(raw_keys.get("graph_signing_base64"), label="GRAPH_KEY"),
        "target": _decode_key(raw_keys.get("target_signing_base64"), label="TARGET_KEY"),
        "peer": _decode_key(
            raw_keys.get("peer_bootstrap_verification_base64"),
            label="PEER_KEY",
        ),
    }
    if len(set(keys.values())) != len(keys):
        raise N7HostCompositionError("N7_TARGETD_KEY_ROLE_COLLISION")
    if policy.graph_authority_id == policy.target_authority_id:
        raise N7HostCompositionError("N7_TARGETD_GRAPH_TARGET_AUTHORITY_NOT_ISOLATED")
    try:
        manifest.verify_signature(keys["bundle"])
        validate_landerpi_rotate_process_call(request, manifest)
    except Exception as exc:
        raise N7HostCompositionError("N7_TARGETD_PHYSICAL_CALL_INVALID") from exc
    runtime_sha256 = manifest.observation_contract.get("provider_runtime_sha256")
    if (
        not isinstance(runtime_sha256, str)
        or _RAW_SHA256.fullmatch(runtime_sha256) is None
        or runtime_sha256 != landerpi_bounded_twist_runtime_sha256()
    ):
        raise N7HostCompositionError("N7_TARGETD_PROVIDER_RUNTIME_INVALID")

    return (
        request,
        manifest,
        source,
        policy,
        intent,
        authority,
        mapping_receipt,
        peer_receipt,
        dict(expected_peer),
        keys,
    )


def _reproduce_mapping_receipt(
    root: Path,
    receipt: MappingConfirmationReceipt,
) -> MappingConfirmationStore:
    assert receipt.expires_at is not None
    ttl = (receipt.expires_at - receipt.decided_at).total_seconds()
    if not math.isfinite(ttl) or int(ttl) != ttl or not 1 <= int(ttl) <= 86_400:
        raise N7HostCompositionError("N7_TARGETD_MAPPING_RECEIPT_TTL_INVALID")
    store = MappingConfirmationStore(root)
    reproduced = store.confirm(
        receipt.admission_identity(),
        decision_id=receipt.decision_id,
        actor_id=receipt.actor_id,
        ttl_s=int(ttl),
        decided_at=receipt.decided_at,
    )
    if reproduced != receipt or store.resolve(receipt.receipt_digest) != receipt:
        raise N7HostCompositionError("N7_TARGETD_MAPPING_RECEIPT_REPRODUCTION_FAILED")
    return store


def _runner_topology_digest(observation: LanderPiIsolationObservation) -> str:
    """Reproduce the runner's topology-only digest from a target observation."""

    return _digest(
        {
            "command_route": observation.command.route,
            "command_interface": observation.command.interface,
            "command_publishers": list(observation.command.publisher_identities),
            "command_publisher_gids": list(observation.command.publisher_gids),
            "command_subscribers": list(observation.command.subscriber_identities),
            "command_subscriber_gids": list(observation.command.subscriber_gids),
            "competing_command_route": observation.competing_command.route,
            "competing_publishers": list(
                observation.competing_command.publisher_identities
            ),
            "competing_publisher_gids": list(
                observation.competing_command.publisher_gids
            ),
            "competing_subscribers": list(
                observation.competing_command.subscriber_identities
            ),
            "competing_subscriber_gids": list(
                observation.competing_command.subscriber_gids
            ),
            "direct_motor_route": observation.direct_motor.route,
            "direct_motor_publishers": list(
                observation.direct_motor.publisher_identities
            ),
            "direct_motor_publisher_gids": list(observation.direct_motor.publisher_gids),
            "direct_motor_subscribers": list(
                observation.direct_motor.subscriber_identities
            ),
            "direct_motor_subscriber_gids": list(
                observation.direct_motor.subscriber_gids
            ),
            "processes": [],
        }
    )


class N7HostTargetdRuntime:
    """Own the exact targetd daemon, worker, target fence, and cleanup proof."""

    def __init__(
        self,
        *,
        bootstrap: Mapping[str, object],
        stage_root: Path,
        request: ExecutionRequestV3,
        manifest: ExecutionBundleManifest,
        policy: MotionSafetyPolicy,
        intent: MotionSafetyIntent,
        peer_receipt: DebugPinnedTargetdPeerBootstrapReceipt,
        targetd_signing_key: bytes,
        service: TargetdService,
        process_runtime: LeasedProcessWorkerRuntime,
        target: Any,
        trust_store: MotionSafetyTrustStore,
    ) -> None:
        self.bootstrap = dict(bootstrap)
        self.stage_root = stage_root
        self.request = request
        self.manifest = manifest
        self.policy = policy
        self.intent = intent
        self.peer_receipt = peer_receipt
        self._targetd_signing_key = bytes(targetd_signing_key)
        self.service = service
        self.process_runtime = process_runtime
        self.target = target
        self.trust_store = trust_store
        self.call_key = WorkerCallKey.from_request(request)
        self.daemon: TargetdDaemon
        self._factory_lock = threading.Lock()
        self._work_attempted = False
        self._acceptance: DebugOnlyUserAttestedAdmission | None = None
        self._finalize_lock = threading.Lock()
        self._finalized = False
        self._finalize_delivered = False
        self._closed = False

    @property
    def finalize_delivered(self) -> bool:
        return self._finalize_delivered

    def physical_work_factory(
        self,
        request: object,
        manifest: ExecutionBundleManifest,
    ) -> LanderPiRotateProcessWorker:
        try:
            parsed_request = ExecutionRequestV3.model_validate(
                request.model_dump(mode="python")  # type: ignore[union-attr]
            )
            parsed_manifest = ExecutionBundleManifest.model_validate(
                manifest.model_dump(mode="python")
            )
        except Exception as exc:
            raise ProtocolError("N7_TARGETD_PREPARE_IDENTITY_INVALID") from exc
        with self._factory_lock:
            if self._work_attempted:
                raise ProtocolError("N7_TARGETD_PREPARE_REPLAYED")
            self._work_attempted = True
        if parsed_request != self.request or parsed_manifest != self.manifest:
            raise ProtocolError("N7_TARGETD_PREPARE_IDENTITY_INVALID")
        if _now() >= self.request.deadline:
            raise ProtocolError("N7_TARGETD_PREPARE_DEADLINE_EXPIRED")
        try:
            self.target.verify_initial_isolation()
            return LanderPiRotateProcessWorker(
                self.request,
                self.manifest,
                container="MentorPi",
                container_user="ubuntu",
                timeout_s=75.0,
            )
        except ProtocolError:
            raise
        except Exception as exc:
            raise ProtocolError("N7_TARGETD_INITIAL_ISOLATION_BLOCKED") from exc

    def physical_acceptance_factory(
        self,
        request: object,
        manifest: ExecutionBundleManifest,
        _armed_zero: object,
        admission: object,
    ) -> DebugUserAttestedPhysicalProviderGate:
        try:
            parsed_request = ExecutionRequestV3.model_validate(
                request.model_dump(mode="python")  # type: ignore[union-attr]
            )
            parsed_manifest = ExecutionBundleManifest.model_validate(
                manifest.model_dump(mode="python")
            )
            parsed_admission = DebugOnlyUserAttestedAdmission.model_validate(
                admission.model_dump(mode="python")  # type: ignore[union-attr]
            )
        except Exception as exc:
            raise ProtocolError("N7_TARGETD_DEBUG_ACCEPTANCE_IDENTITY_INVALID") from exc
        if parsed_request != self.request or parsed_manifest != self.manifest:
            raise ProtocolError("N7_TARGETD_DEBUG_ACCEPTANCE_IDENTITY_INVALID")
        receipt = run_debug_user_attested_zero_motion_acceptance(
            parsed_admission,
            intent=self.intent,
            policy=self.policy,
            trust_store=self.trust_store,
            target=self.target,
            now=_now(),
        )
        if (
            not isinstance(receipt, DebugUserAttestedAcceptanceReceipt)
            or receipt.status != "DEBUG_ACCEPTED"
            or receipt.report_status != "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
            or receipt.reasons
        ):
            raise ProtocolError("N7_TARGETD_DEBUG_ACCEPTANCE_BLOCKED")
        self._acceptance = parsed_admission
        return DebugUserAttestedPhysicalProviderGate(
            admission=parsed_admission,
            acceptance_receipt=receipt,
            intent=self.intent,
            policy=self.policy,
            trust_store=self.trust_store,
            target=self.target,
            clock=_now,
        )

    def ready_payload(self) -> dict[str, object]:
        if self._work_attempted or getattr(self.daemon, "_provider_invocation_count", -1) != 0:
            raise N7HostCompositionError("N7_TARGETD_READY_NOT_INERT")
        return {
            "schema_version": _READY_SCHEMA,
            "status": "READY",
            "ok": True,
            "run_id": self.bootstrap["run_id"],
            "stage_root": str(self.stage_root),
            "target_id": self.request.target_id,
            "call_id": self.request.idempotency_key,
            "session_id": self.request.session_id,
            "bootstrap_payload_sha256": self.bootstrap["payload_sha256"],
            "initial_isolation": "PENDING_PREPARE_AFTER_RUNNER_ISOLATION",
            "provider_runtime_sha256": self.manifest.observation_contract[
                "provider_runtime_sha256"
            ],
            "peer_bootstrap_receipt_digest": self.peer_receipt.payload_sha256,
            "provider_invocation_count": 0,
            "protocol": "rolo-targetd/v1",
        }

    def _validate_finalize(self, value: Mapping[str, object]) -> dict[str, Any]:
        payload = dict(value)
        if set(payload) != _FINALIZE_KEYS or payload.get("schema_version") != _FINALIZE_SCHEMA:
            raise N7HostCompositionError("N7_TARGETD_FINALIZE_INVALID")
        digest = payload.get("finalize_payload_sha256")
        tag = payload.get("finalize_auth_tag")
        unsigned = {
            key: item
            for key, item in payload.items()
            if key not in {"finalize_payload_sha256", "finalize_auth_tag"}
        }
        expected_digest = _digest(unsigned)
        expected_tag = "hmac-sha256:" + hmac.new(
            self._targetd_signing_key,
            expected_digest.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        expected_stage_nonce = "sha256:" + hashlib.sha256(
            str(self.bootstrap["stage_nonce"]).encode("ascii")
        ).hexdigest()
        if (
            digest != expected_digest
            or not isinstance(tag, str)
            or _HMAC_SHA256.fullmatch(tag) is None
            or not hmac.compare_digest(tag, expected_tag)
            or payload.get("run_id") != self.bootstrap["run_id"]
            or payload.get("stage_root") != str(self.stage_root)
            or payload.get("bootstrap_payload_sha256")
            != self.bootstrap["payload_sha256"]
            or payload.get("stage_nonce_sha256") != expected_stage_nonce
            or payload.get("target_id") != self.call_key.target_id
            or payload.get("session_id") != self.call_key.session_id
            or payload.get("call_id") != self.call_key.idempotency_key
            or payload.get("request_digest") != self.call_key.request_digest
            or payload.get("call_key_digest") != self.call_key.digest()
            or payload.get("terminal_status") not in _TERMINAL_STATES
            or payload.get("final_zero_verified") is not True
            or payload.get("stop_acknowledged") is not True
            or payload.get("provider_terminated") is not True
            or payload.get("post_isolated") is not True
            or not isinstance(payload.get("provider_invocation_count"), int)
            or isinstance(payload.get("provider_invocation_count"), bool)
            or payload.get("provider_invocation_count") not in {0, 1}
            or not isinstance(payload.get("terminal_receipt_digest"), str)
            or _SHA256.fullmatch(str(payload["terminal_receipt_digest"])) is None
            or not isinstance(payload.get("post_isolated_graph_revision"), str)
            or _SHA256.fullmatch(str(payload["post_isolated_graph_revision"])) is None
            or not isinstance(payload.get("post_isolated_topology_digest"), str)
            or _SHA256.fullmatch(str(payload["post_isolated_topology_digest"])) is None
        ):
            raise N7HostCompositionError("N7_TARGETD_FINALIZE_AUTHORIZATION_INVALID")
        return payload

    def _load_terminal_proof(
        self,
        finalize: Mapping[str, object],
    ) -> tuple[WorkerLeaseRecord, TargetdCallReceipt, Any]:
        lease = self.process_runtime.store.load(self.call_key)
        if lease is None or lease.state not in _TERMINAL_STATES:
            raise N7HostCompositionError("N7_TARGETD_WORKER_TERMINAL_REQUIRED")
        try:
            receipt = self.service.revalidate_physical_process_terminal(
                self.call_key,
                lease,
            )
        except Exception as exc:
            raise N7HostCompositionError("N7_TARGETD_WORKER_TERMINAL_INVALID") from exc
        result = lease.prepared_result
        acknowledgement = result.get("stop_acknowledgement") if isinstance(result, Mapping) else None
        evidence = result.get("independent_motion_evidence") if isinstance(result, Mapping) else None
        if (
            receipt.status != finalize.get("terminal_status")
            or receipt.status != lease.state
            or _digest(receipt.model_dump(mode="json"))
            != finalize.get("terminal_receipt_digest")
            or not isinstance(result, Mapping)
            or result.get("worker_call_key_digest") != self.call_key.digest()
            or result.get("request_digest") != self.call_key.request_digest
            or result.get("final_zero_verified") is not True
            or result.get("stop_acknowledged") is not True
            or result.get("stop_published") is not True
            or result.get("physical_stop_verified") is not True
            or result.get("stopped_observed") is not True
            or result.get("control_graph_isolated") is not True
            or result.get("target_registry_terminalized") is not True
            or result.get("provider_invocation_count")
            != finalize.get("provider_invocation_count")
            or getattr(self.daemon, "_provider_invocation_count", -1)
            != finalize.get("provider_invocation_count")
            or not isinstance(acknowledgement, Mapping)
            or acknowledgement.get("call_key_digest") != self.call_key.digest()
            or acknowledgement.get("verified") is not True
            or acknowledgement.get("inner_process_gone") is not True
            or not isinstance(evidence, Mapping)
            or evidence.get("independent_of_odom") is not True
            or evidence.get("settled") is not True
        ):
            raise N7HostCompositionError("N7_TARGETD_WORKER_TERMINAL_INVALID")
        try:
            armed = parse_physical_worker_armed_zero(
                lease.armed_zero,
                expected_call_key_digest=self.call_key.digest(),
                expected_target_id=self.call_key.target_id,
                expected_call_id=self.call_key.idempotency_key,
                expected_session_id=self.call_key.session_id,
                expected_request_digest=self.call_key.request_digest,
                expected_execution_subject_digest=self.request.execution_subject_digest,
                expected_runtime_sha256=str(
                    self.manifest.observation_contract["provider_runtime_sha256"]
                ),
            )
            terminal = read_target_physical_worker_terminal_registry(
                expected_call_key_digest=self.call_key.digest(),
                expected_target_id=self.call_key.target_id,
                expected_call_id=self.call_key.idempotency_key,
                expected_session_id=self.call_key.session_id,
                expected_request_digest=self.call_key.request_digest,
                expected_execution_subject_digest=self.request.execution_subject_digest,
                expected_runtime_sha256=str(
                    self.manifest.observation_contract["provider_runtime_sha256"]
                ),
                expected_arm_receipt_digest=armed.arm_receipt_digest,
                container="MentorPi",
                container_user="ubuntu",
            )
        except Exception as exc:
            raise N7HostCompositionError("N7_TARGETD_INNER_EXIT_PROOF_INVALID") from exc
        if terminal is None or terminal.armed_zero != armed:
            raise N7HostCompositionError("N7_TARGETD_INNER_EXIT_PROOF_INVALID")
        return lease, receipt, armed

    def _close_target_fence(self) -> LanderPiIsolationObservation:
        try:
            state = self.target.store.load()
            fence_was_active = state.phase != "SAFE_BASELINE"
            if state.phase != "SAFE_BASELINE":
                if state.acceptance_id is None:
                    raise N7HostCompositionError("N7_TARGETD_FENCE_OWNER_MISSING")
                if self._acceptance is not None and state.acceptance_id != self._acceptance.acceptance_id:
                    raise N7HostCompositionError("N7_TARGETD_FENCE_OWNER_MISMATCH")
                self.target.abort_zero_motion(
                    acceptance_id=state.acceptance_id,
                    intent=self.intent,
                )
            safe = self.target.store.load()
            minimum_epoch = self.request.authority.fence_epoch + (
                1 if fence_was_active else 0
            )
            if safe.phase != "SAFE_BASELINE" or safe.fence_epoch < minimum_epoch:
                raise N7HostCompositionError("N7_TARGETD_SAFE_FENCE_NOT_RESTORED")
            return self.target.verify_initial_isolation()
        except N7HostCompositionError:
            raise
        except Exception as exc:
            raise N7HostCompositionError("N7_TARGETD_FINAL_ISOLATION_INVALID") from exc

    def finalize(self, value: Mapping[str, object]) -> dict[str, object]:
        with self._finalize_lock:
            if self._finalized or self._finalize_delivered:
                raise N7HostCompositionError("N7_TARGETD_FINALIZE_REPLAYED")
            finalize = self._validate_finalize(value)
            _lease, _receipt, armed = self._load_terminal_proof(finalize)
            observation = self._close_target_fence()
            if (
                observation.graph_revision
                != finalize["post_isolated_graph_revision"]
                or _runner_topology_digest(observation)
                != finalize["post_isolated_topology_digest"]
            ):
                raise N7HostCompositionError("N7_TARGETD_FINAL_ISOLATION_MISMATCH")
            if not cleanup_terminal_registry(
                armed,
                expected_call_key_digest=self.call_key.digest(),
                expected_arm_receipt_digest=armed.arm_receipt_digest,
                container="MentorPi",
                container_user="ubuntu",
            ):
                raise N7HostCompositionError("N7_TARGETD_TERMINAL_REGISTRY_CLEANUP_FAILED")

            unsigned: dict[str, object] = {
                "schema_version": _FINALIZE_RECEIPT_SCHEMA,
                "status": "SAFE_TO_CLEANUP",
                **{key: finalize[key] for key in _FINALIZE_CORE_KEYS},
                "worker_terminal_revalidated": True,
                "stage_cleanup_authorized": True,
            }
            digest = _digest(unsigned)
            tag = "hmac-sha256:" + hmac.new(
                self._targetd_signing_key,
                digest.encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
            self._finalized = True
            return {
                **unsigned,
                "receipt_payload_sha256": digest,
                "receipt_auth_tag": tag,
            }

    def mark_finalize_delivered(self) -> None:
        with self._finalize_lock:
            if not self._finalized or self._finalize_delivered:
                raise N7HostCompositionError("N7_TARGETD_FINALIZE_DELIVERY_INVALID")
            self._finalize_delivered = True

    def close(self, *, finalized: bool) -> None:
        if self._closed:
            return
        if finalized:
            if not self._finalized or not self._finalize_delivered:
                raise N7HostCompositionError("N7_TARGETD_STAGE_CLEANUP_NOT_AUTHORIZED")
            self._remove_exact_stage()
            self._closed = True
            return
        self._recover_unfinalized()
        self._closed = True

    def _recover_unfinalized(self) -> None:
        status = "NO_WORKER"
        detail = "N7_TARGETD_UNFINALIZED_STAGE_PRESERVED"
        lease = self.process_runtime.store.load(self.call_key)
        try:
            if lease is not None and lease.state in _ACTIVE_STATES:
                intent = "CANCEL" if lease.state == "CANCEL_REQUESTED" else "STOP"
                self.process_runtime.request_interrupt(self.call_key, intent=intent)
                snapshot = self.process_runtime.join(self.call_key, timeout_s=10.0)
                lease = snapshot.lease
            if lease is not None and lease.state in _TERMINAL_STATES:
                self.service.revalidate_physical_process_terminal(self.call_key, lease)
                self._close_target_fence()
                self._cleanup_recovered_registry(lease)
                status = "SAFE_TERMINAL_STAGE_PRESERVED"
                detail = lease.state
            elif lease is not None and lease.armed_zero is not None:
                recovered = recover_persisted_armed_zero(
                    lease.armed_zero,
                    expected_call_key_digest=self.call_key.digest(),
                    expected_target_id=self.call_key.target_id,
                    expected_call_id=self.call_key.idempotency_key,
                    expected_session_id=self.call_key.session_id,
                    expected_request_digest=self.call_key.request_digest,
                    expected_execution_subject_digest=self.request.execution_subject_digest,
                    expected_runtime_sha256=str(
                        self.manifest.observation_contract["provider_runtime_sha256"]
                    ),
                    container="MentorPi",
                    container_user="ubuntu",
                )
                if recovered:
                    self._close_target_fence()
                    self._cleanup_recovered_registry(lease)
                    status = "SAFE_RECOVERED_UNKNOWN_STAGE_PRESERVED"
                    detail = lease.state
                else:
                    status = "RECOVERY_REQUIRED_STAGE_PRESERVED"
                    detail = lease.state
            elif lease is not None:
                # UNKNOWN before ARMED_ZERO is still a durable worker record.
                # Preserve the stage and report that exact state instead of
                # misclassifying it as NO_WORKER; no target-side identity is
                # available yet from which safe automatic recovery could be
                # proved.
                status = "RECOVERY_REQUIRED_STAGE_PRESERVED"
                detail = lease.state
        except Exception as exc:
            status = "RECOVERY_REQUIRED_STAGE_PRESERVED"
            detail = type(exc).__name__
        self._write_recovery_receipt(status=status, detail=detail)

    def _cleanup_recovered_registry(self, lease: WorkerLeaseRecord) -> None:
        """Remove only the exact authenticated TERMINAL registry after recovery.

        Recovery deliberately preserves the host stage for inspection, but a
        verified dead inner process must not leave a global target registry
        that contaminates the next one-shot attempt.  A pre-ARM interrupt has
        no registry and therefore needs no cleanup.
        """

        if lease.armed_zero is None:
            return
        armed = parse_physical_worker_armed_zero(
            lease.armed_zero,
            expected_call_key_digest=self.call_key.digest(),
            expected_target_id=self.call_key.target_id,
            expected_call_id=self.call_key.idempotency_key,
            expected_session_id=self.call_key.session_id,
            expected_request_digest=self.call_key.request_digest,
            expected_execution_subject_digest=self.request.execution_subject_digest,
            expected_runtime_sha256=str(
                self.manifest.observation_contract["provider_runtime_sha256"]
            ),
        )
        terminal = read_target_physical_worker_terminal_registry(
            expected_call_key_digest=self.call_key.digest(),
            expected_target_id=self.call_key.target_id,
            expected_call_id=self.call_key.idempotency_key,
            expected_session_id=self.call_key.session_id,
            expected_request_digest=self.call_key.request_digest,
            expected_execution_subject_digest=self.request.execution_subject_digest,
            expected_runtime_sha256=str(
                self.manifest.observation_contract["provider_runtime_sha256"]
            ),
            expected_arm_receipt_digest=armed.arm_receipt_digest,
            container="MentorPi",
            container_user="ubuntu",
        )
        if terminal is None or terminal.armed_zero != armed:
            raise N7HostCompositionError("N7_TARGETD_RECOVERY_REGISTRY_INVALID")
        if not cleanup_terminal_registry(
            armed,
            expected_call_key_digest=self.call_key.digest(),
            expected_arm_receipt_digest=armed.arm_receipt_digest,
            container="MentorPi",
            container_user="ubuntu",
        ):
            raise N7HostCompositionError("N7_TARGETD_RECOVERY_REGISTRY_CLEANUP_FAILED")

    def _write_recovery_receipt(self, *, status: str, detail: str) -> None:
        try:
            unsigned = {
                "schema_version": _RECOVERY_SCHEMA,
                "status": status,
                "run_id": self.bootstrap["run_id"],
                "stage_root": str(self.stage_root),
                "target_id": self.call_key.target_id,
                "session_id": self.call_key.session_id,
                "call_id": self.call_key.idempotency_key,
                "request_digest": self.call_key.request_digest,
                "call_key_digest": self.call_key.digest(),
                "detail": detail,
                "recorded_at": _now(),
                "stage_preserved": True,
            }
            digest = _digest(unsigned)
            tag = "hmac-sha256:" + hmac.new(
                self._targetd_signing_key,
                digest.encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
            atomic_write_text(
                self.stage_root / "unfinalized-recovery.json",
                json.dumps(
                    {
                        **unsigned,
                        "receipt_payload_sha256": digest,
                        "receipt_auth_tag": tag,
                    },
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=_json_default,
                )
                + "\n",
            )
            if os.name != "nt":
                os.chmod(self.stage_root / "unfinalized-recovery.json", 0o600)
        except Exception:
            pass

    def _remove_exact_stage(self) -> None:
        _require_stage_root(self.stage_root, self.bootstrap)
        if self.stage_root.parent != Path("/dev/shm"):
            raise N7HostCompositionError("N7_TARGETD_STAGE_CLEANUP_ROOT_INVALID")
        shutil.rmtree(self.stage_root)
        if self.stage_root.exists() or self.stage_root.is_symlink():
            raise N7HostCompositionError("N7_TARGETD_STAGE_CLEANUP_FAILED")


def compose_n7_host_targetd(
    bootstrap: Mapping[str, object],
    *,
    stage_root: Path,
) -> N7HostTargetdRuntime:
    """Construct the single-call debug targetd from the validated bootstrap."""

    root = _require_stage_root(Path(stage_root), bootstrap)
    (
        request,
        manifest,
        source,
        policy,
        intent,
        authority,
        mapping_receipt,
        peer_receipt,
        expected_peer,
        keys,
    ) = _parse_bootstrap(bootstrap, stage_root=root)

    confirmation_store = _reproduce_mapping_receipt(
        root / "mapping-confirmations",
        mapping_receipt,
    )
    admission_gate = MappingAdmissionGate(confirmation_store)
    authority_store = TargetdExecutionAuthorityStore(root / "execution-authority")

    peer_key = TargetSigningKey.from_bytes(keys["peer"])
    capability = consume_debug_pinned_targetd_peer_bootstrap(
        peer_receipt,
        verification_key=peer_key,
        replay_store=DebugPinnedPeerBootstrapReplayStore(
            (root / "peer-bootstrap-replay").resolve()
        ),
        expected_bootstrap_authority_id=str(
            expected_peer.get("bootstrap_authority_id")
        ),
        expected_target_id=request.target_id,
        expected_target_identity=policy.target_identity,
        expected_call_id=request.idempotency_key,
        expected_session_id=request.session_id,
        expected_execution_subject_digest=request.execution_subject_digest,
        expected_ssh_host=str(expected_peer.get("ssh_host")),
        expected_ssh_port=int(expected_peer.get("ssh_port")),
        expected_pinned_host_key_sha256=str(
            expected_peer.get("pinned_host_key_sha256")
        ),
        expected_client_public_key_sha256=str(
            expected_peer.get("client_public_key_sha256")
        ),
        expected_known_hosts_sha256=str(expected_peer.get("known_hosts_sha256")),
        expected_channel_binding_sha256=str(
            expected_peer.get("channel_binding_sha256")
        ),
        at=_now(),
    )
    transport = TargetdDockerPinnedReadControlTransport(
        peer_capability=capability,
        timeout_s=7.0,
    )
    runtime_sha256 = str(manifest.observation_contract["provider_runtime_sha256"])
    rpc = PinnedKeyOnlyLanderPiMotionRpc(
        policy=policy,
        transport=transport,
        expected_call_key_digest=WorkerCallKey.from_request(request).digest(),
        expected_request_digest=request.request_digest(),
        expected_call_id=request.idempotency_key,
        expected_session_id=request.session_id,
        expected_execution_subject_digest=request.execution_subject_digest,
        manifest_provider_runtime_sha256="sha256:" + runtime_sha256,
        clock=_now,
    )
    target = compose_landerpi_zero_motion_target(
        policy=policy,
        rpc=rpc,
        state_root=(root / "motion-target").resolve(),
        graph_signing_key=TargetSigningKey.from_bytes(keys["graph"]),
        target_signing_key=TargetSigningKey.from_bytes(keys["target"]),
        clock=_now,
    )
    target.store.provision(
        LanderPiTargetMotionState.initial(
            intent,
            fence_epoch=authority.fence_epoch,
            now=_now(),
        )
    )
    trust_store = MotionSafetyTrustStore(
        {
            policy.graph_authority_id: keys["graph"],
            policy.target_authority_id: keys["target"],
        }
    )

    worker_store = WorkerLeaseStore(root / "physical-worker-leases")
    gate_store = PhysicalProviderGateReceiptStore(root / "physical-provider-gates")
    acceptance_store = DebugPhysicalAcceptanceReceiptStore(
        root / "debug-physical-acceptances"
    )
    process_runtime = LeasedProcessWorkerRuntime(
        worker_store,
        supervisor_id="n7-host-" + WorkerCallKey.from_request(request).digest()[:20],
        allow_spawn_readonly_substrate=False,
        allow_spawn_physical_substrate=True,
        physical_container="MentorPi",
        physical_container_user="ubuntu",
        max_processes=1,
    )
    service = TargetdService(
        target_id=request.target_id,
        state_root=root / "targetd-state",
        bundle_root=root / "targetd-bundles",
        # ``verification_keys`` is the complete bundle trust set.  The
        # independent host-finalize key must never become a signer fallback.
        signing_key=None,
        verification_keys={manifest.signer_key_id: keys["bundle"]},
        confirmation_store=confirmation_store,
        admission_gate=admission_gate,
        execution_authority_store=authority_store,
        release_catalog=None,
        physical_motion_gate=None,
        physical_worker_store=worker_store,
        physical_gate_receipt_store=gate_store,
        physical_acceptance_receipt_store=acceptance_store,
    )
    service.put_bundle(manifest, source)
    authority_store.publish(authority)
    if authority_store.resolve(authority.tool_id) != authority:
        raise N7HostCompositionError("N7_TARGETD_AUTHORITY_PROVISION_FAILED")

    runtime = N7HostTargetdRuntime(
        bootstrap=bootstrap,
        stage_root=root,
        request=request,
        manifest=manifest,
        policy=policy,
        intent=intent,
        peer_receipt=peer_receipt,
        targetd_signing_key=keys["targetd"],
        service=service,
        process_runtime=process_runtime,
        target=target,
        trust_store=trust_store,
    )
    runtime.daemon = TargetdDaemon(
        service,
        execute_calls=True,
        provider=RosContainerProvider(
            "MentorPi",
            container_user="ubuntu",
            timeout_s=75.0,
            autonomous_source_confirmed=False,
        ),
        physical_process_runtime=process_runtime,
        physical_process_work_factory=runtime.physical_work_factory,
        physical_acceptance_factory=runtime.physical_acceptance_factory,
    )
    return runtime


__all__ = [
    "N7HostCompositionError",
    "N7HostTargetdRuntime",
    "compose_n7_host_targetd",
]
