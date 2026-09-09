"""Small stdio daemon for the signed bundle targetd protocol.

The daemon is intentionally transport-only: it validates sessions, bundles,
requests and receipts, then leaves provider-specific execution to a worker.
This makes bootstrap/handoff testable on a real host without granting shell
access or embedding ROS assumptions in targetd.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import re
import stat
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from rolo.core.hashing import canonical_json_sha256
from rolo.core.rotation_evidence import has_verified_rotation_evidence
from rolo.dsl.admission import MappingAdmissionError, MappingConfirmationStore
from rolo.dsl.parser import loads_unique_json

from .dsl_protocol import DslFrame, DslFrameType
from .dsl_service import TargetdDslService
from .lifecycle import WorkerCallKey, WorkerLeaseStore
from .lifecycle_integration import validate_sealed_odom_r0_call
from .process_worker import (
    LeasedProcessWorkerRuntime,
    PhysicalProcessWorkerPreparation,
    ProcessWorkerFunction,
    ProcessWorkerSnapshot,
)
from .protocol import (
    ExecutionBundleManifest,
    FrameKind,
    JourneyPhase,
    JourneySession,
    ProtocolError,
    ProtocolFrame,
    TargetdAuthorityActivationRequest,
    TargetdExecutionAuthorityStore,
    TargetdMappingCancelRequest,
    TargetdVerifiedReleaseProvisionRequest,
    debug_zero_motion_acceptance_auth_tag,
    decode_frame,
    encode_frame,
    physical_gate_query_auth_tag,
    physical_prepared_start_auth_tag,
    process_control_auth_tag,
    requires_motion_safety,
    validate_execution_request,
)
from .ros2_runtime import Ros2RuntimeResolver, Ros2RuntimeSnapshot
from .runtime_backend import Ros2ReadOnlyExecutor, RuntimeBackendRegistry, ros2_registry
from .service import TargetdReleaseCatalog, TargetdService
from .worker import (
    MAPPING_TOOL_OPERATIONS,
    Provider,
    PythonBundleWorker,
    Ros2OdomLiveFence,
    Ros2OdomProcessWorker,
    RosContainerProvider,
)

_ROS2_READONLY_PROVIDER_ID = "ros2-readonly"
_ROS2_READONLY_OPERATION = "odom.sample"
_ROS2_ODOM_BINDING = {
    "resource_id": "/odom",
    "interface_type": "nav_msgs/msg/Odometry",
}
_ROS2_READONLY_FAILURE_STATUSES = frozenset({"BLOCKED", "CANCELLED", "FAILED", "NOT_ACCEPTED", "STOPPED", "UNKNOWN"})
_ROS2_READONLY_SAFE_ERRORS = frozenset(
    {
        "DDS_USER_MISMATCH",
        "ROS2_TOPIC_ECHO_EMPTY",
        "ROS2_TOPIC_ECHO_FAILED",
        "ROS2_TOPIC_ECHO_TIMEOUT",
    }
)
_PUBLIC_ERROR_CODE = re.compile(
    r"^(?:DSL|EXECUTION_AUTHORITY|MAPPING|PHYSICAL_MOTION|PHYSICAL_WORKER|"
    r"PROCESS_WORKER|ROS2_READ_ONLY|TARGETD)_[A-Z0-9_]{1,127}$"
)


@dataclass
class _PendingPhysicalCall:
    request: object
    manifest: ExecutionBundleManifest
    work: object
    preparation: PhysicalProcessWorkerPreparation
    provider_gate_payload_digest: str | None = None
    debug_acceptance_gate: object | None = None
    debug_acceptance_reference: object | None = None
    debug_acceptance_attempted: bool = False


def _public_error_code(error: ProtocolError | MappingAdmissionError) -> str:
    """Expose only code-shaped errors from reserved, source-owned namespaces."""

    candidate = str(error)
    if _PUBLIC_ERROR_CODE.fullmatch(candidate) is not None:
        return candidate
    return "TARGETD_REQUEST_VALIDATION_FAILED"


def _read_exact(stream, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_signing_key_file(path: Path) -> bytes:
    """Read one bounded owner-only regular key file without following links."""

    descriptor: int | None = None
    try:
        if path.is_symlink():
            raise ValueError("signing key file is not a regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("signing key file is not a regular file")
        if metadata.st_size <= 0 or metadata.st_size > 4096:
            raise ValueError("signing key file size is invalid")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError("signing key file permissions must be 0600")
        raw = os.read(descriptor, metadata.st_size + 1)
        if len(raw) != metadata.st_size:
            raise ValueError("signing key file changed while being read")
    except OSError as exc:
        raise ValueError("signing key file is unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    key = raw.rstrip(b"\r\n")
    if not key or len(key) > 4096 or b"\x00" in key:
        raise ValueError("signing key file content is invalid")
    return key


def load_ros2_dsl_runtime(
    snapshot_path: Path | None,
    *,
    execute_readonly: bool = False,
) -> tuple[Ros2RuntimeResolver | None, RuntimeBackendRegistry | None]:
    """Load an observed ROS2 snapshot and its explicitly read-only backend."""

    if snapshot_path is None:
        if execute_readonly:
            raise ValueError("--execute-readonly requires --ros2-snapshot")
        return None, None
    raw = loads_unique_json(snapshot_path.read_text(encoding="utf-8"))
    if isinstance(raw, dict) and isinstance(raw.get("snapshot"), dict):
        raw = raw["snapshot"]
    if not isinstance(raw, dict):
        raise ValueError("ROS2 snapshot artifact must be a JSON object")
    resolver = Ros2RuntimeResolver(Ros2RuntimeSnapshot.from_dict(raw))
    executor = Ros2ReadOnlyExecutor(resolver) if execute_readonly else None
    return resolver, ros2_registry(resolver, executor)


class Ros2ReadOnlyProvider:
    """Generic CALL bridge for one fixed, observed ROS2 odometry sample."""

    provider_id = _ROS2_READONLY_PROVIDER_ID

    def __init__(self, registry: RuntimeBackendRegistry) -> None:
        self._registry = registry
        try:
            resolved = registry.resolve(
                "OBSERVE",
                dict(_ROS2_ODOM_BINDING),
                required_capabilities=("read_only_topic", "ros2"),
            )
        except Exception:
            raise ProtocolError("ROS2_READ_ONLY_BINDING_UNAVAILABLE") from None
        if resolved.backend_id != "ros2_runtime" or resolved.binding.get("endpoint") != "/odom" or resolved.binding.get("interface_type") != "nav_msgs/msg/Odometry":
            raise ProtocolError("ROS2_READ_ONLY_BINDING_UNAVAILABLE")

    @staticmethod
    def validate_call(operation: str, arguments: dict[str, object]) -> None:
        if operation != _ROS2_READONLY_OPERATION:
            raise ProtocolError("ROS2_READ_ONLY_OPERATION_NOT_ALLOWED")
        if arguments != {}:
            raise ProtocolError("ROS2_READ_ONLY_ARGUMENTS_NOT_ALLOWED")

    def invoke(self, operation: str, arguments: dict[str, object]) -> dict[str, object]:
        self.validate_call(operation, arguments)
        try:
            result = self._registry.execute("OBSERVE", dict(_ROS2_ODOM_BINDING), {})
        except Exception:
            return {"status": "FAILED", "error": "ROS2_READ_ONLY_EXECUTION_FAILED"}
        if not isinstance(result, dict):
            return {"status": "FAILED", "error": "ROS2_READ_ONLY_RESULT_INVALID"}

        status = str(result.get("status", "UNKNOWN")).upper()
        if status == "SUCCEEDED":
            raw = result.get("raw")
            if not isinstance(raw, str):
                return {"status": "FAILED", "error": "ROS2_READ_ONLY_RESULT_INVALID"}
            try:
                payload = raw.encode("utf-8")
            except UnicodeEncodeError:
                return {"status": "FAILED", "error": "ROS2_READ_ONLY_RESULT_INVALID"}
            return {
                "status": "SUCCEEDED",
                "sha256": f"sha256:{hashlib.sha256(payload).hexdigest()}",
                "byte_count": len(payload),
            }

        safe_status = status if status in _ROS2_READONLY_FAILURE_STATUSES else "FAILED"
        error = result.get("error")
        safe_error = error if isinstance(error, str) and error in _ROS2_READONLY_SAFE_ERRORS else "ROS2_READ_ONLY_EXECUTION_FAILED"
        return {"status": safe_status, "error": safe_error}


class TargetdDaemon:
    def __init__(
        self,
        service: TargetdService,
        *,
        execute_calls: bool = False,
        provider: Provider | None = None,
        provider_id: str | None = None,
        dsl_service: TargetdDslService | None = None,
        process_runtime: LeasedProcessWorkerRuntime | None = None,
        process_work: ProcessWorkerFunction | None = None,
        process_live_fence=None,
        physical_process_runtime: LeasedProcessWorkerRuntime | None = None,
        physical_process_work_factory: Callable[[object, ExecutionBundleManifest], object] | None = None,
        physical_gate_factory: Callable[
            [object, ExecutionBundleManifest, object, Mapping[str, object]],
            object,
        ]
        | None = None,
        physical_acceptance_factory: Callable[
            [object, ExecutionBundleManifest, object, object],
            object,
        ]
        | None = None,
    ) -> None:
        self.service = service
        self.worker = PythonBundleWorker(provider) if execute_calls else None
        if not execute_calls:
            self.provider_id = "disabled"
        elif provider is None:
            self.provider_id = "targetd-python"
        elif isinstance(provider, RosContainerProvider):
            self.provider_id = "ros-container"
        elif isinstance(provider, Ros2ReadOnlyProvider):
            self.provider_id = _ROS2_READONLY_PROVIDER_ID
        elif provider_id is not None:
            self.provider_id = provider_id
        else:
            self.provider_id = "unidentified-provider"
        if self.provider_id == _ROS2_READONLY_PROVIDER_ID and not isinstance(provider, Ros2ReadOnlyProvider):
            raise ValueError("ros2-readonly provider requires the fixed runtime bridge")
        configured_process = (process_runtime, process_work, process_live_fence)
        if any(item is not None for item in configured_process) and not all(item is not None for item in configured_process):
            raise ValueError("process read-only worker configuration is incomplete")
        if process_runtime is not None and (not execute_calls or self.provider_id != _ROS2_READONLY_PROVIDER_ID or not isinstance(provider, Ros2ReadOnlyProvider)):
            raise ValueError("process worker is restricted to ros2-readonly")
        self.process_runtime = process_runtime
        self.process_work = process_work
        self.process_live_fence = process_live_fence
        if (physical_process_runtime is None) != (
            physical_process_work_factory is None
        ):
            raise ValueError("physical process worker configuration is incomplete")
        if physical_process_runtime is None and (
            physical_gate_factory is not None
            or physical_acceptance_factory is not None
        ):
            raise ValueError("physical process worker configuration is incomplete")
        if (
            physical_process_runtime is not None
            and physical_gate_factory is None
            and physical_acceptance_factory is None
        ):
            raise ValueError("physical provider gate configuration is missing")
        if physical_process_runtime is not None:
            if (
                not execute_calls
                or self.provider_id != "ros-container"
                or process_runtime is not None
                or physical_process_runtime.allow_spawn_physical_substrate is not True
                or physical_process_runtime.allow_spawn_readonly_substrate is True
                or physical_process_runtime.max_processes != 1
                or service.physical_worker_store is not physical_process_runtime.store
                or service.physical_gate_receipt_store is None
                or (
                    physical_acceptance_factory is not None
                    and getattr(
                        service,
                        "physical_acceptance_receipt_store",
                        None,
                    )
                    is None
                )
            ):
                raise ValueError("physical process worker configuration is invalid")
            physical_process_runtime.bind_physical_start_gate(
                self._start_prepared_physical_provider,
            )
        self.physical_process_runtime = physical_process_runtime
        self.physical_process_work_factory = physical_process_work_factory
        self.physical_gate_factory = physical_gate_factory
        self.physical_acceptance_factory = physical_acceptance_factory
        self._pending_physical: dict[str, _PendingPhysicalCall] = {}
        self.dsl_service = dsl_service
        self._sequence = 0
        self._response_sequence = 0
        self._session: JourneySession | None = None
        self._provider_invocation_count = 0
        if self.process_runtime is not None:
            self._reconcile_process_receipts()
        if self.physical_process_runtime is not None:
            self._reconcile_physical_process_receipts()

    def serve(self, stdin, stdout) -> None:
        while True:
            header = _read_exact(stdin, 4)
            if not header:
                return
            payload = _read_exact(stdin, int.from_bytes(header, "big"))
            if len(payload) != int.from_bytes(header, "big"):
                raise ProtocolError("targetd input frame is truncated")
            frame = decode_frame(header + payload)
            if frame.sequence != self._sequence:
                raise ProtocolError("targetd input sequence is not monotonic")
            self._sequence += 1
            response = self._handle(frame)
            if frame.kind == FrameKind.CALL and response.payload.get("ok") and response.payload.get("call_started") is True:
                event = ProtocolFrame.create(
                    kind=FrameKind.EVENT,
                    sequence=self._response_sequence,
                    session_id=frame.session_id,
                    run_id=frame.run_id,
                    payload={"call_id": frame.payload.get("idempotency_key"), "status": "STARTED"},
                )
                self._response_sequence += 1
                stdout.write(encode_frame(event))
            response = ProtocolFrame.create(
                kind=response.kind,
                sequence=self._response_sequence,
                session_id=response.session_id,
                run_id=response.run_id,
                payload=response.payload,
            )
            self._response_sequence += 1
            try:
                stdout.write(encode_frame(response))
                stdout.flush()
            except Exception:
                if frame.kind == FrameKind.ACCEPT_DEBUG_ZERO_MOTION:
                    self._stop_after_debug_acceptance_ack_failure(frame)
                raise
            if frame.kind == FrameKind.CLOSE_SESSION:
                return

    def _handle(self, frame: ProtocolFrame) -> ProtocolFrame:
        try:
            payload = self._dispatch(frame)
            if frame.kind in {
                FrameKind.ACTIVATE_AUTHORITY,
                FrameKind.CALL,
                FrameKind.CANCEL_MAPPING,
                FrameKind.ACCEPT_DEBUG_ZERO_MOTION,
                FrameKind.PREPARE_PHYSICAL_CALL,
                FrameKind.PROVISION_VERIFIED_RELEASE,
                FrameKind.START_PREPARED_CALL,
            }:
                payload["provider_invocation_count"] = self._provider_invocation_count
            return ProtocolFrame.create(
                kind=FrameKind.RESULT,
                sequence=self._sequence,
                session_id=frame.session_id,
                run_id=frame.run_id,
                payload={"request_kind": frame.kind.value, "ok": True, **payload},
            )
        except MappingAdmissionError as exc:
            return ProtocolFrame.create(
                kind=FrameKind.RESULT,
                sequence=self._sequence,
                session_id=frame.session_id,
                run_id=frame.run_id,
                payload={
                    "request_kind": frame.kind.value,
                    "ok": False,
                    "status": "BLOCKED",
                    "error": _public_error_code(exc),
                    **(
                        {"provider_invocation_count": self._provider_invocation_count}
                        if frame.kind
                        in {
                            FrameKind.ACTIVATE_AUTHORITY,
                            FrameKind.CALL,
                            FrameKind.CANCEL_MAPPING,
                            FrameKind.ACCEPT_DEBUG_ZERO_MOTION,
                            FrameKind.PREPARE_PHYSICAL_CALL,
                            FrameKind.PROVISION_VERIFIED_RELEASE,
                            FrameKind.START_PREPARED_CALL,
                        }
                        else {}
                    ),
                },
            )
        except ProtocolError as exc:
            return ProtocolFrame.create(
                kind=FrameKind.RESULT,
                sequence=self._sequence,
                session_id=frame.session_id,
                run_id=frame.run_id,
                payload={
                    "request_kind": frame.kind.value,
                    "ok": False,
                    "error": _public_error_code(exc),
                    **(
                        {"provider_invocation_count": self._provider_invocation_count}
                        if frame.kind
                        in {
                            FrameKind.ACTIVATE_AUTHORITY,
                            FrameKind.CALL,
                            FrameKind.CANCEL_MAPPING,
                            FrameKind.ACCEPT_DEBUG_ZERO_MOTION,
                            FrameKind.PREPARE_PHYSICAL_CALL,
                            FrameKind.PROVISION_VERIFIED_RELEASE,
                            FrameKind.START_PREPARED_CALL,
                        }
                        else {}
                    ),
                },
            )
        except ValidationError:
            return ProtocolFrame.create(
                kind=FrameKind.RESULT,
                sequence=self._sequence,
                session_id=frame.session_id,
                run_id=frame.run_id,
                payload={
                    "request_kind": frame.kind.value,
                    "ok": False,
                    "error": "TARGETD_REQUEST_VALIDATION_FAILED",
                    **(
                        {"provider_invocation_count": self._provider_invocation_count}
                        if frame.kind
                        in {
                            FrameKind.ACTIVATE_AUTHORITY,
                            FrameKind.CALL,
                            FrameKind.CANCEL_MAPPING,
                            FrameKind.ACCEPT_DEBUG_ZERO_MOTION,
                            FrameKind.PREPARE_PHYSICAL_CALL,
                            FrameKind.PROVISION_VERIFIED_RELEASE,
                            FrameKind.START_PREPARED_CALL,
                        }
                        else {}
                    ),
                },
            )
        except (KeyError, TypeError, ValueError):
            return ProtocolFrame.create(
                kind=FrameKind.RESULT,
                sequence=self._sequence,
                session_id=frame.session_id,
                run_id=frame.run_id,
                payload={
                    "request_kind": frame.kind.value,
                    "ok": False,
                    "error": "TARGETD_REQUEST_VALIDATION_FAILED",
                    **(
                        {"provider_invocation_count": self._provider_invocation_count}
                        if frame.kind
                        in {
                            FrameKind.ACTIVATE_AUTHORITY,
                            FrameKind.CALL,
                            FrameKind.CANCEL_MAPPING,
                            FrameKind.PROVISION_VERIFIED_RELEASE,
                        }
                        else {}
                    ),
                },
            )

    def _dispatch(self, frame: ProtocolFrame) -> dict:
        if frame.kind == FrameKind.OPEN_JOURNEY:
            target_id = str(frame.payload.get("target_id", ""))
            profile_id = str(frame.payload.get("profile_id", ""))
            if target_id != self.service.target_id or not profile_id:
                raise ProtocolError("journey target or profile is invalid")
            try:
                session = self.service.state.load_session(frame.session_id)
            except KeyError:
                session = JourneySession.create(
                    session_id=frame.session_id,
                    target_id=target_id,
                    profile_id=profile_id,
                )
                supplied_token = frame.payload.get("resume_token")
                if supplied_token:
                    session = session.model_copy(update={"resume_token": str(supplied_token)})
                supplied_surface = frame.payload.get("surface_digest")
                if supplied_surface is not None:
                    session = session.model_copy(update={"surface_digest": str(supplied_surface)})
                self.service.open_session(session)
            else:
                if session.target_id != target_id or session.profile_id != profile_id:
                    raise ProtocolError("journey session identity conflicts with stored session")
                supplied_token = str(frame.payload.get("resume_token", ""))
                session = self.service.resume_session(frame.session_id, supplied_token)
                supplied_surface = frame.payload.get("surface_digest")
                if supplied_surface is not None:
                    supplied_surface = str(supplied_surface)
                    if session.surface_digest not in (None, supplied_surface):
                        raise ProtocolError("journey session surface digest conflicts with stored session")
                    if session.surface_digest is None:
                        session = session.model_copy(update={"surface_digest": supplied_surface})
                        self.service.state.save_session(session)
            self._session = session
            return {"session": session.model_dump(mode="json")}
        if frame.kind == FrameKind.RESUME_SESSION:
            token = str(frame.payload.get("resume_token", ""))
            self._session = self.service.resume_session(frame.session_id, token)
            return {"session": self._session.model_dump(mode="json")}
        if self._session is None or frame.session_id != self._session.session_id:
            raise ProtocolError("journey session is not open")
        if frame.kind == FrameKind.BOOTSTRAP:
            return {"health": self.service.health().model_dump(mode="json")}
        if frame.kind == FrameKind.HANDOFF:
            requested = frame.payload.get("phase", JourneyPhase.PROBE.value)
            phase = JourneyPhase(str(requested))
            self._session = self._session.model_copy(update={"phase": phase})
            self.service.state.save_session(self._session)
            return {"health": self.service.health().model_dump(mode="json"), "phase": phase.value}
        if frame.kind == FrameKind.PHASE_CHANGE:
            phase = JourneyPhase(str(frame.payload.get("phase")))
            self._session = self._session.model_copy(update={"phase": phase})
            self.service.state.save_session(self._session)
            return {"phase": phase.value}
        if frame.kind == FrameKind.HAS:
            digest = str(frame.payload.get("bundle_digest", ""))
            return {"bundle_digest": digest, "present": self.service.has_bundle(digest)}
        if frame.kind == FrameKind.PUT:
            manifest = ExecutionBundleManifest.model_validate(frame.payload["manifest"])
            source = base64.b64decode(str(frame.payload["source_b64"]).encode("ascii"), validate=True)
            self.service.put_bundle(manifest, source)
            return {"bundle_digest": manifest.bundle_digest, "present": True}
        if frame.kind == FrameKind.DSL_REQUEST:
            if self.dsl_service is None:
                raise ProtocolError("TARGETD_DSL_SERVICE_UNAVAILABLE")
            dsl_frame = DslFrame.model_validate(frame.payload["frame"])
            journey_session_id = dsl_frame.payload.get("journey_session_id")
            if journey_session_id is not None and journey_session_id != frame.session_id:
                raise ProtocolError("DSL request journey does not match targetd session")
            if dsl_frame.frame_type == DslFrameType.DSL_PUT:
                context = dsl_frame.payload.get("context")
                if not isinstance(context, dict) or context.get("robot_id") != self.service.target_id:
                    raise ProtocolError("DSL PUT target does not match targetd session")
            response = self.dsl_service.handle(dsl_frame)
            return {"frame": response.model_dump(mode="json")}
        if frame.kind == FrameKind.PROVISION_VERIFIED_RELEASE:
            if self.worker is None:
                raise ProtocolError("TARGETD_EXECUTION_DISABLED")
            if self.dsl_service is None:
                raise ProtocolError("TARGETD_DSL_SERVICE_UNAVAILABLE")
            provision = TargetdVerifiedReleaseProvisionRequest.model_validate(frame.payload)
            verified_inputs = self.dsl_service.verified_release_inputs(
                provision.conformance_cache_key,
                journey_session_id=frame.session_id,
            )
            head = self.service.provision_verified_release(
                provision,
                session_id=frame.session_id,
                provider_id=self.provider_id,
                verified_inputs=verified_inputs,
            )
            return {
                "release_digest": head.release_digest,
                "catalog_head_digest": head.catalog_head_digest,
                "release": head.release.model_dump(mode="json"),
            }
        if frame.kind == FrameKind.ACTIVATE_AUTHORITY:
            if self.worker is None:
                raise ProtocolError("TARGETD_EXECUTION_DISABLED")
            activation = TargetdAuthorityActivationRequest.model_validate(frame.payload)
            authority = self.service.activate_authority(
                activation,
                session_id=frame.session_id,
                provider_id=self.provider_id,
            )
            return {"authority": authority.model_dump(mode="json")}
        if frame.kind == FrameKind.CANCEL_MAPPING:
            cancellation = TargetdMappingCancelRequest.model_validate(frame.payload)
            receipt = self.service.cancel_mapping(
                cancellation,
                session_id=frame.session_id,
            )
            return {"receipt": receipt.model_dump(mode="json")}
        if frame.kind == FrameKind.PREPARE_PHYSICAL_CALL:
            request = validate_execution_request(frame.payload)
            if request.session_id != frame.session_id:
                raise ProtocolError("TARGETD_PHYSICAL_PREPARE_SESSION_IDENTITY_MISMATCH")
            if frame.run_id is not None and request.run_id != frame.run_id:
                raise ProtocolError("TARGETD_PHYSICAL_PREPARE_RUN_IDENTITY_MISMATCH")
            manifest, _source = self.service.cache.load(request.bundle_digest)
            return self._dispatch_physical_prepare(request, manifest)
        if frame.kind == FrameKind.ACCEPT_DEBUG_ZERO_MOTION:
            return self._dispatch_debug_zero_motion_acceptance(frame)
        if frame.kind == FrameKind.START_PREPARED_CALL:
            return self._dispatch_physical_start(frame)
        if frame.kind == FrameKind.CALL:
            if self.worker is None:
                raise ProtocolError("TARGETD_EXECUTION_DISABLED")
            request = validate_execution_request(frame.payload)
            if request.session_id != frame.session_id:
                raise ProtocolError("execution request session does not match frame")
            if frame.run_id is not None and request.run_id != frame.run_id:
                raise ProtocolError("execution request run does not match frame")
            worker_provider = getattr(self.worker, "provider", None)
            if isinstance(worker_provider, Ros2ReadOnlyProvider):
                worker_provider.validate_call(
                    request.provider_operation,
                    request.arguments,
                )
            manifest, source = self.service.cache.load(request.bundle_digest)
            if self.process_runtime is not None:
                return self._dispatch_process_call(request, manifest)
            if requires_motion_safety(request.authority):
                raise ProtocolError("TARGETD_PHYSICAL_PROCESS_WORKER_REQUIRED")
            receipt = self.service.accept_call(request, manifest, provider_id=self.provider_id)
            call_started = False
            if receipt.status == "ACCEPTED":
                receipt = self.service.start_call(
                    request,
                    manifest,
                    provider_id=self.provider_id,
                )
                call_started = receipt.status == "STARTED"

                def execute() -> tuple[str, dict]:
                    started = time.monotonic()
                    worker_provider = getattr(self.worker, "provider", None)
                    if manifest.tool_id == "app.base.rotate" and not isinstance(worker_provider, RosContainerProvider):
                        raise ProtocolError("rotation provider is required")
                    if isinstance(worker_provider, Ros2ReadOnlyProvider):
                        self._provider_invocation_count += 1
                        result = worker_provider.invoke(
                            request.provider_operation,
                            request.arguments,
                        )
                    else:
                        result = self.worker.execute(manifest, source, request.arguments)
                    max_duration = float(manifest.limits.get("max_duration_s", 60))
                    if time.monotonic() - started > max_duration:
                        raise ProtocolError("bundle execution exceeded max_duration_s")
                    terminal_status = self._terminal_status(manifest, result)
                    return terminal_status, result

                receipt = self.service.execute_provider(
                    request,
                    manifest,
                    provider_id=self.provider_id,
                    execute=execute,
                )
            return {
                "receipt": receipt.model_dump(mode="json"),
                "call_started": call_started,
            }
        if frame.kind in {FrameKind.CANCEL, FrameKind.STOP}:
            intent = "CANCEL" if frame.kind == FrameKind.CANCEL else "STOP"
            call_id = frame.payload.get("call_id")
            stored = self.service.state.load_receipt(frame.session_id, call_id) if isinstance(call_id, str) else None
            if stored is not None and self.service._is_physical_process_receipt(stored):
                return self._dispatch_process_interrupt(
                    frame,
                    intent=intent,
                    runtime=self.physical_process_runtime,
                    physical=True,
                )
            if self.process_runtime is not None:
                return self._dispatch_process_interrupt(
                    frame,
                    intent=intent,
                    runtime=self.process_runtime,
                    physical=False,
                )
        if frame.kind == FrameKind.CANCEL:
            receipt = self.service.cancel_call(frame.session_id, str(frame.payload["call_id"]))
            return {"receipt": receipt.model_dump(mode="json")}
        if frame.kind == FrameKind.STOP:
            raise ProtocolError("TARGETD_PROCESS_WORKER_REQUIRED")
        if frame.kind == FrameKind.QUERY_CALL:
            call_id = frame.payload.get("call_id")
            stored = self.service.state.load_receipt(frame.session_id, call_id) if isinstance(call_id, str) else None
            physical = stored is not None and (
                (stored.provider_id == "ros-container" and stored.provider_operation == "base.rotate")
                or any(ref.startswith("artifact://targetd/physical-provider-gates/") for ref in stored.evidence_refs)
            )
            if physical:
                return self._dispatch_physical_gate_query(frame)
            if self.process_runtime is not None:
                return self._dispatch_process_query(frame)
            receipt = self.service.query_call(frame.session_id, str(frame.payload["call_id"]))
            return {"receipt": receipt.model_dump(mode="json") if receipt else None}
        if frame.kind == FrameKind.CLOSE_SESSION:
            self._session = self._session.model_copy(update={"closed": True, "expires_at": datetime.now(timezone.utc)})
            self.service.state.save_session(self._session)
            return {"closed": True}
        raise ProtocolError(f"unsupported targetd frame: {frame.kind.value}")

    def _dispatch_physical_prepare(
        self,
        request,
        manifest: ExecutionBundleManifest,
    ) -> dict:
        runtime = self.physical_process_runtime
        work_factory = self.physical_process_work_factory
        if runtime is None or work_factory is None:
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_WORKER_REQUIRED")
        try:
            from .physical_worker import validate_landerpi_rotate_process_call

            request, manifest = validate_landerpi_rotate_process_call(
                request,
                manifest,
            )
        except Exception as exc:
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_REQUEST_REQUIRED") from exc
        call_key = WorkerCallKey.from_request(request)
        key_digest = call_key.digest()
        pending = self._pending_physical.get(key_digest)
        if pending is not None:
            if pending.request != request or pending.manifest != manifest or pending.preparation.call_key != call_key:
                raise ProtocolError("TARGETD_PHYSICAL_PREPARE_IDENTITY_MISMATCH")
            receipt = self.service.state.load_receipt(
                request.session_id,
                request.idempotency_key,
            )
            if receipt is None or receipt.status != "ACCEPTED":
                raise ProtocolError("TARGETD_PHYSICAL_PREPARE_NOT_LIVE")
            return self._physical_prepare_payload(receipt, pending.preparation)

        receipt = self.service.prepare_physical_process_call(
            request,
            manifest,
            provider_id="ros-container",
        )
        if receipt.status != "ACCEPTED":
            return {"receipt": receipt.model_dump(mode="json"), "prepared": False}
        try:
            work = work_factory(request, manifest)
            preparation = runtime.prepare_physical(
                request,
                manifest,
                worker_id="landerpi-bounded-rotate",
                work=work,
                terminal_commit=lambda snapshot: self._commit_physical_snapshot(
                    call_key,
                    snapshot,
                ),
            )
        except Exception as exc:
            lease = runtime.store.load(call_key)
            if lease is not None:
                try:
                    self.service.commit_physical_process_result(call_key, lease)
                except ProtocolError:
                    pass
            else:
                self.service.mark_physical_process_unknown(
                    call_key,
                    outcome_code="PHYSICAL_PROCESS_PREPARE_FAILED",
                )
            if isinstance(exc, ProtocolError):
                raise
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_PREPARE_FAILED") from exc
        pending = _PendingPhysicalCall(
            request=request,
            manifest=manifest,
            work=work,
            preparation=preparation,
        )
        if key_digest in self._pending_physical:
            runtime.request_interrupt(call_key, intent="STOP")
            raise ProtocolError("TARGETD_PHYSICAL_PREPARE_ALREADY_ACTIVE")
        self._pending_physical[key_digest] = pending
        return self._physical_prepare_payload(receipt, preparation)

    @staticmethod
    def _physical_prepare_payload(receipt, preparation) -> dict:
        armed = preparation.armed_zero
        arm_payload = armed.as_dict() if callable(getattr(armed, "as_dict", None)) else None
        if not isinstance(arm_payload, dict):
            raise ProtocolError("TARGETD_PHYSICAL_WORKER_ARM_INVALID")
        return {
            "receipt": receipt.model_dump(mode="json"),
            "prepared": True,
            "armed_zero": arm_payload,
        }

    def _dispatch_debug_zero_motion_acceptance(
        self,
        frame: ProtocolFrame,
    ) -> dict:
        """Run one target-owned rehearsal without releasing the provider."""

        runtime = self.physical_process_runtime
        acceptance_factory = self.physical_acceptance_factory
        store = getattr(self.service, "physical_acceptance_receipt_store", None)
        if (
            runtime is None
            or acceptance_factory is None
            or store is None
            or self._session is None
        ):
            raise ProtocolError("TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_UNAVAILABLE")
        if set(frame.payload) != {
            "call_id",
            "target_id",
            "request_digest",
            "armed_zero_receipt_digest",
            "debug_admission",
            "debug_admission_digest",
            "acceptance_auth",
        }:
            raise ProtocolError("TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_IDENTITY_INVALID")
        call_id = frame.payload.get("call_id")
        target_id = frame.payload.get("target_id")
        request_digest = frame.payload.get("request_digest")
        arm_digest = frame.payload.get("armed_zero_receipt_digest")
        admission_digest = frame.payload.get("debug_admission_digest")
        supplied_auth = frame.payload.get("acceptance_auth")
        try:
            from .landerpi_motion_target import DebugOnlyUserAttestedAdmission

            admission = DebugOnlyUserAttestedAdmission.model_validate(
                frame.payload.get("debug_admission")
            )
        except (TypeError, ValueError) as exc:
            raise ProtocolError(
                "TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_IDENTITY_INVALID"
            ) from exc
        if (
            not isinstance(call_id, str)
            or target_id != self.service.target_id
            or not isinstance(request_digest, str)
            or not isinstance(arm_digest, str)
            or admission_digest != admission.payload_sha256
            or not isinstance(supplied_auth, str)
        ):
            raise ProtocolError("TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_IDENTITY_INVALID")
        expected_auth = debug_zero_motion_acceptance_auth_tag(
            self._session.resume_token,
            target_id=target_id,
            session_id=frame.session_id,
            call_id=call_id,
            request_digest=request_digest,
            armed_zero_receipt_digest=arm_digest,
            debug_admission_digest=admission.payload_sha256,
            sequence=frame.sequence,
        )
        if not hmac.compare_digest(supplied_auth, expected_auth):
            raise ProtocolError(
                "TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_AUTHENTICATION_FAILED"
            )
        call_key = WorkerCallKey(
            target_id=target_id,
            session_id=frame.session_id,
            idempotency_key=call_id,
            request_digest=request_digest,
        )
        pending = self._pending_physical.get(call_key.digest())
        if pending is None or pending.preparation.call_key != call_key:
            raise ProtocolError("TARGETD_PHYSICAL_PREPARED_CALL_NOT_FOUND")
        armed_zero = pending.preparation.armed_zero
        if getattr(armed_zero, "arm_receipt_digest", None) != arm_digest:
            raise ProtocolError("TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_IDENTITY_INVALID")
        if (
            admission.call_id != call_id
            or admission.session_id != frame.session_id
            or admission.target_id != target_id
            or admission.execution_subject_digest
            != pending.request.execution_subject_digest
            or admission.requested_rotation_degrees
            != pending.request.arguments.get("angle_degrees")
            or admission.requested_linear_meters != 0.0
        ):
            raise ProtocolError("TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_IDENTITY_INVALID")
        receipt = self.service.state.load_receipt(frame.session_id, call_id)
        if receipt is None or receipt.status != "ACCEPTED":
            raise ProtocolError("TARGETD_PHYSICAL_PREPARE_NOT_LIVE")

        existing = store.load(call_key)
        if existing is not None:
            if (
                existing.sidecar.debug_admission != admission
                or existing.sidecar.armed_zero
                != (
                    armed_zero.as_dict()
                    if callable(getattr(armed_zero, "as_dict", None))
                    else None
                )
            ):
                raise ProtocolError("TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_CONFLICT")
            durable = store.revalidate(existing)
            receipt = self.service.record_debug_physical_acceptance(
                call_key,
                durable,
            )
            return self._debug_acceptance_payload(
                receipt,
                durable,
                start_eligible=self._debug_acceptance_start_eligible(
                    pending,
                    durable,
                    receipt,
                ),
            )
        if pending.debug_acceptance_attempted:
            raise ProtocolError(
                "TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_OUTCOME_UNKNOWN"
            )

        lease = runtime.store.load(call_key)
        if (
            lease is None
            or lease.state != "RUNNING"
            or lease.armed_zero
            != (
                armed_zero.as_dict()
                if callable(getattr(armed_zero, "as_dict", None))
                else None
            )
            or datetime.now(timezone.utc) >= lease.expires_at
        ):
            raise ProtocolError("TARGETD_PHYSICAL_PREPARE_NOT_LIVE")
        gate = None
        # Burn the in-memory attempt before entering the deployment factory.
        # The target also durably reserves this admission, but setting the
        # local bit closes factory/store/ACK ambiguity without assuming the
        # target can replay a one-shot rehearsal.
        pending.debug_acceptance_attempted = True
        try:
            from .physical_gate import DebugUserAttestedPhysicalProviderGate

            gate = acceptance_factory(
                pending.request,
                pending.manifest,
                armed_zero,
                admission,
            )
            if type(gate) is not DebugUserAttestedPhysicalProviderGate:
                raise ProtocolError("TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_BLOCKED")
            gate.validate_request(
                pending.request,
                pending.request.authority,
            )
            if gate.admission != admission:
                raise ProtocolError("TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_IDENTITY_INVALID")
            lease = runtime.store.load(call_key)
            if (
                lease is None
                or lease.state != "RUNNING"
                or lease.armed_zero != armed_zero.as_dict()
                or datetime.now(timezone.utc) >= lease.expires_at
            ):
                raise ProtocolError("TARGETD_PHYSICAL_PREPARE_NOT_LIVE")
            persisted_at = (
                gate.clock()
                if callable(getattr(gate, "clock", None))
                else datetime.now(timezone.utc)
            )
            if (
                persisted_at.tzinfo is None
                or persisted_at.utcoffset() is None
                or persisted_at >= pending.request.deadline
                or persisted_at >= admission.expires_at
                or persisted_at >= self._session.expires_at
            ):
                raise ProtocolError("TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_TIME_INVALID")
            reference = store.persist(
                call_key,
                gate.acceptance_receipt,
                armed_zero=armed_zero,
                debug_admission=admission,
                now=persisted_at,
            )
            durable = store.revalidate(reference)
            if (
                durable.sidecar.acceptance_receipt != gate.acceptance_receipt
                or durable.sidecar.debug_admission != admission
            ):
                raise ProtocolError("TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_INVALID")
            receipt = self.service.record_debug_physical_acceptance(
                call_key,
                durable,
            )
        except Exception as exc:
            if gate is not None:
                try:
                    gate.target.abort_zero_motion(
                        acceptance_id=admission.acceptance_id,
                        intent=pending.request.motion_safety_admission.intent,
                    )
                except Exception:
                    pass
            try:
                runtime.request_interrupt(call_key, intent="STOP")
            except Exception:
                pass
            if isinstance(exc, ProtocolError):
                raise
            raise ProtocolError(
                "TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_BLOCKED"
            ) from exc
        pending.debug_acceptance_gate = gate
        pending.debug_acceptance_reference = durable
        return self._debug_acceptance_payload(
            receipt,
            durable,
            start_eligible=self._debug_acceptance_start_eligible(
                pending,
                durable,
                receipt,
            ),
        )

    def _debug_acceptance_start_eligible(
        self,
        pending: _PendingPhysicalCall,
        reference,
        receipt,
    ) -> bool:
        """Conservatively report whether the in-memory START seam is live."""

        runtime = self.physical_process_runtime
        gate = pending.debug_acceptance_gate
        session = self._session
        if runtime is None or gate is None or session is None:
            return False
        try:
            point = (
                gate.clock()
                if callable(getattr(gate, "clock", None))
                else datetime.now(timezone.utc)
            )
            if point.tzinfo is None or point.utcoffset() is None:
                return False
            point = point.astimezone(timezone.utc)
            lease = runtime.store.load(pending.preparation.call_key)
            armed = pending.preparation.armed_zero
            challenge = reference.sidecar.acceptance_receipt.provider_gate
            return (
                receipt is not None
                and receipt.status == "ACCEPTED"
                and receipt.provider_started_at is None
                and pending.debug_acceptance_reference == reference
                and gate.acceptance_receipt
                == reference.sidecar.acceptance_receipt
                and gate.admission == reference.sidecar.debug_admission
                and challenge is not None
                and point < challenge.expires_at
                and point < reference.sidecar.debug_admission.expires_at
                and point < pending.request.deadline
                and point < session.expires_at
                and point.timestamp() < armed.registry_expires_at_epoch_s
                and lease is not None
                and lease.call_key == pending.preparation.call_key
                and lease.state == "RUNNING"
                and lease.armed_zero == armed.as_dict()
                and point < lease.expires_at
            )
        except Exception:
            return False

    @staticmethod
    def _debug_acceptance_payload(
        receipt,
        reference,
        *,
        start_eligible: bool,
    ) -> dict:
        sidecar = reference.sidecar
        call_key = sidecar.call_key
        arm_digest = sidecar.armed_zero["arm_receipt_digest"]
        admission_digest = sidecar.debug_admission.payload_sha256
        start = {
            "schema_version": "rolo-targetd-debug-zero-motion-acceptance-reference/v1",
            "authority_class": "DEBUG_ONLY_USER_ATTESTED",
            "production_authority": False,
            "target_id": call_key.target_id,
            "session_id": call_key.session_id,
            "call_id": call_key.idempotency_key,
            "request_digest": call_key.request_digest,
            "armed_zero_receipt_digest": arm_digest,
            "debug_admission_digest": admission_digest,
            "acceptance_uri": reference.uri,
            "acceptance_digest_uri": reference.digest_uri,
            "acceptance_sidecar_digest": sidecar.sidecar_digest,
        }
        return {
            "receipt": receipt.model_dump(mode="json"),
            "accepted": True,
            "start_eligible": start_eligible,
            "acceptance_receipt": sidecar.acceptance_receipt.model_dump(
                mode="json"
            ),
            "debug_acceptance": {
                "uri": reference.uri,
                "digest_uri": reference.digest_uri,
                "sidecar": sidecar.model_dump(mode="json"),
            },
            "provider_gate_start": start,
        }

    def _stop_after_debug_acceptance_ack_failure(
        self,
        frame: ProtocolFrame,
    ) -> None:
        """Fail closed if the durable acceptance response cannot be sent."""

        runtime = self.physical_process_runtime
        call_id = frame.payload.get("call_id")
        request_digest = frame.payload.get("request_digest")
        target_id = frame.payload.get("target_id")
        if (
            runtime is None
            or not isinstance(call_id, str)
            or not isinstance(request_digest, str)
            or target_id != self.service.target_id
        ):
            return
        try:
            call_key = WorkerCallKey(
                target_id=target_id,
                session_id=frame.session_id,
                idempotency_key=call_id,
                request_digest=request_digest,
            )
        except ValueError:
            return
        pending = self._pending_physical.pop(call_key.digest(), None)
        if pending is not None and pending.debug_acceptance_gate is not None:
            try:
                pending.debug_acceptance_gate.target.abort_zero_motion(
                    acceptance_id=(
                        pending.debug_acceptance_gate.admission.acceptance_id
                    ),
                    intent=pending.request.motion_safety_admission.intent,
                )
            except Exception:
                pass
        try:
            runtime.request_interrupt(call_key, intent="STOP")
        except Exception:
            pass

    def _dispatch_physical_start(self, frame: ProtocolFrame) -> dict:
        runtime = self.physical_process_runtime
        gate_factory = self.physical_gate_factory
        if runtime is None or self._session is None:
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_WORKER_REQUIRED")
        if set(frame.payload) != {
            "call_id",
            "target_id",
            "request_digest",
            "armed_zero_receipt_digest",
            "provider_gate",
            "provider_gate_payload_digest",
            "start_auth",
        }:
            raise ProtocolError("TARGETD_PHYSICAL_PREPARED_START_IDENTITY_INVALID")
        call_id = frame.payload.get("call_id")
        target_id = frame.payload.get("target_id")
        request_digest = frame.payload.get("request_digest")
        arm_digest = frame.payload.get("armed_zero_receipt_digest")
        raw_gate = frame.payload.get("provider_gate")
        gate_digest = frame.payload.get("provider_gate_payload_digest")
        supplied_auth = frame.payload.get("start_auth")
        if (
            not isinstance(call_id, str)
            or target_id != self.service.target_id
            or not isinstance(request_digest, str)
            or not isinstance(arm_digest, str)
            or not isinstance(raw_gate, dict)
            or not isinstance(gate_digest, str)
            or not isinstance(supplied_auth, str)
            or canonical_json_sha256(raw_gate) != gate_digest
        ):
            raise ProtocolError("TARGETD_PHYSICAL_PREPARED_START_IDENTITY_INVALID")
        expected_auth = physical_prepared_start_auth_tag(
            self._session.resume_token,
            target_id=target_id,
            session_id=frame.session_id,
            call_id=call_id,
            request_digest=request_digest,
            armed_zero_receipt_digest=arm_digest,
            provider_gate_payload_digest=gate_digest,
            sequence=frame.sequence,
        )
        if not hmac.compare_digest(supplied_auth, expected_auth):
            raise ProtocolError("TARGETD_PHYSICAL_PREPARED_START_AUTHENTICATION_FAILED")
        call_key = WorkerCallKey(
            target_id=target_id,
            session_id=frame.session_id,
            idempotency_key=call_id,
            request_digest=request_digest,
        )
        pending = self._pending_physical.get(call_key.digest())
        if pending is None or pending.preparation.call_key != call_key:
            receipt = self.service.state.load_receipt(frame.session_id, call_id)
            if receipt is not None and receipt.status == "STARTED":
                raise ProtocolError("TARGETD_PHYSICAL_PREPARED_START_ALREADY_CONSUMED")
            raise ProtocolError("TARGETD_PHYSICAL_PREPARED_CALL_NOT_FOUND")
        armed = pending.preparation.armed_zero
        if getattr(armed, "arm_receipt_digest", None) != arm_digest:
            raise ProtocolError("TARGETD_PHYSICAL_PREPARED_START_IDENTITY_INVALID")
        try:
            from .physical_gate import (
                ZeroMotionPhysicalProviderGate,
            )

            if (
                raw_gate.get("schema_version")
                == "rolo-targetd-debug-zero-motion-acceptance-reference/v1"
            ):
                gate = self._resolve_debug_acceptance_start_gate(
                    pending,
                    call_key,
                    raw_gate,
                )
            else:
                if gate_factory is None or pending.debug_acceptance_reference is not None:
                    raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_BLOCKED")
                gate = gate_factory(
                    pending.request,
                    pending.manifest,
                    armed,
                    raw_gate,
                )
                # A debug gate can only originate from the authenticated,
                # persisted ACCEPT_DEBUG_ZERO_MOTION path above. A caller
                # cannot smuggle an acceptance receipt into START.
                if type(gate) is not ZeroMotionPhysicalProviderGate:
                    raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_BLOCKED")
            gate.validate_request(pending.request, pending.request.authority)
            self.service.physical_motion_gate = gate
            pending.provider_gate_payload_digest = gate_digest
            submission = runtime.start_prepared(call_key)
        except Exception as exc:
            lease = runtime.store.load(call_key)
            if lease is not None and lease.state not in {
                "CLAIMED",
                "RUNNING",
                "CANCEL_REQUESTED",
                "STOP_REQUESTED",
            }:
                try:
                    self.service.commit_physical_process_result(call_key, lease)
                except ProtocolError:
                    pass
            if isinstance(exc, ProtocolError):
                raise
            raise ProtocolError("TARGETD_PHYSICAL_PREPARED_START_FAILED") from exc
        self._provider_invocation_count += 1
        receipt = self.service.state.load_receipt(frame.session_id, call_id)
        if receipt is not None and receipt.status in {
            "SUCCEEDED",
            "FAILED",
            "STOPPED",
            "CANCELLED",
        }:
            lease = runtime.store.load(call_key)
            if lease is None:
                self._fail_closed_after_physical_start_ack(runtime, call_key)
                raise ProtocolError("TARGETD_PHYSICAL_PREPARED_START_RECEIPT_MISSING")
            receipt = self.service.revalidate_physical_process_terminal(
                call_key,
                lease,
            )
        elif receipt is None or receipt.status != "STARTED":
            self._fail_closed_after_physical_start_ack(runtime, call_key)
            raise ProtocolError("TARGETD_PHYSICAL_PREPARED_START_RECEIPT_MISSING")
        # START is one-shot at the daemon boundary as well as at the target
        # CAS.  Retaining the prepared handle here would let a duplicated
        # authenticated frame reach the runtime/gate a second time.
        self._pending_physical.pop(call_key.digest(), None)
        return {
            "receipt": receipt.model_dump(mode="json"),
            "call_started": True,
            "process_id": submission.process_id,
        }

    def _resolve_debug_acceptance_start_gate(
        self,
        pending: _PendingPhysicalCall,
        call_key: WorkerCallKey,
        raw_gate: dict[str, object],
    ):
        reference = pending.debug_acceptance_reference
        gate = pending.debug_acceptance_gate
        store = getattr(self.service, "physical_acceptance_receipt_store", None)
        if reference is None or gate is None or store is None:
            raise ProtocolError("TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_REQUIRED")
        expected = self._debug_acceptance_payload(
            self.service.state.load_receipt(
                call_key.session_id,
                call_key.idempotency_key,
            ),
            reference,
            start_eligible=True,
        )["provider_gate_start"]
        if raw_gate != expected:
            raise ProtocolError("TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_REFERENCE_INVALID")
        durable = store.resolve(
            reference.uri,
            call_key=call_key,
            digest_uri=reference.digest_uri,
        )
        if durable != reference:
            raise ProtocolError("TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_REFERENCE_INVALID")
        self.service.resolve_debug_physical_acceptance(
            call_key,
            expected_uri=reference.uri,
            expected_digest_uri=reference.digest_uri,
        )
        try:
            from .physical_gate import DebugUserAttestedPhysicalProviderGate

            if (
                type(gate) is not DebugUserAttestedPhysicalProviderGate
                or gate.acceptance_receipt != durable.sidecar.acceptance_receipt
                or gate.admission != durable.sidecar.debug_admission
            ):
                raise TypeError
        except (AttributeError, TypeError) as exc:
            raise ProtocolError(
                "TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_REFERENCE_INVALID"
            ) from exc
        return gate

    def _fail_closed_after_physical_start_ack(
        self,
        runtime: LeasedProcessWorkerRuntime,
        call_key: WorkerCallKey,
    ) -> None:
        """Stop an acknowledged child whose target receipt is unverifiable."""

        try:
            self.service.mark_physical_process_unknown(
                call_key,
                outcome_code="PHYSICAL_PROCESS_START_RECEIPT_INVALID",
            )
        except ProtocolError:
            pass
        try:
            runtime.request_interrupt(call_key, intent="STOP")
        except (ProtocolError, ValueError):
            pass

    def _start_prepared_physical_provider(
        self,
        lease_claim,
        armed_zero,
    ):
        call_key = lease_claim.lease.call_key
        pending = self._pending_physical.get(call_key.digest())
        if pending is None or pending.preparation.call_key != call_key or pending.preparation.armed_zero != armed_zero or pending.provider_gate_payload_digest is None:
            raise ProtocolError("TARGETD_PHYSICAL_PREPARED_START_IDENTITY_INVALID")
        try:
            from .physical_worker import read_target_physical_worker_registry

            record = lease_claim.lease
            registry = read_target_physical_worker_registry(
                expected_call_key_digest=record.call_key_digest,
                expected_target_id=record.call_key.target_id,
                expected_call_id=record.call_key.idempotency_key,
                expected_session_id=record.call_key.session_id,
                expected_request_digest=record.call_key.request_digest,
                expected_execution_subject_digest=(record.physical_execution_subject_digest or ""),
                expected_runtime_sha256=record.physical_runtime_sha256 or "",
                container=self.physical_process_runtime.physical_container,
                container_user=self.physical_process_runtime.physical_container_user,
                require_live=True,
            )
        except Exception as exc:
            raise ProtocolError("TARGETD_PHYSICAL_WORKER_ARM_NOT_LIVE") from exc
        if registry is None or registry.armed_zero != armed_zero:
            raise ProtocolError("TARGETD_PHYSICAL_WORKER_ARM_NOT_LIVE")
        return self.service.start_physical_process_call(
            pending.request,
            pending.manifest,
            provider_id="ros-container",
            lease_claim=lease_claim,
            armed_zero=armed_zero,
        )

    def _dispatch_process_call(
        self,
        request,
        manifest: ExecutionBundleManifest,
    ) -> dict:
        runtime = self.process_runtime
        work = self.process_work
        live_fence = self.process_live_fence
        if runtime is None or work is None or live_fence is None:
            raise ProtocolError("TARGETD_PROCESS_WORKER_REQUIRED")
        request, manifest = validate_sealed_odom_r0_call(request, manifest)
        call_key = WorkerCallKey.from_request(request)
        receipt = self.service.accept_call(
            request,
            manifest,
            provider_id=self.provider_id,
            preserve_active_process=True,
        )
        call_started = False
        if receipt.status == "ACCEPTED":
            try:
                runtime.submit(
                    request,
                    manifest,
                    worker_id="ros2-odom",
                    work=work,
                    start_gate=lambda _lease: self.service.start_process_call(
                        request,
                        manifest,
                        provider_id=self.provider_id,
                        lease_probe=lambda: runtime.store.reconcile(
                            call_key,
                            supervisor_id=runtime.supervisor_id,
                        ),
                        live_fence=live_fence,
                    ),
                    terminal_commit=lambda snapshot: self._commit_process_snapshot(
                        call_key,
                        snapshot,
                    ),
                )
                self._provider_invocation_count += 1
                call_started = True
            except Exception:
                lease = runtime.store.load(call_key)
                if lease is None:
                    receipt = self.service.complete_call(
                        request.session_id,
                        request.idempotency_key,
                        status="UNKNOWN",
                        result={"error": "PROCESS_WORKER_STARTUP_FAILED"},
                    )
                else:
                    receipt = self.service.commit_process_result(call_key, lease)
                raise
        elif receipt.status == "STARTED":
            snapshot = runtime.reconcile_snapshot(call_key)
            receipt = self._commit_process_snapshot(call_key, snapshot)
        current = self.service.state.load_receipt(
            request.session_id,
            request.idempotency_key,
        )
        if current is not None:
            receipt = current
        return {
            "receipt": receipt.model_dump(mode="json"),
            "call_started": call_started,
        }

    def _dispatch_process_interrupt(
        self,
        frame: ProtocolFrame,
        *,
        intent: str,
        runtime: LeasedProcessWorkerRuntime | None,
        physical: bool,
    ) -> dict:
        if runtime is None or self._session is None:
            raise ProtocolError("TARGETD_PROCESS_WORKER_REQUIRED")
        call_id = str(frame.payload.get("call_id", ""))
        request_digest = str(frame.payload.get("request_digest", ""))
        receipt = self.service.state.load_receipt(frame.session_id, call_id)
        if receipt is None:
            raise ProtocolError("TARGETD_PROCESS_CALL_NOT_FOUND")
        if request_digest != receipt.request_digest:
            raise ProtocolError("TARGETD_PROCESS_CONTROL_CALL_IDENTITY_MISMATCH")
        supplied_auth = frame.payload.get("control_auth")
        expected_auth = process_control_auth_tag(
            self._session.resume_token,
            kind=intent,
            session_id=frame.session_id,
            call_id=call_id,
            request_digest=request_digest,
            sequence=frame.sequence,
        )
        if not isinstance(supplied_auth, str) or not hmac.compare_digest(
            supplied_auth,
            expected_auth,
        ):
            raise ProtocolError("TARGETD_PROCESS_CONTROL_AUTHENTICATION_FAILED")
        call_key = self._call_key_from_receipt(receipt)
        existing = runtime.store.load(call_key)
        if (
            physical
            and existing is not None
            and existing.state
            in {
                "SUCCEEDED",
                "FAILED",
                "STOPPED",
                "CANCELLED",
            }
        ):
            receipt = self.service.revalidate_physical_process_terminal(
                call_key,
                existing,
            )
            return {
                "receipt": receipt.model_dump(mode="json"),
                "interrupt": {
                    "intent": intent,
                    "status": "ALREADY_TERMINAL",
                    "requested": False,
                    "acknowledged": True,
                    "lease_state": existing.state,
                },
            }
        interrupted = runtime.request_interrupt(call_key, intent=intent)
        if physical:
            receipt = self.service.state.load_receipt(frame.session_id, call_id)
            if receipt is None:
                raise ProtocolError("TARGETD_PROCESS_CALL_NOT_FOUND")
        else:
            snapshot = runtime.reconcile_snapshot(call_key)
            receipt = self._commit_process_snapshot(call_key, snapshot)
        return {
            "receipt": receipt.model_dump(mode="json"),
            "interrupt": {
                "intent": intent,
                "requested": interrupted.requested,
                "acknowledged": interrupted.acknowledged,
                "lease_state": interrupted.lease.state,
            },
        }

    def _dispatch_process_query(self, frame: ProtocolFrame) -> dict:
        runtime = self.process_runtime
        if runtime is None:
            raise ProtocolError("TARGETD_PROCESS_WORKER_REQUIRED")
        call_id = str(frame.payload.get("call_id", ""))
        receipt = self.service.state.load_receipt(frame.session_id, call_id)
        if receipt is None:
            return {"receipt": None}
        call_key = self._call_key_from_receipt(receipt)
        snapshot = runtime.reconcile_snapshot(call_key)
        receipt = self._commit_process_snapshot(call_key, snapshot)
        return {"receipt": receipt.model_dump(mode="json")}

    def _dispatch_physical_gate_query(self, frame: ProtocolFrame) -> dict:
        """Authenticate and revalidate a content-addressed gate sidecar."""

        if self._session is None or set(frame.payload) != {
            "call_id",
            "target_id",
            "request_digest",
            "gate_uri",
            "gate_digest_uri",
            "query_gate_auth",
        }:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_QUERY_IDENTITY_INVALID")
        call_id = frame.payload.get("call_id")
        target_id = frame.payload.get("target_id")
        request_digest = frame.payload.get("request_digest")
        gate_uri = frame.payload.get("gate_uri")
        gate_digest_uri = frame.payload.get("gate_digest_uri")
        supplied_auth = frame.payload.get("query_gate_auth")
        if (
            not isinstance(call_id, str)
            or not isinstance(target_id, str)
            or not isinstance(request_digest, str)
            or (gate_uri is not None and not isinstance(gate_uri, str))
            or (gate_digest_uri is not None and not isinstance(gate_digest_uri, str))
            or not isinstance(supplied_auth, str)
            or target_id != self.service.target_id
        ):
            raise ProtocolError("TARGETD_PHYSICAL_GATE_QUERY_IDENTITY_INVALID")
        expected_auth = physical_gate_query_auth_tag(
            self._session.resume_token,
            target_id=target_id,
            session_id=frame.session_id,
            call_id=call_id,
            request_digest=request_digest,
            gate_uri=gate_uri,
            gate_digest_uri=gate_digest_uri,
            sequence=frame.sequence,
        )
        if not hmac.compare_digest(supplied_auth, expected_auth):
            raise ProtocolError("TARGETD_PHYSICAL_GATE_QUERY_AUTHENTICATION_FAILED")
        call_key = WorkerCallKey(
            target_id=target_id,
            session_id=frame.session_id,
            idempotency_key=call_id,
            request_digest=request_digest,
        )
        # Gate evidence read-back is observational. Generic query_call()
        # performs crash reconciliation and would incorrectly terminalize a
        # live physical worker without first obtaining a STOP acknowledgement.
        receipt = self.service.state.load_receipt(frame.session_id, call_id)
        if receipt is None or receipt.request_digest != request_digest:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_QUERY_CALL_MISMATCH")
        runtime = self.physical_process_runtime
        if runtime is None:
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_WORKER_REQUIRED")
        lease = runtime.store.load(call_key)
        if lease is None or lease.call_key != call_key:
            raise ProtocolError("TARGETD_PHYSICAL_WORKER_LEASE_MISSING")
        refs = receipt.evidence_refs
        provider_pair = self._physical_evidence_pair(
            refs,
            prefix="artifact://targetd/physical-provider-gates/",
        )
        acceptance_pair = self._physical_evidence_pair(
            receipt.artifact_refs,
            prefix="artifact://targetd/debug-physical-acceptances/",
        )
        supplied_pair = (
            (gate_uri, gate_digest_uri)
            if gate_uri is not None and gate_digest_uri is not None
            else None
        )
        available_pairs = {
            pair for pair in (provider_pair, acceptance_pair) if pair is not None
        }
        if supplied_pair is not None and supplied_pair not in available_pairs:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_REFERENCE_MISMATCH")
        accepted = None
        debug_acceptance = None
        if acceptance_pair is not None:
            accepted = self.service.resolve_debug_physical_acceptance(
                call_key,
                expected_uri=(gate_uri if supplied_pair == acceptance_pair else None),
                expected_digest_uri=(
                    gate_digest_uri if supplied_pair == acceptance_pair else None
                ),
            )
            debug_acceptance = {
                "uri": accepted.uri,
                "digest_uri": accepted.digest_uri,
                "sidecar": accepted.sidecar.model_dump(mode="json"),
            }
        if provider_pair is None:
            if (
                lease.armed_zero is None
                or receipt.status
                not in {
                    "ACCEPTED",
                    "STOPPED",
                    "CANCELLED",
                    "UNKNOWN",
                }
            ):
                raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_MISSING")
            if accepted is not None:
                pending = self._pending_physical.get(call_key.digest())
                start_eligible = (
                    pending is not None
                    and pending.preparation.call_key == call_key
                    and self._debug_acceptance_start_eligible(
                        pending,
                        accepted,
                        receipt,
                    )
                )
                payload = self._debug_acceptance_payload(
                    receipt,
                    accepted,
                    start_eligible=start_eligible,
                )
                payload.update(
                    {
                        "physical_preparation": {
                            "armed_zero": lease.armed_zero,
                            "lease_state": lease.state,
                        },
                        "physical_worker_lease": lease.model_dump(mode="json"),
                        "physical_provider_gate": None,
                    }
                )
                return payload
            return {
                "receipt": receipt.model_dump(mode="json"),
                "physical_preparation": {
                    "armed_zero": lease.armed_zero,
                    "lease_state": lease.state,
                },
                "physical_worker_lease": lease.model_dump(mode="json"),
                "debug_acceptance": None,
                "physical_provider_gate": None,
            }
        reference = self.service.resolve_physical_provider_gate(
            call_key,
            expected_uri=(gate_uri if supplied_pair == provider_pair else None),
            expected_digest_uri=(
                gate_digest_uri if supplied_pair == provider_pair else None
            ),
        )
        return {
            "receipt": receipt.model_dump(mode="json"),
            "physical_worker_lease": lease.model_dump(mode="json"),
            "debug_acceptance": debug_acceptance,
            "physical_provider_gate": {
                "uri": reference.uri,
                "digest_uri": reference.digest_uri,
                "sidecar": reference.sidecar.model_dump(mode="json"),
            },
        }

    @staticmethod
    def _physical_evidence_pair(
        refs: list[str],
        *,
        prefix: str,
    ) -> tuple[str, str] | None:
        artifacts = [ref for ref in refs if ref.startswith(prefix)]
        if not artifacts:
            return None
        if len(artifacts) != 1:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_REFERENCE_MISMATCH")
        digest_hex = artifacts[0].rsplit("/", 1)[-1]
        digest_uri = f"digest://sha256/{digest_hex}"
        if refs.count(digest_uri) != 1:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_REFERENCE_MISMATCH")
        return artifacts[0], digest_uri

    def _commit_process_snapshot(
        self,
        call_key: WorkerCallKey,
        snapshot: ProcessWorkerSnapshot,
    ):
        runtime = self.process_runtime
        if runtime is None:
            raise ProtocolError("TARGETD_PROCESS_WORKER_REQUIRED")
        receipt = self.service.commit_process_result(call_key, snapshot.lease)
        if snapshot.lease.prepared_result_digest is not None and receipt.status == snapshot.lease.state and snapshot.lease.state in {"SUCCEEDED", "FAILED", "STOPPED", "CANCELLED"}:
            runtime.store.commit_prepared_result(
                call_key,
                result_digest=snapshot.lease.prepared_result_digest,
            )
        return receipt

    def _commit_physical_snapshot(
        self,
        call_key: WorkerCallKey,
        snapshot: ProcessWorkerSnapshot,
    ):
        runtime = self.physical_process_runtime
        if runtime is None:
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_WORKER_REQUIRED")
        receipt = self.service.commit_physical_process_result(
            call_key,
            snapshot.lease,
        )
        if snapshot.lease.prepared_result_digest is not None and receipt.status == snapshot.lease.state and snapshot.lease.state in {"SUCCEEDED", "FAILED", "STOPPED", "CANCELLED"}:
            runtime.store.commit_prepared_result(
                call_key,
                result_digest=snapshot.lease.prepared_result_digest,
            )
        if receipt.status not in {"ACCEPTED", "STARTED"}:
            self._pending_physical.pop(call_key.digest(), None)
        return receipt

    def _reconcile_process_receipts(self) -> None:
        runtime = self.process_runtime
        if runtime is None:
            return
        for lease in runtime.store.list_records():
            if lease.call_key.target_id != self.service.target_id:
                continue
            receipt = self.service.state.load_receipt(
                lease.call_key.session_id,
                lease.call_key.idempotency_key,
            )
            if receipt is None:
                continue
            snapshot = runtime.reconcile_snapshot(lease.call_key)
            self._commit_process_snapshot(lease.call_key, snapshot)

    def _reconcile_physical_process_receipts(self) -> None:
        runtime = self.physical_process_runtime
        if runtime is None:
            return
        for lease in runtime.store.list_records():
            if lease.call_key.target_id != self.service.target_id:
                continue
            receipt = self.service.state.load_receipt(
                lease.call_key.session_id,
                lease.call_key.idempotency_key,
            )
            if receipt is None or not self.service._is_physical_process_receipt(receipt):
                continue
            snapshot = runtime.reconcile_snapshot(lease.call_key)
            self._commit_physical_snapshot(lease.call_key, snapshot)

    @staticmethod
    def _call_key_from_receipt(receipt) -> WorkerCallKey:
        return WorkerCallKey(
            target_id=receipt.target_id,
            session_id=receipt.session_id,
            idempotency_key=receipt.idempotency_key,
            request_digest=receipt.request_digest,
        )

    @staticmethod
    def _terminal_status(manifest: ExecutionBundleManifest, result: object) -> str:
        """Map a worker result to the persisted receipt without false success.

        Generic EXECUTE bundles may legitimately return an application object
        without a ``status`` field.  Rotation is different: it is a physical
        write and may be marked ``SUCCEEDED`` only when the runtime supplied
        stop and independent-motion evidence.  The raw result remains in the
        receipt for diagnosis/replay.
        """

        if manifest.tool_id in MAPPING_TOOL_OPERATIONS:
            # Mapping is a target-side physical/debug operation too.  Unlike a
            # generic EXECUTE bundle, a missing status must never be promoted
            # to success; the provider contract is deliberately terminal and
            # fail-closed.
            if not isinstance(result, dict) or "status" not in result:
                return "UNKNOWN"
            status = str(result.get("status", "UNKNOWN")).upper()
            if status in {"SUCCEEDED", "SUCCESS", "PASS", "PASSED"}:
                return "SUCCEEDED"
            if status in {"CANCELLED", "STOPPED", "FAILED", "UNKNOWN", "NOT_ACCEPTED"}:
                return status
            if status == "BLOCKED":
                return "FAILED"
            # RUNNING (or any future non-terminal status) cannot be persisted
            # as a TargetdCallReceipt terminal value.
            return "UNKNOWN"
        if manifest.tool_id != "app.base.rotate":
            # Generic bundles may return an application object with no
            # ``status`` member; that remains a successful invocation for
            # backwards compatibility.  When a bundle does declare a status,
            # however, never erase an explicit failure/block/unknown result by
            # unconditionally marking the receipt ``SUCCEEDED``.
            if not isinstance(result, dict) or "status" not in result:
                return "SUCCEEDED"
            status = str(result.get("status", "UNKNOWN")).upper()
            if status in {"SUCCEEDED", "SUCCESS", "PASS", "PASSED"}:
                return "SUCCEEDED"
            if status in {"CANCELLED", "STOPPED", "FAILED", "UNKNOWN", "NOT_ACCEPTED"}:
                return status
            if status == "BLOCKED":
                return "FAILED"
            return "UNKNOWN"
        if not isinstance(result, dict):
            return "UNKNOWN"
        status = str(result.get("status", "UNKNOWN")).upper()
        if status == "SUCCEEDED":
            if result.get("stop_published") is True and result.get("physical_stop_verified") is True and result.get("stopped_observed") is True and has_verified_rotation_evidence(result):
                return "SUCCEEDED"
            return "UNKNOWN"
        if status in {"CANCELLED", "STOPPED", "FAILED", "UNKNOWN", "NOT_ACCEPTED"}:
            return status
        if status == "BLOCKED":
            return "FAILED"
        return "UNKNOWN"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    signing_key_group = parser.add_mutually_exclusive_group(required=True)
    signing_key_group.add_argument("--signing-key")
    signing_key_group.add_argument("--signing-key-file", type=Path)
    parser.add_argument("--execute-calls", action="store_true")
    parser.add_argument("--admission-store", type=Path)
    parser.add_argument("--execution-authority-root", type=Path)
    parser.add_argument("--release-catalog-root", type=Path)
    parser.add_argument("--dsl-cache-dir", type=Path)
    parser.add_argument("--ros2-snapshot", type=Path)
    parser.add_argument("--execute-readonly", action="store_true")
    parser.add_argument("--process-readonly-worker", action="store_true")
    parser.add_argument(
        "--provider",
        choices=("none", "ros-container", _ROS2_READONLY_PROVIDER_ID),
        default="none",
    )
    parser.add_argument("--container", default="MentorPi")
    parser.add_argument("--autonomous-source-confirmed", action="store_true")
    args = parser.parse_args()
    try:
        signing_key = (
            _read_signing_key_file(args.signing_key_file)
            if args.signing_key_file is not None
            else args.signing_key.encode("utf-8")
        )
    except (AttributeError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))
    if args.execute_calls and (args.admission_store is None or args.execution_authority_root is None):
        parser.error("--execute-calls requires --admission-store and --execution-authority-root")
    if args.execute_readonly and args.ros2_snapshot is None:
        parser.error("--execute-readonly requires --ros2-snapshot")
    if args.provider == _ROS2_READONLY_PROVIDER_ID and (not args.execute_calls or not args.execute_readonly or args.ros2_snapshot is None):
        parser.error("--provider ros2-readonly requires --execute-calls, --execute-readonly, and --ros2-snapshot")
    if args.process_readonly_worker and args.provider != _ROS2_READONLY_PROVIDER_ID:
        parser.error("--process-readonly-worker requires --provider ros2-readonly")
    confirmation_store = MappingConfirmationStore(args.admission_store) if args.admission_store is not None else None
    service = TargetdService(
        target_id=args.target_id,
        state_root=args.state_root,
        signing_key=signing_key,
        confirmation_store=confirmation_store,
        execution_authority_store=(TargetdExecutionAuthorityStore(args.execution_authority_root) if args.execution_authority_root is not None else None),
        release_catalog=(TargetdReleaseCatalog(args.release_catalog_root) if args.release_catalog_root is not None else None),
    )
    try:
        runtime_resolver, runtime_registry = load_ros2_dsl_runtime(
            args.ros2_snapshot,
            execute_readonly=args.execute_readonly,
        )
        provider: Provider | None
        if args.provider == "ros-container":
            provider = RosContainerProvider(
                args.container,
                autonomous_source_confirmed=args.autonomous_source_confirmed,
            )
        elif args.provider == _ROS2_READONLY_PROVIDER_ID:
            if runtime_registry is None:
                raise ProtocolError("ROS2_READ_ONLY_RUNTIME_REQUIRED")
            provider = Ros2ReadOnlyProvider(runtime_registry)
        else:
            provider = None
        process_runtime = None
        process_work = None
        process_live_fence = None
        if args.process_readonly_worker:
            if runtime_resolver is None:
                raise ProtocolError("ROS2_READ_ONLY_RUNTIME_REQUIRED")
            process_runtime = LeasedProcessWorkerRuntime(
                WorkerLeaseStore(args.state_root / "process-worker"),
                supervisor_id=f"targetd-{args.target_id}",
                allow_spawn_readonly_substrate=True,
            )
            process_work = Ros2OdomProcessWorker(runtime_resolver.snapshot)
            process_live_fence = Ros2OdomLiveFence(runtime_resolver.snapshot)
        dsl_service = (
            TargetdDslService(
                args.dsl_cache_dir or args.state_root / "dsl-cache",
                runtime_resolver=runtime_resolver,
                backend_registry=runtime_registry,
                confirmation_store=confirmation_store,
            )
            if confirmation_store is not None
            else None
        )
        TargetdDaemon(
            service,
            execute_calls=args.execute_calls,
            provider=provider,
            provider_id=(args.provider if provider is not None else None),
            dsl_service=dsl_service,
            process_runtime=process_runtime,
            process_work=process_work,
            process_live_fence=process_live_fence,
        ).serve(sys.stdin.buffer, sys.stdout.buffer)
    except ProtocolError as exc:
        print(f"targetd protocol error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
