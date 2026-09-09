from __future__ import annotations

import hashlib
import io
import json
import math
import queue
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from rolo.targetd.lifecycle import WorkerCallKey
from rolo.targetd.motion_acceptance import compute_armed_zero_provider_identity_digest
from rolo.targetd.physical_worker import (
    _CONTAINER_BOOTSTRAP,
    _PRESTART_GUARD_LIBRARY,
    _PRESTART_TRANSIENT_GRACE_S,
    _REGISTRY_CONTROL,
    _TARGET_REGISTRY_LIBRARY,
    LanderPiRotateProcessWorker,
    PhysicalWorkerAmbiguity,
    PhysicalWorkerConfigurationError,
    _auth_tag,
    _registry_binding_digest,
    cleanup_terminal_registry,
    landerpi_bounded_twist_runtime_sha256,
    parse_physical_worker_armed_zero,
    read_target_physical_worker_registry,
    read_target_physical_worker_terminal_registry,
    recover_persisted_armed_zero,
)
from rolo.targetd.protocol import ExecutionBundleManifest
from tests.test_targetd_protocol import (
    _execution_request,
    _execution_session,
    _execution_setup,
)

ROTATE_SOURCE = b"def execute(arguments, provider):\n    return provider.invoke('base.rotate', arguments)\n"
ROTATE_CONTRACT = {
    "provider": "ros-container",
    "operation": "base.rotate",
    "command_endpoint": "/cmd_vel",
    "feedback_endpoints": ["/odom_raw", "/odom"],
    "independent_feedback_endpoints": [
        "/imu",
        "/imu_corrected",
        "/ros_robot_controller/imu_raw",
    ],
    "interface_type": "geometry_msgs/msg/Twist",
    "stop_strategy": "zero_velocity",
    "provider_runtime_sha256": landerpi_bounded_twist_runtime_sha256(),
}
INNER_IDENTITY = {
    "schema_version": "rolo-targetd-inner-process-identity/v1",
    "pid": 8721,
    "start_ticks": 443322,
    "cmdline_sha256": "d" * 64,
}


def _call(
    tmp_path,
    *,
    contract=None,
    arguments=None,
    deadline=None,
    force_v2=False,
    tool_id="app.base.rotate",
):
    manifest = ExecutionBundleManifest.build(
        tool_id=tool_id,
        source=ROTATE_SOURCE,
        binding_digest="a" * 64,
        signer_key_id="physical-worker-test",
        signing_key=b"secret",
        observation_contract=(ROTATE_CONTRACT if contract is None else contract),
        limits={"max_duration_s": 60, "max_output_bytes": 65_536},
    )
    service, authority, _, _ = _execution_setup(
        tmp_path,
        manifest,
        ROTATE_SOURCE,
        provider_id="ros-container",
        provider_operation="base.rotate",
        journey_session_id="physical-worker-session",
    )
    session = _execution_session(service, authority, "physical-worker-session")
    request = _execution_request(
        authority,
        session,
        arguments=({"angle_degrees": 1.0, "max_speed_rad_s": 0.03} if arguments is None else arguments),
        deadline=(deadline or datetime.now(timezone.utc) + timedelta(seconds=30)),
        force_v2=force_v2,
    )
    return request, manifest


@dataclass
class _Lease:
    call_key_digest: str
    deadline_at: datetime
    state: str = "RUNNING"


class _Control:
    def __init__(self, request, *, intents=(), aborted=False):
        self.call_key = WorkerCallKey.from_request(request)
        self._lease = _Lease(self.call_key.digest(), request.deadline)
        self._intents = iter(intents)
        self._last_intent = None
        self._aborted = aborted

    def heartbeat(self):
        return self._lease

    def interrupt_intent(self):
        try:
            observed = next(self._intents)
        except StopIteration:
            observed = self._last_intent
        if observed is not None:
            self._last_intent = observed
        return observed

    def aborted(self):
        return self._aborted


class _InteractiveOutput:
    def __init__(self):
        self._lines: queue.Queue[bytes | None] = queue.Queue()

    def push(self, value: dict):
        self._lines.put(json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n")

    def push_raw(self, value: bytes):
        self._lines.put(value)

    def close(self):
        self._lines.put(None)

    def readline(self, _size=-1):
        try:
            value = self._lines.get(timeout=2)
        except queue.Empty:
            return b""
        return b"" if value is None else value


class _InteractiveInput:
    def __init__(self, process):
        self.process = process
        self.pending = bytearray()
        self.closed = False

    def write(self, value):
        payload = bytes(value)
        self.pending.extend(payload)
        while b"\n" in self.pending:
            line, _, rest = self.pending.partition(b"\n")
            self.pending = bytearray(rest)
            decoded = json.loads(line)
            self.process.receive_input(decoded)
            if decoded.get("intent") == "START" and self.process.fail_after_start_delivery:
                self.process.fail_after_start_delivery = False
                raise OSError("simulated failure after complete START delivery")
        return len(payload)

    def flush(self):
        return None

    def close(self):
        self.closed = True


class _InteractiveProcess:
    def __init__(
        self,
        result,
        *,
        auto_result_on_start=True,
        arm_updates=None,
        post_auth_arm_updates=None,
        tamper_arm_auth=False,
        response_lost=False,
        returncode=0,
        fail_after_start_delivery=False,
        inner_reap_succeeds=True,
        prepare_error=None,
    ):
        self.stdin = _InteractiveInput(self)
        self.stdout = _InteractiveOutput()
        self.stderr = io.BytesIO(b"")
        self.pid = 4312
        self.returncode = None
        self.final_returncode = returncode
        self.result = result
        self.auto_result_on_start = auto_result_on_start
        self.arm_updates = arm_updates or {}
        self.post_auth_arm_updates = post_auth_arm_updates or {}
        self.tamper_arm_auth = tamper_arm_auth
        self.response_lost = response_lost
        self.fail_after_start_delivery = fail_after_start_delivery
        self.inner_reap_succeeds = inner_reap_succeeds
        self.prepare_error = prepare_error
        self.controls = []
        self.terminated = False
        self.killed = False
        self._done = threading.Event()
        self.bootstrap = None
        self.arm_receipt = None
        self.registry_record = None
        self.terminal_record = None

    def receive_input(self, value):
        if value.get("kind") == "BOOTSTRAP":
            self.bootstrap = value
            if self.prepare_error is not None:
                unsigned = {
                    "schema_version": "rolo-targetd-physical-worker-prepare-error/v1",
                    "kind": "PREPARE_ERROR",
                    "call_key_digest": value["call_key_digest"],
                    "target_id": value["target_id"],
                    "call_id": value["call_id"],
                    "session_id": value["session_id"],
                    "request_digest": value["request_digest"],
                    "error": self.prepare_error,
                }
                self.stdout.push(
                    {
                        **unsigned,
                        "auth_tag": _auth_tag(unsigned, value["control_key"]),
                    }
                )
                self.finish()
                return
            provider_runtime = "sha256:" + value["runtime_sha256"]
            provider_cmdline = "sha256:" + INNER_IDENTITY["cmdline_sha256"]
            publisher_gid = "ab" * 16
            provider_identity_digest = compute_armed_zero_provider_identity_digest(
                call_id=value["call_id"],
                session_id=value["session_id"],
                execution_subject_digest=value["execution_subject_digest"],
                publisher_identity="/rolo_bounded_twist",
                publisher_gid=publisher_gid,
                provider_pid=INNER_IDENTITY["pid"],
                provider_start_time_ticks=INNER_IDENTITY["start_ticks"],
                provider_runtime_sha256=provider_runtime,
                provider_cmdline_sha256=provider_cmdline,
            )
            issued_at = time.time()
            expires_at = min(value["request_deadline_epoch_s"], issued_at + 60.0)
            binding_digest = _registry_binding_digest(
                target_id=value["target_id"],
                call_key_digest=value["call_key_digest"],
                call_id=value["call_id"],
                session_id=value["session_id"],
                execution_subject_digest=value["execution_subject_digest"],
                publisher_identity="/rolo_bounded_twist",
                publisher_gid=publisher_gid,
                provider_pid=INNER_IDENTITY["pid"],
                provider_start_time_ticks=INNER_IDENTITY["start_ticks"],
                provider_runtime_sha256=provider_runtime,
                provider_cmdline_sha256=provider_cmdline,
                issued_at_epoch_s=issued_at,
                expires_at_epoch_s=expires_at,
            )
            arm_fields = {
                "target_id": value["target_id"],
                "schema_version": "rolo-targetd-physical-worker-armed-zero/v1",
                "kind": "ARMED_ZERO",
                "call_key_digest": value["call_key_digest"],
                "call_id": value["call_id"],
                "session_id": value["session_id"],
                "request_digest": value["request_digest"],
                "execution_subject_digest": value["execution_subject_digest"],
                "runtime_sha256": value["runtime_sha256"],
                "command_endpoint": "/cmd_vel",
                "publisher_identity": "/rolo_bounded_twist",
                "publisher_endpoint_gids": [publisher_gid],
                "competing_publisher_count": 0,
                "direct_motor_publisher_identities": ["/odom_publisher"],
                "zeros_published": 5,
                "independent_stationary_sources": ["/imu"],
                "independent_stationary_sample_counts": {"/imu": 3},
                "independent_stationary_last_sample_age_s": {"/imu": 0.01},
                "independent_stationary_max_abs_rad_s": {"/imu": 0.001},
                "independent_stationary_window_s": 0.2,
                "motion_command_emitted": False,
                "motion_enabled": False,
                "inner_process_identity": INNER_IDENTITY,
                "target_monotonic_s": 123.5,
                "provider_runtime_sha256": provider_runtime,
                "provider_cmdline_sha256": provider_cmdline,
                "provider_runtime_identity_digest": provider_identity_digest,
                "registry_issued_at_epoch_s": issued_at,
                "registry_expires_at_epoch_s": expires_at,
                "registry_binding_digest": binding_digest,
                **self.arm_updates,
            }
            receipt = {
                **{key: item for key, item in arm_fields.items() if key not in {"schema_version", "kind"}},
                "schema_version": "rolo-targetd-physical-worker-arm-receipt/v1",
                "publisher_endpoint_count": len(arm_fields["publisher_endpoint_gids"]),
            }
            receipt["arm_receipt_digest"] = hashlib.sha256(
                json.dumps(
                    receipt,
                    allow_nan=False,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
            ).hexdigest()
            self.arm_receipt = receipt
            self.registry_record = {
                "schema_version": "rolo-targetd-physical-worker-registry/v1",
                "state": "ACTIVE",
                "arm_receipt": receipt,
                "updated_at_epoch_s": issued_at,
                "zero_refresh_count": 0,
                "last_zero_at_epoch_s": issued_at,
                "terminal_reason": None,
                "registry_auth_tag": "hmac-sha256:" + "e" * 64,
            }
            unsigned = {
                **arm_fields,
                "arm_receipt_digest": receipt["arm_receipt_digest"],
            }
            unsigned.update(self.post_auth_arm_updates)
            tag = _auth_tag(unsigned, value["control_key"])
            if self.tamper_arm_auth:
                tag = "0" * 64
            self.stdout.push({**unsigned, "auth_tag": tag})
            return
        self.controls.append(value)
        intent = value["intent"]
        if intent == "START" and not self.auto_result_on_start:
            return
        if self.response_lost:
            self.finish()
            return
        self.emit_result(self.result)

    def emit_result(self, result):
        unsigned = {
            "schema_version": "rolo-targetd-physical-worker-result/v1",
            "kind": "RESULT",
            "call_key_digest": self.bootstrap["call_key_digest"],
            "inner_process_identity": INNER_IDENTITY,
            "result": result,
        }
        self.stdout.push(
            {
                **unsigned,
                "auth_tag": _auth_tag(unsigned, self.bootstrap["control_key"]),
            }
        )
        self.finish()

    def finish(self):
        self.returncode = self.final_returncode
        self.stdout.close()
        self._done.set()

    def terminalize_registry(self, reason):
        if self.registry_record is None:
            return
        point = time.time()
        self.terminal_record = {
            **self.registry_record,
            "state": "TERMINAL",
            "updated_at_epoch_s": point,
            "terminal_reason": reason,
        }
        self.registry_record = None

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if not self._done.wait(timeout):
            raise TimeoutError
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.finish()

    def kill(self):
        self.killed = True
        self.returncode = -9
        self.stdout.close()
        self._done.set()


def _verified_result(*, status="SUCCEEDED", **updates):
    goal = math.radians(1.0)
    gyro = goal - 0.001
    result = {
        "status": status,
        "motion_started": True,
        "stop_published": True,
        "physical_stop_verified": True,
        "stopped_observed": True,
        "command_stopped": True,
        "control_graph_isolated": True,
        "independent_motion_evidence": {
            "status": "VERIFIED",
            "independent_of_odom": True,
            "settled": True,
            "gyro_delta_rad": gyro,
            "angle_accuracy_status": "VERIFIED",
            "target_angle_error_rad": abs(abs(gyro) - goal),
            "target_angle_tolerance_rad": max(goal * 0.25, 0.005),
        },
        "angle_accuracy_verified": True,
    }
    result.update(updates)
    return result


def _safe_stop_result(*, motion_started=True):
    result = _verified_result(
        status="UNKNOWN",
        angle_accuracy_verified=False,
        motion_started=motion_started,
        motion_command_emitted=motion_started,
    )
    result["independent_motion_evidence"] = {
        "status": "NOT_VERIFIED",
        "independent_of_odom": True,
        "settled": True,
        "gyro_delta_rad": None,
        "angle_accuracy_status": "NOT_VERIFIED",
        "target_angle_error_rad": None,
        "target_angle_tolerance_rad": 0.005,
    }
    return result


def _install_process(monkeypatch, result, **options):
    process = _InteractiveProcess(result, **options)
    observed = {}

    def spawn(argv, **kwargs):
        observed["argv"] = argv
        observed["kwargs"] = kwargs
        return process

    def inner_control(argv, **kwargs):
        observed.setdefault("inner_commands", []).append((argv, kwargs))
        if len(argv) == 9 and "registry_read_active" in argv[8]:
            output = (
                b"ABSENT\n"
                if process.registry_record is None
                else json.dumps(
                    process.registry_record,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                + b"\n"
            )
            return SimpleNamespace(returncode=0, stdout=output, stderr=b"")
        if len(argv) == 10 and "registry_read_terminal" in argv[8]:
            output = (
                b"ABSENT\n"
                if process.terminal_record is None
                else json.dumps(
                    process.terminal_record,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                + b"\n"
            )
            return SimpleNamespace(returncode=0, stdout=output, stderr=b"")
        if len(argv) > 9 and argv[9] in {"terminal", "cleanup", "quarantine"}:
            if argv[9] in {"terminal", "quarantine"}:
                reason = argv[14] if argv[9] == "terminal" else "AMBIGUOUS_REAP"
                process.terminalize_registry(reason)
            elif argv[9] == "cleanup":
                process.terminal_record = None
            return SimpleNamespace(returncode=0, stdout=b"true\n", stderr=b"")
        if argv[-4] == "reap" and not process.inner_reap_succeeds:
            return SimpleNamespace(returncode=4, stdout=b"LIVE\n", stderr=b"")
        return SimpleNamespace(returncode=0, stdout=b"GONE\n", stderr=b"")

    monkeypatch.setattr("rolo.targetd.physical_worker.subprocess.Popen", spawn)
    monkeypatch.setattr("rolo.targetd.physical_worker.subprocess.run", inner_control)
    return process, observed


def _registry_expectations(worker):
    return {
        "expected_call_key_digest": worker.expected_call_key_digest,
        "expected_target_id": worker.target_id,
        "expected_call_id": worker.call_id,
        "expected_session_id": worker.session_id,
        "expected_request_digest": worker.request_digest,
        "expected_execution_subject_digest": worker.execution_subject_digest,
        "expected_runtime_sha256": worker.runtime_sha256,
    }


def test_generic_one_stage_entrypoint_is_deny_only(tmp_path):
    request, manifest = _call(tmp_path)
    worker = LanderPiRotateProcessWorker(request, manifest)
    with pytest.raises(
        PhysicalWorkerConfigurationError,
        match="PHYSICAL_WORKER_TWO_PHASE_RUNTIME_REQUIRED",
    ):
        worker(_Control(request))


def test_physical_worker_loads_fixed_landerpi_ros_environment() -> None:
    assert "export HOME=/home/ubuntu" in _CONTAINER_BOOTSTRAP
    assert ". /opt/ros/humble/setup.bash" in _CONTAINER_BOOTSTRAP
    assert ". /home/ubuntu/ros2_ws/install/setup.bash" in _CONTAINER_BOOTSTRAP
    assert ". /home/ubuntu/ros2_ws/.robotrc >/dev/null" in _CONTAINER_BOOTSTRAP
    assert _CONTAINER_BOOTSTRAP.index(".robotrc") < _CONTAINER_BOOTSTRAP.index(
        "exec timeout"
    )


def test_inner_runtime_binds_sealed_request_to_three_argument_start_gate(
    tmp_path,
) -> None:
    request, manifest = _call(tmp_path)
    worker = LanderPiRotateProcessWorker(request, manifest)
    program = worker._instrumented_program(
        "def run_ros_entrypoint(request, *, start_gate, result_sink):\n"
        "    return start_gate(None, None, None)\n"
    )

    compile(program, "<instrumented-physical-worker>", "exec")
    assert "start_gate=lambda io, node, publisher: _rolo_prearm(" in program
    assert "publisher,\n            request," in program
    assert "ARM_ZERO_COUNT = zeros; io.spin(0.02)" in program


def _prestart_guard_functions():
    namespace = {}
    exec(compile(_PRESTART_GUARD_LIBRARY, "<prestart-guard>", "exec"), namespace)
    return (
        namespace["classify_prestart_guard_observation"],
        namespace["update_prestart_transient_guard"],
    )


def _healthy_prestart_observation(**updates):
    values = {
        "controlled_names": ["/rolo_bounded_twist"],
        "controlled_gids": ["ab" * 16],
        "expected_controlled_gids": ["ab" * 16],
        "competing_count": 0,
        "direct_names": ["/odom_publisher"],
        "subscription_count": 1,
        "stationary_sources": ["/ros_robot_controller/imu_raw"],
        "expected_stationary_sources": ["/ros_robot_controller/imu_raw"],
        "fresh_zero": True,
    }
    values.update(updates)
    return values


def test_prestart_guard_accepts_allowed_stationary_source_superset() -> None:
    classify, _ = _prestart_guard_functions()

    assert classify(
        **_healthy_prestart_observation(
            stationary_sources=["/imu", "/ros_robot_controller/imu_raw"]
        )
    ) == ("HEALTHY", None)


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        ({"controlled_names": ["/impostor"]}, "UNEXPECTED_CONTROL_PUBLISHER_TOPOLOGY"),
        (
            {
                "controlled_names": ["/rolo_bounded_twist", "/rolo_bounded_twist"],
                "controlled_gids": ["ab" * 16, "cd" * 16],
            },
            "UNEXPECTED_CONTROL_PUBLISHER_TOPOLOGY",
        ),
        ({"controlled_gids": ["cd" * 16]}, "OWN_PUBLISHER_GID_CHANGED"),
        ({"competing_count": 1}, "UNEXPECTED_COMPETING_COMMAND_PUBLISHER"),
        (
            {"direct_names": ["/odom_publisher", "/hand_gesture"]},
            "UNEXPECTED_DIRECT_MOTOR_TOPOLOGY",
        ),
    ],
)
def test_prestart_guard_rejects_unsafe_topology_immediately(updates, reason) -> None:
    classify, _ = _prestart_guard_functions()

    assert classify(**_healthy_prestart_observation(**updates)) == ("DANGER", reason)


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        (
            {"controlled_names": [], "controlled_gids": []},
            "OWN_PUBLISHER_UNDISCOVERED",
        ),
        ({"controlled_gids": [None]}, "OWN_PUBLISHER_GID_UNDISCOVERED"),
        ({"subscription_count": 0}, "OWN_SUBSCRIBER_UNDISCOVERED"),
        ({"direct_names": []}, "DIRECT_MOTOR_PUBLISHER_UNDISCOVERED"),
        ({"stationary_sources": None}, "IMU_STATIONARY_EVIDENCE_UNAVAILABLE"),
        ({"stationary_sources": ["/imu"]}, "ARMED_IMU_SOURCE_UNAVAILABLE"),
        ({"fresh_zero": False}, "ZERO_FEEDBACK_UNAVAILABLE"),
    ],
)
def test_prestart_guard_classifies_safe_discovery_gaps_as_transient(
    updates, reason
) -> None:
    classify, _ = _prestart_guard_functions()

    assert classify(**_healthy_prestart_observation(**updates)) == (
        "TRANSIENT",
        reason,
    )


def test_prestart_transient_grace_is_continuous_and_resets_only_when_healthy() -> None:
    _, update = _prestart_guard_functions()
    started, reason, expired = update(
        None, "OWN_PUBLISHER_UNDISCOVERED", 10.0, _PRESTART_TRANSIENT_GRACE_S
    )
    assert (started, reason, expired) == (
        10.0,
        "OWN_PUBLISHER_UNDISCOVERED",
        False,
    )

    # Switching between safe transient gaps cannot restart the grace clock.
    started, reason, expired = update(
        started,
        "IMU_STATIONARY_EVIDENCE_UNAVAILABLE",
        10.9,
        _PRESTART_TRANSIENT_GRACE_S,
    )
    assert (started, reason, expired) == (
        10.0,
        "IMU_STATIONARY_EVIDENCE_UNAVAILABLE",
        False,
    )
    assert update(
        started,
        "ZERO_FEEDBACK_UNAVAILABLE",
        10.0 + _PRESTART_TRANSIENT_GRACE_S,
        _PRESTART_TRANSIENT_GRACE_S,
    ) == (10.0, "ZERO_FEEDBACK_UNAVAILABLE", True)

    assert update(started, None, 12.0, _PRESTART_TRANSIENT_GRACE_S) == (
        None,
        None,
        False,
    )
    assert update(
        None, "OWN_SUBSCRIBER_UNDISCOVERED", 12.1, _PRESTART_TRANSIENT_GRACE_S
    ) == (12.1, "OWN_SUBSCRIBER_UNDISCOVERED", False)


def test_prepare_surfaces_authenticated_inner_error_code(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    worker = LanderPiRotateProcessWorker(request, manifest)
    _install_process(
        monkeypatch,
        _verified_result(),
        prepare_error="PHYSICAL_WORKER_ARMED_ZERO_TOPOLOGY_UNAVAILABLE",
    )

    with pytest.raises(
        PhysicalWorkerConfigurationError,
        match="PHYSICAL_WORKER_ARMED_ZERO_TOPOLOGY_UNAVAILABLE",
    ):
        worker.prepare(_Control(request, intents=(None,)))


def test_prepare_returns_authenticated_typed_armed_zero_receipt(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    worker = LanderPiRotateProcessWorker(request, manifest)
    process, observed = _install_process(monkeypatch, _verified_result())

    prepared = worker.prepare(_Control(request, intents=(None,)))
    receipt = prepared.arm_receipt()

    assert receipt["publisher_identity"] == "/rolo_bounded_twist"
    assert receipt["publisher_endpoint_count"] == 1
    assert receipt["publisher_endpoint_gids"] == ["ab" * 16]
    assert receipt["motion_command_emitted"] is False
    assert receipt["motion_enabled"] is False
    assert receipt["zeros_published"] >= 5
    assert receipt["inner_process_identity"] == INNER_IDENTITY
    assert receipt["provider_runtime_sha256"] == f"sha256:{worker.runtime_sha256}"
    assert receipt["provider_cmdline_sha256"] == f"sha256:{'d' * 64}"
    assert prepared.armed_zero.provider_binding().provider_runtime_identity_digest == receipt["provider_runtime_identity_digest"]
    assert len(receipt["arm_receipt_digest"]) == 64
    assert observed["kwargs"]["shell"] is False
    assert observed["argv"][:10] == [
        "docker",
        "exec",
        "-i",
        "-u",
        "ubuntu",
        "MentorPi",
        "bash",
        "--noprofile",
        "--norc",
        "-c",
    ]
    assert "/cmd_vel" not in observed["argv"][10]
    assert process.bootstrap["control_key"] not in observed["argv"][-1]


def test_public_arm_parser_recomputes_digest_and_binds_expected_identity(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    worker = LanderPiRotateProcessWorker(request, manifest)
    _install_process(monkeypatch, _verified_result())
    prepared = worker.prepare(_Control(request, intents=(None,)))

    parsed = parse_physical_worker_armed_zero(
        prepared.arm_receipt(),
        expected_call_key_digest=worker.expected_call_key_digest,
        expected_request_digest=worker.request_digest,
        expected_execution_subject_digest=worker.execution_subject_digest,
        expected_runtime_sha256=worker.runtime_sha256,
    )

    assert parsed == prepared.armed_zero
    tampered = prepared.arm_receipt()
    tampered["zeros_published"] = 6
    with pytest.raises(
        PhysicalWorkerAmbiguity,
        match="PHYSICAL_WORKER_ARM_RECEIPT_DIGEST_MISMATCH",
    ):
        parse_physical_worker_armed_zero(
            tampered,
            expected_call_key_digest=worker.expected_call_key_digest,
            expected_request_digest=worker.request_digest,
            expected_execution_subject_digest=worker.execution_subject_digest,
            expected_runtime_sha256=worker.runtime_sha256,
        )


def test_target_registry_reader_returns_only_fresh_exact_typed_record(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    worker = LanderPiRotateProcessWorker(request, manifest)
    process, _ = _install_process(monkeypatch, _verified_result())
    prepared = worker.prepare(_Control(request, intents=(None,)))
    now = time.time()
    process.registry_record.update(
        updated_at_epoch_s=now,
        last_zero_at_epoch_s=now,
        zero_refresh_count=3,
    )

    record = read_target_physical_worker_registry(**_registry_expectations(worker))

    assert record is not None
    assert record.state == "ACTIVE"
    assert record.armed_zero == prepared.armed_zero
    assert record.zero_refresh_count == 3

    process.registry_record["last_zero_at_epoch_s"] = now - 1.0
    with pytest.raises(PhysicalWorkerAmbiguity, match="PHYSICAL_WORKER_REGISTRY_STALE"):
        read_target_physical_worker_registry(**_registry_expectations(worker))


def test_target_registry_reader_rejects_tampered_nested_receipt(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    worker = LanderPiRotateProcessWorker(request, manifest)
    process, _ = _install_process(monkeypatch, _verified_result())
    worker.prepare(_Control(request, intents=(None,)))
    process.registry_record["arm_receipt"] = {
        **process.registry_record["arm_receipt"],
        "zeros_published": 999,
    }

    with pytest.raises(
        PhysicalWorkerAmbiguity,
        match="PHYSICAL_WORKER_ARM_RECEIPT_DIGEST_MISMATCH",
    ):
        read_target_physical_worker_registry(
            **_registry_expectations(worker),
            require_live=False,
        )


def test_arm_rejects_stale_or_unbound_independent_stationary_source(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    process, _ = _install_process(
        monkeypatch,
        _verified_result(),
        arm_updates={
            "independent_stationary_last_sample_age_s": {"/imu": 0.11},
        },
    )
    worker = LanderPiRotateProcessWorker(request, manifest)

    with pytest.raises(
        PhysicalWorkerAmbiguity,
        match="PHYSICAL_WORKER_STATIONARY_EVIDENCE_INVALID",
    ):
        worker.prepare(_Control(request, intents=(None,)))
    assert process.registry_record is None
    assert process.terminal_record is not None


def test_authenticated_but_malformed_arm_exact_reaps_and_quarantines_active_registry(
    tmp_path,
    monkeypatch,
):
    request, manifest = _call(tmp_path)
    process, observed = _install_process(
        monkeypatch,
        _verified_result(),
        post_auth_arm_updates={"arm_receipt_digest": "0" * 64},
    )
    worker = LanderPiRotateProcessWorker(request, manifest)

    with pytest.raises(PhysicalWorkerAmbiguity, match="PHYSICAL_WORKER_ARM_PROOF_INVALID"):
        worker.prepare(_Control(request, intents=(None,)))

    assert process.registry_record is None
    assert process.terminal_record is not None
    modes = [command[9] for command, _ in observed["inner_commands"] if len(command) > 9]
    assert "quarantine" in modes
    assert any(command[-4] == "reap" for command, _ in observed["inner_commands"])


def test_failed_exact_reap_preserves_active_registry_and_never_quarantines(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    process, observed = _install_process(
        monkeypatch,
        _verified_result(),
        response_lost=True,
        inner_reap_succeeds=False,
    )
    worker = LanderPiRotateProcessWorker(request, manifest)
    control = _Control(request, intents=(None, None))
    prepared = worker.prepare(control)

    with pytest.raises(PhysicalWorkerAmbiguity):
        prepared.execute(control)

    assert process.registry_record is not None
    assert not any(len(command) > 9 and command[9] == "quarantine" for command, _ in observed["inner_commands"])


def test_restart_recovery_strictly_parses_then_reaps_exact_persisted_identity(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    worker = LanderPiRotateProcessWorker(request, manifest)
    _, observed = _install_process(monkeypatch, _verified_result())
    prepared = worker.prepare(_Control(request, intents=(None,)))

    recovery_kwargs = _registry_expectations(worker)
    assert (
        recover_persisted_armed_zero(
            prepared.arm_receipt(),
            **recovery_kwargs,
        )
        is True
    )
    reaper_argv, reaper_kwargs = next(item for item in observed["inner_commands"] if item[0][-4:] == ["reap", "8721", "443322", "d" * 64])
    assert reaper_argv[-4:] == ["reap", "8721", "443322", "d" * 64]
    assert reaper_kwargs["shell"] is False

    tampered = prepared.arm_receipt()
    tampered["inner_process_identity"] = {**INNER_IDENTITY, "pid": 9999}
    calls_before = len(observed.get("inner_commands", []))
    assert recover_persisted_armed_zero(tampered, **recovery_kwargs) is False
    assert len(observed["inner_commands"]) == calls_before


def test_restart_recovery_accepts_exact_terminal_after_result_ipc_crash(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    worker = LanderPiRotateProcessWorker(request, manifest)
    process, observed = _install_process(monkeypatch, _verified_result())
    prepared = worker.prepare(_Control(request, intents=(None,)))
    process.terminalize_registry("RESULT_UNKNOWN")

    assert recover_persisted_armed_zero(
        prepared.arm_receipt(),
        **_registry_expectations(worker),
    )
    assert any(len(command) == 10 and command[-1] == prepared.armed_zero.arm_receipt_digest and "registry_read_terminal" in command[8] for command, _ in observed["inner_commands"])
    assert observed["inner_commands"][-1][0][-4:] == [
        "reap",
        "8721",
        "443322",
        "d" * 64,
    ]


def test_restart_recovery_never_trusts_bare_absent_registry(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    worker = LanderPiRotateProcessWorker(request, manifest)
    process, observed = _install_process(monkeypatch, _verified_result())
    prepared = worker.prepare(_Control(request, intents=(None,)))
    process.registry_record = None
    calls_before = len(observed.get("inner_commands", []))

    assert not recover_persisted_armed_zero(
        prepared.arm_receipt(),
        **_registry_expectations(worker),
    )
    new_commands = observed.get("inner_commands", [])[calls_before:]
    assert any(len(command) == 10 and "registry_read_terminal" in command[8] for command, _ in new_commands)
    assert not any(command[-4] == "reap" for command, _ in new_commands)


def test_terminal_registry_read_and_cleanup_are_bound_to_exact_arm(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    worker = LanderPiRotateProcessWorker(request, manifest)
    process, observed = _install_process(monkeypatch, _verified_result())
    prepared = worker.prepare(_Control(request, intents=(None,)))
    process.terminalize_registry("RECOVERED_UNKNOWN")

    terminal = read_target_physical_worker_terminal_registry(
        **_registry_expectations(worker),
        expected_arm_receipt_digest=prepared.armed_zero.arm_receipt_digest,
    )
    assert terminal is not None
    assert terminal.state == "TERMINAL"
    assert terminal.armed_zero == prepared.armed_zero

    calls_before = len(observed["inner_commands"])
    assert not cleanup_terminal_registry(
        prepared.armed_zero,
        expected_call_key_digest=worker.expected_call_key_digest,
        expected_arm_receipt_digest="0" * 64,
    )
    assert len(observed["inner_commands"]) == calls_before
    assert cleanup_terminal_registry(
        prepared.armed_zero,
        expected_call_key_digest=worker.expected_call_key_digest,
        expected_arm_receipt_digest=prepared.armed_zero.arm_receipt_digest,
    )
    assert process.terminal_record is None


def test_program_embeds_exact_release_bound_source_and_uses_formal_result_sink(tmp_path, monkeypatch):
    source = "def run_ros_entrypoint(request, *, start_gate=None, result_sink=None):\n    untouched = 'print(json.dumps(result), flush=True)'\n"
    digest = hashlib.sha256(source.encode()).hexdigest()
    monkeypatch.setattr(
        "rolo.targetd.physical_worker._read_bounded_twist_source",
        lambda: source,
    )
    request, manifest = _call(
        tmp_path,
        contract={**ROTATE_CONTRACT, "provider_runtime_sha256": digest},
    )
    worker = LanderPiRotateProcessWorker(request, manifest)
    _, observed = _install_process(monkeypatch, _verified_result())

    worker.prepare(_Control(request, intents=(None,)))

    program = observed["argv"][-1]
    assert f"runtime_source = {json.dumps(source)}" in program
    assert "runtime_source.replace" not in program
    assert "result_sink=_rolo_emit_result" in program
    assert "issued_at + 60.0" in program
    assert "registry_refresh_active" in program
    assert "next_refresh = time.monotonic() + 0.1" in program
    assert "independent_stationary_evidence(io)" in program
    compile(program, "<physical-worker-test>", "exec")


def test_target_registry_programs_compile_and_exclusive_active_is_no_replace():
    compile(_TARGET_REGISTRY_LIBRARY, "<physical-registry-library>", "exec")
    compile(_REGISTRY_CONTROL, "<physical-registry-control>", "exec")
    assert "_ro.link(temp, name" in _TARGET_REGISTRY_LIBRARY
    exclusive_branch = _TARGET_REGISTRY_LIBRARY.split("if exclusive_target:", 2)[2].split("else:", 1)[0]
    assert "_ro.replace" not in exclusive_branch
    terminal_body = _TARGET_REGISTRY_LIBRARY.split("def registry_terminalize", 1)[1].split(
        "def registry_cleanup_terminal",
        1,
    )[0]
    assert terminal_body.rindex("_rwrite_file(dirfd, terminal") < terminal_body.rindex("_ro.unlink('active.json'")


def test_execute_sends_authenticated_start_then_requires_full_proof(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    worker = LanderPiRotateProcessWorker(request, manifest)
    process, observed = _install_process(monkeypatch, _verified_result())
    control = _Control(request, intents=(None, None, None))
    prepared = worker.prepare(control)

    outcome = prepared.execute(control)

    assert process.controls[0]["intent"] == "START"
    assert process.controls[0]["sequence"] == 1
    assert outcome.completion.status == "SUCCEEDED"
    assert outcome.completion.outcome_code == "ROTATE_SUCCEEDED"
    assert outcome.result["final_zero_verified"] is True
    assert outcome.result["stop_acknowledged"] is True
    assert outcome.result["provider_invocation_count"] == 1
    assert outcome.result["armed_zero_receipt_digest"] == prepared.armed_zero.arm_receipt_digest
    reaper_argv, reaper_kwargs = observed["inner_commands"][-1]
    assert reaper_argv[6:8] == ["python3", "-c"]
    assert reaper_argv[-4:] == ["probe", "8721", "443322", "d" * 64]
    assert reaper_kwargs["shell"] is False


def test_start_readiness_block_commits_only_after_full_safe_stop(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    result = _safe_stop_result(motion_started=False)
    result["status"] = "BLOCKED"
    _install_process(monkeypatch, result)
    worker = LanderPiRotateProcessWorker(request, manifest)
    control = _Control(request, intents=(None, None, None))
    prepared = worker.prepare(control)

    outcome = prepared.execute(control)

    assert outcome.completion.status == "FAILED"
    assert outcome.completion.outcome_code == "ROTATE_BLOCKED_BEFORE_MOTION"
    assert outcome.result["provider_invocation_count"] == 1
    assert outcome.result["motion_started"] is False
    assert outcome.result["motion_command_emitted"] is False
    assert outcome.result["final_zero_verified"] is True
    assert outcome.result["stop_acknowledged"] is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("stopped_observed", False),
        ("physical_stop_verified", False),
        ("control_graph_isolated", False),
        ("stop_published", False),
    ],
)
def test_start_readiness_block_without_independent_safe_stop_is_unknown(
    tmp_path,
    monkeypatch,
    field,
    value,
):
    request, manifest = _call(tmp_path)
    result = _safe_stop_result(motion_started=False)
    result.update(status="BLOCKED", **{field: value})
    _install_process(monkeypatch, result)
    worker = LanderPiRotateProcessWorker(request, manifest)
    control = _Control(request, intents=(None, None, None))
    prepared = worker.prepare(control)

    with pytest.raises(PhysicalWorkerAmbiguity, match="PHYSICAL_WORKER_PREMOTION_STOP_UNPROVED"):
        prepared.execute(control)


def test_gate_failure_can_stop_armed_process_before_start(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    worker = LanderPiRotateProcessWorker(request, manifest)
    process, _ = _install_process(
        monkeypatch,
        _safe_stop_result(motion_started=False),
    )
    control = _Control(request, intents=(None,))
    prepared = worker.prepare(control)

    outcome = prepared.stop(control, intent="STOP")

    assert [item["intent"] for item in process.controls] == ["STOP"]
    assert process.controls[0]["sequence"] == 1
    assert outcome.completion.status == "STOPPED"
    assert outcome.result["final_zero_verified"] is True
    assert outcome.result["stop_acknowledgement"]["inner_process_gone"] is True
    assert outcome.result["provider_invocation_count"] == 0


def test_pending_stop_before_start_keeps_sequence_one_and_zero_invocations(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    worker = LanderPiRotateProcessWorker(request, manifest)
    process, _ = _install_process(
        monkeypatch,
        _safe_stop_result(motion_started=False),
    )
    control = _Control(request, intents=(None, "STOP"))
    prepared = worker.prepare(control)

    outcome = prepared.execute(control)

    assert [(item["intent"], item["sequence"]) for item in process.controls] == [("STOP", 1)]
    assert outcome.completion.status == "STOPPED"
    assert outcome.result["provider_invocation_count"] == 0


def test_prestart_stop_rejects_claim_that_motion_was_invoked(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    worker = LanderPiRotateProcessWorker(request, manifest)
    _install_process(monkeypatch, _safe_stop_result())
    control = _Control(request, intents=(None,))
    prepared = worker.prepare(control)

    with pytest.raises(
        PhysicalWorkerAmbiguity,
        match="PHYSICAL_WORKER_PRESTART_RESULT_CONTRADICTORY",
    ):
        prepared.stop(control, intent="STOP")


def test_running_cancel_uses_sequence_two_and_explicit_ack(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    worker = LanderPiRotateProcessWorker(request, manifest)
    process, _ = _install_process(
        monkeypatch,
        _safe_stop_result(),
        auto_result_on_start=False,
    )
    control = _Control(request, intents=(None, None, "CANCEL"))
    prepared = worker.prepare(control)

    outcome = prepared.execute(control)

    assert [item["intent"] for item in process.controls] == ["START", "CANCEL"]
    assert process.controls[1]["sequence"] == 2
    assert outcome.completion.status == "CANCELLED"
    assert outcome.completion.outcome_code == "ROTATE_CANCEL_CONFIRMED"
    assert outcome.result["stop_acknowledged"] is True
    assert outcome.result["provider_invocation_count"] == 1


def test_weak_exact_angle_never_becomes_success(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    result = _verified_result()
    result["independent_motion_evidence"] = {
        **result["independent_motion_evidence"],
        "gyro_delta_rad": math.radians(10),
    }
    _install_process(monkeypatch, result)
    worker = LanderPiRotateProcessWorker(request, manifest)
    control = _Control(request, intents=(None, None, None))
    prepared = worker.prepare(control)

    with pytest.raises(
        PhysicalWorkerAmbiguity,
        match="PHYSICAL_WORKER_ROTATION_PROOF_AMBIGUOUS",
    ):
        prepared.execute(control)


def test_interrupt_without_final_zero_is_unknown_not_acknowledged(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    weak = _safe_stop_result(motion_started=False)
    weak["physical_stop_verified"] = False
    _install_process(monkeypatch, weak)
    worker = LanderPiRotateProcessWorker(request, manifest)
    control = _Control(request, intents=(None,))
    prepared = worker.prepare(control)

    with pytest.raises(
        PhysicalWorkerAmbiguity,
        match="PHYSICAL_WORKER_INTERRUPT_STOP_UNPROVED",
    ):
        prepared.stop(control, intent="STOP")


@pytest.mark.parametrize(
    "arm_updates",
    [
        {"publisher_endpoint_gids": ["ab" * 16, "cd" * 16]},
        {"publisher_identity": "/impostor"},
        {"competing_publisher_count": 1},
        {"direct_motor_publisher_identities": ["/hand_gesture", "/odom_publisher"]},
        {"motion_command_emitted": True},
    ],
)
def test_arm_rejects_duplicate_or_unsafe_live_topology(tmp_path, monkeypatch, arm_updates):
    request, manifest = _call(tmp_path)
    process, _ = _install_process(monkeypatch, _verified_result(), arm_updates=arm_updates)
    worker = LanderPiRotateProcessWorker(request, manifest)

    with pytest.raises(PhysicalWorkerAmbiguity, match="PHYSICAL_WORKER_ARM_PROOF_INVALID"):
        worker.prepare(_Control(request, intents=(None,)))
    assert process.terminated is True


def test_tampered_arm_auth_is_rejected_and_outer_process_reaped(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    process, _ = _install_process(monkeypatch, _verified_result(), tamper_arm_auth=True)
    worker = LanderPiRotateProcessWorker(request, manifest)

    with pytest.raises(
        PhysicalWorkerAmbiguity,
        match="PHYSICAL_WORKER_MESSAGE_AUTHENTICATION_FAILED",
    ):
        worker.prepare(_Control(request, intents=(None,)))
    assert process.terminated is True


def test_response_loss_runs_exact_inner_reaper_and_remains_unknown(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    process, observed = _install_process(monkeypatch, _verified_result(), response_lost=True)
    worker = LanderPiRotateProcessWorker(request, manifest)
    control = _Control(request, intents=(None, None, None))
    prepared = worker.prepare(control)

    with pytest.raises(PhysicalWorkerAmbiguity):
        prepared.execute(control)
    assert process.controls[0]["intent"] == "START"
    assert any(command[-4] == "reap" for command, _ in observed["inner_commands"])


def test_post_arm_lease_mismatch_reaps_exact_inner_process(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    process, observed = _install_process(
        monkeypatch,
        _verified_result(),
        auto_result_on_start=False,
    )
    worker = LanderPiRotateProcessWorker(request, manifest)
    control = _Control(request, intents=(None,))
    prepared = worker.prepare(control)
    control._lease.call_key_digest = "0" * 64

    with pytest.raises(
        PhysicalWorkerAmbiguity,
        match="PHYSICAL_WORKER_POST_ARM_CONTROL_AMBIGUOUS",
    ):
        prepared.execute(control)

    assert process.terminated is True
    assert any(command[-4] == "reap" for command, _ in observed["inner_commands"])


def test_complete_start_delivery_followed_by_write_error_reaps_exact_inner(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path)
    process, observed = _install_process(
        monkeypatch,
        _verified_result(),
        auto_result_on_start=False,
        fail_after_start_delivery=True,
    )
    worker = LanderPiRotateProcessWorker(request, manifest)
    control = _Control(request, intents=(None, None))
    prepared = worker.prepare(control)

    with pytest.raises(
        PhysicalWorkerAmbiguity,
        match="PHYSICAL_WORKER_CONTROL_CHANNEL_FAILED",
    ):
        prepared.execute(control)

    assert process.controls[0]["intent"] == "START"
    assert process.terminated is True
    assert any(command[-4] == "reap" for command, _ in observed["inner_commands"])


@pytest.mark.parametrize(
    "contract",
    [
        {**ROTATE_CONTRACT, "command_endpoint": "/controller/cmd_vel"},
        {**ROTATE_CONTRACT, "unexpected": True},
        {**ROTATE_CONTRACT, "independent_feedback_endpoints": ["/odom"]},
    ],
)
def test_constructor_rejects_every_unsealed_route(tmp_path, contract):
    request, manifest = _call(tmp_path, contract=contract)
    with pytest.raises(
        PhysicalWorkerConfigurationError,
        match="PHYSICAL_WORKER_OBSERVATION_CONTRACT_NOT_SEALED",
    ):
        LanderPiRotateProcessWorker(request, manifest)


def test_constructor_rejects_signed_manifest_for_different_runtime(tmp_path):
    request, manifest = _call(
        tmp_path,
        contract={**ROTATE_CONTRACT, "provider_runtime_sha256": "0" * 64},
    )
    with pytest.raises(
        PhysicalWorkerConfigurationError,
        match="PHYSICAL_WORKER_RUNTIME_DIGEST_MISMATCH",
    ):
        LanderPiRotateProcessWorker(request, manifest)


def test_constructor_requires_physical_v3_and_rotate_identity(tmp_path):
    request, manifest = _call(tmp_path / "v2", force_v2=True)
    with pytest.raises(PhysicalWorkerConfigurationError, match="PHYSICAL_WORKER_REQUEST_V3_REQUIRED"):
        LanderPiRotateProcessWorker(request, manifest)

    request, manifest = _call(tmp_path / "other", tool_id="app.generic")
    with pytest.raises(PhysicalWorkerConfigurationError, match="PHYSICAL_WORKER_ROUTE_NOT_SEALED"):
        LanderPiRotateProcessWorker(request, manifest)


@pytest.mark.parametrize(
    "arguments",
    [
        {"angle_degrees": 0, "max_speed_rad_s": 0.03},
        {"angle_degrees": 31, "max_speed_rad_s": 0.03},
        {"angle_degrees": 1, "max_speed_rad_s": 0.16},
        {"angle_degrees": 1, "max_speed_rad_s": 0.03, "extra": 1},
        {"angle_degrees": True, "max_speed_rad_s": 0.03},
    ],
)
def test_constructor_rejects_unbounded_arguments(tmp_path, arguments):
    request, manifest = _call(tmp_path, arguments=arguments)
    with pytest.raises(PhysicalWorkerConfigurationError):
        LanderPiRotateProcessWorker(request, manifest)


def test_control_call_identity_mismatch_fails_before_popen(tmp_path, monkeypatch):
    request, manifest = _call(tmp_path / "expected")
    other, _ = _call(
        tmp_path / "other",
        arguments={"angle_degrees": -1, "max_speed_rad_s": 0.03},
    )
    worker = LanderPiRotateProcessWorker(request, manifest)
    monkeypatch.setattr(
        "rolo.targetd.physical_worker.subprocess.Popen",
        lambda *args, **kwargs: pytest.fail("provider must not start"),
    )

    with pytest.raises(
        PhysicalWorkerConfigurationError,
        match="PHYSICAL_WORKER_CALL_IDENTITY_MISMATCH",
    ):
        worker.prepare(_Control(other, intents=(None,)))
