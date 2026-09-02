from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

from rolo.mhs_adapters import MhsEnvironmentDescriptor
from rolo.mhs_hardware import MhsDeviceManifest, MhsDeviceProvider, MhsStatus
from rolo.mhs_write import (
    MhsResourceLocks,
    MhsWriteContext,
    MhsWriteController,
    MhsWriteEventStore,
    MhsWriteRejected,
    MhsWriteRequest,
    MhsWriteStatus,
)

NOW = datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc)
FINGERPRINT = "a" * 64


class FakeWriteBackend:
    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[tuple[str, dict, float, str]] = []
        self.stop_calls: list[tuple[str, str]] = []
        self.fail = fail

    def read(self):
        return {"position": 0.0}

    def status(self):
        return {"health": "OK"}

    def write(self, command_id, arguments, *, timeout_s, idempotency_key):
        self.calls.append((command_id, dict(arguments), timeout_s, idempotency_key))
        if self.fail:
            raise RuntimeError("simulated backend fault")
        return {"accepted": True, "position": arguments["position"]}

    def stop(self, hardware_resource_id, *, reason):
        self.stop_calls.append((hardware_resource_id, reason))
        return {"stopped": True, "resource": hardware_resource_id}


class Allow:
    def authorize(self, manifest, command, request, context) -> None:
        assert manifest.device_id == request.device_id
        assert command.hardware_resource_id == "joint-1"
        assert context.authorization_ref == "auth-1"


class Deny:
    def authorize(self, manifest, command, request, context) -> None:
        del manifest, command, request, context
        raise MhsWriteRejected("authorization denied")


def _manifest() -> MhsDeviceManifest:
    return MhsDeviceManifest(
        device_id="arm-1",
        device_class="actuator",
        name="simulated joint",
        vendor="example",
        model="joint-sim",
        channels=[{"id": "position", "name": "Position", "unit": "rad"}],
        commands=[
            {
                "id": "set_position",
                "hardware_resource_id": "joint-1",
                "risk": "R3",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "position": {"type": "number", "minimum": -1.0, "maximum": 1.0}
                    },
                    "required": ["position"],
                    "additionalProperties": False,
                },
                "timeout_s": 1.0,
                "idempotent": True,
                "requires": ["safety_approved", "actuator_idle"],
                "cancel_capability": "stop",
                "compensation_capability": "stop",
            }
        ],
        driver_id="sim.driver",
        driver_version="1.0",
        driver_sha256="b" * 64,
    )


def _request(manifest: MhsDeviceManifest, **updates) -> MhsWriteRequest:
    values = {
        "device_id": manifest.device_id,
        "command_id": "set_position",
        "route": "mhs://arm-1/set_position",
        "arguments": {"position": 0.5},
        "manifest_sha256": manifest.manifest_sha256,
        "driver_sha256": manifest.driver_sha256,
        "target_host_fingerprint": FINGERPRINT,
        "idempotency_key": "idem-0001",
        "requested_at": NOW,
        "expires_at": NOW + timedelta(seconds=30),
    }
    values.update(updates)
    return MhsWriteRequest(**values)


def _context(**updates) -> MhsWriteContext:
    values = {
        "robot_id": "robot-1",
        "target_host_fingerprint": FINGERPRINT,
        "authorization_ref": "auth-1",
        "resource_lock_ref": "lock-1",
        "safety_fresh_until": NOW + timedelta(seconds=30),
        "verified_preconditions": ["safety_approved", "actuator_idle"],
        "safety_evidence_ids": ["fact-safety-1"],
        "external_estop_clear": True,
        "watchdog_ok": True,
        "quiescent": True,
    }
    values.update(updates)
    return MhsWriteContext(**values)


def _environment(kind: str = "simulation") -> MhsEnvironmentDescriptor:
    return MhsEnvironmentDescriptor(kind=kind, runtime="test-simulator")


def _execute(controller, manifest, backend, request=None, context=None, authorizer=None):
    return controller.execute(
        manifest=manifest,
        environment=_environment(),
        backend=backend,
        request=request or _request(manifest),
        context=context or _context(),
        authorizer=authorizer or Allow(),
        now=NOW + timedelta(seconds=1),
    )


def test_simulation_write_succeeds_only_through_rolo_controller() -> None:
    manifest, backend = _manifest(), FakeWriteBackend()
    result = _execute(MhsWriteController(), manifest, backend)
    assert result.status == MhsWriteStatus.SUCCEEDED
    assert result.robot_id == "robot-1"
    assert result.value == {"accepted": True, "position": 0.5}
    assert len(backend.calls) == 1
    provider = MhsDeviceProvider(manifest, backend)
    command = next(item for item in provider.capabilities() if item["access"] == "write")
    assert command["capability_id"] == "set_position"
    assert command["requires_rolo_write_gate"] is True
    assert provider.invoke("set_position").status == MhsStatus.UNAVAILABLE


def test_write_attempts_are_hash_chained_and_verifiable() -> None:
    manifest, backend = _manifest(), FakeWriteBackend()
    store = MhsWriteEventStore()
    controller = MhsWriteController(event_store=store)
    success = _execute(controller, manifest, backend)
    denied = _execute(
        controller,
        manifest,
        backend,
        request=_request(manifest, idempotency_key="idem-0002", arguments={"position": 2.0}),
    )
    assert success.status == MhsWriteStatus.SUCCEEDED
    assert denied.status == MhsWriteStatus.DENIED
    assert len(store.events()) == 2
    assert store.events()[1].previous_digest == store.events()[0].digest
    store.verify()
    tampered = store.events()[0].model_copy(update={"immutable": False})
    object.__setattr__(store, "_events", [tampered, *store.events()[1:]])
    try:
        store.verify()
    except ValueError:
        pass
    else:
        raise AssertionError("tampered event chain was accepted")


def test_write_command_requires_bounded_input_schema() -> None:
    values = _manifest().model_dump(mode="json")
    values["commands"][0]["input_schema"]["additionalProperties"] = True
    try:
        MhsDeviceManifest.model_validate(values)
    except ValueError:
        pass
    else:
        raise AssertionError("unbounded MHS write schema was accepted")


def test_gate_denials_never_reach_backend() -> None:
    cases = [
        (None, _context(authorization_ref=None), None),
        (None, _context(resource_lock_ref=None), None),
        (None, _context(safety_evidence_ids=[]), None),
        (None, _context(verified_preconditions=["safety_approved"]), None),
        (_request(_manifest(), manifest_sha256="0" * 64), None, None),
        (_request(_manifest(), driver_sha256="0" * 64), None, None),
        (_request(_manifest(), target_host_fingerprint="c" * 64), None, None),
        (_request(_manifest(), expires_at=NOW + timedelta(milliseconds=500)), None, None),
        (None, _context(safety_fresh_until=NOW), None),
        (_request(_manifest(), arguments={"position": 2.0}), None, None),
        (None, None, Deny()),
    ]
    for request, context, authorizer in cases:
        manifest, backend = _manifest(), FakeWriteBackend()
        result = _execute(
            MhsWriteController(), manifest, backend, request, context, authorizer
        )
        assert result.status == MhsWriteStatus.DENIED
        assert backend.calls == []


def test_physical_environment_is_disabled_by_default() -> None:
    manifest, backend = _manifest(), FakeWriteBackend()
    controller = MhsWriteController()
    result = controller.execute(
        manifest=manifest,
        environment=_environment("native"),
        backend=backend,
        request=_request(manifest),
        context=_context(),
        authorizer=Allow(),
        now=NOW + timedelta(seconds=1),
    )
    assert result.status == MhsWriteStatus.DENIED
    assert backend.calls == []


def test_resource_lock_conflict_denies_and_backend_fault_releases_lock() -> None:
    manifest, backend, locks = _manifest(), FakeWriteBackend(), MhsResourceLocks()
    controller = MhsWriteController(locks=locks)
    with locks.claim("joint-1"):
        denied = _execute(controller, manifest, backend)
    assert denied.status == MhsWriteStatus.DENIED
    assert backend.calls == []

    failed = _execute(controller, manifest, FakeWriteBackend(fail=True))
    assert failed.status == MhsWriteStatus.FAILED
    succeeding = _execute(
        controller,
        manifest,
        backend,
        request=_request(manifest, idempotency_key="idem-0002"),
    )
    assert succeeding.status == MhsWriteStatus.SUCCEEDED


def test_idempotent_retry_does_not_repeat_backend_write() -> None:
    manifest, backend, controller = _manifest(), FakeWriteBackend(), MhsWriteController()
    first = _execute(controller, manifest, backend)
    second = _execute(controller, manifest, backend)
    assert second.event_id == first.event_id
    assert len(backend.calls) == 1
    collision = _execute(
        controller,
        manifest,
        backend,
        request=_request(manifest, arguments={"position": 0.25}),
    )
    assert collision.status == MhsWriteStatus.DENIED
    assert len(backend.calls) == 1


def test_external_estop_blocks_write_before_backend() -> None:
    manifest, backend = _manifest(), FakeWriteBackend()
    result = _execute(
        MhsWriteController(),
        manifest,
        backend,
        context=_context(external_estop_clear=False),
    )
    assert result.status == MhsWriteStatus.DENIED
    assert "estop" in (result.reason or "")
    assert backend.calls == []


def test_watchdog_and_quiescence_are_required_safety_gates() -> None:
    for field in ("watchdog_ok", "quiescent"):
        manifest, backend = _manifest(), FakeWriteBackend()
        result = _execute(
            MhsWriteController(),
            manifest,
            backend,
            context=_context(**{field: False}),
        )
        assert result.status == MhsWriteStatus.DENIED
        assert backend.calls == []


class ManualAuthorizer:
    def authorize(self, manifest, command, request, context) -> None:
        del manifest, command, request
        if not context.authorization_ref or not context.authorization_ref.startswith(
            "human:"
        ):
            raise MhsWriteRejected("manual authorization reference is required")


def test_manual_authorization_reference_is_checked_by_rolo() -> None:
    manifest, backend = _manifest(), FakeWriteBackend()
    denied = _execute(
        MhsWriteController(),
        manifest,
        backend,
        context=_context(authorization_ref="policy:auto"),
        authorizer=ManualAuthorizer(),
    )
    assert denied.status == MhsWriteStatus.DENIED
    assert backend.calls == []

    approved = _execute(
        MhsWriteController(),
        manifest,
        backend,
        request=_request(manifest, idempotency_key="idem-manual"),
        context=_context(authorization_ref="human:approval-1"),
        authorizer=ManualAuthorizer(),
    )
    assert approved.status == MhsWriteStatus.SUCCEEDED
    assert len(backend.calls) == 1


class SlowWriteBackend(FakeWriteBackend):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.released = threading.Event()

    def write(self, command_id, arguments, *, timeout_s, idempotency_key):
        self.started.set()
        self.released.wait(timeout=1.0)
        return super().write(
            command_id,
            arguments,
            timeout_s=timeout_s,
            idempotency_key=idempotency_key,
        )

    def stop(self, hardware_resource_id, *, reason):
        value = super().stop(hardware_resource_id, reason=reason)
        self.released.set()
        return value


def test_write_timeout_requests_stop_and_is_audited() -> None:
    values = _manifest().model_dump(mode="json")
    values["commands"][0]["timeout_s"] = 0.01
    manifest, backend = MhsDeviceManifest.model_validate(values), SlowWriteBackend()
    store = MhsWriteEventStore()
    result = _execute(
        MhsWriteController(event_store=store), manifest, backend,
        request=_request(manifest, idempotency_key="idem-timeout"),
    )
    assert result.status == MhsWriteStatus.FAILED
    assert "timed out" in (result.reason or "")
    assert result.value == {"stop": {"stopped": True, "resource": "joint-1"}}
    assert backend.stop_calls == [("joint-1", "write timeout")]
    assert len(store.events()) == 1
