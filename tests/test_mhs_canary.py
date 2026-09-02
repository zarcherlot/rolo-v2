from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from rolo.mhs_adapters import MhsEnvironmentDescriptor
from rolo.mhs_canary import MhsCanaryApproval, MhsCanaryGate, MhsCanaryRejected
from rolo.mhs_hardware import MhsDeviceManifest
from rolo.mhs_write import MhsWriteContext


NOW = datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc)
FINGERPRINT = "a" * 64


def _manifest() -> MhsDeviceManifest:
    return MhsDeviceManifest(
        device_id="arm-1",
        device_class="actuator",
        name="canary joint",
        vendor="example",
        model="joint-canary",
        commands=[
            {
                "id": "set_position",
                "hardware_resource_id": "joint-1",
                "risk": "R1",
                "input_schema": {
                    "type": "object",
                    "properties": {"position": {"type": "number"}},
                    "required": ["position"],
                    "additionalProperties": False,
                },
                "timeout_s": 1.0,
            }
        ],
        driver_id="canary.driver",
        driver_version="1.0",
        driver_sha256="b" * 64,
    )


def _context() -> MhsWriteContext:
    return MhsWriteContext(
        robot_id="robot-1",
        target_host_fingerprint=FINGERPRINT,
        authorization_ref="human:canary-approval-1",
        resource_lock_ref="lock-1",
        safety_fresh_until=NOW + timedelta(minutes=1),
        verified_preconditions=["safety_approved", "actuator_idle"],
        safety_evidence_ids=["fact-safety-1"],
        external_estop_clear=True,
        watchdog_ok=True,
        quiescent=True,
    )


def _approval(**updates) -> MhsCanaryApproval:
    values = {
        "approval_ref": "human:canary-approval-1",
        "independent_safety_review_ref": "safety-review-1",
        "reviewer_refs": ["reviewer:safety-1"],
        "target_host_fingerprint": FINGERPRINT,
        "device_id": "arm-1",
        "command_id": "set_position",
        "environment_kind": "native-canary",
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
        "max_attempts": 2,
        "enabled": True,
        "external_estop_tested": True,
        "stop_tested": True,
        "rollback_tested": True,
    }
    values.update(updates)
    return MhsCanaryApproval(**values)


def test_canary_is_disabled_without_explicit_enablement() -> None:
    gate = MhsCanaryGate(_approval(enabled=False))
    with pytest.raises(MhsCanaryRejected, match="disabled"):
        gate.admit(
            manifest=_manifest(),
            environment=MhsEnvironmentDescriptor(kind="native-canary", runtime="test"),
            command_id="set_position",
            context=_context(),
            now=NOW + timedelta(seconds=1),
        )
    assert gate.attempts == 0


def test_canary_admission_is_bound_and_budgeted() -> None:
    gate = MhsCanaryGate(_approval(max_attempts=1))
    lease = gate.admit(
        manifest=_manifest(),
        environment=MhsEnvironmentDescriptor(kind="native-canary", runtime="test"),
        command_id="set_position",
        context=_context(),
        now=NOW + timedelta(seconds=1),
    )
    assert lease.attempt_number == 1
    assert lease.approval_ref == "human:canary-approval-1"
    with pytest.raises(MhsCanaryRejected, match="budget"):
        gate.admit(
            manifest=_manifest(),
            environment=MhsEnvironmentDescriptor(kind="native-canary", runtime="test"),
            command_id="set_position",
            context=_context(),
            now=NOW + timedelta(seconds=2),
        )


@pytest.mark.parametrize(
    "updates, message",
    [
        ({"external_estop_tested": False}, "estop"),
        ({"stop_tested": False}, "stop"),
        ({"rollback_tested": False}, "rollback"),
        ({"environment_kind": "simulation"}, "environment"),
        ({"target_host_fingerprint": "c" * 64}, "fingerprint"),
    ],
)
def test_canary_requires_independent_safety_evidence(updates, message) -> None:
    gate = MhsCanaryGate(_approval(**updates))
    with pytest.raises(MhsCanaryRejected, match=message):
        gate.admit(
            manifest=_manifest(),
            environment=MhsEnvironmentDescriptor(kind="native-canary", runtime="test"),
            command_id="set_position",
            context=_context(),
            now=NOW + timedelta(seconds=1),
        )
