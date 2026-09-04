from __future__ import annotations

from rolo.mvp.binding_dispatch import ApplicationBindingDispatcher
from rolo.mvp.probe_registration import ExecutionBinding


def _binding(kind: str) -> ExecutionBinding:
    return ExecutionBinding(
        kind=kind,
        command_endpoint="/command",
        interface_type="example/Command",
        stop_strategy="zero_velocity",
        evidence_refs=["target-evidence:" + "a" * 64],
    )


def test_dispatcher_routes_registered_provider_without_ros_assumption() -> None:
    dispatcher = ApplicationBindingDispatcher()
    dispatcher.register("vendor.serial", lambda binding, args: {"status": "SUCCEEDED", "value": args["value"]})
    result = dispatcher.execute(_binding("vendor.serial"), {"value": 7})
    assert result == {"status": "SUCCEEDED", "value": 7}


def test_dispatcher_blocks_unknown_provider_kind() -> None:
    result = ApplicationBindingDispatcher().execute(_binding("vendor.can"), {})
    assert result["status"] == "BLOCKED"
    assert result["error"] == "UNSUPPORTED_BINDING_KIND"
