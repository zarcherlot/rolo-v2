from __future__ import annotations

from rolo.mvp.execution_routes import ExecutionRoute, ExecutionRouteRegistry, RoloRouteBroker


def _route() -> ExecutionRoute:
    return ExecutionRoute(
        route_id="base.motion.velocity",
        target_id="mentorpi",
        provider_id="test-driver",
        interface_type="geometry_msgs/msg/Twist",
        access="write",
        stop_route_id="base.motion.stop",
        parameter_schema={"type": "object", "required": ["angle_degrees"], "properties": {"angle_degrees": {"type": "number"}}, "additionalProperties": False},
        evidence_refs=["target-evidence:" + "a" * 64],
    )


def test_registry_persists_target_bound_route(tmp_path) -> None:
    registry = ExecutionRouteRegistry(tmp_path)
    registered = registry.register(_route())
    assert registered.status == "REGISTERED"
    assert registry.get("mentorpi", "base.motion.velocity").provider_id == "test-driver"


def test_broker_requires_registered_provider_handler(tmp_path) -> None:
    registry = ExecutionRouteRegistry(tmp_path)
    registry.register(_route())
    broker = RoloRouteBroker(registry)
    result = broker.invoke(target_id="mentorpi", route_id="base.motion.velocity", arguments={})
    assert result["status"] == "BLOCKED"
    assert result["error"] == "ROUTE_PROVIDER_UNAVAILABLE"


def test_broker_dispatches_only_registered_route(tmp_path) -> None:
    registry = ExecutionRouteRegistry(tmp_path)
    registry.register(_route())
    broker = RoloRouteBroker(registry, {"test-driver": lambda route, args: {"status": "SUCCEEDED", "route": route.route_id, **args}})
    result = broker.invoke(target_id="mentorpi", route_id="base.motion.velocity", arguments={"angle_degrees": 15})
    assert result == {"status": "SUCCEEDED", "route": "base.motion.velocity", "angle_degrees": 15}


def test_broker_rejects_unbounded_arguments_before_provider(tmp_path) -> None:
    registry = ExecutionRouteRegistry(tmp_path)
    registry.register(_route())
    called = False

    def handler(route, args):
        nonlocal called
        called = True
        return {"status": "SUCCEEDED"}

    result = RoloRouteBroker(registry, {"test-driver": handler}).invoke(
        target_id="mentorpi", route_id="base.motion.velocity", arguments={"angle_degrees": 15, "shell": "rm"}
    )
    assert result["error"] == "ROUTE_ARGUMENTS_INVALID"
    assert called is False
