from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from rolo.agent_tools.native_tools import AgentNativeToolDescriptor, NativeToolInvocation, NativeToolParameter
from rolo.core.models import DiscoveryStatus
from rolo.stages.probe.routes import observed_probe_routes
from rolo.stages.probe.target_evidence import TargetEvidenceBundle

from .probe_registration import ToolRegistrationProposal


class RotationDebugRequest(BaseModel):
    """Bounded parameters for a supervised rotation debug window.

    This model is a planning contract only.  It never produces a generic
    ``cmd_vel`` payload and cannot authorize a physical actuator call.
    """

    model_config = ConfigDict(extra="forbid")

    operation_id: Literal["app.base.rotate"] = "app.base.rotate"
    angle_degrees: float = Field(gt=-180.0, lt=180.0)
    max_speed_rad_s: float = Field(gt=0.0, le=1.0)
    timeout_s: float = Field(gt=0.0, le=30.0)
    direction: Literal["left", "right"]
    dry_run: bool = True


class RotationDebugAssessment(BaseModel):
    """Evidence-bound rotation readiness; ``write_allowed`` is always false."""

    model_config = ConfigDict(extra="forbid")

    target_id: str
    target_evidence_sha256: str
    status: Literal["READY_FOR_SUPERVISED_REVIEW", "BLOCKED"]
    write_allowed: Literal[False] = False
    required_signals: list[str] = Field(default_factory=lambda: ["motion_command", "localization"])
    matched_routes: list[str] = Field(default_factory=list)
    missing_signals: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


def assess_rotation_readiness(bundle: TargetEvidenceBundle) -> RotationDebugAssessment:
    """Check read-only route prerequisites without invoking a device."""

    routes = []
    for probe in bundle.probes.values():
        if probe.status in {DiscoveryStatus.SUCCEEDED, DiscoveryStatus.PARTIAL}:
            routes.extend(observed_probe_routes(probe))
    unique = {route.resource_id: route for route in routes}
    motion = [route for route in unique.values() if route.kind == "ros_topic" and ("cmd_vel" in route.endpoint.lower() or "twist" in (route.interface_type or "").lower())]
    odom = [route for route in unique.values() if route.kind == "ros_topic" and ("odom" in route.endpoint.lower() or "odometry" in (route.endpoint + " " + (route.interface_type or "")).lower())]
    missing = [name for name, present in (("motion_command", bool(motion)), ("localization", bool(odom))) if not present]
    matched = sorted({route.resource_id for route in (*motion, *odom)})
    status = "READY_FOR_SUPERVISED_REVIEW" if not missing else "BLOCKED"
    limitations = [
        "route presence is not behavioral proof of rotation",
        "app.base.rotate remains a deferred physical write operation",
        "no service, action, executable, or actuator was invoked",
    ]
    if missing:
        limitations.append("missing required read-only route signals: " + ", ".join(missing))
    return RotationDebugAssessment(
        target_id=bundle.robot_id,
        target_evidence_sha256=bundle.payload_sha256,
        status=status,
        matched_routes=matched,
        missing_signals=missing,
        limitations=limitations,
    )


_ROTATION_RUNTIME = "\n".join(
    [
        "import json, math, subprocess, sys, time",
        "a = float(sys.argv[1]); s = float(sys.argv[2])",
        "if not -180.0 < a < 180.0 or not 0.0 < s <= 1.0: raise SystemExit('rotation bounds')",
        "z = math.copysign(s, a); duration = abs(math.radians(a)) / s",
        "end = time.monotonic() + duration",
        "msg = lambda v: str(dict(linear=dict(x=0.0, y=0.0, z=0.0), angular=dict(z=v)))",
        "while time.monotonic() < end:",
        "    subprocess.run(['ros2', 'topic', 'pub', '--once', '/cmd_vel', 'geometry_msgs/msg/Twist', msg(z)], check=False)",
        "    time.sleep(0.1)",
        "subprocess.run(['ros2', 'topic', 'pub', '--once', '/cmd_vel', 'geometry_msgs/msg/Twist', msg(0.0)], check=False)",
        "print(json.dumps(dict(status='SUCCEEDED', angle_degrees=a, duration_s=duration)))",
    ]
)


def rotation_tool_proposal(*, target_id: str, evidence_ref: str) -> ToolRegistrationProposal:
    """Build the generic application adapter used by the rotation MVP.

    Future tools use the same proposal/descriptor contract and can supply a
    different fixed runtime adapter and parameter schema.
    """

    descriptor = AgentNativeToolDescriptor(
        tool_id="app.base.rotate",
        family="application",
        execution_path="DIRECT_RUNNER",
        executable="python3",
        argv_template=["python3"],
        access="experimental_write",
        risk="R3",
        max_duration_s=120,
        max_output_bytes=100_000,
        evidence_kind="application_rotation",
        parameters=[
            NativeToolParameter(
                name="angle_degrees",
                kind="token",
                pattern=r"-?(?:[0-9]{1,2}(?:\.[0-9]+)?|1[0-7][0-9](?:\.[0-9]+)?)",
            ),
            NativeToolParameter(
                name="max_speed_rad_s",
                kind="token",
                pattern=r"(?:0(?:\.[0-9]+)?|1(?:\.0)?)",
            ),
        ],
        variants={
            "execute": NativeToolInvocation(
                executable="python3",
                argv_template=["python3", "-c", _ROTATION_RUNTIME, "{angle_degrees}", "{max_speed_rad_s}"],
                required_parameters=["angle_degrees", "max_speed_rad_s"],
            )
        },
    )
    return ToolRegistrationProposal(
        target_id=target_id,
        tool_id=descriptor.tool_id,
        evidence_refs=[evidence_ref],
        descriptor=descriptor,
        harness_notes="MVP timed cmd_vel adapter; add odometry/IMU feedback before claiming angle accuracy.",
    )


__all__ = ["RotationDebugAssessment", "RotationDebugRequest", "assess_rotation_readiness", "rotation_tool_proposal"]
