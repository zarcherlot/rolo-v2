from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from rolo.agent_tools.native_tools import AgentNativeToolDescriptor, NativeToolParameter
from rolo.core.models import DiscoveryStatus
from rolo.stages.probe.routes import observed_probe_routes
from rolo.stages.probe.target_evidence import TargetEvidenceBundle

from .probe_registration import ExecutionBinding, ToolRegistrationProposal


class RotationDebugRequest(BaseModel):
    """Bounded parameters for a supervised rotation debug window.

    This model is a planning contract only.  It never produces a generic
    ``cmd_vel`` payload and cannot authorize a physical actuator call.
    """

    model_config = ConfigDict(extra="forbid")

    operation_id: Literal["app.base.rotate"] = "app.base.rotate"
    angle_degrees: float = Field(ge=-360.0, le=360.0)
    max_speed_rad_s: float = Field(gt=0.0, le=1.0)
    timeout_s: float = Field(gt=0.0, le=90.0)
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


def rotation_tool_proposal(*, target_id: str, evidence_ref: str) -> ToolRegistrationProposal:
    """Build the generic application adapter used by the rotation MVP.

    Future tools use the same proposal/descriptor contract and can supply a
    different fixed runtime adapter and parameter schema.
    """

    descriptor = AgentNativeToolDescriptor(
        tool_id="app.base.rotate",
        family="application",
        execution_path="MIDDLEWARE_CLI",
        executable="rolo-binding-executor",
        argv_template=["rolo-binding-executor"],
        access="experimental_write",
        risk="R3",
        max_duration_s=120,
        max_output_bytes=100_000,
        evidence_kind="application_rotation",
        parameters=[
            NativeToolParameter(
                name="angle_degrees",
                kind="token",
                pattern=r"-?(?:360(?:\.0+)?|3[0-5][0-9](?:\.[0-9]+)?|[0-9]{1,2}(?:\.[0-9]+)?)",
            ),
            NativeToolParameter(
                name="max_speed_rad_s",
                kind="token",
                pattern=r"(?:0(?:\.[0-9]+)?|1(?:\.0)?)",
            ),
        ],
    )
    return ToolRegistrationProposal(
        target_id=target_id,
        tool_id=descriptor.tool_id,
        evidence_refs=[evidence_ref],
        descriptor=descriptor,
        implementation="binding",
        binding=ExecutionBinding(
            kind="ros2_topic",
            command_endpoint="/cmd_vel",
            interface_type="geometry_msgs/msg/Twist",
            feedback_endpoints=["/odom_raw", "/odom_rf2o"],
            stop_strategy="zero_velocity",
            parameter_mapping={"angle_degrees": "angular.z", "max_speed_rad_s": "angular.z.abs"},
            evidence_refs=[evidence_ref],
        ),
        harness_notes="Generic ROS 2 binding discovered from Probe evidence; provider validates timing and odometry feedback.",
    )


__all__ = ["RotationDebugAssessment", "RotationDebugRequest", "assess_rotation_readiness", "rotation_tool_proposal"]
