from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from rolo.core.models import DiscoveryStatus
from rolo.stages.probe.routes import observed_probe_routes
from rolo.stages.probe.target_evidence import TargetEvidenceBundle


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

    @model_validator(mode="after")
    def require_dry_run_by_default(self) -> RotationDebugRequest:
        if not self.dry_run:
            raise ValueError("physical rotation requires the separate R3 canary contract")
        return self


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


__all__ = ["RotationDebugAssessment", "RotationDebugRequest", "assess_rotation_readiness"]
