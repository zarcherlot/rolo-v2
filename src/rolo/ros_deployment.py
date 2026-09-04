"""Read-only ROS namespace/permission/bridge deployment planning.

This module produces an auditable plan only.  Applying it to a target is an
explicit deployment concern and is intentionally not performed by Rolo APIs.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RosBridgeSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    source_namespace: str = Field(pattern=r"^/[A-Za-z0-9_~/.-]{1,127}$")
    target_namespace: str = Field(pattern=r"^/[A-Za-z0-9_~/.-]{1,127}$")
    topics: list[str] = Field(default_factory=list, max_length=128)
    read_only: bool = True


class RosDeploymentPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["rolo-ros-deployment-plan/v1"] = "rolo-ros-deployment-plan/v1"
    robot_id: str = Field(min_length=1, max_length=128)
    target_host_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    namespace: str = Field(pattern=r"^/[A-Za-z0-9_~/.-]{1,127}$")
    run_as_user: str = Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")
    required_groups: list[str] = Field(default_factory=list, max_length=16)
    setup_files: list[str] = Field(default_factory=list, max_length=16)
    bridges: list[RosBridgeSpec] = Field(default_factory=list, max_length=16)
    apply: bool = False
    limitations: list[str] = Field(
        default_factory=lambda: ["plan is descriptive; no target writes are performed"]
    )

    @model_validator(mode="after")
    def validate_plan(self) -> RosDeploymentPlan:
        if self.apply:
            raise ValueError("deployment plan cannot authorize target writes")
        if len(self.bridges) != len({item.name for item in self.bridges}):
            raise ValueError("bridge names must be unique")
        return self

    @property
    def plan_digest(self) -> str:
        payload = self.model_dump(mode="json", exclude={"apply", "limitations"})
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


def build_ros_deployment_plan(
    *,
    robot_id: str,
    target_host_fingerprint: str,
    namespace: str = "/rolo",
    run_as_user: str = "pi",
    required_groups: list[str] | None = None,
    setup_files: list[str] | None = None,
    bridges: list[RosBridgeSpec] | None = None,
) -> RosDeploymentPlan:
    return RosDeploymentPlan(
        robot_id=robot_id,
        target_host_fingerprint=target_host_fingerprint,
        namespace=namespace,
        run_as_user=run_as_user,
        required_groups=required_groups or [],
        setup_files=setup_files or [],
        bridges=bridges or [],
    )
