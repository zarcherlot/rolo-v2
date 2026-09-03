"""Fail-closed admission for a narrowly scoped MHS W4 canary.

The canary gate is deliberately I/O-free.  It validates an independently
reviewed approval and returns a bounded lease that a deployment may pass to
the existing ``MhsWriteController``.  It does not discover targets, open SSH
sessions, or write hardware; those concerns remain deployment-specific.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .mhs_adapters import MhsEnvironmentDescriptor
from .mhs_hardware import MhsDeviceManifest
from .mhs_write import (
    MhsWriteAuthorizer,
    MhsWriteBackend,
    MhsWriteContext,
    MhsWriteController,
    MhsWriteRequest,
    MhsWriteResult,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


class MhsCanaryRejected(RuntimeError):
    """The W4 approval does not admit this target or command."""


class MhsCanaryApproval(BaseModel):
    """Signed-out-of-band approval facts required before a real canary."""

    model_config = ConfigDict(extra="forbid")

    approval_ref: str = Field(pattern=r"^human:[A-Za-z0-9_.:-]{1,127}$")
    independent_safety_review_ref: str = Field(min_length=1, max_length=256)
    reviewer_refs: list[str] = Field(min_length=1, max_length=8)
    target_host_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    device_id: str = Field(min_length=1)
    command_id: str = Field(min_length=1)
    environment_kind: str = Field(
        min_length=1, pattern=r"^[a-z][a-z0-9_.:/-]*$"
    )
    approved_risk: Literal["R1"] = "R1"
    issued_at: datetime
    expires_at: datetime
    max_attempts: int = Field(ge=1, le=3)
    enabled: bool = False
    external_estop_tested: bool = False
    stop_tested: bool = False
    rollback_tested: bool = False

    @model_validator(mode="after")
    def validate_window_and_reviewers(self) -> MhsCanaryApproval:
        if self.expires_at <= self.issued_at:
            raise ValueError("canary expires_at must be after issued_at")
        if len(set(self.reviewer_refs)) != len(self.reviewer_refs):
            raise ValueError("canary reviewer_refs must be unique")
        return self


class MhsCanaryLease(BaseModel):
    """A single bounded admission issued by ``MhsCanaryGate``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    lease_id: str = Field(default_factory=lambda: f"mhs-canary-{uuid4().hex}")
    approval_ref: str
    attempt_number: int = Field(ge=1, le=3)
    device_id: str
    command_id: str
    target_host_fingerprint: str
    admitted_at: datetime


class MhsCanaryGate:
    """Validate W4 approval and cap the number of admitted attempts."""

    def __init__(self, approval: MhsCanaryApproval) -> None:
        self.approval = approval
        self._guard = threading.Lock()
        self._attempts = 0

    @property
    def attempts(self) -> int:
        with self._guard:
            return self._attempts

    def admit(
        self,
        *,
        manifest: MhsDeviceManifest,
        environment: MhsEnvironmentDescriptor,
        command_id: str,
        context: MhsWriteContext,
        now: datetime | None = None,
    ) -> MhsCanaryLease:
        point = now or _now()
        approval = self.approval
        if not approval.enabled:
            raise MhsCanaryRejected("real-device canary is disabled")
        if point < approval.issued_at or point > approval.expires_at:
            raise MhsCanaryRejected("canary approval is not fresh")
        if manifest.device_id != approval.device_id or command_id != approval.command_id:
            raise MhsCanaryRejected("canary approval is bound to another device or command")
        if environment.kind != approval.environment_kind:
            raise MhsCanaryRejected("canary environment does not match approval")
        if context.target_host_fingerprint != approval.target_host_fingerprint:
            raise MhsCanaryRejected("canary target fingerprint does not match approval")
        if context.authorization_ref != approval.approval_ref:
            raise MhsCanaryRejected("canary authorization reference does not match approval")
        try:
            command = next(item for item in manifest.commands if item.id == command_id)
        except StopIteration as exc:
            raise MhsCanaryRejected("canary command is not declared") from exc
        if command.risk != approval.approved_risk:
            raise MhsCanaryRejected("only the independently approved risk level may run")
        if not approval.external_estop_tested:
            raise MhsCanaryRejected("external estop test evidence is required")
        if not approval.stop_tested:
            raise MhsCanaryRejected("stop test evidence is required")
        if not approval.rollback_tested:
            raise MhsCanaryRejected("rollback test evidence is required")
        with self._guard:
            if self._attempts >= approval.max_attempts:
                raise MhsCanaryRejected("canary attempt budget is exhausted")
            self._attempts += 1
            attempt = self._attempts
        return MhsCanaryLease(
            approval_ref=approval.approval_ref,
            attempt_number=attempt,
            device_id=manifest.device_id,
            command_id=command_id,
            target_host_fingerprint=context.target_host_fingerprint,
            admitted_at=point,
        )


class MhsCanaryRunner:
    """Bind a canary lease to the existing Rolo write controller.

    The runner is disabled by default.  A deployment must explicitly enable
    it and configure the controller's environment allowlist; this class does
    not discover, connect to, or select a physical adapter.
    """

    def __init__(
        self,
        gate: MhsCanaryGate,
        controller: MhsWriteController,
        *,
        real_execution_enabled: bool = False,
    ) -> None:
        self.gate = gate
        self.controller = controller
        self.real_execution_enabled = real_execution_enabled

    def execute(
        self,
        *,
        manifest: MhsDeviceManifest,
        environment: MhsEnvironmentDescriptor,
        backend: MhsWriteBackend,
        request: MhsWriteRequest,
        context: MhsWriteContext,
        authorizer: MhsWriteAuthorizer,
        now: datetime | None = None,
    ) -> MhsWriteResult:
        if not self.real_execution_enabled:
            raise MhsCanaryRejected("canary execution is disabled")
        lease = self.gate.admit(
            manifest=manifest,
            environment=environment,
            command_id=request.command_id,
            context=context,
            now=now,
        )
        bound_context = context.model_copy(update={"canary_lease_id": lease.lease_id})
        return self.controller.execute(
            manifest=manifest,
            environment=environment,
            backend=backend,
            request=request,
            context=bound_context,
            authorizer=authorizer,
            now=now,
        )


__all__ = [
    "MhsCanaryRejected",
    "MhsCanaryApproval",
    "MhsCanaryLease",
    "MhsCanaryGate",
    "MhsCanaryRunner",
]
