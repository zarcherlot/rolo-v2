"""Rolo-owned gate for bounded MHS write commands.

This module is simulation-first.  It deliberately does not expose writes via
``MhsDeviceProvider.invoke`` and defaults to allowing only fake/simulation
environment adapters.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .mhs_adapters import MhsEnvironmentDescriptor
from .mhs_hardware import MhsCommandDescriptor, MhsDeviceManifest


def _now() -> datetime:
    return datetime.now(timezone.utc)


class MhsWriteStatus(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    DENIED = "DENIED"
    FAILED = "FAILED"


class MhsWriteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(default_factory=lambda: f"mhs-write-{uuid4().hex}")
    device_id: str = Field(min_length=1)
    command_id: str = Field(min_length=1)
    route: str = Field(pattern=r"^mhs://[a-z][a-z0-9_.-]*/[a-z][a-z0-9_.-]*$")
    arguments: dict[str, Any] = Field(default_factory=dict)
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    driver_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_host_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    idempotency_key: str = Field(min_length=8, max_length=128)
    requested_at: datetime = Field(default_factory=_now)
    expires_at: datetime

    @model_validator(mode="after")
    def validate_window(self) -> MhsWriteRequest:
        if self.expires_at <= self.requested_at:
            raise ValueError("write request expires_at must be after requested_at")
        return self


class MhsWriteContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    robot_id: str = Field(min_length=1)
    target_host_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_ref: str | None = None
    resource_lock_ref: str | None = None
    safety_fresh_until: datetime
    verified_preconditions: list[str] = Field(default_factory=list)
    safety_evidence_ids: list[str] = Field(default_factory=list)


class MhsWriteResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: f"mhs-event-{uuid4().hex}")
    status: MhsWriteStatus
    request_id: str
    device_id: str
    command_id: str
    route: str
    robot_id: str
    target_host_fingerprint: str
    observed_at: datetime = Field(default_factory=_now)
    value: dict[str, Any] | None = None
    reason: str | None = None
    manifest_sha256: str
    driver_sha256: str
    evidence_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class MhsWriteBackend(Protocol):
    def write(
        self,
        command_id: str,
        arguments: Mapping[str, Any],
        *,
        timeout_s: float,
        idempotency_key: str,
    ) -> Mapping[str, Any]: ...


class MhsWriteAuthorizer(Protocol):
    def authorize(
        self,
        manifest: MhsDeviceManifest,
        command: MhsCommandDescriptor,
        request: MhsWriteRequest,
        context: MhsWriteContext,
    ) -> None: ...


class MhsWriteRejected(RuntimeError):
    pass


class MhsResourceLocks:
    """Process-local lock implementation; distributed locks are a later phase."""

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}

    @contextmanager
    def claim(self, resource_id: str) -> Iterator[None]:
        with self._guard:
            lock = self._locks.setdefault(resource_id, threading.Lock())
        if not lock.acquire(blocking=False):
            raise MhsWriteRejected(f"resource is already locked: {resource_id}")
        try:
            yield
        finally:
            lock.release()


class MhsWriteController:
    """Validate Rolo policy context before invoking a bounded MHS backend."""

    def __init__(
        self,
        *,
        locks: MhsResourceLocks | None = None,
        allowed_environment_kinds: set[str] | None = None,
    ) -> None:
        self.locks = locks or MhsResourceLocks()
        self.allowed_environment_kinds = allowed_environment_kinds or {"fake", "simulation"}
        self._idempotent_results: dict[
            tuple[str, str, str], tuple[str, MhsWriteResult]
        ] = {}

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
        point = now or _now()
        command: MhsCommandDescriptor | None = None
        try:
            command = self._command(manifest, request.command_id)
            self._validate(manifest, command, environment, request, context, point)
            authorizer.authorize(manifest, command, request, context)
            key = (request.device_id, request.command_id, request.idempotency_key)
            arguments_sha256 = hashlib.sha256(
                json.dumps(request.arguments, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if command.idempotent and key in self._idempotent_results:
                previous_digest, previous_result = self._idempotent_results[key]
                if previous_digest != arguments_sha256:
                    raise MhsWriteRejected(
                        "idempotency key was reused with different arguments"
                    )
                return previous_result
            with self.locks.claim(command.hardware_resource_id):
                value = dict(
                    backend.write(
                        command.id,
                        request.arguments,
                        timeout_s=command.timeout_s,
                        idempotency_key=request.idempotency_key,
                    )
                )
            result = self._result(
                MhsWriteStatus.SUCCEEDED,
                manifest,
                request,
                context,
                value=value,
                observed_at=point,
            )
            if command.idempotent:
                self._idempotent_results[key] = (arguments_sha256, result)
            return result
        except MhsWriteRejected as exc:
            return self._result(
                MhsWriteStatus.DENIED,
                manifest,
                request,
                context,
                reason=str(exc),
                observed_at=point,
            )
        except Exception as exc:
            return self._result(
                MhsWriteStatus.FAILED,
                manifest,
                request,
                context,
                reason=f"write backend failed: {type(exc).__name__}",
                observed_at=point,
            )

    @staticmethod
    def _command(manifest: MhsDeviceManifest, command_id: str) -> MhsCommandDescriptor:
        for command in manifest.commands:
            if command.id == command_id:
                return command
        raise MhsWriteRejected(f"command is not declared: {command_id}")

    def _validate(
        self,
        manifest: MhsDeviceManifest,
        command: MhsCommandDescriptor,
        environment: MhsEnvironmentDescriptor,
        request: MhsWriteRequest,
        context: MhsWriteContext,
        now: datetime,
    ) -> None:
        expected_route = f"mhs://{manifest.device_id}/{command.id}"
        if request.device_id != manifest.device_id or request.route != expected_route:
            raise MhsWriteRejected("device or canonical route mismatch")
        if request.manifest_sha256 != manifest.manifest_sha256:
            raise MhsWriteRejected("manifest digest mismatch")
        if request.driver_sha256 != manifest.driver_sha256:
            raise MhsWriteRejected("driver digest mismatch")
        if request.target_host_fingerprint != context.target_host_fingerprint:
            raise MhsWriteRejected("target fingerprint mismatch")
        if now < request.requested_at or now > request.expires_at:
            raise MhsWriteRejected("write request is not fresh")
        if now > context.safety_fresh_until:
            raise MhsWriteRejected("safety evidence is stale")
        if not context.authorization_ref:
            raise MhsWriteRejected("authorization reference is required")
        if not context.resource_lock_ref:
            raise MhsWriteRejected("resource lock reference is required")
        if not context.safety_evidence_ids:
            raise MhsWriteRejected("verified safety evidence is required")
        if environment.kind not in self.allowed_environment_kinds:
            raise MhsWriteRejected(f"write environment is not enabled: {environment.kind}")
        missing = sorted(set(command.requires) - set(context.verified_preconditions))
        if missing:
            raise MhsWriteRejected(f"missing verified preconditions: {', '.join(missing)}")
        self._validate_arguments(command.input_schema, request.arguments)

    @staticmethod
    def _validate_arguments(schema: Mapping[str, Any], arguments: Mapping[str, Any]) -> None:
        properties = schema.get("properties", {})
        missing = sorted(set(schema.get("required", [])) - set(arguments))
        if missing:
            raise MhsWriteRejected(f"missing arguments: {', '.join(missing)}")
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(arguments) - set(properties))
            if unknown:
                raise MhsWriteRejected(f"unknown arguments: {', '.join(unknown)}")
        for name, value in arguments.items():
            rule = properties.get(name, {})
            expected = rule.get("type")
            if expected == "number":
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise MhsWriteRejected(f"argument {name} is not a number")
                if not math.isfinite(float(value)):
                    raise MhsWriteRejected(f"argument {name} is not finite")
                if "minimum" in rule and value < rule["minimum"]:
                    raise MhsWriteRejected(f"argument {name} is below minimum")
                if "maximum" in rule and value > rule["maximum"]:
                    raise MhsWriteRejected(f"argument {name} is above maximum")
            elif expected == "integer" and (isinstance(value, bool) or not isinstance(value, int)):
                raise MhsWriteRejected(f"argument {name} is not an integer")
            elif expected == "string" and not isinstance(value, str):
                raise MhsWriteRejected(f"argument {name} is not a string")
            elif expected == "boolean" and not isinstance(value, bool):
                raise MhsWriteRejected(f"argument {name} is not boolean")

    @staticmethod
    def _result(
        status: MhsWriteStatus,
        manifest: MhsDeviceManifest,
        request: MhsWriteRequest,
        context: MhsWriteContext,
        *,
        value: dict[str, Any] | None = None,
        reason: str | None = None,
        observed_at: datetime,
    ) -> MhsWriteResult:
        return MhsWriteResult(
            status=status,
            request_id=request.request_id,
            device_id=request.device_id,
            command_id=request.command_id,
            route=request.route,
            robot_id=context.robot_id,
            target_host_fingerprint=context.target_host_fingerprint,
            value=value,
            reason=reason,
            observed_at=observed_at,
            manifest_sha256=manifest.manifest_sha256,
            driver_sha256=manifest.driver_sha256,
            evidence_ids=[
                *context.safety_evidence_ids,
                f"authorization:{context.authorization_ref}",
                f"resource-lock:{context.resource_lock_ref}",
            ],
            limitations=["simulation-first write controller; physical adapters disabled"],
        )


__all__ = [
    "MhsWriteStatus",
    "MhsWriteRequest",
    "MhsWriteContext",
    "MhsWriteResult",
    "MhsWriteBackend",
    "MhsWriteAuthorizer",
    "MhsWriteRejected",
    "MhsResourceLocks",
    "MhsWriteController",
]
