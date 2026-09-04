from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from rolo.agent_tools.native_tools import (
    AgentNativeRunner,
    AgentNativeToolDescriptor,
    AgentNativeToolResult,
    NativeToolStatus,
)
from rolo.agent_tools.planning import ToolPlan, validate_tool_plan
from rolo.core.artifacts import ArtifactStore

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_NONCE_PATTERN = r"^[A-Za-z0-9_-]{16,128}$"
_SESSION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"


class NativeToolSessionBudget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_calls: int = Field(ge=1, le=10_000)
    max_elapsed_s: float = Field(gt=0, le=86_400)
    max_result_bytes: int = Field(ge=1, le=1_000_000_000)


class NativeToolSessionDescriptor(BaseModel):
    """Immutable authority for one Agent-native tool session."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-native-tool-session/v1"] = "rolo-native-tool-session/v1"
    session_id: str = Field(pattern=_SESSION_PATTERN)
    nonce: str = Field(pattern=_NONCE_PATTERN)
    robot_id: str = Field(min_length=1, max_length=128)
    target_host_fingerprint: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    stage: Literal["probe"]
    native_catalog_sha256: str = Field(pattern=_SHA256_PATTERN)
    allowed_tools: list[str] = Field(min_length=1, max_length=256)
    policy_version: str = Field(min_length=1, max_length=128)
    budget: NativeToolSessionBudget
    created_at: datetime
    expires_at: datetime

    @field_validator("allowed_tools")
    @classmethod
    def require_unique_tools(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("native tool session allowlist must be unique")
        if any(not item or len(item) > 128 for item in value):
            raise ValueError("native tool IDs must contain 1-128 characters")
        return value

    @model_validator(mode="after")
    def validate_bounds(self) -> NativeToolSessionDescriptor:
        if self.created_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("native tool session timestamps must include timezone")
        if self.expires_at <= self.created_at:
            raise ValueError("native tool session expiry must be after creation")
        if (self.expires_at - self.created_at).total_seconds() > 86_400:
            raise ValueError("native tool session TTL exceeds 24 hours")
        return self


class NativeToolSessionAuthorizationError(ValueError):
    """The caller attempted to use a stale or unauthorized native session."""


class NativeToolSessionBudgetError(ValueError):
    """The native session exhausted one of its hard budgets."""


def native_catalog_sha256(
    descriptors: list[AgentNativeToolDescriptor],
) -> str:
    payload = json.dumps(
        [
            item.model_dump(mode="json")
            for item in sorted(descriptors, key=lambda item: item.tool_id)
        ],
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _segment(value: str, label: str) -> str:
    if not _SAFE_SEGMENT.fullmatch(value):
        raise ValueError(f"invalid {label}: {value!r}")
    return value


class NativeToolSession:
    """Budgeted, auditable facade over the bounded AgentNativeRunner."""

    def __init__(
        self,
        *,
        descriptor: NativeToolSessionDescriptor,
        runner: AgentNativeRunner,
        artifacts: ArtifactStore,
        runtime_environment: Mapping[str, str] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.descriptor = NativeToolSessionDescriptor.model_validate(descriptor.model_dump())
        self.runner = runner
        self.artifacts = artifacts
        self.runtime_environment = dict(runtime_environment or {})
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        catalog = runner.list_tools()
        if native_catalog_sha256(catalog) != self.descriptor.native_catalog_sha256:
            raise NativeToolSessionAuthorizationError("native tool catalog identity mismatch")
        available = {item.tool_id for item in catalog}
        unknown = sorted(set(self.descriptor.allowed_tools) - available)
        if unknown:
            raise NativeToolSessionAuthorizationError(
                f"native session allowlist contains unknown tools: {unknown}"
            )
        self._calls = 0
        self._result_bytes = 0
        self._results: list[AgentNativeToolResult] = []
        self._closed = False
        self._lock = threading.Lock()

    def list_tools(self) -> list[AgentNativeToolDescriptor]:
        self._preflight()
        allowed = set(self.descriptor.allowed_tools)
        return [item for item in self.runner.list_tools() if item.tool_id in allowed]

    def execute_plan(
        self,
        plan: ToolPlan,
        *,
        allow_mutating: bool = False,
    ) -> list[AgentNativeToolResult]:
        """Validate and execute one Agent plan through this frozen session."""
        if plan.target_id != self.descriptor.robot_id:
            raise NativeToolSessionAuthorizationError("tool plan target does not match session")
        if plan.session_id != self.descriptor.session_id:
            raise NativeToolSessionAuthorizationError("tool plan session does not match session")
        if plan.session_nonce != self.descriptor.nonce:
            raise NativeToolSessionAuthorizationError("tool plan nonce does not match session")
        if plan.surface_digest != self.descriptor.native_catalog_sha256:
            raise NativeToolSessionAuthorizationError(
                "tool plan surface digest does not match session"
            )
        validate_tool_plan(
            plan,
            allowed_tool_ids=self.descriptor.allowed_tools,
            catalog=self.runner.list_tools(),
            allow_mutating=allow_mutating,
        )
        results: list[AgentNativeToolResult] = []
        for step in plan.steps:
            result = self.invoke(step.tool_id, step.arguments)
            results.append(result)
            if result.status != NativeToolStatus.SUCCEEDED:
                break
        return results

    def invoke(
        self,
        tool_id: str,
        arguments: dict[str, str] | None = None,
        *,
        environment: Mapping[str, str] | None = None,
    ) -> AgentNativeToolResult:
        with self._lock:
            self._preflight()
            if tool_id not in self.descriptor.allowed_tools:
                raise NativeToolSessionAuthorizationError(
                    "native tool is outside the frozen session allowlist"
                )
            budget = self.descriptor.budget
            if self._calls >= budget.max_calls:
                raise NativeToolSessionBudgetError("native tool session call budget is exhausted")
            if self._result_bytes >= budget.max_result_bytes:
                raise NativeToolSessionBudgetError(
                    "native tool session result-byte budget is exhausted"
                )
            self._calls += 1
            result = self.runner.run(
                tool_id,
                arguments,
                environment=environment if environment is not None else self.runtime_environment,
            )
            encoded = json.dumps(
                result.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            if len(encoded) > budget.max_result_bytes - self._result_bytes:
                self._result_bytes = budget.max_result_bytes
                self._audit(tool_id, result, outcome="TRUNCATED", result_bytes=len(encoded))
                raise NativeToolSessionBudgetError(
                    "native tool result exceeds the remaining session byte budget"
                )
            self._result_bytes += len(encoded)
            relative = (
                f"native/{_segment(self.descriptor.robot_id, 'robot_id')}"
                f"/sessions/{_segment(self.descriptor.session_id, 'session_id')}"
                f"/calls/{self._calls:04d}-{_segment(tool_id, 'tool_id')}.json"
            )
            ref = f"artifact://{relative}"
            enriched = result.model_copy(update={"evidence_refs": [ref]})
            artifact_path = self.artifacts.write_json(relative, enriched.model_dump(mode="json"))
            if enriched.sensitive and os.name != "nt":
                artifact_path.chmod(0o600)
            self._audit(tool_id, enriched, outcome=enriched.status.value, result_bytes=len(encoded))
            self._results.append(enriched)
            return enriched

    @property
    def results(self) -> list[AgentNativeToolResult]:
        """Return a defensive copy of results observed in this session."""
        with self._lock:
            return list(self._results)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._audit(None, None, outcome="CLOSED", result_bytes=0)

    def _preflight(self) -> None:
        if self._closed:
            raise NativeToolSessionAuthorizationError("native tool session is closed")
        now = self._now()
        created = self.descriptor.created_at.astimezone(timezone.utc)
        expires = self.descriptor.expires_at.astimezone(timezone.utc)
        if created > now or expires <= now:
            raise NativeToolSessionAuthorizationError(
                "native tool session is expired or not yet valid"
            )
        if (now - created).total_seconds() >= self.descriptor.budget.max_elapsed_s:
            raise NativeToolSessionBudgetError(
                "native tool session elapsed-time budget is exhausted"
            )

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise NativeToolSessionAuthorizationError("native session clock must include timezone")
        return value.astimezone(timezone.utc)

    def _audit(
        self,
        tool_id: str | None,
        result: AgentNativeToolResult | None,
        *,
        outcome: str,
        result_bytes: int,
    ) -> None:
        relative = (
            f"native/{_segment(self.descriptor.robot_id, 'robot_id')}"
            f"/sessions/{_segment(self.descriptor.session_id, 'session_id')}/audit.jsonl"
        )
        self.artifacts.append_jsonl(
            relative,
            {
                "schema_version": "rolo-native-tool-session-audit/v1",
                "session_id": self.descriptor.session_id,
                "robot_id": self.descriptor.robot_id,
                "stage": self.descriptor.stage,
                "tool_id": tool_id,
                "outcome": outcome,
                "status": result.status.value if result else None,
                "result_bytes": result_bytes,
                "observed_at": self._now().isoformat(),
            },
        )
