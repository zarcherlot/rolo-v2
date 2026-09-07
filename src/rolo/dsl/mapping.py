"""Bounded Coding Agent mapping contract and diagnostics repair loop.

The loop is deliberately an orchestration boundary: the caller supplies a
typed DSL generator, while the compiler remains the only authority for DSL
validity.  No SSH, shell or catalog mutation is available from this module.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import Field

from .api import DslCheckRequest, DslCompileRequest, DslCompileResult
from .candidates import CapabilityCandidateIndex, build_candidate_index, query_candidates
from .canonical import context_digest
from .context import ProbeContext
from .contracts import MAPPING_REQUEST_SCHEMA_VERSION, PROBE_FOLLOW_UP_SCHEMA_VERSION
from .models import StrictModel
from .service import RoloDslCompiler


class AdapterMappingRequest(StrictModel):
    """Versioned, digest-bound input exposed to a Coding Agent."""

    schema_version: Literal["rolo-adapter-mapping-request/v1"] = MAPPING_REQUEST_SCHEMA_VERSION
    journey_session_id: str = Field(min_length=1, max_length=256)
    user_goal: str = Field(min_length=1, max_length=2_000)
    context_digest: str = Field(min_length=1)
    available_tool_catalog_digest: str = Field(min_length=1)
    operation_candidates: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    dsl_version: Literal["rolo-dsl/v1"] = "rolo-dsl/v1"


class ProbeFollowUpRequest(StrictModel):
    """Bounded request returned when compilation needs more observed evidence."""

    schema_version: Literal["rolo-probe-follow-up-request/v1"] = PROBE_FOLLOW_UP_SCHEMA_VERSION
    journey_session_id: str = Field(min_length=1, max_length=256)
    reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_.-]{1,63}$")
    requested_items: tuple[str, ...] = Field(min_length=1, max_length=16)
    context_digest: str = Field(min_length=1)
    max_attempts: int = Field(default=1, ge=1, le=32)
    max_artifacts: int = Field(default=1, ge=1, le=128)
    deadline_at: datetime | None = None


@dataclass(frozen=True)
class MappingLoopResult:
    status: Literal["PASS", "BLOCKED"]
    dsl: dict[str, Any] | None
    compile_result: DslCompileResult | None
    attempts: int
    diagnostics: tuple[str, ...] = ()
    probe_follow_up: ProbeFollowUpRequest | None = None


_CONTEXT_GAP_CODES = {
    "EVIDENCE_REF_NOT_FOUND",
    "RESOURCE_NOT_OBSERVED",
    "MESSAGE_SCHEMA_NOT_OBSERVED",
    "MHS_MANIFEST_NOT_REFERENCED",
}


class DslRepairLoop:
    """Run a generator/diagnostic repair loop with hard resource limits."""

    def __init__(
        self,
        generator: Callable[[AdapterMappingRequest, tuple[str, ...]], Mapping[str, Any]],
        *,
        compiler: RoloDslCompiler | None = None,
        max_attempts: int = 4,
        max_artifacts: int = 16,
        timeout_s: float = 120.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not 1 <= max_attempts <= 32:
            raise ValueError("max_attempts must be between 1 and 32")
        if not 1 <= max_artifacts <= 128:
            raise ValueError("max_artifacts must be between 1 and 128")
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        self.generator = generator
        self.compiler = compiler or RoloDslCompiler()
        self.max_attempts = max_attempts
        self.max_artifacts = max_artifacts
        self.timeout_s = timeout_s
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def run(
        self,
        request: AdapterMappingRequest,
        *,
        context: Mapping[str, Any],
        output_dir: str | None = None,
    ) -> MappingLoopResult:
        """Generate and repair DSL until PASS or a bounded BLOCKED result."""

        try:
            context_model = ProbeContext.model_validate(context)
        except ValueError:
            # A mapping loop cannot safely ask an Agent to repair a missing or
            # malformed Context.  The caller must complete the bounded Probe
            # handoff first; do not spend an attempt on an unverifiable DSL.
            return MappingLoopResult(
                status="BLOCKED",
                dsl=None,
                compile_result=None,
                attempts=0,
                diagnostics=("CONTEXT_REQUIRED",),
            )
        normalized_context = context_model.model_dump(mode="python")
        if context_digest(normalized_context) != request.context_digest:
            return MappingLoopResult(
                status="BLOCKED",
                dsl=None,
                compile_result=None,
                attempts=0,
                diagnostics=("CONTEXT_DIGEST_MISMATCH",),
            )
        started = self.clock()
        diagnostics: tuple[str, ...] = ()
        generated = 0
        for attempt in range(1, self.max_attempts + 1):
            if self.clock() - started > timedelta(seconds=self.timeout_s):
                return self._blocked(attempt - 1, diagnostics + ("MAPPING_TIMEOUT",))
            if generated >= self.max_artifacts:
                return self._blocked(attempt - 1, diagnostics + ("MAPPING_ARTIFACT_LIMIT",))
            try:
                candidate = dict(self.generator(request, diagnostics))
            except Exception as exc:
                return self._blocked(attempt, diagnostics + (f"GENERATOR_{type(exc).__name__.upper()}",))
            generated += 1
            checked = self.compiler.check(DslCheckRequest(dsl=candidate, context=normalized_context))
            if checked.status == "PASS":
                compile_result: DslCompileResult | None = None
                if output_dir is not None:
                    compile_result = self.compiler.compile(
                        DslCompileRequest(
                            dsl=candidate,
                            context=normalized_context,
                            dsl_digest=checked.dsl_digest,
                            context_digest=request.context_digest,
                            target_fingerprint=context_model.target_fingerprint,
                        ),
                        output_dir,
                    )
                    if compile_result.status != "PASS":
                        diagnostics = tuple(dict.fromkeys(compile_result.diagnostics))
                        gap = next((code for code in diagnostics if code in _CONTEXT_GAP_CODES), None)
                        if gap is not None:
                            return MappingLoopResult(
                                "BLOCKED",
                                candidate,
                                compile_result,
                                attempt,
                                diagnostics,
                                self._follow_up(request, gap, candidate),
                            )
                        continue
                return MappingLoopResult("PASS", candidate, compile_result, attempt, diagnostics)
            diagnostics = tuple(dict.fromkeys((*diagnostics, *checked.diagnostics)))
            gap = next((code for code in diagnostics if code in _CONTEXT_GAP_CODES), None)
            if gap is not None:
                follow_up = self._follow_up(request, gap, candidate)
                return MappingLoopResult("BLOCKED", candidate, checked, attempt, diagnostics, follow_up)
        return self._blocked(self.max_attempts, diagnostics)

    @staticmethod
    def _requested_items(code: str, dsl: Mapping[str, Any]) -> tuple[str, ...]:
        binding = dsl.get("binding") if isinstance(dsl.get("binding"), Mapping) else {}
        if code == "MESSAGE_SCHEMA_NOT_OBSERVED":
            value = binding.get("message_schema")
            return (str(value),) if value else ("message_schema",)
        value = binding.get("resource_id")
        return (str(value),) if value else ("route",)

    def _follow_up(self, request: AdapterMappingRequest, code: str, dsl: Mapping[str, Any]) -> ProbeFollowUpRequest:
        return ProbeFollowUpRequest(
            journey_session_id=request.journey_session_id,
            reason_code=code,
            requested_items=self._requested_items(code, dsl),
            context_digest=request.context_digest,
            max_attempts=1,
            max_artifacts=1,
            deadline_at=self.clock() + timedelta(seconds=min(self.timeout_s, 60.0)),
        )

    @staticmethod
    def _blocked(attempts: int, diagnostics: tuple[str, ...]) -> MappingLoopResult:
        return MappingLoopResult("BLOCKED", None, None, attempts, tuple(dict.fromkeys(diagnostics)))


def build_mapping_request(
    *,
    journey_session_id: str,
    user_goal: str,
    context: ProbeContext | Mapping[str, Any],
    candidate_index: CapabilityCandidateIndex | None = None,
    available_tool_catalog_digest: str | None = None,
    limit: int = 64,
) -> AdapterMappingRequest:
    """Build the Agent envelope from one digest-verified Context and index.

    The helper intentionally accepts only a typed/read-only candidate index;
    it cannot discover new routes, mutate a catalog, or open a target
    connection.  When no catalog digest is supplied, a deterministic digest
    of the Context's published-tool projection is used for offline replay.
    """

    context_model = context if isinstance(context, ProbeContext) else ProbeContext.model_validate(context)
    index = candidate_index or build_candidate_index(context_model)
    index.verify()
    expected_context_digest = context_digest(context_model)
    if index.context_digest != expected_context_digest:
        raise ValueError("CONTEXT_DIGEST_MISMATCH")
    if not 1 <= limit <= 64:
        raise ValueError("limit must be between 1 and 64")
    matches = query_candidates(index, user_goal, limit=limit)
    catalog_digest = available_tool_catalog_digest or _published_tools_digest(context_model)
    return AdapterMappingRequest(
        journey_session_id=journey_session_id,
        user_goal=user_goal,
        context_digest=expected_context_digest,
        available_tool_catalog_digest=catalog_digest,
        operation_candidates=tuple(item.operation for item in matches),
    )


def _published_tools_digest(context: ProbeContext) -> str:
    payload = json.dumps(
        context.published_tools,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


build_adapter_mapping_request = build_mapping_request


__all__ = [
    "AdapterMappingRequest",
    "DslRepairLoop",
    "MappingLoopResult",
    "ProbeFollowUpRequest",
    "build_adapter_mapping_request",
    "build_mapping_request",
]
