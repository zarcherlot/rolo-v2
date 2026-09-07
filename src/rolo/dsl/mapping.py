"""Bounded Coding Agent mapping contract and diagnostics repair loop.

The loop is deliberately an orchestration boundary: the caller supplies a
typed DSL generator, while the compiler remains the only authority for DSL
validity.  No SSH, shell or catalog mutation is available from this module.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import Field

from .api import DslCheckRequest, DslCompileRequest, DslCompileResult
from .canonical import context_digest
from .models import StrictModel
from .service import RoloDslCompiler


class AdapterMappingRequest(StrictModel):
    """Versioned, digest-bound input exposed to a Coding Agent."""

    schema_version: Literal["rolo-adapter-mapping-request/v1"] = "rolo-adapter-mapping-request/v1"
    journey_session_id: str = Field(min_length=1, max_length=256)
    user_goal: str = Field(min_length=1, max_length=2_000)
    context_digest: str = Field(min_length=1)
    available_tool_catalog_digest: str = Field(min_length=1)
    operation_candidates: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    dsl_version: Literal["rolo-dsl/v1"] = "rolo-dsl/v1"


class ProbeFollowUpRequest(StrictModel):
    """Bounded request returned when compilation needs more observed evidence."""

    schema_version: Literal["rolo-probe-follow-up-request/v1"] = "rolo-probe-follow-up-request/v1"
    journey_session_id: str = Field(min_length=1, max_length=256)
    reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_.-]{1,63}$")
    requested_items: tuple[str, ...] = Field(min_length=1, max_length=16)
    context_digest: str = Field(min_length=1)


@dataclass(frozen=True)
class MappingLoopResult:
    status: Literal["PASS", "BLOCKED"]
    dsl: dict[str, Any] | None
    compile_result: DslCompileResult | None
    attempts: int
    diagnostics: tuple[str, ...] = ()
    probe_follow_up: ProbeFollowUpRequest | None = None


_CONTEXT_GAP_CODES = {
    "TARGET_MISMATCH",
    "EVIDENCE_DIGEST_MISMATCH",
    "EVIDENCE_REF_NOT_FOUND",
    "RESOURCE_NOT_OBSERVED",
    "MESSAGE_SCHEMA_NOT_OBSERVED",
}
_REQUIRED_CONTEXT_KEYS = ("robot_id", "target_fingerprint", "evidence_digest")


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

        if any(not isinstance(context.get(key), str) or not context.get(key) for key in _REQUIRED_CONTEXT_KEYS):
            return self._blocked(0, ("CONTEXT_REQUIRED",))
        if context_digest(dict(context)) != request.context_digest:
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
            checked = self.compiler.check(DslCheckRequest(dsl=candidate, context=dict(context)))
            if checked.status == "PASS":
                compile_result: DslCompileResult | None = None
                if output_dir is not None:
                    compile_result = self.compiler.compile(
                        DslCompileRequest(
                            dsl=candidate,
                            context=dict(context),
                            dsl_digest=checked.dsl_digest,
                            context_digest=request.context_digest,
                            target_fingerprint=str(context.get("target_fingerprint", "")),
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
                                ProbeFollowUpRequest(
                                    journey_session_id=request.journey_session_id,
                                    reason_code=gap,
                                    requested_items=self._requested_items(gap, candidate),
                                    context_digest=request.context_digest,
                                ),
                            )
                        continue
                return MappingLoopResult("PASS", candidate, compile_result, attempt, diagnostics)
            diagnostics = tuple(dict.fromkeys((*diagnostics, *checked.diagnostics)))
            gap = next((code for code in diagnostics if code in _CONTEXT_GAP_CODES), None)
            if gap is not None:
                follow_up = ProbeFollowUpRequest(
                    journey_session_id=request.journey_session_id,
                    reason_code=gap,
                    requested_items=self._requested_items(gap, candidate),
                    context_digest=request.context_digest,
                )
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

    @staticmethod
    def _blocked(attempts: int, diagnostics: tuple[str, ...]) -> MappingLoopResult:
        return MappingLoopResult("BLOCKED", None, None, attempts, tuple(dict.fromkeys(diagnostics)))


__all__ = ["AdapterMappingRequest", "DslRepairLoop", "MappingLoopResult", "ProbeFollowUpRequest"]
