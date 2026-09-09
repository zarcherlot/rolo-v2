"""Typed DSL protocol frames exchanged with targetd."""

from typing import Any, Literal

from pydantic import Field

from rolo._compat import StrEnum
from rolo.dsl.contracts import TARGETD_FRAME_SCHEMA_VERSION, TARGETD_PUT_SCHEMA_VERSION
from rolo.dsl.models import StrictModel


class DslFrameType(StrEnum):
    DSL_PUT = "DSL_PUT"
    DSL_CHECK = "DSL_CHECK"
    PLAN_RESOLVE = "PLAN_RESOLVE"
    TARGET_COMPILE = "TARGET_COMPILE"
    TARGET_CONFORMANCE = "TARGET_CONFORMANCE"
    DSL_COMPILE = "DSL_COMPILE"
    DSL_EVENT = "DSL_EVENT"
    DSL_RESULT = "DSL_RESULT"


class DslFrame(StrictModel):
    schema_version: Literal["rolo-targetd-dsl-frame/v1"] = TARGETD_FRAME_SCHEMA_VERSION
    frame_type: DslFrameType
    request_id: str = Field(min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)


class DslPutPayload(StrictModel):
    schema_version: Literal["rolo-targetd-dsl-put/v1"] = TARGETD_PUT_SCHEMA_VERSION
    journey_session_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    )
    dsl: dict[str, Any]
    context: dict[str, Any]
    compiler_version: str = Field(min_length=1, max_length=128)
    dsl_digest: str
    context_digest: str
    target_fingerprint: str
    dsl_schema_version: str | None = None
    context_schema_version: str | None = None


class DslCompilePayload(StrictModel):
    schema_version: Literal["rolo-targetd-dsl-compile/v2"]
    journey_session_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    )
    confirmation_receipt_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    dsl_digest: str
    context_digest: str
    target_fingerprint: str
    backend_hint: str | None = None
    runtime_backend_hint: str | None = None
    required_capabilities: tuple[str, ...] = Field(default=(), max_length=32)
    required_runtime_capabilities: tuple[str, ...] = Field(default=(), max_length=32)
    source_bundle_digest: str | None = None
    source_bundle_manifest: dict[str, Any] | None = Field(default=None, max_length=32)
    source_bundle_source: str | None = Field(default=None, max_length=1_000_000)


class DslResultPayload(StrictModel):
    status: str
    dsl_digest: str
    ir_digest: str | None = None
    bundle_digest: str | None = None
    conformance_digest: str | None = None
    diagnostics: tuple[str, ...] = ()
    cache_hit: bool = False
