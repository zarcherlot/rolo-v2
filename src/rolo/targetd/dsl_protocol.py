"""Typed DSL protocol frames exchanged with targetd."""

from typing import Any

from pydantic import Field

from rolo._compat import StrEnum
from rolo.dsl.models import StrictModel


class DslFrameType(StrEnum):
    DSL_PUT = "DSL_PUT"
    DSL_CHECK = "DSL_CHECK"
    DSL_COMPILE = "DSL_COMPILE"
    DSL_EVENT = "DSL_EVENT"
    DSL_RESULT = "DSL_RESULT"


class DslFrame(StrictModel):
    frame_type: DslFrameType
    request_id: str = Field(min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)


class DslPutPayload(StrictModel):
    dsl: dict[str, Any]
    context: dict[str, Any]
    compiler_version: str
    dsl_digest: str
    context_digest: str
    target_fingerprint: str


class DslCompilePayload(StrictModel):
    dsl_digest: str
    context_digest: str
    target_fingerprint: str
    backend_hint: str | None = None
    source_bundle_digest: str | None = None


class DslResultPayload(StrictModel):
    status: str
    dsl_digest: str
    ir_digest: str | None = None
    bundle_digest: str | None = None
    conformance_digest: str | None = None
    diagnostics: tuple[str, ...] = ()
    cache_hit: bool = False
