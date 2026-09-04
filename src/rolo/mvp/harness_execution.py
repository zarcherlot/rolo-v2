"""Generic, ephemeral Agent Harness code execution on a target."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class HarnessCodeBundle(BaseModel):
    """A bounded source bundle produced by the interactive Harness."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-harness-code-bundle/v1"] = "rolo-harness-code-bundle/v1"
    tool_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    runtime: Literal["python"] = "python"
    entrypoint: str = Field(default="execute", pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
    source: str = Field(min_length=1, max_length=128_000)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    request: dict[str, Any] = Field(default_factory=dict, max_length=32)

    @field_validator("source")
    @classmethod
    def reject_nul(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("Harness source must not contain NUL bytes")
        return value

    @model_validator(mode="after")
    def verify_source_digest(self) -> HarnessCodeBundle:
        actual = hashlib.sha256(self.source.encode("utf-8")).hexdigest()
        if actual != self.source_sha256:
            raise ValueError("Harness source_sha256 does not match source")
        return self


def make_code_bundle(*, tool_id: str, source: str, request: dict[str, Any], entrypoint: str = "execute") -> HarnessCodeBundle:
    return HarnessCodeBundle(
        tool_id=tool_id,
        source=source,
        source_sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
        request=request,
        entrypoint=entrypoint,
    )


def build_python_launcher(bundle: HarnessCodeBundle) -> str:
    source_b64 = base64.b64encode(bundle.source.encode("utf-8")).decode("ascii")
    request_json = json.dumps(bundle.request, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    request_b64 = base64.b64encode(request_json.encode("utf-8")).decode("ascii")
    return (
        "import base64,json\n"
        f"source=base64.b64decode({source_b64!r}).decode('utf-8')\n"
        f"request=json.loads(base64.b64decode({request_b64!r}))\n"
        "namespace={}\n"
        "exec(compile(source,'<rolo-harness>','exec'),namespace,namespace)\n"
        f"result=namespace[{bundle.entrypoint!r}](request)\n"
        "print(json.dumps(result,ensure_ascii=False,separators=(',',':')),flush=True)\n"
    )


class HarnessCodeExecutor:
    def __init__(self, target_executor: Any) -> None:
        self.target_executor = target_executor

    def execute(self, bundle: HarnessCodeBundle, *, timeout_s: float) -> dict[str, Any]:
        if not 1 <= timeout_s <= 300:
            return {"status": "BLOCKED", "error": "INVALID_EXECUTION_TIMEOUT"}
        try:
            completed = self.target_executor.run_transient_code(
                build_python_launcher(bundle), timeout_s=timeout_s
            )
            if completed.returncode != 0:
                return {
                    "status": "UNKNOWN",
                    "error": "HARNESS_CODE_FAILED",
                    "returncode": completed.returncode,
                    "stderr": completed.stderr,
                    "source_sha256": bundle.source_sha256,
                }
            result = json.loads(completed.stdout)
            if not isinstance(result, dict):
                raise ValueError("Harness result must be a JSON object")
            return {**result, "source_sha256": bundle.source_sha256}
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return {"status": "UNKNOWN", "error": type(exc).__name__, "source_sha256": bundle.source_sha256}


__all__ = ["HarnessCodeBundle", "HarnessCodeExecutor", "build_python_launcher", "make_code_bundle"]
