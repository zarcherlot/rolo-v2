import pytest
from pydantic import ValidationError

from rolo.dsl.api import DslCompileRequest, DslCompileResult
from rolo.dsl.contracts import (
    COMPILE_REQUEST_SCHEMA_VERSION,
    COMPILE_RESULT_SCHEMA_VERSION,
)


def test_compile_request_carries_replay_identity():
    request = DslCompileRequest(
        schema_version=COMPILE_REQUEST_SCHEMA_VERSION,
        journey_session_id="journey-1",
        confirmation_receipt_digest="sha256:" + "0" * 64,
        dsl={"tool_id": "x"},
        dsl_digest="sha256:d",
        context_digest="sha256:c",
        target_fingerprint="fp",
    )
    assert request.compiler_version == "rolo-compiler/0.1"
    assert request.target_fingerprint == "fp"
    assert request.journey_session_id == "journey-1"


def test_compile_request_rejects_legacy_or_missing_admission_version():
    payload = {
        "journey_session_id": "journey-1",
        "confirmation_receipt_digest": "sha256:" + "0" * 64,
        "dsl": {"tool_id": "x"},
        "dsl_digest": "sha256:d",
        "context_digest": "sha256:c",
        "target_fingerprint": "fp",
    }
    with pytest.raises(ValidationError):
        DslCompileRequest.model_validate(payload)
    with pytest.raises(ValidationError):
        DslCompileRequest.model_validate({**payload, "schema_version": "rolo-dsl-compile-request/v1"})


def test_compile_result_can_be_serialized():
    result = DslCompileResult(status="PASS", dsl_digest="sha256:d")
    assert result.schema_version == COMPILE_RESULT_SCHEMA_VERSION
    assert result.model_dump()["status"] == "PASS"
    with pytest.raises(ValidationError):
        DslCompileResult.model_validate(
            {
                "schema_version": "rolo-dsl-compile-result/v1",
                "status": "PASS",
                "dsl_digest": "sha256:d",
            }
        )
