"""Cross-component version and capability rejection checks for the P0 handoff."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from rolo.dsl.api import DslCompileRequest, DslCompileResult
from rolo.dsl.backends import negotiate_backend
from rolo.dsl.context import ProbeContext
from rolo.dsl.contracts import CONTRACT_VERSIONS, contract_manifest
from rolo.dsl.mapping import AdapterMappingRequest, ProbeFollowUpRequest
from rolo.dsl.models import DslDocument
from rolo.releases.journey import PostCompilerJourneyResult
from rolo.releases.publisher import TargetConformanceReport
from rolo.targetd.dsl_protocol import DslCompilePayload, DslFrame, DslPutPayload


def _sample_payloads() -> tuple[tuple[type, dict], ...]:
    return (
        (
            DslDocument,
            {
                "tool_id": "app.state",
                "kind": "OBSERVE",
                "target": {"robot_id": "r", "evidence_digest": "sha256:e"},
            },
        ),
        (
            ProbeContext,
            {
                "robot_id": "r",
                "target_fingerprint": "fp",
                "evidence_digest": "sha256:e",
            },
        ),
        (
            DslCompileRequest,
            {
                "dsl": {},
                "context": {},
                "dsl_digest": "sha256:dsl",
                "context_digest": "sha256:context",
                "target_fingerprint": "fp",
            },
        ),
        (
            DslCompileResult,
            {"status": "BLOCKED", "dsl_digest": "sha256:dsl"},
        ),
        (
            AdapterMappingRequest,
            {
                "journey_session_id": "journey-1",
                "user_goal": "read state",
                "context_digest": "sha256:context",
                "available_tool_catalog_digest": "sha256:catalog",
            },
        ),
        (
            ProbeFollowUpRequest,
            {
                "journey_session_id": "journey-1",
                "reason_code": "RESOURCE_NOT_OBSERVED",
                "requested_items": ["route:/state"],
                "context_digest": "sha256:context",
            },
        ),
        (
            DslFrame,
            {"frame_type": "DSL_CHECK", "request_id": "request-1"},
        ),
        (
            DslPutPayload,
            {
                "dsl": {"tool_id": "app.state", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": "sha256:e"}},
                "context": {"robot_id": "r", "target_fingerprint": "fp", "evidence_digest": "sha256:e"},
                "compiler_version": "rolo-compiler/0.1",
                "dsl_digest": "sha256:dsl",
                "context_digest": "sha256:context",
                "target_fingerprint": "fp",
            },
        ),
        (
            DslCompilePayload,
            {"dsl_digest": "sha256:dsl", "context_digest": "sha256:context", "target_fingerprint": "fp"},
        ),
        (
            TargetConformanceReport,
            {
                "t1_target_resolve": "PASS",
                "t2_bundle_build": "PASS",
                "t3_runtime_behavior": "PASS",
                "t4_release_integrity": "PASS",
                "target_fingerprint": "fp",
            },
        ),
        (
            PostCompilerJourneyResult,
            {
                "status": "PASS",
                "journey_session_id": "journey-1",
                "target_id": "r",
                "dsl_digest": "sha256:dsl",
                "context_digest": "sha256:context",
                "target_compile_status": "PASS",
            },
        ),
    )


def test_contract_manifest_is_backed_by_the_frozen_version_table() -> None:
    manifest = contract_manifest()
    schema = json.loads((Path(__file__).parents[1] / "schemas/rolo-dsl/v1/contract-manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == schema["properties"]["schema_version"]["const"]
    assert manifest["versions"] == dict(sorted(CONTRACT_VERSIONS.items()))
    assert len(manifest["versions"]) >= schema["properties"]["versions"]["minProperties"]


@pytest.mark.parametrize("model,payload", _sample_payloads())
def test_cross_component_models_reject_unknown_schema_versions(model: type, payload: dict) -> None:
    invalid = {**payload, "schema_version": "rolo-unsupported/v9"}
    with pytest.raises(ValidationError):
        model.model_validate(invalid)


def test_backend_capability_matrix_fails_closed() -> None:
    assert negotiate_backend("OBSERVE", backend_id="missing-backend") is None
    assert negotiate_backend("OBSERVE", required_capabilities=("operation:INVOKE",)) is None
    assert negotiate_backend("OBSERVE", required_capabilities=("operation:OBSERVE",)) is not None
