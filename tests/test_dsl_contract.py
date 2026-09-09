import pytest
from pydantic import ValidationError

from rolo.dsl import CONTRACT_VERSIONS, DslDocument, OperationKind, contract_manifest
from rolo.dsl.canonical import canonical_json, dsl_digest


def sample() -> DslDocument:
    return DslDocument(
        tool_id="app.navigation.status",
        kind=OperationKind.OBSERVE,
        target={"robot_id": "landerpi", "evidence_digest": "sha256:evidence"},
        binding={"resource_id": "route:/navigation/state"},
        evidence_refs=("route:/navigation/state",),
    )


def test_unknown_fields_are_rejected():
    with pytest.raises(ValidationError):
        DslDocument.model_validate({**sample().model_dump(), "unknown": True})


def test_unsupported_schema_is_rejected():
    with pytest.raises(ValidationError):
        DslDocument.model_validate({**sample().model_dump(), "schema_version": "rolo-dsl/v2"})


def test_digest_is_stable_and_order_independent():
    document = sample()
    reordered = DslDocument.model_validate({"kind": "OBSERVE", "tool_id": document.tool_id, **document.model_dump(exclude={"kind", "tool_id"})})
    assert canonical_json(document) == canonical_json(reordered)
    assert dsl_digest(document) == dsl_digest(reordered)


def test_duplicate_yaml_keys_are_rejected():
    from rolo.dsl.parser import parse_document

    document, report = parse_document(
        "tool_id: app.state\n"
        "tool_id: app.other\n"
        "kind: OBSERVE\n"
        "target:\n"
        "  robot_id: r\n"
        "  evidence_digest: sha256:e\n"
    )
    assert document is None
    assert report.diagnostics[0].code == "DSL_SCHEMA_INVALID"


def test_contract_manifest_covers_cross_component_handoff_versions():
    manifest = contract_manifest()
    assert manifest["versions"] == dict(sorted(CONTRACT_VERSIONS.items()))
    assert {
        "dsl",
        "compile_context",
        "canonical_ir",
        "bundle_plan",
        "compile_request",
        "compile_result",
        "diagnostics",
        "backend_spi",
        "targetd_frame",
        "target_conformance",
        "release_binding",
        "journey_result",
        "mapping_proposal",
        "mapping_confirmation_receipt",
    } <= set(manifest["versions"])
