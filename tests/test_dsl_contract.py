import pytest
from pydantic import ValidationError

from rolo.dsl import DslDocument, OperationKind
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
