import json
from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_mhs_contract_schemas_are_strict_and_frozen() -> None:
    expected = {
        "MhsReferenceCandidate.schema.json": "rolo-mhs-reference-candidate/v1",
        "MhsManifestReference.schema.json": "rolo-mhs-manifest-reference/v1",
        "MHSReadOnly.schema.json": "rolo-mhs-read-only/v1",
        "ProbeEvidenceView.schema.json": "rolo-probe-evidence-view/v1",
    }
    for name, schema_id in expected.items():
        schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
        assert schema["$id"] == schema_id
        assert schema["additionalProperties"] is False
        assert schema["properties"]["access"]["const"] == "READ_ONLY"


def test_probe_evidence_view_has_zero_write_operations() -> None:
    schema = json.loads((ROOT / "schemas" / "ProbeEvidenceView.schema.json").read_text())
    assert schema["properties"]["write_operations"]["const"] == 0
