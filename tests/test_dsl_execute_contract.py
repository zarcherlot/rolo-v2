from rolo.dsl.models import DslDocument
from rolo.dsl.source_bundle import SourceBundleManifest
from rolo.dsl.typecheck import check_types


def test_execute_source_bundle_contract():
    doc = DslDocument(
        tool_id="x",
        kind="EXECUTE",
        target={"robot_id": "r", "evidence_digest": "sha256:e"},
        implementation={"source_bundle_digest": "sha256:source", "entrypoint": "main:run", "runtime": "python3.12", "implementation_contract": "v1"},
    )
    assert check_types(doc).ok
    manifest = SourceBundleManifest(source_bundle_digest="sha256:source", entrypoint="main:run", runtime="python3.12", implementation_contract="v1")
    assert manifest.schema_version == "rolo-source-bundle/v1"


def test_execute_requires_source_bundle_fields():
    doc = DslDocument(tool_id="x", kind="EXECUTE", target={"robot_id": "r", "evidence_digest": "sha256:e"}, implementation={})
    assert len(check_types(doc).diagnostics) == 4
