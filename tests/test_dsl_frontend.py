from rolo.dsl.frontend import compile_frontend
from rolo.dsl.parser import parse_document
def test_frontend_lowers_observe_to_stable_ir():
    document, report = parse_document("""schema_version: rolo-dsl/v1
tool_id: app.navigation.status
kind: OBSERVE
target:
  robot_id: landerpi
  evidence_digest: sha256:evidence
binding:
  resource_id: route:/navigation/state
""")
    assert report.ok and document is not None
    ir, diagnostics, digest = compile_frontend(document)
    assert diagnostics.ok and ir is not None
    assert ir.kind == "OBSERVE"
    assert digest.startswith("sha256:")
def test_frontend_rejects_missing_observe_binding():
    document, report = parse_document({"tool_id": "x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": "sha256:e"}})
    assert report.ok and document is not None
    ir, diagnostics, _ = compile_frontend(document)
    assert ir is None
    assert diagnostics.diagnostics[0].code == "BINDING_REQUIRED"
