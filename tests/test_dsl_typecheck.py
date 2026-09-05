from rolo.dsl.models import DslDocument
from rolo.dsl.typecheck import check_types

def test_compose_requires_bounds():
    doc = DslDocument(tool_id="x", kind="COMPOSE", target={"robot_id": "r", "evidence_digest": "sha256:e"}, composition={"steps": []})
    codes = {item.code for item in check_types(doc).diagnostics}
    assert codes == {"COMPOSITION_MAX_STEPS_REQUIRED", "COMPOSITION_MAX_RUNTIME_REQUIRED"}
def test_dynamic_mapping_is_rejected():
    doc = DslDocument(tool_id="x", kind="OBSERVE", target={"robot_id": "r", "evidence_digest": "sha256:e"}, binding={"resource_id": "r"}, mapping={"x": "import subprocess"})
    assert check_types(doc).diagnostics[0].code == "DYNAMIC_EXPRESSION_FORBIDDEN"
