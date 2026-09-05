from rolo.dsl.models import DslDocument
from rolo.dsl.typecheck import check_types


def test_compose_cycle_is_rejected():
    doc = DslDocument(
        tool_id="x",
        kind="COMPOSE",
        target={"robot_id": "r", "evidence_digest": "sha256:e"},
        composition={"steps": [{"id": "a", "depends_on": ["b"]}, {"id": "b", "depends_on": ["a"]}], "limits": {"max_steps": 2, "max_runtime_ms": 1000}},
    )
    assert any(item.code == "COMPOSITION_CYCLE" for item in check_types(doc).diagnostics)


def test_compose_step_limit_is_rejected():
    doc = DslDocument(
        tool_id="x", kind="COMPOSE", target={"robot_id": "r", "evidence_digest": "sha256:e"}, composition={"steps": [{"id": "a"}, {"id": "b"}], "limits": {"max_steps": 1, "max_runtime_ms": 1000}}
    )
    assert any(item.code == "COMPOSITION_MAX_STEPS_EXCEEDED" for item in check_types(doc).diagnostics)
