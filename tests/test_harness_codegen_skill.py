from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_harness_codegen_skill_prepares_arguments_before_transport() -> None:
    skill = (ROOT / "skills" / "rolo-harness-codegen" / "SKILL.md").read_text(encoding="utf-8")
    schema = (ROOT / "skills" / "rolo-harness-codegen" / "references" / "output-schema.md").read_text(encoding="utf-8")

    assert "rolo-harness-codegen" in skill
    assert "descriptor" in skill
    assert "isomorphic function" in skill
    assert "manually rebuild" in skill
    assert "CODEGEN_INPUT_GAP" in skill
    assert '"<parameter.name>"' in schema
    assert "observation_contract" in schema
    assert "binding_sha256" in schema
    assert "app.base.rotate" not in skill
