from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_harness_codegen_skill_prepares_arguments_before_transport() -> None:
    skill = (ROOT / "skills" / "rolo-harness-codegen" / "SKILL.md").read_text(encoding="utf-8")
    schema = (ROOT / "skills" / "rolo-harness-codegen" / "references" / "output-schema.md").read_text(encoding="utf-8")

    assert "rolo-harness-codegen" in skill
    assert "typed arguments" in skill
    assert "hand-copy" in skill
    assert "CODEGEN_INPUT_GAP" in skill
    assert '"angle_degrees": 360' in schema
    assert '"max_speed_rad_s": 0.2' in schema
    assert "binding_sha256" in schema
