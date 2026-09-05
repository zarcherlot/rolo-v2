import json
from pathlib import Path

from rolo.targetd import ExecutionBundleManifest, PythonBundleWorker


def test_chassis_rotation_certify_fixture_replays_all_ten_cases():
    fixture = json.loads(Path("examples/chassis-rotation-10.json").read_text(encoding="utf-8"))
    source = b"def execute(arguments):\n    return arguments\n"
    manifest = ExecutionBundleManifest.build(
        tool_id=fixture["tool_id"], source=source, binding_digest="a" * 64,
        signer_key_id="replay", signing_key=b"replay-key",
    )
    results = [PythonBundleWorker().execute(manifest, source, case) for case in fixture["cases"]]
    assert len(results) == 10
    assert [result["case_id"] for result in results] == [case["case_id"] for case in fixture["cases"]]
