from pathlib import Path

from rolo.dsl.context import ProbeContext
from rolo.dsl.models import DslDocument
from rolo.dsl.runner import ConformanceRunner


def document():
    return DslDocument(tool_id="x", kind="OBSERVE", target={"robot_id": "r", "evidence_digest": "sha256:e"}, binding={"resource_id": "route:/state"})


def context():
    return ProbeContext(robot_id="r", target_fingerprint="fp", evidence_digest="sha256:e", evidence_refs=("route:/state",))


def test_runner_writes_report_and_passes(tmp_path: Path):
    report = ConformanceRunner(tmp_path).run(document(), context())
    assert report.passed
    assert (tmp_path / "conformance-c1-c4.json").exists()


def test_runner_blocks_forged_route(tmp_path: Path):
    bad = context().model_copy(update={"evidence_refs": ()})
    report = ConformanceRunner(tmp_path).run(document(), bad)
    assert report.c2_evidence == "FAIL"
    assert not report.passed
