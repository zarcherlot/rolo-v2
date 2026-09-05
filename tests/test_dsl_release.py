from pathlib import Path

from rolo.dsl.compiler import compile_document
from rolo.dsl.context import ProbeContext
from rolo.dsl.models import DslDocument
from rolo.dsl.runner import ConformanceRunner
from rolo.releases import ReleasePublisher


def doc():
    return DslDocument(tool_id="app.test", kind="OBSERVE", target={"robot_id": "r", "evidence_digest": "sha256:e"}, binding={"resource_id": "route:/state"})


def ctx():
    return ProbeContext(robot_id="r", target_fingerprint="fp", evidence_digest="sha256:e", evidence_refs=("route:/state",))


def test_publish_writes_release_and_catalog(tmp_path: Path):
    d, c = doc(), ctx()
    result = compile_document(d, tmp_path / "compile", context=c)
    report = ConformanceRunner(tmp_path / "conf").run(d, c)
    release = ReleasePublisher(tmp_path / "catalog").publish(result, report, target_fingerprint="fp", compiler_version="rolo-compiler/0.1")
    assert release.status == "PUBLISHED"
    assert (tmp_path / "catalog" / "tool-catalog.json").exists()


def test_publish_rejects_failed_conformance(tmp_path: Path):
    d, c = doc(), ctx()
    result = compile_document(d, tmp_path / "compile", context=c)
    report = ConformanceRunner(tmp_path / "conf").run(d, c).model_copy(update={"c4_behavior": "FAIL"})
    try:
        ReleasePublisher(tmp_path / "catalog").publish(result, report, target_fingerprint="fp", compiler_version="rolo-compiler/0.1")
    except ValueError as exc:
        assert str(exc) == "RELEASE_CONFORMANCE_FAILED"
    else:
        raise AssertionError("failed conformance must not publish")
