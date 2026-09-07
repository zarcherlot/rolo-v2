import hashlib
import json
from pathlib import Path

from rolo.dsl.compiler import compile_document
from rolo.dsl.context import ProbeContext
from rolo.dsl.models import DslDocument
from rolo.dsl.runner import ConformanceRunner
from rolo.releases import ReleasePublisher, TargetConformanceReport, TraceConsumer


def _publish(root: Path, *, target_fingerprint: str, context_digest: str):
    document = DslDocument(
        tool_id="app.test",
        kind="OBSERVE",
        target={"robot_id": "r", "evidence_digest": "sha256:e"},
        binding={"resource_id": "route:/state"},
    )
    context = ProbeContext(
        robot_id="r",
        target_fingerprint=target_fingerprint,
        evidence_digest="sha256:e",
        evidence_refs=("route:/state",),
    )
    result = compile_document(document, root / "compile", context=context)
    report = ConformanceRunner(root / "conformance").run(document, context)
    return ReleasePublisher(root / "catalog").publish(
        result,
        report,
        target_fingerprint=target_fingerprint,
        compiler_version="rolo-compiler/0.1",
        compile_context_digest=context_digest,
        route_digest="route-digest-1",
    )


def test_release_current_load_stale_reasons_and_rollback(tmp_path):
    first = _publish(tmp_path / "first", target_fingerprint="a" * 64, context_digest="ctx-1")
    second = _publish(tmp_path / "second", target_fingerprint="b" * 64, context_digest="ctx-2")

    # Both publishers write to their own roots; copy the immutable manifests
    # into one catalog to exercise the lifecycle API without mutating them.
    root = tmp_path / "combined"
    (root / "catalog" / "releases").mkdir(parents=True)
    for release in (first, second):
        digest = "sha256:" + hashlib.sha256(json.dumps(release.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()
        source = tmp_path / ("first" if release is first else "second") / "catalog" / "releases" / f"{digest.removeprefix('sha256:')}.json"
        (root / "catalog" / "releases" / source.name).write_bytes(source.read_bytes())
    publisher = ReleasePublisher(root / "catalog")
    first_digest = "sha256:" + hashlib.sha256(json.dumps(first.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()
    publisher.rollback("app.test", first_digest)
    current = publisher.current("app.test")
    assert current is not None and current[1].target_fingerprint == "a" * 64
    stale_release = publisher.mark_stale("app.test", ("CONTEXT_DIGEST_CHANGED", "CONTEXT_DIGEST_CHANGED"))
    assert stale_release.status == "STALE" and not stale_release.agent_callable
    assert publisher.current("app.test")[1].status == "STALE"
    assert publisher._read_catalog()["tools"]["app.test"]["status"] == "STALE"
    try:
        TraceConsumer().consume(stale_release, release_digest="sha256:release", session_id="s", evidence_digest="sha256:e", target_fingerprint="a" * 64)
    except ValueError as exc:
        assert str(exc) == "RELEASE_NOT_PUBLISHED"
    else:
        raise AssertionError("stale release must not be consumed")
    assert publisher.stale(
        current[1],
        target_fingerprint="b" * 64,
        evidence_digest="sha256:e",
        compiler_version="rolo-compiler/0.1",
        compile_context_digest="ctx-2",
        route_digest="route-digest-2",
        mhs_manifest_digests=("mhs-2",),
    )
    assert "CONTEXT_DIGEST_CHANGED" in publisher.stale_reasons(
        current[1],
        target_fingerprint="a" * 64,
        evidence_digest="sha256:e",
        compiler_version="rolo-compiler/0.1",
        compile_context_digest="ctx-2",
    )


def test_publish_verified_requires_all_target_gates(tmp_path):
    document = DslDocument(
        tool_id="app.test",
        kind="OBSERVE",
        target={"robot_id": "r", "evidence_digest": "sha256:e"},
        binding={"resource_id": "route:/state"},
    )
    context = ProbeContext(robot_id="r", target_fingerprint="fp", evidence_digest="sha256:e", evidence_refs=("route:/state",))
    result = compile_document(document, tmp_path / "compile", context=context)
    compiler_report = ConformanceRunner(tmp_path / "conformance").run(document, context)
    publisher = ReleasePublisher(tmp_path / "catalog")
    failed = TargetConformanceReport(
        t1_target_resolve="PASS", t2_bundle_build="FAIL", t3_runtime_behavior="PASS", t4_release_integrity="PASS", target_fingerprint="fp"
    )
    try:
        publisher.publish_verified(result, compiler_report, failed, target_fingerprint="fp", compiler_version="rolo-compiler/0.1")
    except ValueError as exc:
        assert str(exc) == "RELEASE_TARGET_CONFORMANCE_FAILED"
    else:
        raise AssertionError("failed target conformance must not publish")
    passed = failed.model_copy(update={"t2_bundle_build": "PASS"})
    release = publisher.publish_verified(result, compiler_report, passed, target_fingerprint="fp", compiler_version="rolo-compiler/0.1")
    assert release.target_conformance_digest and release.status == "PUBLISHED"
