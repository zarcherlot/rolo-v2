from rolo.dsl.compiler import compile_document
from rolo.dsl.context import ProbeContext
from rolo.dsl.models import DslDocument
from rolo.dsl.runner import ConformanceRunner
from rolo.releases import CertifyConsumer, ReleasePublisher, TraceConsumer


def setup(tmp_path):
    doc = DslDocument(tool_id="app.test", kind="OBSERVE", target={"robot_id": "r", "evidence_digest": "sha256:e"}, binding={"resource_id": "route:/state"})
    context = ProbeContext(robot_id="r", target_fingerprint="fp", evidence_digest="sha256:e", evidence_refs=("route:/state",))
    result = compile_document(doc, tmp_path / "compile", context=context)
    report = ConformanceRunner(tmp_path / "conf").run(doc, context)
    release = ReleasePublisher(tmp_path / "catalog").publish(result, report, target_fingerprint="fp", compiler_version="rolo-compiler/0.1")
    return release


def test_trace_and_certify_bind_release(tmp_path):
    release = setup(tmp_path)
    trace = TraceConsumer().consume(release, release_digest="sha256:release", session_id="session-1", evidence_digest="sha256:e", target_fingerprint="fp", input={"query": "state"})
    certify = CertifyConsumer().consume(release, release_digest="sha256:release", session_id="session-1", evidence_digest="sha256:e", target_fingerprint="fp", test_case_id="case-1")
    assert trace.consumer == "trace" and certify.test_case_id == "case-1"


def test_consumer_rejects_stale_target(tmp_path):
    release = setup(tmp_path)
    try:
        TraceConsumer().consume(release, release_digest="sha256:release", session_id="s", evidence_digest="sha256:e", target_fingerprint="changed")
    except ValueError as exc:
        assert str(exc) == "TARGET_FINGERPRINT_MISMATCH"
    else:
        raise AssertionError("stale target must be rejected")


def test_consumer_rejects_context_and_mhs_drift(tmp_path):
    release = setup(tmp_path)
    publisher_release = release.model_copy(update={"compile_context_digest": "ctx-1", "mhs_manifest_digests": ("mhs-1",)})
    try:
        TraceConsumer().consume(
            publisher_release,
            release_digest="sha256:release",
            session_id="s",
            evidence_digest="sha256:e",
            target_fingerprint="fp",
            compile_context_digest="ctx-2",
            mhs_manifest_digests=("mhs-1",),
        )
    except ValueError as exc:
        assert str(exc) == "CONTEXT_DIGEST_MISMATCH"
    else:
        raise AssertionError("context drift must be rejected")
    try:
        TraceConsumer().consume(
            publisher_release,
            release_digest="sha256:release",
            session_id="s",
            evidence_digest="sha256:e",
            target_fingerprint="fp",
            compile_context_digest="ctx-1",
            mhs_manifest_digests=("mhs-2",),
        )
    except ValueError as exc:
        assert str(exc) == "MHS_MANIFEST_DIGEST_MISMATCH"
    else:
        raise AssertionError("MHS drift must be rejected")
