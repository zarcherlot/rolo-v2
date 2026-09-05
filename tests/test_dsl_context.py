from rolo.dsl.context import ProbeContext


def test_probe_context_requires_target_identity():
    context = ProbeContext(robot_id="r", target_fingerprint="fp", evidence_digest="sha256:e", evidence_refs=("route:/state",))
    assert context.schema_version == "rolo-probe-context/v1"
    assert context.target_fingerprint == "fp"
