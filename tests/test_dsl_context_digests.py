from rolo.dsl import ContextLayerDigests, context_layer_digests, evaluate_context_change
from rolo.dsl.context import ProbeContext


def context(**updates):
    value = ProbeContext(
        robot_id="r",
        target_fingerprint="target",
        runtime_revision="humble",
        evidence_digest="e1",
        routes=({"operation": "app.base.rotate"},),
        freshness={"collected_at": "t1"},
    )
    return value.model_copy(update=updates)


def test_layered_digests_only_change_affected_layers() -> None:
    first = context_layer_digests(context())
    second = context_layer_digests(context(runtime_revision="humble-2"))
    report = evaluate_context_change(first, second)
    assert report.status == "DIRTY"
    assert report.changed_layers == ("runtime",)
    assert report.dirty_namespaces == ("runtime",)


def test_clean_context_change_and_model_validation() -> None:
    first = context_layer_digests(context())
    assert evaluate_context_change(first, first).status == "CLEAN"
    assert ContextLayerDigests.model_validate(first.model_dump()).evidence_digest == first.evidence_digest
