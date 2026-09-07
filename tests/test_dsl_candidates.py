from pathlib import Path

from rolo.dsl import build_candidate_index, persist_candidate_index, query_candidates
from rolo.dsl.context import ProbeContext


def context() -> ProbeContext:
    return ProbeContext(
        robot_id="mentorpi",
        target_fingerprint="target-fingerprint",
        evidence_digest="evidence-digest",
        evidence_refs=("artifact://probe/evidence",),
        routes=(
            {"route_id": "app.mapping.run", "operation": "app.mapping.run"},
            {"route_id": "app.base.rotate", "operation": "app.base.rotate"},
        ),
        freshness={"collected_at": "2026-09-06T00:00:00Z"},
    )


def test_candidate_index_is_observed_only_and_query_is_deterministic(tmp_path: Path) -> None:
    index = build_candidate_index(context())
    index.verify()
    assert [item.operation for item in query_candidates(index, "完成 base rotate")] == ["app.base.rotate"]
    assert all(item.evidence_refs == ("artifact://probe/evidence",) for item in index.candidates)
    assert persist_candidate_index(index, tmp_path).name == "candidate-index.json"


def test_candidate_index_does_not_invent_records() -> None:
    empty = context().model_copy(update={"routes": (), "published_tools": ()})
    assert build_candidate_index(empty).candidates == ()
