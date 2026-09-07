from pathlib import Path

import pytest

from rolo.dsl import AdapterMappingRequest, build_candidate_index, build_mapping_proposal, persist_mapping_proposal
from rolo.dsl.context import ProbeContext


def test_mapping_proposal_requires_confirmation_and_persists(tmp_path: Path) -> None:
    context = ProbeContext(
        robot_id="mentorpi",
        target_fingerprint="target-fingerprint",
        evidence_digest="evidence-digest",
        evidence_refs=("artifact://probe/evidence",),
        routes=({"operation": "app.base.rotate", "route_id": "app.base.rotate"},),
    )
    index = build_candidate_index(context)
    request = AdapterMappingRequest(
        journey_session_id="journey-1",
        user_goal="rotate base",
        context_digest=index.context_digest,
        available_tool_catalog_digest="catalog-digest",
        operation_candidates=("app.base.rotate",),
    )
    proposal = build_mapping_proposal(request, index, index.candidates[0])
    assert proposal.status == "PROPOSED"
    assert proposal.confirm().status == "CONFIRMED"
    assert persist_mapping_proposal(proposal, tmp_path).is_file()


def test_mapping_proposal_rejects_other_context() -> None:
    context = ProbeContext(robot_id="r", target_fingerprint="t", evidence_digest="e", routes=({"operation": "x"},))
    index = build_candidate_index(context)
    request = AdapterMappingRequest(
        journey_session_id="j",
        user_goal="x",
        context_digest="different",
        available_tool_catalog_digest="c",
    )
    with pytest.raises(ValueError, match="context digest"):
        build_mapping_proposal(request, index, index.candidates[0])
