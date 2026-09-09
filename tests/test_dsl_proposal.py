import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from rolo.dsl import (
    AdapterMappingRequest,
    MappingProposal,
    build_candidate_index,
    build_mapping_proposal,
    persist_mapping_proposal,
)
from rolo.dsl.admission import (
    MappingAdmissionError,
    MappingAdmissionScope,
    mapping_digest,
)
from rolo.dsl.context import ProbeContext
from rolo.dsl.models import DslDocument


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _context() -> ProbeContext:
    return ProbeContext(
        robot_id="mentorpi",
        target_fingerprint="landerpi-target-fingerprint",
        evidence_digest=_digest("e"),
        evidence_refs=("artifact://probe/evidence",),
        routes=(
            {
                "operation": "app.base.rotate",
                "route_id": "app.base.rotate",
                "resource_id": "route:/base/state",
                "evidence_ref": "artifact://probe/evidence",
            },
        ),
    )


def _dsl(**target_updates: str) -> DslDocument:
    target = {
        "robot_id": "mentorpi",
        "evidence_digest": _digest("e"),
        **target_updates,
    }
    return DslDocument(
        tool_id="app.base.rotate",
        kind="OBSERVE",
        target=target,
        binding={"resource_id": "route:/base/state"},
        evidence_refs=("artifact://probe/evidence",),
    )


def _scope(**updates: object) -> MappingAdmissionScope:
    values = {
        "tool_id": "app.base.rotate",
        "operation_kind": "OBSERVE",
        "operations": ("app.base.rotate",),
        "access": "read",
        "risk": "R0",
        **updates,
    }
    return MappingAdmissionScope.model_validate(values)


def _parts():
    context = _context()
    index = build_candidate_index(context)
    request = AdapterMappingRequest(
        journey_session_id="journey-1",
        user_goal="rotate base",
        context_digest=index.context_digest,
        available_tool_catalog_digest=_digest("c"),
        operation_candidates=("app.base.rotate",),
    )
    return context, index, request, index.candidates[0]


def _proposal() -> MappingProposal:
    context, index, request, candidate = _parts()
    return build_mapping_proposal(
        request,
        index,
        candidate,
        dsl=_dsl(),
        context=context,
        scope=_scope(),
    )


def test_mapping_proposal_v2_is_complete_digest_bound_and_requires_receipt(
    tmp_path: Path,
) -> None:
    proposal = _proposal()

    assert proposal.schema_version == "rolo-mapping-proposal/v2"
    assert proposal.status == "PROPOSED"
    assert proposal.dsl_digest.startswith("sha256:")
    assert proposal.candidate_index_digest.startswith("sha256:")
    assert proposal.candidate_digest.startswith("sha256:")
    assert proposal.proposal_digest == mapping_digest(proposal.display_payload())
    assert proposal.admission_identity().proposal_digest == proposal.proposal_digest
    assert proposal.admission_identity().scope == proposal.scope

    with pytest.raises(
        MappingAdmissionError, match="MAPPING_CONFIRMATION_RECEIPT_REQUIRED"
    ):
        proposal.confirm()
    with pytest.raises(
        MappingAdmissionError, match="MAPPING_CONFIRMATION_RECEIPT_REQUIRED"
    ):
        proposal.reject()

    path = persist_mapping_proposal(proposal, tmp_path)
    assert path == (
        tmp_path
        / "mapping-proposals"
        / f"{proposal.proposal_digest.removeprefix('sha256:')}.json"
    )
    assert persist_mapping_proposal(proposal, tmp_path) == path
    assert MappingProposal.model_validate_json(path.read_text(encoding="utf-8")) == proposal


def test_mapping_proposal_requires_explicit_v2_and_cannot_forge_status() -> None:
    payload = _proposal().model_dump(mode="json")
    payload.pop("schema_version")
    with pytest.raises(ValidationError):
        MappingProposal.model_validate(payload)

    payload = _proposal().model_dump(mode="json")
    payload["status"] = "CONFIRMED"
    with pytest.raises(ValidationError):
        MappingProposal.model_validate(payload)

    payload = _proposal().model_dump(mode="json")
    payload["schema_version"] = "rolo-mapping-proposal/v1"
    with pytest.raises(ValidationError):
        MappingProposal.model_validate(payload)


def test_mapping_proposal_digest_covers_the_complete_display_payload() -> None:
    proposal = _proposal()
    for field, replacement in (
        ("user_goal", "different goal"),
        ("candidate_id", "different-candidate"),
        ("dsl_digest", _digest("d")),
        ("context_digest", _digest("f")),
        ("evidence_refs", ("artifact://probe/different",)),
        ("risks", ("new-risk",)),
    ):
        changed = proposal.model_copy(update={field: replacement})
        assert changed.computed_digest() != proposal.proposal_digest
        with pytest.raises(
            MappingAdmissionError, match="MAPPING_PROPOSAL_DIGEST_MISMATCH"
        ):
            changed.verify()


def test_mapping_proposal_rejects_candidate_outside_request() -> None:
    context, index, request, candidate = _parts()
    request = request.model_copy(update={"operation_candidates": ("app.navigation.run",)})

    with pytest.raises(
        MappingAdmissionError, match="MAPPING_PROPOSAL_CANDIDATE_NOT_REQUESTED"
    ):
        build_mapping_proposal(
            request,
            index,
            candidate,
            dsl=_dsl(),
            context=context,
            scope=_scope(),
        )


def test_mapping_proposal_rejects_candidate_outside_index() -> None:
    context, index, request, candidate = _parts()
    candidate = candidate.model_copy(update={"candidate_id": "forged-candidate"})

    with pytest.raises(
        MappingAdmissionError, match="MAPPING_PROPOSAL_CANDIDATE_NOT_IN_INDEX"
    ):
        build_mapping_proposal(
            request,
            index,
            candidate,
            dsl=_dsl(),
            context=context,
            scope=_scope(),
        )


def test_mapping_proposal_rejects_context_and_dsl_identity_drift() -> None:
    context, index, request, candidate = _parts()
    stale_request = request.model_copy(update={"context_digest": _digest("0")})
    with pytest.raises(
        MappingAdmissionError, match="MAPPING_PROPOSAL_CONTEXT_DIGEST_MISMATCH"
    ):
        build_mapping_proposal(
            stale_request,
            index,
            candidate,
            dsl=_dsl(),
            context=context,
            scope=_scope(),
        )

    with pytest.raises(
        MappingAdmissionError, match="MAPPING_PROPOSAL_DSL_CONTEXT_MISMATCH"
    ):
        build_mapping_proposal(
            request,
            index,
            candidate,
            dsl=_dsl(robot_id="other-target"),
            context=context,
            scope=_scope(),
        )

    different_tool = _dsl().model_copy(update={"tool_id": "app.navigation.run"})
    with pytest.raises(
        MappingAdmissionError, match="MAPPING_PROPOSAL_DSL_CANDIDATE_MISMATCH"
    ):
        build_mapping_proposal(
            request,
            index,
            candidate,
            dsl=different_tool,
            context=context,
            scope=_scope(),
        )


def test_mapping_proposal_rejects_scope_drift() -> None:
    context, index, request, candidate = _parts()
    with pytest.raises(
        MappingAdmissionError, match="MAPPING_PROPOSAL_SCOPE_MISMATCH"
    ):
        build_mapping_proposal(
            request,
            index,
            candidate,
            dsl=_dsl(),
            context=context,
            scope=_scope(tool_id="app.navigation.run", operations=("app.navigation.run",)),
        )


def test_mapping_proposal_persistence_never_overwrites_existing_content(
    tmp_path: Path,
) -> None:
    proposal = _proposal()
    path = persist_mapping_proposal(proposal, tmp_path)
    path.write_text('{"tampered":true}\n', encoding="utf-8")

    with pytest.raises(
        MappingAdmissionError, match="MAPPING_PROPOSAL_IMMUTABLE_CONFLICT"
    ):
        persist_mapping_proposal(proposal, tmp_path)
    assert json.loads(path.read_text(encoding="utf-8")) == {"tampered": True}
