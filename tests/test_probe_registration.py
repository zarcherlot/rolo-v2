from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from rolo.agent_tools.native_tools import (
    AgentNativeToolDescriptor,
    NativeToolInvocation,
    NativeToolParameter,
)
from rolo.dsl.admission import (
    MappingAdmissionError,
    MappingAdmissionScope,
    MappingConfirmationReceipt,
    MappingConfirmationStore,
    mapping_digest,
)
from rolo.dsl.candidates import build_candidate_index
from rolo.dsl.context import ProbeContext
from rolo.dsl.mapping import AdapterMappingRequest
from rolo.dsl.proposal import MappingProposal, build_mapping_proposal
from rolo.mvp.probe_registration import (
    ExecutionBinding,
    ToolRegistrationProposal,
    build_probe_analysis_input,
    load_registered_bindings,
    load_registered_codegen_artifact,
    load_registered_descriptors,
    load_registered_proposals,
    register_tool_proposal,
)

NOW = datetime(2026, 9, 8, 4, 0, tzinfo=timezone.utc)
TARGET_ID = "mentorpi"
TARGET_FINGERPRINT = "mentorpi-fingerprint"
TOOL_ID = "app.base.rotate"
EVIDENCE_DIGEST = "sha256:" + "e" * 64
EVIDENCE_REF = "target-evidence:abc"


@dataclass(frozen=True)
class _MappingAuthority:
    proposal: MappingProposal
    dsl: dict[str, Any]
    store: MappingConfirmationStore
    receipt: MappingConfirmationReceipt


def _descriptor(tool_id: str = TOOL_ID) -> AgentNativeToolDescriptor:
    return AgentNativeToolDescriptor(
        tool_id=tool_id,
        family="application",
        execution_path="DIRECT_RUNNER",
        executable="python3",
        argv_template=["python3"],
        access="experimental_write",
        risk="R3",
        max_duration_s=30,
        max_output_bytes=100_000,
        evidence_kind="application_rotation",
        parameters=[
            NativeToolParameter(
                name="angle_degrees",
                kind="token",
                pattern=r"-?[0-9]{1,3}(\.[0-9]+)?",
            )
        ],
        variants={
            "execute": NativeToolInvocation(
                executable="python3",
                argv_template=["python3", "-c", "print('rotation')", "{angle_degrees}"],
                required_parameters=["angle_degrees"],
            )
        },
    )


def _registration_proposal(
    *,
    descriptor: AgentNativeToolDescriptor | None = None,
    evidence_ref: str = EVIDENCE_REF,
    **updates: object,
) -> ToolRegistrationProposal:
    effective_descriptor = descriptor or _descriptor()
    return ToolRegistrationProposal(
        target_id=TARGET_ID,
        tool_id=effective_descriptor.tool_id,
        evidence_refs=[evidence_ref],
        descriptor=effective_descriptor,
        created_at=NOW,
        **updates,
    )


def _descriptor_digest(descriptor: AgentNativeToolDescriptor) -> str:
    encoded = json.dumps(
        descriptor.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _mapping_authority(
    root: Path,
    *,
    name: str = "primary",
    tool_id: str = TOOL_ID,
    target_id: str = TARGET_ID,
    target_fingerprint: str = TARGET_FINGERPRINT,
    journey_session_id: str = "journey-1",
    user_goal: str = "rotate the base",
    access: str = "experimental_write",
    risk: str = "R3",
    registration_proposal: ToolRegistrationProposal | None = None,
) -> _MappingAuthority:
    executable = registration_proposal or _registration_proposal(
        descriptor=_descriptor(tool_id)
    )
    assert executable.tool_id == tool_id
    context = ProbeContext(
        robot_id=target_id,
        target_fingerprint=target_fingerprint,
        evidence_digest=EVIDENCE_DIGEST,
        evidence_refs=(EVIDENCE_REF,),
        routes=(
            {
                "candidate_id": f"candidate:{tool_id}",
                "operation": tool_id,
                "resource_id": "ros_topic:/cmd_vel",
                "evidence_ref": EVIDENCE_REF,
                "confidence": 1.0,
            },
        ),
    )
    index = build_candidate_index(context)
    candidate = index.candidates[0]
    request = AdapterMappingRequest(
        journey_session_id=journey_session_id,
        user_goal=user_goal,
        context_digest=index.context_digest,
        available_tool_catalog_digest=mapping_digest({"catalog": tool_id}),
        operation_candidates=(tool_id,),
    )
    dsl = {
        "tool_id": tool_id,
        "kind": "INVOKE",
        "target": {
            "robot_id": target_id,
            "evidence_digest": EVIDENCE_DIGEST,
        },
        "binding": {
            "operation": tool_id,
            "registration_proposal_digest": "sha256:" + executable.digest(),
            "descriptor_digest": _descriptor_digest(executable.descriptor),
            "implementation_kind": executable.implementation,
            "binding_digest": (
                "sha256:" + executable.binding.digest()
                if executable.binding is not None
                else None
            ),
        },
        "evidence_refs": [EVIDENCE_REF],
    }
    scope = MappingAdmissionScope(
        tool_id=tool_id,
        operation_kind="INVOKE",
        operations=(tool_id,),
        access=access,
        risk=risk,
    )
    proposal = build_mapping_proposal(
        request,
        index,
        candidate,
        dsl=dsl,
        context=context,
        scope=scope,
    )
    store = MappingConfirmationStore(root / f"authority-{name}", clock=lambda: NOW)
    receipt = store.confirm(
        proposal.admission_identity(),
        decision_id=f"decision-{name}",
        actor_id="test-operator",
        ttl_s=900,
        decided_at=NOW,
    )
    return _MappingAuthority(proposal=proposal, dsl=dsl, store=store, receipt=receipt)


def _register(
    proposal: ToolRegistrationProposal,
    authority: _MappingAuthority,
    registry_root: Path,
    **updates: object,
):
    values = {
        "target_id": TARGET_ID,
        "evidence_refs": {EVIDENCE_REF},
        "registry_root": registry_root,
        "mapping_proposal": authority.proposal,
        "mapping_dsl": authority.dsl,
        "confirmation_store": authority.store,
        "confirmation_receipt_digest": authority.receipt.receipt_digest,
        "journey_session_id": authority.proposal.journey_session_id,
        "target_fingerprint": authority.proposal.target_fingerprint,
    }
    values.update(updates)
    return register_tool_proposal(proposal, **values)


def _load_kwargs(authority: _MappingAuthority) -> dict[str, object]:
    return {
        "confirmation_store": authority.store,
        "target_fingerprint": authority.proposal.target_fingerprint,
    }


def _binding() -> ExecutionBinding:
    return ExecutionBinding(
        kind="ros2_topic",
        command_endpoint="/cmd_vel",
        interface_type="geometry_msgs/msg/Twist",
        feedback_endpoints=["/odom"],
        stop_strategy="zero_velocity",
        evidence_refs=[EVIDENCE_REF],
    )


def _codegen_artifact(tool_id: str = TOOL_ID) -> dict[str, object]:
    return {
        "schema_version": "rolo-harness-codegen-artifact/v1",
        "target_id": TARGET_ID,
        "tool_id": tool_id,
        "bundle": {
            "schema_version": "rolo-harness-code-bundle/v1",
            "tool_id": tool_id,
            "runtime": "python",
            "entrypoint": "execute",
            "source": "def execute(request): return {'status': 'SUCCEEDED'}",
            "source_sha256": "0" * 64,
            "request": {},
        },
    }


def test_probe_input_is_generic_and_target_bound() -> None:
    envelope = build_probe_analysis_input(
        target_id=TARGET_ID,
        evidence_refs=[EVIDENCE_REF],
        routes=[{"resource_id": "ros_topic:/cmd_vel"}],
        requested_tool=TOOL_ID,
    )
    assert envelope.schema_version == "rolo-probe-analysis-input/v1"
    assert envelope.routes[0]["resource_id"] == "ros_topic:/cmd_vel"


def test_registration_requires_mapping_proposal_store_and_receipt_before_write(
    tmp_path: Path,
) -> None:
    proposal = _registration_proposal()
    authority = _mapping_authority(tmp_path)
    registry = tmp_path / "registry"

    missing_proposal = register_tool_proposal(
        proposal,
        target_id=TARGET_ID,
        evidence_refs={EVIDENCE_REF},
        registry_root=registry,
    )
    assert missing_proposal.limitations == ["MAPPING_PROPOSAL_REQUIRED"]

    missing_dsl = register_tool_proposal(
        proposal,
        target_id=TARGET_ID,
        evidence_refs={EVIDENCE_REF},
        registry_root=registry,
        mapping_proposal=authority.proposal,
    )
    assert missing_dsl.limitations == ["MAPPING_REGISTRATION_DSL_REQUIRED"]

    missing_store = register_tool_proposal(
        proposal,
        target_id=TARGET_ID,
        evidence_refs={EVIDENCE_REF},
        registry_root=registry,
        mapping_proposal=authority.proposal,
        mapping_dsl=authority.dsl,
    )
    assert missing_store.limitations == ["MAPPING_CONFIRMATION_STORE_REQUIRED"]

    missing_receipt = register_tool_proposal(
        proposal,
        target_id=TARGET_ID,
        evidence_refs={EVIDENCE_REF},
        registry_root=registry,
        mapping_proposal=authority.proposal,
        mapping_dsl=authority.dsl,
        confirmation_store=authority.store,
    )
    assert missing_receipt.limitations == ["MAPPING_CONFIRMATION_REQUIRED"]

    uncommitted = _register(
        proposal,
        authority,
        registry,
        confirmation_receipt_digest="sha256:" + "0" * 64,
    )
    assert uncommitted.limitations == ["MAPPING_CONFIRMATION_NOT_COMMITTED"]
    assert not registry.exists()


def test_registration_persists_lineage_and_reloads_only_through_active_receipt(
    tmp_path: Path,
) -> None:
    authority = _mapping_authority(tmp_path)
    proposal = _registration_proposal()
    registry = tmp_path / "registry"

    result = _register(proposal, authority, registry)

    assert result.status == "REGISTERED"
    assert result.mapping_proposal_digest == authority.proposal.proposal_digest
    assert result.confirmation_receipt_digest == authority.receipt.receipt_digest
    assert result.registration_record_digest is not None

    record_path = registry / TARGET_ID / f"{TOOL_ID}.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert record["schema_version"] == "rolo-registered-tool/v2"
    assert record["proposal"]["status"] == "PROPOSED"
    assert record["registration_proposal_digest"] == "sha256:" + proposal.digest()
    assert record["mapping_proposal_digest"] == authority.proposal.proposal_digest
    assert record["confirmation_receipt_digest"] == authority.receipt.receipt_digest
    assert record["mapping_dsl"]["binding"]["registration_proposal_digest"] == (
        "sha256:" + proposal.digest()
    )

    with pytest.raises(MappingAdmissionError) as missing_gate:
        load_registered_descriptors(registry, TARGET_ID)
    assert missing_gate.value.code == "MAPPING_CONFIRMATION_STORE_REQUIRED"
    with pytest.raises(MappingAdmissionError) as missing_fingerprint:
        load_registered_descriptors(
            registry,
            TARGET_ID,
            confirmation_store=authority.store,
        )
    assert missing_fingerprint.value.code == "MAPPING_TARGET_FINGERPRINT_REQUIRED"
    loaded = load_registered_descriptors(registry, TARGET_ID, **_load_kwargs(authority))
    assert [item.tool_id for item in loaded] == [TOOL_ID]
    loaded_proposals = load_registered_proposals(
        registry, TARGET_ID, **_load_kwargs(authority)
    )
    assert loaded_proposals == [proposal]


def test_registration_rejects_status_mutation_and_tampered_mapping_proposal(
    tmp_path: Path,
) -> None:
    authority = _mapping_authority(tmp_path)
    registry = tmp_path / "registry"

    forged_registered = _registration_proposal().model_copy(
        update={"status": "REGISTERED"}
    )
    result = _register(forged_registered, authority, registry)
    assert result.limitations == ["MAPPING_REGISTRATION_PROPOSAL_NOT_PROPOSED"]

    malformed = _registration_proposal().model_copy(update={"tool_id": "INVALID!"})
    result = _register(malformed, authority, registry)
    assert result.limitations == ["MAPPING_REGISTRATION_PROPOSAL_INVALID"]

    tampered_mapping = authority.proposal.model_copy(
        update={"user_goal": "a different unconfirmed goal"}
    )
    result = _register(
        _registration_proposal(),
        authority,
        registry,
        mapping_proposal=tampered_mapping,
    )
    assert result.limitations == ["MAPPING_PROPOSAL_INVALID"]
    assert not registry.exists()


def test_registration_rejects_wrong_or_old_mapping_proposal(tmp_path: Path) -> None:
    confirmed = _mapping_authority(tmp_path, name="confirmed")
    wrong = _mapping_authority(
        tmp_path,
        name="wrong",
        user_goal="a different reviewed goal",
    )
    registry = tmp_path / "registry"

    result = _register(
        _registration_proposal(),
        confirmed,
        registry,
        mapping_proposal=wrong.proposal,
    )
    assert result.limitations == ["MAPPING_PROPOSAL_DIGEST_MISMATCH"]

    result = _register(
        _registration_proposal(),
        confirmed,
        registry,
        journey_session_id="journey-current",
    )
    assert result.limitations == ["MAPPING_JOURNEY_SESSION_MISMATCH"]
    assert not registry.exists()


def test_registration_rejects_wrong_target_tool_and_scope(tmp_path: Path) -> None:
    authority = _mapping_authority(tmp_path, name="target")
    registry = tmp_path / "registry"
    proposal = _registration_proposal()

    wrong_target = _register(proposal, authority, registry, target_id="landerpi")
    assert wrong_target.limitations == ["MAPPING_TARGET_ID_MISMATCH"]

    wrong_fingerprint = _register(
        proposal,
        authority,
        registry,
        target_fingerprint="other-fingerprint",
    )
    assert wrong_fingerprint.limitations == ["MAPPING_TARGET_FINGERPRINT_MISMATCH"]

    other_tool = _mapping_authority(
        tmp_path,
        name="other-tool",
        tool_id="app.base.other",
    )
    wrong_tool = _register(
        proposal,
        other_tool,
        registry,
        target_id=TARGET_ID,
        journey_session_id=other_tool.proposal.journey_session_id,
        target_fingerprint=other_tool.proposal.target_fingerprint,
    )
    assert wrong_tool.limitations == ["MAPPING_REGISTRATION_TOOL_MISMATCH"]

    wrong_scope = _mapping_authority(
        tmp_path,
        name="wrong-scope",
        access="read",
        risk="R0",
    )
    result = _register(proposal, wrong_scope, registry)
    assert result.limitations == ["MAPPING_SCOPE_MISMATCH"]
    assert not registry.exists()


def test_binding_registration_requires_digest_and_observed_routes(tmp_path: Path) -> None:
    registry = tmp_path / "registry"
    binding = _binding()
    without_digest = _registration_proposal(
        implementation="binding",
        binding=binding,
    )
    unsigned_authority = _mapping_authority(
        tmp_path,
        name="unsigned-binding",
        registration_proposal=without_digest,
    )
    result = _register(without_digest, unsigned_authority, registry)
    assert result.limitations == ["MAPPING_REGISTRATION_BINDING_DIGEST_REQUIRED"]

    proposal = _registration_proposal(
        implementation="binding",
        binding=binding,
        binding_digest=binding.digest(),
    )
    authority = _mapping_authority(
        tmp_path,
        name="binding",
        registration_proposal=proposal,
    )
    result = _register(proposal, authority, registry)
    assert result.limitations == ["MAPPING_REGISTRATION_OBSERVED_ROUTES_REQUIRED"]

    result = _register(
        proposal,
        authority,
        registry,
        observed_route_ids={"ros_topic:/odom"},
    )
    assert result.limitations == [
        "MAPPING_REGISTRATION_BINDING_NOT_OBSERVED:ros_topic:/cmd_vel"
    ]

    tampered = proposal.model_copy(update={"binding_digest": "0" * 64})
    result = _register(
        tampered,
        authority,
        registry,
        observed_route_ids={"ros_topic:/cmd_vel", "ros_topic:/odom"},
    )
    assert result.limitations == ["MAPPING_REGISTRATION_PROPOSAL_INVALID"]

    result = _register(
        proposal,
        authority,
        registry,
        observed_route_ids={"ros_topic:/cmd_vel", "ros_topic:/odom"},
    )
    assert result.status == "REGISTERED"
    loaded = load_registered_bindings(
        registry, TARGET_ID, **_load_kwargs(authority)
    )
    assert loaded == [binding]


def test_one_receipt_cannot_authorize_changed_endpoint_argv_or_codegen(
    tmp_path: Path,
) -> None:
    descriptor = _descriptor()
    binding = _binding()
    artifact = _codegen_artifact()

    def proposal_for(
        *,
        current_descriptor: AgentNativeToolDescriptor = descriptor,
        current_binding: ExecutionBinding = binding,
        current_artifact: dict[str, object] = artifact,
    ) -> ToolRegistrationProposal:
        return _registration_proposal(
            descriptor=current_descriptor,
            implementation="binding",
            binding=current_binding,
            binding_digest=current_binding.digest(),
            codegen_artifact_ref="artifact://harness/mentorpi/app.base.rotate.json",
            input_contract={
                "parameters": [
                    item.model_dump(mode="json")
                    for item in current_descriptor.parameters
                ]
            },
            observation_contract={"fields": ["status"]},
            codegen_artifact=current_artifact,
        )

    confirmed = proposal_for()
    authority = _mapping_authority(
        tmp_path,
        registration_proposal=confirmed,
    )
    changed_descriptor = AgentNativeToolDescriptor.model_validate(
        {**descriptor.model_dump(mode="python"), "argv_template": ["other-runner"]}
    )
    changed_binding = ExecutionBinding.model_validate(
        {**binding.model_dump(mode="python"), "command_endpoint": "/other_cmd"}
    )
    changed_artifact = json.loads(json.dumps(artifact))
    changed_artifact["bundle"]["source"] = "def execute(request): return {'status': 'CHANGED'}"

    variants = (
        proposal_for(current_descriptor=changed_descriptor),
        proposal_for(current_binding=changed_binding),
        proposal_for(current_artifact=changed_artifact),
    )
    for index, changed in enumerate(variants):
        result = _register(
            changed,
            authority,
            tmp_path / f"changed-{index}",
            observed_route_ids={
                "ros_topic:/cmd_vel",
                "ros_topic:/other_cmd",
                "ros_topic:/odom",
            },
        )
        assert result.limitations == [
            "MAPPING_REGISTRATION_PROPOSAL_DIGEST_MISMATCH"
        ]
        assert not (tmp_path / f"changed-{index}").exists()


def test_registration_blocks_unknown_or_unreviewed_evidence(tmp_path: Path) -> None:
    proposal = _registration_proposal()
    authority = _mapping_authority(
        tmp_path,
        registration_proposal=proposal,
    )
    registry = tmp_path / "registry"

    result = _register(proposal, authority, registry, evidence_refs=set())
    assert result.limitations[0].startswith("MAPPING_REGISTRATION_EVIDENCE_UNKNOWN:")

    unknown = _registration_proposal(evidence_ref="target-evidence:missing")
    result = _register(
        unknown,
        authority,
        registry,
        evidence_refs={"target-evidence:missing"},
    )
    assert result.limitations == ["MAPPING_REGISTRATION_EVIDENCE_NOT_IN_DSL"]
    assert not registry.exists()


def test_registration_persists_generic_codegen_contract(tmp_path: Path) -> None:
    descriptor = _descriptor()
    proposal = _registration_proposal(
        descriptor=descriptor,
        code_digest="a" * 64,
        codegen_artifact_ref="artifact://harness/mentorpi/app.base.rotate.json",
        input_contract={
            "parameters": [
                item.model_dump(mode="json") for item in descriptor.parameters
            ]
        },
        observation_contract={"fields": ["status", "angle_degrees", "elapsed_ms"]},
    )
    authority = _mapping_authority(
        tmp_path,
        registration_proposal=proposal,
    )
    registry = tmp_path / "registry"

    result = _register(proposal, authority, registry)

    assert result.status == "REGISTERED"
    persisted = (registry / TARGET_ID / f"{TOOL_ID}.json").read_text(
        encoding="utf-8"
    )
    assert "codegen_artifact_ref" in persisted
    assert not (registry / TARGET_ID / "generated" / f"{TOOL_ID}.json").exists()


def test_codegen_requires_paired_untampered_registration(tmp_path: Path) -> None:
    descriptor = _descriptor()
    artifact = _codegen_artifact()
    proposal = _registration_proposal(
        descriptor=descriptor,
        codegen_artifact_ref="artifact://harness/mentorpi/app.base.rotate.json",
        input_contract={
            "parameters": [
                item.model_dump(mode="json") for item in descriptor.parameters
            ]
        },
        observation_contract={"fields": ["status"]},
        codegen_artifact=artifact,
    )
    authority = _mapping_authority(
        tmp_path,
        registration_proposal=proposal,
    )
    registry = tmp_path / "registry"
    result = _register(proposal, authority, registry)
    assert result.status == "REGISTERED"
    assert (
        load_registered_codegen_artifact(
            registry,
            TARGET_ID,
            TOOL_ID,
            **_load_kwargs(authority),
        )
        == artifact
    )

    generated = registry / TARGET_ID / "generated" / f"{TOOL_ID}.json"
    tampered = json.loads(generated.read_text(encoding="utf-8"))
    tampered["target_id"] = "other-target"
    generated.write_text(json.dumps(tampered), encoding="utf-8")

    assert (
        load_registered_codegen_artifact(
            registry,
            TARGET_ID,
            TOOL_ID,
            **_load_kwargs(authority),
        )
        is None
    )
    assert load_registered_proposals(
        registry, TARGET_ID, **_load_kwargs(authority)
    ) == []


def test_legacy_registered_json_and_orphan_codegen_fail_closed(tmp_path: Path) -> None:
    authority = _mapping_authority(tmp_path)
    registry = tmp_path / "registry"
    target_dir = registry / TARGET_ID
    generated_dir = target_dir / "generated"
    generated_dir.mkdir(parents=True)

    legacy = _registration_proposal().model_copy(update={"status": "REGISTERED"})
    (target_dir / f"{TOOL_ID}.json").write_text(
        legacy.model_dump_json(), encoding="utf-8"
    )
    (generated_dir / f"{TOOL_ID}.json").write_text(
        json.dumps(_codegen_artifact()), encoding="utf-8"
    )

    assert load_registered_descriptors(
        registry, TARGET_ID, **_load_kwargs(authority)
    ) == []
    assert (
        load_registered_codegen_artifact(
            registry,
            TARGET_ID,
            TOOL_ID,
            **_load_kwargs(authority),
        )
        is None
    )


def test_forged_v2_record_cannot_reuse_receipt_for_changed_descriptor(
    tmp_path: Path,
) -> None:
    proposal = _registration_proposal()
    authority = _mapping_authority(
        tmp_path,
        registration_proposal=proposal,
    )
    registry = tmp_path / "registry"
    assert _register(proposal, authority, registry).status == "REGISTERED"

    path = registry / TARGET_ID / f"{TOOL_ID}.json"
    forged = json.loads(path.read_text(encoding="utf-8"))
    forged["proposal"]["descriptor"]["argv_template"] = ["attacker-runner"]
    forged_proposal = ToolRegistrationProposal.model_validate(forged["proposal"])
    forged["registration_proposal_digest"] = "sha256:" + forged_proposal.digest()
    forged["mapping_dsl"]["binding"]["registration_proposal_digest"] = (
        forged["registration_proposal_digest"]
    )
    forged["mapping_dsl"]["binding"]["descriptor_digest"] = _descriptor_digest(
        forged_proposal.descriptor
    )
    forged["record_digest"] = mapping_digest(
        {key: value for key, value in forged.items() if key != "record_digest"}
    )
    path.write_text(json.dumps(forged), encoding="utf-8")

    assert load_registered_descriptors(
        registry, TARGET_ID, **_load_kwargs(authority)
    ) == []


def test_cancelled_or_expired_receipt_cannot_register_or_load(tmp_path: Path) -> None:
    authority = _mapping_authority(tmp_path, name="cancelled")
    registry = tmp_path / "registry"
    proposal = _registration_proposal()
    assert _register(proposal, authority, registry).status == "REGISTERED"

    authority.store.cancel(
        authority.receipt.receipt_digest,
        decision_id="cancel-registration",
        actor_id="test-operator",
        decided_at=NOW + timedelta(minutes=1),
    )
    assert load_registered_descriptors(
        registry, TARGET_ID, **_load_kwargs(authority)
    ) == []

    blocked_registry = tmp_path / "blocked-registry"
    cancelled = _register(proposal, authority, blocked_registry)
    assert cancelled.limitations == ["MAPPING_CONFIRMATION_CANCELLED"]
    assert not blocked_registry.exists()

    expiring = _mapping_authority(tmp_path, name="expired")
    expired_registry = tmp_path / "expired-registry"
    expired = _register(
        proposal,
        expiring,
        expired_registry,
        now=NOW + timedelta(minutes=16),
    )
    assert expired.limitations == ["MAPPING_CONFIRMATION_EXPIRED"]
    assert not expired_registry.exists()

    rejected_store = MappingConfirmationStore(
        tmp_path / "authority-rejected",
        clock=lambda: NOW,
    )
    rejected_receipt = rejected_store.reject(
        expiring.proposal.admission_identity(),
        decision_id="reject-registration",
        actor_id="test-operator",
        decided_at=NOW,
    )
    rejected_authority = _MappingAuthority(
        proposal=expiring.proposal,
        dsl=expiring.dsl,
        store=rejected_store,
        receipt=rejected_receipt,
    )
    rejected_registry = tmp_path / "rejected-registry"
    rejected = _register(proposal, rejected_authority, rejected_registry)
    assert rejected.limitations == ["MAPPING_CONFIRMATION_REJECTED"]
    assert not rejected_registry.exists()


def test_cross_target_record_and_filename_mismatch_fail_closed(tmp_path: Path) -> None:
    authority = _mapping_authority(tmp_path)
    registry = tmp_path / "registry"
    proposal = _registration_proposal()
    assert _register(proposal, authority, registry).status == "REGISTERED"

    source = registry / TARGET_ID / f"{TOOL_ID}.json"
    cross_target = registry / "landerpi"
    cross_target.mkdir()
    shutil.copyfile(source, cross_target / f"{TOOL_ID}.json")
    shutil.copyfile(source, registry / TARGET_ID / "app.base.other.json")

    assert load_registered_descriptors(
        registry,
        "landerpi",
        confirmation_store=authority.store,
        target_fingerprint=TARGET_FINGERPRINT,
    ) == []
    loaded = load_registered_descriptors(
        registry, TARGET_ID, **_load_kwargs(authority)
    )
    assert [item.tool_id for item in loaded] == [TOOL_ID]


def test_registration_is_immutable_across_different_confirmed_lineage(
    tmp_path: Path,
) -> None:
    first = _mapping_authority(tmp_path, name="first", user_goal="first goal")
    second = _mapping_authority(tmp_path, name="second", user_goal="second goal")
    registry = tmp_path / "registry"
    proposal = _registration_proposal()

    initial = _register(proposal, first, registry)
    assert initial.status == "REGISTERED"
    original = (registry / TARGET_ID / f"{TOOL_ID}.json").read_bytes()

    conflict = _register(proposal, second, registry)
    assert conflict.limitations == ["MAPPING_REGISTRATION_IMMUTABLE_CONFLICT"]
    assert (registry / TARGET_ID / f"{TOOL_ID}.json").read_bytes() == original
