from __future__ import annotations

from rolo.agent_tools.native_tools import AgentNativeToolDescriptor, NativeToolInvocation, NativeToolParameter
from rolo.mvp.probe_registration import (
    ToolRegistrationProposal,
    build_probe_analysis_input,
    load_registered_descriptors,
    register_tool_proposal,
)


def _descriptor() -> AgentNativeToolDescriptor:
    return AgentNativeToolDescriptor(
        tool_id="app.base.rotate",
        family="application",
        execution_path="DIRECT_RUNNER",
        executable="python3",
        argv_template=["python3"],
        access="experimental_write",
        risk="R3",
        max_duration_s=30,
        max_output_bytes=100_000,
        evidence_kind="application_rotation",
        parameters=[NativeToolParameter(name="angle_degrees", kind="token", pattern=r"-?[0-9]{1,3}(\.[0-9]+)?")],
        variants={
            "execute": NativeToolInvocation(
                executable="python3",
                argv_template=["python3", "-c", "print('rotation')", "{angle_degrees}"],
                required_parameters=["angle_degrees"],
            )
        },
    )


def test_probe_input_is_generic_and_target_bound() -> None:
    envelope = build_probe_analysis_input(
        target_id="mentorpi",
        evidence_refs=["target-evidence:abc"],
        routes=[{"resource_id": "ros_topic:/cmd_vel"}],
        requested_tool="app.base.rotate",
    )
    assert envelope.schema_version == "rolo-probe-analysis-input/v1"
    assert envelope.routes[0]["resource_id"] == "ros_topic:/cmd_vel"


def test_registration_persists_callable_descriptor_and_reloads(tmp_path) -> None:
    descriptor = _descriptor()
    proposal = ToolRegistrationProposal(
        target_id="mentorpi",
        tool_id=descriptor.tool_id,
        evidence_refs=["target-evidence:abc"],
        descriptor=descriptor,
    )
    result = register_tool_proposal(
        proposal,
        target_id="mentorpi",
        evidence_refs={"target-evidence:abc"},
        registry_root=tmp_path,
    )
    assert result.status == "REGISTERED"
    loaded = load_registered_descriptors(tmp_path, "mentorpi")
    assert [item.tool_id for item in loaded] == ["app.base.rotate"]
    assert loaded[0].access == "experimental_write"


def test_registration_blocks_unknown_evidence(tmp_path) -> None:
    descriptor = _descriptor()
    proposal = ToolRegistrationProposal(
        target_id="mentorpi",
        tool_id=descriptor.tool_id,
        evidence_refs=["target-evidence:missing"],
        descriptor=descriptor,
    )
    result = register_tool_proposal(
        proposal,
        target_id="mentorpi",
        evidence_refs=set(),
        registry_root=tmp_path,
    )
    assert result.status == "BLOCKED"
    assert "unknown evidence" in result.limitations[0]
