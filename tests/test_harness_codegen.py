from __future__ import annotations

from rolo.agent_tools.native_tools import AgentNativeToolDescriptor, NativeToolParameter
from rolo.mvp.harness_codegen import build_codegen_artifact, generate_contract_source


def test_codegen_generates_descriptor_shaped_input_and_output() -> None:
    descriptor = AgentNativeToolDescriptor(
        tool_id="app.demo.action",
        family="application",
        execution_path="DIRECT_RUNNER",
        executable="demo",
        argv_template=["demo"],
        access="experimental_write",
        risk="R3",
        max_duration_s=10,
        max_output_bytes=4096,
        evidence_kind="demo",
        parameters=[
            NativeToolParameter(name="count", kind="integer"),
            NativeToolParameter(name="mode", kind="enum", choices=["fast", "safe"]),
        ],
    )
    source = generate_contract_source(
        descriptor,
        observation_fields=["status", "value"],
        primitive_source="def run_primitive(request):\n    return {'status': 'SUCCEEDED', 'value': request['count']}\n",
    )
    namespace: dict[str, object] = {}
    exec(compile(source, "<generated>", "exec"), namespace, namespace)
    assert namespace["execute"]({"count": 3, "mode": "fast"}) == {"status": "SUCCEEDED", "value": 3}
    try:
        namespace["execute"]({"count": "3", "mode": "fast"})
    except ValueError as exc:
        assert "integer" in str(exc)
    else:
        raise AssertionError("invalid input was accepted")


def test_codegen_rejects_invalid_observation_contract() -> None:
    descriptor = AgentNativeToolDescriptor(
        tool_id="app.demo.action",
        family="application",
        execution_path="DIRECT_RUNNER",
        executable="demo",
        argv_template=["demo"],
        access="experimental_write",
        risk="R3",
        max_duration_s=10,
        max_output_bytes=4096,
        evidence_kind="demo",
    )
    try:
        generate_contract_source(descriptor, observation_fields=["value"], primitive_source="def run_primitive(request): return {}")
    except ValueError as exc:
        assert "status" in str(exc)
    else:
        raise AssertionError("invalid observation contract was accepted")


def test_codegen_artifact_is_generic_and_preserves_typed_contracts() -> None:
    descriptor = AgentNativeToolDescriptor(
        tool_id="app.demo.action",
        family="application",
        execution_path="DIRECT_RUNNER",
        executable="demo",
        argv_template=["demo"],
        access="experimental_write",
        risk="R3",
        max_duration_s=10,
        max_output_bytes=4096,
        evidence_kind="demo",
        parameters=[NativeToolParameter(name="count", kind="integer")],
    )
    artifact = build_codegen_artifact(
        descriptor,
        target_id="mentorpi",
        evidence_refs=["target-evidence:demo"],
        observation_fields=["status", "value"],
        primitive_source="def run_primitive(request):\n    return {'status': 'SUCCEEDED', 'value': request['count']}\n",
        arguments={"count": 2},
        derived_request={"transport_value": 2},
        binding={"kind": "vendor.serial", "command_endpoint": "/drive"},
    )
    assert artifact["tool_id"] == "app.demo.action"
    assert artifact["input_contract"]["parameters"][0]["name"] == "count"
    assert artifact["observation_contract"]["fields"] == ["status", "value"]
    assert artifact["bundle"]["request"] == {"count": 2, "transport_value": 2}
    assert len(artifact["binding_sha256"]) == 64
