from __future__ import annotations

from rolo.mvp.binding_dispatch import ApplicationBindingDispatcher, RegisteredCodegenInvoker
from rolo.mvp.probe_registration import ExecutionBinding


def _binding(kind: str) -> ExecutionBinding:
    return ExecutionBinding(
        kind=kind,
        command_endpoint="/command",
        interface_type="example/Command",
        stop_strategy="zero_velocity",
        evidence_refs=["target-evidence:" + "a" * 64],
    )


def test_dispatcher_routes_registered_provider_without_ros_assumption() -> None:
    dispatcher = ApplicationBindingDispatcher()
    dispatcher.register("vendor.serial", lambda binding, args: {"status": "SUCCEEDED", "value": args["value"]})
    result = dispatcher.execute(_binding("vendor.serial"), {"value": 7})
    assert result == {"status": "SUCCEEDED", "value": 7}


def test_dispatcher_blocks_unknown_provider_kind() -> None:
    result = ApplicationBindingDispatcher().execute(_binding("vendor.can"), {})
    assert result["status"] == "BLOCKED"
    assert result["error"] == "UNSUPPORTED_BINDING_KIND"


def test_registered_codegen_invoker_reconstructs_source_from_registry(tmp_path) -> None:
    target = tmp_path / "mentorpi" / "generated"
    target.mkdir(parents=True)
    source = "def execute(request):\n    return {'status': 'SUCCEEDED', 'value': request['value']}\n"
    import json

    target.joinpath("app.demo.action.json").write_text(
        json.dumps(
            {
                "schema_version": "rolo-harness-codegen-artifact/v1",
                "target_id": "mentorpi",
                "tool_id": "app.demo.action",
                "bundle": {"source": source, "entrypoint": "execute"},
            }
        ),
        encoding="utf-8",
    )

    class Executor:
        def run_transient_code(self, code, *, timeout_s):
            del timeout_s
            namespace = {}
            exec(compile(code, "<launcher>", "exec"), namespace, namespace)
            class Result:
                returncode = 0
                stdout = json.dumps({"status": "SUCCEEDED", "value": 9})
                stderr = ""
            return Result()

    result = RegisteredCodegenInvoker(tmp_path, "mentorpi", Executor()).invoke(
        "app.demo.action", {"value": 9}, "trace-1"
    )
    assert result["status"] == "SUCCEEDED"
    assert result["value"] == 9
