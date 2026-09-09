from __future__ import annotations

import rolo.mvp.binding_dispatch as binding_dispatch
from rolo.dsl.admission import MappingConfirmationStore
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


def test_registered_codegen_invoker_reconstructs_source_from_registry(tmp_path, monkeypatch) -> None:
    source = "def execute(request):\n    return {'status': 'SUCCEEDED', 'value': request['value']}\n"
    import json

    artifact = {
        "schema_version": "rolo-harness-codegen-artifact/v1",
        "target_id": "mentorpi",
        "tool_id": "app.demo.action",
        "bundle": {"source": source, "entrypoint": "execute"},
    }
    confirmation_store = MappingConfirmationStore(tmp_path / "admission")
    loader_calls = []

    def load_artifact(registry_root, target_id, tool_id, **kwargs):
        loader_calls.append((registry_root, target_id, tool_id, kwargs))
        return artifact

    monkeypatch.setattr(binding_dispatch, "load_registered_codegen_artifact", load_artifact)

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

    result = RegisteredCodegenInvoker(
        tmp_path,
        "mentorpi",
        Executor(),
        confirmation_store=confirmation_store,
        target_fingerprint="b" * 64,
    ).invoke(
        "app.demo.action", {"value": 9}, "trace-1"
    )
    assert result["status"] == "SUCCEEDED"
    assert result["value"] == 9
    assert loader_calls == [
        (
            tmp_path,
            "mentorpi",
            "app.demo.action",
            {
                "confirmation_store": confirmation_store,
                "target_fingerprint": "b" * 64,
            },
        )
    ]


def test_registered_codegen_invoker_blocks_without_admission_context(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        binding_dispatch,
        "load_registered_codegen_artifact",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("loader must not run without trusted admission context")
        ),
    )

    result = RegisteredCodegenInvoker(tmp_path, "mentorpi", object()).invoke(
        "app.demo.action", {}, "trace-1"
    )

    assert result == {
        "status": "BLOCKED",
        "error": "MAPPING_CONFIRMATION_STORE_REQUIRED",
    }
