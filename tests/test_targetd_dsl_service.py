import hashlib

from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.parser import parse_document
from rolo.targetd import DslFrame, Ros2RuntimeResolver, Ros2RuntimeSnapshot, TargetdDslService
from rolo.targetd.ros2_runtime import parse_ros2_topic_types


def values():
    dsl = {"tool_id": "x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": "sha256:e"}, "binding": {"resource_id": "route:/state"}}
    context = {"robot_id": "r", "target_fingerprint": "fp", "evidence_digest": "sha256:e", "evidence_refs": ["route:/state"]}
    doc, _ = parse_document(dsl)
    return dsl, context, dsl_digest(doc), context_digest(context)


def test_targetd_put_check_compile_and_cache(tmp_path):
    dsl, context, dd, cd = values()
    service = TargetdDslService(tmp_path)
    put = DslFrame(
        frame_type="DSL_PUT", request_id="1", payload={"dsl": dsl, "context": context, "compiler_version": "rolo-compiler/0.1", "dsl_digest": dd, "context_digest": cd, "target_fingerprint": "fp"}
    )
    assert service.handle(put).payload["phase"] == "PUT"
    assert service.handle(DslFrame(frame_type="DSL_CHECK", request_id="2", payload={"dsl_digest": dd})).payload["status"] == "PASS"
    compile_frame = DslFrame(frame_type="DSL_COMPILE", request_id="3", payload={"dsl_digest": dd, "context_digest": cd, "target_fingerprint": "fp"})
    first = service.handle(compile_frame)
    second = service.handle(DslFrame(frame_type="DSL_COMPILE", request_id="4", payload=compile_frame.payload))
    assert first.payload["status"] == "PASS" and first.payload["cache_hit"] is False
    assert second.payload["cache_hit"] is True


def test_targetd_plan_resolve_compile_and_conformance_phases(tmp_path):
    dsl, context, dd, cd = values()
    service = TargetdDslService(tmp_path)
    put = DslFrame(
        frame_type="DSL_PUT",
        request_id="put",
        payload={
            "dsl": dsl,
            "context": context,
            "compiler_version": "rolo-compiler/0.1",
            "dsl_digest": dd,
            "context_digest": cd,
            "target_fingerprint": "fp",
        },
    )
    assert service.handle(put).payload["phase"] == "PUT"
    resolved = service.handle(DslFrame(frame_type="PLAN_RESOLVE", request_id="resolve", payload={"dsl_digest": dd}))
    assert resolved.payload["phase"] == "PLAN_RESOLVE"
    compiled = service.handle(
        DslFrame(
            frame_type="TARGET_COMPILE",
            request_id="compile",
            payload={"dsl_digest": dd, "context_digest": cd, "target_fingerprint": "fp"},
        )
    )
    assert compiled.payload["phase"] == "TARGET_COMPILE"
    conformance = service.handle(
        DslFrame(
            frame_type="TARGET_CONFORMANCE",
            request_id="conformance",
            payload={"dsl_digest": dd, "context_digest": cd, "target_fingerprint": "fp"},
        )
    )
    assert conformance.payload["phase"] == "TARGET_CONFORMANCE"
    assert conformance.payload["target_conformance"] == "PASS"
    assert conformance.payload["target_conformance_report"]["t4_release_integrity"] == "PASS"
    assert conformance.payload["target_conformance_digest"].startswith("sha256:")


def test_targetd_rejects_unbound_put_digest(tmp_path):
    dsl, context, dd, cd = values()
    service = TargetdDslService(tmp_path)
    frame = DslFrame(
        frame_type="DSL_PUT",
        request_id="bad",
        payload={
            "dsl": dsl,
            "context": context,
            "compiler_version": "rolo-compiler/0.1",
            "dsl_digest": "sha256:" + "0" * 64,
            "context_digest": cd,
            "target_fingerprint": "fp",
        },
    )
    assert service.handle(frame).payload["diagnostics"] == ["DSL_DIGEST_MISMATCH"]


def test_targetd_rejects_put_without_digest_bound_context(tmp_path):
    dsl, _, dd, cd = values()
    service = TargetdDslService(tmp_path)
    frame = DslFrame(
        frame_type="DSL_PUT",
        request_id="missing-context",
        payload={
            "dsl": dsl,
            "context": {},
            "compiler_version": "rolo-compiler/0.1",
            "dsl_digest": dd,
            "context_digest": cd,
            "target_fingerprint": "fp",
        },
    )
    assert service.handle(frame).payload["diagnostics"] == ["CONTEXT_REQUIRED"]


def test_targetd_runtime_resolver_blocks_unobserved_topic(tmp_path):
    dsl, context, dd, cd = values()
    resolver = Ros2RuntimeResolver(
        Ros2RuntimeSnapshot("humble", "/opt/ros/humble/bin/ros2", parse_ros2_topic_types(["/scan sensor_msgs/msg/LaserScan"]))
    )
    service = TargetdDslService(tmp_path, runtime_resolver=resolver)
    put = DslFrame(
        frame_type="DSL_PUT",
        request_id="put",
        payload={
            "dsl": dsl,
            "context": context,
            "compiler_version": "rolo-compiler/0.1",
            "dsl_digest": dd,
            "context_digest": cd,
            "target_fingerprint": "fp",
        },
    )
    service.handle(put)
    result = service.handle(DslFrame(frame_type="PLAN_RESOLVE", request_id="resolve", payload={"dsl_digest": dd}))
    assert result.payload["status"] == "DSL_CHECK_FAILED"
    assert result.payload["diagnostics"] == ("RESOURCE_NOT_OBSERVED",)


def test_targetd_rejects_tampered_cache_result(tmp_path):
    dsl, context, dd, cd = values()
    service = TargetdDslService(tmp_path)
    put = DslFrame(
        frame_type="DSL_PUT",
        request_id="put",
        payload={
            "dsl": dsl,
            "context": context,
            "compiler_version": "rolo-compiler/0.1",
            "dsl_digest": dd,
            "context_digest": cd,
            "target_fingerprint": "fp",
        },
    )
    service.handle(put)
    compiled = service.handle(
        DslFrame(frame_type="TARGET_COMPILE", request_id="compile", payload={"dsl_digest": dd, "context_digest": cd, "target_fingerprint": "fp"})
    )
    assert compiled.payload["status"] == "PASS"
    result_file = next(tmp_path.glob("*/result.json"))
    result_file.write_text(result_file.read_text(encoding="utf-8").replace(dd, "sha256:" + "0" * 64), encoding="utf-8")
    tampered = service.handle(
        DslFrame(frame_type="TARGET_COMPILE", request_id="retry", payload={"dsl_digest": dd, "context_digest": cd, "target_fingerprint": "fp"})
    )
    assert tampered.payload["diagnostics"] == ["CACHE_DIGEST_MISMATCH"]


def test_targetd_requires_declared_execute_source_bundle(tmp_path):
    source = "def run(arguments):\n    return arguments\n"
    source_digest = "sha256:" + hashlib.sha256(source.encode()).hexdigest()
    dsl = {
        "tool_id": "app.execute",
        "kind": "EXECUTE",
        "target": {"robot_id": "r", "evidence_digest": "sha256:e"},
        "implementation": {
            "source_bundle_digest": source_digest,
            "entrypoint": "main:run",
            "runtime": "python3.12",
            "implementation_contract": "v1",
        },
    }
    context = {"robot_id": "r", "target_fingerprint": "fp", "evidence_digest": "sha256:e"}
    document, _ = parse_document(dsl)
    dd, cd = dsl_digest(document), context_digest(context)
    service = TargetdDslService(tmp_path)
    assert service.handle(
        DslFrame(
            frame_type="DSL_PUT",
            request_id="put",
            payload={
                "dsl": dsl,
                "context": context,
                "compiler_version": "rolo-compiler/0.1",
                "dsl_digest": dd,
                "context_digest": cd,
                "target_fingerprint": "fp",
            },
        )
    ).payload["phase"] == "PUT"
    base = {"dsl_digest": dd, "context_digest": cd, "target_fingerprint": "fp"}
    missing = service.handle(DslFrame(frame_type="TARGET_COMPILE", request_id="missing", payload=base))
    assert missing.payload["diagnostics"] == ["SOURCE_BUNDLE_DIGEST_MISMATCH"]
    valid = {
        **base,
        "source_bundle_digest": source_digest,
        "source_bundle_manifest": {
            "source_bundle_digest": source_digest,
            "entrypoint": "main:run",
            "runtime": "python3.12",
            "implementation_contract": "v1",
        },
        "source_bundle_source": source,
    }
    compiled = service.handle(DslFrame(frame_type="TARGET_COMPILE", request_id="compile", payload=valid))
    assert compiled.payload["status"] == "PASS"
