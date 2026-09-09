import hashlib
import json
from datetime import timedelta

import pytest

from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.parser import parse_document
from rolo.targetd import DslFrame, Ros2RuntimeResolver, Ros2RuntimeSnapshot, TargetdDslService
from rolo.targetd.ros2_runtime import parse_ros2_topic_types


def values():
    evidence_digest = "sha256:" + "e" * 64
    dsl = {"tool_id": "app.x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": evidence_digest}, "binding": {"resource_id": "route:/state"}}
    context = {"robot_id": "r", "target_fingerprint": "fp", "evidence_digest": evidence_digest, "evidence_refs": ["route:/state"]}
    doc, _ = parse_document(dsl)
    return dsl, context, dsl_digest(doc), context_digest(context)


def admitted_service(
    tmp_path,
    mapping_confirmation_factory,
    dsl,
    context,
    dd,
    cd,
    *,
    journey_session_id="journey-1",
    receipt_session_id=None,
    **service_kwargs,
):
    confirmed = mapping_confirmation_factory(
        dsl,
        context,
        journey_session_id=receipt_session_id or journey_session_id,
    )
    service = TargetdDslService(
        tmp_path / "cache",
        confirmation_store=confirmed.store,
        **service_kwargs,
    )
    compile_payload = {
        "schema_version": "rolo-targetd-dsl-compile/v2",
        "dsl_digest": dd,
        "context_digest": cd,
        "target_fingerprint": context["target_fingerprint"],
        "journey_session_id": journey_session_id,
        "confirmation_receipt_digest": confirmed.receipt.receipt_digest,
    }
    return service, confirmed.store, confirmed.receipt, compile_payload


def conformed_cache(tmp_path, mapping_confirmation_factory):
    dsl, context, dd, cd = values()
    service, store, receipt, compile_payload = admitted_service(
        tmp_path,
        mapping_confirmation_factory,
        dsl,
        context,
        dd,
        cd,
        allow_unbound_runtime=True,
    )
    put = service.handle(
        DslFrame(
            frame_type="DSL_PUT",
            request_id="put",
            payload={
                "journey_session_id": "journey-1",
                "dsl": dsl,
                "context": context,
                "compiler_version": "rolo-compiler/0.1",
                "dsl_digest": dd,
                "context_digest": cd,
                "target_fingerprint": "fp",
            },
        )
    )
    assert put.payload["phase"] == "PUT"
    compiled = service.handle(
        DslFrame(
            frame_type="TARGET_COMPILE",
            request_id="compile",
            payload=compile_payload,
        )
    )
    assert compiled.payload["status"] == "PASS"
    conformance = service.handle(
        DslFrame(
            frame_type="TARGET_CONFORMANCE",
            request_id="conformance",
            payload=compile_payload,
        )
    )
    assert conformance.payload["target_conformance"] == "PASS"
    return (
        service,
        store,
        receipt,
        compiled.payload["cache_key"],
        compiled.payload,
        conformance.payload,
    )


def test_targetd_put_check_compile_and_cache(tmp_path, mapping_confirmation_factory):
    dsl, context, dd, cd = values()
    service, _store, receipt, compile_payload = admitted_service(tmp_path, mapping_confirmation_factory, dsl, context, dd, cd)
    put = DslFrame(
        frame_type="DSL_PUT",
        request_id="1",
        payload={
            "journey_session_id": "journey-1",
            "dsl": dsl,
            "context": context,
            "compiler_version": "rolo-compiler/0.1",
            "dsl_digest": dd,
            "context_digest": cd,
            "target_fingerprint": "fp",
        },
    )
    assert service.handle(put).payload["phase"] == "PUT"
    assert service.handle(DslFrame(frame_type="DSL_CHECK", request_id="2", payload={"dsl_digest": dd})).payload["status"] == "PASS"
    compile_frame = DslFrame(
        frame_type="DSL_COMPILE",
        request_id="3",
        payload=compile_payload,
    )
    first = service.handle(compile_frame)
    second = service.handle(DslFrame(frame_type="DSL_COMPILE", request_id="4", payload=compile_frame.payload))
    assert first.payload["status"] == "PASS" and first.payload["cache_hit"] is False
    assert second.payload["cache_hit"] is True
    assert second.payload["journey_session_id"] == "journey-1"
    assert second.payload["confirmation_receipt_digest"] == receipt.receipt_digest
    assert service._verify_cache_digest(second.payload)


def test_targetd_plan_resolve_compile_and_conformance_phases(tmp_path, mapping_confirmation_factory):
    dsl, context, dd, cd = values()
    # This is an explicit offline/fake-target replay; live target conformance
    # is fail-closed unless runtime bindings are injected.
    service, _store, receipt, compile_payload = admitted_service(
        tmp_path,
        mapping_confirmation_factory,
        dsl,
        context,
        dd,
        cd,
        allow_unbound_runtime=True,
    )
    put = DslFrame(
        frame_type="DSL_PUT",
        request_id="put",
        payload={
            "journey_session_id": "journey-1",
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
            payload=compile_payload,
        )
    )
    assert compiled.payload["phase"] == "TARGET_COMPILE"
    conformance = service.handle(
        DslFrame(
            frame_type="TARGET_CONFORMANCE",
            request_id="conformance",
            payload=compile_payload,
        )
    )
    assert conformance.payload["phase"] == "TARGET_CONFORMANCE"
    assert conformance.payload["target_conformance"] == "PASS"
    assert conformance.payload["target_conformance_report"]["t4_release_integrity"] == "PASS"
    assert conformance.payload["target_conformance_report"]["confirmation_receipt_digest"] == receipt.receipt_digest
    assert conformance.payload["target_conformance_digest"].startswith("sha256:")
    assert service._verify_cache_digest(conformance.payload)


def test_verified_release_inputs_are_rebuilt_from_target_cache(
    tmp_path,
    mapping_confirmation_factory,
):
    service, _store, receipt, cache_key, compiled, conformance = conformed_cache(
        tmp_path,
        mapping_confirmation_factory,
    )

    verified = service.verified_release_inputs(cache_key, "journey-1")

    expected_conformance = {
        "c1_dsl": "PASS",
        "c2_evidence": "PASS",
        "c3_compile": "PASS",
        "c4_behavior": "PASS",
        "diagnostics": list(compiled["diagnostics"]),
    }
    canonical = json.dumps(
        expected_conformance,
        sort_keys=True,
        separators=(",", ":"),
    )
    assert verified["cache_key"] == cache_key
    assert verified["tool_id"] == compiled["tool_id"]
    assert verified["target_id"] == compiled["target_id"]
    assert verified["bundle_digest"] == compiled["bundle_digest"]
    assert verified["target_conformance_digest"] == conformance["target_conformance_digest"]
    assert verified["conformance_digest"] == ("sha256:" + hashlib.sha256(canonical.encode()).hexdigest())
    assert verified["compiler_conformance"] == expected_conformance
    assert verified["mapping_confirmation_receipt_digest"] == (receipt.receipt_digest)
    assert verified["mapping_admission"] == receipt.admission_identity().model_dump(mode="json")
    assert verified["mapping_confirmation_receipt"] == receipt.model_dump(mode="json")


def test_verified_release_inputs_reject_tampered_target_proof(
    tmp_path,
    mapping_confirmation_factory,
):
    service, _store, _receipt, cache_key, _compiled, _conformance = conformed_cache(tmp_path, mapping_confirmation_factory)
    proof_path = tmp_path / "cache" / cache_key / "target-conformance" / "t3-runtime-behavior.json"
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    proof["runtime_result_digest"] = "sha256:" + "0" * 64
    proof_path.write_text(json.dumps(proof, sort_keys=True), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match="VERIFIED_RELEASE_TARGET_PROOF_IDENTITY_MISMATCH",
    ):
        service.verified_release_inputs(cache_key, "journey-1")


def test_verified_release_inputs_reject_wrong_session(
    tmp_path,
    mapping_confirmation_factory,
):
    service, _store, _receipt, cache_key, _compiled, _conformance = conformed_cache(tmp_path, mapping_confirmation_factory)

    with pytest.raises(ValueError, match="MAPPING_JOURNEY_SESSION_MISMATCH"):
        service.verified_release_inputs(cache_key, "journey-other")


def test_verified_release_inputs_reject_cancelled_mapping(
    tmp_path,
    mapping_confirmation_factory,
):
    service, store, receipt, cache_key, _compiled, _conformance = conformed_cache(
        tmp_path,
        mapping_confirmation_factory,
    )
    store.cancel(
        receipt.receipt_digest,
        decision_id="cancel-before-release-provision",
        actor_id="operator",
        decided_at=receipt.decided_at + timedelta(seconds=1),
    )

    with pytest.raises(ValueError, match="MAPPING_CONFIRMATION_CANCELLED"):
        service.verified_release_inputs(cache_key, "journey-1")


def test_targetd_conformance_requires_runtime_binding(tmp_path, mapping_confirmation_factory):
    dsl, context, dd, cd = values()
    service, _store, _receipt, compile_payload = admitted_service(tmp_path, mapping_confirmation_factory, dsl, context, dd, cd)
    put = DslFrame(
        frame_type="DSL_PUT",
        request_id="put",
        payload={
            "journey_session_id": "journey-1",
            "dsl": dsl,
            "context": context,
            "compiler_version": "rolo-compiler/0.1",
            "dsl_digest": dd,
            "context_digest": cd,
            "target_fingerprint": "fp",
        },
    )
    assert service.handle(put).payload["phase"] == "PUT"
    compile_frame = DslFrame(
        frame_type="TARGET_COMPILE",
        request_id="compile",
        payload=compile_payload,
    )
    assert service.handle(compile_frame).payload["status"] == "PASS"
    result = service.handle(
        DslFrame(
            frame_type="TARGET_CONFORMANCE",
            request_id="conformance",
            payload=compile_payload,
        )
    )
    assert result.payload["target_conformance"] == "FAIL"
    report = result.payload["target_conformance_report"]
    assert report["t3_runtime_behavior"] == "FAIL"
    assert "TARGET_RUNTIME_UNBOUND" in report["diagnostics"]


def test_targetd_put_requires_explicit_journey_session(tmp_path):
    dsl, context, dd, cd = values()
    result = TargetdDslService(tmp_path).handle(
        DslFrame(
            frame_type="DSL_PUT",
            request_id="missing-journey",
            payload={
                "dsl": dsl,
                "context": context,
                "compiler_version": "rolo-compiler/0.1",
                "dsl_digest": dd,
                "context_digest": cd,
                "target_fingerprint": "fp",
            },
        )
    )
    assert result.payload["status"] == "BLOCKED"
    assert result.payload["diagnostics"] == ["DSL_PUT_SCHEMA_INVALID"]


def test_targetd_rejects_unbound_put_digest(tmp_path):
    dsl, context, dd, cd = values()
    service = TargetdDslService(tmp_path)
    frame = DslFrame(
        frame_type="DSL_PUT",
        request_id="bad",
        payload={
            "journey_session_id": "journey-1",
            "dsl": dsl,
            "context": context,
            "compiler_version": "rolo-compiler/0.1",
            "dsl_digest": "sha256:" + "0" * 64,
            "context_digest": cd,
            "target_fingerprint": "fp",
        },
    )
    assert service.handle(frame).payload["diagnostics"] == ["DSL_DIGEST_MISMATCH"]


def test_targetd_blocks_unsupported_contract_version(tmp_path):
    dsl, context, dd, cd = values()
    service = TargetdDslService(tmp_path)
    frame = DslFrame(
        frame_type="DSL_PUT",
        request_id="bad-version",
        payload={
            "schema_version": "rolo-targetd-dsl-put/v1",
            "journey_session_id": "journey-1",
            "dsl": {**dsl, "schema_version": "rolo-dsl/v2"},
            "context": context,
            "compiler_version": "rolo-compiler/0.1",
            "dsl_digest": dd,
            "context_digest": cd,
            "target_fingerprint": "fp",
        },
    )
    result = service.handle(frame)
    assert result.payload["status"] == "BLOCKED"
    assert result.payload["diagnostics"] == ["DSL_SCHEMA_VERSION_UNSUPPORTED"]


def test_targetd_runtime_resolver_blocks_unobserved_topic(tmp_path):
    dsl, context, dd, cd = values()
    resolver = Ros2RuntimeResolver(Ros2RuntimeSnapshot("humble", "/opt/ros/humble/bin/ros2", parse_ros2_topic_types(["/scan sensor_msgs/msg/LaserScan"])))
    service = TargetdDslService(tmp_path, runtime_resolver=resolver)
    put = DslFrame(
        frame_type="DSL_PUT",
        request_id="put",
        payload={
            "journey_session_id": "journey-1",
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


def test_targetd_rejects_tampered_cache_result(tmp_path, mapping_confirmation_factory):
    dsl, context, dd, cd = values()
    service, _store, _receipt, compile_payload = admitted_service(tmp_path, mapping_confirmation_factory, dsl, context, dd, cd)
    put = DslFrame(
        frame_type="DSL_PUT",
        request_id="put",
        payload={
            "journey_session_id": "journey-1",
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
        DslFrame(
            frame_type="TARGET_COMPILE",
            request_id="compile",
            payload=compile_payload,
        )
    )
    assert compiled.payload["status"] == "PASS"
    result_file = next((tmp_path / "cache").glob("*/result.json"))
    result_file.write_text(result_file.read_text(encoding="utf-8").replace(dd, "sha256:" + "0" * 64), encoding="utf-8")
    tampered = service.handle(
        DslFrame(
            frame_type="TARGET_COMPILE",
            request_id="retry",
            payload=compile_payload,
        )
    )
    assert tampered.payload["diagnostics"] == ["CACHE_DIGEST_MISMATCH"]


def test_targetd_requires_declared_execute_source_bundle(tmp_path, mapping_confirmation_factory):
    source = "def run(arguments):\n    return arguments\n"
    source_digest = "sha256:" + hashlib.sha256(source.encode()).hexdigest()
    evidence_digest = "sha256:" + "e" * 64
    dsl = {
        "tool_id": "app.execute",
        "kind": "EXECUTE",
        "target": {"robot_id": "r", "evidence_digest": evidence_digest},
        "implementation": {
            "source_bundle_digest": source_digest,
            "entrypoint": "main:run",
            "runtime": "python3.12",
            "implementation_contract": "v1",
        },
    }
    context = {"robot_id": "r", "target_fingerprint": "fp", "evidence_digest": evidence_digest}
    document, _ = parse_document(dsl)
    dd, cd = dsl_digest(document), context_digest(context)
    service, _store, _receipt, base = admitted_service(tmp_path, mapping_confirmation_factory, dsl, context, dd, cd)
    assert (
        service.handle(
            DslFrame(
                frame_type="DSL_PUT",
                request_id="put",
                payload={
                    "journey_session_id": "journey-1",
                    "dsl": dsl,
                    "context": context,
                    "compiler_version": "rolo-compiler/0.1",
                    "dsl_digest": dd,
                    "context_digest": cd,
                    "target_fingerprint": "fp",
                },
            )
        ).payload["phase"]
        == "PUT"
    )
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


def test_preconfirmation_put_check_and_plan_resolve_remain_available(tmp_path):
    dsl, context, dd, cd = values()
    service = TargetdDslService(tmp_path / "cache")
    put = DslFrame(
        frame_type="DSL_PUT",
        request_id="put",
        payload={
            "journey_session_id": "journey-1",
            "dsl": dsl,
            "context": context,
            "compiler_version": "rolo-compiler/0.1",
            "dsl_digest": dd,
            "context_digest": cd,
            "target_fingerprint": "fp",
        },
    )
    assert service.handle(put).payload["phase"] == "PUT"
    assert (
        service.handle(
            DslFrame(
                frame_type="DSL_CHECK",
                request_id="check",
                payload={"dsl_digest": dd},
            )
        ).payload["status"]
        == "PASS"
    )
    assert (
        service.handle(
            DslFrame(
                frame_type="PLAN_RESOLVE",
                request_id="resolve",
                payload={"dsl_digest": dd},
            )
        ).payload["status"]
        == "PASS"
    )

    missing_admission = service.handle(
        DslFrame(
            frame_type="TARGET_COMPILE",
            request_id="compile",
            payload={
                "schema_version": "rolo-targetd-dsl-compile/v2",
                "dsl_digest": dd,
                "context_digest": cd,
                "target_fingerprint": "fp",
            },
        )
    )
    assert missing_admission.payload["status"] == "BLOCKED"
    assert missing_admission.payload["diagnostics"] == ["DSL_COMPILE_SCHEMA_INVALID"]
    legacy_admission = service.handle(
        DslFrame(
            frame_type="TARGET_COMPILE",
            request_id="legacy-compile",
            payload={
                "schema_version": "rolo-targetd-dsl-compile/v1",
                "dsl_digest": dd,
                "context_digest": cd,
                "target_fingerprint": "fp",
                "journey_session_id": "journey-1",
                "confirmation_receipt_digest": "sha256:" + "0" * 64,
            },
        )
    )
    assert legacy_admission.payload["status"] == "BLOCKED"
    assert legacy_admission.payload["diagnostics"] == ["DSL_COMPILE_SCHEMA_INVALID"]


def test_targetd_compile_requires_injected_trusted_confirmation_store(tmp_path):
    dsl, context, dd, cd = values()
    service = TargetdDslService(tmp_path / "cache")
    service.handle(
        DslFrame(
            frame_type="DSL_PUT",
            request_id="put",
            payload={
                "journey_session_id": "journey-1",
                "dsl": dsl,
                "context": context,
                "compiler_version": "rolo-compiler/0.1",
                "dsl_digest": dd,
                "context_digest": cd,
                "target_fingerprint": "fp",
            },
        )
    )
    result = service.handle(
        DslFrame(
            frame_type="TARGET_COMPILE",
            request_id="compile",
            payload={
                "schema_version": "rolo-targetd-dsl-compile/v2",
                "dsl_digest": dd,
                "context_digest": cd,
                "target_fingerprint": "fp",
                "journey_session_id": "journey-1",
                "confirmation_receipt_digest": "sha256:" + "0" * 64,
            },
        )
    )
    assert result.payload["status"] == "BLOCKED"
    assert result.payload["diagnostics"] == ["MAPPING_CONFIRMATION_STORE_REQUIRED"]


def test_targetd_rejects_expired_confirmation_before_compile(tmp_path, mapping_confirmation_factory, monkeypatch):
    dsl, context, dd, cd = values()
    service, _store, receipt, compile_payload = admitted_service(tmp_path, mapping_confirmation_factory, dsl, context, dd, cd)
    service.handle(
        DslFrame(
            frame_type="DSL_PUT",
            request_id="put",
            payload={
                "journey_session_id": "journey-1",
                "dsl": dsl,
                "context": context,
                "compiler_version": "rolo-compiler/0.1",
                "dsl_digest": dd,
                "context_digest": cd,
                "target_fingerprint": "fp",
            },
        )
    )
    assert receipt.expires_at is not None
    service.admission_gate.clock = lambda: receipt.expires_at
    monkeypatch.setattr(
        service.compiler,
        "compile",
        lambda *_args, **_kwargs: pytest.fail("compiler ran after expiry"),
    )
    result = service.handle(
        DslFrame(
            frame_type="TARGET_COMPILE",
            request_id="compile",
            payload=compile_payload,
        )
    )
    assert result.payload["status"] == "BLOCKED"
    assert result.payload["diagnostics"] == ["MAPPING_CONFIRMATION_EXPIRED"]
    assert not tuple((tmp_path / "cache").glob("*/result.json"))


def test_targetd_cancel_after_compiler_prevents_cache_commit(tmp_path, mapping_confirmation_factory, monkeypatch):
    dsl, context, dd, cd = values()
    service, store, receipt, compile_payload = admitted_service(tmp_path, mapping_confirmation_factory, dsl, context, dd, cd)
    service.handle(
        DslFrame(
            frame_type="DSL_PUT",
            request_id="put",
            payload={
                "journey_session_id": "journey-1",
                "dsl": dsl,
                "context": context,
                "compiler_version": "rolo-compiler/0.1",
                "dsl_digest": dd,
                "context_digest": cd,
                "target_fingerprint": "fp",
            },
        )
    )
    original_compile = service.compiler.compile

    def compile_then_cancel(*args, **kwargs):
        compiled = original_compile(*args, **kwargs)
        store.cancel(
            receipt.receipt_digest,
            decision_id="cancel-before-target-cache",
            actor_id="operator",
            decided_at=receipt.decided_at + timedelta(seconds=1),
        )
        return compiled

    monkeypatch.setattr(service.compiler, "compile", compile_then_cancel)
    result = service.handle(
        DslFrame(
            frame_type="TARGET_COMPILE",
            request_id="compile",
            payload=compile_payload,
        )
    )
    assert result.payload["status"] == "BLOCKED"
    assert result.payload["diagnostics"] == ["MAPPING_CONFIRMATION_CANCELLED"]
    assert not tuple((tmp_path / "cache").glob("*/result.json"))
    assert not tuple((tmp_path / "cache").glob(".*.targetd-*"))


def test_targetd_revalidates_cancelled_confirmation_before_cache_and_conformance(tmp_path, mapping_confirmation_factory):
    dsl, context, dd, cd = values()
    service, store, receipt, compile_payload = admitted_service(
        tmp_path,
        mapping_confirmation_factory,
        dsl,
        context,
        dd,
        cd,
        allow_unbound_runtime=True,
    )
    service.handle(
        DslFrame(
            frame_type="DSL_PUT",
            request_id="put",
            payload={
                "journey_session_id": "journey-1",
                "dsl": dsl,
                "context": context,
                "compiler_version": "rolo-compiler/0.1",
                "dsl_digest": dd,
                "context_digest": cd,
                "target_fingerprint": "fp",
            },
        )
    )
    assert (
        service.handle(
            DslFrame(
                frame_type="TARGET_COMPILE",
                request_id="compile",
                payload=compile_payload,
            )
        ).payload["status"]
        == "PASS"
    )
    store.cancel(
        receipt.receipt_digest,
        decision_id="cancel-decision",
        actor_id="operator",
        decided_at=receipt.decided_at + timedelta(seconds=1),
    )

    replay = service.handle(
        DslFrame(
            frame_type="TARGET_COMPILE",
            request_id="replay",
            payload=compile_payload,
        )
    )
    conformance = service.handle(
        DslFrame(
            frame_type="TARGET_CONFORMANCE",
            request_id="conformance",
            payload=compile_payload,
        )
    )
    assert replay.payload["status"] == "BLOCKED"
    assert replay.payload["diagnostics"] == ["MAPPING_CONFIRMATION_CANCELLED"]
    assert conformance.payload["status"] == "BLOCKED"
    assert conformance.payload["diagnostics"] == ["MAPPING_CONFIRMATION_CANCELLED"]


def test_targetd_rejects_confirmation_for_another_journey_identity(tmp_path, mapping_confirmation_factory):
    dsl, context, dd, cd = values()
    service, _store, _receipt, compile_payload = admitted_service(
        tmp_path,
        mapping_confirmation_factory,
        dsl,
        context,
        dd,
        cd,
        journey_session_id="journey-current",
        receipt_session_id="journey-other",
    )
    service.handle(
        DslFrame(
            frame_type="DSL_PUT",
            request_id="put",
            payload={
                "journey_session_id": "journey-current",
                "dsl": dsl,
                "context": context,
                "compiler_version": "rolo-compiler/0.1",
                "dsl_digest": dd,
                "context_digest": cd,
                "target_fingerprint": "fp",
            },
        )
    )
    result = service.handle(
        DslFrame(
            frame_type="TARGET_COMPILE",
            request_id="compile",
            payload=compile_payload,
        )
    )
    assert result.payload["status"] == "BLOCKED"
    assert result.payload["diagnostics"] == ["MAPPING_JOURNEY_SESSION_MISMATCH"]
    assert not tuple((tmp_path / "cache").glob("*/result.json"))
