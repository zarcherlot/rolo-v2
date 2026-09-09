import hashlib
import io
import json
import shutil
import sys
import tarfile
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import pytest

from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.compiler import compile_document
from rolo.dsl.context import ProbeContext
from rolo.dsl.models import DslDocument
from rolo.dsl.runner import ConformanceRunner
from rolo.releases import ReleasePublisher, tool_release_digest
from rolo.targetd import (
    ExecutionBundleManifest,
    FrameKind,
    ProtocolFrame,
    TargetdDslService,
    TargetdExecutionAuthorityStore,
    TargetdReleaseCatalog,
    TargetdService,
    TargetdV2CertifyResponse,
    encode_frame,
    ros2_registry,
)
from rolo.targetd.daemon import Ros2ReadOnlyProvider, TargetdDaemon
from rolo.targetd.ros2_runtime import (
    Ros2RuntimeResolver,
    Ros2RuntimeSnapshot,
    parse_ros2_topic_types,
)
from scripts.landerpi_n7_r0_canary import (
    _REMOTE_BOOTSTRAP_SOURCE,
    ACCESS,
    CERTIFY_CASES,
    CONTAINER,
    EXPECTED_PROVIDER_CALLS,
    MAX_PACKAGE_BYTES,
    OPERATION_KIND,
    PROVIDER_ID,
    PROVIDER_OPERATION,
    RISK,
    TARGET_ID,
    TOOL_ID,
    TOPIC,
    CanaryBlocked,
    N7R0CanaryHarness,
    N7R0Inputs,
    N7R0SnapshotBinding,
    PinnedSshCanaryChannel,
    VerifiedExecutionPlan,
    inspect_package,
    live_core_blockers,
    stage_root_for,
)


def _package(payload: bytes = b"# bounded targetd fixture\n") -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        info = tarfile.TarInfo("rolo/__init__.py")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


class _Counter:
    def __init__(self) -> None:
        self.count = 0

    def observe(self) -> dict:
        self.count += 1
        return {
            "status": "SUCCEEDED",
            "raw": f"odom-sample-{self.count}",
        }


def _target_snapshot() -> Ros2RuntimeSnapshot:
    return Ros2RuntimeSnapshot(
        "humble",
        "/opt/ros/humble/bin/ros2",
        parse_ros2_topic_types([f"{TOPIC} nav_msgs/msg/Odometry"]),
        nodes=("/odometry_node",),
        executor_user="ubuntu",
    )


class _DaemonBackedChannel:
    """Fake physical channel; ordinary frames execute through real daemon code."""

    channel_id = "fake-pinned-ssh-stdio-1"

    def __init__(
        self,
        daemon,
        counter,
        *,
        expose_raw=False,
        fail_stage=False,
        fail_close=False,
    ) -> None:
        self.daemon = daemon
        self.counter = counter
        self.expose_raw = expose_raw
        self.fail_stage = fail_stage
        self.fail_close = fail_close
        self.events: list[tuple[str, str | None]] = []
        self.requests: list[tuple[str, dict]] = []
        self.sequence = 0
        self.response_sequence = 0
        self.protocol_poisoned = False
        self.stage_roots: set[str] = set()
        self.close_count = 0

    def stage_package(
        self,
        *,
        container,
        stage_root,
        archive,
        expanded_bytes,
        bind_snapshot,
    ):
        self.events.append(("STAGE_PACKAGE", None))
        assert container == CONTAINER
        self.stage_roots.add(stage_root)
        if self.fail_stage:
            raise RuntimeError("injected partial stage failure")
        snapshot = _target_snapshot().as_dict()
        material = bind_snapshot(snapshot)
        admission_ledger = material.admission_ledger
        return {
            "schema_version": "rolo-n7-r0-stage-receipt/v1",
            "ok": True,
            "container": container,
            "stage_root": stage_root,
            "package_sha256": "sha256:" + hashlib.sha256(archive).hexdigest(),
            "admission_ledger_sha256": ("sha256:" + hashlib.sha256(admission_ledger).hexdigest()),
            "archive_bytes": len(archive),
            "expanded_bytes": expanded_bytes,
            "tmpfs_free_bytes": 4 * 1024 * 1024 * 1024,
            "ros2_snapshot_digest": snapshot["runtime_digest"],
            "ros2_path": "/opt/ros/humble/bin/ros2",
            "executor_user": "ubuntu",
            "odom_observed": True,
        }

    def exchange(self, kind, payload, *, run_id=None):
        return self.exchange_frame(kind, payload, run_id=run_id).payload

    def exchange_frame(self, kind, payload, *, run_id=None):
        if self.protocol_poisoned:
            raise CanaryBlocked("N7_R0_CHANNEL_POISONED", "fake channel is poisoned")
        self.events.append((kind, run_id))
        self.requests.append((kind, deepcopy(dict(payload))))
        frame = ProtocolFrame.create(
            kind=FrameKind(kind),
            sequence=self.sequence,
            session_id="n7-r0-session",
            run_id=run_id,
            payload=dict(payload),
        )
        self.sequence += 1
        response = self.daemon._handle(frame)
        response_payload = deepcopy(response.payload)
        if kind == "CLOSE_SESSION" and self.fail_close:
            response_payload = {
                "request_kind": "CLOSE_SESSION",
                "ok": False,
                "error": "INJECTED_CLOSE_FAILURE",
            }
        if self.expose_raw and kind == "CALL" and response_payload.get("ok") is True:
            receipt = response_payload.get("receipt")
            if isinstance(receipt, dict) and isinstance(receipt.get("result"), dict):
                receipt["result"]["raw"] = "malicious-unredacted-odom"
        correlated = ProtocolFrame.create(
            kind=response.kind,
            sequence=self.response_sequence,
            session_id=frame.session_id,
            run_id=frame.run_id,
            payload=response_payload,
        )
        assert correlated.sequence == self.response_sequence
        self.response_sequence += 1
        return correlated

    def call_certification(self, request):
        from rolo.targetd import TargetdV2CertifyResponse

        frame = self.exchange_frame(
            "CALL",
            request.model_dump(mode="json"),
            run_id=request.run_id,
        )
        return TargetdV2CertifyResponse(frame=frame, sequence_correlated=True)

    def cleanup_stage(self, *, container, stage_root):
        self.events.append(("CLEANUP_STAGE", None))
        assert container == CONTAINER
        self.stage_roots.discard(stage_root)
        return {
            "schema_version": "rolo-n7-r0-cleanup-receipt/v1",
            "ok": True,
            "container": container,
            "stage_root": stage_root,
            "residual_count": len(self.stage_roots),
        }

    def close(self):
        self.close_count += 1
        self.events.append(("CHANNEL_CLOSE", None))


def _build_fixture(
    tmp_path,
    mapping_confirmation_factory,
    *,
    expose_raw=False,
    fail_stage=False,
    fail_close=False,
):
    session_id = "n7-r0-session"
    runtime_snapshot = _target_snapshot()
    evidence_digest = runtime_snapshot.runtime_digest
    context = ProbeContext(
        robot_id=TARGET_ID,
        target_fingerprint="a" * 64,
        evidence_digest=evidence_digest,
        evidence_refs=(TOPIC,),
        message_schemas=({"schema_id": "nav_msgs/msg/Odometry"},),
        freshness={"status": "fresh"},
    )
    document = DslDocument(
        tool_id=TOOL_ID,
        kind=OPERATION_KIND,
        target={"robot_id": TARGET_ID, "evidence_digest": evidence_digest},
        binding={
            "resource_id": TOPIC,
            "interface_type": "nav_msgs/msg/Odometry",
        },
        evidence_refs=(TOPIC,),
        output_schema={"type": "object"},
    )
    dsl = document.model_dump(mode="json", exclude_none=True)
    context_payload = context.model_dump(mode="json")
    confirmed = mapping_confirmation_factory(
        dsl,
        context_payload,
        journey_session_id=session_id,
        operations=(PROVIDER_OPERATION,),
        access=ACCESS,
        risk=RISK,
    )
    compile_payload = {
        "schema_version": "rolo-targetd-dsl-compile/v2",
        "journey_session_id": session_id,
        "confirmation_receipt_digest": confirmed.receipt.receipt_digest,
        "dsl_digest": dsl_digest(document),
        "context_digest": context_digest(context),
        "target_fingerprint": context.target_fingerprint,
        "backend_hint": "ros2_observe",
        "runtime_backend_hint": "ros2_runtime",
        "required_capabilities": ["operation:OBSERVE"],
        "required_runtime_capabilities": ["read_only_topic", "ros2"],
    }
    put_payload = {
        "journey_session_id": session_id,
        "dsl": dsl,
        "context": context_payload,
        "compiler_version": "rolo-compiler/0.1",
        "dsl_digest": compile_payload["dsl_digest"],
        "context_digest": compile_payload["context_digest"],
        "target_fingerprint": context.target_fingerprint,
        "dsl_schema_version": document.schema_version,
        "context_schema_version": context.schema_version,
    }
    counter = _Counter()
    resolver = Ros2RuntimeResolver(
        runtime_snapshot
    )
    dsl_service = TargetdDslService(
        tmp_path / "targetd-dsl",
        runtime_resolver=resolver,
        backend_registry=ros2_registry(
            resolver,
            lambda _binding, _arguments: counter.observe(),
        ),
        confirmation_store=confirmed.store,
    )
    authority_store = TargetdExecutionAuthorityStore(tmp_path / "targetd-authority")
    publisher = ReleasePublisher(
        tmp_path / "catalog",
        confirmation_store=confirmed.store,
    )
    target_service = TargetdService(
        target_id=TARGET_ID,
        state_root=tmp_path / "targetd-state",
        signing_key=b"n7-r0-test-key",
        confirmation_store=confirmed.store,
        execution_authority_store=authority_store,
        release_catalog=TargetdReleaseCatalog(tmp_path / "catalog"),
    )
    daemon = TargetdDaemon(
        target_service,
        execute_calls=True,
        provider=Ros2ReadOnlyProvider(
            ros2_registry(
                resolver,
                lambda _binding, _arguments: counter.observe(),
            )
        ),
        dsl_service=dsl_service,
    )
    channel = _DaemonBackedChannel(
        daemon,
        counter,
        expose_raw=expose_raw,
        fail_stage=fail_stage,
        fail_close=fail_close,
    )
    surface_digest = "b" * 64

    def release_builder(remote_compile, target_report, target_conformance_digest):
        compiled = compile_document(
            document,
            tmp_path / "local-compile",
            context=context,
            backend_id="ros2_observe",
            required_capabilities=("operation:OBSERVE",),
            compiler_version="rolo-compiler/0.1",
            **confirmed.compiler_kwargs,
        )
        conformance = ConformanceRunner(tmp_path / "local-conformance").run(
            document,
            context,
            **confirmed.compiler_kwargs,
        )
        release = publisher.publish_verified(
            compiled,
            conformance,
            target_report,
            target_fingerprint=context.target_fingerprint,
            compiler_version="rolo-compiler/0.1",
            target_compile_artifact_digest=remote_compile["compile_artifact_digest"],
            compile_context_digest=context_digest(context),
            journey_session_id=session_id,
            confirmation_receipt_digest=confirmed.receipt.receipt_digest,
        )
        release_digest = tool_release_digest(release)
        source = b"def execute(arguments):\n    return arguments\n"
        contract = {
            "provider": PROVIDER_ID,
            "operation": PROVIDER_OPERATION,
            "topic": TOPIC,
            "operation_kind": OPERATION_KIND,
            "access": ACCESS,
            "risk": RISK,
            "mode": "READ_ONLY",
            "generated_bundle_digest": release.generated_bundle_digest,
        }
        binding_digest = hashlib.sha256(json.dumps(contract, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        manifest = ExecutionBundleManifest.build(
            tool_id=TOOL_ID,
            source=source,
            binding_digest=binding_digest,
            signer_key_id="n7-r0-test",
            signing_key=b"n7-r0-test-key",
            observation_contract=contract,
            limits={"max_duration_s": 10, "max_output_bytes": 64 * 1024},
            release_version=release_digest,
        )
        bridge = {
            "schema_version": "rolo-n7-r0-bundle-bridge/v1",
            "bundle_plan_digest": target_report.bundle_digest,
            "execution_bundle_digest": manifest.bundle_digest,
            "release_digest": release_digest,
            "target_conformance_digest": target_conformance_digest,
            "evidence_mode": "FAKE_CHANNEL",
        }
        return VerifiedExecutionPlan(
            release=release,
            release_digest=release_digest,
            target_conformance_digest=target_conformance_digest,
            manifest=manifest,
            source=source,
            bridge_proof=bridge,
            publisher=publisher,
        )

    snapshot_binding = N7R0SnapshotBinding(
        admission_ledger=confirmed.store.path.read_bytes(),
        dsl_put_payload=put_payload,
        compile_payload=compile_payload,
        release_builder=release_builder,
    )

    def bind_snapshot(snapshot):
        assert Ros2RuntimeSnapshot.from_dict(dict(snapshot)) == runtime_snapshot
        return snapshot_binding

    inputs = N7R0Inputs(
        session_id=session_id,
        certify_run_id="n6-formal-r0-test-run",
        target_id=TARGET_ID,
        surface_digest=surface_digest,
        archive=_package(),
        bind_snapshot=bind_snapshot,
    )
    return inputs, channel


def test_fake_channel_runs_real_daemon_v2_calls_and_cancel_fence(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    inputs, channel = _build_fixture(
        tmp_path,
        mapping_confirmation_factory,
    )
    factory_calls = 0

    def channel_factory():
        nonlocal factory_calls
        factory_calls += 1
        return channel

    artifact = tmp_path / "n7-r0.json"
    result = N7R0CanaryHarness(
        channel_factory,
        artifact_path=artifact,
        evidence_mode="FAKE_CHANNEL",
        clock=lambda: datetime.now(timezone.utc),
    ).run(inputs)

    assert result["status"] == "SIMULATED_PASS"
    assert result["evidence_mode"] == "FAKE_CHANNEL"
    assert result["certify_case_count"] == CERTIFY_CASES
    formal = result["formal_certify"]
    assert formal["status"] == "PASS"
    assert formal["run_id"] == inputs.certify_run_id
    assert formal["session_id"] == inputs.session_id
    assert formal["case_count"] == CERTIFY_CASES
    assert formal["receipt_count"] == CERTIFY_CASES
    assert formal["target_call_attempt_count"] == CERTIFY_CASES
    assert formal["target_call_count"] == CERTIFY_CASES
    assert formal["targetd_call_provider_invocation_count"] == CERTIFY_CASES + 1
    assert set(formal) == {
        "status",
        "session_id",
        "run_id",
        "suite_id",
        "suite_digest",
        "conclusion",
        "case_count",
        "receipt_count",
        "target_call_attempt_count",
        "target_call_count",
        "targetd_call_provider_invocation_count",
        "report",
        "artifact_index",
        "sequence_attestation",
        "raw_persisted",
    }
    assert formal["report"]["path"] == "certification-report.json"
    assert formal["artifact_index"]["path"] == "artifact-index.json"
    assert formal["sequence_attestation"]["channel_id"] == channel.channel_id
    assert formal["sequence_attestation"]["verified_result_count"] == CERTIFY_CASES
    assert result["executor_invocation_evidence"] == {
        "observed_total": EXPECTED_PROVIDER_CALLS,
        "target_conformance_t3": {
            "count": 1,
            "basis": "single-fresh-cache-target-conformance-frame",
            "conformance_idempotency_key": result["executor_invocation_evidence"][
                "target_conformance_t3"
            ]["conformance_idempotency_key"],
            "runtime_result_digest": result["executor_invocation_evidence"][
                "target_conformance_t3"
            ]["runtime_result_digest"],
        },
        "targetd_call_provider": {
            "count": CERTIFY_CASES + 1,
            "basis": "targetd-process-monotonic-counter",
        },
    }
    assert result["executor_invocation_evidence"]["target_conformance_t3"][
        "conformance_idempotency_key"
    ].startswith("sha256:")
    assert result["executor_invocation_evidence"]["target_conformance_t3"][
        "runtime_result_digest"
    ].startswith("sha256:")
    assert channel.counter.count == EXPECTED_PROVIDER_CALLS
    assert result["post_cancel"]["status"] == "BLOCKED"
    assert result["cleanup"]["residual_count"] == 0
    assert result["stage"]["executor_user"] == "ubuntu"
    assert "publisher_user" not in result["stage"]
    assert result["raw_persisted"] is False
    assert result["operator_auth"] == "FIXTURE"
    assert result["authority_partial"] is True
    assert factory_calls == 1
    assert channel.close_count == 1
    assert channel.stage_roots == set()
    assert [kind for kind, _ in channel.events].count("CALL") == 12
    assert [kind for kind, _ in channel.events].count("DSL_REQUEST") == 5
    assert [kind for kind, _ in channel.events].count("CANCEL_MAPPING") == 1
    formal_requests = [
        payload
        for kind, payload in channel.requests
        if kind == "CALL"
        and str(payload.get("idempotency_key", "")).startswith("certify:sha256:")
    ]
    assert len(formal_requests) == CERTIFY_CASES
    assert {payload["run_id"] for payload in formal_requests} == {
        inputs.certify_run_id
    }
    assert len({payload["idempotency_key"] for payload in formal_requests}) == CERTIFY_CASES
    activate_payload = next(payload for kind, payload in channel.requests if kind == "ACTIVATE_AUTHORITY")
    assert set(activate_payload) == {
        "schema_version",
        "tool_id",
        "release_digest",
        "bundle_digest",
        "expected_current_authority_head_digest",
    }
    assert activate_payload["expected_current_authority_head_digest"] is None
    cancel_payload = next(payload for kind, payload in channel.requests if kind == "CANCEL_MAPPING")
    assert set(cancel_payload) == {
        "schema_version",
        "tool_id",
        "authority_head_digest",
        "mapping_confirmation_receipt_digest",
        "idempotency_key",
    }
    assert channel.events[-3:] == [
        ("CLOSE_SESSION", None),
        ("CLEANUP_STAGE", None),
        ("CHANNEL_CLOSE", None),
    ]
    persisted = json.loads(artifact.read_text(encoding="utf-8"))
    assert persisted == result
    assert '"raw"' not in artifact.read_text(encoding="utf-8")
    formal_report = tmp_path / formal["report"]["path"]
    formal_index = tmp_path / formal["artifact_index"]["path"]
    assert hashlib.sha256(formal_report.read_bytes()).hexdigest() == formal["report"][
        "sha256"
    ]
    assert hashlib.sha256(formal_index.read_bytes()).hexdigest() == formal[
        "artifact_index"
    ]["sha256"]
    indexed = json.loads(formal_index.read_text(encoding="utf-8"))
    receipts = [
        entry
        for entry in indexed["artifacts"]
        if entry["path"].endswith(".targetd-call-receipt.json")
    ]
    assert len(receipts) == CERTIFY_CASES
    assert all((tmp_path / entry["path"]).is_file() for entry in receipts)
    assert (tmp_path / "certification-report.events.jsonl").is_file()
    assert (tmp_path / "release-binding.json").is_file()
    assert (tmp_path / "certify-test-suite.json").is_file()
    assert (tmp_path / "canary-artifact-index.json").is_file()
    authority_store = channel.daemon.service.execution_authority_store
    assert authority_store is not None
    authority = authority_store.resolve(TOOL_ID)
    assert authority.authority_head_digest == result["authority_head_digest"]
    confirmation_store = channel.daemon.service.confirmation_store
    assert confirmation_store is not None
    cancellation = confirmation_store.receipts()[-1]
    assert cancellation.decision == "CANCELLED"
    assert cancellation.actor_id == f"targetd:{TARGET_ID}"


def test_raw_provider_result_blocks_and_cleanup_still_proves_zero(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    inputs, channel = _build_fixture(
        tmp_path,
        mapping_confirmation_factory,
        expose_raw=True,
    )
    artifact = tmp_path / "blocked.json"
    result = N7R0CanaryHarness(
        lambda: channel,
        artifact_path=artifact,
        evidence_mode="FAKE_CHANNEL",
    ).run(inputs)

    assert result["status"] == "BLOCKED"
    assert result["code"] == "N7_R0_RAW_RESULT_EXPOSED"
    assert result["cleanup"]["residual_count"] == 0
    assert channel.close_count == 1
    assert '"raw"' not in artifact.read_text(encoding="utf-8")
    stored = channel.daemon.service.state.load_receipt(
        inputs.session_id,
        f"{inputs.session_id}:trace-01",
    )
    assert stored is not None
    assert stored.result is not None
    assert "raw" not in stored.result


def test_formal_artifact_conflict_blocks_before_any_certify_call_and_cleans(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    inputs, channel = _build_fixture(tmp_path, mapping_confirmation_factory)
    occupied = tmp_path / "certification-report.case-01.targetd-call-receipt.json"
    occupied.write_text("historical evidence\n", encoding="utf-8")

    result = N7R0CanaryHarness(
        lambda: channel,
        artifact_path=tmp_path / "formal-conflict-blocked.json",
        evidence_mode="FAKE_CHANNEL",
    ).run(inputs)

    assert result["status"] == "BLOCKED"
    assert result["code"] == "N7_R0_FORMAL_CERTIFY_BLOCKED"
    assert result["formal_certify"]["target_call_attempt_count"] == 0
    assert result["formal_certify"]["target_call_count"] == 0
    assert occupied.read_text(encoding="utf-8") == "historical evidence\n"
    assert [kind for kind, _ in channel.events].count("CALL") == 1
    assert [kind for kind, _ in channel.events].count("CANCEL_MAPPING") == 1
    assert result["mapping_cancel_cleanup"]["status"] == "CANCELLED"
    assert result["cleanup"]["residual_count"] == 0
    assert channel.stage_roots == set()
    assert channel.close_count == 1


def test_unverified_formal_sequence_poison_stops_later_calls_and_cleans(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    inputs, channel = _build_fixture(tmp_path, mapping_confirmation_factory)
    verified_call = channel.call_certification

    def unverified_call(request):
        response = verified_call(request)
        return TargetdV2CertifyResponse(
            frame=response.frame,
            sequence_correlated=False,
        )

    channel.call_certification = unverified_call
    artifact = tmp_path / "sequence-blocked.json"
    result = N7R0CanaryHarness(
        lambda: channel,
        artifact_path=artifact,
        evidence_mode="FAKE_CHANNEL",
    ).run(inputs)

    formal = result["formal_certify"]
    assert result["status"] == "BLOCKED"
    assert result["code"] == "N7_R0_FORMAL_CERTIFY_BLOCKED"
    assert formal["target_call_attempt_count"] == 1
    assert formal["target_call_count"] == 0
    assert formal["publication_reservation_retained"] is False
    formal_requests = [
        payload
        for kind, payload in channel.requests
        if kind == "CALL"
        and str(payload.get("idempotency_key", "")).startswith("certify:sha256:")
    ]
    assert len(formal_requests) == 1
    assert [kind for kind, _ in channel.events].count("CANCEL_MAPPING") == 1
    assert [kind for kind, _ in channel.events].count("CLOSE_SESSION") == 1
    assert result["cleanup"]["residual_count"] == 0
    assert channel.stage_roots == set()
    assert channel.close_count == 1
    assert not (tmp_path / "certification-report.json").exists()
    assert not (tmp_path / "artifact-index.json").exists()
    assert not (tmp_path / ".certify-publication.reservation").exists()
    persisted = artifact.read_text(encoding="utf-8").lower()
    assert '"raw"' not in persisted
    assert '"detail"' not in persisted
    assert '"secret"' not in persisted


def test_live_core_blockers_track_same_channel_release_provision() -> None:
    blockers = live_core_blockers()
    assert "TARGETD_BUNDLE_PLAN_EXECUTION_BRIDGE_TODO" not in blockers
    assert "TARGETD_PINNED_CHANNEL_STAGE_TODO" not in blockers
    assert "TARGETD_PROVIDER_COUNTER_EVIDENCE_TODO" not in blockers
    assert "TARGETD_EXACT_STAGE_CLEANUP_TODO" not in blockers
    assert "TARGETD_READONLY_RESULT_REDACTION_TODO" not in blockers


def test_partial_stage_failure_still_cleans_exact_root(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    inputs, channel = _build_fixture(
        tmp_path,
        mapping_confirmation_factory,
        fail_stage=True,
    )
    result = N7R0CanaryHarness(
        lambda: channel,
        artifact_path=tmp_path / "stage-blocked.json",
        evidence_mode="FAKE_CHANNEL",
    ).run(inputs)

    assert result["status"] == "BLOCKED"
    assert result["code"] == "N7_R0_UNEXPECTED_FAILURE"
    assert result["cleanup"]["residual_count"] == 0
    assert channel.stage_roots == set()
    assert channel.close_count == 1


def test_session_close_failure_cannot_skip_exact_stage_cleanup(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    inputs, channel = _build_fixture(
        tmp_path,
        mapping_confirmation_factory,
        fail_close=True,
    )
    result = N7R0CanaryHarness(
        lambda: channel,
        artifact_path=tmp_path / "close-blocked.json",
        evidence_mode="FAKE_CHANNEL",
    ).run(inputs)

    assert result["status"] == "BLOCKED"
    assert result["code"] == "N7_R0_CLOSE_SESSION_BLOCKED"
    assert result["cleanup"]["residual_count"] == 0
    assert channel.stage_roots == set()
    assert channel.close_count == 1


def test_fallback_cleanup_recovers_exact_root_but_invalidates_pinned_evidence(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    inputs, channel = _build_fixture(
        tmp_path,
        mapping_confirmation_factory,
    )
    pinned_cleanup = channel.cleanup_stage

    def fallback_cleanup(*, container, stage_root):
        receipt = dict(pinned_cleanup(container=container, stage_root=stage_root))
        receipt["schema_version"] = "rolo-n7-r0-cleanup-fallback/v1"
        receipt["cleanup_fallback_connection"] = True
        return receipt

    channel.cleanup_stage = fallback_cleanup
    result = N7R0CanaryHarness(
        lambda: channel,
        artifact_path=tmp_path / "fallback-cleanup-blocked.json",
        evidence_mode="LIVE",
    ).run(inputs)

    assert result["status"] == "BLOCKED"
    assert result["code"] == "N7_R0_CLEANUP_FALLBACK_USED"
    assert result["cleanup"] == {
        "stage_root": stage_root_for(inputs.session_id),
        "residual_count": 0,
        "cleanup_fallback_connection": True,
    }
    assert channel.stage_roots == set()
    assert channel.close_count == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("container", "wrong-container"),
        ("residual_count", False),
    ],
)
def test_harness_rejects_unbound_or_non_integer_cleanup_receipt(
    tmp_path: Path,
    mapping_confirmation_factory,
    field,
    value,
) -> None:
    inputs, channel = _build_fixture(
        tmp_path,
        mapping_confirmation_factory,
    )
    valid_cleanup = channel.cleanup_stage

    def invalid_cleanup(*, container, stage_root):
        receipt = dict(valid_cleanup(container=container, stage_root=stage_root))
        receipt[field] = value
        return receipt

    channel.cleanup_stage = invalid_cleanup
    result = N7R0CanaryHarness(
        lambda: channel,
        artifact_path=tmp_path / f"invalid-cleanup-{field}.json",
        evidence_mode="LIVE",
    ).run(inputs)

    assert result["status"] == "BLOCKED"
    assert result["code"] == "N7_R0_CLEANUP_INCOMPLETE"
    assert "cleanup" not in result
    assert channel.stage_roots == set()


def test_stage_is_fixed_to_container_dev_shm_and_package_limits() -> None:
    archive = _package(b"bounded")
    assert inspect_package(archive) == len(b"bounded")
    assert stage_root_for("session-1").startswith("/dev/shm/rolo-n7-r0-")
    assert len(archive) <= MAX_PACKAGE_BYTES


def test_pinned_bootstrap_uses_one_subprocess_for_stage_frames_and_cleanup(
    tmp_path: Path,
) -> None:
    stage_parent = tmp_path / "fake-dev-shm"
    stage_parent.mkdir()
    ros_log = tmp_path / "ros2-calls.jsonl"
    ros_script = tmp_path / "fake_ros2.py"
    ros_script.write_text(
        "\n".join(
            (
                "import json",
                "import pathlib",
                "import sys",
                f"log = pathlib.Path({str(ros_log)!r})",
                "with log.open('a', encoding='utf-8') as stream:",
                "    stream.write(json.dumps(sys.argv[1:]) + '\\n')",
                "if sys.argv[1:] == ['topic', 'list', '-t', '--no-daemon', '--spin-time', '5']:",
                "    print('/odom [nav_msgs/msg/Odometry]')",
                "elif sys.argv[1:] == ['node', 'list', '--no-daemon', '--spin-time', '5']:",
                "    print('/odometry_node')",
                "else:",
                "    raise SystemExit(2)",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    fake_targetd = r"""
import hashlib
import json
import sys

def read_exact(size):
    chunks = []
    while size:
        chunk = sys.stdin.buffer.read(size)
        if not chunk:
            break
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)

sequence = 0
while True:
    header = read_exact(4)
    if not header:
        break
    size = int.from_bytes(header, "big")
    request = json.loads(read_exact(size).decode("utf-8"))
    payload = {"request_kind": request["kind"], "ok": True}
    frame = {
        "schema_version": "rolo-targetd-frame/v1",
        "kind": "RESULT",
        "sequence": sequence,
        "session_id": request["session_id"],
        "run_id": request.get("run_id"),
        "payload": payload,
    }
    canonical = {key: value for key, value in frame.items() if value is not None}
    frame["frame_digest"] = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    encoded = json.dumps(frame, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(len(encoded).to_bytes(4, "big") + encoded)
    sys.stdout.buffer.flush()
    sequence += 1
    if request["kind"] == "CLOSE_SESSION":
        break
"""
    process_argv = [
        sys.executable,
        "-c",
        _REMOTE_BOOTSTRAP_SOURCE,
        "--test-stage-parent",
        str(stage_parent),
        "--test-ros2-python-script",
        str(ros_script),
        "--",
        sys.executable,
        "-c",
        fake_targetd,
    ]
    session_id = "subprocess-session"
    logical_root = stage_root_for(session_id)
    archive = _package(b"subprocess bootstrap")
    channel = PinnedSshCanaryChannel(
        process_argv,
        session_id=session_id,
        signing_key=b"subprocess-signing-key-fixture",
    )
    observed_snapshots = []

    def bind_snapshot(snapshot):
        observed = Ros2RuntimeSnapshot.from_dict(dict(snapshot))
        observed_snapshots.append(observed)
        return N7R0SnapshotBinding(
            admission_ledger=b'{"fixture":"confirmation"}\n',
            dsl_put_payload={},
            compile_payload={},
            release_builder=lambda *_args: None,
        )

    staged = channel.stage_package(
        container=CONTAINER,
        stage_root=logical_root,
        archive=archive,
        expanded_bytes=len(b"subprocess bootstrap"),
        bind_snapshot=bind_snapshot,
    )
    assert staged["ok"] is True
    assert staged["odom_observed"] is True
    assert staged["executor_user"] == "ubuntu"
    assert "publisher_user" not in staged
    assert (
        channel.exchange(
            "OPEN_JOURNEY",
            {"target_id": TARGET_ID, "profile_id": "landerpi"},
        )["ok"]
        is True
    )
    assert (
        channel.exchange(
            "CLOSE_SESSION",
            {"session_id": session_id},
        )["ok"]
        is True
    )
    cleanup = channel.cleanup_stage(
        container=CONTAINER,
        stage_root=logical_root,
    )
    channel.close()

    assert cleanup["residual_count"] == 0
    assert list(stage_parent.iterdir()) == []
    assert len(observed_snapshots) == 1
    assert observed_snapshots[0].publisher_user is None
    assert observed_snapshots[0].runtime_digest == staged["ros2_snapshot_digest"]
    assert [json.loads(line) for line in ros_log.read_text(encoding="utf-8").splitlines()] == [
        ["topic", "list", "-t", "--no-daemon", "--spin-time", "5"],
        ["node", "list", "--no-daemon", "--spin-time", "5"],
    ]


def test_pinned_bootstrap_rejects_missing_odom_and_cleans_partial_stage(
    tmp_path: Path,
) -> None:
    stage_parent = tmp_path / "fake-dev-shm"
    stage_parent.mkdir()
    ros_script = tmp_path / "fake_ros2_without_odom.py"
    ros_script.write_text(
        "import sys\nif sys.argv[1:] == ['topic', 'list', '-t', '--no-daemon', '--spin-time', '5']:\n"
        "    print('/scan [sensor_msgs/msg/LaserScan]')\n"
        "elif sys.argv[1:] == ['node', 'list', '--no-daemon', '--spin-time', '5']:\n"
        "    print('/scan_node')\n",
        encoding="utf-8",
    )
    process_argv = [
        sys.executable,
        "-c",
        _REMOTE_BOOTSTRAP_SOURCE,
        "--test-stage-parent",
        str(stage_parent),
        "--test-ros2-python-script",
        str(ros_script),
        "--",
        sys.executable,
        "-c",
        "raise SystemExit('child must not start')",
    ]
    session_id = "missing-odom-session"
    logical_root = stage_root_for(session_id)
    archive = _package(b"missing odom")
    channel = PinnedSshCanaryChannel(process_argv, session_id=session_id)

    with pytest.raises(CanaryBlocked, match="ROS2_ODOM_NOT_OBSERVED") as blocked:
        channel.stage_package(
            container=CONTAINER,
            stage_root=logical_root,
            archive=archive,
            expanded_bytes=len(b"missing odom"),
            bind_snapshot=lambda _snapshot: pytest.fail(
                "snapshot binder must not run without /odom"
            ),
        )
    cleanup = channel.cleanup_stage(
        container=CONTAINER,
        stage_root=logical_root,
    )
    channel.close()

    assert blocked.value.code == "N7_R0_STAGE_BLOCKED"
    assert cleanup["residual_count"] == 0
    assert list(stage_parent.iterdir()) == []


def test_pinned_bootstrap_cleans_when_snapshot_binder_rejects(
    tmp_path: Path,
) -> None:
    stage_parent = tmp_path / "fake-dev-shm"
    stage_parent.mkdir()
    ros_script = tmp_path / "fake_ros2.py"
    ros_script.write_text(
        "import sys\n"
        "if sys.argv[1:] == ['topic', 'list', '-t', '--no-daemon', '--spin-time', '5']:\n"
        "    print('/odom [nav_msgs/msg/Odometry]')\n"
        "elif sys.argv[1:] == ['node', 'list', '--no-daemon', '--spin-time', '5']:\n"
        "    print('/odometry_node')\n",
        encoding="utf-8",
    )
    process_argv = [
        sys.executable,
        "-c",
        _REMOTE_BOOTSTRAP_SOURCE,
        "--test-stage-parent",
        str(stage_parent),
        "--test-ros2-python-script",
        str(ros_script),
        "--",
        sys.executable,
        "-c",
        "raise SystemExit('child must not start')",
    ]
    session_id = "binder-reject-session"
    logical_root = stage_root_for(session_id)
    channel = PinnedSshCanaryChannel(process_argv, session_id=session_id)

    def reject_snapshot(_snapshot):
        raise CanaryBlocked("TEST_BINDER_REJECTED", "fixture rejection")

    with pytest.raises(CanaryBlocked) as blocked:
        channel.stage_package(
            container=CONTAINER,
            stage_root=logical_root,
            archive=_package(b"binder reject"),
            expanded_bytes=len(b"binder reject"),
            bind_snapshot=reject_snapshot,
        )
    cleanup = channel.cleanup_stage(container=CONTAINER, stage_root=logical_root)
    channel.close()

    assert blocked.value.code == "TEST_BINDER_REJECTED"
    assert cleanup["schema_version"] == "rolo-n7-r0-stage-receipt/v1"
    assert cleanup["residual_count"] == 0
    assert list(stage_parent.iterdir()) == []


def test_pinned_bootstrap_never_deletes_preexisting_stage_root(
    tmp_path: Path,
) -> None:
    stage_parent = tmp_path / "fake-dev-shm"
    stage_parent.mkdir()
    ros_script = tmp_path / "fake_ros2.py"
    ros_script.write_text(
        "import sys\nif sys.argv[1:] == ['topic', 'list', '-t', '--no-daemon', '--spin-time', '5']:\n"
        "    print('/odom [nav_msgs/msg/Odometry]')\n",
        encoding="utf-8",
    )
    session_id = "preexisting-stage-session"
    logical_root = stage_root_for(session_id)
    physical_root = stage_parent / PurePosixPath(logical_root).name
    physical_root.mkdir()
    sentinel = physical_root / "belongs-to-another-run"
    sentinel.write_text("preserve", encoding="utf-8")

    class RejectingFallbackExecutor:
        calls = 0

        def run_bound(self, argv, *, timeout_s):
            del timeout_s
            self.calls += 1
            assert argv[-2] == logical_root
            marker = physical_root / ".rolo-stage-owner"
            owned = marker.is_file() and marker.read_text(encoding="ascii") == argv[-1] + "\n"

            class Result:
                returncode = 2
                stdout = json.dumps(
                    {
                        "schema_version": "rolo-n7-r0-cleanup-fallback/v1",
                        "ok": False,
                        "stage_root": logical_root,
                        "residual_count": 1,
                        "owned_by_run": owned,
                    }
                )

            return Result()

    fallback_executor = RejectingFallbackExecutor()
    channel = PinnedSshCanaryChannel(
        [
            sys.executable,
            "-c",
            _REMOTE_BOOTSTRAP_SOURCE,
            "--test-stage-parent",
            str(stage_parent),
            "--test-ros2-python-script",
            str(ros_script),
            "--",
            sys.executable,
            "-c",
            "raise SystemExit('child must not start')",
        ],
        session_id=session_id,
        fallback_executor=fallback_executor,
    )

    with pytest.raises(CanaryBlocked, match="FileExistsError"):
        channel.stage_package(
            container=CONTAINER,
            stage_root=logical_root,
            archive=_package(b"collision"),
            expanded_bytes=len(b"collision"),
            bind_snapshot=lambda _snapshot: pytest.fail(
                "snapshot binder must not run on a stage-root collision"
            ),
        )
    with pytest.raises(CanaryBlocked) as cleanup_blocked:
        channel.cleanup_stage(container=CONTAINER, stage_root=logical_root)
    channel.close()

    assert cleanup_blocked.value.code == "N7_R0_CLEANUP_FALLBACK_INCOMPLETE"
    assert fallback_executor.calls == 1
    assert sentinel.read_text(encoding="utf-8") == "preserve"


def test_live_channel_never_places_signing_key_in_process_argv_or_channel_id() -> None:
    class FakeExecutor:
        def stdio_argv(self, remote_argv):
            return ["ssh", "pinned-target", *remote_argv]

    first_key = "first-ephemeral-signing-key"
    second_key = "second-ephemeral-signing-key"
    first = PinnedSshCanaryChannel.from_ssh_executor(
        FakeExecutor(),
        session_id="secret-argv-session",
        signing_key=first_key,
    )
    second = PinnedSshCanaryChannel.from_ssh_executor(
        FakeExecutor(),
        session_id="secret-argv-session",
        signing_key=second_key,
    )

    encoded_argv = json.dumps(first.process_argv)
    assert first_key not in encoded_argv
    assert second_key not in json.dumps(second.process_argv)
    assert first.channel_id == second.channel_id
    wrapper_index = first.process_argv.index("/bin/bash")
    assert first.process_argv[wrapper_index : wrapper_index + 8] == (
        "/bin/bash",
        "--noprofile",
        "--norc",
        "-c",
        'set -e; . /opt/ros/humble/setup.bash; exec "$@"',
        "rolo-n7-r0-targetd",
        "python3",
        "-c",
    )


class _MemoryProcess:
    def __init__(self) -> None:
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()
        self.returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = 143

    def kill(self):
        self.returncode = 137

    def wait(self, timeout=None):
        del timeout
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("container", "wrong-container"),
        ("residual_count", False),
    ],
)
def test_pinned_channel_rejects_unbound_or_non_integer_cleanup_receipt(
    field,
    value,
) -> None:
    session_id = "cleanup-binding-session"
    root = stage_root_for(session_id)
    channel = PinnedSshCanaryChannel(
        ["fake-ssh"],
        session_id=session_id,
        io_timeout_s=0.1,
    )
    channel._process = _MemoryProcess()
    channel._stage_root = root
    channel._stage_complete = True
    channel._daemon_closed = True
    receipt = {
        "schema_version": "rolo-n7-r0-cleanup-receipt/v1",
        "ok": True,
        "container": CONTAINER,
        "stage_root": root,
        "residual_count": 0,
    }
    receipt[field] = value
    encoded = json.dumps(receipt).encode("utf-8")
    channel._stdout_records.put(len(encoded).to_bytes(4, "big") + encoded)

    with pytest.raises(CanaryBlocked) as blocked:
        channel.cleanup_stage(container=CONTAINER, stage_root=root)

    assert blocked.value.code == "N7_R0_CLEANUP_INCOMPLETE"
    assert channel._cleanup_receipt is None


def test_fallback_cleanup_rejects_boolean_residual() -> None:
    session_id = "fallback-binding-session"
    root = stage_root_for(session_id)

    class FallbackResult:
        returncode = 0
        stdout = json.dumps(
            {
                "schema_version": "rolo-n7-r0-cleanup-fallback/v1",
                "ok": True,
                "stage_root": root,
                "residual_count": False,
            }
        )

    class FallbackExecutor:
        def run_bound(self, argv, *, timeout_s):
            del argv, timeout_s
            return FallbackResult()

    channel = PinnedSshCanaryChannel(
        ["fake-ssh"],
        session_id=session_id,
        io_timeout_s=0.1,
        fallback_executor=FallbackExecutor(),
    )

    with pytest.raises(CanaryBlocked) as blocked:
        channel._fallback_cleanup(root)

    assert blocked.value.code == "N7_R0_CLEANUP_FALLBACK_INCOMPLETE"
    assert channel._cleanup_receipt is None


def test_cached_owned_residual_uses_nonce_bound_fallback(tmp_path: Path) -> None:
    session_id = "owned-residual-session"
    root = stage_root_for(session_id)
    physical_root = tmp_path / PurePosixPath(root).name
    physical_root.mkdir()
    channel = PinnedSshCanaryChannel(
        ["fake-ssh"],
        session_id=session_id,
        io_timeout_s=0.1,
    )
    primary = _MemoryProcess()
    channel._process = primary
    marker = physical_root / ".rolo-stage-owner"
    marker.write_text(channel._stage_nonce + "\n", encoding="ascii")
    (physical_root / "partial").write_text("residual", encoding="utf-8")

    class OwnedFallbackExecutor:
        calls = 0

        def run_bound(self, argv, *, timeout_s):
            del timeout_s
            self.calls += 1
            assert primary.returncode == 143
            assert argv[-2:] == [root, channel._stage_nonce]
            owned = marker.read_text(encoding="ascii") == channel._stage_nonce + "\n"
            if owned:
                shutil.rmtree(physical_root)

            class Result:
                returncode = 0
                stdout = json.dumps(
                    {
                        "schema_version": "rolo-n7-r0-cleanup-fallback/v1",
                        "ok": True,
                        "stage_root": root,
                        "residual_count": int(physical_root.exists()),
                        "owned_by_run": owned,
                    }
                )

            return Result()

    fallback_executor = OwnedFallbackExecutor()
    channel._fallback_executor = fallback_executor
    channel._stage_root = root
    channel._remember_failed_stage(
        {
            "schema_version": "rolo-n7-r0-stage-receipt/v1",
            "ok": False,
            "container": CONTAINER,
            "stage_root": root,
            "residual_count": 1,
            "error": "injected cleanup failure",
        },
        stage_root=root,
    )

    cleanup = channel.cleanup_stage(container=CONTAINER, stage_root=root)

    assert cleanup["residual_count"] == 0
    assert cleanup["cleanup_fallback_connection"] is True
    assert fallback_executor.calls == 1
    assert primary.returncode == 143
    assert not physical_root.exists()


@pytest.mark.parametrize(
    ("sequence", "run_id", "request_kind", "expected_code"),
    [
        (1, None, "OPEN_JOURNEY", "N7_R0_PROTOCOL_SEQUENCE_MISMATCH"),
        (0, "wrong-run", "OPEN_JOURNEY", "N7_R0_PROTOCOL_IDENTITY_MISMATCH"),
        (0, None, "HAS", "N7_R0_PROTOCOL_INVALID"),
    ],
)
def test_pinned_channel_rejects_mismatched_results(
    sequence,
    run_id,
    request_kind,
    expected_code,
) -> None:
    channel = PinnedSshCanaryChannel(
        ["fake-ssh"],
        session_id="response-binding-session",
        io_timeout_s=0.1,
    )
    channel._process = _MemoryProcess()
    response = ProtocolFrame.create(
        kind=FrameKind.RESULT,
        sequence=sequence,
        session_id="response-binding-session",
        run_id=run_id,
        payload={"request_kind": request_kind, "ok": True},
    )
    channel._stdout_records.put(encode_frame(response))

    with pytest.raises(CanaryBlocked) as blocked:
        channel.exchange("OPEN_JOURNEY", {"target_id": TARGET_ID})

    assert blocked.value.code == expected_code
    written = channel._process.stdin.getvalue()
    with pytest.raises(CanaryBlocked) as poisoned:
        channel.exchange("OPEN_JOURNEY", {"target_id": TARGET_ID})
    assert poisoned.value.code == "N7_R0_CHANNEL_POISONED"
    assert channel._process.stdin.getvalue() == written


def test_pinned_channel_response_deadline_cannot_hang() -> None:
    channel = PinnedSshCanaryChannel(
        ["fake-ssh"],
        session_id="response-timeout-session",
        io_timeout_s=0.05,
    )
    process = _MemoryProcess()
    channel._process = process

    with pytest.raises(CanaryBlocked) as blocked:
        channel.exchange("OPEN_JOURNEY", {"target_id": TARGET_ID})

    assert blocked.value.code == "N7_R0_CHANNEL_TIMEOUT"
    assert process.returncode == 143
