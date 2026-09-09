from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from rolo.dsl.admission import mapping_digest
from rolo.mvp.artifacts import ArtifactIndex
from rolo.mvp.certify import (
    CertificationInvocationContext,
    CertificationInvocationOutcome,
    CertificationReceiptSidecar,
    CertificationRunner,
    certification_idempotency_key,
    certification_receipt_sidecar_text,
    verify_targetd_certification_evidence,
)
from rolo.mvp.contracts import CertificationCase, CertificationSuite
from rolo.releases import ReleaseBoundCertify, ToolRelease, tool_release_digest
from rolo.targetd.certify_adapter import (
    MAX_CERTIFY_REQUEST_RECORDS,
    TargetdV2CertifyAdapter,
    TargetdV2CertifyRequestRecord,
    TargetdV2CertifyResponse,
)
from rolo.targetd.protocol import (
    ExecutionRequest,
    FrameKind,
    JourneySession,
    ProtocolError,
    ProtocolFrame,
    TargetdCallReceipt,
    TargetdExecutionAuthority,
    provider_fence_digest,
)
from rolo.targetd.transport import JourneySessionClient


def _release_authority(tmp_path, mapping_confirmation_factory):
    target_fingerprint = "a" * 64
    evidence_digest = "sha256:" + "e" * 64
    dsl = {
        "tool_id": "app.observe.odom",
        "kind": "OBSERVE",
        "target": {"robot_id": "mentorpi", "evidence_digest": evidence_digest},
        "binding": {"resource_id": "/odom"},
    }
    context = {
        "robot_id": "mentorpi",
        "target_fingerprint": target_fingerprint,
        "evidence_digest": evidence_digest,
        "evidence_refs": ["ros2:/odom"],
    }
    confirmed = mapping_confirmation_factory(
        dsl,
        context,
        journey_session_id="certify-targetd",
        operations=("odom.sample",),
        access="read",
        risk="R0",
    )
    identity = confirmed.receipt.admission_identity()
    release = ToolRelease(
        tool_id=identity.scope.tool_id,
        target_id=identity.target_id,
        operation_kind="OBSERVE",
        dsl_digest=identity.dsl_digest,
        ir_digest=mapping_digest({"kind": "ir"}),
        probe_evidence_digest=identity.evidence_digest,
        compiler_version="test-compiler/v1",
        generated_bundle_digest=mapping_digest({"kind": "bundle-plan"}),
        conformance_digest=mapping_digest({"kind": "compiler-conformance"}),
        target_fingerprint=identity.target_fingerprint,
        compile_context_digest=identity.context_digest,
        target_conformance_digest=mapping_digest({"kind": "target-conformance"}),
        mapping_confirmation_receipt_digest=confirmed.receipt.receipt_digest,
        mapping_admission=identity,
    )
    release_digest = tool_release_digest(release)
    authority = TargetdExecutionAuthority.build(
        tool_id=release.tool_id,
        target_id=release.target_id or "",
        target_fingerprint=release.target_fingerprint,
        bundle_digest="b" * 64,
        binding_digest="c" * 64,
        surface_digest="d" * 64,
        release_digest=release_digest,
        context_digest=identity.context_digest,
        mapping_confirmation_receipt_digest=confirmed.receipt.receipt_digest,
        mapping_admission=identity,
        catalog_head_digest=mapping_digest({"kind": "catalog-head"}),
        provider_id="ros2-readonly",
        provider_operation="odom.sample",
        mode="READ_ONLY",
        fence_epoch=1,
    )

    class Publisher:
        root = tmp_path / "catalog"
        confirmation_store = confirmed.store

        @staticmethod
        def current(tool_id: str):
            return (release_digest, release) if tool_id == release.tool_id else None

    return Publisher(), release, release_digest, authority


def _receipt(
    request,
    *,
    status: str = "SUCCEEDED",
    result: dict | None = None,
    **changes,
) -> TargetdCallReceipt:
    values = {
        "schema_version": "rolo-targetd-call-receipt/v2",
        "idempotency_key": request.idempotency_key,
        "session_id": request.session_id,
        "target_id": request.target_id,
        "bundle_digest": request.bundle_digest,
        "request_digest": request.request_digest(),
        "release_digest": request.release_digest,
        "context_digest": request.context_digest,
        "mapping_confirmation_receipt_digest": (
            request.mapping_confirmation_receipt_digest
        ),
        "authority_head_digest": request.authority_head_digest,
        "fence_epoch": request.fence_epoch,
        "provider_id": request.provider_id,
        "provider_operation": request.provider_operation,
        "provider_fence_digest": provider_fence_digest(request),
        "status": status,
        "result": result
        if result is not None
        else {
            "status": "SUCCEEDED",
            "sha256": "sha256:" + hashlib.sha256(b"odom sample").hexdigest(),
            "byte_count": len(b"odom sample"),
        },
        "provider_started_at": datetime(2026, 9, 8, 7, 59, tzinfo=timezone.utc),
        "updated_at": datetime(2026, 9, 8, 8, 0, tzinfo=timezone.utc),
    }
    values.update(changes)
    return TargetdCallReceipt.model_validate(values)


def _response(request, receipt, *, run_id: str | None = None) -> ProtocolFrame:
    return ProtocolFrame.create(
        kind=FrameKind.RESULT,
        sequence=1,
        session_id=request.session_id,
        run_id=request.run_id if run_id is None else run_id,
        payload={
            "request_kind": "CALL",
            "ok": True,
            "receipt": receipt.model_dump(mode="json"),
        },
    )


def _context(release, release_digest, authority) -> CertificationInvocationContext:
    key = certification_idempotency_key(
        session_id="certify-targetd",
        run_id="certify-targetd",
        suite_digest="f" * 64,
        case_id="case-01",
    )
    return CertificationInvocationContext(
        run_id="certify-targetd",
        session_id="certify-targetd",
        suite_id="odom-r0-10",
        suite_digest="f" * 64,
        case_id="case-01",
        tool_id=release.tool_id,
        target_id=release.target_id or "",
        arguments={},
        timeout_s=30,
        risk="R0",
        stop_condition="operator stop",
        operation_id=key,
        idempotency_key=key,
        release_digest=release_digest,
        compile_context_digest=release.compile_context_digest,
        target_fingerprint=authority.target_fingerprint,
    )


def _r0_suite(release, *, suite_id: str) -> CertificationSuite:
    return CertificationSuite(
        schema_version="rolo-mvp-certification-suite/v1",
        suite_id=suite_id,
        target_id="mentorpi",
        cases=[
            CertificationCase(
                case_id=f"case-{index:02d}",
                description="sample fixed odometry",
                tool_id=release.tool_id,
                expected={"status": "SUCCEEDED"},
                risk="R0",
            )
            for index in range(1, 11)
        ],
    )


def test_targetd_v2_certify_adapter_indexes_ten_immutable_receipts(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    publisher, release, release_digest, authority = _release_authority(
        tmp_path, mapping_confirmation_factory
    )
    requests = []

    def call(request):
        requests.append(request)
        return TargetdV2CertifyResponse(
            frame=_response(request, _receipt(request)),
            sequence_correlated=True,
        )

    adapter = TargetdV2CertifyAdapter(
        authority,
        call=call,
        clock=lambda: datetime(2026, 9, 8, 8, 0, tzinfo=timezone.utc),
    )
    suite = CertificationSuite(
        schema_version="rolo-mvp-certification-suite/v1",
        suite_id="odom-r0-10",
        target_id="mentorpi",
        cases=[
            CertificationCase(
                case_id=f"case-{index:02d}",
                description="sample fixed odometry",
                tool_id=release.tool_id,
                expected={"status": "SUCCEEDED"},
                risk="R0",
            )
            for index in range(1, 11)
        ],
    )
    report, _ = ReleaseBoundCertify(
        publisher,  # type: ignore[arg-type]
        release_digests={release.tool_id: release_digest},
        target_fingerprint=release.target_fingerprint,
        evidence_digest=release.probe_evidence_digest,
        compile_context_digest=release.compile_context_digest,
        invoker=adapter,
    ).run(
        suite,
        snapshot_digest="UNKNOWN",
        output=tmp_path / "certify.json",
        session_id="certify-targetd",
        run_id="formal-run-1",
    )

    assert report.conclusion == "PASS"
    assert len(requests) == 10
    assert len({request.idempotency_key for request in requests}) == 10
    assert all(len(request.idempotency_key) <= 128 for request in requests)
    assert [item.idempotency_key for item in report.results] == [
        request.idempotency_key for request in requests
    ]
    assert [item.operation_ids for item in report.results] == [
        [request.idempotency_key] for request in requests
    ]
    assert all(
        any(value.startswith("targetd-call-receipt:sha256:") for value in item.evidence_ids)
        for item in report.results
    )

    index = json.loads((tmp_path / "artifact-index.json").read_text(encoding="utf-8"))
    receipt_paths = sorted(
        item["path"]
        for item in index["artifacts"]
        if item["path"].endswith(".targetd-call-receipt.json")
    )
    assert len(receipt_paths) == 10
    for case_number, path in enumerate(receipt_paths, start=1):
        receipt_file = tmp_path / path
        payload = json.loads(receipt_file.read_text(encoding="utf-8"))
        assert payload["case_id"] == f"case-{case_number:02d}"
        assert payload["operation_id"] == requests[case_number - 1].idempotency_key
        assert payload["receipt"]["schema_version"] == "rolo-targetd-call-receipt/v2"
        assert payload["receipt"]["status"] == "SUCCEEDED"
        assert hashlib.sha256(receipt_file.read_bytes()).hexdigest() in report.results[
            case_number - 1
        ].artifact_digests
    persisted = "\n".join(
        path.read_text(encoding="utf-8")
        for path in tmp_path.glob("*.json")
    ).lower()
    assert '"raw"' not in persisted
    assert '"detail"' not in persisted
    assert '"secret"' not in persisted
    events = [
        json.loads(line)
        for line in (tmp_path / "certify.events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert {event["run_id"] for event in events} == {"formal-run-1"}


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        ("manifest", "TARGETD_CERTIFY_INDEX_INVALID"),
        ("run", "TARGETD_CERTIFY_INDEX_IDENTITY_MISMATCH"),
        ("target", "TARGETD_CERTIFY_INDEX_IDENTITY_MISMATCH"),
    ],
)
def test_targetd_certify_evidence_rejects_tampered_index_identity(
    tmp_path: Path,
    mapping_confirmation_factory,
    mutation: str,
    error: str,
) -> None:
    publisher, release, release_digest, authority = _release_authority(
        tmp_path, mapping_confirmation_factory
    )

    def call(request):
        return TargetdV2CertifyResponse(
            frame=_response(request, _receipt(request)),
            sequence_correlated=True,
        )

    report, _ = ReleaseBoundCertify(
        publisher,  # type: ignore[arg-type]
        release_digests={release.tool_id: release_digest},
        target_fingerprint=release.target_fingerprint,
        evidence_digest=release.probe_evidence_digest,
        compile_context_digest=release.compile_context_digest,
        invoker=TargetdV2CertifyAdapter(authority, call=call),
    ).run(
        _r0_suite(release, suite_id="index-verification"),
        snapshot_digest="UNKNOWN",
        output=tmp_path / "certify.json",
        session_id="certify-targetd",
        run_id="index-verification-run",
    )
    receipt_paths = sorted(tmp_path.glob("*.targetd-call-receipt.json"))
    sidecars = []
    for path in receipt_paths:
        encoded = path.read_bytes()
        payload = json.loads(encoded)
        sidecars.append(
            CertificationReceiptSidecar(
                case_id=payload["case_id"],
                idempotency_key=payload["idempotency_key"],
                canonical_bytes=encoded,
                digest=hashlib.sha256(encoded).hexdigest(),
            )
        )
    index = ArtifactIndex.model_validate_json(
        (tmp_path / "artifact-index.json").read_text(encoding="utf-8")
    )
    if mutation == "manifest":
        index = index.model_copy(update={"manifest_sha256": "0" * 64})
    elif mutation == "run":
        index = index.model_copy(update={"run_id": "different-run"})
        index = index.model_copy(update={"manifest_sha256": index.computed_manifest()})
    else:
        index = index.model_copy(update={"target_id": "different-target"})
        index = index.model_copy(update={"manifest_sha256": index.computed_manifest()})

    with pytest.raises(ValueError, match=error):
        verify_targetd_certification_evidence(
            report,
            sidecars,
            receipt_paths=receipt_paths,
            artifact_index=index,
        )


def test_certify_idempotency_key_binds_run_suite_and_case() -> None:
    base = certification_idempotency_key(
        session_id="session-a",
        run_id="run-a",
        suite_digest="a" * 64,
        case_id="case-a",
    )
    assert base == certification_idempotency_key(
        session_id="session-a",
        run_id="run-a",
        suite_digest="a" * 64,
        case_id="case-a",
    )
    assert len(base) <= 128
    assert len(
        {
            base,
            certification_idempotency_key(
                session_id="session-b",
                run_id="run-a",
                suite_digest="a" * 64,
                case_id="case-a",
            ),
            certification_idempotency_key(
                session_id="session-a",
                run_id="run-b",
                suite_digest="a" * 64,
                case_id="case-a",
            ),
            certification_idempotency_key(
                session_id="session-a",
                run_id="run-a",
                suite_digest="b" * 64,
                case_id="case-a",
            ),
            certification_idempotency_key(
                session_id="session-a",
                run_id="run-a",
                suite_digest="a" * 64,
                case_id="case-b",
            ),
        }
    ) == 5


def test_targetd_v2_certify_receipt_sidecar_schema_is_strict() -> None:
    schema = json.loads(
        Path("schemas/TargetdV2CertifyReceiptSidecar.schema.json").read_text(
            encoding="utf-8"
        )
    )

    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])
    assert (
        schema["properties"]["schema_version"]["const"]
        == "rolo-certify-targetd-call-receipt-sidecar/v1"
    )
    assert schema["properties"]["receipt"]["allOf"][0]["$ref"] == (
        "https://rolo.dev/schemas/rolo-targetd-call-receipt-v2.json"
    )
    assert schema["properties"]["receipt"]["allOf"][1]["properties"]["status"][
        "enum"
    ] == [
        "SUCCEEDED",
        "FAILED",
        "STOPPED",
        "CANCELLED",
        "UNKNOWN",
        "NOT_ACCEPTED",
    ]


def test_release_bound_certify_generates_fresh_run_identity_in_same_session(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    publisher, release, release_digest, authority = _release_authority(
        tmp_path, mapping_confirmation_factory
    )
    requests = []

    def call(request):
        requests.append(request)
        return TargetdV2CertifyResponse(
            frame=_response(request, _receipt(request)),
            sequence_correlated=True,
        )

    suite = CertificationSuite(
        schema_version="rolo-mvp-certification-suite/v1",
        suite_id="fresh-run",
        target_id="mentorpi",
        cases=[
            CertificationCase(
                case_id=f"case-{index:02d}",
                description="sample fixed odometry",
                tool_id=release.tool_id,
                expected={"status": "SUCCEEDED"},
                risk="R0",
            )
            for index in range(1, 11)
        ],
    )
    certify = ReleaseBoundCertify(
        publisher,  # type: ignore[arg-type]
        release_digests={release.tool_id: release_digest},
        target_fingerprint=release.target_fingerprint,
        evidence_digest=release.probe_evidence_digest,
        compile_context_digest=release.compile_context_digest,
        invoker=TargetdV2CertifyAdapter(authority, call=call),
    )
    first, _ = certify.run(
        suite,
        snapshot_digest="UNKNOWN",
        output=tmp_path / "first.json",
        session_id="certify-targetd",
    )
    second, _ = certify.run(
        suite,
        snapshot_digest="UNKNOWN",
        output=tmp_path / "second.json",
        session_id="certify-targetd",
    )

    assert first.run_id != second.run_id
    assert first.run_id != "certify-targetd"
    assert second.run_id != "certify-targetd"
    assert {
        request.idempotency_key for request in requests[:10]
    }.isdisjoint({request.idempotency_key for request in requests[10:]})


def test_typed_target_terminal_status_cannot_be_expected_into_pass() -> None:
    class RefusingInvoker:
        restricted_evidence = True

        @staticmethod
        def invoke_certification(_context):
            return CertificationInvocationOutcome(
                actual={"status": "NOT_ACCEPTED", "error": "AUTHORITY_STALE"},
                restricted_evidence=True,
                target_terminal_status="NOT_ACCEPTED",
            )

    suite = CertificationSuite(
        schema_version="rolo-mvp-certification-suite/v1",
        suite_id="refused",
        target_id="mentorpi",
        cases=[
            CertificationCase(
                case_id=f"case-{index:02d}",
                description="must remain blocked",
                tool_id="app.observe.odom",
                expected={"status": "NOT_ACCEPTED"},
                risk="R0",
            )
            for index in range(1, 11)
        ],
    )
    report = CertificationRunner(RefusingInvoker(), target_id="mentorpi").run(
        suite,
        session_id="terminal-refusal",
        run_id="terminal-refusal-run",
        release_digests={"app.observe.odom": "sha256:" + "a" * 64},
        compile_context_digest="sha256:" + "b" * 64,
        target_fingerprint="c" * 64,
    )

    assert report.conclusion == "BLOCKED"
    assert {item.status.value for item in report.results} == {"BLOCKED"}
    assert {item.failure_class for item in report.results} == {
        "EXECUTION_NOT_ACCEPTED"
    }


@pytest.mark.parametrize(
    ("terminal_status", "case_status", "conclusion"),
    [
        ("FAILED", "FAIL", "CONDITIONAL"),
        ("UNKNOWN", "UNKNOWN", "BLOCKED"),
        ("CANCELLED", "UNKNOWN", "BLOCKED"),
        ("STOPPED", "UNKNOWN", "BLOCKED"),
    ],
)
def test_typed_target_terminal_failure_semantics_are_not_matchable(
    terminal_status: str,
    case_status: str,
    conclusion: str,
) -> None:
    class TerminalInvoker:
        restricted_evidence = True

        @staticmethod
        def invoke_certification(_context):
            return CertificationInvocationOutcome(
                actual={"status": terminal_status},
                restricted_evidence=True,
                target_terminal_status=terminal_status,
            )

    suite = CertificationSuite(
        schema_version="rolo-mvp-certification-suite/v1",
        suite_id="terminal-failure",
        target_id="mentorpi",
        cases=[
            CertificationCase(
                case_id=f"case-{index:02d}",
                description="must preserve target terminal status",
                tool_id="app.observe.odom",
                expected={"status": terminal_status},
                risk="R0",
            )
            for index in range(1, 11)
        ],
    )
    report = CertificationRunner(TerminalInvoker(), target_id="mentorpi").run(
        suite,
        session_id="terminal-failure",
        run_id="terminal-failure-run",
        release_digests={"app.observe.odom": "sha256:" + "a" * 64},
        compile_context_digest="sha256:" + "b" * 64,
        target_fingerprint="c" * 64,
    )

    assert report.conclusion == conclusion
    assert {item.status.value for item in report.results} == {case_status}


def test_targetd_v2_certify_adapter_rejects_non_r0_case(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    _, release, release_digest, authority = _release_authority(
        tmp_path, mapping_confirmation_factory
    )
    adapter = TargetdV2CertifyAdapter(
        authority,
        call=lambda _request: (_ for _ in ()).throw(
            AssertionError("transport must not be called")
        ),
    )

    with pytest.raises(ProtocolError, match="TARGETD_CERTIFY_CONTEXT_MISMATCH"):
        adapter.invoke_certification(
            replace(_context(release, release_digest, authority), risk="R1")
        )
    with pytest.raises(ProtocolError, match="TARGETD_CERTIFY_CONTEXT_MISMATCH"):
        adapter.invoke_certification(
            replace(
                _context(release, release_digest, authority),
                suite_digest="1" * 64,
            )
        )


def test_targetd_v2_certify_adapter_reuses_exact_request_on_retry(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    _, release, release_digest, authority = _release_authority(
        tmp_path, mapping_confirmation_factory
    )
    requests = []
    clock_values = iter(
        [
            datetime(2026, 9, 8, 8, 0, tzinfo=timezone.utc),
            datetime(2026, 9, 8, 8, 5, tzinfo=timezone.utc),
        ]
    )

    def call(request):
        requests.append(request)
        return TargetdV2CertifyResponse(
            frame=_response(request, _receipt(request)),
            sequence_correlated=True,
        )

    adapter = TargetdV2CertifyAdapter(
        authority,
        call=call,
        clock=lambda: next(clock_values),
    )
    context = _context(release, release_digest, authority)

    first = adapter.invoke_certification(context)
    second = adapter.invoke_certification(context)

    assert first == second
    assert len(requests) == 2
    assert requests[0].deadline == requests[1].deadline
    assert requests[0].request_digest() == requests[1].request_digest()


def test_targetd_v2_certify_adapter_rejects_corrupt_or_full_request_store(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    _, release, release_digest, authority = _release_authority(
        tmp_path, mapping_confirmation_factory
    )
    records: dict[str, TargetdV2CertifyRequestRecord] = {}

    def call(request):
        return TargetdV2CertifyResponse(
            frame=_response(request, _receipt(request)),
            sequence_correlated=True,
        )

    context = _context(release, release_digest, authority)
    adapter = TargetdV2CertifyAdapter(
        authority,
        call=call,
        request_store=records,
    )
    adapter.invoke_certification(context)
    record = records[context.idempotency_key]
    records[context.idempotency_key] = replace(
        record,
        request_json=record.request_json.replace(
            b'"mode":"READ_ONLY"',
            b'"mode":"READ_ONLX"',
        ),
    )
    with pytest.raises(ProtocolError, match="REQUEST_STORE_INVALID"):
        adapter.invoke_certification(context)

    records.clear()
    for index in range(MAX_CERTIFY_REQUEST_RECORDS):
        records[f"occupied-{index}"] = record
    with pytest.raises(ProtocolError, match="REQUEST_STORE_FULL"):
        adapter.invoke_certification(context)


def test_targetd_v2_certify_sidecar_exposes_only_fresh_payload_copies(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    _, release, release_digest, authority = _release_authority(
        tmp_path, mapping_confirmation_factory
    )

    def call(request):
        return TargetdV2CertifyResponse(
            frame=_response(request, _receipt(request)),
            sequence_correlated=True,
        )

    outcome = TargetdV2CertifyAdapter(authority, call=call).invoke_certification(
        _context(release, release_digest, authority)
    )
    assert outcome.receipt_sidecar is not None
    original_bytes = outcome.receipt_sidecar.canonical_bytes
    exposed = outcome.receipt_sidecar.payload
    exposed["case_id"] = "case-tampered"
    exposed["receipt"]["result"]["byte_count"] = 999

    assert outcome.receipt_sidecar.canonical_bytes == original_bytes
    assert outcome.receipt_sidecar.payload["case_id"] == "case-01"
    assert outcome.receipt_sidecar.payload["receipt"]["result"]["byte_count"] == len(
        b"odom sample"
    )
    assert hashlib.sha256(original_bytes).hexdigest() == outcome.receipt_sidecar.digest


def test_formal_certify_rejects_mutable_sidecars_without_publishing(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    publisher, release, release_digest, _ = _release_authority(
        tmp_path, mapping_confirmation_factory
    )
    buffers = []

    class MutableSidecarInvoker:
        requires_receipt_sidecar = True
        requires_target_terminal_status = True

        @staticmethod
        def invoke_certification(context):
            if buffers:
                buffers[0].extend(b"mutated-after-first-case")
            encoded = bytearray(b"{}\n")
            buffers.append(encoded)
            return CertificationInvocationOutcome(
                actual={
                    "status": "SUCCEEDED",
                    "sha256": "sha256:" + "a" * 64,
                    "byte_count": 0,
                },
                receipt_sidecar=CertificationReceiptSidecar(
                    case_id=context.case_id,
                    idempotency_key=context.idempotency_key,
                    canonical_bytes=encoded,  # type: ignore[arg-type]
                    digest=hashlib.sha256(encoded).hexdigest(),
                ),
                restricted_evidence=True,
                target_terminal_status="SUCCEEDED",
            )

    with pytest.raises(ValueError, match="TARGETD_CERTIFY_RECEIPTS_INCOMPLETE"):
        ReleaseBoundCertify(
            publisher,  # type: ignore[arg-type]
            release_digests={release.tool_id: release_digest},
            target_fingerprint=release.target_fingerprint,
            evidence_digest=release.probe_evidence_digest,
            compile_context_digest=release.compile_context_digest,
            invoker=MutableSidecarInvoker(),
        ).run(
            _r0_suite(release, suite_id="mutable-sidecars"),
            snapshot_digest="UNKNOWN",
            output=tmp_path / "certify.json",
            session_id="certify-targetd",
            run_id="mutable-sidecars-run",
        )

    assert len(buffers) == 10
    assert not (tmp_path / "certify.json").exists()
    assert not (tmp_path / "artifact-index.json").exists()


def test_formal_certify_rejects_report_result_that_differs_from_receipt(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    publisher, release, release_digest, authority = _release_authority(
        tmp_path, mapping_confirmation_factory
    )
    requests = []

    def call(request):
        requests.append(request)
        return TargetdV2CertifyResponse(
            frame=_response(request, _receipt(request)),
            sequence_correlated=True,
        )

    adapter = TargetdV2CertifyAdapter(authority, call=call)

    class ResultChangingInvoker:
        requires_receipt_sidecar = True
        requires_target_terminal_status = True

        @staticmethod
        def invoke_certification(context):
            outcome = adapter.invoke_certification(context)
            return replace(
                outcome,
                actual={
                    "status": "SUCCEEDED",
                    "sha256": "sha256:" + "b" * 64,
                    "byte_count": 11,
                },
            )

    with pytest.raises(
        ValueError,
        match="TARGETD_CERTIFY_REPORT_RECEIPT_RESULT_MISMATCH",
    ):
        ReleaseBoundCertify(
            publisher,  # type: ignore[arg-type]
            release_digests={release.tool_id: release_digest},
            target_fingerprint=release.target_fingerprint,
            evidence_digest=release.probe_evidence_digest,
            compile_context_digest=release.compile_context_digest,
            invoker=ResultChangingInvoker(),
        ).run(
            _r0_suite(release, suite_id="receipt-result-mismatch"),
            snapshot_digest="UNKNOWN",
            output=tmp_path / "certify.json",
            session_id="certify-targetd",
            run_id="receipt-result-mismatch-run",
        )

    assert len(requests) == 10
    assert not (tmp_path / "certify.json").exists()
    assert not (tmp_path / "artifact-index.json").exists()
    assert not (tmp_path / ".certify-publication.reservation").exists()


@pytest.mark.parametrize("mutation", ["status-conflict", "missing-required-field"])
def test_formal_certify_rejects_malformed_receipt_that_could_match_report(
    tmp_path: Path,
    mapping_confirmation_factory,
    mutation: str,
) -> None:
    publisher, release, release_digest, authority = _release_authority(
        tmp_path, mapping_confirmation_factory
    )
    requests = []

    def call(request):
        requests.append(request)
        return TargetdV2CertifyResponse(
            frame=_response(request, _receipt(request)),
            sequence_correlated=True,
        )

    adapter = TargetdV2CertifyAdapter(authority, call=call)

    class ReceiptChangingInvoker:
        requires_receipt_sidecar = True
        requires_target_terminal_status = True

        @staticmethod
        def invoke_certification(context):
            outcome = adapter.invoke_certification(context)
            assert outcome.receipt_sidecar is not None
            payload = outcome.receipt_sidecar.payload
            if mutation == "status-conflict":
                payload["receipt"]["result"]["status"] = "FAILED"
            else:
                payload["receipt"].pop("request_digest")
            encoded = certification_receipt_sidecar_text(payload).encode("utf-8")
            return replace(
                outcome,
                actual=dict(payload["receipt"]["result"]),
                receipt_sidecar=CertificationReceiptSidecar(
                    case_id=context.case_id,
                    idempotency_key=context.idempotency_key,
                    canonical_bytes=encoded,
                    digest=hashlib.sha256(encoded).hexdigest(),
                ),
            )

    suite = CertificationSuite(
        schema_version="rolo-mvp-certification-suite/v1",
        suite_id=f"malformed-receipt-{mutation}",
        target_id="mentorpi",
        cases=[
            CertificationCase(
                case_id=f"case-{index:02d}",
                description="malformed receipt must not certify",
                tool_id=release.tool_id,
                expected={"byte_count": 11},
                risk="R0",
            )
            for index in range(1, 11)
        ],
    )
    with pytest.raises(ValueError, match="TARGETD_CERTIFY_RECEIPT_PAYLOAD_INVALID"):
        ReleaseBoundCertify(
            publisher,  # type: ignore[arg-type]
            release_digests={release.tool_id: release_digest},
            target_fingerprint=release.target_fingerprint,
            evidence_digest=release.probe_evidence_digest,
            compile_context_digest=release.compile_context_digest,
            invoker=ReceiptChangingInvoker(),
        ).run(
            suite,
            snapshot_digest="UNKNOWN",
            output=tmp_path / "certify.json",
            session_id="certify-targetd",
            run_id=f"malformed-receipt-{mutation}-run",
        )

    assert len(requests) == 10
    assert not (tmp_path / "certify.json").exists()
    assert not (tmp_path / "artifact-index.json").exists()
    assert not (tmp_path / ".certify-publication.reservation").exists()


def test_release_bound_certify_releases_reservation_after_early_failure(
    tmp_path: Path,
    mapping_confirmation_factory,
    monkeypatch,
) -> None:
    publisher, release, release_digest, authority = _release_authority(
        tmp_path, mapping_confirmation_factory
    )
    requests = []

    def call(request):
        requests.append(request)
        return TargetdV2CertifyResponse(
            frame=_response(request, _receipt(request)),
            sequence_correlated=True,
        )

    certify = ReleaseBoundCertify(
        publisher,  # type: ignore[arg-type]
        release_digests={release.tool_id: release_digest},
        target_fingerprint=release.target_fingerprint,
        evidence_digest=release.probe_evidence_digest,
        compile_context_digest=release.compile_context_digest,
        invoker=TargetdV2CertifyAdapter(authority, call=call),
    )
    suite = _r0_suite(release, suite_id="reservation-early-failure")

    def fail_before_cases(*_args, **_kwargs):
        raise RuntimeError("injected early failure")

    with monkeypatch.context() as scoped:
        scoped.setattr(
            "rolo.releases.journey.CertificationRunner.run",
            fail_before_cases,
        )
        with pytest.raises(RuntimeError, match="injected early failure"):
            certify.run(
                suite,
                snapshot_digest="UNKNOWN",
                output=tmp_path / "certify.json",
                session_id="certify-targetd",
                run_id="reservation-early-attempt",
            )

    assert requests == []
    assert not (tmp_path / ".certify-publication.reservation").exists()

    report, paths = certify.run(
        suite,
        snapshot_digest="UNKNOWN",
        output=tmp_path / "certify.json",
        session_id="certify-targetd",
        run_id="reservation-early-retry",
    )

    assert report.conclusion == "PASS"
    assert paths[0] == tmp_path / "certify.json"
    assert len(requests) == 10
    assert len({request.idempotency_key for request in requests}) == 10
    assert not (tmp_path / ".certify-publication.reservation").exists()


def test_release_bound_certify_late_failure_preserves_artifacts_and_retry_plan(
    tmp_path: Path,
    mapping_confirmation_factory,
    monkeypatch,
) -> None:
    from rolo.releases import journey as release_journey

    publisher, release, release_digest, authority = _release_authority(
        tmp_path, mapping_confirmation_factory
    )
    requests = []

    def call(request):
        requests.append(request)
        return TargetdV2CertifyResponse(
            frame=_response(request, _receipt(request)),
            sequence_correlated=True,
        )

    certify = ReleaseBoundCertify(
        publisher,  # type: ignore[arg-type]
        release_digests={release.tool_id: release_digest},
        target_fingerprint=release.target_fingerprint,
        evidence_digest=release.probe_evidence_digest,
        compile_context_digest=release.compile_context_digest,
        invoker=TargetdV2CertifyAdapter(authority, call=call),
    )
    suite = _r0_suite(release, suite_id="reservation-late-failure")
    original_write = release_journey.write_new_artifact

    def fail_after_first_receipt(path, content):
        original_write(path, content)
        if path.name == "certify.case-01.targetd-call-receipt.json":
            raise OSError("injected late publication failure")

    with monkeypatch.context() as scoped:
        scoped.setattr(release_journey, "write_new_artifact", fail_after_first_receipt)
        with pytest.raises(OSError, match="injected late publication failure"):
            certify.run(
                suite,
                snapshot_digest="UNKNOWN",
                output=tmp_path / "certify.json",
                session_id="certify-targetd",
                run_id="reservation-late-attempt",
            )

    assert len(requests) == 10
    first_request_identities = [
        (request.idempotency_key, request.request_digest(), request.deadline)
        for request in requests
    ]
    assert len({identity[0] for identity in first_request_identities}) == 10
    assert not (tmp_path / ".certify-publication.reservation").exists()
    historical = {
        path.name: path.read_bytes()
        for path in tmp_path.iterdir()
        if path.is_file()
    }
    assert "certify.json" in historical
    assert "certify.case-01.targetd-call-receipt.json" in historical
    assert "artifact-index.json" not in historical

    report, paths = certify.run(
        suite,
        snapshot_digest="UNKNOWN",
        output=tmp_path / "certify.json",
        session_id="certify-targetd",
        run_id="reservation-late-attempt",
    )

    assert report.conclusion == "PASS"
    assert paths[0] == tmp_path / "certify.reservation-late-attempt.json"
    assert (tmp_path / "certify.reservation-late-attempt.artifact-index.json").is_file()
    assert all((tmp_path / name).read_bytes() == payload for name, payload in historical.items())
    assert len(requests) == 20
    retry_request_identities = [
        (request.idempotency_key, request.request_digest(), request.deadline)
        for request in requests[10:]
    ]
    assert retry_request_identities == first_request_identities
    assert not (tmp_path / ".certify-publication.reservation").exists()


@pytest.mark.parametrize("occupied_kind", ["file", "symlink"])
def test_release_bound_certify_preflights_receipt_paths_before_report_write(
    tmp_path: Path,
    mapping_confirmation_factory,
    occupied_kind: str,
) -> None:
    publisher, release, release_digest, authority = _release_authority(
        tmp_path, mapping_confirmation_factory
    )

    calls = []

    def call(request):
        calls.append(request)
        return TargetdV2CertifyResponse(
            frame=_response(request, _receipt(request)),
            sequence_correlated=True,
        )

    adapter = TargetdV2CertifyAdapter(authority, call=call)
    suite = CertificationSuite(
        schema_version="rolo-mvp-certification-suite/v1",
        suite_id="preflight",
        target_id="mentorpi",
        cases=[
            CertificationCase(
                case_id=f"case-{index:02d}",
                description="sample fixed odometry",
                tool_id=release.tool_id,
                expected={"status": "SUCCEEDED"},
                risk="R0",
            )
            for index in range(1, 11)
        ],
    )
    occupied = tmp_path / "certify.case-01.targetd-call-receipt.json"
    if occupied_kind == "file":
        occupied.write_text("historical evidence\n", encoding="utf-8")
    else:
        target = tmp_path / "historical-receipt.json"
        target.write_text("historical evidence\n", encoding="utf-8")
        try:
            occupied.symlink_to(target)
        except OSError:
            pytest.skip("symlink creation is unavailable")

    with pytest.raises(ValueError, match="artifact"):
        ReleaseBoundCertify(
            publisher,  # type: ignore[arg-type]
            release_digests={release.tool_id: release_digest},
            target_fingerprint=release.target_fingerprint,
            evidence_digest=release.probe_evidence_digest,
            compile_context_digest=release.compile_context_digest,
            invoker=adapter,
        ).run(
            suite,
            snapshot_digest="UNKNOWN",
            output=tmp_path / "certify.json",
            session_id="certify-targetd",
            run_id="preflight-run",
        )

    assert not (tmp_path / "certify.json").exists()
    assert not (tmp_path / "certify.md").exists()
    assert not (tmp_path / "certify.html").exists()
    assert not (tmp_path / "artifact-index.json").exists()
    assert not (tmp_path / "release-binding.json").exists()
    assert not (tmp_path / "certify-test-suite.json").exists()
    assert not (tmp_path / "certify.events.jsonl").exists()
    assert calls == []


@pytest.mark.parametrize("failure", ["parent-file", "invalid-snapshot"])
def test_release_bound_certify_rejects_unpublishable_inputs_before_call(
    tmp_path: Path,
    mapping_confirmation_factory,
    failure: str,
) -> None:
    publisher, release, release_digest, authority = _release_authority(
        tmp_path, mapping_confirmation_factory
    )
    calls = []

    def call(request):
        calls.append(request)
        return TargetdV2CertifyResponse(
            frame=_response(request, _receipt(request)),
            sequence_correlated=True,
        )

    output = tmp_path / "certify.json"
    snapshot_digest = "UNKNOWN"
    if failure == "parent-file":
        parent = tmp_path / "not-a-directory"
        parent.write_text("occupied\n", encoding="utf-8")
        output = parent / "certify.json"
    else:
        snapshot_digest = "not-a-digest"

    with pytest.raises((OSError, ValueError)):
        ReleaseBoundCertify(
            publisher,  # type: ignore[arg-type]
            release_digests={release.tool_id: release_digest},
            target_fingerprint=release.target_fingerprint,
            evidence_digest=release.probe_evidence_digest,
            compile_context_digest=release.compile_context_digest,
            invoker=TargetdV2CertifyAdapter(authority, call=call),
        ).run(
            _r0_suite(release, suite_id="precall-validation"),
            snapshot_digest=snapshot_digest,
            output=output,
            session_id="certify-targetd",
            run_id="precall-validation-run",
        )

    assert calls == []


def test_release_bound_certify_checks_output_is_writable_before_call(
    tmp_path: Path,
    mapping_confirmation_factory,
    monkeypatch,
) -> None:
    publisher, release, release_digest, authority = _release_authority(
        tmp_path, mapping_confirmation_factory
    )
    calls = []

    def deny_write(*_args, **_kwargs):
        raise PermissionError("read-only destination")

    monkeypatch.setattr("rolo.mvp.certify.tempfile.mkstemp", deny_write)
    with pytest.raises(PermissionError, match="read-only"):
        ReleaseBoundCertify(
            publisher,  # type: ignore[arg-type]
            release_digests={release.tool_id: release_digest},
            target_fingerprint=release.target_fingerprint,
            evidence_digest=release.probe_evidence_digest,
            compile_context_digest=release.compile_context_digest,
            invoker=TargetdV2CertifyAdapter(
                authority,
                call=lambda request: calls.append(request),
            ),
        ).run(
            _r0_suite(release, suite_id="unwritable-output"),
            snapshot_digest="UNKNOWN",
            output=tmp_path / "certify.json",
            session_id="certify-targetd",
            run_id="unwritable-output-run",
        )

    assert calls == []


def test_release_bound_certify_reserves_same_output_before_call(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    publisher, release, release_digest, authority = _release_authority(
        tmp_path, mapping_confirmation_factory
    )
    first_call_started = threading.Event()
    finish_first_call = threading.Event()
    requests = []
    first_error = []

    def call(request):
        requests.append(request)
        if request.run_id == "reservation-first" and len(requests) == 1:
            first_call_started.set()
            assert finish_first_call.wait(timeout=10)
        return TargetdV2CertifyResponse(
            frame=_response(request, _receipt(request)),
            sequence_correlated=True,
        )

    certify = ReleaseBoundCertify(
        publisher,  # type: ignore[arg-type]
        release_digests={release.tool_id: release_digest},
        target_fingerprint=release.target_fingerprint,
        evidence_digest=release.probe_evidence_digest,
        compile_context_digest=release.compile_context_digest,
        invoker=TargetdV2CertifyAdapter(authority, call=call),
    )
    suite = _r0_suite(release, suite_id="exclusive-reservation")
    second_suite = CertificationSuite(
        schema_version="rolo-mvp-certification-suite/v1",
        suite_id="overlapping-but-different-plan",
        target_id="mentorpi",
        cases=[
            CertificationCase(
                case_id=f"other-{index:02d}",
                description="sample fixed odometry",
                tool_id=release.tool_id,
                expected={"status": "SUCCEEDED"},
                risk="R0",
            )
            for index in range(1, 11)
        ],
    )

    def first_run() -> None:
        try:
            certify.run(
                suite,
                snapshot_digest="UNKNOWN",
                output=tmp_path / "certify.json",
                session_id="certify-targetd",
                run_id="reservation-first",
            )
        except Exception as exc:  # pragma: no cover - asserted below
            first_error.append(exc)

    thread = threading.Thread(target=first_run)
    thread.start()
    assert first_call_started.wait(timeout=10)
    try:
        with pytest.raises(ValueError, match="already reserved"):
            certify.run(
                second_suite,
                snapshot_digest="UNKNOWN",
                output=tmp_path / "certify.json",
                session_id="certify-targetd",
                run_id="reservation-second",
            )
        assert not any(
            request.run_id == "reservation-second" for request in requests
        )
    finally:
        finish_first_call.set()
        thread.join(timeout=15)

    assert not thread.is_alive()
    assert first_error == []
    assert len([request for request in requests if request.run_id == "reservation-first"]) == 10


def test_release_bound_certify_sanitizes_binding_check_errors(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    publisher, release, release_digest, authority = _release_authority(
        tmp_path, mapping_confirmation_factory
    )
    calls = []

    def call(request):
        calls.append(request)
        return TargetdV2CertifyResponse(
            frame=_response(request, _receipt(request)),
            sequence_correlated=True,
        )

    def raise_secret(_tool_id):
        raise RuntimeError("token=do-not-persist C:/private/device.key")

    publisher.current = raise_secret
    report, _ = ReleaseBoundCertify(
        publisher,  # type: ignore[arg-type]
        release_digests={release.tool_id: release_digest},
        target_fingerprint=release.target_fingerprint,
        evidence_digest=release.probe_evidence_digest,
        compile_context_digest=release.compile_context_digest,
        invoker=TargetdV2CertifyAdapter(authority, call=call),
    ).run(
        _r0_suite(release, suite_id="safe-binding-error"),
        snapshot_digest="UNKNOWN",
        output=tmp_path / "certify.json",
        session_id="certify-targetd",
        run_id="safe-binding-error-run",
    )

    assert report.conclusion == "BLOCKED"
    assert calls == []
    persisted = "\n".join(
        path.read_text(encoding="utf-8")
        for path in tmp_path.glob("certify*")
        if path.is_file()
    ).lower()
    assert "do-not-persist" not in persisted
    assert "c:/private" not in persisted
    assert "token=" not in persisted
    assert {
        item.actual["error"] for item in report.results
    } == {"RELEASE_CURRENT_CHECK_FAILED"}


def test_targetd_v2_certify_journey_client_glue_rejects_wrong_sequence(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    _, release, release_digest, authority = _release_authority(
        tmp_path, mapping_confirmation_factory
    )

    class WrongSequenceChannel:
        def __init__(self):
            self.response = None
            self.send_count = 0

        def send(self, frame):
            self.send_count += 1
            request = ExecutionRequest.model_validate(frame.payload)
            self.response = _response(request, _receipt(request))

        def receive(self):
            assert self.response is not None
            return self.response

        def close(self):
            return None

    session = JourneySession.create(
        session_id="certify-targetd",
        target_id="mentorpi",
        profile_id="landerpi",
    )
    channel = WrongSequenceChannel()
    client = JourneySessionClient(channel, session)
    adapter = TargetdV2CertifyAdapter.from_journey_client(authority, client)
    context = _context(release, release_digest, authority)

    with pytest.raises(ProtocolError, match="response sequence"):
        adapter.invoke_certification(context)
    with pytest.raises(ProtocolError, match="unusable after a channel failure"):
        adapter.invoke_certification(context)
    assert channel.send_count == 1


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        ("bare-frame", "TARGETD_CERTIFY_RESPONSE_METADATA_REQUIRED"),
        ("unverified-sequence", "TARGETD_CERTIFY_RESPONSE_SEQUENCE_UNVERIFIED"),
        ("wrong-run", "TARGETD_CERTIFY_RESPONSE_IDENTITY_MISMATCH"),
        ("wrong-receipt", "TARGETD_CERTIFY_RECEIPT_IDENTITY_MISMATCH"),
        ("started", "TARGETD_CERTIFY_RECEIPT_NOT_TERMINAL"),
        ("raw-result", "TARGETD_CERTIFY_RESULT_INVALID"),
        ("oversize-result", "TARGETD_CERTIFY_RESULT_INVALID"),
        ("missing-start", "TARGETD_CERTIFY_RECEIPT_TIME_INVALID"),
    ],
)
def test_targetd_v2_certify_adapter_fails_closed_on_unproven_receipts(
    tmp_path: Path,
    mapping_confirmation_factory,
    mutation: str,
    error: str,
) -> None:
    _, release, release_digest, authority = _release_authority(
        tmp_path, mapping_confirmation_factory
    )

    def call(request):
        receipt = _receipt(request)
        if mutation == "wrong-receipt":
            receipt = _receipt(request, target_id="different-target")
        elif mutation == "started":
            receipt = _receipt(request, status="STARTED", result=None)
        elif mutation == "raw-result":
            receipt = _receipt(
                request,
                result={"status": "SUCCEEDED", "raw": "private payload"},
            )
        elif mutation == "oversize-result":
            receipt = _receipt(
                request,
                result={
                    "status": "SUCCEEDED",
                    "sha256": "sha256:" + "a" * 64,
                    "byte_count": 65_537,
                },
            )
        elif mutation == "missing-start":
            receipt = _receipt(request, provider_started_at=None)
        frame = _response(
            request,
            receipt,
            run_id="different-run" if mutation == "wrong-run" else None,
        )
        if mutation == "bare-frame":
            return frame
        return TargetdV2CertifyResponse(
            frame=frame,
            sequence_correlated=mutation != "unverified-sequence",
        )

    adapter = TargetdV2CertifyAdapter(authority, call=call)
    with pytest.raises(ProtocolError, match=error):
        adapter.invoke_certification(_context(release, release_digest, authority))
