from pathlib import Path

import pytest
from pydantic import ValidationError

from rolo.releases.targetd_upload import (
    TargetdReleaseUploadAdapter,
    TargetdReleaseUploadBeginRequest,
    TargetdReleaseUploadBeginResponse,
    TargetdReleaseUploadCommitRequest,
    TargetdReleaseUploadCommitResponse,
    TargetdReleaseUploadError,
    TargetdReleaseUploadPutChunkRequest,
    TargetdReleaseUploadPutChunkResponse,
    TargetdReleaseUploadReceipt,
    TargetdReleaseUploadRequest,
    TargetdReleaseUploadResponse,
    TargetdReleaseUploadService,
    TargetdReleaseUploadStatusRequest,
    TargetdReleaseUploadStatusResponse,
    targetd_release_upload_idempotency_key,
)
from rolo.releases.upload import ContentAddressedUploadStore, UploadCommit


class FakeTargetdReleaseUploadTransport:
    """Typed fake targetd endpoint backed by the production upload store."""

    def __init__(self, root: Path) -> None:
        self.store = ContentAddressedUploadStore(root)
        self.calls: list[TargetdReleaseUploadRequest] = []
        self.disconnect_after_chunk: int | None = None
        self.tamper_operation: str | None = None
        self.tamper_commit = False

    def exchange(
        self,
        request: TargetdReleaseUploadRequest,
    ) -> TargetdReleaseUploadResponse:
        self.calls.append(request)
        common = {
            "target_id": request.target_id,
            "session_id": request.session_id,
            "manifest_digest": request.manifest_digest,
            "idempotency_key": request.idempotency_key,
            "request_digest": request.request_digest,
        }
        response: TargetdReleaseUploadResponse
        if isinstance(request, TargetdReleaseUploadBeginRequest):
            response = TargetdReleaseUploadBeginResponse(
                **common,
                upload_status=self.store.begin(request.manifest),
            )
        elif isinstance(request, TargetdReleaseUploadStatusRequest):
            response = TargetdReleaseUploadStatusResponse(
                **common,
                upload_status=self.store.status(request.manifest_digest),
            )
        elif isinstance(request, TargetdReleaseUploadPutChunkRequest):
            status = self.store.put_chunk(
                request.manifest_digest,
                request.chunk_index,
                request.chunk_payload,
            )
            if request.chunk_index == self.disconnect_after_chunk:
                self.disconnect_after_chunk = None
                raise ConnectionError("response was lost after target accepted chunk")
            response = TargetdReleaseUploadPutChunkResponse(
                **common,
                upload_status=status,
            )
        elif isinstance(request, TargetdReleaseUploadCommitRequest):
            commit = self.store.finalize(request.manifest_digest)
            if self.tamper_commit:
                commit = UploadCommit(
                    manifest_digest=commit.manifest_digest,
                    blob_digest="sha256:" + "0" * 64,
                    total_bytes=commit.total_bytes,
                    chunk_count=commit.chunk_count,
                )
            response = TargetdReleaseUploadCommitResponse(
                **common,
                commit=commit,
            )
        else:  # pragma: no cover - closed union, retained for fake safety
            raise AssertionError(type(request))

        if request.operation == self.tamper_operation:
            return response.model_copy(update={"target_id": "different-target"})
        return response


def _adapter(
    transport: FakeTargetdReleaseUploadTransport,
) -> TargetdReleaseUploadAdapter:
    return TargetdReleaseUploadAdapter(
        transport,
        target_id="landerpi",
        session_id="release-session-1",
    )


def _captured_begin_request(
    tmp_path: Path,
    *,
    target_id: str = "landerpi",
    session_id: str = "release-session-1",
) -> TargetdReleaseUploadBeginRequest:
    transport = FakeTargetdReleaseUploadTransport(tmp_path / "request-capture")
    TargetdReleaseUploadAdapter(
        transport,
        target_id=target_id,
        session_id=session_id,
    ).upload(b"captured-request", chunk_size=64)
    request = transport.calls[0]
    assert isinstance(request, TargetdReleaseUploadBeginRequest)
    return request


def test_targetd_upload_transfers_and_commits_with_bound_identities(
    tmp_path: Path,
) -> None:
    payload = b"abcdefghij"
    transport = FakeTargetdReleaseUploadTransport(tmp_path / "target-uploads")

    receipt = _adapter(transport).upload(payload, chunk_size=4)
    assert TargetdReleaseUploadReceipt.model_validate_json(receipt.model_dump_json()) == receipt

    assert [request.operation for request in transport.calls] == [
        "BEGIN",
        "PUT_CHUNK",
        "PUT_CHUNK",
        "PUT_CHUNK",
        "COMMIT",
    ]
    assert receipt.initial_operation == "BEGIN"
    assert receipt.uploaded_chunks == (0, 1, 2)
    assert receipt.commit.manifest_digest == receipt.manifest.manifest_digest
    assert receipt.commit.blob_digest == receipt.manifest.blob_digest
    assert (
        transport.store.committed_blob_path(receipt.manifest.manifest_digest).read_bytes()
        == payload
    )
    assert receipt.idempotency_keys == tuple(
        request.idempotency_key for request in transport.calls
    )
    for request in transport.calls:
        kwargs = {}
        if isinstance(request, TargetdReleaseUploadPutChunkRequest):
            kwargs = {
                "chunk_index": request.chunk_index,
                "chunk_digest": request.chunk_digest,
            }
        assert request.idempotency_key == targetd_release_upload_idempotency_key(
            target_id="landerpi",
            session_id="release-session-1",
            manifest_digest=receipt.manifest.manifest_digest,
            operation=request.operation,
            **kwargs,
        )


def test_targetd_upload_service_authorizes_each_operation_and_commits(
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, str]] = []
    store = ContentAddressedUploadStore(tmp_path / "target-service")
    service = TargetdReleaseUploadService(
        store,
        target_id="landerpi",
        session_authorizer=lambda target_id, session_id: (
            calls.append((target_id, session_id)) or True
        ),
    )

    receipt = TargetdReleaseUploadAdapter(
        service,
        target_id="landerpi",
        session_id="release-session-1",
    ).upload(b"abcdefghij", chunk_size=4)

    assert calls == [("landerpi", "release-session-1")] * 5
    assert store.committed_blob_path(receipt.manifest.manifest_digest).read_bytes() == (
        b"abcdefghij"
    )


def test_targetd_upload_service_rejects_inactive_session_before_store_mutation(
    tmp_path: Path,
) -> None:
    request = _captured_begin_request(tmp_path)
    store_root = tmp_path / "inactive-service"
    service = TargetdReleaseUploadService(
        ContentAddressedUploadStore(store_root),
        target_id="landerpi",
        session_authorizer=lambda _target_id, _session_id: False,
    )

    with pytest.raises(
        TargetdReleaseUploadError,
        match="TARGETD_RELEASE_UPLOAD_SESSION_NOT_AUTHORIZED",
    ):
        service.exchange(request)

    assert not store_root.exists()


def test_targetd_upload_service_rejects_wrong_target_and_authority_failure(
    tmp_path: Path,
) -> None:
    wrong_target = _captured_begin_request(tmp_path, target_id="other-target")
    service = TargetdReleaseUploadService(
        ContentAddressedUploadStore(tmp_path / "wrong-target-service"),
        target_id="landerpi",
        session_authorizer=lambda _target_id, _session_id: True,
    )
    with pytest.raises(
        TargetdReleaseUploadError,
        match="TARGETD_RELEASE_UPLOAD_TARGET_MISMATCH",
    ):
        service.exchange(wrong_target)

    request = _captured_begin_request(tmp_path, session_id="authority-failure")

    def unavailable(_target_id: str, _session_id: str) -> bool:
        raise RuntimeError("authority database unavailable")

    unavailable_service = TargetdReleaseUploadService(
        ContentAddressedUploadStore(tmp_path / "authority-failure-service"),
        target_id="landerpi",
        session_authorizer=unavailable,
    )
    with pytest.raises(
        TargetdReleaseUploadError,
        match="TARGETD_RELEASE_UPLOAD_SESSION_AUTHORITY_UNAVAILABLE",
    ):
        unavailable_service.exchange(request)


def test_uncertain_transport_poisons_instance_and_fresh_adapter_resumes_by_status(
    tmp_path: Path,
) -> None:
    payload = b"abcdefghij"
    transport = FakeTargetdReleaseUploadTransport(tmp_path / "target-uploads")
    transport.disconnect_after_chunk = 0
    first = _adapter(transport)

    with pytest.raises(
        TargetdReleaseUploadError,
        match="TARGETD_RELEASE_UPLOAD_TRANSPORT_UNCERTAIN",
    ):
        first.upload(payload, chunk_size=4)
    assert first.poisoned is True
    assert [request.operation for request in transport.calls] == [
        "BEGIN",
        "PUT_CHUNK",
    ]

    call_count = len(transport.calls)
    with pytest.raises(
        TargetdReleaseUploadError,
        match="TARGETD_RELEASE_UPLOAD_ADAPTER_POISONED",
    ):
        first.resume(payload, chunk_size=4)
    assert len(transport.calls) == call_count

    resumed_calls_start = len(transport.calls)
    receipt = _adapter(transport).resume(payload, chunk_size=4)
    resumed_calls = transport.calls[resumed_calls_start:]
    assert [request.operation for request in resumed_calls] == [
        "STATUS",
        "PUT_CHUNK",
        "PUT_CHUNK",
        "COMMIT",
    ]
    assert receipt.initial_operation == "STATUS"
    assert receipt.uploaded_chunks == (1, 2)
    assert [
        request.chunk_index
        for request in resumed_calls
        if isinstance(request, TargetdReleaseUploadPutChunkRequest)
    ] == [1, 2]


def test_tampered_response_identity_poisons_without_retry(tmp_path: Path) -> None:
    transport = FakeTargetdReleaseUploadTransport(tmp_path / "target-uploads")
    transport.tamper_operation = "BEGIN"
    adapter = _adapter(transport)

    with pytest.raises(
        TargetdReleaseUploadError,
        match="TARGETD_RELEASE_UPLOAD_RESPONSE_TAMPERED",
    ):
        adapter.upload(b"payload", chunk_size=4)
    assert adapter.poisoned is True
    assert len(transport.calls) == 1

    with pytest.raises(
        TargetdReleaseUploadError,
        match="TARGETD_RELEASE_UPLOAD_ADAPTER_POISONED",
    ):
        adapter.upload(b"payload", chunk_size=4)
    assert len(transport.calls) == 1


def test_tampered_commit_identity_is_not_accepted(tmp_path: Path) -> None:
    transport = FakeTargetdReleaseUploadTransport(tmp_path / "target-uploads")
    transport.tamper_commit = True
    adapter = _adapter(transport)

    with pytest.raises(
        TargetdReleaseUploadError,
        match="TARGETD_RELEASE_UPLOAD_RESPONSE_TAMPERED",
    ):
        adapter.upload(b"complete", chunk_size=4)
    assert adapter.poisoned is True
    assert transport.calls[-1].operation == "COMMIT"


def test_request_models_reject_forged_derived_identity(tmp_path: Path) -> None:
    transport = FakeTargetdReleaseUploadTransport(tmp_path / "target-uploads")
    _adapter(transport).upload(b"payload", chunk_size=4)
    request = transport.calls[0]
    payload = request.model_dump(mode="python")
    payload["idempotency_key"] = "sha256:" + "0" * 64

    with pytest.raises(ValidationError):
        TargetdReleaseUploadBeginRequest.model_validate(payload)


def test_put_chunk_request_json_round_trip_preserves_arbitrary_binary(
    tmp_path: Path,
) -> None:
    payload = b"\xff\x00\x80binary"
    transport = FakeTargetdReleaseUploadTransport(tmp_path / "binary-capture")
    _adapter(transport).upload(payload, chunk_size=len(payload))
    request = next(
        request
        for request in transport.calls
        if isinstance(request, TargetdReleaseUploadPutChunkRequest)
    )

    encoded = request.model_dump_json()
    round_trip = TargetdReleaseUploadPutChunkRequest.model_validate_json(encoded)

    assert round_trip == request
    assert round_trip.chunk_payload == payload
    forged = request.model_dump(mode="json")
    forged["chunk_payload"] = "not+canonical==="
    with pytest.raises(ValidationError):
        TargetdReleaseUploadPutChunkRequest.model_validate(forged)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("uploaded_chunks", (63,)),
        ("idempotency_keys", ("sha256:" + "0" * 64,) * 3),
        ("request_digests", ("sha256:" + "1" * 64,) * 3),
    ],
)
def test_upload_receipt_rejects_forged_operation_chain(
    tmp_path: Path,
    field: str,
    replacement: tuple[object, ...],
) -> None:
    transport = FakeTargetdReleaseUploadTransport(tmp_path / field)
    receipt = _adapter(transport).upload(b"one-chunk", chunk_size=64)
    payload = receipt.model_dump(mode="python")
    payload[field] = replacement

    with pytest.raises(ValidationError):
        TargetdReleaseUploadReceipt.model_validate(payload)
