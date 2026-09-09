"""Fail-closed resumable Release upload client and target-side service.

The typed service is transport-independent.  A daemon transport must preserve
the already-derived target/session/request identities when carrying these
messages and must not retry an uncertain mutating exchange.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable
from threading import Lock
from typing import Annotated, Literal, Protocol, TypeAlias, TypeVar, cast

from pydantic import Field, field_serializer, field_validator, model_validator

from rolo.dsl.models import StrictModel

from .upload import (
    MAX_CHUNK_BYTES,
    MAX_UPLOAD_CHUNKS,
    ChunkUploadManifest,
    ContentAddressedUploadStore,
    ReleaseUploadError,
    UploadCommit,
    UploadStatus,
    content_digest,
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_OPERATIONS = frozenset({"BEGIN", "STATUS", "PUT_CHUNK", "COMMIT"})

TargetdReleaseUploadOperation: TypeAlias = Literal[
    "BEGIN", "STATUS", "PUT_CHUNK", "COMMIT"
]
TargetdUploadChunkIndex = Annotated[
    int,
    Field(strict=True, ge=0, lt=MAX_UPLOAD_CHUNKS),
]


class TargetdReleaseUploadError(ReleaseUploadError):
    """A targetd upload exchange was uncertain, poisoned, or untrusted."""


def _canonical_digest(value: dict[str, object]) -> str:
    return content_digest(
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    )


def _require_upload_identity(
    *,
    target_id: str,
    session_id: str,
    manifest_digest: str,
    operation: str,
    chunk_index: int | None,
    chunk_digest: str | None,
) -> None:
    if (
        not isinstance(target_id, str)
        or _IDENTIFIER.fullmatch(target_id) is None
        or not isinstance(session_id, str)
        or _IDENTIFIER.fullmatch(session_id) is None
    ):
        raise TargetdReleaseUploadError("TARGETD_RELEASE_UPLOAD_IDENTITY_INVALID")
    if not isinstance(manifest_digest, str) or _DIGEST.fullmatch(manifest_digest) is None:
        raise TargetdReleaseUploadError(
            "TARGETD_RELEASE_UPLOAD_MANIFEST_DIGEST_INVALID"
        )
    if operation not in _OPERATIONS:
        raise TargetdReleaseUploadError("TARGETD_RELEASE_UPLOAD_OPERATION_INVALID")
    if operation == "PUT_CHUNK":
        if (
            isinstance(chunk_index, bool)
            or not isinstance(chunk_index, int)
            or not 0 <= chunk_index < MAX_UPLOAD_CHUNKS
            or not isinstance(chunk_digest, str)
            or _DIGEST.fullmatch(chunk_digest) is None
        ):
            raise TargetdReleaseUploadError(
                "TARGETD_RELEASE_UPLOAD_CHUNK_IDENTITY_INVALID"
            )
    elif chunk_index is not None or chunk_digest is not None:
        raise TargetdReleaseUploadError(
            "TARGETD_RELEASE_UPLOAD_CHUNK_IDENTITY_UNEXPECTED"
        )


def _operation_identity(
    *,
    namespace: str,
    target_id: str,
    session_id: str,
    manifest_digest: str,
    operation: TargetdReleaseUploadOperation,
    chunk_index: int | None = None,
    chunk_digest: str | None = None,
    idempotency_key: str | None = None,
) -> str:
    _require_upload_identity(
        target_id=target_id,
        session_id=session_id,
        manifest_digest=manifest_digest,
        operation=operation,
        chunk_index=chunk_index,
        chunk_digest=chunk_digest,
    )
    identity: dict[str, object] = {
        "schema_version": namespace,
        "target_id": target_id,
        "session_id": session_id,
        "manifest_digest": manifest_digest,
        "operation": operation,
    }
    if chunk_index is not None:
        identity["chunk_index"] = chunk_index
        identity["chunk_digest"] = cast(str, chunk_digest)
    if idempotency_key is not None:
        if _DIGEST.fullmatch(idempotency_key) is None:
            raise TargetdReleaseUploadError(
                "TARGETD_RELEASE_UPLOAD_IDEMPOTENCY_KEY_INVALID"
            )
        identity["idempotency_key"] = idempotency_key
    return _canonical_digest(identity)


def targetd_release_upload_idempotency_key(
    *,
    target_id: str,
    session_id: str,
    manifest_digest: str,
    operation: TargetdReleaseUploadOperation,
    chunk_index: int | None = None,
    chunk_digest: str | None = None,
) -> str:
    """Derive the stable target/session/manifest-bound operation identity."""

    return _operation_identity(
        namespace="rolo-targetd-release-upload-idempotency/v1",
        target_id=target_id,
        session_id=session_id,
        manifest_digest=manifest_digest,
        operation=operation,
        chunk_index=chunk_index,
        chunk_digest=chunk_digest,
    )


def _request_digest(
    *,
    target_id: str,
    session_id: str,
    manifest_digest: str,
    operation: TargetdReleaseUploadOperation,
    idempotency_key: str,
    chunk_index: int | None = None,
    chunk_digest: str | None = None,
) -> str:
    return _operation_identity(
        namespace="rolo-targetd-release-upload-request/v1",
        target_id=target_id,
        session_id=session_id,
        manifest_digest=manifest_digest,
        operation=operation,
        chunk_index=chunk_index,
        chunk_digest=chunk_digest,
        idempotency_key=idempotency_key,
    )


class _TargetdReleaseUploadRequest(StrictModel):
    schema_version: Literal["rolo-targetd-release-upload-request/v1"] = (
        "rolo-targetd-release-upload-request/v1"
    )
    target_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    session_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    idempotency_key: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    request_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    def _validate_derived_identity(
        self,
        operation: TargetdReleaseUploadOperation,
        *,
        chunk_index: int | None = None,
        chunk_digest: str | None = None,
    ) -> None:
        expected_key = targetd_release_upload_idempotency_key(
            target_id=self.target_id,
            session_id=self.session_id,
            manifest_digest=self.manifest_digest,
            operation=operation,
            chunk_index=chunk_index,
            chunk_digest=chunk_digest,
        )
        expected_request_digest = _request_digest(
            target_id=self.target_id,
            session_id=self.session_id,
            manifest_digest=self.manifest_digest,
            operation=operation,
            idempotency_key=expected_key,
            chunk_index=chunk_index,
            chunk_digest=chunk_digest,
        )
        if self.idempotency_key != expected_key:
            raise ValueError("targetd upload idempotency identity does not match")
        if self.request_digest != expected_request_digest:
            raise ValueError("targetd upload request digest does not match")


class TargetdReleaseUploadBeginRequest(_TargetdReleaseUploadRequest):
    operation: Literal["BEGIN"] = "BEGIN"
    manifest: ChunkUploadManifest

    @model_validator(mode="after")
    def validate_identity(self) -> TargetdReleaseUploadBeginRequest:
        if self.manifest.manifest_digest != self.manifest_digest:
            raise ValueError("targetd upload manifest identity does not match")
        self._validate_derived_identity(self.operation)
        return self


class TargetdReleaseUploadStatusRequest(_TargetdReleaseUploadRequest):
    operation: Literal["STATUS"] = "STATUS"

    @model_validator(mode="after")
    def validate_identity(self) -> TargetdReleaseUploadStatusRequest:
        self._validate_derived_identity(self.operation)
        return self


class TargetdReleaseUploadPutChunkRequest(_TargetdReleaseUploadRequest):
    operation: Literal["PUT_CHUNK"] = "PUT_CHUNK"
    chunk_index: TargetdUploadChunkIndex
    chunk_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    chunk_payload: bytes = Field(min_length=1, max_length=MAX_CHUNK_BYTES)

    @field_validator("chunk_payload", mode="before")
    @classmethod
    def decode_canonical_base64_payload(cls, value: object) -> object:
        """Decode the JSON wire representation without accepting aliases."""

        if not isinstance(value, str):
            return value
        max_encoded_length = ((MAX_CHUNK_BYTES + 2) // 3) * 4
        if not value or len(value) > max_encoded_length:
            raise ValueError("targetd upload chunk Base64 length is invalid")
        try:
            encoded = value.encode("ascii")
            decoded = base64.b64decode(encoded, validate=True)
        except (UnicodeEncodeError, ValueError) as exc:
            raise ValueError("targetd upload chunk payload is not strict Base64") from exc
        if base64.b64encode(decoded).decode("ascii") != value:
            raise ValueError("targetd upload chunk payload is not canonical Base64")
        return decoded

    @field_serializer("chunk_payload", when_used="json")
    def encode_canonical_base64_payload(self, value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")

    @model_validator(mode="after")
    def validate_identity(self) -> TargetdReleaseUploadPutChunkRequest:
        if content_digest(self.chunk_payload) != self.chunk_digest:
            raise ValueError("targetd upload chunk payload does not match digest")
        self._validate_derived_identity(
            self.operation,
            chunk_index=self.chunk_index,
            chunk_digest=self.chunk_digest,
        )
        return self


class TargetdReleaseUploadCommitRequest(_TargetdReleaseUploadRequest):
    operation: Literal["COMMIT"] = "COMMIT"

    @model_validator(mode="after")
    def validate_identity(self) -> TargetdReleaseUploadCommitRequest:
        self._validate_derived_identity(self.operation)
        return self


TargetdReleaseUploadRequest: TypeAlias = (
    TargetdReleaseUploadBeginRequest
    | TargetdReleaseUploadStatusRequest
    | TargetdReleaseUploadPutChunkRequest
    | TargetdReleaseUploadCommitRequest
)


class _TargetdReleaseUploadResponse(StrictModel):
    schema_version: Literal["rolo-targetd-release-upload-response/v1"] = (
        "rolo-targetd-release-upload-response/v1"
    )
    target_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    session_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    idempotency_key: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    request_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    status: Literal["OK"] = "OK"


class TargetdReleaseUploadBeginResponse(_TargetdReleaseUploadResponse):
    operation: Literal["BEGIN"] = "BEGIN"
    upload_status: UploadStatus


class TargetdReleaseUploadStatusResponse(_TargetdReleaseUploadResponse):
    operation: Literal["STATUS"] = "STATUS"
    upload_status: UploadStatus


class TargetdReleaseUploadPutChunkResponse(_TargetdReleaseUploadResponse):
    operation: Literal["PUT_CHUNK"] = "PUT_CHUNK"
    upload_status: UploadStatus


class TargetdReleaseUploadCommitResponse(_TargetdReleaseUploadResponse):
    operation: Literal["COMMIT"] = "COMMIT"
    commit: UploadCommit


TargetdReleaseUploadResponse: TypeAlias = (
    TargetdReleaseUploadBeginResponse
    | TargetdReleaseUploadStatusResponse
    | TargetdReleaseUploadPutChunkResponse
    | TargetdReleaseUploadCommitResponse
)


class TargetdReleaseUploadTransport(Protocol):
    """One-attempt exchange boundary implemented by a targetd client."""

    def exchange(
        self,
        request: TargetdReleaseUploadRequest,
    ) -> TargetdReleaseUploadResponse: ...


class TargetdReleaseUploadService:
    """Target-owned request handler backed by the durable upload store.

    Session authorization is re-evaluated for every operation.  The service
    accepts only the exact typed request variants, revalidates their derived
    identities, and echoes those identities in the response.  The underlying
    content-addressed store makes duplicate same-content operations
    idempotent while rejecting collisions and tampering.
    """

    def __init__(
        self,
        store: ContentAddressedUploadStore,
        *,
        target_id: str,
        session_authorizer: Callable[[str, str], bool],
    ) -> None:
        _require_upload_identity(
            target_id=target_id,
            session_id="targetd-upload-service",
            manifest_digest="sha256:" + "0" * 64,
            operation="STATUS",
            chunk_index=None,
            chunk_digest=None,
        )
        if not isinstance(store, ContentAddressedUploadStore):
            raise TypeError("store must be a ContentAddressedUploadStore")
        if not callable(session_authorizer):
            raise TypeError("session_authorizer must be callable")
        self.store = store
        self.target_id = target_id
        self.session_authorizer = session_authorizer

    def exchange(
        self,
        request: TargetdReleaseUploadRequest,
    ) -> TargetdReleaseUploadResponse:
        request_types = (
            TargetdReleaseUploadBeginRequest,
            TargetdReleaseUploadStatusRequest,
            TargetdReleaseUploadPutChunkRequest,
            TargetdReleaseUploadCommitRequest,
        )
        if type(request) not in request_types:
            raise TargetdReleaseUploadError(
                "TARGETD_RELEASE_UPLOAD_REQUEST_INVALID"
            )
        request_type = type(request)
        try:
            parsed = request_type.model_validate(request.model_dump(mode="python"))
        except (AttributeError, TypeError, ValueError) as exc:
            raise TargetdReleaseUploadError(
                "TARGETD_RELEASE_UPLOAD_REQUEST_INVALID"
            ) from exc
        if parsed.target_id != self.target_id:
            raise TargetdReleaseUploadError(
                "TARGETD_RELEASE_UPLOAD_TARGET_MISMATCH"
            )
        try:
            authorized = self.session_authorizer(parsed.target_id, parsed.session_id)
        except Exception as exc:
            raise TargetdReleaseUploadError(
                "TARGETD_RELEASE_UPLOAD_SESSION_AUTHORITY_UNAVAILABLE"
            ) from exc
        if authorized is not True:
            raise TargetdReleaseUploadError(
                "TARGETD_RELEASE_UPLOAD_SESSION_NOT_AUTHORIZED"
            )

        common = {
            "target_id": parsed.target_id,
            "session_id": parsed.session_id,
            "manifest_digest": parsed.manifest_digest,
            "idempotency_key": parsed.idempotency_key,
            "request_digest": parsed.request_digest,
        }
        try:
            if isinstance(parsed, TargetdReleaseUploadBeginRequest):
                return TargetdReleaseUploadBeginResponse(
                    **common,
                    upload_status=self.store.begin(parsed.manifest),
                )
            if isinstance(parsed, TargetdReleaseUploadStatusRequest):
                return TargetdReleaseUploadStatusResponse(
                    **common,
                    upload_status=self.store.status(parsed.manifest_digest),
                )
            if isinstance(parsed, TargetdReleaseUploadPutChunkRequest):
                return TargetdReleaseUploadPutChunkResponse(
                    **common,
                    upload_status=self.store.put_chunk(
                        parsed.manifest_digest,
                        parsed.chunk_index,
                        parsed.chunk_payload,
                    ),
                )
            if isinstance(parsed, TargetdReleaseUploadCommitRequest):
                return TargetdReleaseUploadCommitResponse(
                    **common,
                    commit=self.store.finalize(parsed.manifest_digest),
                )
        except ReleaseUploadError as exc:
            raise TargetdReleaseUploadError(str(exc)) from exc
        except Exception as exc:
            raise TargetdReleaseUploadError(
                "TARGETD_RELEASE_UPLOAD_STORE_UNAVAILABLE"
            ) from exc
        raise TargetdReleaseUploadError("TARGETD_RELEASE_UPLOAD_REQUEST_INVALID")


class TargetdReleaseUploadReceipt(StrictModel):
    schema_version: Literal["rolo-targetd-release-upload-receipt/v1"] = (
        "rolo-targetd-release-upload-receipt/v1"
    )
    target_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    session_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    manifest: ChunkUploadManifest
    commit: UploadCommit
    initial_operation: Literal["BEGIN", "STATUS"]
    uploaded_chunks: tuple[TargetdUploadChunkIndex, ...] = Field(
        max_length=MAX_UPLOAD_CHUNKS
    )
    idempotency_keys: tuple[str, ...] = Field(
        min_length=2,
        max_length=MAX_UPLOAD_CHUNKS + 2,
    )
    request_digests: tuple[str, ...] = Field(
        min_length=2,
        max_length=MAX_UPLOAD_CHUNKS + 2,
    )

    @model_validator(mode="after")
    def validate_commit(self) -> TargetdReleaseUploadReceipt:
        expected_commit = UploadCommit(
            manifest_digest=self.manifest.manifest_digest,
            blob_digest=self.manifest.blob_digest,
            total_bytes=self.manifest.total_bytes,
            chunk_count=len(self.manifest.chunk_digests),
        )
        chunk_count = len(self.manifest.chunk_digests)
        operation_count = len(self.uploaded_chunks) + 2
        if (
            self.commit != expected_commit
            or tuple(sorted(set(self.uploaded_chunks))) != self.uploaded_chunks
            or any(index >= chunk_count for index in self.uploaded_chunks)
            or len(self.idempotency_keys) != operation_count
            or len(self.request_digests) != operation_count
            or any(_DIGEST.fullmatch(value) is None for value in self.idempotency_keys)
            or any(_DIGEST.fullmatch(value) is None for value in self.request_digests)
        ):
            raise ValueError("targetd upload receipt identity is invalid")
        operations: list[tuple[TargetdReleaseUploadOperation, int | None, str | None]] = [
            (self.initial_operation, None, None),
            *(
                ("PUT_CHUNK", index, self.manifest.chunk_digests[index])
                for index in self.uploaded_chunks
            ),
            ("COMMIT", None, None),
        ]
        expected_keys: list[str] = []
        expected_request_digests: list[str] = []
        for operation, chunk_index, chunk_digest in operations:
            key = targetd_release_upload_idempotency_key(
                target_id=self.target_id,
                session_id=self.session_id,
                manifest_digest=self.manifest.manifest_digest,
                operation=operation,
                chunk_index=chunk_index,
                chunk_digest=chunk_digest,
            )
            expected_keys.append(key)
            expected_request_digests.append(
                _request_digest(
                    target_id=self.target_id,
                    session_id=self.session_id,
                    manifest_digest=self.manifest.manifest_digest,
                    operation=operation,
                    idempotency_key=key,
                    chunk_index=chunk_index,
                    chunk_digest=chunk_digest,
                )
            )
        if (
            self.idempotency_keys != tuple(expected_keys)
            or self.request_digests != tuple(expected_request_digests)
        ):
            raise ValueError("targetd upload receipt identity is invalid")
        return self


_ResponseT = TypeVar("_ResponseT", bound=_TargetdReleaseUploadResponse)


class TargetdReleaseUploadAdapter:
    """Upload once or resume from target status, poisoning on uncertainty.

    This object never retries an exchange.  A timeout or connection error may
    mean the target committed the operation, so the instance becomes unusable.
    Construct a fresh adapter and call :meth:`resume` to reconcile via STATUS.
    """

    def __init__(
        self,
        transport: TargetdReleaseUploadTransport,
        *,
        target_id: str,
        session_id: str,
    ) -> None:
        _require_upload_identity(
            target_id=target_id,
            session_id=session_id,
            manifest_digest="sha256:" + "0" * 64,
            operation="STATUS",
            chunk_index=None,
            chunk_digest=None,
        )
        if not callable(getattr(transport, "exchange", None)):
            raise TypeError("transport must provide exchange(request)")
        self.transport = transport
        self.target_id = target_id
        self.session_id = session_id
        self._poisoned = False
        self._lock = Lock()

    @property
    def poisoned(self) -> bool:
        return self._poisoned

    def upload(
        self,
        payload: bytes,
        *,
        chunk_size: int = MAX_CHUNK_BYTES,
        media_type: str = "application/octet-stream",
    ) -> TargetdReleaseUploadReceipt:
        """Begin a manifest and transfer only the target-reported gaps."""

        return self._transfer(
            payload,
            chunk_size=chunk_size,
            media_type=media_type,
            initial_operation="BEGIN",
        )

    def resume(
        self,
        payload: bytes,
        *,
        chunk_size: int = MAX_CHUNK_BYTES,
        media_type: str = "application/octet-stream",
    ) -> TargetdReleaseUploadReceipt:
        """Reconstruct the manifest, query STATUS, and send only missing chunks."""

        return self._transfer(
            payload,
            chunk_size=chunk_size,
            media_type=media_type,
            initial_operation="STATUS",
        )

    def _transfer(
        self,
        payload: bytes,
        *,
        chunk_size: int,
        media_type: str,
        initial_operation: Literal["BEGIN", "STATUS"],
    ) -> TargetdReleaseUploadReceipt:
        with self._lock:
            self._require_usable()
            manifest = ChunkUploadManifest.from_payload(
                payload,
                chunk_size=chunk_size,
                media_type=media_type,
            )
            requests: list[TargetdReleaseUploadRequest] = []
            if initial_operation == "BEGIN":
                initial_request = self._begin_request(manifest)
                requests.append(initial_request)
                status = self._status_exchange(initial_request, manifest)
            else:
                initial_request = self._status_request(manifest)
                requests.append(initial_request)
                status = self._status_exchange(initial_request, manifest)

            uploaded: list[int] = []
            for index in tuple(status.missing_chunks):
                if index not in status.missing_chunks:
                    continue
                offset = index * manifest.chunk_size
                chunk = payload[offset : offset + manifest.expected_chunk_bytes(index)]
                request = self._put_request(manifest, index, chunk)
                requests.append(request)
                status = self._status_exchange(
                    request,
                    manifest,
                    prior=status,
                    required_chunk=index,
                )
                uploaded.append(index)

            if status.missing_chunks:
                self._reject_response()

            commit_request = self._commit_request(manifest)
            requests.append(commit_request)
            commit = self._commit_exchange(commit_request, manifest)
            return TargetdReleaseUploadReceipt(
                target_id=self.target_id,
                session_id=self.session_id,
                manifest=manifest,
                commit=commit,
                initial_operation=initial_operation,
                uploaded_chunks=tuple(uploaded),
                idempotency_keys=tuple(request.idempotency_key for request in requests),
                request_digests=tuple(request.request_digest for request in requests),
            )

    def _status_exchange(
        self,
        request: (
            TargetdReleaseUploadBeginRequest
            | TargetdReleaseUploadStatusRequest
            | TargetdReleaseUploadPutChunkRequest
        ),
        manifest: ChunkUploadManifest,
        *,
        prior: UploadStatus | None = None,
        required_chunk: int | None = None,
    ) -> UploadStatus:
        response_type: type[
            TargetdReleaseUploadBeginResponse
            | TargetdReleaseUploadStatusResponse
            | TargetdReleaseUploadPutChunkResponse
        ]
        if isinstance(request, TargetdReleaseUploadBeginRequest):
            response_type = TargetdReleaseUploadBeginResponse
        elif isinstance(request, TargetdReleaseUploadStatusRequest):
            response_type = TargetdReleaseUploadStatusResponse
        else:
            response_type = TargetdReleaseUploadPutChunkResponse
        response = self._exchange(request, response_type)
        status = response.upload_status
        received = set(status.received_chunks)
        missing = set(status.missing_chunks)
        expected_chunks = set(range(len(manifest.chunk_digests)))
        if (
            status.manifest_digest != manifest.manifest_digest
            or status.blob_digest != manifest.blob_digest
            or status.total_bytes != manifest.total_bytes
            or received | missing != expected_chunks
            or len(received) + len(missing) != len(expected_chunks)
            or (status.finalized and missing)
            or (prior is not None and not set(prior.received_chunks) <= received)
            or (prior is not None and prior.finalized and not status.finalized)
            or (required_chunk is not None and required_chunk not in received)
        ):
            self._reject_response()
        return status

    def _commit_exchange(
        self,
        request: TargetdReleaseUploadCommitRequest,
        manifest: ChunkUploadManifest,
    ) -> UploadCommit:
        response = self._exchange(request, TargetdReleaseUploadCommitResponse)
        expected = UploadCommit(
            manifest_digest=manifest.manifest_digest,
            blob_digest=manifest.blob_digest,
            total_bytes=manifest.total_bytes,
            chunk_count=len(manifest.chunk_digests),
        )
        if response.commit != expected:
            self._reject_response()
        return response.commit

    def _exchange(
        self,
        request: TargetdReleaseUploadRequest,
        response_type: type[_ResponseT],
    ) -> _ResponseT:
        self._require_usable()
        try:
            raw_response = self.transport.exchange(request)
        except Exception as exc:
            self._poisoned = True
            raise TargetdReleaseUploadError(
                "TARGETD_RELEASE_UPLOAD_TRANSPORT_UNCERTAIN"
            ) from exc
        if type(raw_response) is not response_type:
            self._reject_response()
        try:
            response = response_type.model_validate(
                raw_response.model_dump(mode="python")
            )
        except (AttributeError, TypeError, ValueError) as exc:
            self._reject_response(exc)
        if (
            response.operation != request.operation
            or response.target_id != request.target_id
            or response.session_id != request.session_id
            or response.manifest_digest != request.manifest_digest
            or response.idempotency_key != request.idempotency_key
            or response.request_digest != request.request_digest
        ):
            self._reject_response()
        return response

    def _begin_request(
        self, manifest: ChunkUploadManifest
    ) -> TargetdReleaseUploadBeginRequest:
        key, digest = self._derived_request_identity(manifest, "BEGIN")
        return TargetdReleaseUploadBeginRequest(
            target_id=self.target_id,
            session_id=self.session_id,
            manifest_digest=manifest.manifest_digest,
            idempotency_key=key,
            request_digest=digest,
            manifest=manifest,
        )

    def _status_request(
        self, manifest: ChunkUploadManifest
    ) -> TargetdReleaseUploadStatusRequest:
        key, digest = self._derived_request_identity(manifest, "STATUS")
        return TargetdReleaseUploadStatusRequest(
            target_id=self.target_id,
            session_id=self.session_id,
            manifest_digest=manifest.manifest_digest,
            idempotency_key=key,
            request_digest=digest,
        )

    def _put_request(
        self,
        manifest: ChunkUploadManifest,
        index: int,
        payload: bytes,
    ) -> TargetdReleaseUploadPutChunkRequest:
        chunk_digest = manifest.chunk_digests[index]
        key, digest = self._derived_request_identity(
            manifest,
            "PUT_CHUNK",
            chunk_index=index,
            chunk_digest=chunk_digest,
        )
        return TargetdReleaseUploadPutChunkRequest(
            target_id=self.target_id,
            session_id=self.session_id,
            manifest_digest=manifest.manifest_digest,
            idempotency_key=key,
            request_digest=digest,
            chunk_index=index,
            chunk_digest=chunk_digest,
            chunk_payload=payload,
        )

    def _commit_request(
        self, manifest: ChunkUploadManifest
    ) -> TargetdReleaseUploadCommitRequest:
        key, digest = self._derived_request_identity(manifest, "COMMIT")
        return TargetdReleaseUploadCommitRequest(
            target_id=self.target_id,
            session_id=self.session_id,
            manifest_digest=manifest.manifest_digest,
            idempotency_key=key,
            request_digest=digest,
        )

    def _derived_request_identity(
        self,
        manifest: ChunkUploadManifest,
        operation: TargetdReleaseUploadOperation,
        *,
        chunk_index: int | None = None,
        chunk_digest: str | None = None,
    ) -> tuple[str, str]:
        key = targetd_release_upload_idempotency_key(
            target_id=self.target_id,
            session_id=self.session_id,
            manifest_digest=manifest.manifest_digest,
            operation=operation,
            chunk_index=chunk_index,
            chunk_digest=chunk_digest,
        )
        digest = _request_digest(
            target_id=self.target_id,
            session_id=self.session_id,
            manifest_digest=manifest.manifest_digest,
            operation=operation,
            idempotency_key=key,
            chunk_index=chunk_index,
            chunk_digest=chunk_digest,
        )
        return key, digest

    def _require_usable(self) -> None:
        if self._poisoned:
            raise TargetdReleaseUploadError(
                "TARGETD_RELEASE_UPLOAD_ADAPTER_POISONED"
            )

    def _reject_response(self, cause: Exception | None = None) -> None:
        self._poisoned = True
        error = TargetdReleaseUploadError(
            "TARGETD_RELEASE_UPLOAD_RESPONSE_TAMPERED"
        )
        if cause is None:
            raise error
        raise error from cause


__all__ = [
    "TargetdReleaseUploadAdapter",
    "TargetdReleaseUploadBeginRequest",
    "TargetdReleaseUploadBeginResponse",
    "TargetdReleaseUploadCommitRequest",
    "TargetdReleaseUploadCommitResponse",
    "TargetdReleaseUploadError",
    "TargetdReleaseUploadOperation",
    "TargetdReleaseUploadPutChunkRequest",
    "TargetdReleaseUploadPutChunkResponse",
    "TargetdReleaseUploadReceipt",
    "TargetdReleaseUploadRequest",
    "TargetdReleaseUploadResponse",
    "TargetdReleaseUploadStatusRequest",
    "TargetdReleaseUploadStatusResponse",
    "TargetdReleaseUploadService",
    "TargetdReleaseUploadTransport",
    "targetd_release_upload_idempotency_key",
]
