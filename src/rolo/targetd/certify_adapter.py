"""Fail-closed bridge from formal Certify cases to targetd CALL v2.

This slice is intentionally limited to the fixed ROS 2 odometry observation
provider.  It does not authorize a generic provider or any physical write.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import TYPE_CHECKING

from rolo.mvp.certify import (
    CertificationInvocationContext,
    CertificationInvocationOutcome,
    CertificationReceiptSidecar,
    certification_idempotency_key,
    certification_receipt_sidecar_text,
)

from .protocol import (
    ExecutionRequest,
    FrameKind,
    ProtocolError,
    ProtocolFrame,
    TargetdCallReceipt,
    TargetdExecutionAuthority,
    provider_fence_digest,
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_UNPREFIXED_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SAFE_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_SAFE_REF = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]{1,31}://[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$")
_TERMINAL = frozenset(
    {"SUCCEEDED", "FAILED", "STOPPED", "CANCELLED", "UNKNOWN", "NOT_ACCEPTED"}
)
MAX_CERTIFY_REQUEST_RECORDS = 1_024

if TYPE_CHECKING:
    from .transport import JourneySessionClient


@dataclass(frozen=True)
class TargetdV2CertifyResponse:
    """CALL result whose transport has correlated its response sequence.

    A bare ``ProtocolFrame`` is deliberately insufficient: the adapter cannot
    reconstruct the channel's expected response sequence after the fact.  The
    channel wrapper must perform that check and attest it here.
    """

    frame: ProtocolFrame
    sequence_correlated: bool


@dataclass(frozen=True)
class TargetdV2CertifyRequestRecord:
    """Integrity-checked immutable request retained for exact retries.

    The injected mapping is a trusted local store.  The record detects
    accidental mutation/corruption; it is not a substitute for a signed or
    access-controlled persistence layer.
    """

    request_json: bytes
    content_digest: str
    request_digest: str
    created_at: datetime
    timeout_s: float


class TargetdV2CertifyAdapter:
    """Invoke fixed-target R0 Certify cases through targetd CALL v2."""

    requires_receipt_sidecar = True
    requires_target_terminal_status = True

    def __init__(
        self,
        authority: TargetdExecutionAuthority,
        *,
        call: Callable[[ExecutionRequest], TargetdV2CertifyResponse],
        clock: Callable[[], datetime] | None = None,
        request_store: MutableMapping[
            str, TargetdV2CertifyRequestRecord
        ] | None = None,
    ) -> None:
        self.authority = TargetdExecutionAuthority.model_validate(
            authority.model_dump(mode="python")
        )
        self.call = call
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        # Keep the complete first request, including its deadline.  A retry
        # with the same idempotency key must have the same request digest or
        # targetd will (correctly) reject it as an identity collision.  A
        # caller that needs restart-safe retries may inject a durable mapping.
        self.request_store = request_store if request_store is not None else {}
        self._request_lock = Lock()
        self._require_read_only_authority()

    @classmethod
    def from_journey_client(
        cls,
        authority: TargetdExecutionAuthority,
        client: JourneySessionClient,
        *,
        clock: Callable[[], datetime] | None = None,
        request_store: MutableMapping[
            str, TargetdV2CertifyRequestRecord
        ] | None = None,
    ) -> TargetdV2CertifyAdapter:
        """Bind to the standard client that verifies response sequencing."""

        from .transport import JourneySessionClient

        if not isinstance(client, JourneySessionClient):
            raise TypeError("client must be a JourneySessionClient")

        def call(request: ExecutionRequest) -> TargetdV2CertifyResponse:
            return TargetdV2CertifyResponse(
                frame=client.call_remote(request),
                sequence_correlated=True,
            )

        return cls(
            authority,
            call=call,
            clock=clock,
            request_store=request_store,
        )

    def invoke_certification(
        self,
        context: CertificationInvocationContext,
    ) -> CertificationInvocationOutcome:
        """Execute exactly once and return only receipt-backed safe evidence."""

        self._validate_context(context)
        request = self._request_for_context(context)
        exchange = self.call(request)
        if not isinstance(exchange, TargetdV2CertifyResponse):
            raise ProtocolError("TARGETD_CERTIFY_RESPONSE_METADATA_REQUIRED")
        if exchange.sequence_correlated is not True:
            raise ProtocolError("TARGETD_CERTIFY_RESPONSE_SEQUENCE_UNVERIFIED")
        if not isinstance(exchange.frame, ProtocolFrame):
            raise ProtocolError("TARGETD_CERTIFY_RESPONSE_INVALID")
        frame = ProtocolFrame.model_validate(exchange.frame.model_dump(mode="python"))
        receipt = self._receipt_from_frame(frame, request)
        actual = self._safe_actual(receipt)
        payload = {
            "schema_version": "rolo-certify-targetd-call-receipt-sidecar/v1",
            "run_id": context.run_id,
            "session_id": context.session_id,
            "suite_id": context.suite_id,
            "suite_digest": context.suite_digest,
            "case_id": context.case_id,
            "operation_id": context.operation_id,
            "idempotency_key": context.idempotency_key,
            "receipt": receipt.model_dump(mode="json"),
        }
        encoded = certification_receipt_sidecar_text(payload).encode("utf-8")
        sidecar = CertificationReceiptSidecar(
            case_id=context.case_id,
            idempotency_key=context.idempotency_key,
            canonical_bytes=encoded,
            digest=hashlib.sha256(encoded).hexdigest(),
        )
        return CertificationInvocationOutcome(
            actual=actual,
            receipt_sidecar=sidecar,
            restricted_evidence=True,
            target_terminal_status=receipt.status,
        )

    def _request_for_context(
        self,
        context: CertificationInvocationContext,
    ) -> ExecutionRequest:
        """Return the immutable first request for one idempotency identity."""

        with self._request_lock:
            record = self.request_store.get(context.idempotency_key)
            if record is not None:
                if not isinstance(record, TargetdV2CertifyRequestRecord):
                    raise ProtocolError("TARGETD_CERTIFY_REQUEST_STORE_INVALID")
                try:
                    if (
                        hashlib.sha256(record.request_json).hexdigest()
                        != record.content_digest
                        or record.created_at.tzinfo is None
                        or record.timeout_s != context.timeout_s
                    ):
                        raise ValueError
                    request = ExecutionRequest.model_validate_json(record.request_json)
                    if (
                        request.request_digest() != record.request_digest
                        or request.deadline
                        != record.created_at + timedelta(seconds=record.timeout_s)
                    ):
                        raise ValueError
                except (AttributeError, TypeError, ValueError):
                    raise ProtocolError(
                        "TARGETD_CERTIFY_REQUEST_STORE_INVALID"
                    ) from None
                self._validate_stored_request(request, context)
                return request

            now = self.clock()
            if now.tzinfo is None:
                raise ProtocolError("TARGETD_CERTIFY_CLOCK_INVALID")
            if len(self.request_store) >= MAX_CERTIFY_REQUEST_RECORDS:
                raise ProtocolError("TARGETD_CERTIFY_REQUEST_STORE_FULL")
            request = ExecutionRequest(
                schema_version="rolo-execution-request/v2",
                run_id=context.run_id,
                session_id=context.session_id,
                target_id=context.target_id,
                idempotency_key=context.idempotency_key,
                bundle_digest=self.authority.bundle_digest,
                binding_digest=self.authority.binding_digest,
                surface_digest=self.authority.surface_digest,
                release_digest=context.release_digest,
                context_digest=context.compile_context_digest,
                mapping_confirmation_receipt_digest=(
                    self.authority.mapping_confirmation_receipt_digest
                ),
                authority_head_digest=self.authority.authority_head_digest,
                fence_epoch=self.authority.fence_epoch,
                provider_id=self.authority.provider_id,
                provider_operation=self.authority.provider_operation,
                authority=self.authority,
                arguments=dict(context.arguments),
                mode=self.authority.mode,
                deadline=now + timedelta(seconds=context.timeout_s),
            )
            request_json = json.dumps(
                request.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
            self.request_store[context.idempotency_key] = (
                TargetdV2CertifyRequestRecord(
                    request_json=request_json,
                    content_digest=hashlib.sha256(request_json).hexdigest(),
                    request_digest=request.request_digest(),
                    created_at=now,
                    timeout_s=context.timeout_s,
                )
            )
            return request

    def _validate_stored_request(
        self,
        request: ExecutionRequest,
        context: CertificationInvocationContext,
    ) -> None:
        expected = {
            "run_id": context.run_id,
            "session_id": context.session_id,
            "target_id": context.target_id,
            "idempotency_key": context.idempotency_key,
            "bundle_digest": self.authority.bundle_digest,
            "binding_digest": self.authority.binding_digest,
            "surface_digest": self.authority.surface_digest,
            "release_digest": context.release_digest,
            "context_digest": context.compile_context_digest,
            "mapping_confirmation_receipt_digest": (
                self.authority.mapping_confirmation_receipt_digest
            ),
            "authority_head_digest": self.authority.authority_head_digest,
            "fence_epoch": self.authority.fence_epoch,
            "provider_id": self.authority.provider_id,
            "provider_operation": self.authority.provider_operation,
            "authority": self.authority,
            "arguments": dict(context.arguments),
            "mode": self.authority.mode,
        }
        if any(getattr(request, field) != value for field, value in expected.items()):
            raise ProtocolError("TARGETD_CERTIFY_REQUEST_STORE_COLLISION")

    def _require_read_only_authority(self) -> None:
        scope = self.authority.mapping_admission.scope
        if (
            scope.operation_kind.value != "OBSERVE"
            or scope.access != "read"
            or scope.risk != "R0"
            or self.authority.mode != "READ_ONLY"
            or self.authority.provider_id != "ros2-readonly"
            or self.authority.provider_operation != "odom.sample"
        ):
            raise ProtocolError("TARGETD_CERTIFY_R0_AUTHORITY_REQUIRED")

    def _validate_context(self, context: CertificationInvocationContext) -> None:
        expected_key = certification_idempotency_key(
            session_id=context.session_id,
            run_id=context.run_id,
            suite_digest=context.suite_digest,
            case_id=context.case_id,
        )
        if (
            context.tool_id != self.authority.tool_id
            or context.target_id != self.authority.target_id
            or context.target_fingerprint != self.authority.target_fingerprint
            or context.release_digest != self.authority.release_digest
            or context.compile_context_digest != self.authority.context_digest
            or context.session_id
            != self.authority.mapping_admission.journey_session_id
            or dict(context.arguments) != {}
            or context.risk != "R0"
            or _UNPREFIXED_DIGEST.fullmatch(context.suite_digest) is None
            or context.idempotency_key != expected_key
            or context.operation_id != expected_key
        ):
            raise ProtocolError("TARGETD_CERTIFY_CONTEXT_MISMATCH")
        if not 0 < context.timeout_s <= 300:
            raise ProtocolError("TARGETD_CERTIFY_TIMEOUT_INVALID")

    @staticmethod
    def _receipt_from_frame(
        frame: ProtocolFrame,
        request: ExecutionRequest,
    ) -> TargetdCallReceipt:
        if (
            frame.kind != FrameKind.RESULT
            or frame.session_id != request.session_id
            or frame.run_id != request.run_id
            or frame.payload.get("request_kind") != FrameKind.CALL.value
            or frame.payload.get("ok") is not True
        ):
            raise ProtocolError("TARGETD_CERTIFY_RESPONSE_IDENTITY_MISMATCH")
        raw_receipt = frame.payload.get("receipt")
        if not isinstance(raw_receipt, Mapping):
            raise ProtocolError("TARGETD_CERTIFY_RECEIPT_REQUIRED")
        try:
            receipt = TargetdCallReceipt.model_validate(dict(raw_receipt))
        except (TypeError, ValueError):
            raise ProtocolError("TARGETD_CERTIFY_RECEIPT_INVALID") from None
        expected = {
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
        }
        if any(getattr(receipt, field) != value for field, value in expected.items()):
            raise ProtocolError("TARGETD_CERTIFY_RECEIPT_IDENTITY_MISMATCH")
        if receipt.status not in _TERMINAL:
            raise ProtocolError("TARGETD_CERTIFY_RECEIPT_NOT_TERMINAL")
        if (
            (receipt.status == "SUCCEEDED" and receipt.provider_started_at is None)
            or (
                receipt.provider_started_at is not None
                and receipt.updated_at < receipt.provider_started_at
            )
        ):
            raise ProtocolError("TARGETD_CERTIFY_RECEIPT_TIME_INVALID")
        TargetdV2CertifyAdapter._validate_refs(receipt)
        TargetdV2CertifyAdapter._safe_actual(receipt)
        return receipt

    @staticmethod
    def _validate_refs(receipt: TargetdCallReceipt) -> None:
        for ref in (*receipt.evidence_refs, *receipt.artifact_refs):
            if not _SAFE_REF.fullmatch(ref):
                raise ProtocolError("TARGETD_CERTIFY_RECEIPT_REF_INVALID")

    @staticmethod
    def _safe_actual(receipt: TargetdCallReceipt) -> dict[str, object]:
        result = receipt.result
        if receipt.status == "SUCCEEDED":
            if not isinstance(result, dict) or set(result) != {
                "status",
                "sha256",
                "byte_count",
            }:
                raise ProtocolError("TARGETD_CERTIFY_RESULT_INVALID")
            if (
                result.get("status") != "SUCCEEDED"
                or not isinstance(result.get("sha256"), str)
                or _DIGEST.fullmatch(result["sha256"]) is None
                or isinstance(result.get("byte_count"), bool)
                or not isinstance(result.get("byte_count"), int)
                or not 0 <= result["byte_count"] <= 65_536
            ):
                raise ProtocolError("TARGETD_CERTIFY_RESULT_INVALID")
            return dict(result)

        if result is None:
            return {"status": receipt.status}
        if not isinstance(result, dict) or not set(result) <= {"status", "error", "code"}:
            raise ProtocolError("TARGETD_CERTIFY_RESULT_INVALID")
        reported_status = result.get("status")
        if reported_status is not None and reported_status != receipt.status:
            raise ProtocolError("TARGETD_CERTIFY_RESULT_STATUS_MISMATCH")
        for key in ("error", "code"):
            value = result.get(key)
            if value is not None and (
                not isinstance(value, str) or _SAFE_CODE.fullmatch(value) is None
            ):
                raise ProtocolError("TARGETD_CERTIFY_RESULT_INVALID")
        return {"status": receipt.status, **result}


__all__ = [
    "MAX_CERTIFY_REQUEST_RECORDS",
    "TargetdV2CertifyAdapter",
    "TargetdV2CertifyRequestRecord",
    "TargetdV2CertifyResponse",
]
