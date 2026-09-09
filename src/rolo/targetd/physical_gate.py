"""One-shot physical provider-gate adapter for targetd process workers.

The adapter owns the deployment's zero-motion request/receipt, trust roots,
policy and target CAS implementation. Merely constructing it does not permit
provider execution: :meth:`consume` performs the fresh, one-shot target CAS
and returns only a fully validated consumption receipt.
"""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, TypeAlias

from pydantic import BaseModel, ConfigDict, model_validator

from rolo.core.hashing import canonical_json_sha256
from rolo.core.persistence import atomic_write_text, interprocess_lock
from rolo.dsl.parser import loads_unique_json

from .landerpi_motion_target import (
    DebugOnlyUserAttestedAdmission,
    DebugUserAttestedAcceptanceReceipt,
    DebugUserAttestedProviderGateReceipt,
    LanderPiZeroMotionTarget,
    consume_debug_user_attested_provider_gate,
    revalidate_debug_user_attested_provider_gate,
)
from .lifecycle import WorkerCallKey
from .motion_acceptance import (
    ProviderGateConsumptionReceipt,
    ZeroMotionAcceptanceReceipt,
    ZeroMotionAcceptanceRequest,
    ZeroMotionTarget,
    consume_provider_gate_challenge,
)
from .motion_safety import MotionSafetyIntent, MotionSafetyPolicy, MotionSafetyTrustStore
from .protocol import (
    ExecutionRequestV3,
    ProtocolError,
    TargetdExecutionAuthority,
)

_MAX_GATE_RECEIPTS = 2_048
_MAX_GATE_STATE_BYTES = 4_194_304
_GATE_ARTIFACT_URI = re.compile(r"^artifact://targetd/physical-provider-gates/([0-9a-f]{64})/([0-9a-f]{64})$")
_GATE_DIGEST_URI = re.compile(r"^digest://sha256/([0-9a-f]{64})$")

PhysicalProviderGateReceipt: TypeAlias = ProviderGateConsumptionReceipt | DebugUserAttestedProviderGateReceipt


def _validate_armed_zero(
    value: object,
    call_key: WorkerCallKey,
) -> dict[str, object]:
    raw = value.as_dict() if callable(getattr(value, "as_dict", None)) else value
    if not isinstance(raw, dict):
        raise ProtocolError("TARGETD_PHYSICAL_WORKER_ARM_INVALID")
    try:
        from .physical_worker import parse_physical_worker_armed_zero

        parsed = parse_physical_worker_armed_zero(
            raw,
            expected_call_key_digest=call_key.digest(),
            expected_target_id=call_key.target_id,
            expected_request_digest=call_key.request_digest,
            expected_execution_subject_digest=str(raw.get("execution_subject_digest", "")),
            expected_runtime_sha256=str(raw.get("runtime_sha256", "")),
            expected_call_id=call_key.idempotency_key,
            expected_session_id=call_key.session_id,
        )
    except Exception as exc:
        raise ProtocolError("TARGETD_PHYSICAL_WORKER_ARM_INVALID") from exc
    return parsed.as_dict()


class PhysicalProviderGateSidecar(BaseModel):
    """Immutable target-side record of the gate consumed for one call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "rolo-targetd-physical-provider-gate-sidecar/v1"
    call_key: WorkerCallKey
    armed_zero: dict[str, object]
    provider_gate: PhysicalProviderGateReceipt
    debug_admission: DebugOnlyUserAttestedAdmission | None = None
    persisted_at: datetime
    sidecar_digest: str

    @model_validator(mode="after")
    def validate_sidecar(self) -> PhysicalProviderGateSidecar:
        if self.schema_version != "rolo-targetd-physical-provider-gate-sidecar/v1":
            raise ValueError("physical provider gate sidecar schema is invalid")
        if self.persisted_at.tzinfo is None or self.persisted_at.utcoffset() is None:
            raise ValueError("physical provider gate sidecar time must be aware")
        expected = "sha256:" + canonical_json_sha256(self.model_dump(mode="json", exclude={"sidecar_digest"}))
        if self.sidecar_digest != expected:
            raise ValueError("physical provider gate sidecar digest mismatch")
        gate = self.provider_gate
        production = isinstance(gate, ProviderGateConsumptionReceipt)
        debug = isinstance(gate, DebugUserAttestedProviderGateReceipt)
        if (
            (production and (gate.status != "CONSUMED" or gate.provider_boundary_open is not True or self.debug_admission is not None))
            or (
                debug
                and (
                    gate.status != "DEBUG_CONSUMED"
                    or gate.debug_provider_boundary_open is not True
                    or gate.production_provider_boundary_open is not False
                    or self.debug_admission is None
                    or gate.debug_admission_digest != self.debug_admission.payload_sha256
                )
            )
            or (not production and not debug)
            or gate.call_id != self.call_key.idempotency_key
            or gate.session_id != self.call_key.session_id
            or gate.target_id != self.call_key.target_id
        ):
            raise ValueError("physical provider gate sidecar identity mismatch")
        try:
            armed = _validate_armed_zero(self.armed_zero, self.call_key)
        except ProtocolError as exc:
            raise ValueError("physical provider gate sidecar arm mismatch") from exc
        if armed != self.armed_zero:
            raise ValueError("physical provider gate sidecar arm mismatch")
        return self


@dataclass(frozen=True)
class PhysicalProviderGateReference:
    uri: str
    digest_uri: str
    sidecar: PhysicalProviderGateSidecar


class PhysicalProviderGateReceiptStore:
    """Durably index consumed provider gates before target START is written."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(os.path.abspath(Path(root)))
        self.index_path = self.root / "index.json"
        for candidate in (self.root, *self.root.parents):
            if candidate.exists() and candidate.is_symlink():
                raise ProtocolError("TARGETD_PHYSICAL_GATE_STORE_UNTRUSTED")

    def persist(
        self,
        call_key: WorkerCallKey,
        receipt: PhysicalProviderGateReceipt,
        *,
        armed_zero: object,
        debug_admission: DebugOnlyUserAttestedAdmission | None = None,
        now: datetime | None = None,
    ) -> PhysicalProviderGateReference:
        call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
        if isinstance(receipt, DebugUserAttestedProviderGateReceipt):
            receipt = DebugUserAttestedProviderGateReceipt.model_validate(receipt.model_dump(mode="python"))
            if debug_admission is None:
                raise ProtocolError("TARGETD_PHYSICAL_GATE_DEBUG_ADMISSION_REQUIRED")
            debug_admission = DebugOnlyUserAttestedAdmission.model_validate(debug_admission.model_dump(mode="python"))
        elif isinstance(receipt, ProviderGateConsumptionReceipt):
            receipt = ProviderGateConsumptionReceipt.model_validate(receipt.model_dump(mode="python"))
            if debug_admission is not None:
                raise ProtocolError("TARGETD_PHYSICAL_GATE_DEBUG_ADMISSION_INVALID")
        else:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_RECEIPT_INVALID")
        point = datetime.now(timezone.utc) if now is None else now
        if point.tzinfo is None or point.utcoffset() is None:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_STORE_TIME_INVALID")
        normalized_point = point.astimezone(timezone.utc)
        persisted_text = normalized_point.isoformat().replace("+00:00", "Z")
        armed_payload = _validate_armed_zero(armed_zero, call_key)
        unsigned = {
            "schema_version": "rolo-targetd-physical-provider-gate-sidecar/v1",
            "call_key": call_key.model_dump(mode="json"),
            "armed_zero": armed_payload,
            "provider_gate": receipt.model_dump(mode="json"),
            "debug_admission": (debug_admission.model_dump(mode="json") if debug_admission is not None else None),
            "persisted_at": persisted_text,
        }
        sidecar = PhysicalProviderGateSidecar.model_validate(
            {
                **unsigned,
                "sidecar_digest": "sha256:" + canonical_json_sha256(unsigned),
            }
        )
        key_digest = call_key.digest()
        digest_hex = sidecar.sidecar_digest.removeprefix("sha256:")
        relative_path = f"receipts/{digest_hex}.json"
        receipt_path = self.root / relative_path
        encoded = (
            json.dumps(
                sidecar.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        if len(encoded.encode("utf-8")) > _MAX_GATE_STATE_BYTES:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_TOO_LARGE")

        self._require_trusted_store()
        with interprocess_lock(self.index_path):
            self._require_trusted_store()
            self._require_contained_receipt_path(receipt_path)
            if receipt_path.is_symlink():
                raise ProtocolError("TARGETD_PHYSICAL_GATE_STORE_UNTRUSTED")
            index = self._read_index_unlocked()
            existing = index["entries"].get(key_digest)
            entry = {
                "sidecar_digest": sidecar.sidecar_digest,
                "relative_path": relative_path,
            }
            if existing is not None and existing != entry:
                raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_CONFLICT")
            if receipt_path.exists():
                try:
                    self._require_regular_bounded_file(receipt_path)
                    current = PhysicalProviderGateSidecar.model_validate(loads_unique_json(receipt_path.read_text(encoding="utf-8")))
                    self._require_consumed_artifact_identity(current)
                except (OSError, UnicodeError, ValueError) as exc:
                    raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_INVALID") from exc
                if current != sidecar:
                    raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_CONFLICT")
            else:
                atomic_write_text(receipt_path, encoded)
            if existing is None:
                if len(index["entries"]) >= _MAX_GATE_RECEIPTS:
                    raise ProtocolError("TARGETD_PHYSICAL_GATE_STORE_CAPACITY_EXCEEDED")
                index["entries"][key_digest] = entry
                atomic_write_text(
                    self.index_path,
                    json.dumps(
                        index,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n",
                    acquire_lock=False,
                )
        return PhysicalProviderGateReference(
            uri=f"artifact://targetd/physical-provider-gates/{key_digest}/{digest_hex}",
            digest_uri=f"digest://sha256/{digest_hex}",
            sidecar=sidecar,
        )

    def load(
        self,
        call_key: WorkerCallKey,
    ) -> PhysicalProviderGateReference | None:
        """Load the indexed receipt for one exact call and revalidate bytes."""

        call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
        self._require_trusted_store()
        with interprocess_lock(self.index_path):
            self._require_trusted_store()
            index = self._read_index_unlocked()
            entry = index["entries"].get(call_key.digest())
            if entry is None:
                return None
            return self._load_entry_unlocked(call_key, entry)

    def resolve(
        self,
        uri: str,
        *,
        call_key: WorkerCallKey,
        digest_uri: str,
    ) -> PhysicalProviderGateReference:
        """Resolve content-addressed refs without accepting a filesystem path."""

        call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
        artifact_match = _GATE_ARTIFACT_URI.fullmatch(uri) if isinstance(uri, str) else None
        digest_match = _GATE_DIGEST_URI.fullmatch(digest_uri) if isinstance(digest_uri, str) else None
        if artifact_match is None or digest_match is None or artifact_match.group(1) != call_key.digest() or artifact_match.group(2) != digest_match.group(1):
            raise ProtocolError("TARGETD_PHYSICAL_GATE_REFERENCE_INVALID")
        reference = self.load(call_key)
        if reference is None:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_MISSING")
        if reference.uri != uri or reference.digest_uri != digest_uri:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_REFERENCE_MISMATCH")
        return reference

    def revalidate(
        self,
        reference: PhysicalProviderGateReference,
    ) -> PhysicalProviderGateReference:
        """Reload an earlier result and prove index/path/content identity again."""

        if not isinstance(reference, PhysicalProviderGateReference):
            raise ProtocolError("TARGETD_PHYSICAL_GATE_REFERENCE_INVALID")
        durable = self.resolve(
            reference.uri,
            call_key=reference.sidecar.call_key,
            digest_uri=reference.digest_uri,
        )
        if durable.sidecar != reference.sidecar:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_CONFLICT")
        return durable

    def _load_entry_unlocked(
        self,
        call_key: WorkerCallKey,
        entry: dict,
    ) -> PhysicalProviderGateReference:
        digest = entry["sidecar_digest"]
        digest_hex = digest.removeprefix("sha256:")
        expected_relative = f"receipts/{digest_hex}.json"
        if entry["relative_path"] != expected_relative:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_INDEX_INVALID")
        receipt_path = self.root / "receipts" / f"{digest_hex}.json"
        self._require_contained_receipt_path(receipt_path)
        self._require_regular_bounded_file(receipt_path)
        try:
            encoded = receipt_path.read_bytes()
            if not encoded or len(encoded) > _MAX_GATE_STATE_BYTES:
                raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_TOO_LARGE")
            raw = loads_unique_json(encoded.decode("utf-8"))
            sidecar = PhysicalProviderGateSidecar.model_validate(raw)
        except ProtocolError:
            raise
        except (OSError, UnicodeError, ValueError) as exc:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_INVALID") from exc
        if sidecar.call_key != call_key or sidecar.sidecar_digest != digest:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_INVALID")
        self._require_consumed_artifact_identity(sidecar)
        uri = f"artifact://targetd/physical-provider-gates/{call_key.digest()}/{digest_hex}"
        return PhysicalProviderGateReference(
            uri=uri,
            digest_uri=f"digest://sha256/{digest_hex}",
            sidecar=sidecar,
        )

    def _require_trusted_store(self) -> None:
        receipts = self.root / "receipts"
        for candidate in (self.root, receipts, *self.root.parents):
            if candidate.exists() and candidate.is_symlink():
                raise ProtocolError("TARGETD_PHYSICAL_GATE_STORE_UNTRUSTED")
        if self.index_path.is_symlink():
            raise ProtocolError("TARGETD_PHYSICAL_GATE_STORE_UNTRUSTED")

    def _require_contained_receipt_path(self, path: Path) -> None:
        try:
            root = self.root.resolve(strict=False)
            resolved = path.resolve(strict=False)
            if os.path.commonpath((str(root), str(resolved))) != str(root):
                raise ProtocolError("TARGETD_PHYSICAL_GATE_STORE_UNTRUSTED")
        except (OSError, ValueError) as exc:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_STORE_UNTRUSTED") from exc

    @staticmethod
    def _require_consumed_artifact_identity(
        sidecar: PhysicalProviderGateSidecar,
    ) -> None:
        receipt = sidecar.provider_gate
        artifact = receipt.consume_artifact
        persisted_at = sidecar.persisted_at.astimezone(timezone.utc)
        if (
            artifact is None
            or persisted_at < artifact.issued_at.astimezone(timezone.utc)
            or persisted_at >= artifact.expires_at.astimezone(timezone.utc)
            or receipt.evaluated_at.astimezone(timezone.utc) > persisted_at
        ):
            raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_INVALID")
        if isinstance(receipt, DebugUserAttestedProviderGateReceipt):
            admission = sidecar.debug_admission
            if (
                admission is None
                or receipt.status != "DEBUG_CONSUMED"
                or receipt.report_status != "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
                or receipt.production_provider_boundary_open is not False
                or receipt.production_ready is not False
                or receipt.production_authority_verified is not False
                or receipt.fresh_estop_challenge_verified is not False
                or receipt.debug_provider_boundary_open is not True
                or receipt.debug_motion_authorized is not True
                or receipt.provider_invocation_limit != 1
                or receipt.debug_admission_digest != admission.payload_sha256
                or artifact.kind != "PROVIDER_GATE_CONSUMED"
                or artifact.call_id != sidecar.call_key.idempotency_key
                or artifact.session_id != sidecar.call_key.session_id
                or artifact.target_id != sidecar.call_key.target_id
                or artifact.claims.get("consumed") is not True
                or artifact.claims.get("one_shot") is not True
                or artifact.claims.get("motion_enabled") is not False
                or artifact.claims.get("provider_invocation_count") != 0
            ):
                raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_INVALID")
            return
        if (
            artifact.kind != "PROVIDER_GATE_CONSUMED"
            or artifact.acceptance_id != receipt.acceptance_id
            or artifact.call_id != sidecar.call_key.idempotency_key
            or artifact.session_id != sidecar.call_key.session_id
            or artifact.target_id != sidecar.call_key.target_id
            or artifact.target_identity != receipt.target_identity
            or artifact.operator_id != receipt.operator_id
            or artifact.execution_subject_digest != receipt.execution_subject_digest
            or artifact.ros_graph_digest != receipt.ros_graph_digest
            or artifact.command_route != receipt.command_route
            or artifact.command_interface != receipt.command_interface
            or artifact.publisher_identity != receipt.publisher_identity
            or artifact.direct_motor_route != receipt.direct_motor_route
            or artifact.direct_motor_interface != receipt.direct_motor_interface
            or artifact.direct_motor_publisher_identity != receipt.direct_motor_publisher_identity
            or artifact.claims.get("challenge_artifact_digest") != receipt.challenge_artifact_digest
            or artifact.claims.get("provider_fence_digest") != receipt.provider_fence_digest
            or artifact.claims.get("consumed") is not True
            or artifact.claims.get("one_shot") is not True
            or artifact.claims.get("graph_compare_and_set") is not True
            or artifact.claims.get("fence_compare_and_set") is not True
            or artifact.claims.get("motion_enabled") is not False
            or artifact.claims.get("provider_invocation_count") != 0
        ):
            raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_INVALID")

    @staticmethod
    def _require_regular_bounded_file(path: Path) -> None:
        try:
            metadata = os.lstat(path)
        except FileNotFoundError as exc:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_MISSING") from exc
        except OSError as exc:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_INVALID") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ProtocolError("TARGETD_PHYSICAL_GATE_STORE_UNTRUSTED")
        if metadata.st_size <= 0 or metadata.st_size > _MAX_GATE_STATE_BYTES:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_TOO_LARGE")

    def _read_index_unlocked(self) -> dict:
        try:
            self._require_trusted_store()
            if self.index_path.stat().st_size > _MAX_GATE_STATE_BYTES:
                raise ProtocolError("TARGETD_PHYSICAL_GATE_INDEX_TOO_LARGE")
            raw = loads_unique_json(self.index_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {
                "schema_version": "rolo-targetd-physical-provider-gate-index/v1",
                "entries": {},
            }
        except ProtocolError:
            raise
        except (OSError, ValueError) as exc:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_INDEX_INVALID") from exc
        if (
            not isinstance(raw, dict)
            or set(raw) != {"schema_version", "entries"}
            or raw.get("schema_version") != "rolo-targetd-physical-provider-gate-index/v1"
            or not isinstance(raw.get("entries"), dict)
            or len(raw["entries"]) > _MAX_GATE_RECEIPTS
        ):
            raise ProtocolError("TARGETD_PHYSICAL_GATE_INDEX_INVALID")
        for key, entry in raw["entries"].items():
            if (
                not isinstance(key, str)
                or len(key) != 64
                or any(character not in "0123456789abcdef" for character in key)
                or not isinstance(entry, dict)
                or set(entry) != {"sidecar_digest", "relative_path"}
                or not isinstance(entry["sidecar_digest"], str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", entry["sidecar_digest"]) is None
                or entry["relative_path"] != f"receipts/{entry['sidecar_digest'].removeprefix('sha256:')}.json"
            ):
                raise ProtocolError("TARGETD_PHYSICAL_GATE_INDEX_INVALID")
        return raw


class PhysicalMotionProviderGate(Protocol):
    """Deployment-owned gate consumed only at an isolated provider boundary."""

    def validate_request(
        self,
        request: ExecutionRequestV3,
        authority: TargetdExecutionAuthority,
    ) -> None: ...

    def consume(
        self,
        request: ExecutionRequestV3,
        authority: TargetdExecutionAuthority,
    ) -> PhysicalProviderGateReceipt: ...

    def revalidate_consumption(
        self,
        receipt: PhysicalProviderGateReceipt,
        call_key: WorkerCallKey,
        *,
        at: datetime,
    ) -> None: ...


@dataclass(frozen=True)
class ZeroMotionPhysicalProviderGate:
    """Bind and consume one exact zero-motion provider-gate challenge."""

    acceptance_request: ZeroMotionAcceptanceRequest
    acceptance_receipt: ZeroMotionAcceptanceReceipt
    policy: MotionSafetyPolicy
    trust_store: MotionSafetyTrustStore
    target: ZeroMotionTarget
    clock: Callable[[], datetime] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "acceptance_request",
            ZeroMotionAcceptanceRequest.model_validate(self.acceptance_request.model_dump(mode="python")),
        )
        object.__setattr__(
            self,
            "acceptance_receipt",
            ZeroMotionAcceptanceReceipt.model_validate(self.acceptance_receipt.model_dump(mode="python")),
        )
        object.__setattr__(
            self,
            "policy",
            MotionSafetyPolicy.model_validate(self.policy.model_dump(mode="python")),
        )
        if not isinstance(self.trust_store, MotionSafetyTrustStore):
            raise ValueError("physical provider gate trust store is invalid")
        if self.clock is not None and not callable(self.clock):
            raise ValueError("physical provider gate clock is invalid")

    def validate_request(
        self,
        request: ExecutionRequestV3,
        authority: TargetdExecutionAuthority,
    ) -> None:
        """Validate static identity without consuming the one-shot gate."""

        if not isinstance(request, ExecutionRequestV3) or request.authority != authority:
            raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_IDENTITY_MISMATCH")
        acceptance = self.acceptance_request
        receipt = self.acceptance_receipt
        intent = acceptance.admission.intent
        if (
            acceptance.admission != request.motion_safety_admission
            or intent.call_id != request.idempotency_key
            or intent.session_id != request.session_id
            or intent.target_id != request.target_id
            or intent.target_identity != authority.mapping_admission.target_identity_digest
            or intent.execution_subject_digest != request.execution_subject_digest
            or receipt.status != "READY_FOR_PROVIDER_GATE"
            or receipt.acceptance_id != acceptance.acceptance_id
            or receipt.call_id != intent.call_id
            or receipt.session_id != intent.session_id
            or receipt.target_id != intent.target_id
            or receipt.target_identity != intent.target_identity
            or receipt.operator_id != intent.operator_id
            or receipt.execution_subject_digest != intent.execution_subject_digest
            or receipt.ros_graph_digest != intent.ros_graph_digest
            or receipt.provider_gate is None
            or receipt.motion_authorized is not False
            or receipt.requires_live_provider_cas is not True
        ):
            raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_IDENTITY_MISMATCH")

    def consume(
        self,
        request: ExecutionRequestV3,
        authority: TargetdExecutionAuthority,
    ) -> ProviderGateConsumptionReceipt:
        """Perform the target fresh-CAS and require a fully open one-shot receipt."""

        self.validate_request(request, authority)
        try:
            point = self.clock() if self.clock is not None else None
            result = consume_provider_gate_challenge(
                self.acceptance_request,
                self.acceptance_receipt,
                policy=self.policy,
                trust_store=self.trust_store,
                target=self.target,
                now=point,
            )
        except Exception as exc:
            raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_BLOCKED") from exc
        intent = self.acceptance_request.admission.intent
        consume_artifact = result.consume_artifact
        if (
            result.status != "CONSUMED"
            or result.consumed is not True
            or result.provider_boundary_open is not True
            or result.provider_invocation_limit != 1
            or result.motion_authorized is not False
            or result.acceptance_id != self.acceptance_request.acceptance_id
            or result.call_id != request.idempotency_key
            or result.session_id != request.session_id
            or result.target_id != request.target_id
            or result.target_identity != intent.target_identity
            or result.operator_id != intent.operator_id
            or result.execution_subject_digest != request.execution_subject_digest
            or result.ros_graph_digest != intent.ros_graph_digest
            or result.command_route != intent.command_route
            or result.command_interface != intent.command_interface
            or result.publisher_identity != intent.publisher_identity
            or result.direct_motor_route != intent.direct_motor_route
            or result.direct_motor_interface != intent.direct_motor_interface
            or result.direct_motor_publisher_identity != intent.direct_motor_publisher_identity
            or result.challenge_artifact_digest != self.acceptance_receipt.provider_gate.payload_sha256
            or result.provider_fence_digest is None
            or consume_artifact is None
            or consume_artifact.kind != "PROVIDER_GATE_CONSUMED"
            or consume_artifact.claims.get("provider_fence_digest") != result.provider_fence_digest
        ):
            raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_BLOCKED")
        return result

    def revalidate_consumption(
        self,
        receipt: PhysicalProviderGateReceipt,
        call_key: WorkerCallKey,
        *,
        at: datetime,
    ) -> None:
        """Recheck a durable consumed artifact against current trust roots."""

        if not isinstance(receipt, ProviderGateConsumptionReceipt):
            raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_BLOCKED")
        call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
        receipt = ProviderGateConsumptionReceipt.model_validate(receipt.model_dump(mode="python"))
        artifact = receipt.consume_artifact
        point = at
        if point.tzinfo is None or point.utcoffset() is None:
            raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_BLOCKED")
        intent = self.acceptance_request.admission.intent
        if (
            artifact is None
            or artifact.issuer_id != self.policy.target_authority_id
            or not self.trust_store.verify_payload_signature(
                issuer_id=artifact.issuer_id,
                payload_sha256=artifact.payload_sha256,
                signature_hmac_sha256=artifact.signature_hmac_sha256,
            )
            or point.astimezone(timezone.utc) < artifact.issued_at.astimezone(timezone.utc)
            or point.astimezone(timezone.utc) >= artifact.expires_at.astimezone(timezone.utc)
            or receipt.acceptance_id != self.acceptance_request.acceptance_id
            or receipt.challenge_artifact_digest != self.acceptance_receipt.provider_gate.payload_sha256
            or receipt.call_id != call_key.idempotency_key
            or receipt.session_id != call_key.session_id
            or receipt.target_id != call_key.target_id
            or receipt.target_identity != intent.target_identity
            or receipt.operator_id != intent.operator_id
            or receipt.execution_subject_digest != intent.execution_subject_digest
            or receipt.ros_graph_digest != intent.ros_graph_digest
            or receipt.command_route != intent.command_route
            or receipt.command_interface != intent.command_interface
            or receipt.publisher_identity != intent.publisher_identity
            or receipt.direct_motor_route != intent.direct_motor_route
            or receipt.direct_motor_interface != intent.direct_motor_interface
            or receipt.direct_motor_publisher_identity != intent.direct_motor_publisher_identity
            or artifact.acceptance_id != receipt.acceptance_id
            or artifact.target_identity != receipt.target_identity
            or artifact.operator_id != receipt.operator_id
            or artifact.command_route != receipt.command_route
            or artifact.command_interface != receipt.command_interface
            or artifact.publisher_identity != receipt.publisher_identity
            or artifact.direct_motor_route != receipt.direct_motor_route
            or artifact.direct_motor_interface != receipt.direct_motor_interface
            or artifact.direct_motor_publisher_identity != receipt.direct_motor_publisher_identity
            or artifact.claims.get("challenge_artifact_digest") != receipt.challenge_artifact_digest
            or artifact.claims.get("provider_fence_digest") != receipt.provider_fence_digest
        ):
            raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_BLOCKED")


@dataclass(frozen=True)
class DebugUserAttestedPhysicalProviderGate:
    """Explicit debug-only one-shot gate for the user-attested field slice."""

    admission: DebugOnlyUserAttestedAdmission
    acceptance_receipt: DebugUserAttestedAcceptanceReceipt
    intent: MotionSafetyIntent
    policy: MotionSafetyPolicy
    trust_store: MotionSafetyTrustStore
    target: LanderPiZeroMotionTarget
    clock: Callable[[], datetime] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "admission",
            DebugOnlyUserAttestedAdmission.model_validate(self.admission.model_dump(mode="python")),
        )
        object.__setattr__(
            self,
            "acceptance_receipt",
            DebugUserAttestedAcceptanceReceipt.model_validate(self.acceptance_receipt.model_dump(mode="python")),
        )
        object.__setattr__(
            self,
            "intent",
            MotionSafetyIntent.model_validate(self.intent.model_dump(mode="python")),
        )
        object.__setattr__(
            self,
            "policy",
            MotionSafetyPolicy.model_validate(self.policy.model_dump(mode="python")),
        )
        if not isinstance(self.trust_store, MotionSafetyTrustStore) or not isinstance(
            self.target,
            LanderPiZeroMotionTarget,
        ):
            raise ValueError("debug physical provider gate deployment is invalid")
        if self.clock is not None and not callable(self.clock):
            raise ValueError("debug physical provider gate clock is invalid")

    def validate_request(
        self,
        request: ExecutionRequestV3,
        authority: TargetdExecutionAuthority,
    ) -> None:
        admission = self.admission
        receipt = self.acceptance_receipt
        intent = self.intent
        try:
            admission.validate_debug_boundary()
        except Exception as exc:
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_PROVIDER_GATE_BLOCKED") from exc
        if (
            not isinstance(request, ExecutionRequestV3)
            or request.authority != authority
            or request.motion_safety_admission.intent != intent
            or admission.call_id != request.idempotency_key
            or admission.session_id != request.session_id
            or admission.target_id != request.target_id
            or admission.target_identity != authority.mapping_admission.target_identity_digest
            or admission.operator_id != intent.operator_id
            or admission.execution_subject_digest != request.execution_subject_digest
            or admission.requested_rotation_degrees != request.arguments.get("angle_degrees")
            or admission.requested_linear_meters != 0.0
            or abs(admission.requested_rotation_degrees) > 1.0
            or receipt.status != "DEBUG_ACCEPTED"
            or receipt.report_status != "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
            or receipt.debug_gate_ready is not True
            or receipt.production_ready is not False
            or receipt.production_authority_verified is not False
            or receipt.fresh_estop_challenge_verified is not False
            or receipt.motion_authorized is not False
            or receipt.provider_boundary_open is not False
            or receipt.debug_admission_digest != admission.payload_sha256
            or receipt.call_id != request.idempotency_key
            or receipt.session_id != request.session_id
            or receipt.target_id != request.target_id
            or receipt.execution_subject_digest != request.execution_subject_digest
        ):
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_PROVIDER_GATE_BLOCKED")

    def consume(
        self,
        request: ExecutionRequestV3,
        authority: TargetdExecutionAuthority,
    ) -> DebugUserAttestedProviderGateReceipt:
        self.validate_request(request, authority)
        point = self.clock() if self.clock is not None else datetime.now(timezone.utc)
        result = consume_debug_user_attested_provider_gate(
            self.admission,
            self.acceptance_receipt,
            intent=self.intent,
            policy=self.policy,
            trust_store=self.trust_store,
            target=self.target,
            now=point,
        )
        validation_point = self.clock() if self.clock is not None else datetime.now(timezone.utc)
        try:
            revalidate_debug_user_attested_provider_gate(
                self.admission,
                result,
                intent=self.intent,
                policy=self.policy,
                trust_store=self.trust_store,
                at=validation_point,
            )
        except ValueError as exc:
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_PROVIDER_GATE_BLOCKED") from exc
        if result.status != "DEBUG_CONSUMED":
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_PROVIDER_GATE_BLOCKED")
        return result

    def revalidate_consumption(
        self,
        receipt: PhysicalProviderGateReceipt,
        call_key: WorkerCallKey,
        *,
        at: datetime,
    ) -> None:
        if not isinstance(receipt, DebugUserAttestedProviderGateReceipt):
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_PROVIDER_GATE_BLOCKED")
        try:
            validation = revalidate_debug_user_attested_provider_gate(
                self.admission,
                receipt,
                intent=self.intent,
                policy=self.policy,
                trust_store=self.trust_store,
                at=at,
            )
        except (TypeError, ValueError) as exc:
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_PROVIDER_GATE_BLOCKED") from exc
        if validation.call_id != call_key.idempotency_key or validation.session_id != call_key.session_id or validation.target_id != call_key.target_id:
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_PROVIDER_GATE_BLOCKED")


__all__ = [
    "DebugUserAttestedPhysicalProviderGate",
    "PhysicalMotionProviderGate",
    "PhysicalProviderGateReceipt",
    "PhysicalProviderGateReceiptStore",
    "PhysicalProviderGateReference",
    "PhysicalProviderGateSidecar",
    "ZeroMotionPhysicalProviderGate",
]
