"""Durable debug-only physical acceptance records.

This store captures the last zero-motion acceptance state *before* a debug
provider gate is consumed.  The record is deliberately distinct from the
consumed-provider-gate sidecar: an accepted debug rehearsal still has both
production and provider boundaries closed.

The filesystem root is an authority boundary.  References are content
addressed and never contain caller-controlled paths; every read rechecks the
index, path containment, file type, bounded size, canonical digest, exact
call identity, and the signed-artifact time windows that were current when
the sidecar was persisted.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from rolo.core.hashing import canonical_json_sha256
from rolo.core.persistence import atomic_write_text, interprocess_lock
from rolo.dsl.parser import loads_unique_json

from .landerpi_motion_target import (
    DebugOnlyUserAttestedAdmission,
    DebugUserAttestedAcceptanceReceipt,
)
from .lifecycle import WorkerCallKey
from .motion_acceptance import ArmedZeroProviderBinding, SignedZeroMotionArtifact
from .physical_worker import PhysicalWorkerArmedZero, parse_physical_worker_armed_zero
from .protocol import ProtocolError

MAX_DEBUG_PHYSICAL_ACCEPTANCES = 2_048
MAX_DEBUG_PHYSICAL_ACCEPTANCE_SIDECAR_BYTES = 262_144
MAX_DEBUG_PHYSICAL_ACCEPTANCE_INDEX_BYTES = 4_194_304
MAX_DEBUG_PHYSICAL_ACCEPTANCE_STORE_BYTES = 67_108_864

_SIDECAR_SCHEMA = "rolo-targetd-debug-physical-acceptance-sidecar/v1"
_INDEX_SCHEMA = "rolo-targetd-debug-physical-acceptance-index/v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_URI = re.compile(
    r"^artifact://targetd/debug-physical-acceptances/([0-9a-f]{64})/([0-9a-f]{64})$"
)
_DIGEST_URI = re.compile(r"^digest://sha256/([0-9a-f]{64})$")


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _normalize_armed_zero(
    value: object,
    *,
    call_key: WorkerCallKey,
    execution_subject_digest: str,
) -> PhysicalWorkerArmedZero:
    raw = value.as_dict() if callable(getattr(value, "as_dict", None)) else value
    if not isinstance(raw, dict):
        raise ValueError("debug physical acceptance armed-zero receipt is invalid")
    runtime_sha256 = raw.get("runtime_sha256")
    if not isinstance(runtime_sha256, str) or _HEX_SHA256.fullmatch(runtime_sha256) is None:
        raise ValueError("debug physical acceptance armed-zero runtime is invalid")
    try:
        return parse_physical_worker_armed_zero(
            raw,
            expected_call_key_digest=call_key.digest(),
            expected_target_id=call_key.target_id,
            expected_call_id=call_key.idempotency_key,
            expected_session_id=call_key.session_id,
            expected_request_digest=call_key.request_digest,
            expected_execution_subject_digest=execution_subject_digest,
            expected_runtime_sha256=runtime_sha256,
        )
    except Exception as exc:
        raise ValueError("debug physical acceptance armed-zero receipt is invalid") from exc


def _common_artifact_identity(
    artifact: SignedZeroMotionArtifact,
    *,
    admission: DebugOnlyUserAttestedAdmission,
) -> bool:
    return (
        artifact.acceptance_id == admission.acceptance_id
        and artifact.call_id == admission.call_id
        and artifact.session_id == admission.session_id
        and artifact.target_id == admission.target_id
        and artifact.target_identity == admission.target_identity
        and artifact.operator_id == admission.operator_id
        and artifact.execution_subject_digest == admission.execution_subject_digest
    )


def _artifact_route_identity(artifact: SignedZeroMotionArtifact) -> tuple[str, ...]:
    return (
        artifact.issuer_id,
        artifact.ros_graph_digest,
        artifact.command_route,
        artifact.command_interface,
        artifact.publisher_identity,
        artifact.direct_motor_route,
        artifact.direct_motor_interface,
        artifact.direct_motor_publisher_identity,
    )


def _expected_debug_gate_binding(
    admission: DebugOnlyUserAttestedAdmission,
    debug_artifact: SignedZeroMotionArtifact,
) -> dict[str, object]:
    return {
        "debug_admission_digest": admission.payload_sha256,
        "debug_attestation_artifact_digest": debug_artifact.payload_sha256,
        "basis_digest": admission.basis_digest,
        "requested_rotation_degrees": admission.requested_rotation_degrees,
        "requested_linear_meters": admission.requested_linear_meters,
        "max_abs_rotation_degrees": 1.0,
        "max_abs_linear_meters": 0.03,
        "production_authority_verified": False,
        "fresh_estop_challenge_verified": False,
        "production_ready": False,
        "report_status": "PASS_WITH_USER_ATTESTED_SITE_SAFETY",
    }


class DebugPhysicalAcceptanceSidecar(BaseModel):
    """Immutable proof that one exact debug acceptance was durable in time."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["rolo-targetd-debug-physical-acceptance-sidecar/v1"] = _SIDECAR_SCHEMA
    call_key: WorkerCallKey
    armed_zero: dict[str, object]
    debug_admission: DebugOnlyUserAttestedAdmission
    acceptance_receipt: DebugUserAttestedAcceptanceReceipt
    persisted_at: datetime
    sidecar_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @property
    def content_digest(self) -> str:
        """The canonical content digest used by both durable references."""

        return self.sidecar_digest

    @model_validator(mode="after")
    def validate_sidecar(self) -> DebugPhysicalAcceptanceSidecar:
        point = _utc(self.persisted_at, "debug physical acceptance persisted_at")
        expected_digest = "sha256:" + canonical_json_sha256(
            self.model_dump(mode="json", exclude={"sidecar_digest"})
        )
        if self.sidecar_digest != expected_digest:
            raise ValueError("debug physical acceptance sidecar digest mismatch")

        admission = self.debug_admission
        receipt = self.acceptance_receipt
        if (
            admission.call_id != self.call_key.idempotency_key
            or admission.session_id != self.call_key.session_id
            or admission.target_id != self.call_key.target_id
            or receipt.status != "DEBUG_ACCEPTED"
            or receipt.report_status != "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
            or receipt.reasons
            or receipt.debug_gate_ready is not True
            or receipt.production_ready is not False
            or receipt.production_authority_verified is not False
            or receipt.fresh_estop_challenge_verified is not False
            or receipt.motion_authorized is not False
            or receipt.provider_boundary_open is not False
            or receipt.one_shot is not True
            or receipt.acceptance_id != admission.acceptance_id
            or receipt.call_id != admission.call_id
            or receipt.session_id != admission.session_id
            or receipt.target_id != admission.target_id
            or receipt.target_identity != admission.target_identity
            or receipt.operator_id != admission.operator_id
            or receipt.execution_subject_digest != admission.execution_subject_digest
            or receipt.debug_admission_digest != admission.payload_sha256
            or not receipt.artifacts.complete()
        ):
            raise ValueError("debug physical acceptance identity mismatch")

        armed = _normalize_armed_zero(
            self.armed_zero,
            call_key=self.call_key,
            execution_subject_digest=admission.execution_subject_digest,
        )
        if armed.as_dict() != self.armed_zero:
            raise ValueError("debug physical acceptance armed-zero normalization mismatch")

        debug_artifact = receipt.debug_attestation_artifact
        challenge = receipt.provider_gate
        if debug_artifact is None or challenge is None:
            raise ValueError("debug physical acceptance artifacts are missing")
        try:
            debug_artifact = SignedZeroMotionArtifact.model_validate(
                debug_artifact.model_dump(mode="python")
            )
            challenge = SignedZeroMotionArtifact.model_validate(
                challenge.model_dump(mode="python")
            )
        except Exception as exc:
            raise ValueError("debug physical acceptance artifact is invalid") from exc

        evaluated_at = _utc(receipt.evaluated_at, "debug physical acceptance evaluated_at")
        admission_issued = _utc(admission.issued_at, "debug admission issued_at")
        admission_expires = _utc(admission.expires_at, "debug admission expires_at")
        artifacts = (debug_artifact, challenge)
        if (
            admission_issued > evaluated_at
            or evaluated_at > point
            or point >= admission_expires
            or any(
                _utc(artifact.issued_at, "debug artifact issued_at") > evaluated_at
                or evaluated_at >= _utc(artifact.expires_at, "debug artifact expires_at")
                or point < _utc(artifact.issued_at, "debug artifact issued_at")
                or point >= _utc(artifact.expires_at, "debug artifact expires_at")
                for artifact in artifacts
            )
        ):
            raise ValueError("debug physical acceptance historical time window is invalid")

        if (
            debug_artifact.kind != "DEBUG_USER_ATTESTED_ADMISSION"
            or challenge.kind != "PROVIDER_GATE_CHALLENGE"
            or not _common_artifact_identity(debug_artifact, admission=admission)
            or not _common_artifact_identity(challenge, admission=admission)
            or _artifact_route_identity(debug_artifact)
            != _artifact_route_identity(challenge)
            or challenge.command_route != armed.command_endpoint
            or challenge.publisher_identity != armed.publisher_identity
            or challenge.direct_motor_publisher_identity
            not in armed.direct_motor_publisher_identities
            or receipt.artifacts.provider_gate_challenge != challenge.payload_sha256
            or debug_artifact.claims.get("debug_only") is not True
            or debug_artifact.claims.get("report_status")
            != "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
            or debug_artifact.claims.get("debug_admission_digest") != admission.payload_sha256
            or debug_artifact.claims.get("basis") != admission.basis
            or debug_artifact.claims.get("basis_digest") != admission.basis_digest
            or debug_artifact.claims.get("requested_rotation_degrees")
            != admission.requested_rotation_degrees
            or debug_artifact.claims.get("requested_linear_meters")
            != admission.requested_linear_meters
            or debug_artifact.claims.get("site_id") != admission.site_id
            or debug_artifact.claims.get("safe_zone_id") != admission.safe_zone_id
            or debug_artifact.claims.get("max_abs_rotation_degrees") != 1.0
            or debug_artifact.claims.get("max_abs_linear_meters") != 0.03
            or debug_artifact.claims.get("onsite_operator_asserted") is not True
            or debug_artifact.claims.get("independent_estop_available_asserted")
            is not True
            or debug_artifact.claims.get("safe_zone_clear_asserted") is not True
            or debug_artifact.claims.get("production_authority_verified") is not False
            or debug_artifact.claims.get("fresh_estop_challenge_verified") is not False
            or debug_artifact.claims.get("production_ready") is not False
            or debug_artifact.claims.get("one_shot") is not True
            or debug_artifact.claims.get("motion_enabled") is not False
            or debug_artifact.claims.get("provider_invocation_count") != 0
            or challenge.claims.get("debug_gate_binding")
            != _expected_debug_gate_binding(admission, debug_artifact)
            or challenge.claims.get("one_shot") is not True
            or challenge.claims.get("consumed") is not False
            or challenge.claims.get("motion_enabled") is not False
            or challenge.claims.get("provider_invocation_count") != 0
        ):
            raise ValueError("debug physical acceptance artifact identity mismatch")
        try:
            challenge_binding = ArmedZeroProviderBinding.model_validate(
                challenge.claims.get("armed_zero_provider_binding")
            )
        except Exception as exc:
            raise ValueError("debug physical acceptance armed-zero binding is invalid") from exc
        if challenge_binding != armed.provider_binding():
            raise ValueError("debug physical acceptance armed-zero binding mismatch")
        return self


@dataclass(frozen=True)
class DebugPhysicalAcceptanceReference:
    uri: str
    digest_uri: str
    sidecar: DebugPhysicalAcceptanceSidecar


class DebugPhysicalAcceptanceReceiptStore:
    """Content-addressed debug acceptance store with a separate call index."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(os.path.abspath(Path(root)))
        self.receipts_root = self.root / "receipts"
        self.index_path = self.root / "index.json"
        self._require_trusted_store()

    def persist(
        self,
        call_key: WorkerCallKey,
        receipt: DebugUserAttestedAcceptanceReceipt,
        *,
        armed_zero: object,
        debug_admission: DebugOnlyUserAttestedAdmission,
        now: datetime | None = None,
    ) -> DebugPhysicalAcceptanceReference:
        """Persist one immutable acceptance; a changed replay is a conflict."""

        try:
            call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
            debug_admission = DebugOnlyUserAttestedAdmission.model_validate(
                debug_admission.model_dump(mode="python")
            )
            receipt = DebugUserAttestedAcceptanceReceipt.model_validate(
                receipt.model_dump(mode="python")
            )
            point = datetime.now(timezone.utc) if now is None else now
            point = _utc(point, "debug physical acceptance store time")
            armed = _normalize_armed_zero(
                armed_zero,
                call_key=call_key,
                execution_subject_digest=debug_admission.execution_subject_digest,
            )
            unsigned = {
                "schema_version": _SIDECAR_SCHEMA,
                "call_key": call_key.model_dump(mode="json"),
                "armed_zero": armed.as_dict(),
                "debug_admission": debug_admission.model_dump(mode="json"),
                "acceptance_receipt": receipt.model_dump(mode="json"),
                "persisted_at": point.isoformat().replace("+00:00", "Z"),
            }
            sidecar = DebugPhysicalAcceptanceSidecar.model_validate(
                {
                    **unsigned,
                    "sidecar_digest": "sha256:" + canonical_json_sha256(unsigned),
                }
            )
        except ProtocolError:
            raise
        except Exception as exc:
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_INVALID") from exc

        encoded = self._encode_sidecar(sidecar)
        key_digest = call_key.digest()
        digest_hex = sidecar.sidecar_digest.removeprefix("sha256:")
        relative_path = f"receipts/{digest_hex}.json"
        receipt_path = self.root / relative_path
        entry = {
            "sidecar_digest": sidecar.sidecar_digest,
            "relative_path": relative_path,
            "size_bytes": len(encoded),
            "arm_receipt_digest": sidecar.armed_zero["arm_receipt_digest"],
            "debug_admission_digest": debug_admission.payload_sha256,
            "acceptance_id": debug_admission.acceptance_id,
        }

        self._require_trusted_store()
        try:
            with interprocess_lock(self.index_path, stale_after_s=None):
                self._require_trusted_store()
                self._require_contained_path(receipt_path)
                index = self._read_index_unlocked()
                existing = index["entries"].get(key_digest)
                if existing is not None and existing != entry:
                    raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_CONFLICT")
                for indexed_key, indexed_entry in index["entries"].items():
                    if indexed_key != key_digest and (
                        indexed_entry["debug_admission_digest"]
                        == debug_admission.payload_sha256
                        or indexed_entry["acceptance_id"]
                        == debug_admission.acceptance_id
                    ):
                        raise ProtocolError(
                            "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_CONFLICT"
                        )
                receipt_already_exists = receipt_path.exists()
                if receipt_already_exists:
                    current = self._read_sidecar_file(receipt_path)
                    if current != sidecar:
                        raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_CONFLICT")
                if existing is None:
                    if len(index["entries"]) >= MAX_DEBUG_PHYSICAL_ACCEPTANCES:
                        raise ProtocolError(
                            "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_CAPACITY_EXCEEDED"
                        )
                    index["entries"][key_digest] = entry
                    index_encoded = self._encode_index(index)
                    self._require_store_capacity(
                        index_encoded=index_encoded,
                        additional_receipt_bytes=(
                            0 if receipt_already_exists else len(encoded)
                        ),
                        additional_receipt_files=(0 if receipt_already_exists else 1),
                    )
                    if not receipt_already_exists:
                        atomic_write_text(
                            receipt_path,
                            encoded.decode("utf-8"),
                            acquire_lock=False,
                            require_absent=True,
                        )
                    atomic_write_text(
                        self.index_path,
                        index_encoded.decode("utf-8"),
                        acquire_lock=False,
                    )
                else:
                    self._require_store_capacity()
        except ProtocolError:
            raise
        except (FileExistsError, OSError, TimeoutError) as exc:
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_STORE_IO_ERROR") from exc
        return self._reference(call_key, sidecar)

    def load(self, call_key: WorkerCallKey) -> DebugPhysicalAcceptanceReference | None:
        """Load one call's acceptance and revalidate the indexed bytes."""

        call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
        self._require_trusted_store()
        try:
            with interprocess_lock(self.index_path, stale_after_s=None):
                self._require_trusted_store()
                index = self._read_index_unlocked()
                self._require_store_capacity()
                entry = index["entries"].get(call_key.digest())
                if entry is None:
                    return None
                return self._load_entry_unlocked(call_key, entry)
        except ProtocolError:
            raise
        except (OSError, TimeoutError) as exc:
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_STORE_IO_ERROR") from exc

    def resolve(
        self,
        uri: str,
        *,
        call_key: WorkerCallKey,
        digest_uri: str,
    ) -> DebugPhysicalAcceptanceReference:
        """Resolve only the exact content-addressed URI pair for ``call_key``."""

        call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
        artifact_match = _ARTIFACT_URI.fullmatch(uri) if isinstance(uri, str) else None
        digest_match = _DIGEST_URI.fullmatch(digest_uri) if isinstance(digest_uri, str) else None
        if (
            artifact_match is None
            or digest_match is None
            or artifact_match.group(1) != call_key.digest()
            or artifact_match.group(2) != digest_match.group(1)
        ):
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_REFERENCE_INVALID")
        reference = self.load(call_key)
        if reference is None:
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_MISSING")
        if reference.uri != uri or reference.digest_uri != digest_uri:
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_REFERENCE_MISMATCH")
        return reference

    def revalidate(
        self,
        reference: DebugPhysicalAcceptanceReference,
    ) -> DebugPhysicalAcceptanceReference:
        """Reload a prior reference; never trust its cached sidecar alone."""

        if not isinstance(reference, DebugPhysicalAcceptanceReference):
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_REFERENCE_INVALID")
        durable = self.resolve(
            reference.uri,
            call_key=reference.sidecar.call_key,
            digest_uri=reference.digest_uri,
        )
        if durable.sidecar != reference.sidecar:
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_CONFLICT")
        return durable

    @staticmethod
    def _encode_sidecar(sidecar: DebugPhysicalAcceptanceSidecar) -> bytes:
        encoded = (
            json.dumps(
                sidecar.model_dump(mode="json"),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        if not encoded or len(encoded) > MAX_DEBUG_PHYSICAL_ACCEPTANCE_SIDECAR_BYTES:
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_SIDECAR_TOO_LARGE")
        return encoded

    @staticmethod
    def _encode_index(index: dict[str, object]) -> bytes:
        encoded = (
            json.dumps(
                index,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        if not encoded or len(encoded) > MAX_DEBUG_PHYSICAL_ACCEPTANCE_INDEX_BYTES:
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_INDEX_TOO_LARGE")
        return encoded

    def _reference(
        self,
        call_key: WorkerCallKey,
        sidecar: DebugPhysicalAcceptanceSidecar,
    ) -> DebugPhysicalAcceptanceReference:
        digest_hex = sidecar.sidecar_digest.removeprefix("sha256:")
        return DebugPhysicalAcceptanceReference(
            uri=(
                "artifact://targetd/debug-physical-acceptances/"
                f"{call_key.digest()}/{digest_hex}"
            ),
            digest_uri=f"digest://sha256/{digest_hex}",
            sidecar=sidecar,
        )

    def _load_entry_unlocked(
        self,
        call_key: WorkerCallKey,
        entry: dict[str, object],
    ) -> DebugPhysicalAcceptanceReference:
        digest = entry["sidecar_digest"]
        if not isinstance(digest, str):
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_INDEX_INVALID")
        digest_hex = digest.removeprefix("sha256:")
        expected_relative = f"receipts/{digest_hex}.json"
        if entry["relative_path"] != expected_relative:
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_INDEX_INVALID")
        receipt_path = self.receipts_root / f"{digest_hex}.json"
        self._require_contained_path(receipt_path)
        sidecar = self._read_sidecar_file(receipt_path)
        actual_size = os.lstat(receipt_path).st_size
        if (
            entry["size_bytes"] != actual_size
            or entry["arm_receipt_digest"]
            != sidecar.armed_zero["arm_receipt_digest"]
            or entry["debug_admission_digest"]
            != sidecar.debug_admission.payload_sha256
            or entry["acceptance_id"] != sidecar.debug_admission.acceptance_id
            or sidecar.call_key != call_key
            or sidecar.sidecar_digest != digest
        ):
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_SIDECAR_INVALID")
        return self._reference(call_key, sidecar)

    def _read_sidecar_file(self, path: Path) -> DebugPhysicalAcceptanceSidecar:
        self._require_regular_bounded_file(
            path,
            missing_code="TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_MISSING",
            maximum=MAX_DEBUG_PHYSICAL_ACCEPTANCE_SIDECAR_BYTES,
        )
        try:
            encoded = path.read_bytes()
            raw = loads_unique_json(encoded.decode("utf-8"))
            return DebugPhysicalAcceptanceSidecar.model_validate(raw)
        except ProtocolError:
            raise
        except (OSError, UnicodeError, ValueError) as exc:
            raise ProtocolError(
                "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_SIDECAR_INVALID"
            ) from exc

    def _read_index_unlocked(self) -> dict[str, object]:
        try:
            os.lstat(self.index_path)
        except FileNotFoundError:
            return {"schema_version": _INDEX_SCHEMA, "entries": {}}
        except OSError as exc:
            raise ProtocolError(
                "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_INDEX_INVALID"
            ) from exc
        try:
            self._require_trusted_store()
            self._require_regular_bounded_file(
                self.index_path,
                missing_code="TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_INDEX_MISSING",
                maximum=MAX_DEBUG_PHYSICAL_ACCEPTANCE_INDEX_BYTES,
            )
            raw = loads_unique_json(self.index_path.read_text(encoding="utf-8"))
        except ProtocolError:
            raise
        except (OSError, UnicodeError, ValueError) as exc:
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_INDEX_INVALID") from exc
        if (
            not isinstance(raw, dict)
            or set(raw) != {"schema_version", "entries"}
            or raw.get("schema_version") != _INDEX_SCHEMA
            or not isinstance(raw.get("entries"), dict)
            or len(raw["entries"]) > MAX_DEBUG_PHYSICAL_ACCEPTANCES
        ):
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_INDEX_INVALID")
        admission_digests: set[str] = set()
        acceptance_ids: set[str] = set()
        for key, entry in raw["entries"].items():
            if (
                not isinstance(key, str)
                or _HEX_SHA256.fullmatch(key) is None
                or not isinstance(entry, dict)
                or set(entry)
                != {
                    "sidecar_digest",
                    "relative_path",
                    "size_bytes",
                    "arm_receipt_digest",
                    "debug_admission_digest",
                    "acceptance_id",
                }
                or not isinstance(entry["sidecar_digest"], str)
                or _SHA256.fullmatch(entry["sidecar_digest"]) is None
                or not isinstance(entry["arm_receipt_digest"], str)
                or _HEX_SHA256.fullmatch(entry["arm_receipt_digest"]) is None
                or not isinstance(entry["debug_admission_digest"], str)
                or _SHA256.fullmatch(entry["debug_admission_digest"]) is None
                or not isinstance(entry["acceptance_id"], str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", entry["acceptance_id"])
                is None
                or entry["relative_path"]
                != f"receipts/{entry['sidecar_digest'].removeprefix('sha256:')}.json"
                or isinstance(entry["size_bytes"], bool)
                or not isinstance(entry["size_bytes"], int)
                or not 0 < entry["size_bytes"] <= MAX_DEBUG_PHYSICAL_ACCEPTANCE_SIDECAR_BYTES
            ):
                raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_INDEX_INVALID")
            if (
                entry["debug_admission_digest"] in admission_digests
                or entry["acceptance_id"] in acceptance_ids
            ):
                raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_INDEX_INVALID")
            admission_digests.add(entry["debug_admission_digest"])
            acceptance_ids.add(entry["acceptance_id"])
        return raw

    def _require_trusted_store(self) -> None:
        for candidate in (
            *self.root.parents,
            self.root,
            self.receipts_root,
            self.index_path,
        ):
            try:
                metadata = os.lstat(candidate)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ProtocolError(
                    "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_STORE_UNTRUSTED"
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_STORE_UNTRUSTED")
        if self.root.exists() and not self.root.is_dir():
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_STORE_UNTRUSTED")
        if self.receipts_root.exists() and not self.receipts_root.is_dir():
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_STORE_UNTRUSTED")
        self._require_contained_path(self.index_path)
        self._require_contained_path(self.receipts_root)

    def _require_contained_path(self, path: Path) -> None:
        try:
            root = os.path.normcase(str(self.root.resolve(strict=False)))
            resolved = os.path.normcase(str(path.resolve(strict=False)))
            if os.path.commonpath((root, resolved)) != root:
                raise ProtocolError(
                    "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_STORE_UNTRUSTED"
                )
        except ProtocolError:
            raise
        except (OSError, ValueError) as exc:
            raise ProtocolError(
                "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_STORE_UNTRUSTED"
            ) from exc

    @staticmethod
    def _require_regular_bounded_file(
        path: Path,
        *,
        missing_code: str,
        maximum: int,
    ) -> None:
        try:
            metadata = os.lstat(path)
        except FileNotFoundError as exc:
            raise ProtocolError(missing_code) from exc
        except OSError as exc:
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_STORE_IO_ERROR") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_STORE_UNTRUSTED")
        if metadata.st_size <= 0 or metadata.st_size > maximum:
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_SIDECAR_TOO_LARGE")

    def _require_store_capacity(
        self,
        *,
        index_encoded: bytes | None = None,
        additional_receipt_bytes: int = 0,
        additional_receipt_files: int = 0,
    ) -> None:
        self._require_trusted_store()
        receipt_count = 0
        total_bytes = len(index_encoded) if index_encoded is not None else 0
        if index_encoded is None and self.index_path.exists():
            metadata = os.lstat(self.index_path)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_STORE_UNTRUSTED")
            total_bytes += metadata.st_size
        if self.receipts_root.exists():
            try:
                entries = list(os.scandir(self.receipts_root))
            except OSError as exc:
                raise ProtocolError(
                    "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_STORE_IO_ERROR"
                ) from exc
            for entry in entries:
                try:
                    if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                        raise ProtocolError(
                            "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_STORE_UNTRUSTED"
                        )
                    metadata = entry.stat(follow_symlinks=False)
                except ProtocolError:
                    raise
                except OSError as exc:
                    raise ProtocolError(
                        "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_STORE_IO_ERROR"
                    ) from exc
                if (
                    re.fullmatch(r"[0-9a-f]{64}\.json", entry.name) is None
                    or metadata.st_size <= 0
                    or metadata.st_size > MAX_DEBUG_PHYSICAL_ACCEPTANCE_SIDECAR_BYTES
                ):
                    raise ProtocolError(
                        "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_STORE_UNTRUSTED"
                    )
                receipt_count += 1
                total_bytes += metadata.st_size
        if (
            receipt_count + additional_receipt_files
            > MAX_DEBUG_PHYSICAL_ACCEPTANCES
            or total_bytes + additional_receipt_bytes
            > MAX_DEBUG_PHYSICAL_ACCEPTANCE_STORE_BYTES
        ):
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_CAPACITY_EXCEEDED")


DebugPhysicalAcceptanceStore = DebugPhysicalAcceptanceReceiptStore

__all__ = [
    "DebugPhysicalAcceptanceReceiptStore",
    "DebugPhysicalAcceptanceReference",
    "DebugPhysicalAcceptanceSidecar",
    "DebugPhysicalAcceptanceStore",
    "MAX_DEBUG_PHYSICAL_ACCEPTANCES",
    "MAX_DEBUG_PHYSICAL_ACCEPTANCE_INDEX_BYTES",
    "MAX_DEBUG_PHYSICAL_ACCEPTANCE_SIDECAR_BYTES",
    "MAX_DEBUG_PHYSICAL_ACCEPTANCE_STORE_BYTES",
]
