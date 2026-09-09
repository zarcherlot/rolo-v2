"""Targetd service state machine used by the SSH stdio bridge and tests."""

from __future__ import annotations

import hmac
import json
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

from rolo.core.hashing import canonical_json_sha256
from rolo.core.persistence import atomic_write_text, interprocess_lock
from rolo.dsl.admission import (
    MappingAdmissionError,
    MappingAdmissionGate,
    MappingAdmissionIdentity,
    MappingConfirmationReceipt,
    MappingConfirmationStore,
    ProductionMappingConfirmationStore,
    bind_mapping_admission_gate,
)
from rolo.dsl.parser import loads_unique_json
from rolo.releases.publisher import ToolRelease, tool_release_digest

from .landerpi_motion_target import (
    DebugOnlyUserAttestedAdmission,
    DebugUserAttestedProviderGateReceipt,
)
from .lifecycle import (
    WorkerCallKey,
    WorkerLeaseClaim,
    WorkerLeaseRecord,
    WorkerLeaseStore,
)
from .lifecycle_integration import validate_sealed_odom_r0_call
from .motion_acceptance import (
    ArmedZeroProviderBinding,
    ProviderGateConsumptionReceipt,
)
from .physical_gate import (
    DebugUserAttestedPhysicalProviderGate,
    PhysicalMotionProviderGate,
    PhysicalProviderGateReceipt,
    PhysicalProviderGateReceiptStore,
    PhysicalProviderGateReference,
)
from .protocol import (
    _IDENTIFIER,
    _SHA256,
    BundleCache,
    ExecutionBundleManifest,
    ExecutionRequestLike,
    ExecutionRequestV3,
    FrameKind,
    JourneySession,
    ProtocolError,
    TargetdAuthorityActivationRequest,
    TargetdCallReceipt,
    TargetdExecutionAuthority,
    TargetdExecutionAuthorityStore,
    TargetdMappingCancelRequest,
    TargetdStateStore,
    TargetdVerifiedReleaseProvisionRequest,
    provider_fence_digest,
    requires_motion_safety,
    validate_execution_request,
)

if TYPE_CHECKING:
    from .physical_acceptance import (
        DebugPhysicalAcceptanceReceiptStore,
        DebugPhysicalAcceptanceReference,
    )


class TargetdHealth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-targetd-health/v1"] = "rolo-targetd-health/v1"
    status: Literal["HEALTHY", "DEGRADED", "UNAVAILABLE"]
    target_id: str = Field(pattern=_IDENTIFIER)
    capability_digest: str = Field(pattern=_SHA256)
    active_sessions: int = Field(ge=0)


@dataclass(frozen=True)
class TargetdReleaseHead:
    """A fully reloaded target-side Catalog current pointer."""

    tool_id: str
    release_digest: str
    release: ToolRelease
    catalog_head_digest: str


@dataclass(frozen=True)
class TargetdPhysicalProcessStart:
    """Target START receipt plus the consumed one-shot provider fence."""

    receipt: TargetdCallReceipt
    provider_gate: PhysicalProviderGateReceipt


class TargetdReleaseCatalog:
    """Read and fence a target-resident verified Release Catalog.

    The directory is a deployment authority boundary.  Activation requests
    carry only expected digests; this resolver reloads the Catalog and the
    immutable Release file itself, recomputes their digests, and rejects
    stale/non-callable/unverified entries.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.catalog_path = self.root / "tool-catalog.json"

    def resolve_current(self, tool_id: str) -> TargetdReleaseHead:
        with interprocess_lock(self.catalog_path):
            return self._resolve_current_unlocked(tool_id)

    def provision_verified(
        self,
        *,
        release_digest: str,
        release: ToolRelease,
        expected_catalog_head_digest: str | None,
    ) -> TargetdReleaseHead:
        """CAS one independently verified immutable Release into current."""

        release = ToolRelease.model_validate(release.model_dump(mode="python"))
        if tool_release_digest(release) != release_digest:
            raise ProtocolError("TARGETD_VERIFIED_RELEASE_DIGEST_MISMATCH")
        with interprocess_lock(self.catalog_path):
            if self.catalog_path.is_symlink():
                raise ProtocolError("TARGETD_RELEASE_CATALOG_UNTRUSTED")
            try:
                catalog = loads_unique_json(self.catalog_path.read_text(encoding="utf-8"))
            except FileNotFoundError:
                catalog = {
                    "schema_version": "rolo-tool-catalog/v1",
                    "tools": {},
                }
                actual_head = None
            except (OSError, ValueError, TypeError) as exc:
                raise ProtocolError("TARGETD_RELEASE_CATALOG_INVALID") from exc
            else:
                if not isinstance(catalog, dict) or catalog.get("schema_version") != "rolo-tool-catalog/v1" or not isinstance(catalog.get("tools"), dict):
                    raise ProtocolError("TARGETD_RELEASE_CATALOG_INVALID")
                actual_head = "sha256:" + canonical_json_sha256(catalog)

            entry = catalog["tools"].get(release.tool_id)
            if isinstance(entry, dict) and entry.get("current") == release_digest and entry.get("status") != "STALE":
                current = self._resolve_current_unlocked(release.tool_id)
                if current.release != release:
                    raise ProtocolError("TARGETD_RELEASE_CATALOG_ENTRY_MISMATCH")
                return current
            if expected_catalog_head_digest != actual_head:
                raise ProtocolError("TARGETD_RELEASE_CATALOG_CAS_FAILED")

            release_path = self.root / "releases" / f"{release_digest.removeprefix('sha256:')}.json"
            if release_path.is_symlink():
                raise ProtocolError("TARGETD_VERIFIED_RELEASE_UNTRUSTED")
            if release_path.exists():
                try:
                    existing = ToolRelease.model_validate(loads_unique_json(release_path.read_text(encoding="utf-8")))
                except (OSError, ValueError, TypeError) as exc:
                    raise ProtocolError("TARGETD_VERIFIED_RELEASE_INVALID") from exc
                if existing != release:
                    raise ProtocolError("TARGETD_VERIFIED_RELEASE_IMMUTABLE")
            else:
                atomic_write_text(
                    release_path,
                    json.dumps(
                        release.model_dump(mode="json"),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n",
                )

            catalog["tools"][release.tool_id] = {
                "current": release_digest,
                "release": release.model_dump(mode="json"),
            }
            atomic_write_text(
                self.catalog_path,
                json.dumps(
                    catalog,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
                acquire_lock=False,
            )
            return self._resolve_current_unlocked(release.tool_id)

    def commit_if_current(
        self,
        expected: TargetdReleaseHead,
        commit: Callable[[], TargetdExecutionAuthority | TargetdCallReceipt],
    ) -> TargetdExecutionAuthority | TargetdCallReceipt:
        with interprocess_lock(self.catalog_path):
            current = self._resolve_current_unlocked(expected.tool_id)
            if current != expected:
                raise ProtocolError("TARGETD_RELEASE_CATALOG_HEAD_STALE")
            return commit()

    def require_authority_current(
        self,
        authority: TargetdExecutionAuthority,
    ) -> TargetdReleaseHead:
        head = self.resolve_current(authority.tool_id)
        if (
            head.release_digest != authority.release_digest
            or head.catalog_head_digest != authority.catalog_head_digest
            or head.release.mapping_confirmation_receipt_digest != authority.mapping_confirmation_receipt_digest
            or head.release.mapping_admission != authority.mapping_admission
        ):
            raise ProtocolError("TARGETD_RELEASE_CATALOG_HEAD_STALE")
        return head

    def _resolve_current_unlocked(self, tool_id: str) -> TargetdReleaseHead:
        if self.catalog_path.is_symlink():
            raise ProtocolError("TARGETD_RELEASE_CATALOG_UNTRUSTED")
        try:
            catalog = loads_unique_json(self.catalog_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ProtocolError("TARGETD_VERIFIED_RELEASE_REQUIRED") from exc
        except (OSError, ValueError, TypeError) as exc:
            raise ProtocolError("TARGETD_RELEASE_CATALOG_INVALID") from exc
        if not isinstance(catalog, dict) or catalog.get("schema_version") != "rolo-tool-catalog/v1" or not isinstance(catalog.get("tools"), dict):
            raise ProtocolError("TARGETD_RELEASE_CATALOG_INVALID")
        entry = catalog["tools"].get(tool_id)
        if not isinstance(entry, dict):
            raise ProtocolError("TARGETD_VERIFIED_RELEASE_REQUIRED")
        release_digest = entry.get("current")
        if not isinstance(release_digest, str) or not release_digest.startswith("sha256:") or len(release_digest) != 71 or entry.get("status") == "STALE":
            raise ProtocolError("TARGETD_VERIFIED_RELEASE_NOT_CURRENT")
        release_path = self.root / "releases" / f"{release_digest.removeprefix('sha256:')}.json"
        if release_path.is_symlink():
            raise ProtocolError("TARGETD_VERIFIED_RELEASE_UNTRUSTED")
        try:
            release_payload = loads_unique_json(release_path.read_text(encoding="utf-8"))
            release = ToolRelease.model_validate(release_payload)
        except (OSError, ValueError, TypeError) as exc:
            raise ProtocolError("TARGETD_VERIFIED_RELEASE_INVALID") from exc
        if tool_release_digest(release) != release_digest:
            raise ProtocolError("TARGETD_VERIFIED_RELEASE_DIGEST_MISMATCH")
        embedded = entry.get("release")
        if embedded is not None:
            try:
                if ToolRelease.model_validate(embedded) != release:
                    raise ProtocolError("TARGETD_RELEASE_CATALOG_ENTRY_MISMATCH")
            except ValueError as exc:
                raise ProtocolError("TARGETD_RELEASE_CATALOG_ENTRY_MISMATCH") from exc
        if (
            release.tool_id != tool_id
            or release.status != "PUBLISHED"
            or not release.agent_callable
            or release.target_conformance_digest is None
            or release.mapping_admission is None
            or release.mapping_confirmation_receipt_digest is None
            or release.compile_context_digest is None
        ):
            raise ProtocolError("TARGETD_VERIFIED_RELEASE_REQUIRED")
        catalog_head_digest = "sha256:" + canonical_json_sha256(catalog)
        return TargetdReleaseHead(
            tool_id=tool_id,
            release_digest=release_digest,
            release=release,
            catalog_head_digest=catalog_head_digest,
        )


class TargetdService:
    """Persisted targetd lifecycle and call receipt authority.

    The service intentionally does not execute source itself.  A worker can
    consume an ``ACCEPTED`` receipt and report a terminal result through
    :meth:`complete_call`; this keeps transport/state semantics reusable for
    Python, ROS, and future providers.
    """

    def __init__(
        self,
        *,
        target_id: str,
        state_root,
        bundle_root=None,
        signing_key: bytes | None = None,
        verification_keys: dict[str, bytes] | None = None,
        confirmation_store: (MappingConfirmationStore | ProductionMappingConfirmationStore | None) = None,
        admission_gate: MappingAdmissionGate | None = None,
        execution_authority_store: TargetdExecutionAuthorityStore | None = None,
        release_catalog: TargetdReleaseCatalog | None = None,
        physical_motion_gate: PhysicalMotionProviderGate | None = None,
        physical_worker_store: WorkerLeaseStore | None = None,
        physical_gate_receipt_store: PhysicalProviderGateReceiptStore | None = None,
        physical_acceptance_receipt_store: DebugPhysicalAcceptanceReceiptStore
        | None = None,
    ) -> None:
        self.target_id = target_id
        self.state = TargetdStateStore(state_root)
        self.cache = BundleCache(bundle_root or state_root)
        self.signing_key = signing_key
        self.verification_keys = dict(verification_keys or {})
        self.confirmation_store = confirmation_store
        self.admission_gate = bind_mapping_admission_gate(
            confirmation_store,
            admission_gate,
        )
        self.execution_authority_store = execution_authority_store
        self.release_catalog = release_catalog
        self.physical_motion_gate = physical_motion_gate
        # Live gate objects contain deployment callbacks and cannot be
        # serialized. Keep them keyed by exact call while this process is
        # alive; historical/restart reads are instead anchored by the
        # target-owned START receipt and the immutable content-addressed
        # sidecar. Never use the mutable "current" gate to verify an older
        # call, because a later call may install different trust inputs.
        self._physical_gate_verifiers: dict[str, PhysicalMotionProviderGate] = {}
        self._physical_gate_verifiers_lock = threading.Lock()
        if (physical_worker_store is None) != (physical_gate_receipt_store is None):
            raise ValueError("physical worker and gate stores must be configured together")
        if physical_acceptance_receipt_store is not None and physical_worker_store is None:
            raise ValueError(
                "physical acceptance store requires physical worker and gate stores"
            )
        self.physical_worker_store = physical_worker_store
        self.physical_gate_receipt_store = physical_gate_receipt_store
        self.physical_acceptance_receipt_store = physical_acceptance_receipt_store

    def health(self) -> TargetdHealth:
        capability_digest = canonical_json_sha256({"protocol": "rolo-targetd/v1", "frames": sorted(item.value for item in FrameKind)})
        try:
            session_ids = self._session_ids()
        except ProtocolError:
            # Corrupt or unreadable persisted state must never be reported as
            # healthy: admission callers use this status before handing a
            # physical call to the provider.
            return TargetdHealth(
                status="UNAVAILABLE",
                target_id=self.target_id,
                capability_digest=capability_digest,
                active_sessions=0,
            )
        active = 0
        for session_id in session_ids:
            try:
                session = self.state.load_session(session_id)
            except (KeyError, ProtocolError):
                continue
            if not session.closed and session.expires_at > datetime.now(timezone.utc):
                active += 1
        return TargetdHealth(
            status="HEALTHY",
            target_id=self.target_id,
            capability_digest=capability_digest,
            active_sessions=active,
        )

    def open_session(self, session: JourneySession) -> JourneySession:
        if session.target_id != self.target_id:
            raise ProtocolError("journey session target does not match targetd")
        return self.state.create_session(session)

    def resume_session(self, session_id: str, resume_token: str) -> JourneySession:
        session = self.state.load_session(session_id)
        now = datetime.now(timezone.utc)
        if session.closed or session.expires_at <= now:
            raise ProtocolError("journey session is closed or expired")
        if not self._constant_time_equal(session.resume_token, resume_token):
            raise ProtocolError("journey session resume token mismatch")
        return session

    def has_bundle(self, bundle_digest: str) -> bool:
        return self.cache.has(bundle_digest)

    def put_bundle(self, manifest: ExecutionBundleManifest, source: bytes) -> None:
        verification_key = self.verification_keys.get(manifest.signer_key_id, self.signing_key)
        if verification_key is not None:
            manifest.verify_signature(verification_key)
        elif self.verification_keys:
            raise ProtocolError("TARGETD_BUNDLE_SIGNER_UNTRUSTED")
        self.cache.put(manifest, source)

    def provision_verified_release(
        self,
        request: TargetdVerifiedReleaseProvisionRequest,
        *,
        session_id: str,
        provider_id: str,
        verified_inputs: Mapping[str, object],
    ) -> TargetdReleaseHead:
        """CAS a Release only from targetd-reloaded conformance inputs."""

        request = TargetdVerifiedReleaseProvisionRequest.model_validate(request.model_dump(mode="python"))
        if self.release_catalog is None or self.admission_gate is None:
            raise ProtocolError("TARGETD_VERIFIED_RELEASE_PROVISION_UNAVAILABLE")
        session = self._require_execution_session(session_id)
        try:
            candidate = ToolRelease.model_validate(request.candidate_release.model_dump(mode="python"))
        except ValueError as exc:
            raise ProtocolError("TARGETD_VERIFIED_RELEASE_CANDIDATE_INVALID") from exc
        if tool_release_digest(candidate) != request.release_digest:
            raise ProtocolError("TARGETD_VERIFIED_RELEASE_DIGEST_MISMATCH")
        if candidate.mhs_manifest_digests or candidate.route_digest is not None or candidate.status != "PUBLISHED" or not candidate.agent_callable:
            raise ProtocolError("TARGETD_RELEASE_UNVERIFIED_OPTIONAL_LINEAGE")
        try:
            mapping_admission = MappingAdmissionIdentity.model_validate(verified_inputs["mapping_admission"])
            expected = ToolRelease(
                tool_id=str(verified_inputs["tool_id"]),
                target_id=str(verified_inputs["target_id"]),
                operation_kind=str(verified_inputs["operation_kind"]),
                dsl_digest=str(verified_inputs["dsl_digest"]),
                ir_digest=str(verified_inputs["ir_digest"]),
                probe_evidence_digest=str(verified_inputs["evidence_digest"]),
                mhs_manifest_digests=(),
                compiler_version=str(verified_inputs["compiler_version"]),
                generated_bundle_digest=str(verified_inputs["bundle_digest"]),
                conformance_digest=str(verified_inputs["conformance_digest"]),
                target_fingerprint=str(verified_inputs["target_fingerprint"]),
                compile_context_digest=str(verified_inputs["context_digest"]),
                route_digest=None,
                target_conformance_digest=str(verified_inputs["target_conformance_digest"]),
                mapping_confirmation_receipt_digest=str(verified_inputs["mapping_confirmation_receipt_digest"]),
                mapping_admission=mapping_admission,
                status="PUBLISHED",
                agent_callable=True,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError("TARGETD_VERIFIED_RELEASE_INPUTS_INVALID") from exc
        if candidate != expected or tool_release_digest(expected) != request.release_digest:
            raise ProtocolError("TARGETD_VERIFIED_RELEASE_IDENTITY_MISMATCH")
        if mapping_admission.journey_session_id != session.session_id or expected.target_id != self.target_id or mapping_admission.target_id != self.target_id:
            raise ProtocolError("TARGETD_VERIFIED_RELEASE_SESSION_MISMATCH")

        manifest, _ = self.cache.load(request.execution_bundle_digest)
        self._verify_cached_manifest_signature(manifest)
        contract = manifest.observation_contract
        if (
            manifest.tool_id != expected.tool_id
            or manifest.release_version != request.release_digest
            or contract.get("generated_bundle_digest") != expected.generated_bundle_digest
            or contract.get("provider") != provider_id
            or contract.get("operation") not in mapping_admission.scope.operations
            or not isinstance(contract.get("mode"), str)
            or not contract["mode"]
        ):
            raise ProtocolError("TARGETD_EXECUTION_BUNDLE_RELEASE_MISMATCH")

        def commit() -> TargetdReleaseHead:
            return self.release_catalog.provision_verified(
                release_digest=request.release_digest,
                release=expected,
                expected_catalog_head_digest=request.expected_catalog_head_digest,
            )

        _, head = self.admission_gate.commit_if_active(
            expected.mapping_confirmation_receipt_digest or "",
            mapping_admission,
            commit,
        )
        return head

    def activate_authority(
        self,
        request: TargetdAuthorityActivationRequest,
        *,
        session_id: str,
        provider_id: str,
    ) -> TargetdExecutionAuthority:
        """Activate a verified target-side Release as the current Tool head.

        Only selector digests cross the wire.  Mapping identity and Release
        lineage are reloaded from target stores; provider/operation/mode come
        from the daemon runtime and signed execution bundle; targetd chooses
        the monotonic fence epoch under the authority-store lock.
        """

        request = TargetdAuthorityActivationRequest.model_validate(request.model_dump(mode="python"))
        if self.release_catalog is None or self.execution_authority_store is None or self.admission_gate is None:
            raise ProtocolError("TARGETD_AUTHORITY_ACTIVATION_UNAVAILABLE")
        session = self._require_execution_session(session_id)
        head = self.release_catalog.resolve_current(request.tool_id)
        if head.release_digest != request.release_digest:
            raise ProtocolError("TARGETD_VERIFIED_RELEASE_NOT_CURRENT")
        release = head.release
        lineage = release.mapping_admission
        assert lineage is not None
        receipt_digest = release.mapping_confirmation_receipt_digest
        assert receipt_digest is not None
        if (
            release.target_id != self.target_id
            or lineage.target_id != self.target_id
            or lineage.journey_session_id != session.session_id
            or release.target_fingerprint != lineage.target_fingerprint
            or release.compile_context_digest != lineage.context_digest
            or release.operation_kind != lineage.scope.operation_kind.value
            or release.tool_id != lineage.scope.tool_id
        ):
            raise ProtocolError("TARGETD_VERIFIED_RELEASE_IDENTITY_MISMATCH")

        manifest, _ = self.cache.load(request.bundle_digest)
        self._verify_cached_manifest_signature(manifest)
        contract = manifest.observation_contract
        provider_operation = contract.get("operation")
        mode = contract.get("mode")
        if (
            manifest.tool_id != release.tool_id
            or manifest.release_version != head.release_digest
            or contract.get("generated_bundle_digest") != release.generated_bundle_digest
            or contract.get("provider") != provider_id
            or not isinstance(provider_operation, str)
            or not isinstance(mode, str)
            or not mode
        ):
            raise ProtocolError("TARGETD_EXECUTION_BUNDLE_RELEASE_MISMATCH")

        def build(epoch: int) -> TargetdExecutionAuthority:
            return TargetdExecutionAuthority.build(
                tool_id=release.tool_id,
                target_id=self.target_id,
                target_fingerprint=release.target_fingerprint,
                bundle_digest=manifest.bundle_digest,
                binding_digest=manifest.binding_digest,
                surface_digest=session.surface_digest or "",
                release_digest=head.release_digest,
                context_digest=lineage.context_digest,
                mapping_confirmation_receipt_digest=receipt_digest,
                mapping_admission=lineage,
                catalog_head_digest=head.catalog_head_digest,
                provider_id=provider_id,
                provider_operation=provider_operation,
                mode=mode,
                fence_epoch=epoch,
            )

        def activate_current() -> TargetdExecutionAuthority:
            activated = self.release_catalog.commit_if_current(
                head,
                lambda: self.execution_authority_store.activate(
                    request.tool_id,
                    expected_current_head_digest=request.expected_current_authority_head_digest,
                    build=build,
                ),
            )
            assert isinstance(activated, TargetdExecutionAuthority)
            return activated

        _, activated = self.admission_gate.commit_if_active(
            receipt_digest,
            lineage,
            activate_current,
        )
        return activated

    def cancel_mapping(
        self,
        request: TargetdMappingCancelRequest,
        *,
        session_id: str,
    ) -> MappingConfirmationReceipt:
        """Append a target-authored cancel for the current Mapping receipt."""

        request = TargetdMappingCancelRequest.model_validate(request.model_dump(mode="python"))
        if self.confirmation_store is None or self.execution_authority_store is None:
            raise ProtocolError("TARGETD_MAPPING_CANCEL_UNAVAILABLE")
        if isinstance(self.confirmation_store, ProductionMappingConfirmationStore):
            # The v1 target-authored request carries no operator assertion or
            # signed ACL decision.  Never downgrade a production store to its
            # legacy actor_id cancellation shape.
            raise ProtocolError("TARGETD_SIGNED_MAPPING_CANCEL_REQUIRED")
        session = self._require_execution_session(session_id)
        authority = self.execution_authority_store.resolve(request.tool_id)
        if (
            authority.authority_head_digest != request.authority_head_digest
            or authority.mapping_confirmation_receipt_digest != request.mapping_confirmation_receipt_digest
            or authority.mapping_admission.journey_session_id != session.session_id
            or authority.target_id != self.target_id
        ):
            raise ProtocolError("TARGETD_MAPPING_CANCEL_HEAD_MISMATCH")
        # The wire idempotency key is correlation only.  The target derives
        # both the durable decision id and actor identity itself.
        decision_material = {
            "schema_version": request.schema_version,
            "session_id": session.session_id,
            "tool_id": request.tool_id,
            "authority_head_digest": request.authority_head_digest,
            "mapping_confirmation_receipt_digest": request.mapping_confirmation_receipt_digest,
            "idempotency_key": request.idempotency_key,
        }
        decision_id = "targetd-cancel-" + canonical_json_sha256(decision_material)[:48]

        def require_current_head() -> None:
            self.execution_authority_store.commit_if_current(
                authority,
                lambda: None,
            )

        return self.confirmation_store.cancel(
            authority.mapping_confirmation_receipt_digest,
            decision_id=decision_id,
            actor_id=f"targetd:{self.target_id}",
            guard=require_current_head,
        )

    def accept_call(
        self,
        request: ExecutionRequestLike,
        manifest: ExecutionBundleManifest,
        *,
        provider_id: str,
        preserve_active_process: bool = False,
    ) -> TargetdCallReceipt:
        return self._accept_call(
            request,
            manifest,
            provider_id=provider_id,
            preserve_active_process=preserve_active_process,
            defer_physical_gate=False,
        )

    def prepare_physical_process_call(
        self,
        request: ExecutionRequestLike,
        manifest: ExecutionBundleManifest,
        *,
        provider_id: str,
    ) -> TargetdCallReceipt:
        """Persist ACCEPTED for one sealed worker before its zero-only ARM."""

        try:
            from .physical_worker import validate_landerpi_rotate_process_call

            request, manifest = validate_landerpi_rotate_process_call(
                request,
                manifest,
            )
        except Exception as exc:
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_REQUEST_REQUIRED") from exc
        if provider_id != "ros-container":
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_REQUEST_REQUIRED")
        return self._accept_call(
            request,
            manifest,
            provider_id=provider_id,
            preserve_active_process=True,
            defer_physical_gate=True,
        )

    def _accept_call(
        self,
        request: ExecutionRequestLike,
        manifest: ExecutionBundleManifest,
        *,
        provider_id: str,
        preserve_active_process: bool,
        defer_physical_gate: bool,
    ) -> TargetdCallReceipt:
        request = validate_execution_request(request)
        manifest = ExecutionBundleManifest.model_validate(manifest.model_dump(mode="python"))
        request_digest = request.request_digest()
        existing = self.state.load_receipt(request.session_id, request.idempotency_key)
        if existing is not None:
            if existing.request_digest != request_digest:
                raise ProtocolError("idempotency key was reused with different call identity")
            if existing.status in {"ACCEPTED", "STARTED"}:
                if preserve_active_process:
                    # The process coordinator must still reconcile the exact
                    # durable lease; this flag alone never authorizes replay.
                    self._require_authorized(
                        request,
                        manifest,
                        provider_id=provider_id,
                        defer_physical_gate=defer_physical_gate,
                    )
                    return existing
                # targetd may have accepted or started the physical operation
                # before its controller disconnected. Re-submitting the CALL
                # must never execute it a second time; force an explicit
                # reconciliation/query path instead.
                return self.complete_call(
                    request.session_id,
                    request.idempotency_key,
                    status="UNKNOWN",
                    result={"error": "CALL_RECONCILIATION_REQUIRED"},
                )
            return existing
        authority = self._require_authorized(
            request,
            manifest,
            provider_id=provider_id,
            defer_physical_gate=defer_physical_gate,
        )
        receipt = TargetdCallReceipt(
            schema_version="rolo-targetd-call-receipt/v2",
            idempotency_key=request.idempotency_key,
            session_id=request.session_id,
            target_id=request.target_id,
            bundle_digest=request.bundle_digest,
            request_digest=request_digest,
            release_digest=request.release_digest,
            context_digest=request.context_digest,
            mapping_confirmation_receipt_digest=request.mapping_confirmation_receipt_digest,
            authority_head_digest=request.authority_head_digest,
            fence_epoch=request.fence_epoch,
            provider_id=request.provider_id,
            provider_operation=request.provider_operation,
            provider_fence_digest=provider_fence_digest(request),
            status="ACCEPTED",
            updated_at=datetime.now(timezone.utc),
        )
        return self._commit_authorized(
            authority,
            lambda: self.state.update_receipt(
                request.session_id,
                request.idempotency_key,
                lambda current: self._accept_transition(current, receipt),
            ),
        )

    def start_call(
        self,
        request: ExecutionRequestLike,
        manifest: ExecutionBundleManifest,
        *,
        provider_id: str,
    ) -> TargetdCallReceipt:
        """Persist the worker-start boundary before provider execution."""

        request = validate_execution_request(request)
        if requires_motion_safety(request.authority):
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_WORKER_REQUIRED")
        manifest = ExecutionBundleManifest.model_validate(manifest.model_dump(mode="python"))
        authority = self._require_authorized(request, manifest, provider_id=provider_id)
        return self._commit_authorized(
            authority,
            lambda: self.state.update_receipt(
                request.session_id,
                request.idempotency_key,
                lambda receipt: self._start_transition(receipt, request),
            ),
        )

    def execute_provider(
        self,
        request: ExecutionRequestLike,
        manifest: ExecutionBundleManifest,
        *,
        provider_id: str,
        execute: Callable[[], tuple[str, dict]],
    ) -> TargetdCallReceipt:
        """Execute once behind Mapping, current-head, and target state locks.

        The callback is the lowest provider side-effect boundary.  Mapping
        cancellation, current Release promotion and target CANCEL are ordered
        against it, so a cancellation/head change that wins first yields zero
        provider calls.  A crash after STARTED is reconciled as UNKNOWN and is
        never replayed automatically.
        """

        manifest = ExecutionBundleManifest.model_validate(manifest.model_dump(mode="python"))
        try:
            request = validate_execution_request(request)
            authority = self._require_authorized(request, manifest, provider_id=provider_id)
            return self._commit_authorized(
                authority,
                lambda: self.state.update_receipt(
                    request.session_id,
                    request.idempotency_key,
                    lambda receipt: self._provider_transition(
                        receipt,
                        request,
                        authority,
                        execute,
                    ),
                ),
            )
        except (KeyError, MappingAdmissionError, ProtocolError, TimeoutError) as exc:
            return self._reject_before_provider(request, str(exc))

    def complete_call(
        self,
        session_id: str,
        idempotency_key: str,
        *,
        status: Literal["SUCCEEDED", "FAILED", "STOPPED", "CANCELLED", "UNKNOWN", "NOT_ACCEPTED"],
        result: dict | None = None,
        evidence_refs: list[str] | None = None,
        artifact_refs: list[str] | None = None,
    ) -> TargetdCallReceipt:
        if status == "SUCCEEDED":
            raise ProtocolError("successful completion requires the fenced provider boundary")

        def transition(receipt: TargetdCallReceipt | None) -> TargetdCallReceipt:
            if receipt is not None and self._is_physical_process_receipt(receipt):
                raise ProtocolError("TARGETD_PHYSICAL_PROCESS_COMMIT_REQUIRED")
            return self._complete_transition(
                receipt,
                status=status,
                result=result,
                evidence_refs=evidence_refs,
                artifact_refs=artifact_refs,
            )

        return self.state.update_receipt(
            session_id,
            idempotency_key,
            transition,
        )

    def cancel_call(self, session_id: str, idempotency_key: str) -> TargetdCallReceipt:
        def transition(receipt: TargetdCallReceipt | None) -> TargetdCallReceipt:
            if receipt is not None and self._is_physical_process_receipt(receipt):
                raise ProtocolError("TARGETD_PHYSICAL_PROCESS_CONTROL_REQUIRED")
            return self._complete_transition(
                receipt,
                status="CANCELLED",
                result={"code": "CALL_CANCELLED"},
            )

        return self.state.update_receipt(
            session_id,
            idempotency_key,
            transition,
        )

    def query_call(self, session_id: str, idempotency_key: str) -> TargetdCallReceipt | None:
        receipt = self.state.load_receipt(session_id, idempotency_key)
        if receipt is not None and receipt.status in {"ACCEPTED", "STARTED"} and self._is_physical_process_receipt(receipt):
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_QUERY_REQUIRED")
        if receipt is None or receipt.status not in {"ACCEPTED", "STARTED"}:
            return receipt
        # A new daemon cannot prove whether a crashed worker crossed its
        # provider boundary. QUERY is the explicit reconciliation path and
        # therefore terminalizes persisted in-flight state as UNKNOWN.
        return self.state.update_receipt(
            session_id,
            idempotency_key,
            lambda current: (
                current.model_copy(
                    update={
                        "status": "UNKNOWN",
                        "result": {"error": "CALL_RECONCILIATION_REQUIRED"},
                        "updated_at": datetime.now(timezone.utc),
                    }
                )
                if current is not None and current.status in {"ACCEPTED", "STARTED"}
                else self._require_current_receipt(current)
            ),
        )

    def _commit_authorized(
        self,
        authority: TargetdExecutionAuthority,
        commit: Callable[[], TargetdCallReceipt],
    ) -> TargetdCallReceipt:
        """Linearize a boundary against Mapping cancel and head promotion."""

        if self.admission_gate is None or self.execution_authority_store is None:
            raise ProtocolError("TARGETD_EXECUTION_ADMISSION_REQUIRED")

        def commit_current() -> TargetdCallReceipt:
            if self.release_catalog is None:
                return self.execution_authority_store.commit_if_current(
                    authority,
                    commit,
                )
            release_head = self.release_catalog.require_authority_current(authority)
            committed = self.release_catalog.commit_if_current(
                release_head,
                lambda: self.execution_authority_store.commit_if_current(
                    authority,
                    commit,
                ),
            )
            assert isinstance(committed, TargetdCallReceipt)
            return committed

        _, result = self.admission_gate.commit_if_active(
            authority.mapping_confirmation_receipt_digest,
            authority.mapping_admission,
            commit_current,
        )
        return result

    def _require_authorized(
        self,
        request: ExecutionRequestLike,
        manifest: ExecutionBundleManifest,
        *,
        provider_id: str,
        defer_physical_gate: bool = False,
    ) -> TargetdExecutionAuthority:
        if self.execution_authority_store is None:
            raise ProtocolError("TARGETD_EXECUTION_AUTHORITY_STORE_REQUIRED")
        if self.admission_gate is None:
            raise ProtocolError("MAPPING_CONFIRMATION_STORE_REQUIRED")
        try:
            authority = self.execution_authority_store.resolve(manifest.tool_id)
        except KeyError as exc:
            raise ProtocolError("TARGETD_CURRENT_RELEASE_REQUIRED") from exc
        if authority != request.authority:
            raise ProtocolError("EXECUTION_AUTHORITY_HEAD_STALE")
        if self.release_catalog is not None:
            self.release_catalog.require_authority_current(authority)
        if request.deadline <= datetime.now(timezone.utc):
            raise ProtocolError("execution request deadline has expired")
        session = self._require_execution_session(request.session_id)
        if request.target_id != self.target_id or session.target_id != request.target_id:
            raise ProtocolError("execution request target does not match targetd")
        if request.bundle_digest != manifest.bundle_digest:
            raise ProtocolError("execution request bundle does not match manifest")
        if request.binding_digest != manifest.binding_digest:
            raise ProtocolError("execution request binding does not match manifest")
        if request.surface_digest != session.surface_digest:
            raise ProtocolError("execution request surface does not match journey session")
        if manifest.tool_id != authority.tool_id:
            raise ProtocolError("execution bundle tool does not match current authority")
        if provider_id != request.provider_id:
            raise ProtocolError("execution provider does not match targetd runtime")
        scope = authority.mapping_admission.scope
        if scope.operation_kind.value == "OBSERVE":
            if scope.access != "read" or scope.risk != "R0" or request.provider_id != "ros2-readonly":
                raise ProtocolError("TARGETD_READ_ONLY_PROVIDER_REQUIRED")
        elif scope.operation_kind.value != "EXECUTE" or scope.access != "experimental_write" or scope.risk != "R3" or request.provider_id == "ros2-readonly":
            raise ProtocolError("TARGETD_EXECUTION_SCOPE_UNDERDECLARED")
        contract = manifest.observation_contract
        if request.provider_id == "targetd-python":
            if contract.get("provider") not in (None, "targetd-python"):
                raise ProtocolError("bundle provider contract does not match targetd runtime")
        elif contract.get("provider") != request.provider_id or contract.get("operation") != request.provider_operation:
            raise ProtocolError("bundle provider contract does not match execution authority")
        if manifest.tool_id == "app.mapping.status" and request.provider_id == "ros-container":
            raise ProtocolError("MAPPING_STATUS_PROVIDER_NOT_READ_ONLY")
        if not self.cache.has(request.bundle_digest):
            raise ProtocolError("execution bundle is not present in targetd cache")
        self.admission_gate.require_active(
            authority.mapping_confirmation_receipt_digest,
            authority.mapping_admission,
        )
        if not defer_physical_gate:
            self._require_physical_motion_execution_capability(request, authority)
        elif not requires_motion_safety(authority):
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_REQUEST_REQUIRED")
        return authority

    def start_process_call(
        self,
        request: ExecutionRequestLike,
        manifest: ExecutionBundleManifest,
        *,
        provider_id: str,
        lease_probe: Callable[[], WorkerLeaseRecord],
        live_fence: Callable[[ExecutionRequestLike, TargetdExecutionAuthority], None],
    ) -> TargetdCallReceipt:
        """Persist target-owned START only behind a live lease/fence callback."""

        request, manifest = validate_sealed_odom_r0_call(request, manifest)
        if not callable(lease_probe) or not callable(live_fence):
            raise ProtocolError("TARGETD_PROCESS_START_FENCE_REQUIRED")
        authority = self._require_authorized(request, manifest, provider_id=provider_id)
        call_key = WorkerCallKey.from_request(request)

        def transition(receipt: TargetdCallReceipt | None) -> TargetdCallReceipt:
            self._require_receipt_identity(receipt, request)
            assert receipt is not None
            if receipt.status != "ACCEPTED":
                return receipt

            def require_live_lease() -> WorkerLeaseRecord:
                lease = lease_probe()
                if (
                    lease.call_key != call_key
                    or lease.call_key_digest != call_key.digest()
                    or lease.state != "RUNNING"
                    or lease.provider_started_at is None
                    or datetime.now(timezone.utc) >= lease.expires_at
                ):
                    raise ProtocolError("TARGETD_PROCESS_WORKER_LEASE_NOT_LIVE")
                return lease

            require_live_lease()
            # The callback may block on a live graph observation/CAS. Probe
            # the durable lease both before and after it; an expired worker or
            # daemon reincarnation must never receive START on stale evidence.
            live_fence(request, authority)
            require_live_lease()
            now = datetime.now(timezone.utc)
            if now >= request.deadline:
                raise ProtocolError("TARGETD_PROCESS_START_DEADLINE_EXPIRED")
            if receipt.updated_at > now:
                # A wall-clock rollback makes receipt/lease ordering
                # unverifiable even if the monotonic child heartbeat is live.
                raise ProtocolError("TARGETD_PROCESS_WORKER_LEASE_NOT_LIVE")
            # This callback executes while Mapping/current-authority/Release
            # and target receipt locks are held. A future motion adapter may
            # consume only a final target acceptance receipt that binds the
            # live command/feedback route identities; a static safety
            # decision is not accepted here. Physical requests remain blocked
            # earlier by _require_physical_motion_execution_capability.
            return receipt.model_copy(
                update={
                    "status": "STARTED",
                    "provider_started_at": now,
                    "updated_at": now,
                }
            )

        return self._commit_authorized(
            authority,
            lambda: self.state.update_receipt(
                request.session_id,
                request.idempotency_key,
                transition,
            ),
        )

    def commit_process_result(
        self,
        call_key: WorkerCallKey,
        lease: WorkerLeaseRecord,
    ) -> TargetdCallReceipt:
        """Commit a durable prepared worker result, or reconcile UNKNOWN."""

        return self._commit_leased_process_result(
            call_key,
            lease,
            provider_id="ros2-readonly",
            provider_operation="odom.sample",
            physical=False,
        )

    def commit_physical_process_result(
        self,
        call_key: WorkerCallKey,
        lease: WorkerLeaseRecord,
    ) -> TargetdCallReceipt:
        """Commit only a sealed rotation worker's durable terminal proof."""

        return self._commit_leased_process_result(
            call_key,
            lease,
            provider_id="ros-container",
            provider_operation="base.rotate",
            physical=True,
        )

    def mark_physical_process_unknown(
        self,
        call_key: WorkerCallKey,
        *,
        outcome_code: str,
    ) -> TargetdCallReceipt:
        """Fail closed when PREPARE cannot establish any durable worker lease."""

        call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", outcome_code) is None:
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_OUTCOME_INVALID")

        def transition(receipt: TargetdCallReceipt | None) -> TargetdCallReceipt:
            if (
                receipt is None
                or not self._is_physical_process_receipt(receipt)
                or receipt.target_id != call_key.target_id
                or receipt.session_id != call_key.session_id
                or receipt.idempotency_key != call_key.idempotency_key
                or receipt.request_digest != call_key.request_digest
            ):
                raise ProtocolError("TARGETD_PHYSICAL_PROCESS_RECEIPT_IDENTITY_MISMATCH")
            return self._complete_transition(
                receipt,
                status="UNKNOWN",
                result={"error": outcome_code},
            )

        return self.state.update_receipt(
            call_key.session_id,
            call_key.idempotency_key,
            transition,
        )

    def revalidate_physical_process_terminal(
        self,
        call_key: WorkerCallKey,
        lease: WorkerLeaseRecord,
    ) -> TargetdCallReceipt:
        """Return ALREADY_TERMINAL eligibility only with full durable proof."""

        call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
        lease = WorkerLeaseRecord.model_validate(lease.model_dump(mode="python"))
        receipt = self.commit_physical_process_result(call_key, lease)
        if receipt.status not in {"SUCCEEDED", "FAILED", "STOPPED", "CANCELLED"}:
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_TERMINAL_PROOF_INVALID")
        if lease.provider_started_at is None:
            if receipt.status not in {"STOPPED", "CANCELLED"}:
                raise ProtocolError("TARGETD_PHYSICAL_PROCESS_TERMINAL_PROOF_INVALID")
            self._require_physical_prestart_interrupt_result(call_key, lease)
        else:
            self.resolve_physical_provider_gate(call_key)
            self._require_physical_terminal_result(call_key, lease)
        return receipt

    def _commit_leased_process_result(
        self,
        call_key: WorkerCallKey,
        lease: WorkerLeaseRecord,
        *,
        provider_id: str,
        provider_operation: str,
        physical: bool,
    ) -> TargetdCallReceipt:
        """Commit one exact prepared result without broadening provider scope."""

        call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
        lease = WorkerLeaseRecord.model_validate(lease.model_dump(mode="python"))
        if lease.call_key != call_key or lease.call_key_digest != call_key.digest():
            raise ProtocolError("TARGETD_PROCESS_RESULT_CALL_IDENTITY_MISMATCH")

        observed = self.state.load_receipt(
            call_key.session_id,
            call_key.idempotency_key,
        )
        if observed is None:
            raise ProtocolError("TARGETD_PROCESS_RESULT_RECEIPT_MISSING")
        physical_gate_reference: PhysicalProviderGateReference | None = None
        if physical and observed.status != "ACCEPTED":
            # Every post-START terminal result remains anchored to the exact
            # durable one-shot gate. Historical validation uses persisted_at,
            # not the current wall clock.
            physical_gate_reference = self.resolve_physical_provider_gate(call_key)
            if lease.armed_zero != physical_gate_reference.sidecar.armed_zero:
                raise ProtocolError("TARGETD_PHYSICAL_PROCESS_ARM_IDENTITY_MISMATCH")

        def transition(receipt: TargetdCallReceipt | None) -> TargetdCallReceipt:
            if receipt is None:
                raise ProtocolError("TARGETD_PROCESS_RESULT_RECEIPT_MISSING")
            if (
                receipt.target_id != call_key.target_id
                or receipt.session_id != call_key.session_id
                or receipt.idempotency_key != call_key.idempotency_key
                or receipt.request_digest != call_key.request_digest
                or receipt.provider_id != provider_id
                or receipt.provider_operation != provider_operation
            ):
                raise ProtocolError("TARGETD_PROCESS_RESULT_RECEIPT_IDENTITY_MISMATCH")
            terminal = {
                "SUCCEEDED",
                "FAILED",
                "STOPPED",
                "CANCELLED",
                "UNKNOWN",
                "NOT_ACCEPTED",
            }
            if receipt.status in terminal:
                if receipt.status == "UNKNOWN":
                    return receipt
                if receipt.status == lease.state:
                    if (
                        lease.prepared_status == lease.state
                        and lease.prepared_outcome_code == lease.outcome_code
                        and lease.prepared_result is not None
                        and lease.prepared_result_digest is not None
                        and lease.result_prepared_at is not None
                        and receipt.result == lease.prepared_result
                    ):
                        return receipt
                    raise ProtocolError("TARGETD_PROCESS_RESULT_TERMINAL_MISMATCH")
                raise ProtocolError("TARGETD_PROCESS_RESULT_TERMINAL_MISMATCH")
            if lease.state in {"CLAIMED", "RUNNING", "CANCEL_REQUESTED", "STOP_REQUESTED"}:
                return receipt
            if lease.state == "UNKNOWN":
                return self._complete_transition(
                    receipt,
                    status="UNKNOWN",
                    result={"error": lease.outcome_code or "WORKER_RESULT_RECONCILIATION_REQUIRED"},
                )
            if receipt.status != "STARTED":
                if (
                    physical
                    and receipt.status == "ACCEPTED"
                    and lease.state in {"STOPPED", "CANCELLED"}
                    and self._require_physical_prestart_interrupt_result(
                        call_key,
                        lease,
                    )
                ):
                    return self._complete_transition(
                        receipt,
                        status=lease.state,
                        result=dict(lease.prepared_result or {}),
                    )
                return self._complete_transition(
                    receipt,
                    status="UNKNOWN",
                    result={"error": "TARGETD_PROCESS_START_RECEIPT_MISSING"},
                )
            if (
                lease.prepared_status != lease.state
                or lease.prepared_outcome_code != lease.outcome_code
                or lease.prepared_result is None
                or lease.prepared_result_digest is None
                or lease.result_prepared_at is None
            ):
                return self._complete_transition(
                    receipt,
                    status="UNKNOWN",
                    result={"error": "TARGETD_PROCESS_RESULT_PREPARE_MISSING"},
                )
            if physical:
                self._require_physical_terminal_result(call_key, lease)
            return self._complete_transition(
                receipt,
                status=lease.state,
                result=dict(lease.prepared_result),
            )

        return self.state.update_receipt(
            call_key.session_id,
            call_key.idempotency_key,
            transition,
        )

    @staticmethod
    def _require_physical_prestart_interrupt_result(
        call_key: WorkerCallKey,
        lease: WorkerLeaseRecord,
    ) -> bool:
        result = lease.prepared_result
        armed_zero = lease.armed_zero
        acknowledgement = lease.stop_acknowledgement
        if (
            result is None
            or not isinstance(armed_zero, Mapping)
            or acknowledgement is None
            or acknowledgement.call_key != call_key
            or result.get("worker_call_key_digest") != call_key.digest()
            or result.get("request_digest") != call_key.request_digest
            or not _safe_digest_equal(
                result.get("armed_zero_receipt_digest"),
                armed_zero.get("arm_receipt_digest"),
            )
            or result.get("runtime_sha256") != armed_zero.get("runtime_sha256")
            or result.get("provider_runtime_sha256") != armed_zero.get("provider_runtime_sha256")
            or result.get("provider_cmdline_sha256") != armed_zero.get("provider_cmdline_sha256")
            or result.get("provider_runtime_identity_digest") != armed_zero.get("provider_runtime_identity_digest")
            or result.get("provider_process_identity") != armed_zero.get("inner_process_identity")
            or result.get("provider_invocation_count") != 0
            or result.get("motion_started") is not False
            or result.get("motion_command_emitted") is not False
            or result.get("final_zero_verified") is not True
            or result.get("stop_acknowledged") is not True
        ):
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_TERMINAL_PROOF_INVALID")
        return True

    @staticmethod
    def _require_physical_terminal_result(
        call_key: WorkerCallKey,
        lease: WorkerLeaseRecord,
    ) -> None:
        result = lease.prepared_result
        armed_zero = lease.armed_zero
        if (
            result is None
            or not isinstance(armed_zero, Mapping)
            or result.get("worker_call_key_digest") != call_key.digest()
            or result.get("request_digest") != call_key.request_digest
            or not _safe_digest_equal(
                result.get("armed_zero_receipt_digest"),
                armed_zero.get("arm_receipt_digest"),
            )
            or result.get("runtime_sha256") != armed_zero.get("runtime_sha256")
            or result.get("provider_runtime_sha256") != armed_zero.get("provider_runtime_sha256")
            or result.get("provider_cmdline_sha256") != armed_zero.get("provider_cmdline_sha256")
            or result.get("provider_runtime_identity_digest") != armed_zero.get("provider_runtime_identity_digest")
            or result.get("provider_process_identity") != armed_zero.get("inner_process_identity")
            or result.get("final_zero_verified") is not True
            or result.get("stop_acknowledged") is not True
        ):
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_TERMINAL_PROOF_INVALID")
        if lease.state in {"STOPPED", "CANCELLED"}:
            acknowledgement = lease.stop_acknowledgement
            result_ack = result.get("stop_acknowledgement")
            if (
                result.get("provider_invocation_count") not in {0, 1}
                or (result.get("provider_invocation_count") == 0 and (result.get("motion_started") is not False or result.get("motion_command_emitted") is not False))
                or acknowledgement is None
                or acknowledgement.call_key != call_key
                or not isinstance(result_ack, Mapping)
                or result_ack.get("call_key_digest") != call_key.digest()
                or result_ack.get("inner_process_gone") is not True
                or result_ack.get("verified") is not True
            ):
                raise ProtocolError("TARGETD_PHYSICAL_PROCESS_TERMINAL_PROOF_INVALID")
        elif result.get("provider_invocation_count") != 1:
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_TERMINAL_PROOF_INVALID")

    def start_physical_process_call(
        self,
        request: ExecutionRequestLike,
        manifest: ExecutionBundleManifest,
        *,
        provider_id: str,
        lease_claim: WorkerLeaseClaim,
        armed_zero: object,
    ) -> TargetdPhysicalProcessStart:
        """Consume the final target gate immediately before process START.

        This method does not execute a provider. It is intended only as the
        ``start_gate`` of an isolated duplex process runtime. The ordinary
        synchronous daemon path remains unable to execute physical calls.
        """

        try:
            from .physical_worker import (
                PhysicalWorkerArmedZero,
                validate_landerpi_rotate_process_call,
            )

            request, manifest = validate_landerpi_rotate_process_call(
                request,
                manifest,
            )
        except Exception as exc:
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_REQUEST_REQUIRED") from exc
        if not isinstance(request, ExecutionRequestV3) or not requires_motion_safety(request.authority) or provider_id != "ros-container" or not isinstance(armed_zero, PhysicalWorkerArmedZero):
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_REQUEST_REQUIRED")
        if not isinstance(lease_claim, WorkerLeaseClaim):
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_LEASE_REQUIRED")
        authority = self._require_authorized(
            request,
            manifest,
            provider_id=provider_id,
        )
        gate = self.physical_motion_gate
        worker_store = self.physical_worker_store
        gate_receipt_store = self.physical_gate_receipt_store
        if gate is None or worker_store is None or gate_receipt_store is None:
            raise ProtocolError("TARGETD_PHYSICAL_MOTION_EXECUTION_UNAVAILABLE")
        call_key = WorkerCallKey.from_request(request)
        if lease_claim.lease.call_key != call_key:
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_LEASE_IDENTITY_MISMATCH")
        self._require_physical_armed_zero(
            armed_zero,
            request,
            manifest,
            lease_claim,
        )
        consumed: PhysicalProviderGateReceipt | None = None

        def require_live_lease() -> WorkerLeaseRecord:
            try:
                # heartbeat authenticates the non-persisted lease token,
                # generation, worker and runtime incarnation against the
                # TargetdService-owned store.
                lease = worker_store.heartbeat(lease_claim)
            except ProtocolError as exc:
                raise ProtocolError("TARGETD_PHYSICAL_PROCESS_WORKER_LEASE_NOT_LIVE") from exc
            if (
                lease.call_key != call_key
                or lease.call_key_digest != call_key.digest()
                or lease.state != "RUNNING"
                or lease.provider_started_at is None
                or datetime.now(timezone.utc) >= lease.expires_at
                or lease.armed_zero != armed_zero.as_dict()
                or lease.armed_zero_digest is None
                or lease.armed_at is None
            ):
                raise ProtocolError("TARGETD_PHYSICAL_PROCESS_WORKER_LEASE_NOT_LIVE")
            return lease

        def transition(receipt: TargetdCallReceipt | None) -> TargetdCallReceipt:
            nonlocal consumed
            self._require_receipt_identity(receipt, request)
            assert receipt is not None
            if receipt.status != "ACCEPTED":
                raise ProtocolError("TARGETD_PHYSICAL_PROCESS_RECEIPT_NOT_ACCEPTED")
            require_live_lease()
            if isinstance(gate, DebugUserAttestedPhysicalProviderGate):
                accepted = self.resolve_debug_physical_acceptance(call_key)
                if (
                    gate.acceptance_receipt
                    != accepted.sidecar.acceptance_receipt
                    or gate.admission != accepted.sidecar.debug_admission
                    or accepted.sidecar.armed_zero != armed_zero.as_dict()
                ):
                    raise ProtocolError(
                        "TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_REFERENCE_INVALID"
                    )
            elif any(
                ref.startswith(
                    "artifact://targetd/debug-physical-acceptances/"
                )
                for ref in receipt.artifact_refs
            ):
                # A persisted debug-only acceptance may only be consumed by
                # the deployment-owned gate that produced that exact signed
                # challenge.  It can never be upgraded into a production gate.
                raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_BLOCKED")
            self._bind_physical_gate_verifier(call_key, gate)
            # The READY rehearsal receipt is deliberately not sufficient.
            # This performs the target-owned fresh graph/fence CAS once,
            # inside Mapping/current-head/Release/target receipt locks.
            consumed = gate.consume(request, authority)
            self._require_consumed_physical_gate(
                consumed,
                request,
                authority,
                armed_zero,
            )
            try:
                gate.revalidate_consumption(consumed, call_key, at=datetime.now(timezone.utc))
            except Exception as exc:
                raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_BLOCKED") from exc
            require_live_lease()
            now = datetime.now(timezone.utc)
            if now >= request.deadline or receipt.updated_at > now:
                raise ProtocolError("TARGETD_PHYSICAL_PROCESS_START_TIME_INVALID")
            if consumed.challenge_artifact_digest is None or consumed.consume_artifact is None:
                raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_BLOCKED")
            if isinstance(consumed, ProviderGateConsumptionReceipt) and consumed.provider_fence_digest is None:
                raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_BLOCKED")
            # Receipt persistence is part of the START transaction's
            # precondition. A write/index failure burns the one-shot gate but
            # sends no child START and never enters a provider callback.
            reference = gate_receipt_store.persist(
                call_key,
                consumed,
                armed_zero=armed_zero,
                debug_admission=(
                    gate.admission
                    if isinstance(consumed, DebugUserAttestedProviderGateReceipt)
                    and isinstance(
                        getattr(gate, "admission", None),
                        DebugOnlyUserAttestedAdmission,
                    )
                    else None
                ),
                now=now,
            )
            # START is conditional on a content-addressed read-back, not the
            # in-memory object returned by the write call.
            try:
                durable_reference = gate_receipt_store.revalidate(reference)
                gate.revalidate_consumption(
                    durable_reference.sidecar.provider_gate,
                    call_key,
                    at=durable_reference.sidecar.persisted_at,
                )
            except Exception as exc:
                raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_INVALID") from exc
            if durable_reference.sidecar.provider_gate != consumed:
                raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_INVALID")
            evidence_refs = [
                *receipt.evidence_refs,
                durable_reference.uri,
                durable_reference.digest_uri,
            ]
            if len(evidence_refs) != len(set(evidence_refs)):
                raise ProtocolError("TARGETD_PHYSICAL_GATE_REFERENCE_MISMATCH")
            return receipt.model_copy(
                update={
                    "status": "STARTED",
                    "provider_started_at": now,
                    "updated_at": now,
                    "evidence_refs": evidence_refs,
                }
            )

        receipt = self._commit_authorized(
            authority,
            lambda: self.state.update_receipt(
                request.session_id,
                request.idempotency_key,
                transition,
            ),
        )
        if consumed is None:
            raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_BLOCKED")
        return TargetdPhysicalProcessStart(receipt=receipt, provider_gate=consumed)

    def record_debug_physical_acceptance(
        self,
        call_key: WorkerCallKey,
        reference: DebugPhysicalAcceptanceReference,
    ) -> TargetdCallReceipt:
        """Bind one durable zero-motion acceptance to its target receipt.

        This transition deliberately leaves the call ``ACCEPTED`` and does
        not write ``provider_started_at``.  The acceptance challenge remains
        closed until :meth:`start_physical_process_call` consumes it.
        """

        try:
            call_key = WorkerCallKey.model_validate(
                call_key.model_dump(mode="python")
            )
        except Exception as exc:
            raise ProtocolError(
                "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_IDENTITY_INVALID"
            ) from exc
        store = self.physical_acceptance_receipt_store
        worker_store = self.physical_worker_store
        if store is None or worker_store is None:
            raise ProtocolError("TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_UNAVAILABLE")
        try:
            durable = store.revalidate(reference)
        except ProtocolError:
            raise
        except Exception as exc:
            raise ProtocolError(
                "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_INVALID"
            ) from exc
        if durable.sidecar.call_key != call_key:
            raise ProtocolError(
                "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_IDENTITY_INVALID"
            )
        lease = worker_store.load(call_key)
        if (
            lease is None
            or lease.call_key != call_key
            or lease.armed_zero is None
            or lease.armed_zero != durable.sidecar.armed_zero
            or lease.physical_execution_subject_digest
            != durable.sidecar.debug_admission.execution_subject_digest
        ):
            raise ProtocolError("TARGETD_PHYSICAL_WORKER_ARM_NOT_LIVE")

        exact_refs = [durable.uri, durable.digest_uri]

        def transition(receipt: TargetdCallReceipt | None) -> TargetdCallReceipt:
            if (
                receipt is None
                or receipt.target_id != call_key.target_id
                or receipt.session_id != call_key.session_id
                or receipt.idempotency_key != call_key.idempotency_key
                or receipt.request_digest != call_key.request_digest
                or not self._is_physical_process_receipt(receipt)
                or receipt.provider_started_at is not None
            ):
                raise ProtocolError(
                    "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_IDENTITY_INVALID"
                )
            if receipt.status != "ACCEPTED":
                raise ProtocolError("TARGETD_PHYSICAL_PROCESS_RECEIPT_NOT_ACCEPTED")
            if receipt.artifact_refs == exact_refs:
                return receipt
            if receipt.artifact_refs:
                raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_CONFLICT")
            if durable.sidecar.persisted_at < receipt.updated_at:
                raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_TIME_INVALID")
            return receipt.model_copy(
                update={
                    "artifact_refs": exact_refs,
                    "updated_at": durable.sidecar.persisted_at,
                }
            )

        return self.state.update_receipt(
            call_key.session_id,
            call_key.idempotency_key,
            transition,
        )

    def resolve_debug_physical_acceptance(
        self,
        call_key: WorkerCallKey,
        *,
        expected_uri: str | None = None,
        expected_digest_uri: str | None = None,
    ) -> DebugPhysicalAcceptanceReference:
        """Purely read back one target-owned debug acceptance sidecar."""

        call_key = WorkerCallKey.model_validate(
            call_key.model_dump(mode="python")
        )
        receipt = self.state.load_receipt(
            call_key.session_id,
            call_key.idempotency_key,
        )
        if (
            receipt is None
            or receipt.target_id != call_key.target_id
            or receipt.request_digest != call_key.request_digest
            or not self._is_physical_process_receipt(receipt)
        ):
            raise ProtocolError("TARGETD_PHYSICAL_GATE_QUERY_CALL_MISMATCH")
        store = self.physical_acceptance_receipt_store
        if store is None:
            raise ProtocolError("TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_UNAVAILABLE")
        refs = receipt.artifact_refs
        acceptance_uris = [
            ref
            for ref in refs
            if ref.startswith(
                "artifact://targetd/debug-physical-acceptances/"
            )
        ]
        if len(acceptance_uris) != 1:
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_MISSING")
        uri = acceptance_uris[0]
        digest_hex = uri.rsplit("/", 1)[-1]
        digest_uri = f"digest://sha256/{digest_hex}"
        if refs.count(digest_uri) != 1:
            raise ProtocolError("TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_MISSING")
        if expected_uri is not None and expected_uri != uri:
            raise ProtocolError(
                "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_REFERENCE_MISMATCH"
            )
        if expected_digest_uri is not None and expected_digest_uri != digest_uri:
            raise ProtocolError(
                "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_REFERENCE_MISMATCH"
            )
        try:
            durable = store.resolve(
                uri,
                call_key=call_key,
                digest_uri=digest_uri,
            )
        except ProtocolError:
            raise
        except Exception as exc:
            raise ProtocolError(
                "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_INVALID"
            ) from exc
        lease = self.physical_worker_store.load(call_key) if self.physical_worker_store else None
        if (
            durable.sidecar.call_key != call_key
            or lease is None
            or lease.armed_zero != durable.sidecar.armed_zero
            or lease.physical_execution_subject_digest
            != durable.sidecar.debug_admission.execution_subject_digest
        ):
            raise ProtocolError(
                "TARGETD_DEBUG_PHYSICAL_ACCEPTANCE_IDENTITY_INVALID"
            )
        return durable

    def resolve_physical_provider_gate(
        self,
        call_key: WorkerCallKey,
        *,
        expected_uri: str | None = None,
        expected_digest_uri: str | None = None,
    ) -> PhysicalProviderGateReference:
        """Read back and revalidate one physical provider gate sidecar."""

        call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
        receipt = self.state.load_receipt(
            call_key.session_id,
            call_key.idempotency_key,
        )
        if receipt is None or receipt.target_id != call_key.target_id or receipt.request_digest != call_key.request_digest:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_QUERY_CALL_MISMATCH")
        store = self.physical_gate_receipt_store
        if store is None:
            raise ProtocolError("TARGETD_PHYSICAL_MOTION_EXECUTION_UNAVAILABLE")
        refs = receipt.evidence_refs
        gate_uris = [ref for ref in refs if ref.startswith("artifact://targetd/physical-provider-gates/")]
        if len(gate_uris) != 1:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_MISSING")
        uri = gate_uris[0]
        digest_uri = f"digest://sha256/{uri.rsplit('/', 1)[-1]}"
        if refs.count(digest_uri) != 1:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_MISSING")
        if expected_uri is not None and expected_uri != uri:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_REFERENCE_MISMATCH")
        if expected_digest_uri is not None and expected_digest_uri != digest_uri:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_REFERENCE_MISMATCH")
        try:
            reference = store.resolve(
                uri,
                call_key=call_key,
                digest_uri=digest_uri,
            )
            if receipt.provider_started_at != reference.sidecar.persisted_at:
                raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_INVALID")
            with self._physical_gate_verifiers_lock:
                gate = self._physical_gate_verifiers.get(call_key.digest())
            if gate is not None:
                gate.revalidate_consumption(
                    reference.sidecar.provider_gate,
                    call_key,
                    at=reference.sidecar.persisted_at,
                )
        except ProtocolError:
            raise
        except Exception as exc:
            raise ProtocolError("TARGETD_PHYSICAL_GATE_SIDECAR_INVALID") from exc
        return reference

    def _bind_physical_gate_verifier(
        self,
        call_key: WorkerCallKey,
        gate: PhysicalMotionProviderGate,
    ) -> None:
        """Pin the live verifier to one call without making it replay state."""

        digest = call_key.digest()
        with self._physical_gate_verifiers_lock:
            existing = self._physical_gate_verifiers.get(digest)
            if existing is not None and existing is not gate:
                raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_CONFLICT")
            if existing is None and len(self._physical_gate_verifiers) >= 2_048:
                raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_CAPACITY_EXCEEDED")
            self._physical_gate_verifiers[digest] = gate

    @staticmethod
    def _require_consumed_physical_gate(
        consumed: PhysicalProviderGateReceipt,
        request: ExecutionRequestV3,
        authority: TargetdExecutionAuthority,
        armed_zero: object,
    ) -> None:
        """Defensively bind an injected gate's final target CAS receipt."""

        if not isinstance(
            consumed,
            (ProviderGateConsumptionReceipt, DebugUserAttestedProviderGateReceipt),
        ):
            raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_BLOCKED")
        intent = request.motion_safety_admission.intent
        artifact = consumed.consume_artifact
        try:
            from .physical_worker import PhysicalWorkerArmedZero

            if not isinstance(armed_zero, PhysicalWorkerArmedZero):
                raise TypeError
            expected_binding = ArmedZeroProviderBinding(
                call_id=request.idempotency_key,
                session_id=request.session_id,
                execution_subject_digest=request.execution_subject_digest,
                publisher_identity=armed_zero.publisher_identity,
                publisher_gid=armed_zero.publisher_endpoint_gids[0],
                provider_pid=armed_zero.inner_process_identity.pid,
                provider_start_time_ticks=(armed_zero.inner_process_identity.start_ticks),
                provider_runtime_sha256=armed_zero.provider_runtime_sha256,
                provider_cmdline_sha256=armed_zero.provider_cmdline_sha256,
                provider_runtime_identity_digest=(armed_zero.provider_runtime_identity_digest),
            )
        except Exception as exc:
            raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_BLOCKED") from exc
        common_invalid = (
            consumed.call_id != request.idempotency_key
            or consumed.session_id != request.session_id
            or consumed.target_id != request.target_id
            or consumed.target_identity != authority.mapping_admission.target_identity_digest
            or consumed.operator_id != intent.operator_id
            or consumed.execution_subject_digest != request.execution_subject_digest
            or consumed.challenge_artifact_digest is None
            or artifact is None
            or artifact.kind != "PROVIDER_GATE_CONSUMED"
            or artifact.call_id != request.idempotency_key
            or artifact.session_id != request.session_id
            or artifact.target_id != request.target_id
            or artifact.target_identity != intent.target_identity
            or artifact.operator_id != intent.operator_id
            or artifact.execution_subject_digest != request.execution_subject_digest
            or artifact.ros_graph_digest != intent.ros_graph_digest
            or artifact.claims.get("consumed") is not True
            or artifact.claims.get("one_shot") is not True
            or artifact.claims.get("challenge_artifact_digest") != consumed.challenge_artifact_digest
            or artifact.claims.get("graph_compare_and_set") is not True
            or artifact.claims.get("fence_compare_and_set") is not True
            or artifact.claims.get("motion_enabled") is not False
            or artifact.claims.get("provider_invocation_count") != 0
            or artifact.claims.get("armed_zero_provider_binding") != expected_binding.model_dump(mode="json")
        )
        if common_invalid:
            raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_BLOCKED")
        if isinstance(consumed, DebugUserAttestedProviderGateReceipt):
            if (
                consumed.status != "DEBUG_CONSUMED"
                or consumed.report_status != "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
                or consumed.reasons
                or consumed.debug_provider_boundary_open is not True
                or consumed.production_provider_boundary_open is not False
                or consumed.production_ready is not False
                or consumed.production_authority_verified is not False
                or consumed.fresh_estop_challenge_verified is not False
                or consumed.debug_motion_authorized is not True
                or consumed.provider_invocation_limit != 1
                or consumed.max_abs_rotation_degrees != 1.0
                or consumed.max_abs_linear_meters != 0.03
                or consumed.one_shot is not True
                or artifact.claims.get("debug_gate_binding") is None
            ):
                raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_BLOCKED")
            return
        if (
            consumed.status != "CONSUMED"
            or consumed.consumed is not True
            or consumed.provider_boundary_open is not True
            or consumed.provider_invocation_limit != 1
            or consumed.motion_authorized is not False
            or consumed.ros_graph_digest != intent.ros_graph_digest
            or consumed.command_route != intent.command_route
            or consumed.command_interface != intent.command_interface
            or consumed.publisher_identity != intent.publisher_identity
            or consumed.direct_motor_route != intent.direct_motor_route
            or consumed.direct_motor_interface != intent.direct_motor_interface
            or consumed.direct_motor_publisher_identity != intent.direct_motor_publisher_identity
            or consumed.provider_fence_digest is None
            or artifact.claims.get("provider_fence_digest") != consumed.provider_fence_digest
        ):
            raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_BLOCKED")

    @staticmethod
    def _require_physical_armed_zero(
        armed_zero: object,
        request: ExecutionRequestV3,
        manifest: ExecutionBundleManifest,
        claim: WorkerLeaseClaim,
    ) -> None:
        try:
            from .physical_worker import PhysicalWorkerArmedZero

            if not isinstance(armed_zero, PhysicalWorkerArmedZero):
                raise TypeError
            intent = request.motion_safety_admission.intent
            now_epoch_s = datetime.now(timezone.utc).timestamp()
            if (
                armed_zero.call_key_digest != WorkerCallKey.from_request(request).digest()
                or armed_zero.target_id != request.target_id
                or armed_zero.call_id != request.idempotency_key
                or armed_zero.session_id != request.session_id
                or armed_zero.request_digest != request.request_digest()
                or armed_zero.execution_subject_digest != request.execution_subject_digest
                or armed_zero.runtime_sha256 != manifest.observation_contract.get("provider_runtime_sha256")
                or armed_zero.command_endpoint != intent.command_route
                or armed_zero.publisher_identity != intent.publisher_identity
                or len(armed_zero.publisher_endpoint_gids) != 1
                or armed_zero.competing_publisher_count != 0
                or armed_zero.direct_motor_publisher_identities != (intent.direct_motor_publisher_identity,)
                or armed_zero.provider_runtime_sha256 != "sha256:" + armed_zero.runtime_sha256
                or armed_zero.provider_cmdline_sha256 != "sha256:" + armed_zero.inner_process_identity.cmdline_sha256
                or not (armed_zero.registry_issued_at_epoch_s <= now_epoch_s < armed_zero.registry_expires_at_epoch_s)
                or claim.lease.call_key_digest != armed_zero.call_key_digest
            ):
                raise TypeError
        except Exception as exc:
            raise ProtocolError("TARGETD_PHYSICAL_WORKER_ARM_INVALID") from exc

    def _require_physical_motion_execution_capability(
        self,
        request: ExecutionRequestLike,
        authority: TargetdExecutionAuthority,
    ) -> None:
        """Require v3 identity plus an injected final target-gate adapter.

        This is only the non-consuming preflight. The one-shot fresh CAS is
        consumed by :meth:`start_physical_process_call`; synchronous provider
        execution remains rejected even when this preflight succeeds.
        """

        if not requires_motion_safety(authority):
            return
        if not isinstance(request, ExecutionRequestV3):
            raise ProtocolError("PHYSICAL_MOTION_EXECUTION_REQUEST_V3_REQUIRED")
        gate = self.physical_motion_gate
        if gate is None:
            raise ProtocolError("TARGETD_PHYSICAL_MOTION_EXECUTION_UNAVAILABLE")
        try:
            gate.validate_request(request, authority)
        except ProtocolError:
            raise
        except Exception as exc:
            raise ProtocolError("TARGETD_PHYSICAL_PROVIDER_GATE_BLOCKED") from exc

    def _require_execution_session(self, session_id: str) -> JourneySession:
        try:
            persisted = self.state.load_session(session_id)
        except KeyError as exc:
            raise ProtocolError("journey session is not open") from exc
        session = self.resume_session(session_id, persisted.resume_token)
        if session.phase.value not in {"TRACE", "CERTIFY"}:
            raise ProtocolError("execution request is not in an executable journey phase")
        if session.surface_digest is None:
            raise ProtocolError("execution journey requires a bound surface")
        if session.target_id != self.target_id:
            raise ProtocolError("journey session target does not match targetd")
        return session

    def _verify_cached_manifest_signature(
        self,
        manifest: ExecutionBundleManifest,
    ) -> None:
        verification_key = self.verification_keys.get(
            manifest.signer_key_id,
            self.signing_key,
        )
        if verification_key is None:
            raise ProtocolError("TARGETD_TRUSTED_BUNDLE_SIGNER_REQUIRED")
        manifest.verify_signature(verification_key)

    @staticmethod
    def _accept_transition(
        current: TargetdCallReceipt | None,
        proposed: TargetdCallReceipt,
    ) -> TargetdCallReceipt:
        if current is None:
            return proposed
        if current.request_digest != proposed.request_digest:
            raise ProtocolError("idempotency key was reused with different call identity")
        if current.status in {"ACCEPTED", "STARTED"}:
            return current.model_copy(
                update={
                    "status": "UNKNOWN",
                    "result": {"error": "CALL_RECONCILIATION_REQUIRED"},
                    "updated_at": datetime.now(timezone.utc),
                }
            )
        return current

    @staticmethod
    def _start_transition(
        receipt: TargetdCallReceipt | None,
        request: ExecutionRequestLike,
    ) -> TargetdCallReceipt:
        TargetdService._require_receipt_identity(receipt, request)
        assert receipt is not None
        if receipt.status != "ACCEPTED":
            return receipt
        return receipt.model_copy(update={"status": "STARTED", "updated_at": datetime.now(timezone.utc)})

    def _provider_transition(
        self,
        receipt: TargetdCallReceipt | None,
        request: ExecutionRequestLike,
        authority: TargetdExecutionAuthority,
        execute: Callable[[], tuple[str, dict]],
    ) -> TargetdCallReceipt:
        TargetdService._require_receipt_identity(receipt, request)
        assert receipt is not None
        if receipt.status != "STARTED":
            return receipt
        # Defense in depth for any receipt persisted by an older process.
        # Static evidence is never treated as a live graph/fence CAS, so the
        # current implementation cannot cross this boundary for motion.
        self._require_physical_motion_execution_capability(request, authority)
        if requires_motion_safety(authority):
            # Physical execution is available only through
            # start_physical_process_call plus an isolated duplex worker. The
            # synchronous provider callback cannot receive authenticated STOP
            # while it is running and therefore must remain closed.
            raise ProtocolError("TARGETD_PHYSICAL_PROCESS_WORKER_REQUIRED")
        started_at = datetime.now(timezone.utc)
        try:
            status, result = execute()
            if status not in {
                "SUCCEEDED",
                "FAILED",
                "STOPPED",
                "CANCELLED",
                "UNKNOWN",
                "NOT_ACCEPTED",
            }:
                raise ProtocolError("provider returned an invalid terminal status")
        except Exception:
            # Once the callback is entered, an exception cannot prove whether
            # the provider crossed a side-effect boundary. Only an explicit,
            # trusted provider return may claim FAILED; ambiguous termination
            # is fail-closed and never leaks exception details into receipts.
            status = "UNKNOWN"
            result = {"error": "WORKER_EXCEPTION_AMBIGUOUS"}
        return receipt.model_copy(
            update={
                "status": status,
                "result": result,
                "provider_started_at": started_at,
                "updated_at": datetime.now(timezone.utc),
            }
        )

    def _reject_before_provider(self, request: ExecutionRequestLike, code: str) -> TargetdCallReceipt:
        return self.state.update_receipt(
            request.session_id,
            request.idempotency_key,
            lambda receipt: self._complete_transition(
                receipt,
                status="NOT_ACCEPTED",
                result={"error": code[:512]},
            ),
        )

    @staticmethod
    def _complete_transition(
        receipt: TargetdCallReceipt | None,
        *,
        status: Literal[
            "SUCCEEDED",
            "FAILED",
            "STOPPED",
            "CANCELLED",
            "UNKNOWN",
            "NOT_ACCEPTED",
        ],
        result: dict | None = None,
        evidence_refs: list[str] | None = None,
        artifact_refs: list[str] | None = None,
    ) -> TargetdCallReceipt:
        if receipt is None:
            raise ProtocolError("cannot complete an unknown call")
        if receipt.status in {
            "SUCCEEDED",
            "FAILED",
            "STOPPED",
            "CANCELLED",
            "UNKNOWN",
            "NOT_ACCEPTED",
        }:
            return receipt
        return receipt.model_copy(
            update={
                "status": status,
                "result": result,
                "evidence_refs": (receipt.evidence_refs if evidence_refs is None else evidence_refs),
                "artifact_refs": (receipt.artifact_refs if artifact_refs is None else artifact_refs),
                "updated_at": datetime.now(timezone.utc),
            }
        )

    @staticmethod
    def _require_receipt_identity(
        receipt: TargetdCallReceipt | None,
        request: ExecutionRequestLike,
    ) -> None:
        if receipt is None:
            raise ProtocolError("cannot operate on an unknown call")
        if (
            receipt.request_digest != request.request_digest()
            or receipt.authority_head_digest != request.authority_head_digest
            or receipt.fence_epoch != request.fence_epoch
            or receipt.provider_fence_digest != provider_fence_digest(request)
        ):
            raise ProtocolError("targetd receipt fence identity mismatch")

    @staticmethod
    def _require_current_receipt(
        receipt: TargetdCallReceipt | None,
    ) -> TargetdCallReceipt:
        if receipt is None:
            raise ProtocolError("cannot reconcile an unknown call")
        return receipt

    @staticmethod
    def _is_physical_process_receipt(receipt: TargetdCallReceipt) -> bool:
        return (receipt.provider_id == "ros-container" and receipt.provider_operation == "base.rotate") or any(
            ref.startswith("artifact://targetd/physical-provider-gates/") for ref in receipt.evidence_refs
        )

    def _session_ids(self) -> list[str]:
        payload = self.state._read()
        sessions = payload.get("sessions", {})
        if not isinstance(sessions, dict):
            raise ProtocolError("targetd session state is invalid")
        return list(sessions)

    @staticmethod
    def _constant_time_equal(left: str, right: str) -> bool:
        return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _safe_digest_equal(left: object, right: object) -> bool:
    """Compare bounded textual digests without accepting coercions."""

    if not isinstance(left, str) or not isinstance(right, str) or len(left) > 128 or len(right) > 128:
        return False
    try:
        return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))
    except UnicodeEncodeError:
        return False
