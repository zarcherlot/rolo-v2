"""Immutable Tool Release and atomic Tool Catalog publishing."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator

from rolo.dsl.admission import (
    MappingAdmissionError,
    MappingAdmissionIdentity,
    MappingAdmissionScope,
    MappingConfirmationReceipt,
    MappingConfirmationStore,
    ProductionMappingAdmissionGate,
    ProductionMappingConfirmationStore,
    bind_mapping_admission_gate,
)
from rolo.dsl.canonical import ir_digest
from rolo.dsl.compiler import CompileResult
from rolo.dsl.models import StrictModel
from rolo.dsl.parser import loads_unique_json
from rolo.dsl.report import ConformanceReport
from rolo.dsl.target_conformance import TargetConformanceReport

from .catalog import (
    CatalogMutation,
    CatalogTransaction,
    ReleaseCatalog,
    ReleaseCatalogError,
)
from .proofs import (
    TRUSTED_TARGET_CONFORMANCE_AUTHORITY,
    ReleaseTargetConformanceBinding,
    TargetConformanceArtifactReference,
    TrustedTargetConformanceArtifactResolver,
)
from .signature import (
    PRODUCTION_TARGET_SIGNATURE_AUTHORITY,
    TargetReleaseSignature,
    TargetReleaseSigner,
    TargetSignatureVerifier,
)


class ToolRelease(StrictModel):
    tool_id: str = Field(min_length=1)
    target_id: str | None = None
    operation_kind: str
    dsl_digest: str
    ir_digest: str
    probe_evidence_digest: str
    mhs_manifest_digests: tuple[str, ...] = ()
    compiler_version: str
    generated_bundle_digest: str
    conformance_digest: str
    target_fingerprint: str
    compile_context_digest: str | None = None
    route_digest: str | None = None
    target_conformance_digest: str | None = None
    mapping_confirmation_receipt_digest: str | None = None
    mapping_admission: MappingAdmissionIdentity | None = None
    status: str = "PUBLISHED"
    agent_callable: bool = True


def tool_release_digest(release: ToolRelease) -> str:
    """Return the immutable catalog digest for a ToolRelease manifest."""

    payload = json.dumps(
        release.model_dump(mode="json"),
        sort_keys=True,
        allow_nan=False,
    ).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


class ReleasePublicationReceipt(StrictModel):
    """Signed Catalog result handed directly to a Release-bound consumer."""

    schema_version: Literal["rolo-release-publication-receipt/v1"] = (
        "rolo-release-publication-receipt/v1"
    )
    authority_mode: Literal["PRODUCTION_SIGNED"] = "PRODUCTION_SIGNED"
    release_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    catalog_sequence: int = Field(strict=True, ge=1)
    catalog_transaction_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    catalog_mutation: CatalogMutation
    target_signature: TargetReleaseSignature
    target_conformance_artifact: TargetConformanceArtifactReference
    release: ToolRelease

    @model_validator(mode="after")
    def bind_release(self) -> ReleasePublicationReceipt:
        if tool_release_digest(self.release) != self.release_digest:
            raise ValueError("publication receipt release digest mismatch")
        mutation = self.catalog_mutation
        if (
            mutation.operation != "PUBLISH"
            or mutation.sequence != self.catalog_sequence
            or mutation.release_digest != self.release_digest
            or mutation.release != self.release.model_dump(mode="json")
            or mutation.tool_id != self.release.tool_id
            or mutation.target_id != self.release.target_id
            or mutation.context_digest != self.release.compile_context_digest
            or mutation.manifest_digest != self.release.generated_bundle_digest
            or mutation.status != "PUBLISHED"
            or mutation.stale_reasons
        ):
            raise ValueError("publication receipt Catalog mutation mismatch")
        if (
            self.target_signature.target_id != self.release.target_id
            or self.target_signature.signed_digest != mutation.signing_digest
        ):
            raise ValueError("publication receipt target identity mismatch")
        transaction = CatalogTransaction.build(mutation, self.target_signature)
        if transaction.transaction_digest != self.catalog_transaction_digest:
            raise ValueError("publication receipt Catalog transaction mismatch")
        if (
            self.release.target_conformance_digest
            != self.target_conformance_artifact.target_conformance_digest
        ):
            raise ValueError("publication receipt target artifact mismatch")
        return self


class ReleasePublisher:
    authority_mode = "COMPATIBILITY_UNSIGNED"

    def __init__(
        self,
        root: str | Path,
        *,
        confirmation_store: MappingConfirmationStore | None = None,
    ):
        if isinstance(confirmation_store, ProductionMappingConfirmationStore):
            raise MappingAdmissionError(
                "RELEASE_UNSIGNED_PRODUCTION_AUTHORITY_FORBIDDEN"
            )
        self.confirmation_store = confirmation_store
        self.admission_gate = bind_mapping_admission_gate(confirmation_store)
        # Compatibility publication remains unsigned until a target signature
        # authority is explicitly wired by a higher layer.  The Catalog still
        # gains append-only/CAS semantics; secure callers use ReleaseCatalog's
        # signature-required mode directly.
        self.catalog_store = ReleaseCatalog(
            root,
            require_target_signatures=False,
        )
        self.root = self.catalog_store.root
        self.releases = self.root / "releases"
        self.catalog_path = self.root / "tool-catalog.json"
        self._releases_directory_identity: tuple[int, int] | None = None

    def publish(
        self,
        result: CompileResult,
        conformance: ConformanceReport,
        **_kwargs: Any,
    ) -> ToolRelease:
        """Reject the legacy compiler-only publication bypass.

        A target conformance digest supplied by a caller is not proof that a
        target produced or persisted T1-T4 evidence.  All callable releases
        must therefore enter through :meth:`publish_verified`.
        """

        del result, conformance
        raise ValueError("RELEASE_TARGET_CONFORMANCE_REQUIRED")

    def _commit_verified_release(
        self,
        result: CompileResult,
        conformance: ConformanceReport,
        *,
        target_fingerprint: str,
        compiler_version: str,
        mhs_manifest_digests: tuple[str, ...] = (),
        compile_context_digest: str | None = None,
        route_digest: str | None = None,
        target_conformance_digest: str | None = None,
        target_conformance_artifact: TargetConformanceArtifactReference | None = None,
        journey_session_id: str | None = None,
        confirmation_receipt_digest: str | None = None,
    ) -> ToolRelease:
        release, _ = self._commit_verified_release_transaction(
            result,
            conformance,
            target_fingerprint=target_fingerprint,
            compiler_version=compiler_version,
            mhs_manifest_digests=mhs_manifest_digests,
            compile_context_digest=compile_context_digest,
            route_digest=route_digest,
            target_conformance_digest=target_conformance_digest,
            target_conformance_artifact=target_conformance_artifact,
            journey_session_id=journey_session_id,
            confirmation_receipt_digest=confirmation_receipt_digest,
        )
        return release

    def _commit_verified_release_transaction(
        self,
        result: CompileResult,
        conformance: ConformanceReport,
        *,
        target_fingerprint: str,
        compiler_version: str,
        mhs_manifest_digests: tuple[str, ...] = (),
        compile_context_digest: str | None = None,
        route_digest: str | None = None,
        target_conformance_digest: str | None = None,
        target_conformance_artifact: TargetConformanceArtifactReference | None = None,
        journey_session_id: str | None = None,
        confirmation_receipt_digest: str | None = None,
    ) -> tuple[ToolRelease, CatalogTransaction]:
        if not conformance.passed or not result.ok:
            raise ValueError("RELEASE_CONFORMANCE_FAILED")
        receipt = self._require_active_mapping(
            result,
            target_fingerprint=target_fingerprint,
            compile_context_digest=compile_context_digest,
            journey_session_id=journey_session_id,
            confirmation_receipt_digest=confirmation_receipt_digest,
        )
        mapping_identity = receipt.admission_identity()
        report_json = json.dumps(conformance.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        report_digest = "sha256:" + hashlib.sha256(report_json.encode()).hexdigest()
        release = ToolRelease(
            tool_id=result.document.tool_id,
            target_id=result.document.target.robot_id,
            operation_kind=str(result.document.kind),
            dsl_digest=result.dsl_digest,
            ir_digest=ir_digest(result.ir),
            probe_evidence_digest=result.document.target.evidence_digest,
            mhs_manifest_digests=mhs_manifest_digests,
            compiler_version=compiler_version,
            generated_bundle_digest=result.bundle.digest,
            conformance_digest=report_digest,
            target_fingerprint=target_fingerprint,
            compile_context_digest=mapping_identity.context_digest,
            route_digest=route_digest,
            target_conformance_digest=target_conformance_digest,
            mapping_confirmation_receipt_digest=receipt.receipt_digest,
            mapping_admission=mapping_identity,
        )
        release_digest = tool_release_digest(release)
        self._write_immutable_release(release_digest, release)
        self._prepare_release_artifacts(
            release_digest,
            release,
            target_conformance_artifact,
        )
        head = self.catalog_store.head()
        catalog = self.catalog_store.snapshot()
        current_entry = catalog.get("tools", {}).get(release.tool_id)
        expected_current = (
            current_entry.get("current")
            if isinstance(current_entry, dict)
            else None
        )
        mutation = self.catalog_store.propose(
            operation="PUBLISH",
            tool_id=release.tool_id,
            target_id=release.target_id or "",
            release_digest=release_digest,
            context_digest=release.compile_context_digest or "",
            manifest_digest=release.generated_bundle_digest,
            release=release.model_dump(mode="json"),
            expected_catalog_head_digest=head.transaction_digest,
            expected_current_release_digest=expected_current,
        )
        transaction = self._commit_catalog_mutation(
            mutation,
            receipt_digest=receipt.receipt_digest,
            mapping_identity=mapping_identity,
        )
        return release, transaction

    def publish_verified(
        self,
        result: CompileResult,
        compiler_conformance: ConformanceReport,
        target_conformance: TargetConformanceReport | Mapping[str, Any],
        *,
        target_fingerprint: str,
        compiler_version: str,
        target_compile_artifact_digest: str,
        mhs_manifest_digests: tuple[str, ...] = (),
        compile_context_digest: str | None = None,
        route_digest: str | None = None,
        journey_session_id: str | None = None,
        confirmation_receipt_digest: str | None = None,
    ) -> ToolRelease:
        """Publish only after both offline C1-C4 and target T1-T4 pass."""

        release, _ = self._publish_verified_report(
            result,
            compiler_conformance,
            target_conformance,
            target_fingerprint=target_fingerprint,
            compiler_version=compiler_version,
            target_compile_artifact_digest=target_compile_artifact_digest,
            mhs_manifest_digests=mhs_manifest_digests,
            compile_context_digest=compile_context_digest,
            route_digest=route_digest,
            journey_session_id=journey_session_id,
            confirmation_receipt_digest=confirmation_receipt_digest,
        )
        return release

    def _publish_verified_report(
        self,
        result: CompileResult,
        compiler_conformance: ConformanceReport,
        target_conformance: TargetConformanceReport | Mapping[str, Any],
        *,
        target_fingerprint: str,
        compiler_version: str,
        target_compile_artifact_digest: str,
        mhs_manifest_digests: tuple[str, ...] = (),
        compile_context_digest: str | None = None,
        route_digest: str | None = None,
        journey_session_id: str | None = None,
        confirmation_receipt_digest: str | None = None,
        target_conformance_artifact: TargetConformanceArtifactReference | None = None,
    ) -> tuple[ToolRelease, CatalogTransaction]:
        target_report = (
            target_conformance
            if isinstance(target_conformance, TargetConformanceReport)
            else TargetConformanceReport.model_validate(target_conformance)
        )
        if not target_report.passed or target_report.target_fingerprint != target_fingerprint:
            raise ValueError("RELEASE_TARGET_CONFORMANCE_FAILED")
        if result.document is None or result.ir is None or result.bundle is None:
            raise ValueError("RELEASE_TARGET_CONFORMANCE_IDENTITY_MISMATCH")
        bundle = result.bundle.manifest
        expected_identity = {
            "tool_id": result.document.tool_id,
            "operation_kind": result.document.kind,
            "target_id": result.document.target.robot_id,
            "evidence_digest": result.document.target.evidence_digest,
            "dsl_digest": result.dsl_digest,
            "ir_digest": ir_digest(result.ir),
            "bundle_digest": result.bundle.digest,
            "compiler_version": compiler_version,
            "compiler_backend_id": bundle.backend_id,
            "compiler_backend_version": bundle.backend_version,
            "negotiated_capabilities": bundle.negotiated_capabilities,
            "compile_artifact_digest": target_compile_artifact_digest,
        }
        if compile_context_digest is None:
            raise ValueError("RELEASE_TARGET_CONFORMANCE_IDENTITY_MISMATCH")
        expected_identity["context_digest"] = compile_context_digest
        if any(getattr(target_report, field) != value for field, value in expected_identity.items()):
            raise ValueError("RELEASE_TARGET_CONFORMANCE_IDENTITY_MISMATCH")
        if (
            not journey_session_id
            or not confirmation_receipt_digest
            or target_report.journey_session_id != journey_session_id
            or target_report.confirmation_receipt_digest != confirmation_receipt_digest
        ):
            raise MappingAdmissionError("MAPPING_TARGET_CONFORMANCE_ADMISSION_MISMATCH")
        if self.confirmation_store is None:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_STORE_REQUIRED")
        committed_receipt = self.confirmation_store.resolve(confirmation_receipt_digest)
        if target_report.target_identity_digest != committed_receipt.target_identity_digest:
            raise MappingAdmissionError("MAPPING_TARGET_CONFORMANCE_ADMISSION_MISMATCH")
        target_json = json.dumps(target_report.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        target_digest = "sha256:" + hashlib.sha256(target_json.encode()).hexdigest()
        return self._commit_verified_release_transaction(
            result,
            compiler_conformance,
            target_fingerprint=target_fingerprint,
            compiler_version=compiler_version,
            mhs_manifest_digests=mhs_manifest_digests,
            compile_context_digest=compile_context_digest,
            route_digest=route_digest,
            target_conformance_digest=target_digest,
            target_conformance_artifact=target_conformance_artifact,
            journey_session_id=journey_session_id,
            confirmation_receipt_digest=confirmation_receipt_digest,
        )

    def _commit_catalog_mutation(
        self,
        mutation: CatalogMutation,
        *,
        receipt_digest: str | None = None,
        mapping_identity: MappingAdmissionIdentity | None = None,
    ) -> CatalogTransaction:
        """Commit unsigned compatibility state under the Mapping fence."""

        if receipt_digest is None and mapping_identity is None:
            return self.catalog_store.commit(mutation)
        if (
            receipt_digest is None
            or mapping_identity is None
            or self.admission_gate is None
        ):
            raise MappingAdmissionError("MAPPING_CONFIRMATION_STORE_REQUIRED")
        _, transaction = self.admission_gate.commit_if_active(
            receipt_digest,
            mapping_identity,
            lambda: self.catalog_store.commit(mutation),
        )
        if not isinstance(transaction, CatalogTransaction):
            raise ReleaseCatalogError("RELEASE_CATALOG_COMMIT_INVALID")
        return transaction

    def _prepare_release_artifacts(
        self,
        release_digest: str,
        release: ToolRelease,
        reference: TargetConformanceArtifactReference | None,
    ) -> None:
        """Compatibility publications carry no production proof sidecar."""

        del release_digest, release
        if reference is not None:
            raise ValueError("RELEASE_PRODUCTION_PUBLISHER_REQUIRED")

    def _require_active_mapping(
        self,
        result: CompileResult,
        *,
        target_fingerprint: str,
        compile_context_digest: str | None,
        journey_session_id: str | None,
        confirmation_receipt_digest: str | None,
    ) -> MappingConfirmationReceipt:
        """Resolve one trusted receipt and bind it to compiler-owned identity.

        This check deliberately runs before creating the release directory or
        reading and rewriting the Catalog.  The receipt supplies proposal and
        candidate lineage, while the document and Bundle Plan supply the
        release-facing DSL, Context, evidence, target, tool, and kind.
        """

        if self.confirmation_store is None or self.admission_gate is None:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_STORE_REQUIRED")
        if not confirmation_receipt_digest:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_REQUIRED")
        if not journey_session_id:
            raise MappingAdmissionError("MAPPING_JOURNEY_SESSION_REQUIRED")
        if result.document is None or result.bundle is None:
            raise MappingAdmissionError("MAPPING_COMPILE_RESULT_REQUIRED")

        receipt = self.confirmation_store.resolve(confirmation_receipt_digest)
        document = result.document
        manifest = result.bundle.manifest
        if manifest.dsl_digest != result.dsl_digest:
            raise MappingAdmissionError("MAPPING_DSL_DIGEST_MISMATCH")
        if manifest.tool_id != document.tool_id or manifest.kind != document.kind:
            raise MappingAdmissionError("MAPPING_SCOPE_MISMATCH")
        if manifest.target_fingerprint != target_fingerprint:
            raise MappingAdmissionError("MAPPING_TARGET_FINGERPRINT_MISMATCH")
        if compile_context_digest is not None and compile_context_digest != manifest.context_digest:
            raise MappingAdmissionError("MAPPING_CONTEXT_DIGEST_MISMATCH")

        scope = MappingAdmissionScope(
            tool_id=document.tool_id,
            operation_kind=document.kind,
            operations=receipt.scope.operations,
            access=receipt.scope.access,
            risk=receipt.scope.risk,
        )
        expected = MappingAdmissionIdentity.build(
            journey_session_id=journey_session_id,
            target_id=document.target.robot_id,
            target_fingerprint=manifest.target_fingerprint,
            candidate_index_digest=receipt.candidate_index_digest,
            candidate_digest=receipt.candidate_digest,
            proposal_digest=receipt.proposal_digest,
            dsl_digest=result.dsl_digest,
            context_digest=manifest.context_digest,
            evidence_digest=document.target.evidence_digest,
            available_tool_catalog_digest=receipt.available_tool_catalog_digest,
            scope=scope,
        )
        return self.admission_gate.require_active(
            confirmation_receipt_digest,
            expected,
        )

    def stale(
        self,
        release: ToolRelease,
        *,
        target_fingerprint: str,
        evidence_digest: str,
        compiler_version: str,
        compile_context_digest: str | None = None,
        route_digest: str | None = None,
        mhs_manifest_digests: tuple[str, ...] | None = None,
    ) -> bool:
        """Return whether a release no longer matches the current evidence."""

        return bool(
            self.stale_reasons(
                release,
                target_fingerprint=target_fingerprint,
                evidence_digest=evidence_digest,
                compiler_version=compiler_version,
                compile_context_digest=compile_context_digest,
                route_digest=route_digest,
                mhs_manifest_digests=mhs_manifest_digests,
            )
        )

    def stale_reasons(
        self,
        release: ToolRelease,
        *,
        target_fingerprint: str,
        evidence_digest: str,
        compiler_version: str,
        compile_context_digest: str | None = None,
        route_digest: str | None = None,
        mhs_manifest_digests: tuple[str, ...] | None = None,
    ) -> tuple[str, ...]:
        reasons: list[str] = []
        if release.target_fingerprint != target_fingerprint:
            reasons.append("TARGET_FINGERPRINT_CHANGED")
        if release.probe_evidence_digest != evidence_digest:
            reasons.append("PROBE_EVIDENCE_CHANGED")
        if release.compiler_version != compiler_version:
            reasons.append("COMPILER_VERSION_CHANGED")
        if release.compile_context_digest is not None and compile_context_digest is not None and release.compile_context_digest != compile_context_digest:
            reasons.append("CONTEXT_DIGEST_CHANGED")
        if release.route_digest is not None and route_digest is not None and release.route_digest != route_digest:
            reasons.append("ROUTE_DIGEST_CHANGED")
        if mhs_manifest_digests is not None and tuple(sorted(set(release.mhs_manifest_digests))) != tuple(sorted(set(mhs_manifest_digests))):
            reasons.append("MHS_MANIFEST_CHANGED")
        return tuple(reasons)

    def current(self, tool_id: str) -> tuple[str, ToolRelease] | None:
        """Load current state and revalidate its Mapping confirmation."""

        current = self._current_unchecked(tool_id)
        if current is None:
            return None
        _, release = current
        if release.status == "PUBLISHED" and self.admission_gate is not None:
            self._require_release_mapping_active(release)
        return current

    def _current_unchecked(self, tool_id: str) -> tuple[str, ToolRelease] | None:
        """Read current Catalog state without blocking a safety tombstone."""

        entry = self._read_catalog().get("tools", {}).get(tool_id)
        if not isinstance(entry, dict):
            return None
        digest = entry.get("current")
        if not isinstance(digest, str):
            return None
        release = self.load(digest)
        if entry.get("status") == "STALE":
            release = release.model_copy(update={"status": "STALE", "agent_callable": False})
        return digest, release

    def _require_release_mapping_active(
        self,
        release: ToolRelease,
    ) -> MappingAdmissionIdentity:
        if self.admission_gate is None or self.confirmation_store is None:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_STORE_REQUIRED")
        if (
            not release.mapping_confirmation_receipt_digest
            or release.mapping_admission is None
            or not release.target_id
            or release.compile_context_digest is None
        ):
            raise MappingAdmissionError("MAPPING_RELEASE_IDENTITY_INCOMPLETE")
        lineage = release.mapping_admission
        scope = MappingAdmissionScope(
            tool_id=release.tool_id,
            operation_kind=release.operation_kind,
            operations=lineage.scope.operations,
            access=lineage.scope.access,
            risk=lineage.scope.risk,
        )
        expected = MappingAdmissionIdentity.build(
            journey_session_id=lineage.journey_session_id,
            target_id=release.target_id,
            target_fingerprint=release.target_fingerprint,
            candidate_index_digest=lineage.candidate_index_digest,
            candidate_digest=lineage.candidate_digest,
            proposal_digest=lineage.proposal_digest,
            dsl_digest=release.dsl_digest,
            context_digest=release.compile_context_digest,
            evidence_digest=release.probe_evidence_digest,
            available_tool_catalog_digest=lineage.available_tool_catalog_digest,
            scope=scope,
        )
        receipt = self.admission_gate.require_active(
            release.mapping_confirmation_receipt_digest,
            expected,
        )
        if receipt.admission_identity() != lineage:
            raise MappingAdmissionError("MAPPING_RELEASE_LINEAGE_MISMATCH")
        return expected

    def mark_stale(self, tool_id: str, reasons: tuple[str, ...]) -> ToolRelease:
        """Mark the catalog pointer stale while preserving its immutable manifest."""

        current = self._current_unchecked(tool_id)
        if current is None:
            raise KeyError(tool_id)
        digest, release = current
        head = self.catalog_store.head()
        mutation = self.catalog_store.propose(
            operation="MARK_STALE",
            tool_id=tool_id,
            target_id=release.target_id or "",
            release_digest=digest,
            context_digest=release.compile_context_digest or "",
            manifest_digest=release.generated_bundle_digest,
            release=release.model_dump(mode="json"),
            expected_catalog_head_digest=head.transaction_digest,
            expected_current_release_digest=digest,
            stale_reasons=tuple(dict.fromkeys(reasons)),
        )
        self._commit_catalog_mutation(mutation)
        return release.model_copy(update={"status": "STALE", "agent_callable": False})

    def load(self, release_digest: str) -> ToolRelease:
        """Load a release by its catalog digest and verify its filename digest."""

        self.catalog_store.head()
        self._assert_releases_directory(create=False)
        if (
            not release_digest.startswith("sha256:")
            or len(release_digest) != 71
            or any(character not in "0123456789abcdef" for character in release_digest[7:])
        ):
            raise ValueError("RELEASE_DIGEST_INVALID")
        path = self.releases / f"{release_digest.removeprefix('sha256:')}.json"
        is_junction = getattr(path, "is_junction", None)
        if (
            not path.is_file()
            or path.is_symlink()
            or (callable(is_junction) and is_junction())
            or path.stat().st_nlink != 1
        ):
            raise FileNotFoundError(release_digest)
        release = ToolRelease.model_validate(
            loads_unique_json(path.read_text(encoding="utf-8"))
        )
        actual = tool_release_digest(release)
        if actual != release_digest:
            raise ValueError("RELEASE_DIGEST_MISMATCH")
        return release

    def rollback(self, tool_id: str, release_digest: str) -> ToolRelease:
        """Atomically point a tool back to an existing immutable release."""

        release = self.load(release_digest)
        if release.tool_id != tool_id:
            raise ValueError("RELEASE_TOOL_MISMATCH")
        mapping_identity: MappingAdmissionIdentity | None = None
        if self.admission_gate is not None:
            mapping_identity = self._require_release_mapping_active(release)
        head = self.catalog_store.head()
        catalog = self.catalog_store.snapshot()
        current_entry = catalog.get("tools", {}).get(tool_id)
        expected_current = (
            current_entry.get("current")
            if isinstance(current_entry, dict)
            else None
        )
        mutation = self.catalog_store.propose(
            operation="ROLLBACK",
            tool_id=tool_id,
            target_id=release.target_id or "",
            release_digest=release_digest,
            context_digest=release.compile_context_digest or "",
            manifest_digest=release.generated_bundle_digest,
            release=release.model_dump(mode="json"),
            expected_catalog_head_digest=head.transaction_digest,
            expected_current_release_digest=expected_current,
        )
        self._commit_catalog_mutation(
            mutation,
            receipt_digest=(
                release.mapping_confirmation_receipt_digest
                if mapping_identity is not None
                else None
            ),
            mapping_identity=mapping_identity,
        )
        return release

    def _read_catalog(self) -> dict[str, Any]:
        return self.catalog_store.snapshot()

    def _write_immutable_release(
        self,
        release_digest: str,
        release: ToolRelease,
    ) -> None:
        from rolo.core.persistence import interprocess_lock

        release_file = self.releases / f"{release_digest.removeprefix('sha256:')}.json"
        encoded = json.dumps(
            release.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        self.catalog_store.head()
        self._assert_releases_directory(create=True)
        with interprocess_lock(self.releases / "release-object.locked"):
            self.catalog_store.head()
            self._assert_releases_directory(create=True)
            is_junction = getattr(release_file, "is_junction", None)
            if release_file.is_symlink() or (
                callable(is_junction) and is_junction()
            ):
                raise ReleaseCatalogError("RELEASE_IMMUTABLE_PATH_UNTRUSTED")
            if release_file.exists():
                if not release_file.is_file() or release_file.stat().st_nlink != 1:
                    raise ReleaseCatalogError("RELEASE_IMMUTABLE_PATH_UNTRUSTED")
                try:
                    existing = ToolRelease.model_validate(
                        loads_unique_json(release_file.read_text(encoding="utf-8"))
                    )
                except (OSError, ValueError) as exc:
                    raise ReleaseCatalogError("RELEASE_IMMUTABLE_OBJECT_INVALID") from exc
                if existing != release:
                    raise ReleaseCatalogError("RELEASE_IMMUTABLE_OBJECT_CONFLICT")
                return
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".release-",
                dir=self.releases,
            )
            temporary = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.link(temporary, release_file, follow_symlinks=False)
                except FileExistsError as exc:
                    raise ReleaseCatalogError(
                        "RELEASE_IMMUTABLE_OBJECT_CONFLICT"
                    ) from exc
                except OSError as exc:
                    raise ReleaseCatalogError(
                        "RELEASE_IMMUTABLE_OBJECT_PUBLISH_FAILED"
                    ) from exc
                self._fsync_directory(self.releases)
            finally:
                temporary.unlink(missing_ok=True)
                self._fsync_directory(self.releases)
            if release_file.stat().st_nlink != 1:
                raise ReleaseCatalogError("RELEASE_IMMUTABLE_PATH_UNTRUSTED")

    def _assert_releases_directory(self, *, create: bool) -> None:
        if self._is_linklike(self.releases):
            raise ReleaseCatalogError("RELEASE_IMMUTABLE_PATH_UNTRUSTED")
        if create:
            try:
                self.releases.mkdir(parents=False, exist_ok=True)
            except OSError as exc:
                raise ReleaseCatalogError("RELEASE_IMMUTABLE_PATH_UNTRUSTED") from exc
        if not self.releases.exists():
            return
        if self._is_linklike(self.releases) or not self.releases.is_dir():
            raise ReleaseCatalogError("RELEASE_IMMUTABLE_PATH_UNTRUSTED")
        metadata = self.releases.stat()
        identity = (metadata.st_dev, metadata.st_ino)
        if self._releases_directory_identity is None:
            self._releases_directory_identity = identity
        elif self._releases_directory_identity != identity:
            raise ReleaseCatalogError("RELEASE_IMMUTABLE_DIRECTORY_REPLACED")

    @staticmethod
    def _is_linklike(path: Path) -> bool:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        try:
            attributes = getattr(path.lstat(), "st_file_attributes", 0)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise ReleaseCatalogError("RELEASE_IMMUTABLE_PATH_UNTRUSTED") from exc
        return bool(
            attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        )

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _atomic_json(path: Path, value: dict[str, Any]) -> None:
        from rolo.core.persistence import atomic_write_text

        atomic_write_text(
            path,
            json.dumps(value, sort_keys=True, indent=2),
        )


class ProductionReleasePublisher(ReleasePublisher):
    """Signature-required publisher over trusted target and Mapping evidence."""

    authority_mode = "PRODUCTION_SIGNED"

    def __init__(
        self,
        root: str | Path,
        *,
        confirmation_store: ProductionMappingConfirmationStore,
        artifact_resolver: TrustedTargetConformanceArtifactResolver,
        target_signer: TargetReleaseSigner,
        signature_verifier: TargetSignatureVerifier,
        admission_gate: ProductionMappingAdmissionGate | None = None,
    ) -> None:
        if not isinstance(confirmation_store, ProductionMappingConfirmationStore):
            raise MappingAdmissionError("MAPPING_PRODUCTION_AUTHORITY_REQUIRED")
        bound_gate = bind_mapping_admission_gate(confirmation_store, admission_gate)
        if not isinstance(bound_gate, ProductionMappingAdmissionGate):
            raise MappingAdmissionError("MAPPING_PRODUCTION_AUTHORITY_REQUIRED")
        self._require_provider(
            artifact_resolver,
            TRUSTED_TARGET_CONFORMANCE_AUTHORITY,
            "RELEASE_TARGET_ARTIFACT_RESOLVER_UNTRUSTED",
        )
        self._require_provider(
            target_signer,
            PRODUCTION_TARGET_SIGNATURE_AUTHORITY,
            "RELEASE_TARGET_SIGNER_UNTRUSTED",
        )
        self._require_provider(
            signature_verifier,
            PRODUCTION_TARGET_SIGNATURE_AUTHORITY,
            "RELEASE_TARGET_SIGNATURE_VERIFIER_UNTRUSTED",
        )
        self.confirmation_store = confirmation_store
        self.admission_gate = bound_gate
        self.artifact_resolver = artifact_resolver
        self.target_signer = target_signer
        self.catalog_store = ReleaseCatalog(
            root,
            signature_verifier=signature_verifier,
            require_target_signatures=True,
        )
        self.root = self.catalog_store.root
        self.releases = self.root / "releases"
        self.release_artifacts = self.root / "release-target-artifacts"
        self.catalog_path = self.root / "tool-catalog.json"
        self._releases_directory_identity = None
        self._release_artifacts_directory_identity: tuple[int, int] | None = None

    def publish_verified(
        self,
        result: CompileResult,
        compiler_conformance: ConformanceReport,
        target_conformance: TargetConformanceReport | Mapping[str, Any],
        *,
        target_fingerprint: str,
        compiler_version: str,
        target_compile_artifact_digest: str,
        mhs_manifest_digests: tuple[str, ...] = (),
        compile_context_digest: str | None = None,
        route_digest: str | None = None,
        journey_session_id: str | None = None,
        confirmation_receipt_digest: str | None = None,
    ) -> ToolRelease:
        """Reject caller-carried PASS reports at the production boundary."""

        del (
            result,
            compiler_conformance,
            target_conformance,
            target_fingerprint,
            compiler_version,
            target_compile_artifact_digest,
            mhs_manifest_digests,
            compile_context_digest,
            route_digest,
            journey_session_id,
            confirmation_receipt_digest,
        )
        raise ValueError("RELEASE_TRUSTED_CONFORMANCE_REFERENCE_REQUIRED")

    def publish_from_trusted_conformance(
        self,
        result: CompileResult,
        artifact_reference: TargetConformanceArtifactReference | Mapping[str, Any],
    ) -> ReleasePublicationReceipt:
        """Reload target evidence, sign the full CAS mutation, and publish."""

        if result.document is None:
            raise ValueError("RELEASE_TARGET_CONFORMANCE_IDENTITY_MISMATCH")
        resolved = self.artifact_resolver.resolve(
            artifact_reference,
            expected_target_id=result.document.target.robot_id,
        )
        report = resolved.report
        compiler_conformance = ConformanceReport(
            c1_dsl="PASS",
            c2_evidence="PASS",
            c3_compile="PASS",
            c4_behavior="PASS",
            diagnostics=report.diagnostics,
        )
        release, transaction = self._publish_verified_report(
            result,
            compiler_conformance,
            report,
            target_fingerprint=report.target_fingerprint,
            compiler_version=report.compiler_version,
            target_compile_artifact_digest=report.compile_artifact_digest,
            compile_context_digest=report.context_digest,
            journey_session_id=report.journey_session_id,
            confirmation_receipt_digest=report.confirmation_receipt_digest,
            target_conformance_artifact=resolved.reference,
        )
        if transaction.target_signature is None:
            raise ReleaseCatalogError("RELEASE_TARGET_SIGNATURE_REQUIRED")
        return ReleasePublicationReceipt(
            release_digest=tool_release_digest(release),
            catalog_sequence=transaction.mutation.sequence,
            catalog_transaction_digest=transaction.transaction_digest,
            catalog_mutation=transaction.mutation,
            target_signature=transaction.target_signature,
            target_conformance_artifact=resolved.reference,
            release=release,
        )

    def current(self, tool_id: str) -> tuple[str, ToolRelease] | None:
        """Fail closed if Catalog, target proof, or Mapping freshness changes."""

        head_before = self.catalog_store.head().transaction_digest
        current = self._current_unchecked(tool_id)
        if current is None:
            if self.catalog_store.head().transaction_digest != head_before:
                raise ReleaseCatalogError(
                    "RELEASE_CATALOG_CHANGED_DURING_VALIDATION"
                )
            return None
        digest, release = current
        if release.status == "PUBLISHED":
            self._require_trusted_release_artifacts(digest, release)
            self._require_release_mapping_active(release)
        head_after = self.catalog_store.head().transaction_digest
        current_after = self._current_unchecked(tool_id)
        if (
            head_after != head_before
            or current_after is None
            or current_after[0] != digest
            or current_after[1].status != release.status
        ):
            raise ReleaseCatalogError("RELEASE_CATALOG_CHANGED_DURING_VALIDATION")
        return digest, release

    def rollback(self, tool_id: str, release_digest: str) -> ToolRelease:
        """Revalidate immutable target evidence before a signed rollback."""

        release = self.load(release_digest)
        if release.tool_id != tool_id:
            raise ValueError("RELEASE_TOOL_MISMATCH")
        self._require_trusted_release_artifacts(release_digest, release)
        return super().rollback(tool_id, release_digest)

    def _commit_catalog_mutation(
        self,
        mutation: CatalogMutation,
        *,
        receipt_digest: str | None = None,
        mapping_identity: MappingAdmissionIdentity | None = None,
    ) -> CatalogTransaction:
        statement = mutation.model_dump(mode="json")
        try:
            raw_signature = self.target_signer.sign(
                target_id=mutation.target_id,
                statement=statement,
            )
            signature = TargetReleaseSignature.model_validate(
                raw_signature.model_dump(mode="python")
                if isinstance(raw_signature, TargetReleaseSignature)
                else raw_signature
            )
        except Exception as exc:  # noqa: BLE001 - external signers fail closed
            raise ReleaseCatalogError("RELEASE_TARGET_SIGNING_FAILED") from exc

        def commit() -> CatalogTransaction:
            return self.catalog_store.commit(
                mutation,
                target_signature=signature,
            )

        if receipt_digest is None and mapping_identity is None:
            return commit()
        if receipt_digest is None or mapping_identity is None:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_STORE_REQUIRED")
        _, transaction = self.admission_gate.commit_if_active(
            receipt_digest,
            mapping_identity,
            commit,
        )
        if not isinstance(transaction, CatalogTransaction):
            raise ReleaseCatalogError("RELEASE_CATALOG_COMMIT_INVALID")
        return transaction

    def _require_trusted_release_artifacts(
        self,
        release_digest: str,
        release: ToolRelease,
    ) -> None:
        lineage = release.mapping_admission
        if (
            lineage is None
            or release.target_id is None
            or release.target_conformance_digest is None
        ):
            raise ValueError("RELEASE_TRUSTED_CONFORMANCE_REFERENCE_REQUIRED")
        binding = self._load_release_artifact_binding(release_digest)
        reference = binding.artifact_reference
        if (
            binding.target_id != release.target_id
            or binding.journey_session_id != lineage.journey_session_id
            or binding.target_conformance_digest
            != release.target_conformance_digest
        ):
            raise ValueError("RELEASE_TARGET_CONFORMANCE_IDENTITY_MISMATCH")
        resolved = self.artifact_resolver.resolve(
            reference,
            expected_target_id=release.target_id,
            expected_journey_session_id=lineage.journey_session_id,
        )
        report = resolved.report
        expected = {
            "tool_id": release.tool_id,
            "operation_kind": release.operation_kind,
            "target_id": release.target_id,
            "target_fingerprint": release.target_fingerprint,
            "target_identity_digest": lineage.target_identity_digest,
            "evidence_digest": release.probe_evidence_digest,
            "dsl_digest": release.dsl_digest,
            "context_digest": release.compile_context_digest,
            "ir_digest": release.ir_digest,
            "bundle_digest": release.generated_bundle_digest,
            "compiler_version": release.compiler_version,
            "journey_session_id": lineage.journey_session_id,
            "confirmation_receipt_digest": (
                release.mapping_confirmation_receipt_digest
            ),
        }
        if (
            resolved.reference != reference
            or reference.target_conformance_digest
            != release.target_conformance_digest
            or any(getattr(report, field) != value for field, value in expected.items())
        ):
            raise ValueError("RELEASE_TARGET_CONFORMANCE_IDENTITY_MISMATCH")

    def _prepare_release_artifacts(
        self,
        release_digest: str,
        release: ToolRelease,
        reference: TargetConformanceArtifactReference | None,
    ) -> None:
        if (
            reference is None
            or release.target_id is None
            or release.mapping_admission is None
            or release.target_conformance_digest is None
        ):
            raise ValueError("RELEASE_TRUSTED_CONFORMANCE_REFERENCE_REQUIRED")
        binding = ReleaseTargetConformanceBinding(
            release_digest=release_digest,
            target_id=release.target_id,
            journey_session_id=release.mapping_admission.journey_session_id,
            target_conformance_digest=release.target_conformance_digest,
            artifact_reference=reference,
        )
        self._assert_release_artifacts_directory(create=True)
        path = self.release_artifacts / f"{release_digest[7:]}.json"
        encoded = json.dumps(
            binding.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        from rolo.core.persistence import interprocess_lock

        with interprocess_lock(
            self.release_artifacts / "release-target-artifact.locked",
            stale_after_s=None,
        ):
            self._assert_release_artifacts_directory(create=True)
            if self._is_linklike(path):
                raise ReleaseCatalogError("RELEASE_TARGET_ARTIFACT_PATH_UNTRUSTED")
            if path.exists():
                try:
                    if not path.is_file() or path.stat().st_nlink != 1:
                        raise OSError("untrusted artifact binding")
                    existing = ReleaseTargetConformanceBinding.model_validate(
                        loads_unique_json(path.read_text(encoding="utf-8"))
                    )
                except (OSError, ValueError) as exc:
                    raise ReleaseCatalogError(
                        "RELEASE_TARGET_ARTIFACT_BINDING_INVALID"
                    ) from exc
                if existing != binding:
                    raise ReleaseCatalogError(
                        "RELEASE_TARGET_ARTIFACT_BINDING_CONFLICT"
                    )
                return
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".release-target-artifact-",
                dir=self.release_artifacts,
            )
            temporary = Path(temporary_name)
            try:
                with os.fdopen(
                    descriptor,
                    "w",
                    encoding="utf-8",
                    newline="",
                ) as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.link(temporary, path, follow_symlinks=False)
                except (FileExistsError, OSError) as exc:
                    raise ReleaseCatalogError(
                        "RELEASE_TARGET_ARTIFACT_BINDING_PUBLISH_FAILED"
                    ) from exc
                self._fsync_directory(self.release_artifacts)
            finally:
                temporary.unlink(missing_ok=True)
                self._fsync_directory(self.release_artifacts)
            if path.stat().st_nlink != 1:
                raise ReleaseCatalogError("RELEASE_TARGET_ARTIFACT_PATH_UNTRUSTED")

    def _load_release_artifact_binding(
        self,
        release_digest: str,
    ) -> ReleaseTargetConformanceBinding:
        self._assert_release_artifacts_directory(create=False)
        path = self.release_artifacts / f"{release_digest[7:]}.json"
        try:
            if (
                self._is_linklike(path)
                or not path.is_file()
                or path.stat().st_nlink != 1
                or path.stat().st_size > 64 * 1024
            ):
                raise OSError("untrusted artifact binding")
            binding = ReleaseTargetConformanceBinding.model_validate(
                loads_unique_json(path.read_text(encoding="utf-8"))
            )
        except (OSError, ValueError) as exc:
            raise ReleaseCatalogError(
                "RELEASE_TARGET_ARTIFACT_BINDING_INVALID"
            ) from exc
        if binding.release_digest != release_digest:
            raise ReleaseCatalogError("RELEASE_TARGET_ARTIFACT_BINDING_MISMATCH")
        return binding

    def _assert_release_artifacts_directory(self, *, create: bool) -> None:
        if self._is_linklike(self.release_artifacts):
            raise ReleaseCatalogError("RELEASE_TARGET_ARTIFACT_PATH_UNTRUSTED")
        if create:
            try:
                self.release_artifacts.mkdir(parents=False, exist_ok=True)
            except OSError as exc:
                raise ReleaseCatalogError(
                    "RELEASE_TARGET_ARTIFACT_PATH_UNTRUSTED"
                ) from exc
        if not self.release_artifacts.is_dir():
            raise ReleaseCatalogError("RELEASE_TARGET_ARTIFACT_PATH_UNTRUSTED")
        metadata = self.release_artifacts.stat()
        identity = (metadata.st_dev, metadata.st_ino)
        if self._release_artifacts_directory_identity is None:
            self._release_artifacts_directory_identity = identity
        elif self._release_artifacts_directory_identity != identity:
            raise ReleaseCatalogError(
                "RELEASE_TARGET_ARTIFACT_DIRECTORY_REPLACED"
            )

    @staticmethod
    def _require_provider(provider: object, authority: str, code: str) -> None:
        if (
            getattr(provider, "authority_class", None) != authority
            or re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
                str(getattr(provider, "provider_id", "")),
            )
            is None
        ):
            raise ValueError(code)
