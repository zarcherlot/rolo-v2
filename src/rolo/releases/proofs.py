"""Trusted reload of target-owned Release conformance artifacts.

The production publisher accepts only an opaque cache reference.  It never
accepts a caller-provided ``TargetConformanceReport`` as evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import Field, model_validator

from rolo.dsl.models import StrictModel
from rolo.dsl.parser import loads_unique_json
from rolo.dsl.target_conformance import TargetConformanceReport

TRUSTED_TARGET_CONFORMANCE_AUTHORITY = "PRODUCTION_TRUSTED_ARTIFACT_STORE"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_EXPECTED_FILES = frozenset(
    {
        "result.json",
        "report.json",
        "t1-target-resolve.json",
        "t2-bundle-build.json",
        "t3-runtime-behavior.json",
        "t4-release-integrity.json",
    }
)
_MAX_RESULT_BYTES = 4 * 1024 * 1024
_MAX_EVIDENCE_BYTES = 1024 * 1024


class TargetConformanceArtifactError(ValueError):
    """A trusted target artifact snapshot failed a closed verification."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class TargetConformanceArtifactReference(StrictModel):
    """Opaque, digest-bound locator into a target-owned cache."""

    schema_version: Literal["rolo-target-conformance-artifact-reference/v1"] = (
        "rolo-target-conformance-artifact-reference/v1"
    )
    cache_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_conformance_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ResolvedTargetConformanceArtifacts(StrictModel):
    """Report reconstructed from a verified target-owned artifact set."""

    reference: TargetConformanceArtifactReference
    report: TargetConformanceReport
    result_artifact_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def bind_reference(self) -> ResolvedTargetConformanceArtifacts:
        if self.reference.target_conformance_digest != _json_digest(
            self.report.model_dump(mode="json")
        ):
            raise ValueError("artifact reference does not identify report")
        return self


class ReleaseTargetConformanceBinding(StrictModel):
    """Immutable sidecar binding a Release digest to its target cache ref."""

    schema_version: Literal["rolo-release-target-conformance-binding/v1"] = (
        "rolo-release-target-conformance-binding/v1"
    )
    release_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    target_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    journey_session_id: str = Field(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
    )
    target_conformance_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    artifact_reference: TargetConformanceArtifactReference

    @model_validator(mode="after")
    def bind_report_digest(self) -> ReleaseTargetConformanceBinding:
        if (
            self.artifact_reference.target_conformance_digest
            != self.target_conformance_digest
        ):
            raise ValueError("release artifact binding digest mismatch")
        return self


class TrustedTargetConformanceArtifactResolver(Protocol):
    """Deployment-owned resolver accepted by ``ProductionReleasePublisher``."""

    provider_id: str
    authority_class: str

    def resolve(
        self,
        reference: TargetConformanceArtifactReference | Mapping[str, Any],
        *,
        expected_target_id: str,
        expected_journey_session_id: str | None = None,
    ) -> ResolvedTargetConformanceArtifacts: ...


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _json_digest(value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


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
        raise TargetConformanceArtifactError(
            "RELEASE_TARGET_ARTIFACT_PATH_UNREADABLE"
        ) from exc
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


class TargetConformanceArtifactStore:
    """Read-only verifier for targetd's immutable conformance cache layout.

    Trust in this boundary depends on deploying ``root`` under target-owned
    filesystem permissions.  The reader additionally rejects links, hardlinks,
    directory replacement, non-canonical evidence, and digest substitution.
    """

    authority_class = TRUSTED_TARGET_CONFORMANCE_AUTHORITY

    def __init__(self, root: str | Path, *, provider_id: str) -> None:
        if not isinstance(provider_id, str) or _IDENTIFIER.fullmatch(provider_id) is None:
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_ARTIFACT_PROVIDER_INVALID"
            )
        self.provider_id = provider_id
        self.root = Path(os.path.abspath(os.fspath(Path(root).expanduser())))
        self._directory_identities: dict[str, tuple[int, int]] = {}
        if self.root.exists():
            self._require_directory(self.root, "root")

    def resolve(
        self,
        reference: TargetConformanceArtifactReference | Mapping[str, Any],
        *,
        expected_target_id: str,
        expected_journey_session_id: str | None = None,
    ) -> ResolvedTargetConformanceArtifacts:
        try:
            candidate = TargetConformanceArtifactReference.model_validate(
                reference.model_dump(mode="python")
                if isinstance(reference, TargetConformanceArtifactReference)
                else reference
            )
        except (TypeError, ValueError) as exc:
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_ARTIFACT_REFERENCE_INVALID"
            ) from exc
        if _IDENTIFIER.fullmatch(expected_target_id) is None:
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_ARTIFACT_TARGET_INVALID"
            )
        if expected_journey_session_id is not None and (
            _IDENTIFIER.fullmatch(expected_journey_session_id) is None
        ):
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_ARTIFACT_SESSION_INVALID"
            )

        artifact_dir = self.root / candidate.cache_key
        conformance_dir = artifact_dir / "target-conformance"
        self._require_directory(self.root, "root")
        self._require_directory(artifact_dir, candidate.cache_key)
        self._require_directory(
            conformance_dir,
            f"{candidate.cache_key}/target-conformance",
        )
        try:
            names = {item.name for item in conformance_dir.iterdir()}
        except OSError as exc:
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_ARTIFACT_PATH_UNREADABLE"
            ) from exc
        if names != _EXPECTED_FILES:
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_ARTIFACT_SET_INVALID"
            )

        result, result_raw = self._read_json(
            conformance_dir / "result.json",
            max_bytes=_MAX_RESULT_BYTES,
        )
        report_payload, report_raw = self._read_json(
            conformance_dir / "report.json",
            max_bytes=_MAX_EVIDENCE_BYTES,
        )
        try:
            report = TargetConformanceReport.model_validate(report_payload)
        except ValueError as exc:
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_CONFORMANCE_REPORT_INVALID"
            ) from exc
        canonical_report = report.model_dump(mode="json")
        report_digest = _json_digest(canonical_report)
        if report_payload != canonical_report or hashlib.sha256(report_raw).hexdigest() != report_digest[7:]:
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_CONFORMANCE_REPORT_NONCANONICAL"
            )
        if not report.passed:
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_CONFORMANCE_FAILED"
            )
        if (
            report_digest != candidate.target_conformance_digest
            or result.get("target_conformance_digest") != report_digest
            or result.get("target_conformance_report") != canonical_report
        ):
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_CONFORMANCE_DIGEST_MISMATCH"
            )
        result_artifact_digest = result.get("artifact_digest")
        result_body = {
            key: value
            for key, value in result.items()
            if key not in {"artifact_digest", "cache_hit", "conformance_cache_hit"}
        }
        if (
            not isinstance(result_artifact_digest, str)
            or result_artifact_digest != _json_digest(result_body)
            or result.get("phase") != "TARGET_CONFORMANCE"
            or result.get("status") != "PASS"
            or result.get("target_conformance") != "PASS"
            or result.get("cache_key") != candidate.cache_key
            or result.get("conformance_idempotency_key")
            != "sha256:" + candidate.cache_key
        ):
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_CONFORMANCE_RESULT_INVALID"
            )
        del result_raw

        report_result_fields = (
            "tool_id",
            "operation_kind",
            "target_id",
            "target_fingerprint",
            "target_identity_digest",
            "evidence_digest",
            "dsl_digest",
            "context_digest",
            "ir_digest",
            "bundle_digest",
            "compile_artifact_digest",
            "compiler_version",
            "compiler_backend_id",
            "compiler_backend_version",
            "runtime_backend_id",
            "runtime_binding_digest",
            "required_capabilities",
            "required_runtime_capabilities",
            "negotiated_capabilities",
            "journey_session_id",
            "confirmation_receipt_digest",
            "conformance_idempotency_key",
            "diagnostics",
        )
        if any(
            result.get(field) != canonical_report[field]
            for field in report_result_fields
        ):
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_CONFORMANCE_IDENTITY_MISMATCH"
            )
        if report.target_id != expected_target_id:
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_CONFORMANCE_TARGET_MISMATCH"
            )
        if (
            expected_journey_session_id is not None
            and report.journey_session_id != expected_journey_session_id
        ):
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_CONFORMANCE_SESSION_MISMATCH"
            )

        expected_proofs = self._expected_proofs(canonical_report)
        if tuple(proof.gate for proof in report.proofs) != tuple(expected_proofs):
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_PROOF_SET_INVALID"
            )
        for proof in report.proofs:
            evidence_ref, expected_payload = expected_proofs[proof.gate]
            if proof.status != "PASS" or proof.evidence_ref != evidence_ref:
                raise TargetConformanceArtifactError(
                    "RELEASE_TARGET_PROOF_SET_INVALID"
                )
            proof_payload, proof_raw = self._read_json(
                conformance_dir / Path(evidence_ref).name,
                max_bytes=_MAX_EVIDENCE_BYTES,
            )
            if proof_payload != expected_payload:
                raise TargetConformanceArtifactError(
                    "RELEASE_TARGET_PROOF_IDENTITY_MISMATCH"
                )
            if (
                _json_digest(proof_payload) != proof.evidence_digest
                or hashlib.sha256(proof_raw).hexdigest()
                != proof.evidence_digest[7:]
            ):
                raise TargetConformanceArtifactError(
                    "RELEASE_TARGET_PROOF_DIGEST_MISMATCH"
                )

        self._require_directory(self.root, "root")
        self._require_directory(artifact_dir, candidate.cache_key)
        self._require_directory(
            conformance_dir,
            f"{candidate.cache_key}/target-conformance",
        )
        return ResolvedTargetConformanceArtifacts(
            reference=candidate,
            report=report,
            result_artifact_digest=result_artifact_digest,
        )

    @staticmethod
    def _expected_proofs(
        report: dict[str, Any],
    ) -> dict[str, tuple[str, dict[str, object]]]:
        return {
            "T1": (
                "target-conformance/t1-target-resolve.json",
                {
                    "gate": "T1",
                    "status": "PASS",
                    "target_id": report["target_id"],
                    "target_fingerprint": report["target_fingerprint"],
                    "target_identity_digest": report["target_identity_digest"],
                    "context_digest": report["context_digest"],
                    "evidence_digest": report["evidence_digest"],
                    "runtime_backend_id": report["runtime_backend_id"],
                    "runtime_binding_digest": report["runtime_binding_digest"],
                    "required_runtime_capabilities": report[
                        "required_runtime_capabilities"
                    ],
                },
            ),
            "T2": (
                "target-conformance/t2-bundle-build.json",
                {
                    "gate": "T2",
                    "status": "PASS",
                    "dsl_digest": report["dsl_digest"],
                    "context_digest": report["context_digest"],
                    "ir_digest": report["ir_digest"],
                    "bundle_digest": report["bundle_digest"],
                    "compile_artifact_digest": report["compile_artifact_digest"],
                    "compiler_backend_id": report["compiler_backend_id"],
                    "compiler_backend_version": report[
                        "compiler_backend_version"
                    ],
                },
            ),
            "T3": (
                "target-conformance/t3-runtime-behavior.json",
                {
                    "gate": "T3",
                    "status": "PASS",
                    "runtime_backend_id": report["runtime_backend_id"],
                    "runtime_binding_digest": report["runtime_binding_digest"],
                    "runtime_result_digest": report["runtime_result_digest"],
                    "required_runtime_capabilities": report[
                        "required_runtime_capabilities"
                    ],
                    "conformance_idempotency_key": report[
                        "conformance_idempotency_key"
                    ],
                },
            ),
            "T4": (
                "target-conformance/t4-release-integrity.json",
                {
                    "gate": "T4",
                    "status": "PASS",
                    "tool_id": report["tool_id"],
                    "operation_kind": report["operation_kind"],
                    "target_identity_digest": report["target_identity_digest"],
                    "dsl_digest": report["dsl_digest"],
                    "context_digest": report["context_digest"],
                    "ir_digest": report["ir_digest"],
                    "bundle_digest": report["bundle_digest"],
                    "confirmation_receipt_digest": report[
                        "confirmation_receipt_digest"
                    ],
                },
            ),
        }

    def _require_directory(self, path: Path, identity_key: str) -> None:
        if _is_linklike(path) or not path.is_dir():
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_ARTIFACT_PATH_UNTRUSTED"
            )
        try:
            metadata = path.stat()
        except OSError as exc:
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_ARTIFACT_PATH_UNREADABLE"
            ) from exc
        identity = (metadata.st_dev, metadata.st_ino)
        previous = self._directory_identities.setdefault(identity_key, identity)
        if previous != identity:
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_ARTIFACT_DIRECTORY_REPLACED"
            )

    @staticmethod
    def _read_json(path: Path, *, max_bytes: int) -> tuple[dict[str, Any], bytes]:
        if _is_linklike(path):
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_ARTIFACT_PATH_UNTRUSTED"
            )
        try:
            with path.open("rb") as stream:
                before = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_size > max_bytes
                ):
                    raise TargetConformanceArtifactError(
                        "RELEASE_TARGET_ARTIFACT_PATH_UNTRUSTED"
                    )
                raw = stream.read(max_bytes + 1)
                after = os.fstat(stream.fileno())
            current = path.stat()
        except TargetConformanceArtifactError:
            raise
        except (OSError, UnicodeError) as exc:
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_ARTIFACT_PATH_UNREADABLE"
            ) from exc
        if (
            len(raw) > max_bytes
            or (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or (before.st_dev, before.st_ino, before.st_size)
            != (current.st_dev, current.st_ino, current.st_size)
            or current.st_nlink != 1
            or _is_linklike(path)
        ):
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_ARTIFACT_CHANGED_DURING_READ"
            )
        try:
            value = loads_unique_json(raw.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_ARTIFACT_JSON_INVALID"
            ) from exc
        if not isinstance(value, dict):
            raise TargetConformanceArtifactError(
                "RELEASE_TARGET_ARTIFACT_JSON_INVALID"
            )
        return value, raw


__all__ = [
    "ReleaseTargetConformanceBinding",
    "ResolvedTargetConformanceArtifacts",
    "TRUSTED_TARGET_CONFORMANCE_AUTHORITY",
    "TargetConformanceArtifactError",
    "TargetConformanceArtifactReference",
    "TargetConformanceArtifactStore",
    "TrustedTargetConformanceArtifactResolver",
]
