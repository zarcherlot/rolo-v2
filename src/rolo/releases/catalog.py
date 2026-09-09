"""Append-only, CAS-fenced Release Catalog transactions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator

from rolo.core.persistence import atomic_write_text, interprocess_lock
from rolo.dsl.models import StrictModel
from rolo.dsl.parser import loads_unique_json

from .signature import (
    TargetReleaseSignature,
    TargetSignatureVerifier,
    require_target_signature,
    statement_digest,
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_MAX_TRANSACTION_BYTES = 4 * 1024 * 1024
_MAX_CATALOG_LOG_BYTES = 128 * 1024 * 1024
_MAX_CATALOG_SNAPSHOT_BYTES = 16 * 1024 * 1024


class ReleaseCatalogError(ValueError):
    """A Catalog chain, CAS, or immutable entry is invalid."""


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
        raise ReleaseCatalogError("RELEASE_CATALOG_UNREADABLE_PATH") from exc
    return bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _lexical_absolute(path: str | Path) -> Path:
    """Make a path absolute without following any existing link component."""

    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _directory_identity(path: Path) -> tuple[int, int]:
    metadata = path.stat()
    return metadata.st_dev, metadata.st_ino


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


def _require_regular_or_absent(path: Path) -> None:
    if _is_linklike(path):
        raise ReleaseCatalogError("RELEASE_CATALOG_UNTRUSTED_PATH")
    try:
        metadata = path.stat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ReleaseCatalogError("RELEASE_CATALOG_UNREADABLE_PATH") from exc
    if not path.is_file() or metadata.st_nlink != 1:
        raise ReleaseCatalogError("RELEASE_CATALOG_UNTRUSTED_PATH")


def _canonical(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def release_payload_digest(payload: Mapping[str, Any]) -> str:
    """Match ``tool_release_digest`` without importing the publisher module."""

    encoded = json.dumps(dict(payload), sort_keys=True, allow_nan=False).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class CatalogMutation(StrictModel):
    """CAS proposal whose complete identity can be signed by the target."""

    schema_version: Literal["rolo-release-catalog-mutation/v1"] = (
        "rolo-release-catalog-mutation/v1"
    )
    sequence: int = Field(strict=True, ge=1)
    previous_transaction_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    expected_current_release_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    operation: Literal["PUBLISH", "MARK_STALE", "ROLLBACK"]
    tool_id: str = Field(min_length=1, max_length=256)
    target_id: str = Field(pattern=_IDENTIFIER)
    release_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    context_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    release: dict[str, Any]
    status: Literal["PUBLISHED", "STALE"]
    stale_reasons: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_identity(self) -> CatalogMutation:
        if self.release.get("tool_id") != self.tool_id:
            raise ValueError("release tool identity differs from Catalog mutation")
        if self.release.get("target_id") != self.target_id:
            raise ValueError("release target identity differs from Catalog mutation")
        if self.release.get("compile_context_digest") != self.context_digest:
            raise ValueError("release Context identity differs from Catalog mutation")
        if self.release.get("generated_bundle_digest") != self.manifest_digest:
            raise ValueError("release manifest identity differs from Catalog mutation")
        if release_payload_digest(self.release) != self.release_digest:
            raise ValueError("release payload digest differs from Catalog mutation")
        if self.operation == "MARK_STALE":
            if (
                self.status != "STALE"
                or not self.stale_reasons
                or self.expected_current_release_digest != self.release_digest
            ):
                raise ValueError(
                    "MARK_STALE requires the current Release and at least one reason"
                )
        elif self.status != "PUBLISHED" or self.stale_reasons:
            raise ValueError("current Release mutation cannot carry stale state")
        if any(
            not reason
            or reason != reason.strip()
            or len(reason) > 256
            or any(ord(character) < 32 for character in reason)
            for reason in self.stale_reasons
        ):
            raise ValueError("Catalog stale reason is invalid")
        if len(set(self.stale_reasons)) != len(self.stale_reasons):
            raise ValueError("Catalog stale reasons must be unique")
        return self

    @property
    def signing_digest(self) -> str:
        return statement_digest(self.model_dump(mode="json"))


class CatalogTransaction(StrictModel):
    schema_version: Literal["rolo-release-catalog-transaction/v1"] = (
        "rolo-release-catalog-transaction/v1"
    )
    mutation: CatalogMutation
    target_signature: TargetReleaseSignature | None = None
    transaction_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_digest(self) -> CatalogTransaction:
        expected = self.compute_digest(self.mutation, self.target_signature)
        if self.transaction_digest != expected:
            raise ValueError("Catalog transaction digest mismatch")
        return self

    @staticmethod
    def compute_digest(
        mutation: CatalogMutation,
        target_signature: TargetReleaseSignature | None,
    ) -> str:
        payload = {
            "schema_version": "rolo-release-catalog-transaction/v1",
            "mutation": mutation.model_dump(mode="json"),
            "target_signature": (
                target_signature.model_dump(mode="json")
                if target_signature is not None
                else None
            ),
        }
        return "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()

    @classmethod
    def build(
        cls,
        mutation: CatalogMutation,
        target_signature: TargetReleaseSignature | None,
    ) -> CatalogTransaction:
        return cls(
            mutation=mutation,
            target_signature=target_signature,
            transaction_digest=cls.compute_digest(mutation, target_signature),
        )


@dataclass(frozen=True)
class CatalogHead:
    sequence: int
    transaction_digest: str | None


class ReleaseCatalog:
    """Linearizable current pointers backed by an append-only hash chain.

    Selecting an older immutable Release is represented by a new ``ROLLBACK``
    transaction at a higher sequence; truncating or replaying history never
    moves the accepted head backwards.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        signature_verifier: TargetSignatureVerifier | None = None,
        require_target_signatures: bool = True,
    ) -> None:
        self.root = _lexical_absolute(root)
        self._directory_identities: dict[str, tuple[int, int]] = {}
        self._incomplete_log_prefix_bytes: int | None = None
        self._assert_trusted_root(create=False)
        self.catalog_path = self.root / "tool-catalog.json"
        self.transactions_path = self.root / "catalog-transactions.jsonl"
        self.lock_path = self.root / "catalog-transaction.locked"
        self.signature_verifier = signature_verifier
        self.require_target_signatures = require_target_signatures

    def head(self) -> CatalogHead:
        self._assert_trusted_root(create=True)
        with interprocess_lock(self.lock_path, stale_after_s=None):
            self._assert_trusted_root(create=True)
            records = self._read_records_unlocked()
            self._read_snapshot_unlocked(records)
            return CatalogHead(
                sequence=len(records),
                transaction_digest=(records[-1].transaction_digest if records else None),
            )

    def snapshot(self) -> dict[str, Any]:
        self._assert_trusted_root(create=True)
        with interprocess_lock(self.lock_path, stale_after_s=None):
            self._assert_trusted_root(create=True)
            records = self._read_records_unlocked()
            return self._read_snapshot_unlocked(records)

    def propose(
        self,
        *,
        operation: Literal["PUBLISH", "MARK_STALE", "ROLLBACK"],
        tool_id: str,
        target_id: str,
        release_digest: str,
        context_digest: str,
        manifest_digest: str,
        release: Mapping[str, Any],
        expected_catalog_head_digest: str | None,
        expected_current_release_digest: str | None,
        stale_reasons: tuple[str, ...] = (),
    ) -> CatalogMutation:
        self._assert_trusted_root(create=True)
        with interprocess_lock(self.lock_path, stale_after_s=None):
            self._assert_trusted_root(create=True)
            records = self._read_records_unlocked()
            snapshot = self._read_snapshot_unlocked(records)
            actual_head = records[-1].transaction_digest if records else None
            if expected_catalog_head_digest != actual_head:
                raise ReleaseCatalogError("RELEASE_CATALOG_CAS_FAILED")
            entry = snapshot.get("tools", {}).get(tool_id)
            actual_current = entry.get("current") if isinstance(entry, dict) else None
            if expected_current_release_digest != actual_current:
                raise ReleaseCatalogError("RELEASE_CURRENT_CAS_FAILED")
            return CatalogMutation(
                sequence=len(records) + 1,
                previous_transaction_digest=actual_head,
                expected_current_release_digest=actual_current,
                operation=operation,
                tool_id=tool_id,
                target_id=target_id,
                release_digest=release_digest,
                context_digest=context_digest,
                manifest_digest=manifest_digest,
                release=dict(release),
                status="STALE" if operation == "MARK_STALE" else "PUBLISHED",
                stale_reasons=tuple(dict.fromkeys(stale_reasons)),
            )

    def commit(
        self,
        mutation: CatalogMutation | Mapping[str, Any],
        *,
        target_signature: TargetReleaseSignature | Mapping[str, Any] | None = None,
    ) -> CatalogTransaction:
        try:
            candidate = CatalogMutation.model_validate(
                mutation.model_dump(mode="python")
                if isinstance(mutation, CatalogMutation)
                else mutation
            )
        except ValueError as exc:
            raise ReleaseCatalogError("RELEASE_CATALOG_MUTATION_INVALID") from exc
        signature: TargetReleaseSignature | None = None
        if target_signature is not None or self.require_target_signatures:
            signature = require_target_signature(
                candidate.model_dump(mode="json"),
                target_signature,
                self.signature_verifier,
                expected_target_id=candidate.target_id,
            )
        transaction = CatalogTransaction.build(candidate, signature)
        encoded = json.dumps(
            transaction.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        if len(encoded.encode("utf-8")) > _MAX_TRANSACTION_BYTES:
            raise ReleaseCatalogError("RELEASE_CATALOG_TRANSACTION_TOO_LARGE")

        self._assert_trusted_root(create=True)
        with interprocess_lock(self.lock_path, stale_after_s=None):
            self._assert_trusted_root(create=True)
            records = self._read_records_unlocked()
            snapshot = self._read_snapshot_unlocked(records)
            if records and records[-1].transaction_digest == transaction.transaction_digest:
                self._write_snapshot_unlocked(self._snapshot_from_records(records))
                return records[-1]
            if any(
                record.transaction_digest == transaction.transaction_digest
                for record in records
            ):
                raise ReleaseCatalogError("RELEASE_CATALOG_TRANSACTION_REPLAYED")
            actual_head = records[-1].transaction_digest if records else None
            if candidate.sequence != len(records) + 1 or candidate.previous_transaction_digest != actual_head:
                raise ReleaseCatalogError("RELEASE_CATALOG_CAS_FAILED")
            current = snapshot.get("tools", {}).get(candidate.tool_id)
            actual_current = current.get("current") if isinstance(current, dict) else None
            if candidate.expected_current_release_digest != actual_current:
                raise ReleaseCatalogError("RELEASE_CURRENT_CAS_FAILED")
            if not records and snapshot.get("tools"):
                raise ReleaseCatalogError("RELEASE_CATALOG_LEGACY_MIGRATION_REQUIRED")

            self.root.mkdir(parents=True, exist_ok=True)
            _require_regular_or_absent(self.transactions_path)
            _require_regular_or_absent(self.catalog_path)
            with self.transactions_path.open("a", encoding="utf-8", newline="") as stream:
                stream.write(encoded + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            _fsync_directory(self.root)
            committed = [*records, transaction]
            self._write_snapshot_unlocked(self._snapshot_from_records(committed))
            return transaction

    def _read_records_unlocked(self) -> list[CatalogTransaction]:
        self._assert_trusted_root(create=True)
        self._incomplete_log_prefix_bytes = None
        _require_regular_or_absent(self.transactions_path)
        try:
            if self.transactions_path.stat().st_size > _MAX_CATALOG_LOG_BYTES:
                raise ReleaseCatalogError("RELEASE_CATALOG_LOG_TOO_LARGE")
            raw = self.transactions_path.read_bytes()
        except FileNotFoundError:
            return []
        except ReleaseCatalogError:
            raise
        except OSError as exc:
            raise ReleaseCatalogError("RELEASE_CATALOG_LOG_UNREADABLE") from exc
        incomplete_tail = bool(raw) and not raw.endswith(b"\n")
        complete_bytes = raw
        if incomplete_tail:
            boundary = raw.rfind(b"\n") + 1
            if len(raw) - boundary > _MAX_TRANSACTION_BYTES:
                raise ReleaseCatalogError("RELEASE_CATALOG_LOG_INVALID")
            complete_bytes = raw[:boundary]
            self._incomplete_log_prefix_bytes = len(complete_bytes)
        try:
            lines = complete_bytes.decode("utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise ReleaseCatalogError("RELEASE_CATALOG_LOG_INVALID") from exc
        records: list[CatalogTransaction] = []
        previous: str | None = None
        for index, line in enumerate(lines, start=1):
            if not line or len(line.encode("utf-8")) > _MAX_TRANSACTION_BYTES:
                raise ReleaseCatalogError("RELEASE_CATALOG_LOG_INVALID")
            try:
                payload = loads_unique_json(line)
                record = CatalogTransaction.model_validate(payload)
            except (TypeError, ValueError) as exc:
                raise ReleaseCatalogError("RELEASE_CATALOG_LOG_INVALID") from exc
            if (
                record.mutation.sequence != index
                or record.mutation.previous_transaction_digest != previous
            ):
                raise ReleaseCatalogError("RELEASE_CATALOG_CHAIN_INVALID")
            self._verify_record_signature(record)
            records.append(record)
            previous = record.transaction_digest
        return records

    def _verify_record_signature(self, record: CatalogTransaction) -> None:
        if record.target_signature is None and not self.require_target_signatures:
            return
        require_target_signature(
            record.mutation.model_dump(mode="json"),
            record.target_signature,
            self.signature_verifier,
            expected_target_id=record.mutation.target_id,
        )

    def _read_snapshot_unlocked(
        self,
        records: list[CatalogTransaction],
    ) -> dict[str, Any]:
        self._assert_trusted_root(create=True)
        derived = self._snapshot_from_records(records)
        _require_regular_or_absent(self.catalog_path)
        try:
            if self.catalog_path.stat().st_size > _MAX_CATALOG_SNAPSHOT_BYTES:
                raise ReleaseCatalogError("RELEASE_CATALOG_SNAPSHOT_TOO_LARGE")
            raw = loads_unique_json(self.catalog_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            self._recover_incomplete_log_tail_unlocked()
            if records:
                self._write_snapshot_unlocked(derived)
            return derived
        except ReleaseCatalogError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise ReleaseCatalogError("RELEASE_CATALOG_SNAPSHOT_INVALID") from exc
        if not isinstance(raw, dict) or raw.get("schema_version") != "rolo-tool-catalog/v1" or not isinstance(raw.get("tools"), dict):
            raise ReleaseCatalogError("RELEASE_CATALOG_SNAPSHOT_INVALID")
        if not records:
            if self.require_target_signatures and raw != derived:
                raise ReleaseCatalogError(
                    "RELEASE_CATALOG_LEGACY_MIGRATION_REQUIRED"
                )
            self._recover_incomplete_log_tail_unlocked()
            return raw
        for length in range(len(records), -1, -1):
            if raw == self._snapshot_from_records(records[:length]):
                self._recover_incomplete_log_tail_unlocked()
                if raw != derived:
                    self._write_snapshot_unlocked(derived)
                return derived
        raise ReleaseCatalogError("RELEASE_CATALOG_SNAPSHOT_MISMATCH")

    def _recover_incomplete_log_tail_unlocked(self) -> None:
        prefix_bytes = self._incomplete_log_prefix_bytes
        if prefix_bytes is None:
            return
        # An append is committed only once its terminating newline is durable.
        # The snapshot must first have authenticated the complete signed prefix;
        # never truncate bytes when the snapshot is ahead or inconsistent.
        try:
            _require_regular_or_absent(self.transactions_path)
            with self.transactions_path.open("r+b") as stream:
                stream.truncate(prefix_bytes)
                stream.flush()
                os.fsync(stream.fileno())
            _fsync_directory(self.root)
        except OSError as exc:
            raise ReleaseCatalogError("RELEASE_CATALOG_LOG_RECOVERY_FAILED") from exc
        finally:
            self._incomplete_log_prefix_bytes = None

    @staticmethod
    def _snapshot_from_records(
        records: list[CatalogTransaction],
    ) -> dict[str, Any]:
        tools: dict[str, Any] = {}
        for transaction in records:
            mutation = transaction.mutation
            entry: dict[str, Any] = {
                "current": mutation.release_digest,
                "release": mutation.release,
            }
            if mutation.status == "STALE":
                entry.update(
                    {
                        "status": "STALE",
                        "stale_reasons": list(mutation.stale_reasons),
                    }
                )
            tools[mutation.tool_id] = entry
        snapshot: dict[str, Any] = {
            "schema_version": "rolo-tool-catalog/v1",
            "tools": tools,
        }
        if records:
            snapshot.update(
                {
                    "catalog_sequence": len(records),
                    "catalog_head_digest": records[-1].transaction_digest,
                }
            )
        return snapshot

    def _write_snapshot_unlocked(self, snapshot: dict[str, Any]) -> None:
        self._assert_trusted_root(create=True)
        _require_regular_or_absent(self.catalog_path)
        atomic_write_text(
            self.catalog_path,
            json.dumps(
                snapshot,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            + "\n",
            acquire_lock=False,
        )

    def _assert_trusted_root(self, *, create: bool) -> None:
        """Reject link traversal and directory replacement on every I/O."""

        chain = [*reversed(self.root.parents), self.root]
        for component in chain:
            if _is_linklike(component):
                raise ReleaseCatalogError("RELEASE_CATALOG_UNTRUSTED_PATH")
            try:
                metadata = component.stat()
            except FileNotFoundError:
                break
            except OSError as exc:
                raise ReleaseCatalogError("RELEASE_CATALOG_UNREADABLE_PATH") from exc
            if not component.is_dir():
                raise ReleaseCatalogError("RELEASE_CATALOG_UNTRUSTED_PATH")
            identity = (metadata.st_dev, metadata.st_ino)
            key = os.path.normcase(os.fspath(component))
            expected = self._directory_identities.setdefault(key, identity)
            if expected != identity:
                raise ReleaseCatalogError("RELEASE_CATALOG_DIRECTORY_REPLACED")
        if not create:
            return
        try:
            self.root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ReleaseCatalogError("RELEASE_CATALOG_ROOT_CREATE_FAILED") from exc
        # Re-run after creation so every newly created component is pinned.
        for component in chain:
            if _is_linklike(component):
                raise ReleaseCatalogError("RELEASE_CATALOG_UNTRUSTED_PATH")
            try:
                metadata = component.stat()
            except OSError as exc:
                raise ReleaseCatalogError("RELEASE_CATALOG_UNREADABLE_PATH") from exc
            if not component.is_dir():
                raise ReleaseCatalogError("RELEASE_CATALOG_UNTRUSTED_PATH")
            identity = _directory_identity(component)
            key = os.path.normcase(os.fspath(component))
            expected = self._directory_identities.setdefault(key, identity)
            if expected != identity:
                raise ReleaseCatalogError("RELEASE_CATALOG_DIRECTORY_REPLACED")


__all__ = [
    "CatalogHead",
    "CatalogMutation",
    "CatalogTransaction",
    "ReleaseCatalog",
    "ReleaseCatalogError",
    "release_payload_digest",
]
