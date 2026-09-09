"""Append-only request mappings for restart-safe targetd Trace and Certify.

Both target adapters deliberately accept ``MutableMapping`` for compatibility
with tests.  These implementations provide the deployable filesystem-backed
variant: keys are hashed into bounded filenames, values are immutable, and
every read revalidates the exact serialized request and metadata.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from collections.abc import Iterator, MutableMapping
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from rolo.core.persistence import atomic_write_text, interprocess_lock
from rolo.dsl.parser import loads_unique_json

_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_REQUEST_BYTES = 256 * 1024
_MAX_RECORDS = 10_000


def _reparse(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except FileNotFoundError:
        return False
    import stat

    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


class _RequestEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-targetd-durable-request/v1"] = "rolo-targetd-durable-request/v1"
    kind: Literal["CERTIFY", "TRACE"]
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    request_b64: str = Field(min_length=1, max_length=400_000)
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    timeout_s: float = Field(gt=0, le=300)
    envelope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"envelope_digest"})

    def computed_digest(self) -> str:
        return hashlib.sha256(
            json.dumps(self.unsigned_payload(), ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
        ).hexdigest()

    @model_validator(mode="after")
    def validate_record(self) -> _RequestEnvelope:
        if self.created_at.tzinfo is None:
            raise ValueError("durable request time must include timezone")
        try:
            request = base64.b64decode(self.request_b64, validate=True)
        except ValueError as exc:
            raise ValueError("durable request encoding is invalid") from exc
        if len(request) > _MAX_REQUEST_BYTES or hashlib.sha256(request).hexdigest() != self.content_digest:
            raise ValueError("durable request content digest mismatch")
        if self.envelope_digest != self.computed_digest():
            raise ValueError("durable request envelope digest mismatch")
        return self


class _DurableRequestStore(MutableMapping[str, Any]):
    kind: Literal["CERTIFY", "TRACE"]
    durable_targetd_request_store = True

    def __init__(self, root: str | Path, *, max_records: int = _MAX_RECORDS) -> None:
        self.root = Path(os.path.abspath(os.fspath(root)))
        if isinstance(max_records, bool) or not isinstance(max_records, int) or not 1 <= max_records <= _MAX_RECORDS:
            raise ValueError("durable request max_records is invalid")
        self.max_records = max_records
        if self.root.exists() and (self.root.is_symlink() or _reparse(self.root) or not self.root.is_dir()):
            raise ValueError("durable request root is unsafe")
        self.root.mkdir(parents=True, exist_ok=True)
        if self.root.is_symlink() or _reparse(self.root):
            raise ValueError("durable request root is unsafe")
        self.lock_path = self.root / "request-store"

    def _path(self, key: str) -> Path:
        if not isinstance(key, str) or _KEY.fullmatch(key) is None:
            raise KeyError(key)
        return self.root / f"{hashlib.sha256(key.encode('utf-8')).hexdigest()}.json"

    def __getitem__(self, key: str) -> Any:
        path = self._path(key)
        with interprocess_lock(self.lock_path, stale_after_s=None):
            if not path.exists():
                raise KeyError(key)
            envelope = self._read(path)
        if envelope.idempotency_key != key or envelope.kind != self.kind:
            raise ValueError("durable request key collision")
        request_json = base64.b64decode(envelope.request_b64, validate=True)
        if self.kind == "CERTIFY":
            from rolo.targetd.certify_adapter import TargetdV2CertifyRequestRecord

            return TargetdV2CertifyRequestRecord(
                request_json=request_json,
                content_digest=envelope.content_digest,
                request_digest=envelope.request_digest,
                created_at=envelope.created_at,
                timeout_s=envelope.timeout_s,
            )
        from rolo.mvp.trace_plan import TargetdTraceRequestRecord

        return TargetdTraceRequestRecord(
            request_json=request_json,
            content_digest=envelope.content_digest,
            request_digest=envelope.request_digest,
            created_at=envelope.created_at,
            timeout_s=envelope.timeout_s,
        )

    def __setitem__(self, key: str, value: Any) -> None:
        path = self._path(key)
        try:
            request_json = bytes(value.request_json)
            content_digest = str(value.content_digest)
            request_digest = str(value.request_digest)
            created_at = value.created_at
            timeout_s = float(value.timeout_s)
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("durable request record is invalid") from exc
        if len(request_json) > _MAX_REQUEST_BYTES or hashlib.sha256(request_json).hexdigest() != content_digest:
            raise ValueError("durable request record content mismatch")
        payload = {
            "schema_version": "rolo-targetd-durable-request/v1",
            "kind": self.kind,
            "idempotency_key": key,
            "request_b64": base64.b64encode(request_json).decode("ascii"),
            "content_digest": content_digest,
            "request_digest": request_digest,
            "created_at": created_at,
            "timeout_s": timeout_s,
        }
        provisional = _RequestEnvelope.model_construct(**payload, envelope_digest="0" * 64)
        envelope = provisional.model_copy(update={"envelope_digest": provisional.computed_digest()})
        envelope = _RequestEnvelope.model_validate(envelope.model_dump(mode="python"))
        encoded = envelope.model_dump_json(indent=2) + "\n"
        with interprocess_lock(self.lock_path, stale_after_s=None):
            if path.exists():
                current = self._read(path)
                if current != envelope:
                    raise ValueError("durable request idempotency collision")
                return
            if self._count_unlocked() >= self.max_records:
                raise ValueError("durable request store is full")
            atomic_write_text(path, encoded, acquire_lock=False, require_absent=True)

    def __delitem__(self, key: str) -> None:
        del key
        raise TypeError("durable request records are append-only")

    def __iter__(self) -> Iterator[str]:
        with interprocess_lock(self.lock_path, stale_after_s=None):
            records = [self._read(path) for path in self._paths_unlocked()]
        for record in records:
            if record.kind != self.kind:
                raise ValueError("durable request kind mismatch")
            yield record.idempotency_key

    def __len__(self) -> int:
        with interprocess_lock(self.lock_path, stale_after_s=None):
            return self._count_unlocked()

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def _paths_unlocked(self) -> list[Path]:
        paths = sorted(self.root.glob("*.json"), key=lambda path: path.name)
        if any(
            re.fullmatch(r"[0-9a-f]{64}\.json", path.name) is None
            or path.is_symlink()
            or _reparse(path)
            or not path.is_file()
            for path in paths
        ):
            raise ValueError("durable request store contains an unsafe artifact")
        return paths

    def _count_unlocked(self) -> int:
        return len(self._paths_unlocked())

    @staticmethod
    def _read(path: Path) -> _RequestEnvelope:
        if path.stat().st_size > 512 * 1024:
            raise ValueError("durable request record exceeds size limit")
        try:
            return _RequestEnvelope.model_validate(loads_unique_json(path.read_text(encoding="utf-8")))
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError("durable request record is invalid") from exc


class DurableCertifyRequestStore(_DurableRequestStore):
    """Filesystem-backed mapping accepted by ``TargetdV2CertifyAdapter``."""

    kind = "CERTIFY"


class DurableTraceRequestStore(_DurableRequestStore):
    """Filesystem-backed mapping accepted by ``TargetdTraceAdapter``."""

    kind = "TRACE"


__all__ = ["DurableCertifyRequestStore", "DurableTraceRequestStore"]
