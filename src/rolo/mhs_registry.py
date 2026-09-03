"""Durable, fail-closed registry for read-only MHS providers.

Registration is an inventory/provenance operation only.  It never promotes a
provider to a verified or Agent-callable tool.  Backends are intentionally not
serialized; a process must re-bind a provider explicitly after loading the
registry.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from rolo.core.persistence import atomic_write_text, interprocess_lock
from rolo.mhs_hardware import MhsDeviceProvider


class MhsRegistrationStatus(str, Enum):
    REGISTERED = "REGISTERED"
    REJECTED = "REJECTED"
    STALE = "STALE"


class MhsRegistryError(ValueError):
    """A provider cannot be admitted to the durable registry."""


class MhsRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-mhs-registration/v1"
    provider_id: str = Field(min_length=1, max_length=128)
    device_id: str = Field(min_length=1, max_length=128)
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    driver_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    capabilities: list[str] = Field(default_factory=list)
    routes: list[str] = Field(default_factory=list)
    status: MhsRegistrationStatus
    registered_at: datetime
    evidence_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class MhsRegistryDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-mhs-registry/v1"
    registrations: list[MhsRegistration] = Field(default_factory=list)


class MhsProviderRegistry:
    """Persist provider identity and registration evidence atomically."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.path = self.root / "providers.json"

    def list(self) -> list[MhsRegistration]:
        return list(self._load().registrations)

    def get(self, provider_id: str) -> MhsRegistration | None:
        return next((item for item in self.list() if item.provider_id == provider_id), None)

    def register(
        self, provider: MhsDeviceProvider, *, now: datetime | None = None
    ) -> MhsRegistration:
        manifest = provider.manifest
        provider_id = provider.provider_id
        existing = self.get(provider_id)
        if existing is not None:
            if (
                existing.manifest_sha256 != manifest.manifest_sha256
                or existing.driver_sha256 != manifest.driver_sha256
            ):
                raise MhsRegistryError("provider identity or digest drift detected")
            raise MhsRegistryError(f"duplicate provider id: {provider_id}")
        observed = now or datetime.now(timezone.utc)
        capabilities = sorted(MhsDeviceProvider.READ_CAPABILITIES)
        record = MhsRegistration(
            provider_id=provider_id,
            device_id=manifest.device_id,
            manifest_sha256=manifest.manifest_sha256,
            driver_sha256=manifest.driver_sha256,
            capabilities=capabilities,
            routes=[provider.route(capability) for capability in capabilities],
            status=MhsRegistrationStatus.REGISTERED,
            registered_at=observed,
            evidence_ids=[
                f"mhs-manifest:{manifest.manifest_sha256}",
                f"mhs-driver:{manifest.driver_sha256}",
            ],
            limitations=["registration is provenance only; verification remains independent"],
        )
        document = self._load()
        document.registrations.append(record)
        self._save(document)
        return record

    def mark_stale(
        self,
        provider_id: str,
        *,
        reason: str = "provider digest is no longer current",
    ) -> MhsRegistration:
        document = self._load()
        for index, item in enumerate(document.registrations):
            if item.provider_id == provider_id:
                updated = item.model_copy(
                    update={
                        "status": MhsRegistrationStatus.STALE,
                        "limitations": [*item.limitations, reason],
                    }
                )
                document.registrations[index] = updated
                self._save(document)
                return updated
        raise MhsRegistryError(f"provider is not registered: {provider_id}")

    def _load(self) -> MhsRegistryDocument:
        try:
            return MhsRegistryDocument.model_validate_json(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return MhsRegistryDocument()
        except (OSError, ValueError) as exc:
            raise MhsRegistryError("MHS registry is unreadable") from exc

    def _save(self, document: MhsRegistryDocument) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        payload = (
            json.dumps(document.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
            + "\n"
        )
        with interprocess_lock(self.path):
            atomic_write_text(self.path, payload, acquire_lock=False)


__all__ = [
    "MhsProviderRegistry",
    "MhsRegistration",
    "MhsRegistrationStatus",
    "MhsRegistryDocument",
    "MhsRegistryError",
]
