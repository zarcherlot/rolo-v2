"""Durable MHS provider inventory and explicit registration lifecycle."""
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
    pass

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
    def __init__(self, root: Path) -> None:
        self.root = root.resolve(); self.path = self.root / "providers.json"
    def _load(self) -> MhsRegistryDocument:
        try: return MhsRegistryDocument.model_validate_json(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError: return MhsRegistryDocument()
        except (OSError, ValueError) as exc: raise MhsRegistryError("MHS registry is unreadable") from exc
    def list(self) -> list[MhsRegistration]: return list(self._load().registrations)
    def get(self, provider_id: str) -> MhsRegistration | None:
        return next((item for item in self.list() if item.provider_id == provider_id), None)
    def register(self, provider: MhsDeviceProvider, *, now: datetime | None = None) -> MhsRegistration:
        manifest = provider.manifest; existing = self.get(provider.provider_id)
        if existing:
            if (existing.manifest_sha256 != manifest.manifest_sha256 or existing.driver_sha256 != manifest.driver_sha256):
                raise MhsRegistryError("provider identity or digest drift detected")
            raise MhsRegistryError(f"duplicate provider id: {provider.provider_id}")
        observed = now or datetime.now(timezone.utc)
        record = MhsRegistration(provider_id=provider.provider_id, device_id=manifest.device_id,
            manifest_sha256=manifest.manifest_sha256, driver_sha256=manifest.driver_sha256,
            capabilities=sorted(MhsDeviceProvider.READ_CAPABILITIES),
            routes=[provider.route(cap) for cap in sorted(MhsDeviceProvider.READ_CAPABILITIES)],
            status=MhsRegistrationStatus.REGISTERED, registered_at=observed,
            evidence_ids=[f"mhs-manifest:{manifest.manifest_sha256}", f"mhs-driver:{manifest.driver_sha256}"],
            limitations=["registration is provenance only; verification remains independent"])
        document = self._load(); document.registrations.append(record); self._save(document); return record
    def mark_stale(self, provider_id: str, *, reason: str = "provider digest is no longer current") -> MhsRegistration:
        document = self._load()
        for index, item in enumerate(document.registrations):
            if item.provider_id == provider_id:
                updated = item.model_copy(update={"status": MhsRegistrationStatus.STALE, "limitations": [*item.limitations, reason]})
                document.registrations[index] = updated; self._save(document); return updated
        raise MhsRegistryError(f"provider is not registered: {provider_id}")
    def _save(self, document: MhsRegistryDocument) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(document.model_dump(mode="json"), sort_keys=True, separators=(",", ":")) + "\n"
        with interprocess_lock(self.path): atomic_write_text(self.path, payload, acquire_lock=False)

class MhsRegistrationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "rolo-mhs-registration/v1"
    robot_id: str = Field(min_length=1, max_length=128)
    device_id: str = Field(min_length=1, max_length=128)
    provider_id: str = Field(min_length=1, max_length=128)
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    driver_id: str = Field(min_length=1, max_length=128)
    driver_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    registration: str = Field(pattern=r"^(REGISTERED|REJECTED|UNREGISTERED)$")
    discovered_at: datetime
    registered_at: datetime | None = None
    route: str
    limitations: list[str] = Field(default_factory=list)

class MhsRegistryLifecycleDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "rolo-mhs-registry/v1"
    updated_at: datetime
    records: list[MhsRegistrationRecord] = Field(default_factory=list)

class MhsRegistry:
    def __init__(self, path: Path) -> None: self.path = path.expanduser()
    def _doc(self) -> MhsRegistryLifecycleDocument:
        if not self.path.exists(): return MhsRegistryLifecycleDocument(updated_at=datetime.now(timezone.utc))
        try: return MhsRegistryLifecycleDocument.model_validate_json(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc: raise MhsRegistryError("MHS registry is invalid") from exc
    def load(self) -> MhsRegistryLifecycleDocument:
        return self._doc()
    def _save(self, doc: MhsRegistryLifecycleDocument) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(self.path, json.dumps(doc.model_dump(mode="json"), sort_keys=True, separators=(",", ":")) + "\n")
    def _make(self, robot_id: str, manifest, state: str, now: datetime, reason: str) -> MhsRegistrationRecord:
        return MhsRegistrationRecord(robot_id=robot_id, device_id=manifest.device_id, provider_id=f"mhs.{manifest.device_id}",
            manifest_sha256=manifest.manifest_sha256, driver_id=manifest.driver_id, driver_sha256=manifest.driver_sha256,
            registration=state, discovered_at=now, registered_at=now if state == "REGISTERED" else None,
            route=f"mhs://{manifest.device_id}/inspect", limitations=[reason])
    def discover(self, *, robot_id: str, manifest, discovered_at: datetime | None = None) -> MhsRegistrationRecord:
        now = discovered_at or datetime.now(timezone.utc); doc = self._doc()
        existing = next((x for x in doc.records if x.robot_id == robot_id and x.device_id == manifest.device_id), None)
        if existing and existing.manifest_sha256 == manifest.manifest_sha256 and existing.driver_sha256 == manifest.driver_sha256: return existing
        state = "REJECTED" if existing else "UNREGISTERED"
        reason = "manifest or driver digest drift requires explicit re-registration" if existing else "discovery does not grant registration or Tool verification"
        record = self._make(robot_id, manifest, state, now, reason)
        doc.records = [x for x in doc.records if not (x.robot_id == robot_id and x.device_id == manifest.device_id)] + [record]
        doc.updated_at = now; self._save(doc); return record
    def register(self, *, robot_id: str, manifest, registered_at: datetime | None = None) -> MhsRegistrationRecord:
        now = registered_at or datetime.now(timezone.utc); doc = self._doc()
        existing = next((x for x in doc.records if x.robot_id == robot_id and x.device_id == manifest.device_id), None)
        if existing and (existing.manifest_sha256 != manifest.manifest_sha256 or existing.driver_sha256 != manifest.driver_sha256): raise MhsRegistryError("MHS manifest or driver digest drift requires explicit re-registration")
        record = self._make(robot_id, manifest, "REGISTERED", now, "registration does not grant Tool verification")
        doc.records = [x for x in doc.records if not (x.robot_id == robot_id and x.device_id == manifest.device_id)] + [record]; doc.updated_at = now; self._save(doc); return record
    def unregister(self, *, robot_id: str, device_id: str, at: datetime | None = None, reason: str = "provider is no longer present") -> MhsRegistrationRecord | None:
        doc = self._doc(); existing = next((x for x in doc.records if x.robot_id == robot_id and x.device_id == device_id), None)
        if existing is None: return None
        record = existing.model_copy(update={"registration": "UNREGISTERED", "registered_at": None, "limitations": [reason]}); doc.records = [x for x in doc.records if not (x.robot_id == robot_id and x.device_id == device_id)] + [record]; doc.updated_at = at or datetime.now(timezone.utc); self._save(doc); return record
    def for_robot(self, robot_id: str) -> dict[str, MhsRegistrationRecord]:
        return {key: item for item in self._doc().records if item.robot_id == robot_id for key in (item.device_id, item.provider_id)}

__all__ = ["MhsProviderRegistry", "MhsRegistration", "MhsRegistrationStatus", "MhsRegistryDocument", "MhsRegistryError", "MhsRegistry", "MhsRegistrationRecord"]
