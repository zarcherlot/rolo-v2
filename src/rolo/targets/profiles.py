"""Persisted target profiles with explicit credential and host-key references."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from rolo.core.persistence import atomic_write_text, interprocess_lock
from rolo.target_ref import SshTargetRef, TargetRef

_PROFILE_ID = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
_CREDENTIAL_REF = re.compile(r"^[a-z][a-z0-9_-]{0,31}:[A-Za-z0-9._/-]{1,127}$")
_PROVIDER_HINT_KEY = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_SSH_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]+={0,2}$")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CredentialReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["ssh-agent", "secret-store", "platform-keychain"]
    reference: str = Field(min_length=3, max_length=160)

    @field_validator("reference")
    @classmethod
    def validate_reference(cls, value: str) -> str:
        if not _CREDENTIAL_REF.fullmatch(value):
            raise ValueError("credential reference must be a typed reference, not secret material")
        return value


class HostKeyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["PENDING", "APPROVED", "REVOKED"] = "PENDING"
    host: str = Field(min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    fingerprint: str | None = None
    decided_at: datetime | None = None
    decided_by: str | None = Field(default=None, min_length=1, max_length=128)

    @field_validator("fingerprint")
    @classmethod
    def validate_fingerprint(cls, value: str | None) -> str | None:
        if value is not None and not _SSH_FINGERPRINT.fullmatch(value):
            raise ValueError("host-key fingerprint must use the SHA256:... format")
        return value

    @field_validator("decided_by")
    @classmethod
    def validate_decider(cls, value: str | None) -> str | None:
        if value is not None and any(character.isspace() for character in value):
            raise ValueError("host-key decision actor must not contain whitespace")
        return value


class TargetProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-target-profile/v1"] = "rolo-target-profile/v1"
    profile_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{2,63}$")
    robot_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{2,63}$")
    target: TargetRef
    credential: CredentialReference
    remote_command_prefix: list[str] = Field(default_factory=list, max_length=8)
    provider_hints: dict[str, str] = Field(default_factory=dict, max_length=8)
    host_key: HostKeyDecision | None = None
    created_at: datetime
    updated_at: datetime

    @field_validator("profile_id", "robot_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if not _PROFILE_ID.fullmatch(value):
            raise ValueError("profile and robot identifiers must match ^[a-z][a-z0-9_-]{2,63}$")
        return value

    @field_validator("remote_command_prefix")
    @classmethod
    def validate_remote_command_prefix(cls, value: list[str]) -> list[str]:
        if any(
            not item
            or "\x00" in item
            or any(character in item for character in "'\";$`\\")
            for item in value
        ):
            raise ValueError("remote command prefix must contain shell-free, NUL-free tokens")
        if len(value) != len(set(value)):
            raise ValueError("remote command prefix tokens must be unique")
        return value

    @field_validator("provider_hints")
    @classmethod
    def validate_provider_hints(cls, value: dict[str, str]) -> dict[str, str]:
        if any(
            not _PROVIDER_HINT_KEY.fullmatch(key)
            or not item
            or len(item) > 256
            or "\x00" in item
            for key, item in value.items()
        ):
            raise ValueError("provider hints must use bounded, NUL-free values")
        return dict(sorted(value.items()))


class TargetProfileStore:
    def __init__(self, config_root: Path) -> None:
        self.root = config_root.expanduser().resolve() / "target-profiles"

    def path_for(self, profile_id: str) -> Path:
        if not _PROFILE_ID.fullmatch(profile_id):
            raise ValueError("profile_id must match ^[a-z][a-z0-9_-]{2,63}$")
        return self.root / f"{profile_id}.json"

    def load(self, profile_id: str) -> TargetProfile:
        path = self.path_for(profile_id)
        if not path.is_file():
            raise FileNotFoundError(f"target profile is missing: {path}")
        try:
            profile = TargetProfile.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError(f"invalid target profile {path}: {exc}") from exc
        if profile.profile_id != profile_id or profile.robot_id != profile_id:
            raise ValueError("target profile identity does not match its path")
        return profile

    def list_profiles(self) -> list[TargetProfile]:
        """Load every persisted profile in stable order.

        A malformed profile is an unavailable producer fact, so fail the complete
        read model instead of silently returning a partial fleet projection.
        """

        if not self.root.is_dir():
            return []
        profiles: list[TargetProfile] = []
        for path in sorted(self.root.glob("*.json"), key=lambda item: item.name):
            if path.is_symlink():
                raise ValueError(f"target profile must not be a symlink: {path}")
            profile_id = path.stem
            profiles.append(self.load(profile_id))
        return profiles

    def save(self, profile: TargetProfile) -> Path:
        if profile.profile_id != profile.robot_id:
            raise ValueError("target profile_id and robot_id must match")
        path = self.path_for(profile.profile_id)
        with interprocess_lock(path):
            if path.is_symlink():
                raise ValueError(f"target profile must not be a symlink: {path}")
            if path.is_file():
                previous = self.load(profile.profile_id)
                if previous.target != profile.target:
                    raise ValueError("target profile target is immutable; create a new profile")
                profile = profile.model_copy(update={"created_at": previous.created_at})
            atomic_write_text(
                path,
                profile.model_dump_json(indent=2) + "\n",
                acquire_lock=False,
            )
        return path

    def create(
        self,
        *,
        robot_id: str,
        target: TargetRef,
        credential: CredentialReference,
        remote_command_prefix: list[str] | None = None,
        provider_hints: dict[str, str] | None = None,
        now: datetime | None = None,
    ) -> TargetProfile:
        timestamp = now or _utc_now()
        host_key = None
        if isinstance(target, SshTargetRef):
            host_key = HostKeyDecision(host=target.host, port=target.port)
        profile = TargetProfile(
            profile_id=robot_id,
            robot_id=robot_id,
            target=target,
            credential=credential,
            remote_command_prefix=remote_command_prefix or [],
            provider_hints=provider_hints or {},
            host_key=host_key,
            created_at=timestamp,
            updated_at=timestamp,
        )
        self.save(profile)
        return profile
