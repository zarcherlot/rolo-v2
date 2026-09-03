"""Deterministic replay adapter for structured MHS sampling."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .mhs_hardware import MhsDeviceManifest, MhsInterfaceSample


class MhsReplayBackend:
    """Serve captured scalar/structured samples without touching hardware."""

    def __init__(
        self,
        manifest: MhsDeviceManifest,
        *,
        scalar_values: Mapping[str, int | float | bool | str] | None = None,
        structured_samples: Sequence[MhsInterfaceSample] = (),
    ) -> None:
        self.manifest = manifest
        self.scalar_values = dict(scalar_values or {})
        self.structured_samples = list(structured_samples)

    def read(self) -> Mapping[str, int | float | bool | str]:
        return dict(self.scalar_values)

    def status(self) -> Mapping[str, Any]:
        return {"health": "REPLAY", "read_only": True, "sample_count": len(self.structured_samples)}

    def read_structured(self) -> list[MhsInterfaceSample]:
        return list(self.structured_samples)


__all__ = ["MhsReplayBackend"]
