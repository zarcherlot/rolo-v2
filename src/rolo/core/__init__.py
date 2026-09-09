"""Small shared primitives used by the v2 Probe chain."""

from typing import TYPE_CHECKING

from rolo.core.artifacts import ArtifactStore
from rolo.core.signed_artifacts import SignedArtifact, SignedArtifactStore

if TYPE_CHECKING:
    from rolo.core.config import Settings, get_settings

__all__ = ["ArtifactStore", "Settings", "SignedArtifact", "SignedArtifactStore", "get_settings"]

_LAZY_CONTROL_PLANE_EXPORTS = frozenset({"Settings", "get_settings"})


def __getattr__(name: str) -> object:
    """Load control-plane settings only when their public exports are used."""

    if name in _LAZY_CONTROL_PLANE_EXPORTS:
        from rolo.core import config

        value = getattr(config, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
