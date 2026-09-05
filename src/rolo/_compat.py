"""Small standard-library compatibility shims for supported Python versions."""

from enum import Enum

try:
    from enum import StrEnum
except ImportError:  # pragma: no cover - exercised on Python 3.10

    class StrEnum(str, Enum):
        """Backport of :class:`enum.StrEnum` for Python 3.10."""

        def __str__(self) -> str:
            return self.value
