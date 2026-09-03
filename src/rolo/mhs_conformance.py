"""Fail-closed conformance checks for the Probe/MHS read-only boundary."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

FORBIDDEN_OPERATIONS = {"reset", "calibrate", "setpoint", "power", "power_cycle", "stop", "write"}


def validate_read_only_surface(
    *,
    operations: Sequence[str],
    references: Sequence[Mapping[str, object]] = (),
) -> list[str]:
    """Return deterministic violations; an empty list means the surface is safe."""

    violations: list[str] = []
    for operation in operations:
        if operation.lower() in FORBIDDEN_OPERATIONS:
            violations.append(f"write-like operation exposed: {operation}")
    for reference in references:
        transport = str(reference.get("transport", "")).upper()
        if transport in {"I2C", "SPI", "GPIO"} and reference.get("approved_access") is not True:
            violations.append(f"unapproved {transport} access")
        if reference.get("access") != "READ_ONLY":
            violations.append("reference is not READ_ONLY")
    return violations


__all__ = ["FORBIDDEN_OPERATIONS", "validate_read_only_surface"]
