"""Fail-closed validation for bounded rotation result evidence.

The target runtime returns a JSON object rather than a signed receipt.  Keep
the small semantic gate in a dependency-light module so both the targetd
receipt mapper and the controller-side normalizer apply the same rule.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any


def has_verified_independent_motion_evidence(result: Mapping[str, Any]) -> bool:
    """Return whether a result proves independent, settled body motion."""

    evidence = result.get("independent_motion_evidence")
    return (
        isinstance(evidence, Mapping)
        and str(evidence.get("status", "")).upper() == "VERIFIED"
        and evidence.get("independent_of_odom") is True
        and evidence.get("settled") is True
    )


def has_verified_rotation_angle(result: Mapping[str, Any]) -> bool:
    """Return whether the result proves the requested angle was met.

    The top-level flag is retained as an explicit runtime assertion, but it is
    not sufficient on its own.  The nested evidence must also carry a finite
    non-negative error, a positive tolerance, and a matching verified status.
    """

    if result.get("angle_accuracy_verified") is not True:
        return False
    evidence = result.get("independent_motion_evidence")
    if not isinstance(evidence, Mapping):
        return False
    if str(evidence.get("angle_accuracy_status", "")).upper() != "VERIFIED":
        return False
    error = evidence.get("target_angle_error_rad")
    tolerance = evidence.get("target_angle_tolerance_rad")
    if isinstance(error, bool) or isinstance(tolerance, bool):
        return False
    try:
        error_value = float(error)
        tolerance_value = float(tolerance)
    except (TypeError, ValueError, OverflowError):
        return False
    return (
        math.isfinite(error_value)
        and error_value >= 0.0
        and math.isfinite(tolerance_value)
        and tolerance_value > 0.0
        and error_value <= tolerance_value
    )


def has_verified_rotation_evidence(result: Mapping[str, Any]) -> bool:
    """Return whether independent motion and exact-angle gates both pass."""

    return has_verified_independent_motion_evidence(result) and has_verified_rotation_angle(result)


__all__ = [
    "has_verified_independent_motion_evidence",
    "has_verified_rotation_angle",
    "has_verified_rotation_evidence",
]
