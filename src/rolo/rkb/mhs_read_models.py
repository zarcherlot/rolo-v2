"""RKB projections for MHS references and read-only observations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .read_models import TypedQueryResult


def project_mhs_read_result(
    result: Mapping[str, Any], *, evidence_ids: Sequence[str] = ()
) -> TypedQueryResult[dict[str, Any]]:
    """Map one MHS read result into the common RKB typed envelope.

    The projection deliberately preserves ``UNKNOWN``, ``STALE`` and
    ``UNAVAILABLE`` states and always advertises read-only access.
    """

    status = str(result.get("status", "UNKNOWN"))
    if status not in {"AVAILABLE", "STALE", "UNAVAILABLE", "UNKNOWN"}:
        status = "UNKNOWN"
    limitations = list(result.get("limitations") or [])
    if result.get("access") != "READ_ONLY":
        status = "UNKNOWN"
        limitations.append("MHS result is not read-only")
    value = dict(result) if status != "AVAILABLE" else dict(result.get("value") or {})
    return TypedQueryResult(
        status=status,
        value=value,
        evidence_ids=list(evidence_ids or result.get("evidence_ids") or []),
        observed_at=result.get("observed_at"),
        fresh_until=result.get("fresh_until"),
        limitations=limitations,
        status_reason=str(result.get("reason") or ""),
    )


def project_probe_evidence_view(
    *,
    target_fingerprint: str,
    references: Sequence[Mapping[str, Any]] = (),
    manifests: Sequence[Mapping[str, Any]] = (),
    read_results: Sequence[Mapping[str, Any]] = (),
    freshness: str = "UNKNOWN",
    limitations: Sequence[str] = (),
) -> dict[str, Any]:
    """Build the strict ProbeEvidenceView wire shape without write affordances."""

    return {
        "schema_version": "rolo-probe-evidence-view/v1",
        "target_fingerprint": target_fingerprint,
        "mhs_references": [dict(item) for item in references],
        "manifests": [dict(item) for item in manifests],
        "read_results": [dict(item) for item in read_results],
        "freshness": freshness,
        "limitations": list(limitations),
        "access": "READ_ONLY",
        "write_operations": 0,
    }


__all__ = ["project_mhs_read_result", "project_probe_evidence_view"]
