"""Presentation-safe payload adapter for rolo-vis consumers."""

from __future__ import annotations

from .mhs_read_models import ProbeEvidenceView


def render_probe_evidence_cards(view: ProbeEvidenceView) -> dict:
    """Render source/status cards without collapsing provisional states."""

    cards: list[dict[str, object]] = []
    for reference in view.mhs_references:
        cards.append(
            {
                "kind": "mhs_reference",
                "id": reference.candidate_id,
                "source": reference.source_kind,
                "authority": reference.authority,
                "status": reference.status,
                "freshness": reference.freshness,
                "limitations": reference.limitations,
            }
        )
    for manifest in view.manifests:
        cards.append(
            {
                "kind": "manifest",
                "id": manifest.manifest_id,
                "source": manifest.source_kind,
                "authority": manifest.authority,
                "status": manifest.status,
                "freshness": view.freshness,
                "limitations": manifest.limitations,
            }
        )
    for result in view.read_results:
        cards.append(
            {
                "kind": "read_result",
                "id": result.device_id,
                "source": "OBSERVED",
                "authority": "OBSERVED",
                "status": result.status,
                "freshness": view.freshness,
                "limitations": result.limitations,
            }
        )
    return {
        "schema_version": "rolo-vis-mhs-evidence-cards/v1",
        "target_fingerprint": view.target_fingerprint,
        "overall_freshness": view.freshness,
        "cards": cards,
        "limitations": view.limitations,
        "access": "READ_ONLY",
        "write_operations": 0,
    }


__all__ = ["render_probe_evidence_cards"]
