"""In-process read-only API facade for ProbeEvidenceView.

The facade is intentionally transport-neutral so rolo-vis or an HTTP adapter
can consume the same validated payload without gaining mutation operations.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .mhs_read_models import ProbeEvidenceView, build_probe_evidence_view


class MhsEvidenceReadApi:
    """Small target-bound store exposing only validated read operations."""

    def __init__(self) -> None:
        self._views: dict[str, ProbeEvidenceView] = {}

    def publish(self, payload: Mapping[str, object]) -> ProbeEvidenceView:
        """Validate and replace one target's evidence view."""

        view = ProbeEvidenceView.model_validate(dict(payload))
        self._views[view.target_fingerprint] = view
        return view

    def publish_parts(
        self,
        *,
        target_fingerprint: str,
        references: Sequence[Mapping[str, object]] = (),
        manifests: Sequence[Mapping[str, object]] = (),
        read_results: Sequence[Mapping[str, object]] = (),
        limitations: Sequence[str] = (),
    ) -> ProbeEvidenceView:
        view = build_probe_evidence_view(
            target_fingerprint=target_fingerprint,
            references=references,
            manifests=manifests,
            read_results=read_results,
            limitations=limitations,
        )
        self._views[target_fingerprint] = view
        return view

    def get(self, target_fingerprint: str) -> ProbeEvidenceView | None:
        return self._views.get(target_fingerprint)

    def list_targets(self) -> list[str]:
        return sorted(self._views)


__all__ = ["MhsEvidenceReadApi"]
