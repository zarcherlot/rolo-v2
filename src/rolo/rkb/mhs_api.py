"""In-process read-only API facade for ProbeEvidenceView.

The facade is intentionally transport-neutral so rolo-vis or an HTTP adapter
can consume the same validated payload without gaining mutation operations.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from pydantic import BaseModel

from ..mhs_manifest_records import (
    MhsManifestReference as StrictManifestReference,
)
from ..mhs_manifest_records import MhsReadOnly as StrictReadOnly
from ..mhs_manifest_records import (
    MhsReferenceCandidate as StrictReferenceCandidate,
)
from .mhs_read_models import ProbeEvidenceView, build_probe_evidence_view


def _strict_payload(model_type: type[BaseModel], item: Mapping[str, object] | BaseModel) -> dict:
    payload = item.model_dump(mode="json") if isinstance(item, BaseModel) else dict(item)
    return model_type.model_validate(payload).model_dump(mode="json")


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
        references: Sequence[Mapping[str, object] | BaseModel] = (),
        manifests: Sequence[Mapping[str, object] | BaseModel] = (),
        read_results: Sequence[Mapping[str, object] | BaseModel] = (),
        limitations: Sequence[str] = (),
    ) -> ProbeEvidenceView:
        # Validate registry/provider records at the service boundary.  The
        # transport model remains the public wire shape, while the strict
        # records enforce source authority, canonical routes, and read-only
        # access before anything is published to the in-process store.
        validated_references = [
            _strict_payload(StrictReferenceCandidate, item) for item in references
        ]
        validated_manifests = [
            _strict_payload(StrictManifestReference, item)
            for item in manifests
        ]
        validated_results = [_strict_payload(StrictReadOnly, item) for item in read_results]
        view = build_probe_evidence_view(
            target_fingerprint=target_fingerprint,
            references=validated_references,
            manifests=validated_manifests,
            read_results=validated_results,
            limitations=limitations,
        )
        self._views[target_fingerprint] = view
        return view

    def get(self, target_fingerprint: str) -> ProbeEvidenceView | None:
        return self._views.get(target_fingerprint)

    def list_targets(self) -> list[str]:
        return sorted(self._views)


__all__ = ["MhsEvidenceReadApi"]
