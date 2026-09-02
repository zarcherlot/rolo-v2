"""Typed, read-only Robot Knowledge Base evidence models."""

from .models import (
    EvidenceEnvelope,
    Fact,
    FactConfidence,
    FactSourceKind,
    FreshnessStatus,
    IdentityStatus,
    SnapshotIdentity,
    canonical_json,
    envelope_from_probe,
    snapshot_from_target_bundle,
)
from .query import QueryResult, ReadOnlyKnowledgeBase

__all__ = [
    "EvidenceEnvelope",
    "Fact",
    "FactConfidence",
    "FactSourceKind",
    "FreshnessStatus",
    "IdentityStatus",
    "SnapshotIdentity",
    "canonical_json",
    "envelope_from_probe",
    "snapshot_from_target_bundle",
    "QueryResult",
    "ReadOnlyKnowledgeBase",
]
