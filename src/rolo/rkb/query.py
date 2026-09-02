"""Small read-only query facade over verified RKB envelopes."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .models import EvidenceEnvelope, Fact, FreshnessStatus, Snapshot
from .validation import validate_envelope


class QueryResult(BaseModel):
    status: FreshnessStatus
    value: Any = None
    evidence_ids: list[str] = Field(default_factory=list)
    observed_at: datetime | None = None
    fresh_until: datetime | None = None
    limitations: list[str] = Field(default_factory=list)


class ReadOnlyKnowledgeBase:
    """Index verified envelopes without exposing raw unverified bundle access."""

    def __init__(self, envelopes: list[EvidenceEnvelope | Snapshot] | None = None) -> None:
        self._envelopes = list(envelopes or [])

    def add_verified(
        self,
        envelope: EvidenceEnvelope | Snapshot,
        *,
        now: datetime | None = None,
        hmac_secret: bytes | None = None,
    ) -> None:
        validate_envelope(
            envelope,
            now=now,
            require_fresh=False,
            hmac_secret=hmac_secret,
        )
        self._envelopes.append(envelope)

    def identity(self, *, now: datetime | None = None) -> QueryResult:
        if not self._envelopes:
            return QueryResult(status=FreshnessStatus.UNKNOWN, limitations=["no verified evidence"])
        envelope = self._envelopes[-1]
        return QueryResult(
            status=envelope.identity.freshness(now=now),
            value=envelope.identity.model_dump(mode="json"),
            observed_at=envelope.identity.observed_at,
            fresh_until=envelope.identity.fresh_until,
            limitations=[],
        )

    def facts(self, *, now: datetime | None = None) -> list[QueryResult]:
        results: list[QueryResult] = []
        for envelope in self._envelopes:
            for fact in envelope.facts:
                results.append(self._fact_result(fact, now=now))
        return results

    def get(self, fact_id: str, *, now: datetime | None = None) -> QueryResult:
        for result in self.facts(now=now):
            if fact_id in result.evidence_ids:
                return result
        return QueryResult(status=FreshnessStatus.UNKNOWN, limitations=["fact not found"])

    @staticmethod
    def _fact_result(fact: Fact, *, now: datetime | None) -> QueryResult:
        return QueryResult(
            status=fact.freshness(now=now),
            value=fact.value,
            evidence_ids=[fact.fact_id],
            observed_at=fact.observed_at,
            fresh_until=fact.fresh_until,
            limitations=fact.limitations,
        )
