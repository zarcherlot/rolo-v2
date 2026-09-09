from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import count
from pathlib import Path
from typing import Any

import pytest

from rolo.dsl.admission import (
    MappingAdmissionIdentity,
    MappingAdmissionScope,
    MappingConfirmationReceipt,
    MappingConfirmationStore,
    mapping_digest,
)
from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.context import ProbeContext
from rolo.dsl.parser import parse_document


@dataclass(frozen=True)
class ConfirmedMappingFixture:
    store: MappingConfirmationStore
    receipt: MappingConfirmationReceipt

    @property
    def compiler_kwargs(self) -> dict[str, Any]:
        return {
            "confirmation_store": self.store,
            "confirmation_receipt_digest": self.receipt.receipt_digest,
            "journey_session_id": self.receipt.journey_session_id,
        }


@pytest.fixture
def mapping_confirmation_factory(tmp_path: Path):
    """Create a committed confirmation for boundary tests.

    Proposal-specific tests exercise the production Proposal builder.  This
    fixture deliberately supplies the other trusted identities directly so a
    compiler, targetd, registry, or release test can focus on its own gate.
    """

    sequence = count(1)
    now = datetime(2026, 9, 8, 4, 0, tzinfo=timezone.utc)

    def create(
        dsl: dict[str, Any],
        context: dict[str, Any],
        *,
        journey_session_id: str = "journey-1",
        operations: tuple[str, ...] | None = None,
        access: str | None = None,
        risk: str | None = None,
        store_root: Path | None = None,
    ) -> ConfirmedMappingFixture:
        item = next(sequence)
        document, report = parse_document(dsl)
        assert document is not None and report.ok
        normalized_context = ProbeContext.model_validate(context)
        operation_values = operations or (document.tool_id,)
        effective_access = access or ("read" if document.kind.value == "OBSERVE" else "experimental_write")
        effective_risk = risk or ("R0" if effective_access == "read" else "R3")
        scope = MappingAdmissionScope(
            tool_id=document.tool_id,
            operation_kind=document.kind,
            operations=operation_values,
            access=effective_access,
            risk=effective_risk,
        )
        identity_seed = {
            "journey_session_id": journey_session_id,
            "item": item,
            "tool_id": document.tool_id,
        }
        identity = MappingAdmissionIdentity.build(
            journey_session_id=journey_session_id,
            target_id=normalized_context.robot_id,
            target_fingerprint=normalized_context.target_fingerprint,
            candidate_index_digest=mapping_digest({**identity_seed, "kind": "candidate-index"}),
            candidate_digest=mapping_digest({**identity_seed, "kind": "candidate"}),
            proposal_digest=mapping_digest({**identity_seed, "kind": "proposal"}),
            dsl_digest=dsl_digest(document),
            context_digest=context_digest(normalized_context),
            evidence_digest=normalized_context.evidence_digest,
            available_tool_catalog_digest=mapping_digest({**identity_seed, "kind": "catalog"}),
            scope=scope,
        )
        store = MappingConfirmationStore(store_root or tmp_path / f"admission-{item}", clock=lambda: now)
        receipt = store.confirm(
            identity,
            decision_id=f"decision-{item}",
            actor_id="test-operator",
            ttl_s=900,
            decided_at=now,
        )
        return ConfirmedMappingFixture(store=store, receipt=receipt)

    return create
