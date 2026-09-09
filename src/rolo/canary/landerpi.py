"""Offline LanderPi MVP canary pipeline."""

import json
from pathlib import Path

from rolo.dsl.admission import (
    MappingAdmissionScope,
    MappingConfirmationStore,
    mapping_digest,
)
from rolo.dsl.candidates import build_candidate_index
from rolo.dsl.canonical import context_digest
from rolo.dsl.context import ProbeContext
from rolo.dsl.mapping import AdapterMappingRequest
from rolo.dsl.models import DslDocument
from rolo.dsl.proposal import build_mapping_proposal, persist_mapping_proposal
from rolo.releases import (
    CertifyConsumer,
    PostCompilerJourney,
    ReleasePublisher,
    TraceConsumer,
    tool_release_digest,
)


class LanderPiCanary:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    def run(self) -> dict:
        evidence_digest = "sha256:" + "e" * 64
        context = ProbeContext(
            robot_id="landerpi",
            target_fingerprint="a" * 64,
            evidence_digest=evidence_digest,
            evidence_refs=("route:/navigation/state",),
            routes=(
                {
                    "candidate_id": "navigation-status-route",
                    "operation": "app.navigation.status",
                    "resource_id": "route:/navigation/state",
                    "protocol": "ros2",
                    "confidence": 1.0,
                },
            ),
            message_schemas=({"schema_id": "nav_msgs/msg/Odometry"},),
            freshness={"status": "fresh"},
        )
        document = DslDocument(
            tool_id="app.navigation.status",
            kind="OBSERVE",
            target={"robot_id": "landerpi", "evidence_digest": context.evidence_digest},
            binding={"resource_id": "route:/navigation/state"},
            evidence_refs=("route:/navigation/state",),
            output_schema={"type": "object"},
        )
        candidate_index = build_candidate_index(context)
        proposal = build_mapping_proposal(
            AdapterMappingRequest(
                journey_session_id="landerpi-canary-session",
                user_goal="inspect offline LanderPi navigation state",
                context_digest=context_digest(context),
                available_tool_catalog_digest=mapping_digest({"schema_version": "rolo-tool-catalog/v1", "tools": {}}),
                operation_candidates=(document.tool_id,),
            ),
            candidate_index,
            candidate_index.candidates[0],
            dsl=document,
            context=context,
            scope=MappingAdmissionScope(
                tool_id=document.tool_id,
                operation_kind=document.kind,
                operations=(document.tool_id,),
                access="read",
                risk="R0",
            ),
        )
        proposal_path = persist_mapping_proposal(proposal, self.root / "admission")
        confirmation_store = MappingConfirmationStore(self.root / "admission")
        receipt = confirmation_store.confirm(
            proposal.admission_identity(),
            decision_id="landerpi-offline-canary-decision",
            actor_id="landerpi-offline-canary-fixture",
            ttl_s=900,
        )
        publisher = ReleasePublisher(self.root / "catalog", confirmation_store=confirmation_store)
        journey, release = PostCompilerJourney(
            self.root / "journey",
            publisher=publisher,
            offline_replay=True,
        ).run(
            journey_session_id="landerpi-canary-session",
            target_id=context.robot_id,
            dsl=document.model_dump(mode="json"),
            context=context.model_dump(mode="json"),
            target_fingerprint=context.target_fingerprint,
            confirmation_receipt_digest=receipt.receipt_digest,
        )
        if journey.status != "PASS" or release is None:
            raise RuntimeError(f"offline LanderPi journey blocked: {journey.diagnostics}")
        release_digest = tool_release_digest(release)
        trace = TraceConsumer(confirmation_store=confirmation_store).consume(
            release,
            release_digest=release_digest,
            session_id="landerpi-canary-session",
            evidence_digest=context.evidence_digest,
            target_fingerprint=context.target_fingerprint,
            compile_context_digest=context_digest(context),
            input={"query": "navigation.status"},
        )
        cases = []
        for index in range(1, 11):
            case = CertifyConsumer(confirmation_store=confirmation_store).consume(
                release,
                release_digest=release_digest,
                session_id="landerpi-canary-session",
                evidence_digest=context.evidence_digest,
                target_fingerprint=context.target_fingerprint,
                compile_context_digest=context_digest(context),
                test_case_id=f"landerpi-certify-{index:02d}",
            )
            cases.append(case.model_dump(mode="json"))
        report = {
            "status": "PASS",
            "target": context.robot_id,
            "release_digest": release_digest,
            "mapping_proposal": str(proposal_path),
            "proposal_digest": proposal.proposal_digest,
            "confirmation_receipt_digest": receipt.receipt_digest,
            "trace": trace.model_dump(mode="json"),
            "certify": cases,
            "conformance": journey.model_dump(mode="json"),
        }
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "landerpi-canary.json").write_text(json.dumps(report, sort_keys=True, indent=2), encoding="utf-8")
        return report
