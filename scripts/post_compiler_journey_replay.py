"""Replay the complete offline post-compiler journey.

This is the CI/fake-target companion to the LanderPi canary.  It exercises the
same digest checks and release-bound Trace/Certify adapters without touching a
robot or opening an SSH connection.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
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
from rolo.mvp.contracts import CatalogTool, CertificationCase, CertificationSuite, TargetCatalog, ToolState, TraceCall, TraceSessionRequest
from rolo.releases import PostCompilerJourney, ReleaseBoundCertify, ReleaseBoundTrace, ReleasePublisher


def run(output: Path) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=True)
    fingerprint = "a" * 64
    evidence_digest = "sha256:" + "e" * 64
    context_model = ProbeContext(
        robot_id="mentorpi",
        target_fingerprint=fingerprint,
        evidence_digest=evidence_digest,
        evidence_refs=("route:/state",),
        routes=(
            {
                "candidate_id": "mapping-status-route",
                "operation": "app.mapping.status",
                "resource_id": "route:/state",
                "confidence": 1.0,
            },
        ),
        freshness={"status": "fresh"},
    )
    document = DslDocument(
        tool_id="app.mapping.status",
        kind="OBSERVE",
        target={
            "robot_id": "mentorpi",
            "evidence_digest": evidence_digest,
        },
        binding={"resource_id": "route:/state"},
        evidence_refs=("route:/state",),
    )
    context = context_model.model_dump(mode="json")
    dsl = document.model_dump(mode="json", exclude_none=True)

    # This is an explicit fake-target decision outside PostCompilerJourney.
    # The journey itself only consumes a receipt already committed to the
    # trusted ledger and cannot synthesize or renew one.
    candidate_index = build_candidate_index(context_model)
    candidate = candidate_index.candidates[0]
    mapping_request = AdapterMappingRequest(
        journey_session_id="replay-journey-1",
        user_goal="inspect offline mapping state",
        context_digest=context_digest(context_model),
        available_tool_catalog_digest=mapping_digest({"schema_version": "rolo-tool-catalog/v1", "tools": {}}),
        operation_candidates=(document.tool_id,),
    )
    proposal = build_mapping_proposal(
        mapping_request,
        candidate_index,
        candidate,
        dsl=document,
        context=context_model,
        scope=MappingAdmissionScope(
            tool_id=document.tool_id,
            operation_kind=document.kind,
            operations=(document.tool_id,),
            access="read",
            risk="R0",
        ),
    )
    proposal_path = persist_mapping_proposal(proposal, output / "admission")
    confirmation_store = MappingConfirmationStore(output / "admission")
    receipt = confirmation_store.confirm(
        proposal.admission_identity(),
        decision_id="offline-replay-decision-1",
        actor_id="offline-replay-fixture",
        ttl_s=900,
    )
    publisher = ReleasePublisher(output / "catalog", confirmation_store=confirmation_store)
    journey, release = PostCompilerJourney(output / "journey", publisher=publisher, offline_replay=True).run(
        journey_session_id="replay-journey-1",
        target_id="mentorpi",
        dsl=dsl,
        context=context,
        target_fingerprint=fingerprint,
        confirmation_receipt_digest=receipt.receipt_digest,
    )
    if journey.status != "PASS" or release is None or journey.release_digest is None:
        raise RuntimeError(f"post-compiler journey blocked: {journey.diagnostics}")
    catalog = TargetCatalog(
        target_id="mentorpi",
        target_fingerprint=fingerprint,
        snapshot_digest="UNKNOWN",
        generated_at=datetime.now(timezone.utc),
        freshness="fresh",
        tools=[CatalogTool(tool_id=release.tool_id, target_id="mentorpi", state=ToolState.CALLABLE, agent_callable=True)],
    ).with_digest()
    trace = ReleaseBoundTrace(
        catalog,
        publisher,
        release_digest=journey.release_digest,
        target_fingerprint=fingerprint,
        evidence_digest=evidence_digest,
        compile_context_digest=journey.context_digest,
        invoker=lambda *_: {"status": "SUCCEEDED"},
        artifact_root=output / "trace",
    )
    trace_session, trace_paths = trace.run(
        TraceSessionRequest(target_id="mentorpi", catalog_digest=catalog.digest or "", task="inspect mapping state"),
        [TraceCall(tool_id=release.tool_id)],
    )
    suite = CertificationSuite(
        schema_version="rolo-mvp-certification-suite/v1",
        suite_id="mapping-replay-10",
        target_id="mentorpi",
        cases=[
            CertificationCase(
                case_id=f"case-{index:02d}",
                description="replay mapping status",
                tool_id=release.tool_id,
                expected={"status": "SUCCEEDED"},
            )
            for index in range(1, 11)
        ],
    )
    certify = ReleaseBoundCertify(
        publisher,
        release_digests={release.tool_id: journey.release_digest},
        target_fingerprint=fingerprint,
        evidence_digest=evidence_digest,
        compile_context_digest=journey.context_digest,
        invoker=lambda *_: {"status": "SUCCEEDED"},
    )
    report, certify_paths = certify.run(
        suite,
        snapshot_digest="UNKNOWN",
        output=output / "certify" / "report.json",
        session_id="replay-certify-1",
    )
    if trace_session.state.value != "COMPLETED" or report.conclusion != "PASS":
        raise RuntimeError("Trace/Certify replay did not pass")
    return {
        "status": "PASS",
        "mapping_proposal": str(proposal_path),
        "confirmation_receipt_digest": receipt.receipt_digest,
        "journey": journey.model_dump(mode="json"),
        "trace_state": trace_session.state.value,
        "trace_artifact_index": str(trace_paths["index"]),
        "certify_conclusion": report.conclusion,
        "certify_case_count": len(report.results),
        "certify_report": str(certify_paths[0]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay the offline post-compiler journey")
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/post-compiler-replay"))
    args = parser.parse_args()
    print(json.dumps(run(args.output_dir), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
