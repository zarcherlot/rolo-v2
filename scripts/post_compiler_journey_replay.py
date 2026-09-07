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

from rolo.mvp.contracts import CatalogTool, CertificationCase, CertificationSuite, TargetCatalog, ToolState, TraceCall, TraceSessionRequest
from rolo.releases import PostCompilerJourney, ReleaseBoundCertify, ReleaseBoundTrace, ReleasePublisher


def run(output: Path) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=True)
    fingerprint = "a" * 64
    context = {
        "robot_id": "mentorpi",
        "target_fingerprint": fingerprint,
        "evidence_digest": "sha256:e",
        "evidence_refs": ["route:/state"],
    }
    dsl = {
        "tool_id": "app.mapping.status",
        "kind": "OBSERVE",
        "target": {"robot_id": "mentorpi", "evidence_digest": "sha256:e"},
        "binding": {"resource_id": "route:/state"},
    }
    publisher = ReleasePublisher(output / "catalog")
    journey, release = PostCompilerJourney(output / "journey", publisher=publisher).run(
        journey_session_id="replay-journey-1",
        target_id="mentorpi",
        dsl=dsl,
        context=context,
        target_fingerprint=fingerprint,
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
        evidence_digest="sha256:e",
        compile_context_digest=journey.context_digest,
        invoker=lambda *_: {"status": "SUCCEEDED"},
        artifact_root=output / "trace",
    )
    trace_session, trace_paths = trace.run(
        TraceSessionRequest(target_id="mentorpi", catalog_digest=catalog.digest or "", task="inspect mapping state"),
        [TraceCall(tool_id=release.tool_id)],
    )
    suite = CertificationSuite(
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
        evidence_digest="sha256:e",
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
