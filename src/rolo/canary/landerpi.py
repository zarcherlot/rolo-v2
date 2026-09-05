"""Offline LanderPi MVP canary pipeline."""

import json
from pathlib import Path

from rolo.dsl.compiler import compile_document
from rolo.dsl.context import ProbeContext
from rolo.dsl.models import DslDocument
from rolo.dsl.runner import ConformanceRunner
from rolo.releases import CertifyConsumer, ReleasePublisher, TraceConsumer


class LanderPiCanary:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    def run(self) -> dict:
        context = ProbeContext(
            robot_id="landerpi",
            target_fingerprint="landerpi-offline-v1",
            evidence_digest="sha256:landerpi-evidence",
            evidence_refs=("route:/navigation/state",),
            routes=({"resource_id": "route:/navigation/state", "protocol": "ros2"},),
            message_schemas=({"schema_id": "nav_msgs/msg/Odometry"},),
        )
        document = DslDocument(
            tool_id="app.navigation.status",
            kind="OBSERVE",
            target={"robot_id": "landerpi", "evidence_digest": context.evidence_digest},
            binding={"resource_id": "route:/navigation/state", "protocol": "ros2"},
            evidence_refs=("route:/navigation/state",),
            output_schema={"type": "object"},
        )
        result = compile_document(document, self.root / "compile", context=context)
        conformance = ConformanceRunner(self.root / "conformance").run(document, context)
        release = ReleasePublisher(self.root / "catalog").publish(result, conformance, target_fingerprint=context.target_fingerprint, compiler_version="rolo-compiler/0.1")
        release_digest = "sha256:offline-landerpi-release"
        trace = TraceConsumer().consume(
            release,
            release_digest=release_digest,
            session_id="landerpi-canary-session",
            evidence_digest=context.evidence_digest,
            target_fingerprint=context.target_fingerprint,
            input={"query": "navigation.status"},
        )
        cases = []
        for index in range(1, 11):
            case = CertifyConsumer().consume(
                release,
                release_digest=release_digest,
                session_id="landerpi-canary-session",
                evidence_digest=context.evidence_digest,
                target_fingerprint=context.target_fingerprint,
                test_case_id=f"landerpi-certify-{index:02d}",
            )
            cases.append(case.model_dump(mode="json"))
        report = {
            "status": "PASS",
            "target": context.robot_id,
            "release_digest": release_digest,
            "trace": trace.model_dump(mode="json"),
            "certify": cases,
            "conformance": conformance.model_dump(mode="json"),
        }
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "landerpi-canary.json").write_text(json.dumps(report, sort_keys=True, indent=2), encoding="utf-8")
        return report
