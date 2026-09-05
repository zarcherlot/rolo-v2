"""Formal C1-C4 conformance runner for offline compiler artifacts."""

import hashlib
import json
from pathlib import Path

from .canonical import ir_digest
from .compiler import compile_document
from .conformance import conformance
from .context import ProbeContext
from .models import DslDocument
from .report import ConformanceReport, GateStatus
from .resolver import resolve_evidence


class ConformanceRunner:
    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)

    def run(self, document: DslDocument, context: ProbeContext | dict) -> ConformanceReport:
        result = compile_document(document, self.output_dir / "compile", context=context)
        diagnostics = [item.code for item in result.report.diagnostics]
        c1 = GateStatus.PASS if result.document is not None and result.report.ok else GateStatus.FAIL
        c2 = GateStatus.PASS if resolve_evidence(document, context).ok else GateStatus.FAIL
        bundle_report = conformance(result)
        c3 = GateStatus.PASS if bundle_report.ok else GateStatus.FAIL
        c4 = GateStatus.FAIL
        if result.ok:
            replay = compile_document(document, self.output_dir / "replay", context=context)
            c4 = GateStatus.PASS if replay.ok and ir_digest(result.ir) == ir_digest(replay.ir) and result.bundle.digest == replay.bundle.digest else GateStatus.FAIL
            if c4 == GateStatus.FAIL:
                diagnostics.append("REPLAY_DIGEST_MISMATCH")
        diagnostics.extend(item.code for item in bundle_report.diagnostics)
        report = ConformanceReport(c1_dsl=c1, c2_evidence=c2, c3_compile=c3, c4_behavior=c4, diagnostics=tuple(dict.fromkeys(diagnostics)))
        payload = report.model_dump(mode="json")
        payload["report_digest"] = "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "conformance-c1-c4.json").write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")
        return report
