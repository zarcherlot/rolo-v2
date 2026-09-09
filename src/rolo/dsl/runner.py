"""Formal C1-C4 conformance runner for offline compiler artifacts."""

import hashlib
import json
import os
import tempfile
from pathlib import Path

from .admission import MappingAdmissionError, MappingConfirmationStore
from .canonical import ir_digest
from .compiler import _require_compile_admission, compile_document
from .conformance import conformance
from .context import ProbeContext
from .models import DslDocument
from .report import ConformanceReport, GateStatus
from .resolver import resolve_evidence


class ConformanceRunner:
    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)

    def run(
        self,
        document: DslDocument,
        context: ProbeContext | dict,
        *,
        confirmation_store: MappingConfirmationStore | None = None,
        confirmation_receipt_digest: str | None = None,
        journey_session_id: str | None = None,
    ) -> ConformanceReport:
        admission = {
            "confirmation_store": confirmation_store,
            "confirmation_receipt_digest": confirmation_receipt_digest,
            "journey_session_id": journey_session_id,
        }
        result = compile_document(
            document,
            self.output_dir / "compile",
            context=context,
            **admission,
        )
        diagnostics = [item.code for item in result.report.diagnostics]
        c1 = GateStatus.PASS if result.document is not None and result.report.ok else GateStatus.FAIL
        c2 = GateStatus.PASS if resolve_evidence(document, context).ok else GateStatus.FAIL
        bundle_report = conformance(result)
        c3 = GateStatus.PASS if bundle_report.ok else GateStatus.FAIL
        c4 = GateStatus.FAIL
        if result.ok:
            replay = compile_document(
                document,
                self.output_dir / "replay",
                context=context,
                **admission,
            )
            c4 = GateStatus.PASS if replay.ok and ir_digest(result.ir) == ir_digest(replay.ir) and result.bundle.digest == replay.bundle.digest else GateStatus.FAIL
            if c4 == GateStatus.FAIL:
                diagnostics.extend(item.code for item in replay.report.diagnostics)
                diagnostics.append("REPLAY_DIGEST_MISMATCH")
        diagnostics.extend(item.code for item in bundle_report.diagnostics)
        report = ConformanceReport(c1_dsl=c1, c2_evidence=c2, c3_compile=c3, c4_behavior=c4, diagnostics=tuple(dict.fromkeys(diagnostics)))
        payload = report.model_dump(mode="json")
        payload["report_digest"] = "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        # Missing, cancelled, expired, or mismatched admission is a boundary
        # failure, not a conformance artifact.  Keep the output tree untouched.
        if not any(code.startswith("MAPPING_") for code in diagnostics):
            self.output_dir.mkdir(parents=True, exist_ok=True)
            handle, staging_name = tempfile.mkstemp(
                prefix=".conformance-c1-c4.",
                suffix=".tmp",
                dir=self.output_dir,
            )
            os.close(handle)
            staging_report = Path(staging_name)
            try:
                staging_report.write_text(
                    json.dumps(payload, sort_keys=True, indent=2),
                    encoding="utf-8",
                )
                normalized_context = (
                    context
                    if isinstance(context, ProbeContext)
                    else ProbeContext.model_validate(context)
                )
                _require_compile_admission(
                    document,
                    normalized_context,
                    result.dsl_digest,
                    confirmation_store=confirmation_store,
                    confirmation_receipt_digest=confirmation_receipt_digest,
                    journey_session_id=journey_session_id,
                    commit=lambda: os.replace(
                        staging_report,
                        self.output_dir / "conformance-c1-c4.json",
                    ),
                )
            except MappingAdmissionError as exc:
                diagnostics.append(exc.code)
                report = report.model_copy(
                    update={
                        "c4_behavior": GateStatus.FAIL,
                        "diagnostics": tuple(dict.fromkeys(diagnostics)),
                    }
                )
            finally:
                staging_report.unlink(missing_ok=True)
        return report
