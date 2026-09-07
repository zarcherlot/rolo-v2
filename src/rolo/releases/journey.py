"""Release-bound Trace/Certify consumers and a replayable post-compiler journey.

The compiler and targetd layers produce immutable, digest-addressed artifacts.
This module is the small adapter that makes the same release identity
mandatory for Trace and Certify, while keeping the existing MVP services as
the state-machine implementations.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.compiler import compile_document
from rolo.dsl.models import StrictModel
from rolo.dsl.parser import parse_document
from rolo.dsl.runner import ConformanceRunner
from rolo.mvp.artifacts import build_artifact_index, write_artifact_index
from rolo.mvp.certify import CertificationRunner, write_report
from rolo.mvp.contracts import CertificationReport, CertificationSuite, TargetCatalog, TraceCall, TraceSessionRequest
from rolo.mvp.trace import TraceService
from rolo.observability import ObservabilityRecorder
from rolo.targetd.dsl_protocol import DslFrame, DslFrameType
from rolo.targetd.dsl_service import TargetdDslService

from .consumers import CertifyConsumer, ExecutionEnvelope, TraceConsumer
from .publisher import ReleasePublisher, TargetConformanceReport, ToolRelease


@dataclass(frozen=True)
class ReleaseInvocation:
    """One release-bound invocation retained for the journey artifact graph."""

    envelope: ExecutionEnvelope
    result: Any


class PublishedReleaseInvoker:
    """Invoke a tool only while its exact immutable release is current."""

    def __init__(
        self,
        publisher: ReleasePublisher,
        release_digest: str,
        *,
        target_fingerprint: str,
        evidence_digest: str,
        invoker: Callable[..., Any],
        compile_context_digest: str | None = None,
        route_digest: str | None = None,
        mhs_manifest_digests: tuple[str, ...] = (),
    ) -> None:
        self.publisher = publisher
        self.release_digest = release_digest
        self.target_fingerprint = target_fingerprint
        self.evidence_digest = evidence_digest
        self.invoker = invoker
        self.compile_context_digest = compile_context_digest
        self.route_digest = route_digest
        self.mhs_manifest_digests = tuple(mhs_manifest_digests)
        self.invocations: list[ReleaseInvocation] = []

    def __call__(
        self,
        tool_id: str,
        arguments: Mapping[str, Any],
        session_id: str,
        idempotency_key: str | None = None,
    ) -> Any:
        current = self.publisher.current(tool_id)
        if current is None:
            raise ValueError("RELEASE_NOT_CURRENT")
        current_digest, release = current
        if current_digest != self.release_digest:
            raise ValueError("RELEASE_NOT_CURRENT")
        if release.status != "PUBLISHED" or not release.agent_callable:
            raise ValueError("RELEASE_NOT_CURRENT")
        envelope = TraceConsumer().consume(
            release,
            release_digest=self.release_digest,
            session_id=session_id,
            idempotency_key=idempotency_key,
            evidence_digest=self.evidence_digest,
            target_fingerprint=self.target_fingerprint,
            compile_context_digest=self.compile_context_digest,
            route_digest=self.route_digest,
            mhs_manifest_digests=self.mhs_manifest_digests,
            input=dict(arguments),
        )
        result = self._invoke_target(tool_id, arguments, session_id, idempotency_key)
        self.invocations.append(ReleaseInvocation(envelope=envelope, result=result))
        return result

    def _invoke_target(
        self,
        tool_id: str,
        arguments: Mapping[str, Any],
        session_id: str,
        idempotency_key: str | None,
    ) -> Any:
        """Preserve compatibility with legacy three-argument providers."""

        if idempotency_key is None:
            return self.invoker(tool_id, arguments, session_id)
        try:
            import inspect

            signature = inspect.signature(self.invoker)
            positional = [
                parameter
                for parameter in signature.parameters.values()
                if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
            ]
            accepts_varargs = any(parameter.kind == parameter.VAR_POSITIONAL for parameter in signature.parameters.values())
        except (TypeError, ValueError):
            positional = []
            accepts_varargs = True
        if accepts_varargs or len(positional) >= 4:
            return self.invoker(tool_id, arguments, session_id, idempotency_key)
        return self.invoker(tool_id, arguments, session_id)


class ReleaseBoundTrace:
    """Run the existing Trace state machine against a published release."""

    def __init__(
        self,
        catalog: TargetCatalog,
        publisher: ReleasePublisher,
        *,
        release_digest: str,
        target_fingerprint: str,
        evidence_digest: str,
        invoker: Callable[[str, Mapping[str, Any], str], Any],
        artifact_root: Path | None = None,
        compile_context_digest: str | None = None,
        route_digest: str | None = None,
        mhs_manifest_digests: tuple[str, ...] = (),
    ) -> None:
        self.bound_invoker = PublishedReleaseInvoker(
            publisher,
            release_digest,
            target_fingerprint=target_fingerprint,
            evidence_digest=evidence_digest,
            invoker=invoker,
            compile_context_digest=compile_context_digest,
            route_digest=route_digest,
            mhs_manifest_digests=mhs_manifest_digests,
        )
        trace_root = artifact_root or (publisher.root / "trace-artifacts")
        self.service = TraceService(
            catalog,
            self.bound_invoker,
            artifact_root=trace_root,
            release_digest=release_digest,
            compile_context_digest=compile_context_digest,
            target_fingerprint=target_fingerprint,
        )

    def run(
        self,
        request: TraceSessionRequest,
        calls: Sequence[TraceCall | Mapping[str, Any]],
        *,
        diagnose: Callable[[Any, Any], TraceCall | Mapping[str, Any] | None] | None = None,
        recover: Callable[[Any, Any], TraceCall | Mapping[str, Any] | None] | None = None,
    ) -> tuple[Any, dict[str, Path]]:
        # The release identity is authoritative at this boundary.  A caller
        # may omit metadata for compatibility, but cannot substitute another
        # release/context/target in the Trace request.
        request = request.model_copy(
            update={
                "release_digest": self.bound_invoker.release_digest,
                "compile_context_digest": self.bound_invoker.compile_context_digest,
                "target_fingerprint": self.bound_invoker.target_fingerprint,
            }
        )
        session = self.service.create_session(request)
        session = self.service.execute(session.session_id, calls, diagnose=diagnose, recover=recover)
        paths = self.service.persist_session(session.session_id)
        session_dir = Path(paths["session"]).parent
        binding_path = session_dir / "release-binding.json"
        binding_path.write_text(
            json.dumps(
                {
                    "schema_version": "rolo-release-binding/v1",
                    "release_digest": self.bound_invoker.release_digest,
                    "target_fingerprint": self.bound_invoker.target_fingerprint,
                    "evidence_digest": self.bound_invoker.evidence_digest,
                    "compile_context_digest": self.bound_invoker.compile_context_digest,
                    "route_digest": self.bound_invoker.route_digest,
                    "mhs_manifest_digests": list(self.bound_invoker.mhs_manifest_digests),
                },
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        event_path = session_dir / "trace-events.jsonl"
        index = build_artifact_index(
            run_id=session.session_id,
            target_id=session.target_id,
            files=[paths["session"], paths["evidence"], binding_path, event_path],
            root=session_dir,
        )
        write_artifact_index(session_dir / "artifact-index.json", index)
        paths["binding"] = binding_path
        paths["index"] = session_dir / "artifact-index.json"
        return session, paths


class ReleaseBoundCertify:
    """Run the fixed certification suite through the same release guard."""

    def __init__(
        self,
        publisher: ReleasePublisher,
        *,
        release_digests: Mapping[str, str],
        target_fingerprint: str,
        evidence_digest: str,
        invoker: Callable[..., Any],
        compile_context_digest: str | None = None,
        route_digest: str | None = None,
        mhs_manifest_digests: tuple[str, ...] = (),
    ) -> None:
        self.publisher = publisher
        self.release_digests = dict(release_digests)
        self.target_fingerprint = target_fingerprint
        self.evidence_digest = evidence_digest
        self.invoker = invoker
        self.compile_context_digest = compile_context_digest
        self.route_digest = route_digest
        self.mhs_manifest_digests = tuple(mhs_manifest_digests)
        self.invocations: list[ReleaseInvocation] = []

    def run(
        self,
        suite: CertificationSuite,
        *,
        snapshot_digest: str,
        output: Path,
        session_id: str | None = None,
    ) -> tuple[CertificationReport, tuple[Path, Path]]:
        def invoke(
            tool_id: str,
            arguments: Mapping[str, Any],
            session: str,
            idempotency_key: str | None = None,
        ) -> Any:
            release_digest = self.release_digests.get(tool_id)
            if release_digest is None:
                raise ValueError("RELEASE_NOT_CURRENT")
            current = self.publisher.current(tool_id)
            if current is None or current[0] != release_digest:
                raise ValueError("RELEASE_NOT_CURRENT")
            if current[1].status != "PUBLISHED" or not current[1].agent_callable:
                raise ValueError("RELEASE_NOT_CURRENT")
            envelope = CertifyConsumer().consume(
                current[1],
                release_digest=release_digest,
                session_id=session,
                idempotency_key=idempotency_key,
                evidence_digest=self.evidence_digest,
                target_fingerprint=self.target_fingerprint,
                compile_context_digest=self.compile_context_digest,
                route_digest=self.route_digest,
                mhs_manifest_digests=self.mhs_manifest_digests,
                input=dict(arguments),
            )
            if idempotency_key is None:
                result = self.invoker(tool_id, arguments, session)
            else:
                try:
                    import inspect

                    signature = inspect.signature(self.invoker)
                    positional = [
                        parameter
                        for parameter in signature.parameters.values()
                        if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
                    ]
                    accepts_varargs = any(parameter.kind == parameter.VAR_POSITIONAL for parameter in signature.parameters.values())
                except (TypeError, ValueError):
                    positional = []
                    accepts_varargs = True
                result = (
                    self.invoker(tool_id, arguments, session, idempotency_key)
                    if accepts_varargs or len(positional) >= 4
                    else self.invoker(tool_id, arguments, session)
                )
            self.invocations.append(ReleaseInvocation(envelope=envelope, result=result))
            return result

        runner = CertificationRunner(invoke, target_id=suite.target_id)
        report = runner.run(
            suite,
            snapshot_digest=snapshot_digest,
            session_id=session_id,
            compile_context_digest=self.compile_context_digest,
            target_fingerprint=self.target_fingerprint,
            release_digests=self.release_digests,
        )
        paths = write_report(report, output)
        json_path, md_path = paths
        html_path = json_path.with_suffix(".html")
        binding_path = json_path.parent / "release-binding.json"
        if binding_path.exists():
            binding_path = json_path.parent / f"{json_path.stem}.release-binding.json"
        binding_path.write_text(
            json.dumps(
                {
                    "schema_version": "rolo-release-binding/v1",
                    "release_digests": dict(sorted(self.release_digests.items())),
                    "target_fingerprint": self.target_fingerprint,
                    "evidence_digest": self.evidence_digest,
                    "compile_context_digest": self.compile_context_digest,
                    "route_digest": self.route_digest,
                    "mhs_manifest_digests": list(self.mhs_manifest_digests),
                },
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        suite_name = "certify-test-suite.json" if json_path.name == (output if output.suffix == ".json" else output.with_suffix(".json")).name else f"{json_path.stem}.certify-test-suite.json"
        suite_path = json_path.parent / suite_name
        suite_path.write_text(json.dumps(suite.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        event_path = json_path.parent / f"{json_path.stem}.events.jsonl"
        event_path.write_text("".join(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n" for item in runner.events), encoding="utf-8")
        index_name = "artifact-index.json" if json_path.name == (output if output.suffix == ".json" else output.with_suffix(".json")).name else f"{json_path.stem}.artifact-index.json"
        index_path = json_path.with_name(index_name)
        files = [json_path, md_path, binding_path, suite_path, event_path]
        if html_path.is_file():
            files.append(html_path)
        index = build_artifact_index(run_id=report.run_id, target_id=report.target_id, files=files, root=json_path.parent)
        write_artifact_index(index_path, index)
        return report, (json_path, md_path)


class PostCompilerJourneyResult(StrictModel):
    """Digest-linked summary of the offline-to-release part of a journey."""

    schema_version: str = "rolo-post-compiler-journey-result/v1"
    status: str
    journey_session_id: str
    target_id: str
    dsl_digest: str
    context_digest: str
    target_compile_status: str
    target_conformance_digest: str | None = None
    release_digest: str | None = None
    diagnostics: tuple[str, ...] = ()


class PostCompilerJourney:
    """Execute the frozen DSL → targetd → conformance → publish sequence.

    The targetd service can be replaced by the SSH stdio transport at the
    caller boundary.  This class deliberately never publishes when any gate
    is failed and writes a digest-linked manifest for replay.
    """

    def __init__(self, root: Path, *, publisher: ReleasePublisher, targetd: TargetdDslService | None = None, observability: ObservabilityRecorder | None = None) -> None:
        self.root = Path(root)
        self.publisher = publisher
        self.targetd = targetd or TargetdDslService(self.root / "targetd-cache")
        self.observability = observability

    def _metric(self, *, event: str, status: str, journey_session_id: str, target_id: str, payload: Mapping[str, Any] | None = None) -> None:
        if self.observability is not None:
            self.observability.record(
                event=event,
                stage="post-compiler-journey",
                status=status,
                session_id=journey_session_id,
                target_id=target_id,
                payload=payload or {},
            )

    def run(
        self,
        *,
        journey_session_id: str,
        target_id: str,
        dsl: Mapping[str, Any],
        context: Mapping[str, Any],
        target_fingerprint: str,
        compiler_version: str = "rolo-compiler/0.1",
        mhs_manifest_digests: tuple[str, ...] = (),
        route_digest: str | None = None,
    ) -> tuple[PostCompilerJourneyResult, ToolRelease | None]:
        self._metric(event="journey.started", status="STARTED", journey_session_id=journey_session_id, target_id=target_id)
        dsl_dict = dict(dsl)
        context_dict = dict(context)
        actual_context_digest = context_digest(context_dict)
        document, parse_report = parse_document(dsl_dict)
        if document is None or not parse_report.ok:
            result = PostCompilerJourneyResult(
                status="BLOCKED",
                journey_session_id=journey_session_id,
                target_id=target_id,
                dsl_digest="",
                context_digest=actual_context_digest,
                target_compile_status="DSL_COMPILE_FAILED",
                diagnostics=tuple(item.code for item in parse_report.diagnostics),
            )
            self._metric(event="journey.blocked", status="BLOCKED", journey_session_id=journey_session_id, target_id=target_id, payload={"diagnostics": list(result.diagnostics)})
            return result, None
        actual_dsl_digest = dsl_digest(document)
        put = DslFrame(
            frame_type=DslFrameType.DSL_PUT,
            request_id=f"{journey_session_id}:put",
            payload={
                "dsl": dsl_dict,
                "context": context_dict,
                "compiler_version": compiler_version,
                "dsl_digest": actual_dsl_digest,
                "context_digest": actual_context_digest,
                "target_fingerprint": target_fingerprint,
            },
        )
        put_response = self.targetd.handle(put)
        if put_response.payload.get("diagnostics"):
            return self._blocked(journey_session_id, target_id, actual_dsl_digest, actual_context_digest, put_response.payload), None
        check_response = self.targetd.handle(
            DslFrame(
                frame_type=DslFrameType.DSL_CHECK,
                request_id=f"{journey_session_id}:check",
                payload={"dsl_digest": actual_dsl_digest},
            )
        )
        if check_response.payload.get("status") != "PASS":
            return self._blocked(journey_session_id, target_id, actual_dsl_digest, actual_context_digest, check_response.payload), None
        resolve_response = self.targetd.handle(
            DslFrame(
                frame_type=DslFrameType.PLAN_RESOLVE,
                request_id=f"{journey_session_id}:resolve",
                payload={"dsl_digest": actual_dsl_digest},
            )
        )
        if resolve_response.payload.get("status") != "PASS":
            return self._blocked(journey_session_id, target_id, actual_dsl_digest, actual_context_digest, resolve_response.payload), None
        compile_response = self.targetd.handle(
            DslFrame(
                frame_type=DslFrameType.TARGET_COMPILE,
                request_id=f"{journey_session_id}:compile",
                payload={
                    "dsl_digest": actual_dsl_digest,
                    "context_digest": actual_context_digest,
                    "target_fingerprint": target_fingerprint,
                },
            )
        )
        compile_payload = compile_response.payload
        if compile_payload.get("status") != "PASS":
            return self._blocked(journey_session_id, target_id, actual_dsl_digest, actual_context_digest, compile_payload), None
        conformance_response = self.targetd.handle(
            DslFrame(
                frame_type=DslFrameType.TARGET_CONFORMANCE,
                request_id=f"{journey_session_id}:conformance",
                payload={
                    "dsl_digest": actual_dsl_digest,
                    "context_digest": actual_context_digest,
                    "target_fingerprint": target_fingerprint,
                },
            )
        )
        conformance_payload = conformance_response.payload
        target_report = conformance_payload.get("target_conformance_report")
        if conformance_payload.get("target_conformance") != "PASS" or not isinstance(target_report, Mapping):
            return self._blocked(journey_session_id, target_id, actual_dsl_digest, actual_context_digest, conformance_payload), None
        target_conformance = TargetConformanceReport.model_validate(target_report)
        compiler_result = compile_document(document, self.root / "compiler", context=context_dict)
        compiler_report = ConformanceRunner(self.root / "compiler-conformance").run(document, context_dict)
        if not compiler_result.ok or not compiler_report.passed:
            return self._blocked(journey_session_id, target_id, actual_dsl_digest, actual_context_digest, {"diagnostics": ["COMPILER_CONFORMANCE_FAILED"]}), None
        release = self.publisher.publish_verified(
            compiler_result,
            compiler_report,
            target_conformance,
            target_fingerprint=target_fingerprint,
            compiler_version=compiler_version,
            mhs_manifest_digests=mhs_manifest_digests,
            compile_context_digest=actual_context_digest,
            route_digest=route_digest,
        )
        release_digest = self.publisher.current(release.tool_id)[0] if self.publisher.current(release.tool_id) else None
        artifact_dir = self.root / "journeys" / target_id / journey_session_id
        artifact_dir.mkdir(parents=True, exist_ok=True)
        files = {
            "dsl": artifact_dir / "mapping.dsl.json",
            "context": artifact_dir / "compile-context.json",
            "compiler_conformance": artifact_dir / "compiler-conformance.json",
            "bundle": artifact_dir / "bundle-manifest.json",
            "dsl_check": artifact_dir / "dsl-check.json",
            "plan_resolve": artifact_dir / "plan-resolve.json",
            "target_compile": artifact_dir / "target-compile.json",
            "target_conformance": artifact_dir / "target-conformance.json",
            "release": artifact_dir / "release-manifest.json",
            "journey": artifact_dir / "journey-result.json",
        }
        files["dsl"].write_text(json.dumps(dsl_dict, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        files["context"].write_text(json.dumps(context_dict, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        files["compiler_conformance"].write_text(
            (self.root / "compiler-conformance" / "conformance-c1-c4.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        files["bundle"].write_text(
            (self.root / "compiler" / "manifest.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        files["dsl_check"].write_text(json.dumps(check_response.payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        files["plan_resolve"].write_text(json.dumps(resolve_response.payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        files["target_compile"].write_text(json.dumps(compile_payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        files["target_conformance"].write_text(json.dumps(conformance_payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        files["release"].write_text(
            json.dumps(
                {"release_digest": release_digest, "release": release.model_dump(mode="json")},
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        result = PostCompilerJourneyResult(
            status="PASS",
            journey_session_id=journey_session_id,
            target_id=target_id,
            dsl_digest=actual_dsl_digest,
            context_digest=actual_context_digest,
            target_compile_status=str(compile_payload.get("status")),
            target_conformance_digest=conformance_payload.get("target_conformance_digest"),
            release_digest=release_digest,
            diagnostics=tuple(conformance_payload.get("diagnostics", ())),
        )
        files["journey"].write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
        index = build_artifact_index(run_id=journey_session_id, target_id=target_id, files=list(files.values()), root=artifact_dir)
        write_artifact_index(artifact_dir / "artifact-index.json", index)
        self._metric(event="journey.completed", status="PASS", journey_session_id=journey_session_id, target_id=target_id, payload={"release_digest": release_digest})
        return result, release

    def _blocked(self, journey_session_id: str, target_id: str, dsl_digest_value: str, context_digest_value: str, payload: Mapping[str, Any]) -> PostCompilerJourneyResult:
        diagnostics = payload.get("diagnostics", ())
        if isinstance(diagnostics, str):
            diagnostics = (diagnostics,)
        result = PostCompilerJourneyResult(
            status="BLOCKED",
            journey_session_id=journey_session_id,
            target_id=target_id,
            dsl_digest=dsl_digest_value,
            context_digest=context_digest_value,
            target_compile_status=str(payload.get("status", "BLOCKED")),
            target_conformance_digest=payload.get("target_conformance_digest"),
            diagnostics=tuple(str(item) for item in diagnostics),
        )
        self._metric(
            event="journey.blocked",
            status="BLOCKED",
            journey_session_id=journey_session_id,
            target_id=target_id,
            payload={"diagnostics": list(result.diagnostics), "stage": result.target_compile_status},
        )
        return result


__all__ = [
    "PostCompilerJourney",
    "PostCompilerJourneyResult",
    "PublishedReleaseInvoker",
    "ReleaseBoundCertify",
    "ReleaseBoundTrace",
    "ReleaseInvocation",
]
