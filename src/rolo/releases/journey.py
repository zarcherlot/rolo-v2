"""Release-bound Trace/Certify consumers and a replayable post-compiler journey.

The compiler and targetd layers produce immutable, digest-addressed artifacts.
This module is the small adapter that makes the same release identity
mandatory for Trace and Certify, while keeping the existing MVP services as
the state-machine implementations.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from rolo.dsl.admission import (
    MappingAdmissionError,
    MappingAdmissionGate,
    MappingAdmissionIdentity,
    MappingAdmissionScope,
    MappingConfirmationReceipt,
)
from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.compiler import compile_document
from rolo.dsl.context import ProbeContext
from rolo.dsl.contracts import JOURNEY_RESULT_SCHEMA_VERSION, RELEASE_BINDING_SCHEMA_VERSION, TARGETD_COMPILE_SCHEMA_VERSION
from rolo.dsl.models import StrictModel
from rolo.dsl.parser import parse_document
from rolo.dsl.runner import ConformanceRunner
from rolo.mvp.artifacts import build_artifact_index, write_artifact_index
from rolo.mvp.certify import (
    ArtifactPlanReservation,
    CertificationInvocationContext,
    CertificationInvocationOutcome,
    CertificationRunner,
    reserve_new_artifact_paths,
    select_certification_report_path,
    validate_certification_run_inputs,
    verify_targetd_certification_evidence,
    write_new_artifact,
    write_report,
)
from rolo.mvp.contracts import CertificationReport, CertificationSuite, SessionState, TargetCatalog, TraceCall, TraceSessionRequest
from rolo.mvp.episodes import EpisodeRevision, EpisodeStore
from rolo.mvp.trace import TraceService
from rolo.mvp.trace_plan import DurableTraceStore, TargetdTraceAdapter, TracePlan
from rolo.observability import ObservabilityRecorder
from rolo.targetd.dsl_protocol import DslFrame, DslFrameType
from rolo.targetd.dsl_service import TargetdDslService
from rolo.targetd.session import FrameTransport
from rolo.targetd.transport import InMemoryTargetdTransport

from .consumers import CertifyConsumer, ExecutionEnvelope, TraceConsumer
from .publisher import ReleasePublisher, TargetConformanceReport, ToolRelease, tool_release_digest


@dataclass(frozen=True)
class ReleaseInvocation:
    """One release-bound invocation retained for the journey artifact graph."""

    envelope: ExecutionEnvelope
    result: Any


class _TypedCertifyInvoker:
    """Small adapter that makes the runner use its typed invocation path."""

    def __init__(
        self,
        invoke: Callable[[CertificationInvocationContext], CertificationInvocationOutcome],
        *,
        restricted_evidence: bool,
    ) -> None:
        self._invoke = invoke
        self.restricted_evidence = restricted_evidence

    def invoke_certification(
        self,
        context: CertificationInvocationContext,
    ) -> CertificationInvocationOutcome:
        return self._invoke(context)


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
        envelope = self.prepare(
            tool_id,
            arguments,
            session_id,
            idempotency_key=idempotency_key,
        )
        result = self._invoke_target(tool_id, arguments, session_id, idempotency_key)
        self.invocations.append(ReleaseInvocation(envelope=envelope, result=result))
        return result

    def prepare(
        self,
        tool_id: str,
        arguments: Mapping[str, Any],
        session_id: str,
        *,
        idempotency_key: str | None = None,
    ) -> ExecutionEnvelope:
        """Revalidate current Release/Context/Mapping without invoking it."""

        current = self.publisher.current(tool_id)
        if current is None:
            raise ValueError("RELEASE_NOT_CURRENT")
        current_digest, release = current
        if current_digest != self.release_digest:
            raise ValueError("RELEASE_NOT_CURRENT")
        if release.status != "PUBLISHED" or not release.agent_callable:
            raise ValueError("RELEASE_NOT_CURRENT")
        return TraceConsumer(confirmation_store=self.publisher.confirmation_store).consume(
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

    def trace_receipt_evidence(
        self,
        session_id: str,
        idempotency_key: str,
    ) -> tuple[str, ...]:
        resolver = getattr(self.invoker, "trace_receipt_evidence", None)
        if not callable(resolver):
            return ()
        evidence = resolver(session_id, idempotency_key)
        if not isinstance(evidence, tuple) or any(not isinstance(item, str) for item in evidence):
            raise ValueError("TRACE_RECEIPT_EVIDENCE_INVALID")
        return evidence

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
            positional = [parameter for parameter in signature.parameters.values() if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)]
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
        episode_store: EpisodeStore | None = None,
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
        self.store = DurableTraceStore(trace_root)
        self.episode_store = episode_store or EpisodeStore(trace_root / "episodes")
        self.last_episode: EpisodeRevision | None = None
        self._plan_digests: dict[str, str] = {}

        def checkpoint(session: Any) -> None:
            plan_digest = self._plan_digests.get(session.session_id)
            if plan_digest is None:
                # create_session emits SESSION_CREATED before the immutable
                # plan can include that generated session id.  run() commits
                # this sole pre-plan event immediately after create_plan;
                # no target call is possible in between.
                return
            self.store.checkpoint(session, plan_digest=plan_digest)

        self.service = TraceService(
            catalog,
            self.bound_invoker,
            artifact_root=trace_root,
            release_digest=release_digest,
            compile_context_digest=compile_context_digest,
            target_fingerprint=target_fingerprint,
            checkpoint_sink=checkpoint,
            stream_event_artifacts=False,
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
        targetd = self._targetd_adapter()
        if targetd is not None and request.session_id is None:
            request = request.model_copy(
                update={
                    "session_id": targetd.authority.mapping_admission.journey_session_id,
                }
            )
        request = request.model_copy(
            update={
                "release_digest": self.bound_invoker.release_digest,
                "compile_context_digest": self.bound_invoker.compile_context_digest,
                "target_fingerprint": self.bound_invoker.target_fingerprint,
            }
        )
        normalized_calls = tuple(
            call if isinstance(call, TraceCall) else TraceCall.model_validate(call)
            for call in calls
        )
        if not normalized_calls:
            raise ValueError("TRACE_PLAN_CALLS_REQUIRED")
        session = self.service.create_session(request)
        descriptors = {item.tool_id: item for item in self.service.catalog.tools}
        envelopes: list[ExecutionEnvelope] = []
        for planned_call in normalized_calls:
            descriptor = descriptors.get(planned_call.tool_id)
            if descriptor is None:
                raise ValueError("TRACE_PLAN_TOOL_NOT_IN_CATALOG")
            envelopes.append(
                self.bound_invoker.prepare(
                    planned_call.tool_id,
                    planned_call.arguments,
                    session.session_id,
                    idempotency_key=planned_call.idempotency_key,
                )
            )
        mapping = envelopes[0].mapping_admission
        receipt_digest = envelopes[0].mapping_confirmation_receipt_digest
        if any(
            envelope.mapping_admission != mapping
            or envelope.mapping_confirmation_receipt_digest != receipt_digest
            for envelope in envelopes
        ):
            raise ValueError("TRACE_PLAN_MAPPING_IDENTITY_MIXED")
        plan = TracePlan.build(
            session=session,
            calls=normalized_calls,
            timeouts={tool_id: descriptor.timeout_s for tool_id, descriptor in descriptors.items()},
            release_digest=self.bound_invoker.release_digest,
            evidence_digest=self.bound_invoker.evidence_digest,
            mapping_confirmation_receipt_digest=receipt_digest,
            mapping_admission=mapping,
            targetd_authority=targetd.authority if targetd is not None else None,
        )
        self.store.create_plan(plan)
        self._plan_digests[session.session_id] = plan.plan_digest
        # SESSION_CREATED happened before the immutable plan existed; commit
        # that first checkpoint now, then all later events flow directly into
        # the hash-chained journal.
        self.store.checkpoint(session, plan_digest=plan.plan_digest)
        if targetd is not None:
            targetd.bind_plan(plan, receipt_sink=self.store.persist_receipt)
        try:
            session = self.service.execute(
                session.session_id,
                [call.trace_call() for call in plan.calls],
                diagnose=diagnose,
                recover=recover,
            )
        finally:
            # A Python exception can occur after the durable TOOL_CALL entry.
            # Do not retry here; resume() will QUERY_CALL against targetd.
            session = self.service.get(session.session_id)
        paths = self.store.snapshot(plan, session, binding=self._binding(plan))
        self.last_episode = self.episode_store.publish(
            episode_id=session.session_id,
            run_id=session.session_id,
            target_id=session.target_id,
            kind="TRACE",
            status=session.state.value,
            artifact_index_path=paths["index"],
            release_digest=plan.release_digest,
            compile_context_digest=plan.compile_context_digest,
            target_fingerprint=plan.target_fingerprint,
            mapping_confirmation_receipt_digest=plan.mapping_confirmation_receipt_digest,
            plan_digest=plan.plan_digest,
        )
        return session, paths

    def resume(self, session_id: str) -> tuple[Any, dict[str, Path]]:
        """Reconcile one durable run and continue only unsubmitted plan calls."""

        plan, durable_session = self.store.load_session(
            self.service.catalog.target_id,
            session_id,
        )
        self._validate_plan_current(plan)
        self._plan_digests[session_id] = plan.plan_digest
        targetd = self._targetd_adapter()
        if targetd is not None:
            targetd.bind_plan(plan, receipt_sink=self.store.persist_receipt)
        session = self.service.restore_session(durable_session)
        targetd_receipts_required = targetd is not None
        terminal_events = {
            event.idempotency_key
            for event in session.events
            if event.event in {"TOOL_RESULT", "TOOL_RESULT_RECONCILED"}
            and event.idempotency_key is not None
            and (
                not targetd_receipts_required
                or any(
                    evidence.startswith("targetd-trace-receipt:")
                    for evidence in event.evidence_ids
                )
            )
        }
        submitted = [
            call
            for call in plan.calls
            if any(
                event.event == "TOOL_CALL"
                and event.idempotency_key == call.idempotency_key
                for event in session.events
            )
        ]
        unresolved = [call for call in submitted if call.idempotency_key not in terminal_events]
        if len(unresolved) > 1:
            raise ValueError("TRACE_RECONCILE_MULTIPLE_UNRESOLVED_CALLS")
        if unresolved:
            if targetd is None:
                raise ValueError("TRACE_TARGETD_RECONCILER_REQUIRED")
            outcome = targetd.reconcile(plan, unresolved[0])
            if outcome is not None:
                result, status, evidence_id = outcome
                session = self.service.reconcile_call(
                    session_id,
                    idempotency_key=unresolved[0].idempotency_key,
                    tool_id=unresolved[0].tool_id,
                    arguments=unresolved[0].arguments,
                    result=result,
                    terminal_status=status,
                    evidence_id=evidence_id,
                )
                terminal_events.add(unresolved[0].idempotency_key)
        remaining = [call.trace_call() for call in plan.calls if call.idempotency_key not in terminal_events and call not in unresolved]
        if session.state in {SessionState.DISCOVERED, SessionState.PLANNED, SessionState.OBSERVED}:
            session = self.service.execute(session_id, remaining)
        paths = self.store.snapshot(plan, session, binding=self._binding(plan))
        self.last_episode = self.episode_store.publish(
            episode_id=session.session_id,
            run_id=session.session_id,
            target_id=session.target_id,
            kind="TRACE",
            status=session.state.value,
            artifact_index_path=paths["index"],
            release_digest=plan.release_digest,
            compile_context_digest=plan.compile_context_digest,
            target_fingerprint=plan.target_fingerprint,
            mapping_confirmation_receipt_digest=plan.mapping_confirmation_receipt_digest,
            plan_digest=plan.plan_digest,
        )
        return session, paths

    def _validate_plan_current(self, plan: TracePlan) -> None:
        if (
            plan.release_digest != self.bound_invoker.release_digest
            or plan.compile_context_digest != self.bound_invoker.compile_context_digest
            or plan.target_fingerprint != self.bound_invoker.target_fingerprint
            or plan.evidence_digest != self.bound_invoker.evidence_digest
            or plan.catalog_digest != self.service.catalog.digest
            or plan.target_id != self.service.catalog.target_id
        ):
            raise ValueError("TRACE_PLAN_BOUND_IDENTITY_MISMATCH")
        for call in plan.calls:
            envelope = self.bound_invoker.prepare(
                call.tool_id,
                call.arguments,
                plan.session_id,
                idempotency_key=call.idempotency_key,
            )
            if (
                envelope.mapping_admission != plan.mapping_admission
                or envelope.mapping_confirmation_receipt_digest
                != plan.mapping_confirmation_receipt_digest
            ):
                raise ValueError("TRACE_PLAN_MAPPING_NOT_CURRENT")
        targetd = self._targetd_adapter()
        if targetd is not None:
            targetd.validate_current_plan(plan)

    def _targetd_adapter(self) -> TargetdTraceAdapter | None:
        candidate = self.bound_invoker.invoker
        if isinstance(candidate, TargetdTraceAdapter):
            return candidate
        return None

    def _binding(self, plan: TracePlan) -> dict[str, Any]:
        return {
            "schema_version": RELEASE_BINDING_SCHEMA_VERSION,
            "plan_digest": plan.plan_digest,
            "release_digest": self.bound_invoker.release_digest,
            "target_fingerprint": self.bound_invoker.target_fingerprint,
            "evidence_digest": self.bound_invoker.evidence_digest,
            "compile_context_digest": self.bound_invoker.compile_context_digest,
            "route_digest": self.bound_invoker.route_digest,
            "mhs_manifest_digests": list(self.bound_invoker.mhs_manifest_digests),
            "mapping_confirmation_receipt_digest": plan.mapping_confirmation_receipt_digest,
            "mapping_identity_digest": plan.mapping_identity_digest,
            "targetd_authority_head_digest": plan.targetd_authority_head_digest,
            "targetd_catalog_head_digest": plan.targetd_catalog_head_digest,
        }


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
        episode_store: EpisodeStore | None = None,
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
        self.episode_store = episode_store
        self.last_episode: EpisodeRevision | None = None

    def run(
        self,
        suite: CertificationSuite,
        *,
        snapshot_digest: str,
        output: Path,
        session_id: str | None = None,
        run_id: str | None = None,
    ) -> tuple[CertificationReport, tuple[Path, Path]]:
        """Run one immutable certification publication attempt.

        The reservation is cooperative process state rather than evidence.  It
        must therefore be removed on every exit, including failures after a
        subset of the no-replace artifacts has been published.  Those
        artifacts themselves remain immutable; a later attempt will select a
        non-conflicting report plan during its own preflight.
        """

        reservations: list[ArtifactPlanReservation] = []
        try:
            return self._run_reserved(
                suite,
                snapshot_digest=snapshot_digest,
                output=output,
                session_id=session_id,
                run_id=run_id,
                reservations=reservations,
            )
        finally:
            if reservations:
                reservations[0].release()

    def _run_reserved(
        self,
        suite: CertificationSuite,
        *,
        snapshot_digest: str,
        output: Path,
        session_id: str | None,
        run_id: str | None,
        reservations: list[ArtifactPlanReservation],
    ) -> tuple[CertificationReport, tuple[Path, Path]]:
        if suite.digest is None:
            suite = suite.with_digest()
        effective_run_id = run_id or f"certify-run-{secrets.token_urlsafe(10)}"
        validate_certification_run_inputs(
            snapshot_digest=snapshot_digest,
            run_id=effective_run_id,
        )
        tool_id = suite.cases[0].tool_id

        # Reserve the complete publication plan before the first target CALL.
        # A historical/symlinked receipt must block execution, not merely fail
        # publication after targetd has already accepted ten operations.
        requested_json = (
            output if output.suffix == ".json" else output.with_suffix(".json")
        )
        json_path = select_certification_report_path(output, effective_run_id)
        md_path = json_path.with_suffix(".md")
        html_path = json_path.with_suffix(".html")
        binding_path = json_path.parent / "release-binding.json"
        if binding_path.exists() and not binding_path.is_symlink():
            binding_path = json_path.parent / f"{json_path.stem}.release-binding.json"
        suite_name = (
            "certify-test-suite.json"
            if json_path == requested_json
            else f"{json_path.stem}.certify-test-suite.json"
        )
        suite_path = json_path.parent / suite_name
        event_path = json_path.parent / f"{json_path.stem}.events.jsonl"
        planned_receipt_paths = {
            case.case_id: json_path.parent
            / f"{json_path.stem}.{case.case_id}.targetd-call-receipt.json"
            for case in suite.cases
        }
        index_name = (
            "artifact-index.json"
            if json_path == requested_json
            else f"{json_path.stem}.artifact-index.json"
        )
        index_path = json_path.with_name(index_name)
        artifact_reservation = reserve_new_artifact_paths(
            [
                json_path,
                md_path,
                html_path,
                binding_path,
                suite_path,
                event_path,
                *planned_receipt_paths.values(),
                index_path,
            ]
        )
        reservations.append(artifact_reservation)

        def require_current_release() -> None:
            if set(self.release_digests) != {tool_id}:
                raise ValueError("MULTIPLE_RELEASES_NOT_ALLOWED")
            release_digest = self.release_digests[tool_id]
            current = self.publisher.current(tool_id)
            if current is None or current[0] != release_digest:
                raise ValueError("RELEASE_NOT_CURRENT")
            release = current[1]
            if release.status != "PUBLISHED" or not release.agent_callable:
                raise ValueError("RELEASE_NOT_CURRENT")
            if release.target_id != suite.target_id:
                raise ValueError("TARGET_ID_MISMATCH")
            if release.target_fingerprint != self.target_fingerprint:
                raise ValueError("TARGET_FINGERPRINT_MISMATCH")
            if release.compile_context_digest != self.compile_context_digest:
                raise ValueError("CONTEXT_DIGEST_MISMATCH")
            target_conformance_digest = release.target_conformance_digest
            if target_conformance_digest is None or len(target_conformance_digest) != 71 or not target_conformance_digest.startswith("sha256:"):
                raise ValueError("TARGET_CONFORMANCE_REQUIRED")

        def invoke(context: CertificationInvocationContext) -> CertificationInvocationOutcome:
            tool_id = context.tool_id
            arguments = context.arguments
            session = context.session_id
            idempotency_key = context.idempotency_key
            release_digest = self.release_digests.get(tool_id)
            if release_digest is None:
                raise ValueError("RELEASE_NOT_CURRENT")
            current = self.publisher.current(tool_id)
            if current is None or current[0] != release_digest:
                raise ValueError("RELEASE_NOT_CURRENT")
            if current[1].status != "PUBLISHED" or not current[1].agent_callable:
                raise ValueError("RELEASE_NOT_CURRENT")
            envelope = CertifyConsumer(confirmation_store=self.publisher.confirmation_store).consume(
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
                test_case_id=context.case_id,
            )
            typed = getattr(self.invoker, "invoke_certification", None)
            if callable(typed):
                result = typed(context)
                if not isinstance(result, CertificationInvocationOutcome):
                    raise ValueError("CERTIFY_TYPED_OUTCOME_REQUIRED")
                if (
                    getattr(self.invoker, "requires_receipt_sidecar", False)
                    and (
                        result.receipt_sidecar is None
                        or result.restricted_evidence is not True
                    )
                ):
                    raise ValueError("TARGETD_CERTIFY_RECEIPT_REQUIRED")
                if (
                    getattr(self.invoker, "requires_target_terminal_status", False)
                    and result.target_terminal_status is None
                ):
                    raise ValueError("TARGETD_CERTIFY_TERMINAL_STATUS_REQUIRED")
                recorded_result = result.actual
            else:
                try:
                    import inspect

                    signature = inspect.signature(self.invoker)
                    positional = [parameter for parameter in signature.parameters.values() if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)]
                    accepts_varargs = any(parameter.kind == parameter.VAR_POSITIONAL for parameter in signature.parameters.values())
                except (TypeError, ValueError):
                    positional = []
                    accepts_varargs = True
                legacy_result = (
                    self.invoker(tool_id, arguments, session, idempotency_key)
                    if accepts_varargs or len(positional) >= 4
                    else self.invoker(tool_id, arguments, session)
                )
                result = CertificationInvocationOutcome(actual=legacy_result)
                recorded_result = legacy_result
            self.invocations.append(
                ReleaseInvocation(envelope=envelope, result=recorded_result)
            )
            return result

        runner = CertificationRunner(
            _TypedCertifyInvoker(
                invoke,
                restricted_evidence=callable(
                    getattr(self.invoker, "invoke_certification", None)
                ),
            ),
            target_id=suite.target_id,
        )
        report = runner.run(
            suite,
            snapshot_digest=snapshot_digest,
            run_id=effective_run_id,
            session_id=session_id,
            compile_context_digest=self.compile_context_digest,
            target_fingerprint=self.target_fingerprint,
            release_digests=self.release_digests,
            binding_check=require_current_release,
        )
        if report.run_id != effective_run_id:
            raise ValueError("certification run identity changed during execution")
        receipt_paths = [
            planned_receipt_paths[sidecar.case_id]
            for sidecar in runner.receipt_sidecars
        ]
        formal_targetd_evidence = bool(
            getattr(self.invoker, "requires_receipt_sidecar", False)
        )
        if formal_targetd_evidence:
            verify_targetd_certification_evidence(
                report,
                runner.receipt_sidecars,
            )
        paths = write_report(
            report,
            output,
            write_index=False,
            planned_json_path=json_path,
        )
        if paths != (json_path, md_path):
            raise ValueError("certification artifact plan changed during publication")
        write_new_artifact(
            binding_path,
            json.dumps(
                {
                    "schema_version": RELEASE_BINDING_SCHEMA_VERSION,
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
        )
        write_new_artifact(
            suite_path,
            json.dumps(suite.model_dump(mode="json"), ensure_ascii=False, indent=2)
            + "\n",
        )
        write_new_artifact(
            event_path,
            "".join(
                json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n"
                for item in runner.events
            ),
        )
        for sidecar, receipt_path in zip(
            runner.receipt_sidecars, receipt_paths, strict=True
        ):
            write_new_artifact(
                receipt_path,
                sidecar.canonical_bytes.decode("utf-8"),
            )
        files = [
            json_path,
            md_path,
            html_path,
            binding_path,
            suite_path,
            event_path,
            *receipt_paths,
        ]
        index = build_artifact_index(run_id=report.run_id, target_id=report.target_id, files=files, root=json_path.parent)
        if formal_targetd_evidence:
            verify_targetd_certification_evidence(
                report,
                runner.receipt_sidecars,
                receipt_paths=receipt_paths,
                artifact_index=index,
            )
        write_new_artifact(index_path, index.model_dump_json(indent=2) + "\n")
        if self.episode_store is not None:
            current_release = self.publisher.current(report.tool_id)
            mapping_receipt = (
                current_release[1].mapping_confirmation_receipt_digest
                if current_release is not None
                else None
            )
            self.last_episode = self.episode_store.publish(
                episode_id=report.run_id,
                run_id=report.run_id,
                target_id=report.target_id,
                kind="CERTIFY",
                status=report.conclusion,
                artifact_index_path=index_path,
                release_digest=report.release_digest,
                compile_context_digest=report.compile_context_digest,
                target_fingerprint=report.target_fingerprint,
                mapping_confirmation_receipt_digest=mapping_receipt,
            )
        return report, (json_path, md_path)


class PostCompilerJourneyResult(StrictModel):
    """Digest-linked summary of the offline-to-release part of a journey."""

    schema_version: Literal["rolo-post-compiler-journey-result/v2"] = JOURNEY_RESULT_SCHEMA_VERSION
    status: Literal["PASS", "BLOCKED"]
    journey_session_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    target_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    dsl_digest: str
    context_digest: str
    target_compile_status: str
    confirmation_receipt_digest: str | None = None
    proposal_digest: str | None = None
    target_conformance_digest: str | None = None
    release_digest: str | None = None
    diagnostics: tuple[str, ...] = ()


class PostCompilerJourney:
    """Execute the frozen DSL → targetd → conformance → publish sequence.

    The targetd service can be replaced by the SSH stdio transport at the
    caller boundary.  This class deliberately never publishes when any gate
    is failed and writes a digest-linked manifest for replay.
    """

    def __init__(
        self,
        root: Path,
        *,
        publisher: ReleasePublisher,
        targetd: FrameTransport | TargetdDslService | None = None,
        observability: ObservabilityRecorder | None = None,
        offline_replay: bool = False,
    ) -> None:
        self.root = Path(root)
        self.publisher = publisher
        # A real journey is fail-closed unless its caller injects a targetd
        # service bound to the observed runtime and backend registry.  Offline
        # replay is an explicit opt-in so a default constructor cannot
        # accidentally publish a release without T3 runtime evidence.
        if targetd is None:
            service = TargetdDslService(
                self.root / "targetd-cache",
                confirmation_store=publisher.confirmation_store,
                allow_unbound_runtime=offline_replay,
            )
            self.targetd: FrameTransport = InMemoryTargetdTransport(service)
        elif callable(getattr(targetd, "request", None)):
            self.targetd = targetd
        else:
            # Compatibility for injected fake services while all real callers
            # move to the single-session transport boundary.
            self.targetd = InMemoryTargetdTransport(targetd)
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
        confirmation_receipt_digest: str | None = None,
        compiler_version: str = "rolo-compiler/0.1",
        mhs_manifest_digests: tuple[str, ...] = (),
        route_digest: str | None = None,
    ) -> tuple[PostCompilerJourneyResult, ToolRelease | None]:
        self._metric(event="journey.started", status="STARTED", journey_session_id=journey_session_id, target_id=target_id)
        dsl_dict = dict(dsl)
        context_dict = dict(context)
        actual_context_digest = context_digest(context_dict)

        # The confirmation ledger is the first authority consulted.  Merely
        # supplying a self-consistent receipt object (or a digest unknown to
        # this publisher) must never unlock compiler, targetd, or Catalog side
        # effects.
        receipt: MappingConfirmationReceipt | None = None
        if self.publisher.confirmation_store is None:
            return self._blocked(
                journey_session_id,
                target_id,
                "",
                actual_context_digest,
                {
                    "status": "MAPPING_ADMISSION_BLOCKED",
                    "diagnostics": ["MAPPING_CONFIRMATION_STORE_REQUIRED"],
                },
            ), None
        if not confirmation_receipt_digest:
            return self._blocked(
                journey_session_id,
                target_id,
                "",
                actual_context_digest,
                {
                    "status": "MAPPING_ADMISSION_BLOCKED",
                    "diagnostics": ["MAPPING_CONFIRMATION_REQUIRED"],
                },
            ), None
        try:
            receipt = self.publisher.confirmation_store.resolve(confirmation_receipt_digest)
        except (MappingAdmissionError, ValueError) as exc:
            code = exc.code if isinstance(exc, MappingAdmissionError) else "MAPPING_CONFIRMATION_DIGEST_INVALID"
            return self._blocked(
                journey_session_id,
                target_id,
                "",
                actual_context_digest,
                {"status": "MAPPING_ADMISSION_BLOCKED", "diagnostics": [code]},
            ), None

        document, parse_report = parse_document(dsl_dict)
        if document is None or not parse_report.ok:
            return self._blocked(
                journey_session_id,
                target_id,
                "",
                actual_context_digest,
                {
                    "status": "DSL_COMPILE_FAILED",
                    "diagnostics": [item.code for item in parse_report.diagnostics],
                },
                receipt=receipt,
            ), None
        actual_dsl_digest = dsl_digest(document)
        try:
            context_model = ProbeContext.model_validate(context_dict)
            if target_id != context_model.robot_id:
                raise MappingAdmissionError("MAPPING_TARGET_ID_MISMATCH")
            if target_fingerprint != context_model.target_fingerprint:
                raise MappingAdmissionError("MAPPING_TARGET_FINGERPRINT_MISMATCH")
            if document.target.robot_id != context_model.robot_id:
                raise MappingAdmissionError("MAPPING_TARGET_ID_MISMATCH")
            if document.target.evidence_digest != context_model.evidence_digest:
                raise MappingAdmissionError("MAPPING_EVIDENCE_DIGEST_MISMATCH")
            expected_scope = MappingAdmissionScope(
                tool_id=document.tool_id,
                operation_kind=document.kind,
                operations=receipt.scope.operations,
                access=receipt.scope.access,
                risk=receipt.scope.risk,
            )
            expected_identity = MappingAdmissionIdentity.build(
                journey_session_id=journey_session_id,
                target_id=context_model.robot_id,
                target_fingerprint=context_model.target_fingerprint,
                candidate_index_digest=receipt.candidate_index_digest,
                candidate_digest=receipt.candidate_digest,
                proposal_digest=receipt.proposal_digest,
                dsl_digest=actual_dsl_digest,
                context_digest=actual_context_digest,
                evidence_digest=context_model.evidence_digest,
                available_tool_catalog_digest=(receipt.available_tool_catalog_digest),
                scope=expected_scope,
            )
            receipt = MappingAdmissionGate(self.publisher.confirmation_store).require_active(confirmation_receipt_digest, expected_identity)
        except MappingAdmissionError as exc:
            return self._blocked(
                journey_session_id,
                target_id,
                actual_dsl_digest,
                actual_context_digest,
                {
                    "status": "MAPPING_ADMISSION_BLOCKED",
                    "diagnostics": [exc.code],
                },
                receipt=receipt,
            ), None
        except ValueError:
            return self._blocked(
                journey_session_id,
                target_id,
                actual_dsl_digest,
                actual_context_digest,
                {
                    "status": "MAPPING_ADMISSION_BLOCKED",
                    "diagnostics": ["MAPPING_CONFIRMATION_IDENTITY_INVALID"],
                },
                receipt=receipt,
            ), None

        put = DslFrame(
            frame_type=DslFrameType.DSL_PUT,
            request_id=f"{journey_session_id}:put",
            payload={
                "journey_session_id": journey_session_id,
                "dsl": dsl_dict,
                "context": context_dict,
                "compiler_version": compiler_version,
                "dsl_digest": actual_dsl_digest,
                "context_digest": actual_context_digest,
                "target_fingerprint": target_fingerprint,
                "dsl_schema_version": document.schema_version,
                "context_schema_version": context_model.schema_version,
            },
        )
        put_response = self.targetd.request(put)
        if put_response.payload.get("diagnostics"):
            return self._blocked(journey_session_id, target_id, actual_dsl_digest, actual_context_digest, put_response.payload, receipt=receipt), None
        check_response = self.targetd.request(
            DslFrame(
                frame_type=DslFrameType.DSL_CHECK,
                request_id=f"{journey_session_id}:check",
                payload={
                    "journey_session_id": journey_session_id,
                    "dsl_digest": actual_dsl_digest,
                },
            )
        )
        if check_response.payload.get("status") != "PASS":
            return self._blocked(journey_session_id, target_id, actual_dsl_digest, actual_context_digest, check_response.payload, receipt=receipt), None
        resolve_response = self.targetd.request(
            DslFrame(
                frame_type=DslFrameType.PLAN_RESOLVE,
                request_id=f"{journey_session_id}:resolve",
                payload={
                    "journey_session_id": journey_session_id,
                    "dsl_digest": actual_dsl_digest,
                },
            )
        )
        if resolve_response.payload.get("status") != "PASS":
            return self._blocked(journey_session_id, target_id, actual_dsl_digest, actual_context_digest, resolve_response.payload, receipt=receipt), None
        targetd_admission = {
            "journey_session_id": journey_session_id,
            "confirmation_receipt_digest": receipt.receipt_digest,
        }
        targetd_lineage = {
            **targetd_admission,
            "dsl_digest": actual_dsl_digest,
            "context_digest": actual_context_digest,
            "target_fingerprint": target_fingerprint,
        }
        compile_response = self.targetd.request(
            DslFrame(
                frame_type=DslFrameType.TARGET_COMPILE,
                request_id=f"{journey_session_id}:compile",
                payload={
                    "schema_version": TARGETD_COMPILE_SCHEMA_VERSION,
                    "dsl_digest": actual_dsl_digest,
                    "context_digest": actual_context_digest,
                    "target_fingerprint": target_fingerprint,
                    **targetd_admission,
                },
            )
        )
        compile_payload = compile_response.payload
        if compile_payload.get("status") != "PASS":
            return self._blocked(journey_session_id, target_id, actual_dsl_digest, actual_context_digest, compile_payload, receipt=receipt), None
        if any(compile_payload.get(key) != value for key, value in targetd_lineage.items()):
            return self._blocked(
                journey_session_id,
                target_id,
                actual_dsl_digest,
                actual_context_digest,
                {
                    "status": "MAPPING_ADMISSION_BLOCKED",
                    "diagnostics": ["MAPPING_TARGETD_ADMISSION_LINEAGE_MISMATCH"],
                },
                receipt=receipt,
            ), None
        conformance_response = self.targetd.request(
            DslFrame(
                frame_type=DslFrameType.TARGET_CONFORMANCE,
                request_id=f"{journey_session_id}:conformance",
                payload={
                    "schema_version": TARGETD_COMPILE_SCHEMA_VERSION,
                    "dsl_digest": actual_dsl_digest,
                    "context_digest": actual_context_digest,
                    "target_fingerprint": target_fingerprint,
                    **targetd_admission,
                },
            )
        )
        conformance_payload = conformance_response.payload
        target_report = conformance_payload.get("target_conformance_report")
        if conformance_payload.get("target_conformance") != "PASS" or not isinstance(target_report, Mapping):
            return self._blocked(journey_session_id, target_id, actual_dsl_digest, actual_context_digest, conformance_payload, receipt=receipt), None
        if any(conformance_payload.get(key) != value for key, value in targetd_lineage.items()) or any(target_report.get(key) != value for key, value in targetd_admission.items()):
            return self._blocked(
                journey_session_id,
                target_id,
                actual_dsl_digest,
                actual_context_digest,
                {
                    "status": "MAPPING_ADMISSION_BLOCKED",
                    "diagnostics": ["MAPPING_TARGETD_ADMISSION_LINEAGE_MISMATCH"],
                },
                receipt=receipt,
            ), None
        target_report_identity = {
            "tool_id": document.tool_id,
            "operation_kind": document.kind,
            "target_id": target_id,
            "target_fingerprint": target_fingerprint,
            "target_identity_digest": receipt.target_identity_digest,
            "evidence_digest": context_model.evidence_digest,
            "dsl_digest": actual_dsl_digest,
            "context_digest": actual_context_digest,
            "ir_digest": compile_payload.get("ir_digest"),
            "bundle_digest": compile_payload.get("bundle_digest"),
            "compile_artifact_digest": compile_payload.get("compile_artifact_digest"),
            "compiler_version": compiler_version,
            "compiler_backend_id": compile_payload.get("compiler_backend_id"),
            "compiler_backend_version": compile_payload.get("compiler_backend_version"),
            "runtime_backend_id": compile_payload.get("runtime_backend_id"),
            "runtime_binding_digest": compile_payload.get("runtime_binding_digest"),
            "required_capabilities": list(compile_payload.get("required_capabilities", ())),
            "required_runtime_capabilities": list(compile_payload.get("required_runtime_capabilities", ())),
            "negotiated_capabilities": list(compile_payload.get("negotiated_capabilities", ())),
        }
        if any(target_report.get(key) != value for key, value in target_report_identity.items()):
            return self._blocked(
                journey_session_id,
                target_id,
                actual_dsl_digest,
                actual_context_digest,
                {
                    "status": "TARGET_CONFORMANCE_IDENTITY_BLOCKED",
                    "diagnostics": ["TARGET_CONFORMANCE_IDENTITY_MISMATCH"],
                },
                receipt=receipt,
            ), None
        target_conformance = TargetConformanceReport.model_validate(target_report)
        compiler_admission = {
            "confirmation_store": self.publisher.confirmation_store,
            "confirmation_receipt_digest": receipt.receipt_digest,
            "journey_session_id": journey_session_id,
        }
        compiler_result = compile_document(
            document,
            self.root / "compiler",
            context=context_dict,
            **compiler_admission,
        )
        compiler_report = ConformanceRunner(self.root / "compiler-conformance").run(
            document,
            context_dict,
            **compiler_admission,
        )
        if not compiler_result.ok or not compiler_report.passed:
            return self._blocked(journey_session_id, target_id, actual_dsl_digest, actual_context_digest, {"diagnostics": ["COMPILER_CONFORMANCE_FAILED"]}, receipt=receipt), None
        if compiler_result.bundle is None or compiler_result.bundle.digest != compile_payload.get("bundle_digest"):
            return self._blocked(
                journey_session_id,
                target_id,
                actual_dsl_digest,
                actual_context_digest,
                {
                    "status": "MAPPING_ADMISSION_BLOCKED",
                    "diagnostics": ["MAPPING_TARGETD_BUNDLE_LINEAGE_MISMATCH"],
                },
                receipt=receipt,
            ), None
        try:
            release = self.publisher.publish_verified(
                compiler_result,
                compiler_report,
                target_conformance,
                target_fingerprint=target_fingerprint,
                compiler_version=compiler_version,
                target_compile_artifact_digest=compile_payload["compile_artifact_digest"],
                mhs_manifest_digests=mhs_manifest_digests,
                compile_context_digest=actual_context_digest,
                route_digest=route_digest,
                journey_session_id=journey_session_id,
                confirmation_receipt_digest=receipt.receipt_digest,
            )
        except (MappingAdmissionError, ValueError) as exc:
            diagnostic = exc.code if isinstance(exc, MappingAdmissionError) else str(exc)
            return self._blocked(
                journey_session_id,
                target_id,
                actual_dsl_digest,
                actual_context_digest,
                {
                    "status": "MAPPING_ADMISSION_BLOCKED",
                    "diagnostics": [diagnostic],
                },
                receipt=receipt,
            ), None
        release_digest = tool_release_digest(release)
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
            "confirmation_receipt": artifact_dir / "mapping-confirmation-receipt.json",
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
        files["confirmation_receipt"].write_text(
            receipt.model_dump_json(indent=2) + "\n",
            encoding="utf-8",
        )
        result = PostCompilerJourneyResult(
            status="PASS",
            journey_session_id=journey_session_id,
            target_id=target_id,
            dsl_digest=actual_dsl_digest,
            context_digest=actual_context_digest,
            target_compile_status=str(compile_payload.get("status")),
            confirmation_receipt_digest=receipt.receipt_digest,
            proposal_digest=receipt.proposal_digest,
            target_conformance_digest=conformance_payload.get("target_conformance_digest"),
            release_digest=release_digest,
            diagnostics=tuple(conformance_payload.get("diagnostics", ())),
        )
        files["journey"].write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
        index = build_artifact_index(run_id=journey_session_id, target_id=target_id, files=list(files.values()), root=artifact_dir)
        write_artifact_index(artifact_dir / "artifact-index.json", index)
        self._metric(
            event="journey.completed",
            status="PASS",
            journey_session_id=journey_session_id,
            target_id=target_id,
            payload={
                "release_digest": release_digest,
                "confirmation_receipt_digest": receipt.receipt_digest,
                "proposal_digest": receipt.proposal_digest,
            },
        )
        return result, release

    def _blocked(
        self,
        journey_session_id: str,
        target_id: str,
        dsl_digest_value: str,
        context_digest_value: str,
        payload: Mapping[str, Any],
        *,
        receipt: MappingConfirmationReceipt | None = None,
    ) -> PostCompilerJourneyResult:
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
            confirmation_receipt_digest=(receipt.receipt_digest if receipt is not None else None),
            proposal_digest=(receipt.proposal_digest if receipt is not None else None),
            target_conformance_digest=payload.get("target_conformance_digest"),
            diagnostics=tuple(str(item) for item in diagnostics),
        )
        artifact_dir = self.root / "journeys" / target_id / journey_session_id
        artifact_dir.mkdir(parents=True, exist_ok=True)
        result_path = artifact_dir / "journey-result.json"
        result_path.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
        indexed_files = [result_path]
        if receipt is not None:
            receipt_path = artifact_dir / "mapping-confirmation-receipt.json"
            receipt_path.write_text(receipt.model_dump_json(indent=2) + "\n", encoding="utf-8")
            indexed_files.append(receipt_path)
        index = build_artifact_index(
            run_id=journey_session_id,
            target_id=target_id,
            files=indexed_files,
            root=artifact_dir,
        )
        write_artifact_index(artifact_dir / "artifact-index.json", index)
        self._metric(
            event="journey.blocked",
            status="BLOCKED",
            journey_session_id=journey_session_id,
            target_id=target_id,
            payload={
                "diagnostics": list(result.diagnostics),
                "stage": result.target_compile_status,
                "confirmation_receipt_digest": result.confirmation_receipt_digest,
                "proposal_digest": result.proposal_digest,
            },
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
