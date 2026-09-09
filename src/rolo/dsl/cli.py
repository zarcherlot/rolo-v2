"""Small JSON CLI for the standalone DSL compiler service."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from .admission import (
    MappingAdmissionError,
    MappingAdmissionScope,
    MappingConfirmationStore,
)
from .api import DslCheckRequest, DslCompileRequest
from .bootstrap_replay import verify_bootstrap_artifacts
from .candidates import CapabilityCandidateIndex, build_candidate_index, persist_candidate_index, query_candidates
from .canonical import dsl_digest
from .context import ProbeContext
from .contracts import COMPILE_REQUEST_SCHEMA_VERSION
from .mapping import AdapterMappingRequest
from .parser import loads_unique_json, parse_document
from .proposal import MappingProposal, build_mapping_proposal, persist_mapping_proposal
from .service import RoloDslCompiler
from .sufficiency import assess_mapping_sufficiency


def _read(path: Path) -> dict[str, Any]:
    value = loads_unique_json(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _write_json(path: Path, payload: Any) -> None:
    """Write one deterministic JSON artifact without exposing a partial file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _load_dsl_request(path: Path, context_path: Path | None = None) -> DslCheckRequest:
    text = path.read_text(encoding="utf-8")
    try:
        payload = loads_unique_json(text)
    except json.JSONDecodeError:
        # ``validate`` is intentionally useful with the YAML mapping files
        # that Agents commonly produce.  Parse through the same duplicate-key
        # rejecting DSL parser used by the compiler rather than accepting a
        # second, looser YAML dialect at the CLI boundary.
        document, report = parse_document(text)
        if document is None or not report.ok:
            raise ValueError("invalid DSL document") from None
        payload = document.model_dump(mode="json")
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON/YAML object")
    if "dsl" in payload:
        return DslCheckRequest.model_validate(payload)
    context = _read(context_path) if context_path is not None else {}
    return DslCheckRequest(dsl=payload, context=context)


def _error_envelope(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, MappingAdmissionError):
        return {
            "status": "BLOCKED",
            "error": type(exc).__name__,
            "code": exc.code,
            "message": str(exc),
        }
    return {
        "status": "ERROR",
        "error": type(exc).__name__,
        "message": str(exc) or type(exc).__name__,
    }


def _compile_request(path: Path) -> DslCompileRequest:
    payload = _read(path)
    if payload.get("schema_version") != COMPILE_REQUEST_SCHEMA_VERSION:
        raise MappingAdmissionError("DSL_COMPILE_REQUEST_V2_REQUIRED")
    if "confirmation_receipt_digest" not in payload:
        raise MappingAdmissionError("MAPPING_CONFIRMATION_REQUIRED")
    return DslCompileRequest.model_validate(payload)


def _admission_store(path: Path | None) -> MappingConfirmationStore:
    if path is None:
        raise MappingAdmissionError("MAPPING_CONFIRMATION_STORE_REQUIRED")
    return MappingConfirmationStore(path)


def _proposal(path: Path) -> MappingProposal:
    proposal = MappingProposal.model_validate(_read(path))
    proposal.verify()
    return proposal


def _emit_decision(receipt, store: MappingConfirmationStore) -> None:
    print(
        json.dumps(
            {
                "status": receipt.decision,
                "receipt_digest": receipt.receipt_digest,
                "receipt": receipt.model_dump(mode="json"),
                "ledger": str(store.path),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rolo-dsl")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check")
    check.add_argument("request", type=Path, help="JSON request envelope")
    check.add_argument("--output-dir", type=Path, default=Path(".rolo-dsl-output"))
    compile_command = sub.add_parser("compile")
    compile_command.add_argument("request", type=Path, help="DslCompileRequest v2 JSON envelope")
    compile_command.add_argument("--output-dir", type=Path, default=Path(".rolo-dsl-output"))
    compile_command.add_argument("--admission-store", type=Path, default=None, help="Trusted Mapping confirmation ledger root")
    validate = sub.add_parser("validate", help="Validate a DSL document against an optional Compile Context")
    validate.add_argument("dsl", type=Path, help="DSL JSON/YAML document or a check request envelope")
    validate.add_argument("--context", type=Path, default=None, help="Compile Context JSON")
    canonicalize = sub.add_parser("canonicalize", help="Write the canonical DSL payload and digest")
    canonicalize.add_argument("dsl", type=Path, help="DSL JSON/YAML document")
    canonicalize.add_argument("--output", type=Path, required=True, help="Canonical JSON artifact")
    replay_command = sub.add_parser("replay", help="Compile one request twice and compare artifact digests")
    replay_command.add_argument("request", type=Path, help="DslCompileRequest v2 JSON envelope")
    replay_command.add_argument("--output-dir", type=Path, default=Path(".rolo-dsl-replay"))
    replay_command.add_argument("--admission-store", type=Path, default=None, help="Trusted Mapping confirmation ledger root")
    candidates = sub.add_parser("candidates")
    candidates.add_argument("context", type=Path, help="Compile Context JSON")
    candidates.add_argument("--output-dir", type=Path, default=Path(".rolo-dsl-output"))
    candidates.add_argument("--intent", type=str, default=None)
    proposal = sub.add_parser("proposal")
    proposal.add_argument("request", type=Path, help="Adapter Mapping Request JSON")
    proposal.add_argument("index", type=Path, help="Capability Candidate Index JSON")
    proposal.add_argument("--candidate-id", required=True)
    proposal.add_argument("--dsl", type=Path, required=True, help="Checked DSL JSON/YAML document")
    proposal.add_argument("--context", type=Path, required=True, help="Verified Compile Context JSON")
    proposal.add_argument("--scope-operation", action="append", default=None, help="Confirmed operation; repeat for an exact multi-operation scope")
    proposal.add_argument("--scope-access", choices=("read", "experimental_write"), required=True)
    proposal.add_argument("--scope-risk", choices=("R0", "R1", "R2", "R3"), required=True)
    proposal.add_argument("--output-dir", type=Path, default=Path(".rolo-dsl-output"))
    for decision_name in ("confirm", "reject"):
        decision = sub.add_parser(decision_name, help=f"Append a {decision_name} decision for a Mapping Proposal")
        decision.add_argument("proposal", type=Path, help="Digest-bound Mapping Proposal v2 JSON")
        decision.add_argument("--admission-store", type=Path, required=True, help="Trusted Mapping confirmation ledger root")
        decision.add_argument("--actor-id", required=True, help="Authenticated operator identity")
        decision.add_argument("--decision-id", required=True, help="Idempotency key for this human decision")
        if decision_name == "confirm":
            decision.add_argument("--ttl-s", type=int, default=900)
    cancel = sub.add_parser("cancel", help="Append a cancellation tombstone for an active confirmation")
    cancel.add_argument("receipt_digest", help="Committed CONFIRMED receipt digest")
    cancel.add_argument("--admission-store", type=Path, required=True, help="Trusted Mapping confirmation ledger root")
    cancel.add_argument("--actor-id", required=True, help="Authenticated operator identity")
    cancel.add_argument("--decision-id", required=True, help="Idempotency key for this cancellation")
    sufficiency = sub.add_parser("sufficiency")
    sufficiency.add_argument("context", type=Path, help="Compile Context JSON")
    sufficiency.add_argument("index", type=Path, help="Capability Candidate Index JSON")
    sufficiency.add_argument("--intent", type=str, required=True)
    bootstrap_verify = sub.add_parser("bootstrap-verify", help="Verify persisted Bootstrap artifacts without contacting a target")
    bootstrap_verify.add_argument("root", type=Path, help="Bootstrap artifact directory")
    bootstrap_verify.add_argument("--robot-id", type=str, default=None)
    bootstrap_verify.add_argument("--target-fingerprint", type=str, default=None)
    args = parser.parse_args(argv)
    try:
        if args.command == "candidates":
            payload = _read(args.context)
            index = build_candidate_index(ProbeContext.model_validate(payload))
            path = persist_candidate_index(index, args.output_dir)
            response: dict[str, Any] = {"status": "PASS", "index": index.model_dump(mode="json"), "artifact": str(path)}
            if args.intent is not None:
                response["matches"] = [item.model_dump(mode="json") for item in query_candidates(index, args.intent)]
            print(json.dumps(response, ensure_ascii=False, sort_keys=True))
            return 0
        if args.command == "proposal":
            request = AdapterMappingRequest.model_validate(_read(args.request))
            index = CapabilityCandidateIndex.model_validate(_read(args.index))
            candidate = next((item for item in index.candidates if item.candidate_id == args.candidate_id), None)
            if candidate is None:
                raise ValueError(f"candidate not found: {args.candidate_id}")
            context = ProbeContext.model_validate(_read(args.context))
            dsl_request = _load_dsl_request(args.dsl, args.context)
            checked = RoloDslCompiler().check(
                DslCheckRequest(
                    dsl=dsl_request.dsl,
                    context=context.model_dump(mode="python"),
                    compiler_version=dsl_request.compiler_version,
                )
            )
            if checked.status != "PASS":
                raise MappingAdmissionError("MAPPING_PROPOSAL_DSL_CHECK_FAILED")
            document, report = parse_document(dsl_request.dsl)
            if document is None or not report.ok:
                raise MappingAdmissionError("MAPPING_PROPOSAL_DSL_INVALID")
            scope = MappingAdmissionScope(
                tool_id=document.tool_id,
                operation_kind=document.kind,
                operations=tuple(args.scope_operation or (candidate.operation,)),
                access=args.scope_access,
                risk=args.scope_risk,
            )
            proposal = build_mapping_proposal(
                request,
                index,
                candidate,
                dsl=document,
                context=context,
                scope=scope,
            )
            path = persist_mapping_proposal(proposal, args.output_dir)
            print(json.dumps({"status": "PASS", "proposal": proposal.model_dump(mode="json"), "artifact": str(path)}, ensure_ascii=False, sort_keys=True))
            return 0
        if args.command in {"confirm", "reject"}:
            proposal = _proposal(args.proposal)
            store = _admission_store(args.admission_store)
            if args.command == "confirm":
                receipt = store.confirm(
                    proposal.admission_identity(),
                    decision_id=args.decision_id,
                    actor_id=args.actor_id,
                    ttl_s=args.ttl_s,
                )
            else:
                receipt = store.reject(
                    proposal.admission_identity(),
                    decision_id=args.decision_id,
                    actor_id=args.actor_id,
                )
            _emit_decision(receipt, store)
            return 0
        if args.command == "cancel":
            store = _admission_store(args.admission_store)
            receipt = store.cancel(
                args.receipt_digest,
                decision_id=args.decision_id,
                actor_id=args.actor_id,
            )
            _emit_decision(receipt, store)
            return 0
        if args.command == "sufficiency":
            context = ProbeContext.model_validate(_read(args.context))
            index = CapabilityCandidateIndex.model_validate(_read(args.index))
            report = assess_mapping_sufficiency(context, index, args.intent)
            print(json.dumps(report.model_dump(mode="json"), ensure_ascii=False, sort_keys=True))
            return 0 if report.status != "UNSUPPORTED" else 2
        if args.command == "bootstrap-verify":
            report = verify_bootstrap_artifacts(
                args.root,
                expected_robot_id=args.robot_id,
                expected_target_fingerprint=args.target_fingerprint,
            )
            print(json.dumps(report.model_dump(mode="json"), ensure_ascii=False, sort_keys=True))
            return 0 if report.status == "PASS" else 2
        if args.command == "validate":
            result = RoloDslCompiler().check(_load_dsl_request(args.dsl, args.context))
            print(json.dumps(result.model_dump(mode="json"), ensure_ascii=False, sort_keys=True))
            return 0 if result.status == "PASS" else 1
        if args.command == "canonicalize":
            document, report = parse_document(args.dsl.read_text(encoding="utf-8"))
            if document is None or not report.ok:
                response = {"status": "DSL_CHECK_FAILED", "diagnostics": [item.model_dump(mode="json") for item in report.diagnostics]}
                print(json.dumps(response, ensure_ascii=False, sort_keys=True))
                return 1
            canonical = document.model_dump(mode="json", exclude_none=True)
            digest = dsl_digest(document)
            _write_json(args.output, canonical)
            print(json.dumps({"status": "PASS", "dsl_digest": digest, "artifact": str(args.output)}, ensure_ascii=False, sort_keys=True))
            return 0
        if args.command == "replay":
            store = _admission_store(args.admission_store)
            payload = _compile_request(args.request)
            first_dir = args.output_dir / "first"
            second_dir = args.output_dir / "second"
            compiler = RoloDslCompiler(store)
            first = compiler.compile(payload, first_dir)
            second = compiler.compile(payload, second_dir)
            stable = (
                first.status == "PASS"
                and second.status == "PASS"
                and first.dsl_digest == second.dsl_digest
                and first.ir_digest is not None
                and first.ir_digest == second.ir_digest
                and first.bundle_digest is not None
                and first.bundle_digest == second.bundle_digest
                and first.backend_id == second.backend_id
            )
            response = {
                "status": "PASS" if stable else "DSL_REPLAY_FAILED",
                "first": first.model_dump(mode="json"),
                "second": second.model_dump(mode="json"),
                "stable": stable,
                "output_dir": str(args.output_dir),
            }
            print(json.dumps(response, ensure_ascii=False, sort_keys=True))
            return 0 if stable else 1
        if args.command == "check":
            payload = _read(args.request)
            compiler = RoloDslCompiler()
            result = compiler.check(DslCheckRequest.model_validate(payload))
        else:
            store = _admission_store(args.admission_store)
            compiler = RoloDslCompiler(store)
            result = compiler.compile(_compile_request(args.request), args.output_dir)
        print(json.dumps(result.model_dump(mode="json"), ensure_ascii=False, sort_keys=True))
        return 0 if result.status == "PASS" else 1
    except (OSError, TypeError, ValueError) as exc:
        print(json.dumps(_error_envelope(exc), ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
