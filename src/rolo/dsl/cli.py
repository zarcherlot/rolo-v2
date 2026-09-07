"""Small JSON CLI for the standalone DSL compiler service."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from .api import DslCheckRequest, DslCompileRequest
from .bootstrap_replay import verify_bootstrap_artifacts
from .candidates import CapabilityCandidateIndex, build_candidate_index, persist_candidate_index, query_candidates
from .canonical import dsl_digest
from .context import ProbeContext
from .mapping import AdapterMappingRequest
from .parser import parse_document
from .proposal import build_mapping_proposal, persist_mapping_proposal
from .service import RoloDslCompiler
from .sufficiency import assess_mapping_sufficiency


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
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
        payload = json.loads(text)
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
    return {
        "status": "ERROR",
        "error": type(exc).__name__,
        "message": str(exc) or type(exc).__name__,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rolo-dsl")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "compile"):
        command = sub.add_parser(name)
        command.add_argument("request", type=Path, help="JSON request envelope")
        command.add_argument("--output-dir", type=Path, default=Path(".rolo-dsl-output"))
    validate = sub.add_parser("validate", help="Validate a DSL document against an optional Compile Context")
    validate.add_argument("dsl", type=Path, help="DSL JSON/YAML document or a check request envelope")
    validate.add_argument("--context", type=Path, default=None, help="Compile Context JSON")
    canonicalize = sub.add_parser("canonicalize", help="Write the canonical DSL payload and digest")
    canonicalize.add_argument("dsl", type=Path, help="DSL JSON/YAML document")
    canonicalize.add_argument("--output", type=Path, required=True, help="Canonical JSON artifact")
    replay_command = sub.add_parser("replay", help="Compile one request twice and compare artifact digests")
    replay_command.add_argument("request", type=Path, help="DslCompileRequest JSON envelope")
    replay_command.add_argument("--output-dir", type=Path, default=Path(".rolo-dsl-replay"))
    candidates = sub.add_parser("candidates")
    candidates.add_argument("context", type=Path, help="Compile Context JSON")
    candidates.add_argument("--output-dir", type=Path, default=Path(".rolo-dsl-output"))
    candidates.add_argument("--intent", type=str, default=None)
    proposal = sub.add_parser("proposal")
    proposal.add_argument("request", type=Path, help="Adapter Mapping Request JSON")
    proposal.add_argument("index", type=Path, help="Capability Candidate Index JSON")
    proposal.add_argument("--candidate-id", required=True)
    proposal.add_argument("--output-dir", type=Path, default=Path(".rolo-dsl-output"))
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
            proposal = build_mapping_proposal(request, index, candidate)
            path = persist_mapping_proposal(proposal, args.output_dir)
            print(json.dumps({"status": "PASS", "proposal": proposal.model_dump(mode="json"), "artifact": str(path)}, ensure_ascii=False, sort_keys=True))
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
            payload = DslCompileRequest.model_validate(_read(args.request))
            first_dir = args.output_dir / "first"
            second_dir = args.output_dir / "second"
            compiler = RoloDslCompiler()
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
        payload = _read(args.request)
        compiler = RoloDslCompiler()
        if args.command == "check":
            result = compiler.check(DslCheckRequest.model_validate(payload))
        else:
            result = compiler.compile(DslCompileRequest.model_validate(payload), args.output_dir)
        print(json.dumps(result.model_dump(mode="json"), ensure_ascii=False, sort_keys=True))
        return 0 if result.status == "PASS" else 1
    except (OSError, TypeError, ValueError) as exc:
        print(json.dumps(_error_envelope(exc), ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
