"""Small JSON CLI for the standalone DSL compiler service."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .api import DslCheckRequest, DslCompileRequest
from .bootstrap_replay import verify_bootstrap_artifacts
from .candidates import CapabilityCandidateIndex, build_candidate_index, persist_candidate_index, query_candidates
from .context import ProbeContext
from .mapping import AdapterMappingRequest
from .proposal import build_mapping_proposal, persist_mapping_proposal
from .service import RoloDslCompiler
from .sufficiency import assess_mapping_sufficiency


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rolo-dsl")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "compile"):
        command = sub.add_parser(name)
        command.add_argument("request", type=Path, help="JSON request envelope")
        command.add_argument("--output-dir", type=Path, default=Path(".rolo-dsl-output"))
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
    bootstrap_verify = sub.add_parser("bootstrap-verify")
    bootstrap_verify.add_argument("root", type=Path, help="Bootstrap artifact directory")
    bootstrap_verify.add_argument("--robot-id", type=str, default=None)
    bootstrap_verify.add_argument("--target-fingerprint", type=str, default=None)
    args = parser.parse_args(argv)
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
    payload = _read(args.request)
    compiler = RoloDslCompiler()
    if args.command == "check":
        result = compiler.check(DslCheckRequest.model_validate(payload))
    else:
        result = compiler.compile(DslCompileRequest.model_validate(payload), args.output_dir)
    print(json.dumps(result.model_dump(mode="json"), ensure_ascii=False, sort_keys=True))
    return 0 if result.status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
