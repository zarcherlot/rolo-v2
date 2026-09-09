import json
from datetime import datetime, timezone

from rolo.dsl.admission import MappingAdmissionScope, MappingConfirmationStore
from rolo.dsl.candidates import build_candidate_index, persist_candidate_index
from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.cli import main
from rolo.dsl.context import ProbeContext
from rolo.dsl.mapping import AdapterMappingRequest
from rolo.dsl.proposal import build_mapping_proposal, persist_mapping_proposal


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _dsl() -> dict:
    return {
        "tool_id": "app.state",
        "kind": "OBSERVE",
        "target": {"robot_id": "r", "evidence_digest": _digest("e")},
        "binding": {"resource_id": "route:/state"},
    }


def _context() -> ProbeContext:
    return ProbeContext(
        robot_id="r",
        evidence_digest=_digest("e"),
        target_fingerprint="target-fingerprint",
        evidence_refs=("route:/state",),
        routes=(
            {
                "operation": "app.state",
                "resource_id": "route:/state",
            },
        ),
    )


def _proposal(tmp_path, *, journey_session_id: str = "journey-1", user_goal: str = "read state"):
    context = _context()
    index = build_candidate_index(context)
    candidate = index.candidates[0]
    request = AdapterMappingRequest(
        journey_session_id=journey_session_id,
        user_goal=user_goal,
        context_digest=context_digest(context),
        available_tool_catalog_digest=_digest("c"),
        operation_candidates=(candidate.operation,),
    )
    proposal = build_mapping_proposal(
        request,
        index,
        candidate,
        dsl=_dsl(),
        context=context,
        scope=MappingAdmissionScope(
            tool_id="app.state",
            operation_kind="OBSERVE",
            operations=("app.state",),
            access="read",
            risk="R0",
        ),
    )
    return proposal, persist_mapping_proposal(proposal, tmp_path / "proposals")


def _compile_payload(proposal, receipt_digest: str) -> dict:
    return {
        "schema_version": "rolo-dsl-compile-request/v2",
        "journey_session_id": proposal.journey_session_id,
        "confirmation_receipt_digest": receipt_digest,
        "dsl": _dsl(),
        "dsl_digest": dsl_digest(_dsl()),
        "context": _context().model_dump(mode="json"),
        "context_digest": context_digest(_context()),
        "target_fingerprint": _context().target_fingerprint,
    }


def _admitted_compile_request(tmp_path, *, name: str = "compile"):
    proposal, proposal_path = _proposal(tmp_path / name)
    store_root = tmp_path / name / "admission"
    receipt = MappingConfirmationStore(store_root).confirm(
        proposal.admission_identity(),
        decision_id=f"{name}-confirm",
        actor_id="operator@example",
    )
    request_path = tmp_path / name / "compile-request.json"
    request_path.parent.mkdir(parents=True, exist_ok=True)
    request_path.write_text(
        json.dumps(_compile_payload(proposal, receipt.receipt_digest)),
        encoding="utf-8",
    )
    return request_path, store_root, proposal, proposal_path, receipt


def test_cli_check_emits_result_and_success_exit(tmp_path, capsys):
    request = tmp_path / "request.json"
    request.write_text(json.dumps({"dsl": _dsl()}), encoding="utf-8")

    assert main(["check", str(request)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "PASS"
    assert result["dsl_digest"].startswith("sha256:")


def test_cli_proposal_reads_checked_dsl_and_context_and_writes_v2(tmp_path, capsys):
    context = _context()
    context_path = tmp_path / "context.json"
    context_path.write_text(context.model_dump_json(), encoding="utf-8")
    index = build_candidate_index(context)
    index_path = persist_candidate_index(index, tmp_path / "candidate")
    request_path = tmp_path / "mapping-request.json"
    request_path.write_text(
        AdapterMappingRequest(
            journey_session_id="journey-cli",
            user_goal="read state",
            context_digest=context_digest(context),
            available_tool_catalog_digest=_digest("c"),
            operation_candidates=("app.state",),
        ).model_dump_json(),
        encoding="utf-8",
    )
    dsl_path = tmp_path / "mapping.json"
    dsl_path.write_text(json.dumps(_dsl()), encoding="utf-8")
    output = tmp_path / "proposal-output"

    assert (
        main(
            [
                "proposal",
                str(request_path),
                str(index_path),
                "--candidate-id",
                "app.state",
                "--dsl",
                str(dsl_path),
                "--context",
                str(context_path),
                "--scope-access",
                "read",
                "--scope-risk",
                "R0",
                "--output-dir",
                str(output),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    artifact = output / "mapping-proposals" / f"{result['proposal']['proposal_digest'][7:]}.json"
    assert result["status"] == "PASS"
    assert result["proposal"]["schema_version"] == "rolo-mapping-proposal/v2"
    assert result["proposal"]["dsl_digest"] == dsl_digest(_dsl())
    assert result["proposal"]["context_digest"] == context_digest(context)
    assert result["artifact"] == str(artifact)
    assert artifact.is_file()


def test_cli_confirm_is_idempotent_and_cancel_tombstones_receipt(tmp_path, capsys):
    proposal, proposal_path = _proposal(tmp_path)
    store_root = tmp_path / "admission"
    command = [
        "confirm",
        str(proposal_path),
        "--admission-store",
        str(store_root),
        "--actor-id",
        "operator@example",
        "--decision-id",
        "confirm-cli",
        "--ttl-s",
        "900",
    ]
    assert main(command) == 0
    confirmed = json.loads(capsys.readouterr().out)
    assert confirmed["status"] == "CONFIRMED"
    assert confirmed["receipt"]["proposal_digest"] == proposal.proposal_digest

    assert main(command) == 0
    replayed = json.loads(capsys.readouterr().out)
    assert replayed["receipt_digest"] == confirmed["receipt_digest"]
    assert len(MappingConfirmationStore(store_root).receipts()) == 1

    assert (
        main(
            [
                "cancel",
                confirmed["receipt_digest"],
                "--admission-store",
                str(store_root),
                "--actor-id",
                "operator@example",
                "--decision-id",
                "cancel-cli",
            ]
        )
        == 0
    )
    cancelled = json.loads(capsys.readouterr().out)
    assert cancelled["status"] == "CANCELLED"
    assert cancelled["receipt"]["supersedes_receipt_digest"] == confirmed["receipt_digest"]
    assert len(MappingConfirmationStore(store_root).receipts()) == 2


def test_cli_reject_writes_terminal_receipt(tmp_path, capsys):
    proposal, proposal_path = _proposal(tmp_path)
    store_root = tmp_path / "admission"
    assert (
        main(
            [
                "reject",
                str(proposal_path),
                "--admission-store",
                str(store_root),
                "--actor-id",
                "operator@example",
                "--decision-id",
                "reject-cli",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "REJECTED"
    assert result["receipt"]["proposal_digest"] == proposal.proposal_digest


def test_cli_compile_writes_bundle_artifacts_only_with_committed_confirmation(tmp_path, capsys):
    request, store_root, _, _, receipt = _admitted_compile_request(tmp_path)
    output = tmp_path / "output"

    assert (
        main(
            [
                "compile",
                str(request),
                "--output-dir",
                str(output),
                "--admission-store",
                str(store_root),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "PASS"
    assert result["confirmation_receipt_digest"] == receipt.receipt_digest
    assert (output / "manifest.json").exists()


def test_cli_compile_requires_store_v2_and_receipt_before_writing_artifacts(tmp_path, capsys):
    request, store_root, _, _, _ = _admitted_compile_request(tmp_path)

    missing_store_output = tmp_path / "missing-store"
    assert main(["compile", str(request), "--output-dir", str(missing_store_output)]) == 2
    missing_store = json.loads(capsys.readouterr().out)
    assert missing_store["status"] == "BLOCKED"
    assert missing_store["code"] == "MAPPING_CONFIRMATION_STORE_REQUIRED"
    assert not missing_store_output.exists()

    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps({"dsl": _dsl()}), encoding="utf-8")
    legacy_output = tmp_path / "legacy-output"
    assert (
        main(
            [
                "compile",
                str(legacy),
                "--output-dir",
                str(legacy_output),
                "--admission-store",
                str(store_root),
            ]
        )
        == 2
    )
    legacy_result = json.loads(capsys.readouterr().out)
    assert legacy_result["code"] == "DSL_COMPILE_REQUEST_V2_REQUIRED"
    assert not legacy_output.exists()

    missing_receipt_payload = _compile_payload(_proposal(tmp_path / "missing-receipt")[0], _digest("f"))
    missing_receipt_payload.pop("confirmation_receipt_digest")
    missing_receipt = tmp_path / "missing-receipt.json"
    missing_receipt.write_text(json.dumps(missing_receipt_payload), encoding="utf-8")
    missing_receipt_output = tmp_path / "missing-receipt-output"
    assert (
        main(
            [
                "compile",
                str(missing_receipt),
                "--output-dir",
                str(missing_receipt_output),
                "--admission-store",
                str(store_root),
            ]
        )
        == 2
    )
    receipt_result = json.loads(capsys.readouterr().out)
    assert receipt_result["code"] == "MAPPING_CONFIRMATION_REQUIRED"
    assert not missing_receipt_output.exists()


def test_cli_compile_rejects_uncommitted_or_cancelled_receipt_without_artifact(tmp_path, capsys):
    request, store_root, _, _, receipt = _admitted_compile_request(tmp_path)
    empty_store = tmp_path / "empty-admission"
    uncommitted_output = tmp_path / "uncommitted-output"
    assert (
        main(
            [
                "compile",
                str(request),
                "--output-dir",
                str(uncommitted_output),
                "--admission-store",
                str(empty_store),
            ]
        )
        == 1
    )
    uncommitted = json.loads(capsys.readouterr().out)
    assert uncommitted["diagnostics"] == ["MAPPING_CONFIRMATION_NOT_COMMITTED"]
    assert not uncommitted_output.exists()

    MappingConfirmationStore(store_root).cancel(
        receipt.receipt_digest,
        decision_id="cancel-before-compile",
        actor_id="operator@example",
    )
    cancelled_output = tmp_path / "cancelled-output"
    assert (
        main(
            [
                "compile",
                str(request),
                "--output-dir",
                str(cancelled_output),
                "--admission-store",
                str(store_root),
            ]
        )
        == 1
    )
    cancelled = json.loads(capsys.readouterr().out)
    assert cancelled["diagnostics"] == ["MAPPING_CONFIRMATION_CANCELLED"]
    assert not cancelled_output.exists()


def test_cli_candidates_writes_index_and_intent_matches(tmp_path, capsys):
    context = tmp_path / "context.json"
    context.write_text(
        json.dumps(
            {
                "robot_id": "r",
                "target_fingerprint": "fp",
                "evidence_digest": _digest("e"),
                "evidence_refs": ["artifact://probe/e"],
                "routes": [{"operation": "app.base.rotate"}],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "candidates"
    assert main(["candidates", str(context), "--output-dir", str(output), "--intent", "base rotate"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "PASS"
    assert result["matches"][0]["operation"] == "app.base.rotate"
    assert (output / "candidate-index.json").exists()


def test_cli_validate_canonicalize_and_replay_are_json_only(tmp_path, capsys):
    dsl_path = tmp_path / "mapping.json"
    dsl_path.write_text(json.dumps(_dsl()), encoding="utf-8")

    assert main(["validate", str(dsl_path)]) == 0
    validated = json.loads(capsys.readouterr().out)
    assert validated["status"] == "PASS"

    canonical_path = tmp_path / "canonical.json"
    assert main(["canonicalize", str(dsl_path), "--output", str(canonical_path)]) == 0
    canonicalized = json.loads(capsys.readouterr().out)
    assert canonicalized["status"] == "PASS"
    assert canonicalized["dsl_digest"].startswith("sha256:")
    assert json.loads(canonical_path.read_text(encoding="utf-8"))["schema_version"] == "rolo-dsl/v1"

    request_path, store_root, _, _, _ = _admitted_compile_request(tmp_path, name="replay-input")
    replay_output = tmp_path / "replay"
    assert (
        main(
            [
                "replay",
                str(request_path),
                "--output-dir",
                str(replay_output),
                "--admission-store",
                str(store_root),
            ]
        )
        == 0
    )
    replayed = json.loads(capsys.readouterr().out)
    assert replayed["status"] == "PASS"
    assert replayed["stable"] is True
    assert (replay_output / "first" / "manifest.json").exists()


def test_cli_replay_requires_store_v2_and_receipt_before_creating_output(tmp_path, capsys):
    request_path, store_root, proposal, _, receipt = _admitted_compile_request(
        tmp_path, name="replay-boundary"
    )
    output = tmp_path / "replay-no-store-output"
    assert main(["replay", str(request_path), "--output-dir", str(output)]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["code"] == "MAPPING_CONFIRMATION_STORE_REQUIRED"
    assert not output.exists()

    legacy_request = tmp_path / "replay-legacy.json"
    legacy_request.write_text(json.dumps({"dsl": _dsl()}), encoding="utf-8")
    legacy_output = tmp_path / "replay-legacy-output"
    assert (
        main(
            [
                "replay",
                str(legacy_request),
                "--output-dir",
                str(legacy_output),
                "--admission-store",
                str(store_root),
            ]
        )
        == 2
    )
    legacy = json.loads(capsys.readouterr().out)
    assert legacy["code"] == "DSL_COMPILE_REQUEST_V2_REQUIRED"
    assert not legacy_output.exists()

    missing_receipt_payload = _compile_payload(proposal, receipt.receipt_digest)
    missing_receipt_payload.pop("confirmation_receipt_digest")
    missing_receipt_request = tmp_path / "replay-missing-receipt.json"
    missing_receipt_request.write_text(
        json.dumps(missing_receipt_payload), encoding="utf-8"
    )
    missing_receipt_output = tmp_path / "replay-missing-receipt-output"
    assert (
        main(
            [
                "replay",
                str(missing_receipt_request),
                "--output-dir",
                str(missing_receipt_output),
                "--admission-store",
                str(store_root),
            ]
        )
        == 2
    )
    missing_receipt = json.loads(capsys.readouterr().out)
    assert missing_receipt["code"] == "MAPPING_CONFIRMATION_REQUIRED"
    assert not missing_receipt_output.exists()


def test_cli_validate_accepts_yaml_and_rejects_duplicate_keys(tmp_path, capsys):
    dsl_path = tmp_path / "mapping.yaml"
    dsl_path.write_text(
        "tool_id: app.state\n"
        "kind: OBSERVE\n"
        "target:\n"
        "  robot_id: r\n"
        f"  evidence_digest: {_digest('e')}\n"
        "binding:\n"
        "  resource_id: route:/state\n",
        encoding="utf-8",
    )
    assert main(["validate", str(dsl_path)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "PASS"

    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text("tool_id: one\ntool_id: two\nkind: OBSERVE\n", encoding="utf-8")
    assert main(["validate", str(duplicate)]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "ERROR"


def test_cli_validate_rejects_duplicate_json_keys(tmp_path, capsys):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"tool_id":"state","tool_id":"shadow","kind":"OBSERVE",'
        f'"target":{{"robot_id":"r","evidence_digest":"{_digest("e")}"}},'
        '"binding":{"resource_id":"route:/state"}}',
        encoding="utf-8",
    )
    assert main(["validate", str(duplicate)]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "ERROR"
    assert result["error"] == "ValueError"
    assert "duplicate mapping key" in result["message"]


def test_cli_returns_structured_error_for_missing_input(tmp_path, capsys):
    assert main(["check", str(tmp_path / "missing.json")]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "ERROR"
    assert result["error"] == "FileNotFoundError"


def test_cli_bootstrap_verify_reports_success(tmp_path, capsys):
    from rolo.dsl.bootstrap import BootstrapProbeProfile, run_bootstrap_projection

    bundle = {
        "schema_version": "robot-target-evidence-bundle/v4",
        "robot_id": "robot-1",
        "source_id": "probe-1",
        "target_host_fingerprint": "b" * 64,
        "request_nonce": "c" * 32,
        "requested_layers": ["ros"],
        "access": "READ_ONLY",
        "collected_at": datetime(2026, 9, 6, tzinfo=timezone.utc).isoformat(),
        "probes": {
            "ros": {
                "layer": "ros",
                "status": "SUCCEEDED",
                "data": {"routes": [{"resource_id": "/scan", "operation": "sensor.scan"}]},
                "warnings": [],
                "errors": [],
            }
        },
        "payload_sha256": "a" * 64,
        "signature_hmac_sha256": "d" * 64,
    }
    _, paths = run_bootstrap_projection(
        bundle,
        tmp_path,
        profile=BootstrapProbeProfile(profile_id="p", robot_id="robot-1"),
        evidence_verified=True,
    )
    assert main(["bootstrap-verify", str(paths["manifest"].parent), "--robot-id", "robot-1"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "PASS"
