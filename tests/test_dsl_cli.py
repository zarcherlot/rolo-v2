import json
from datetime import datetime, timezone

from rolo.dsl.cli import main


def _dsl() -> dict:
    return {
        "tool_id": "state",
        "kind": "OBSERVE",
        "target": {"robot_id": "r", "evidence_digest": "sha256:e"},
        "binding": {"resource_id": "route:/state"},
    }


def test_cli_check_emits_result_and_success_exit(tmp_path, capsys):
    request = tmp_path / "request.json"
    request.write_text(json.dumps({"dsl": _dsl()}), encoding="utf-8")

    assert main(["check", str(request)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "PASS"
    assert result["dsl_digest"].startswith("sha256:")


def test_cli_compile_writes_bundle_artifacts(tmp_path, capsys):
    check_request = {"dsl": _dsl()}
    from rolo.dsl.api import DslCheckRequest
    from rolo.dsl.canonical import context_digest
    from rolo.dsl.service import RoloDslCompiler

    checked = RoloDslCompiler().check(DslCheckRequest.model_validate(check_request))
    context = {
        "robot_id": "r",
        "evidence_digest": "sha256:e",
        "target_fingerprint": "fp",
        "evidence_refs": ["route:/state"],
    }
    request = tmp_path / "compile.json"
    request.write_text(
        json.dumps(
            {
                "dsl": _dsl(),
                "dsl_digest": checked.dsl_digest,
                "context": context,
                "context_digest": context_digest(context),
                "target_fingerprint": "fp",
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "output"

    assert main(["compile", str(request), "--output-dir", str(output)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "PASS"
    assert (output / "manifest.json").exists()


def test_cli_candidates_writes_index_and_intent_matches(tmp_path, capsys):
    context = tmp_path / "context.json"
    context.write_text(
        json.dumps(
            {
                "robot_id": "r",
                "target_fingerprint": "fp",
                "evidence_digest": "sha256:e",
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

    from rolo.dsl.canonical import context_digest
    from rolo.dsl.parser import parse_document

    context = {
        "robot_id": "r",
        "target_fingerprint": "fp",
        "evidence_digest": "sha256:e",
        "evidence_refs": ["route:/state"],
    }
    document, report = parse_document(_dsl())
    assert document is not None and report.ok
    request_path = tmp_path / "compile-request.json"
    request_path.write_text(
        json.dumps(
            {
                "dsl": _dsl(),
                "context": context,
                "dsl_digest": canonicalized["dsl_digest"],
                "context_digest": context_digest(context),
                "target_fingerprint": "fp",
            }
        ),
        encoding="utf-8",
    )
    assert main(["replay", str(request_path), "--output-dir", str(tmp_path / "replay")]) == 0
    replayed = json.loads(capsys.readouterr().out)
    assert replayed["status"] == "PASS"
    assert replayed["stable"] is True
    assert (tmp_path / "replay" / "first" / "manifest.json").exists()


def test_cli_validate_accepts_yaml_and_rejects_duplicate_keys(tmp_path, capsys):
    dsl_path = tmp_path / "mapping.yaml"
    dsl_path.write_text(
        "tool_id: state\n"
        "kind: OBSERVE\n"
        "target:\n"
        "  robot_id: r\n"
        "  evidence_digest: sha256:e\n"
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
        '"target":{"robot_id":"r","evidence_digest":"sha256:e"},'
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
