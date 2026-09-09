from rolo.dsl.api import DslCheckRequest, DslCompileRequest
from rolo.dsl.canonical import context_digest
from rolo.dsl.contracts import COMPILE_REQUEST_SCHEMA_VERSION
from rolo.dsl.service import RoloDslCompiler


def test_service_check_rejects_invalid_semantics():
    request = DslCheckRequest(dsl={"tool_id": "x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": "sha256:e"}})
    assert RoloDslCompiler().check(request).status == "DSL_CHECK_FAILED"


def test_service_check_with_context_rejects_unobserved_resource():
    request = DslCheckRequest(
        dsl={
            "tool_id": "x",
            "kind": "OBSERVE",
            "target": {"robot_id": "r", "evidence_digest": "sha256:e"},
            "binding": {"resource_id": "route:/not-observed"},
        },
        context={
            "robot_id": "r",
            "target_fingerprint": "fp",
            "evidence_digest": "sha256:e",
            "evidence_refs": ["route:/state"],
        },
    )
    result = RoloDslCompiler().check(request)
    assert result.status == "DSL_CHECK_FAILED"
    assert "RESOURCE_NOT_OBSERVED" in result.diagnostics


def test_service_compile_rejects_target_fingerprint_drift(tmp_path):
    dsl = {
        "tool_id": "x",
        "kind": "OBSERVE",
        "target": {"robot_id": "r", "evidence_digest": "sha256:e"},
        "binding": {"resource_id": "route:/state"},
    }
    context = {
        "robot_id": "r",
        "target_fingerprint": "fp",
        "evidence_digest": "sha256:e",
        "evidence_refs": ["route:/state"],
    }
    checked = RoloDslCompiler().check(DslCheckRequest(dsl=dsl, context=context))
    result = RoloDslCompiler().compile(
        DslCompileRequest(
            schema_version=COMPILE_REQUEST_SCHEMA_VERSION,
            journey_session_id="journey-1",
            confirmation_receipt_digest="sha256:" + "0" * 64,
            dsl=dsl,
            context=context,
            dsl_digest=checked.dsl_digest,
            context_digest=context_digest(context),
            target_fingerprint="different-target",
        ),
        tmp_path,
    )
    assert result.status == "DSL_COMPILE_FAILED"
    assert result.diagnostics == ("TARGET_FINGERPRINT_MISMATCH",)


def test_service_check_rejects_malformed_context_without_raising():
    request = DslCheckRequest(
        dsl={
            "tool_id": "x",
            "kind": "OBSERVE",
            "target": {"robot_id": "r", "evidence_digest": "sha256:e"},
            "binding": {"resource_id": "route:/state"},
        },
        context={"robot_id": "r"},
    )
    result = RoloDslCompiler().check(request)
    assert result.status == "DSL_CHECK_FAILED"
    assert result.diagnostics == ("CONTEXT_INVALID",)


def test_service_compile_rejects_malformed_context_without_writing_artifact(tmp_path):
    dsl = {
        "tool_id": "x",
        "kind": "OBSERVE",
        "target": {"robot_id": "r", "evidence_digest": "sha256:e"},
        "binding": {"resource_id": "route:/state"},
    }
    result = RoloDslCompiler().compile(
        DslCompileRequest(
            schema_version=COMPILE_REQUEST_SCHEMA_VERSION,
            journey_session_id="journey-1",
            confirmation_receipt_digest="sha256:" + "0" * 64,
            dsl=dsl,
            context={"robot_id": "r"},
            dsl_digest="sha256:" + "0" * 64,
            context_digest="sha256:" + "0" * 64,
            target_fingerprint="fp",
        ),
        tmp_path,
    )
    assert result.status == "DSL_COMPILE_FAILED"
    assert result.diagnostics == ("CONTEXT_INVALID",)
    assert not list(tmp_path.iterdir())
