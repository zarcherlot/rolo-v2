from rolo.dsl.api import DslCheckRequest, DslCompileRequest
from rolo.dsl.canonical import context_digest
from rolo.dsl.contracts import COMPILE_REQUEST_SCHEMA_VERSION
from rolo.dsl.service import RoloDslCompiler


def value():
    return {
        "tool_id": "app.x",
        "kind": "OBSERVE",
        "target": {"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64},
        "binding": {"resource_id": "route:/state"},
    }


def context():
    return {
        "robot_id": "r",
        "evidence_digest": "sha256:" + "e" * 64,
        "target_fingerprint": "fp",
        "evidence_refs": ["route:/state"],
    }


def test_service_check_and_compile(tmp_path, mapping_confirmation_factory):
    confirmed = mapping_confirmation_factory(value(), context())
    service = RoloDslCompiler(confirmed.store)
    checked = service.check(DslCheckRequest(dsl=value()))
    assert checked.status == "PASS"
    compiled = service.compile(
        DslCompileRequest(
            schema_version=COMPILE_REQUEST_SCHEMA_VERSION,
            journey_session_id=confirmed.receipt.journey_session_id,
            confirmation_receipt_digest=confirmed.receipt.receipt_digest,
            dsl=value(),
            dsl_digest=checked.dsl_digest,
            context=context(),
            context_digest=context_digest(context()),
            target_fingerprint="fp",
        ),
        tmp_path / "compile",
    )
    assert compiled.status == "PASS"
    assert compiled.conformance and compiled.conformance.passed
    assert compiled.confirmation_receipt_digest == confirmed.receipt.receipt_digest


def test_service_compile_requires_committed_mapping_confirmation(tmp_path):
    checked = RoloDslCompiler().check(DslCheckRequest(dsl=value(), context=context()))
    compiled = RoloDslCompiler().compile(
        DslCompileRequest(
            schema_version=COMPILE_REQUEST_SCHEMA_VERSION,
            journey_session_id="journey-1",
            confirmation_receipt_digest="sha256:" + "0" * 64,
            dsl=value(),
            dsl_digest=checked.dsl_digest,
            context=context(),
            context_digest=context_digest(context()),
            target_fingerprint="fp",
        ),
        tmp_path,
    )
    assert compiled.status == "DSL_COMPILE_FAILED"
    assert compiled.diagnostics == ("MAPPING_CONFIRMATION_REQUIRED",)
    assert not (tmp_path / "manifest.json").exists()
