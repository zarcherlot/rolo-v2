from pathlib import Path

import rolo.dsl.admission as admission
import rolo.dsl.service as dsl_service
import rolo.release_check as release_check


def test_release_check_inventories_admission_contracts_and_passes_real_smoke() -> None:
    result = release_check.run_release_check()

    assert result.status == "PASS", result.failures
    assert "mapping-admission:confirmed-and-cancel-fail-closed" in result.checks
    assert "targetd-transport-idempotency-smoke:passed" in result.checks
    assert "targetd-replay:passed" not in result.checks
    assert {
        "schema:mapping-proposal-v2",
        "schema:mapping-confirmation-receipt-v1",
        "schema:dsl-compile-request-v2",
        "schema:target-conformance-v3",
        "schema:post-compiler-journey-result-v2",
    }.issubset(result.checks)


def test_cancelled_admission_stops_before_a_second_compile_or_artifact(
    tmp_path: Path,
    monkeypatch,
) -> None:
    compile_calls: list[Path] = []
    production_compile = dsl_service.compile_document

    def counted_compile(*args, **kwargs):
        compile_calls.append(Path(args[1]))
        return production_compile(*args, **kwargs)

    monkeypatch.setattr(dsl_service, "compile_document", counted_compile)

    release_check._confirmed_mapping_admission_smoke(tmp_path)

    assert compile_calls == [tmp_path / "confirmed-compile"]
    assert (tmp_path / "confirmed-compile" / "manifest.json").is_file()
    assert not (tmp_path / "cancelled-compile").exists()


def test_release_check_fails_when_core_gate_allows_a_cancelled_receipt(monkeypatch) -> None:
    def unsafe_gate(self, receipt_digest, expected_identity, *, now=None):
        del expected_identity, now
        return self.store.resolve(receipt_digest)

    monkeypatch.setattr(
        admission.MappingAdmissionGate,
        "require_active",
        unsafe_gate,
    )

    def unsafe_commit(self, receipt_digest, expected_identity, commit, *, now=None):
        del expected_identity, now
        return self.store.resolve(receipt_digest), commit()

    monkeypatch.setattr(
        admission.MappingAdmissionGate,
        "commit_if_active",
        unsafe_commit,
    )

    result = release_check.run_release_check()

    assert result.status == "FAIL"
    assert "mapping-admission:confirmed-and-cancel-fail-closed" not in result.checks
    assert any(failure.startswith("mapping-admission: cancelled Mapping confirmation crossed the artifact boundary") for failure in result.failures)
