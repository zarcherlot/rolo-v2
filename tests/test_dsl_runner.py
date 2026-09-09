from pathlib import Path

import rolo.dsl.runner as runner_module
from rolo.dsl.context import ProbeContext
from rolo.dsl.models import DslDocument
from rolo.dsl.runner import ConformanceRunner


def document():
    return DslDocument(tool_id="app.x", kind="OBSERVE", target={"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64}, binding={"resource_id": "route:/state"})


def context():
    return ProbeContext(robot_id="r", target_fingerprint="fp", evidence_digest="sha256:" + "e" * 64, evidence_refs=("route:/state",))


def test_runner_writes_report_and_passes(tmp_path: Path, mapping_confirmation_factory):
    confirmed = mapping_confirmation_factory(
        document().model_dump(mode="json"),
        context().model_dump(mode="json"),
    )
    report = ConformanceRunner(tmp_path).run(
        document(),
        context(),
        **confirmed.compiler_kwargs,
    )
    assert report.passed
    assert (tmp_path / "conformance-c1-c4.json").exists()


def test_runner_blocks_forged_route(tmp_path: Path, mapping_confirmation_factory):
    bad = context().model_copy(update={"evidence_refs": ()})
    confirmed = mapping_confirmation_factory(
        document().model_dump(mode="json"),
        bad.model_dump(mode="json"),
    )
    report = ConformanceRunner(tmp_path).run(
        document(),
        bad,
        **confirmed.compiler_kwargs,
    )
    assert report.c2_evidence == "FAIL"
    assert not report.passed


def test_runner_cancellation_before_replay_writes_no_report(
    tmp_path: Path,
    monkeypatch,
    mapping_confirmation_factory,
):
    confirmed = mapping_confirmation_factory(
        document().model_dump(mode="json"),
        context().model_dump(mode="json"),
    )
    original_compile = runner_module.compile_document
    calls = 0

    def compile_then_cancel(*args, **kwargs):
        nonlocal calls
        result = original_compile(*args, **kwargs)
        calls += 1
        if calls == 1 and result.ok:
            confirmed.store.cancel(
                confirmed.receipt.receipt_digest,
                decision_id="cancel-before-replay",
                actor_id="test-operator",
            )
        return result

    monkeypatch.setattr(runner_module, "compile_document", compile_then_cancel)
    report = ConformanceRunner(tmp_path).run(
        document(),
        context(),
        **confirmed.compiler_kwargs,
    )

    assert not report.passed and report.c4_behavior == "FAIL"
    assert "MAPPING_CONFIRMATION_CANCELLED" in report.diagnostics
    assert not (tmp_path / "conformance-c1-c4.json").exists()
    assert not (tmp_path / "replay").exists()
