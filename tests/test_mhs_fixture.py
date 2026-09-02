from rolo.mhs_fixture import MhsBenchFixture


def test_bench_fixture_is_fail_closed_until_all_evidence_is_recorded() -> None:
    fixture = MhsBenchFixture("landerpi-no-load", resource_id="arm")
    assert fixture.bundle().is_write_ready() is False
    fixture.record("no_load", status="VERIFIED", notes="dummy load disconnected")
    fixture.record("external_estop", status="FAILED", notes="no external e-stop installed")
    assert fixture.bundle().is_write_ready() is False


def test_fixture_evidence_id_is_stable_and_snapshot_is_audit_friendly() -> None:
    fixture = MhsBenchFixture("fixture-1", resource_id="resource-1")
    assert fixture.evidence_id("stop") == "fixture:fixture-1:resource-1:stop"
    snapshot = fixture.snapshot()
    assert snapshot["fixture_id"] == "fixture-1"
    assert snapshot["write_ready"] is False
