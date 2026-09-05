from pathlib import Path

from rolo.canary import LanderPiCanary


def test_landerpi_offline_canary_has_trace_and_ten_certify_cases(tmp_path: Path):
    report = LanderPiCanary(tmp_path).run()
    assert report["status"] == "PASS"
    assert report["target"] == "landerpi"
    assert report["conformance"]["c1_dsl"] == "PASS"
    assert report["trace"]["consumer"] == "trace"
    assert len(report["certify"]) == 10
    assert (tmp_path / "landerpi-canary.json").exists()
