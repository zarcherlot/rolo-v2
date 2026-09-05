from rolo.dsl.report import ConformanceReport, GateStatus

def test_conformance_report_requires_all_gates():
    report = ConformanceReport(c1_dsl="PASS", c2_evidence="PASS", c3_compile="PASS", c4_behavior="PASS")
    assert report.passed
    report = ConformanceReport(c1_dsl="PASS", c2_evidence="FAIL", c3_compile="PASS", c4_behavior="PASS")
    assert not report.passed
