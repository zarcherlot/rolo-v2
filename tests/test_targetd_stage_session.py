from rolo.stages.targetd_session import TargetdStageSession


class Router:
    def enter_probe(self): return "probe"
    def enter_trace(self): return "trace"
    def enter_certify(self): return "certify"

    def call(self, manifest, source, request): return (manifest, source, request)


def test_business_stages_share_one_router():
    session = TargetdStageSession(Router())
    assert session.probe() == "probe"
    assert session.trace() == "trace"
    assert session.certify() == "certify"
