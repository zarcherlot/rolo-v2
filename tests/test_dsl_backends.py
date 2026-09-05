from pathlib import Path
from rolo.dsl.frontend import compile_frontend
from rolo.dsl.parser import parse_document
from rolo.dsl.backends import default_backends

def test_each_kind_has_fake_backend(tmp_path: Path):
    for kind, extra in [("OBSERVE", {"binding": {"resource_id": "route:x"}}), ("COMPOSE", {"composition": {"steps": []}}), ("INVOKE", {"binding": {"operation": "x"}}), ("EXECUTE", {"implementation": {"source_bundle_digest": "sha256:src"}})]:
        raw = {"tool_id": "app.test", "kind": kind, "target": {"robot_id": "r", "evidence_digest": "sha256:e"}, **extra}
        doc, parsed = parse_document(raw)
        assert parsed.ok and doc
        ir, checked, _ = compile_frontend(doc)
        assert checked.ok and ir
        backend = next(item for item in default_backends() if item.supports(ir))
        bundle = backend.compile(ir, tmp_path / kind)
        assert bundle.manifest["kind"] == kind
