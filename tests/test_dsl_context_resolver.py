from rolo.dsl.context import ProbeContext
from rolo.dsl.models import DslDocument
from rolo.dsl.resolver import resolve_evidence


def test_resolver_checks_routes_schema_and_mhs():
    doc = DslDocument(
        tool_id="x",
        kind="INVOKE",
        target={"robot_id": "r", "evidence_digest": "sha256:e", "mhs_manifest_refs": ("vendor.v1",)},
        binding={"resource_id": "route:/call", "message_schema": "schema:Call", "mhs_manifest_refs": ["vendor.v1"]},
    )
    context = ProbeContext(
        robot_id="r", target_fingerprint="fp", evidence_digest="sha256:e", routes=({"resource_id": "route:/call"},), message_schemas=({"schema_id": "schema:Call"},), mhs_manifest_refs=("vendor.v1",)
    )
    assert resolve_evidence(doc, context).ok
