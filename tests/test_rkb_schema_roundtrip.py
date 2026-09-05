import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rolo.rkb import (
    Fact,
    FactSourceKind,
    ReadOnlyKnowledgeBase,
    RuntimeStatusModel,
    Snapshot,
    SnapshotIdentity,
    TypedQueryResult,
)

ROOT = Path(__file__).parents[1]
NOW = datetime(2026, 9, 2, 8, 0, tzinfo=timezone.utc)


def test_typed_query_schema_and_model_round_trip():
    schema = json.loads((ROOT / "schemas/RKBTypedReadModels.schema.json").read_text())
    assert schema["$id"] == "rkb-typed-read-models/v1"
    assert schema["properties"]["schema_version"]["const"] == "rkb-typed-query-result/v1"
    identity = SnapshotIdentity(
        robot_id="robot-1",
        target_host_fingerprint="a" * 64,
        source_id="source-1",
        deployment_mode="local",
        request_nonce="b" * 32,
        observed_at=NOW,
        fresh_until=NOW + timedelta(minutes=5),
    )
    fact = Fact(
        robot_id="robot-1",
        target_host_fingerprint="a" * 64,
        source_id="source-1",
        deployment_mode="local",
        request_nonce="b" * 32,
        source_kind=FactSourceKind.OBSERVED_RUNTIME,
        source_ref="artifact://schema#/linux",
        observed_at=NOW,
        fresh_until=NOW + timedelta(minutes=5),
        value={"layer": "linux", "data": {"host": {"system": "Linux"}}},
    )
    snapshot = Snapshot(identity=identity, facts=[fact]).with_digest()
    result = ReadOnlyKnowledgeBase([snapshot]).os.runtime_status(now=NOW)
    restored = TypedQueryResult[RuntimeStatusModel].model_validate_json(result.model_dump_json())
    assert restored.schema_version == "rkb-typed-query-result/v1"
    assert restored.value.os_name == "Linux"
