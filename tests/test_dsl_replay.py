from rolo.dsl.replay import replay_stable


def test_replay_is_deterministic():
    value = {"tool_id": "x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": "sha256:e"}, "binding": {"resource_id": "route:/state"}}
    context = {"robot_id": "r", "evidence_digest": "sha256:e", "evidence_refs": ["route:/state"]}
    assert replay_stable(value, context)
