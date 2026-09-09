from rolo.dsl.replay import replay_stable


def test_replay_is_deterministic(mapping_confirmation_factory):
    value = {"tool_id": "app.x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64}, "binding": {"resource_id": "route:/state"}}
    context = {"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64, "target_fingerprint": "fp", "evidence_refs": ["route:/state"]}
    confirmed = mapping_confirmation_factory(value, context)
    assert replay_stable(value, context, **confirmed.compiler_kwargs)
