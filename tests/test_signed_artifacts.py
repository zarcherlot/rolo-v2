import pytest

from rolo.core.signed_artifacts import SignedArtifact, SignedArtifactStore


def test_signed_artifact_publish_activate_and_rollback(tmp_path):
    store = SignedArtifactStore(tmp_path, {"release-1": b"secret"})
    first = SignedArtifact.build(
        artifact_id="targetd", version="1", payload={"digest": "a"},
        signer_key_id="release-1", key=b"secret"
    )
    second = SignedArtifact.build(
        artifact_id="targetd", version="2", payload={"digest": "b"},
        signer_key_id="release-1", key=b"secret"
    )
    assert store.publish(first).endswith("signed/targetd/1.json")
    assert store.publish(second).endswith("signed/targetd/2.json")
    assert store.activate("targetd", "2").endswith("current.json")
    assert store.rollback("targetd", "1").endswith("current.json")
    tampered = first.model_copy(update={"payload": {"digest": "tampered"}})
    with pytest.raises(ValueError, match="payload digest"):
        tampered.verify(b"secret")
