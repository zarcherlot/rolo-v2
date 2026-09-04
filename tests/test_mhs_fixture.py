from datetime import datetime, timezone

import pytest

from rolo.mhs_fixture import MhsProvisionalFixture, replay_fixture


def _fixture() -> MhsProvisionalFixture:
    raw = {
        "fixture_id": "fixture-1",
        "target_fingerprint": "a" * 64,
        "generated_by": "test",
        "generated_at": datetime(2026, 9, 3, tzinfo=timezone.utc),
        "input_evidence_ids": ["e1"],
        "samples": {"camera": {"bound": "PARTIAL"}},
        "freshness": "FRESH",
        "digest": "0" * 64,
    }
    model = MhsProvisionalFixture.model_construct(**raw)
    raw["digest"] = model.computed_digest()
    return MhsProvisionalFixture.model_validate(raw)


def test_fixture_digest_and_replay_are_target_bound() -> None:
    fixture = _fixture()
    result = replay_fixture(fixture, target_fingerprint="a" * 64)
    assert result["access"] == "READ_ONLY"
    assert result["limitations"]
    with pytest.raises(ValueError, match="fingerprint"):
        replay_fixture(fixture, target_fingerprint="b" * 64)


def test_fixture_cannot_claim_vendor_authority() -> None:
    fixture = _fixture().model_dump(mode="json")
    fixture["authority"] = "VENDOR"
    fixture["digest"] = "0" * 64
    with pytest.raises(ValueError):
        MhsProvisionalFixture.model_validate(fixture)
