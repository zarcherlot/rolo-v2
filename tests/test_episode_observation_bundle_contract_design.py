from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parents[1]


def _design() -> dict[str, object]:
    path = ROOT / "schemas" / "rolo-episode-observation-bundle-contract-design-v1.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _contract() -> str:
    path = ROOT / "docs" / "EPISODE_OBSERVATION_BUNDLE_CONTRACT_DESIGN.md"
    return path.read_text(encoding="utf-8")


def test_e22b_contract_is_versioned_feature_negotiated_and_consumer_deferred() -> None:
    design = _design()
    assert design["schema_version"] == "rolo-episode-observation-bundle-contract-design/v1"
    assert design["status"] == "e22b-producer-review-candidate"
    assert design["base_feature"] == "workbench.episode-read-model/v1"
    assert design["candidate_feature"] == "workbench.episode-observation-bundle/v1"
    assert design["implementation"] == {
        "producer": "candidate-e22b",
        "endpoint": "candidate-e22b",
        "feature_advertisement": "candidate-e22b",
        "consumer": "deferred-e22c",
        "media_delivery": False,
        "supports_capture": False,
        "supports_recollection": False,
        "supports_replay": False,
        "supports_export": False,
        "supports_write": False,
    }


def test_e22a_reuses_episode_assets_and_evidence_instead_of_republishing_content() -> None:
    contracts = _design()["contracts"]
    assert contracts["asset_reference"] == "rolo-episode-asset-summary/v1"
    assert contracts["evidence_reference"] == "rolo-evidence-record/v1"
    assert set(contracts) == {
        "collection",
        "summary",
        "source_coverage",
        "asset_reference",
        "evidence_reference",
    }


def test_e22a_keeps_time_alignment_world_and_availability_dimensions_separate() -> None:
    design = _design()
    assert set(design["synchronization_states"]) == {
        "SYNCED",
        "DEGRADED",
        "UNSYNCED",
        "UNKNOWN",
    }
    assert set(design["spatial_alignment_states"]) == {
        "ALIGNED",
        "DEGRADED",
        "UNALIGNED",
        "UNKNOWN",
    }
    assert set(design["world_kinds"]) == {"PHYSICAL", "SIMULATED", "REPLAYED"}
    assert {"NONE", "MIXED"} <= set(design["world_scopes"])
    assert set(design["source_availability"]) == {
        "AVAILABLE",
        "MISSING",
        "STALE",
        "REJECTED",
        "UNAVAILABLE",
    }


def test_e22a_forbids_internal_locations_payloads_identity_and_content() -> None:
    forbidden = set(_design()["forbidden_fields"])
    assert {
        "artifact_ref",
        "local_path",
        "remote_path",
        "signed_url",
        "hostname",
        "device_path",
        "topic_name",
        "source_identity",
        "provider_identity",
        "credential",
        "command_payload",
        "telemetry_payload",
        "tf_payload",
        "calibration_payload",
        "renderer_config",
        "model_prompt",
        "model_response",
        "content_url",
        "content_key",
    } <= forbidden


def test_e22a_contract_keeps_bundle_completeness_release_neutral() -> None:
    design = _design()
    fields = set(design["bundle_public_fields"])
    invariants = " ".join(design["required_invariants"]).lower()
    assert "influences_verification" in fields
    assert "complete bundle status never upgrades" in invariants
    assert "influences_verification is always false" in invariants
    contract = _contract()
    assert "does not establish execution outcome" in contract
    assert "E22B implements only the reviewed read-only producer" in contract


def test_e22a_orders_pages_newest_first_and_defers_parent_resolution_safely() -> None:
    design = _design()
    invariants = " ".join(design["required_invariants"]).lower()
    assert design["ordering_policy"] == "NEWEST_FIRST_STRICT_SEQUENCE_DESCENDING"
    assert "complete traversal resolves every parent" in invariants
    assert "asset bearing source world kinds" in invariants
    assert "no assets means none" in invariants
