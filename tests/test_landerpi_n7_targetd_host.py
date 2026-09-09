from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from rolo.targetd.lifecycle import WorkerCallKey
from rolo.targetd.n7_host_composition import N7HostTargetdRuntime
from scripts.landerpi_n7_targetd_host import (
    HostBootstrapError,
    bootstrap_payload_sha256,
    validate_bootstrap,
)
from tests.test_targetd_process_service import _physical_service


def _bootstrap(tmp_path):
    _service, _authority, request, manifest = _physical_service(tmp_path)
    nonce = "a" * 64
    stage_root = "/dev/shm/rolo-n7-targetd-" + "b" * 20
    raw_key = "Y" * 44
    payload = {
        "schema_version": "rolo-n7-targetd-host-bootstrap/v1",
        "run_id": "n7-host-contract",
        "stage_root": stage_root,
        "stage_nonce": nonce,
        "target_id": request.target_id,
        "target_identity": request.authority.mapping_admission.target_identity_digest,
        "expected_call": {
            "id": request.idempotency_key,
            "session": request.session_id,
            "execution_subject_digest": request.execution_subject_digest,
            "motion_fence_epoch": request.authority.fence_epoch,
            "request_digest": request.request_digest(),
            "call_key_digest": WorkerCallKey.from_request(request).digest(),
        },
        "execution_request": request.model_dump(mode="json"),
        "motion_intent": request.motion_safety_admission.intent.model_dump(mode="json"),
        "policy": {},
        "authority": request.authority.model_dump(mode="json"),
        "mapping_confirmation_receipt": {},
        "manifest": manifest.model_dump(mode="json"),
        "bundle_source_base64": "ZA==",
        "keys": {
            "targetd_signing_base64": raw_key,
            "bundle_verification_base64": raw_key,
            "graph_signing_base64": raw_key,
            "target_signing_base64": raw_key,
            "peer_bootstrap_verification_base64": raw_key,
        },
        "peer_bootstrap_receipt": {},
        "provider_runtime_sha256": manifest.observation_contract[
            "provider_runtime_sha256"
        ],
        "expected_peer": {
            "bootstrap_authority_id": "debug-controller:n7",
            "ssh_host": "landerpi",
            "ssh_port": 22,
            "ssh_username": "pi",
            "pinned_host_key_sha256": "sha256:" + "1" * 64,
            "client_public_key_sha256": "sha256:" + "2" * 64,
            "known_hosts_sha256": "sha256:" + "3" * 64,
            "channel_binding_sha256": "sha256:" + "4" * 64,
        },
    }
    payload["payload_sha256"] = bootstrap_payload_sha256(payload)
    owner = {
        "schema_version": "rolo-n7-targetd-host-stage/v1",
        "stage_root": stage_root,
        "run_id": payload["run_id"],
        "nonce_sha256": "sha256:"
        + hashlib.sha256(nonce.encode("ascii")).hexdigest(),
    }
    return payload, owner


def test_launcher_binds_full_v3_request_and_call_key(tmp_path):
    payload, owner = _bootstrap(tmp_path)

    assert validate_bootstrap(
        payload,
        stage_root=payload["stage_root"],
        owner=owner,
    ) == payload


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("request_digest", "5" * 64),
        ("call_key_digest", "6" * 64),
        ("execution_subject_digest", "sha256:" + "7" * 64),
    ],
)
def test_launcher_rejects_expected_call_drift(tmp_path, field, replacement):
    payload, owner = _bootstrap(tmp_path)
    payload["expected_call"][field] = replacement
    payload["payload_sha256"] = bootstrap_payload_sha256(payload)

    with pytest.raises(
        HostBootstrapError,
        match="N7_TARGETD_HOST_EXECUTION_REQUEST_MISMATCH",
    ):
        validate_bootstrap(
            payload,
            stage_root=payload["stage_root"],
            owner=owner,
        )


def test_launcher_rejects_missing_execution_request(tmp_path):
    payload, owner = _bootstrap(tmp_path)
    payload.pop("execution_request")
    payload["payload_sha256"] = bootstrap_payload_sha256(payload)

    with pytest.raises(
        HostBootstrapError,
        match="N7_TARGETD_HOST_BOOTSTRAP_INVALID",
    ):
        validate_bootstrap(
            payload,
            stage_root=payload["stage_root"],
            owner=owner,
        )


def test_unfinalized_recovery_cleans_only_exact_terminal_registry(monkeypatch):
    runtime = object.__new__(N7HostTargetdRuntime)
    runtime.call_key = SimpleNamespace(
        digest=lambda: "call-key-digest",
        target_id="mentorpi",
        idempotency_key="call-1",
        session_id="session-1",
        request_digest="request-digest",
    )
    runtime.request = SimpleNamespace(execution_subject_digest="sha256:" + "1" * 64)
    runtime.manifest = SimpleNamespace(
        observation_contract={"provider_runtime_sha256": "2" * 64}
    )
    armed = SimpleNamespace(arm_receipt_digest="arm-digest")
    observed: list[tuple[str, object]] = []

    monkeypatch.setattr(
        "rolo.targetd.n7_host_composition.parse_physical_worker_armed_zero",
        lambda value, **kwargs: observed.append(("parse", (value, kwargs))) or armed,
    )
    monkeypatch.setattr(
        "rolo.targetd.n7_host_composition.read_target_physical_worker_terminal_registry",
        lambda **kwargs: observed.append(("read", kwargs))
        or SimpleNamespace(armed_zero=armed),
    )
    monkeypatch.setattr(
        "rolo.targetd.n7_host_composition.cleanup_terminal_registry",
        lambda value, **kwargs: observed.append(("cleanup", (value, kwargs))) or True,
    )

    runtime._cleanup_recovered_registry(SimpleNamespace(armed_zero={"arm": "receipt"}))

    assert [kind for kind, _value in observed] == ["parse", "read", "cleanup"]
    assert observed[-1][1][1]["expected_call_key_digest"] == "call-key-digest"
    assert observed[-1][1][1]["expected_arm_receipt_digest"] == "arm-digest"


def test_unfinalized_prearm_recovery_has_no_global_registry_cleanup(monkeypatch):
    runtime = object.__new__(N7HostTargetdRuntime)
    monkeypatch.setattr(
        "rolo.targetd.n7_host_composition.cleanup_terminal_registry",
        lambda *_args, **_kwargs: pytest.fail("registry cleanup not expected"),
    )

    runtime._cleanup_recovered_registry(SimpleNamespace(armed_zero=None))
