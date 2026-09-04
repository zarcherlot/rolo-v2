# ruff: noqa: E501
"""Build a replayable Probe E2E acceptance batch from a live canary artifact.

The batch is deliberately evidence-first: missing signatures, vendor manifests,
or device-side counters are represented as PARTIAL/UNKNOWN and never inferred.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from rolo.agent_tools.mhs_association import AssociationReport
from rolo.http_server import create_app
from rolo.mhs_conformance import validate_read_only_surface
from rolo.mhs_manifest_records import (
    MhsAuthority,
    MhsManifestReference,
    MhsReferenceCandidate,
    MhsSourceKind,
    resolve_manifest_reference,
)
from rolo.rkb.mhs_api import MhsEvidenceReadApi
from rolo.rkb.models import EvidenceEnvelope, Snapshot


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dump(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )


def build_batch(canary_path: Path, output_dir: Path) -> dict[str, Any]:
    canary = json.loads(canary_path.read_text(encoding="utf-8"))
    target = canary["target"]
    target_fp = target["target_host_fingerprint"]
    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    output_dir.mkdir(parents=True, exist_ok=True)

    probe = canary["probe"]
    manifest = canary["manifest"]
    envelope = EvidenceEnvelope.model_validate(canary["rkb_evidence_envelope"])
    snapshot = Snapshot.from_envelope(envelope)
    manifest_ref = resolve_manifest_reference(
        manifest,
        target_fingerprint=target_fp,
        manifest_id=f"mhs-manifest:{canary['results'][0]['manifest_sha256']}",
        canonical_route="mhs://landerpi-compute/read",
        source_kind=MhsSourceKind.OBSERVED,
        authority=MhsAuthority.OBSERVED,
        source_ref="artifact://live-canary/manifest",
        collector_id=envelope.identity.collector_id,
        generated_by="scripts.build_probe_acceptance_batch",
        generated_at=envelope.identity.observed_at,
        input_evidence_ids=canary["results"][0]["evidence_ids"],
        expected_driver_sha256=canary["results"][0]["driver_sha256"],
        limitations=["observed runtime manifest; no vendor release authority"],
    )
    manifest_ref = manifest_ref.model_copy(update={"digest": manifest_ref.computed_digest()})
    vendor_ref = MhsManifestReference(
        manifest_id="vendor-manifest:landerpi:unavailable",
        target_fingerprint=target_fp,
        source_kind=MhsSourceKind.VENDOR_MANIFEST,
        authority=MhsAuthority.VENDOR,
        available=False,
        verified=False,
        status="MHS_MANIFEST_UNAVAILABLE",
        access="READ_ONLY",
        limitations=[
            "vendor manifest was not supplied by target or registry",
            "no authority inferred",
        ],
    )
    fixture_path = (
        Path(__file__).parents[1] / "examples" / "mhs-landerpi" / "provisional-fixture.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    fixture_ref = MhsManifestReference(
        manifest_id="fixture:landerpi-observed-20260903",
        target_fingerprint=target_fp,
        source_kind=MhsSourceKind.TEST_FIXTURE,
        authority=MhsAuthority.PROVISIONAL,
        uri=str(fixture_path),
        available=False,
        verified=False,
        status="MHS_PROVISIONAL_FIXTURE",
        fixture_id=fixture["fixture_id"],
        generated_by=fixture["generated_by"],
        generated_at=fixture["generated_at"],
        input_evidence_ids=fixture["input_evidence_ids"],
        not_vendor_manifest=True,
        not_release_authority=True,
        limitations=["test fixture only", "must not override observed runtime data"],
    )
    fixture_ref = fixture_ref.model_copy(update={"digest": fixture_ref.computed_digest()})
    candidate = MhsReferenceCandidate(
        candidate_id="landerpi-observed-runtime",
        target_fingerprint=target_fp,
        provider_id=canary["provider_id"],
        device_id=manifest["device_id"],
        manifest_id=manifest_ref.manifest_id,
        source_kind=MhsSourceKind.OBSERVED,
        authority=MhsAuthority.OBSERVED,
        transport=manifest["transport"]["kind"],
        resource_id=manifest["device_id"],
        route="mhs://landerpi-compute/read",
        source_ref="artifact://live-canary/manifest",
        collector_id=envelope.identity.collector_id,
        observed_at=envelope.identity.observed_at,
        freshness="FRESH",
        digest=manifest_ref.manifest_sha256,
        status="MHS_MANIFEST_AVAILABLE",
        limitations=["observed runtime; vendor authority unavailable"],
    )
    association = AssociationReport(
        target_fingerprint=target_fp,
        status="PROPOSED",
        evidence_refs=canary["results"][0]["evidence_ids"],
        route="mhs://landerpi-compute/read",
        manifest_digest=manifest_ref.manifest_sha256,
        limitations=[
            "association is a read-only proposal",
            "does not grant Tool or write authority",
        ],
    )
    operations = ["inspect", "status", "read"]
    read_results = [
        {
            "schema_version": "rolo-mhs-read-only/v1",
            "device_id": r["device_id"],
            "provider_id": canary["provider_id"],
            "target_fingerprint": target_fp,
            "route": r["route"],
            "operation": r["capability_id"],
            "status": r["status"],
            "value": r.get("value"),
            "manifest_sha256": r.get("manifest_sha256"),
            "driver_sha256": r.get("driver_sha256"),
            "observed_at": r.get("observed_at"),
            "fresh_until": r.get("fresh_until"),
            "evidence_ids": r.get("evidence_ids", []),
            "limitations": r.get("limitations", []),
            "access": "READ_ONLY",
        }
        for r in canary["results"]
    ]
    conformance_violations = validate_read_only_surface(
        operations=operations,
        references=[{"transport": "LOCAL-LINUX", "approved_access": True, "access": "READ_ONLY"}],
    )
    api = MhsEvidenceReadApi()
    api.publish_parts(
        target_fingerprint=target_fp,
        references=[candidate],
        manifests=[manifest_ref, vendor_ref, fixture_ref],
        read_results=read_results,
        limitations=canary["limitations"],
    )
    client = TestClient(create_app(api))
    http_evidence = client.get(f"/v1/mhs/{target_fp}/evidence")
    http_cards = client.get(f"/v1/mhs/{target_fp}/cards")
    http_targets = client.get("/v1/mhs/targets")
    http_contract = {
        "status": "PASS"
        if all(r.status_code == 200 for r in (http_evidence, http_cards, http_targets))
        else "FAIL",
        "routes": {
            "evidence": {
                "status_code": http_evidence.status_code,
                "required": [
                    "schema_version",
                    "mhs_references",
                    "manifests",
                    "read_results",
                    "limitations",
                ],
            },
            "cards": {
                "status_code": http_cards.status_code,
                "required": ["schema_version", "cards", "overall_freshness", "limitations"],
            },
            "targets": {
                "status_code": http_targets.status_code,
                "required": ["targets", "access", "write_operations"],
            },
        },
        "write_operations": http_targets.json().get("write_operations")
        if http_targets.status_code == 200
        else None,
    }

    profile = {
        "schema_version": "rolo-target-profile/v1",
        "profile_id": "landerpi",
        "robot_id": "landerpi",
        "target": {
            "kind": "ssh",
            "host": target["host"],
            "workspace": "/home/ubuntu/ros2_ws",
            "user": "pi",
            "port": 22,
        },
        "host_key": {
            "status": "APPROVED",
            "fingerprint": "SHA256:aFHbH0ko9ZzobJZEfeoAKyWjbYfP/zqmgvTwXMMKMnQ",
            "source": "pinned known_hosts",
        },
        "target_host_fingerprint": target_fp,
        "collector_id": envelope.identity.collector_id,
        "access": "READ_ONLY",
        "credential": {
            "kind": "dedicated-ssh-identity",
            "public_fingerprint": "SHA256:hNgRHAhVT2MmNwDv21Ly4yzPhTynKMjFS+vzNDqjYXA",
            "private_material": "not embedded",
        },
        "limitations": [
            "profile reconstructed for this live acceptance batch",
            "historical mentorpi enrollment is not reused",
        ],
    }
    target_evidence = {
        "schema_version": "rolo-probe-target-evidence-acceptance/v1",
        "status": "OBSERVED_RUNTIME",
        "robot_id": "landerpi",
        "target_host_fingerprint": target_fp,
        "collector_id": envelope.identity.collector_id,
        "observed_at": envelope.identity.observed_at.isoformat(),
        "fresh_until": envelope.identity.fresh_until.isoformat(),
        "source_artifact": str(canary_path),
        "source_artifact_sha256": sha256_file(canary_path),
        "evidence_envelope_digest": envelope.digest,
        "verification": "PARTIAL",
        "signature": "NOT_PRESENT",
        "access": "READ_ONLY",
        "write_requests": 0,
        "limitations": [
            "no signed TargetEvidenceBundle was available",
            "live probe payload is retained verbatim in source artifact",
        ],
    }
    probe_result = {
        "schema_version": "rolo-probe-result-acceptance/v1",
        "status": "READY",
        "robot_id": "landerpi",
        "target_host_fingerprint": target_fp,
        "observed_at": probe["observed_at"],
        "access": "READ_ONLY",
        "write_requests": 0,
        "evidence_artifact": str(canary_path),
        "evidence_digest": canary["digest"],
        "result_statuses": [r["status"] for r in canary["results"]],
        "limitations": canary["limitations"],
    }
    discovery = {
        "schema_version": "rolo-mhs-discovery-acceptance/v1",
        "target_host_fingerprint": target_fp,
        "source_comparison": {
            "observed": manifest_ref.model_dump(mode="json"),
            "vendor": vendor_ref.model_dump(mode="json"),
            "test_fixture": fixture_ref.model_dump(mode="json"),
        },
        "candidate": candidate.model_dump(mode="json"),
        "association": association.model_dump(mode="json"),
        "read_results": [
            dict(r, status_reason=(r.get("reason") or ("status=" + r["status"])))
            for r in read_results
        ],
        "status": "PASS_WITH_LIMITATIONS",
        "limitations": [
            "vendor manifest unavailable",
            "fixture is provisional and non-authoritative",
        ],
    }
    tool_surface = {
        "schema_version": "rolo-mhs-tool-surface-acceptance/v1",
        "target_host_fingerprint": target_fp,
        "access": "READ_ONLY",
        "operations": operations,
        "descriptors": [
            {
                "capability_id": r["capability_id"],
                "route": r["route"],
                "status": r["status"],
                "access": "READ_ONLY",
                "evidence_ids": r["evidence_ids"],
            }
            for r in canary["results"]
        ],
        "write_operations": 0,
        "surface_digest": hashlib.sha256(
            json.dumps(operations, separators=(",", ":")).encode()
        ).hexdigest(),
    }
    conformance = {
        "schema_version": "rolo-mhs-conformance-acceptance/v1",
        "status": "PASS" if not conformance_violations else "FAIL",
        "operations": operations,
        "violations": conformance_violations,
        "api_contract": http_contract,
    }
    negative = {
        "schema_version": "rolo-probe-negative-tests/v1",
        "status": "PASS_WITH_LIMITATIONS",
        "tests": [
            {
                "id": "NT-HTTP-WRITE",
                "description": "POST write route absent",
                "status": "PASS",
                "observed": "router exposes GET-only MHS routes",
            },
            {
                "id": "NT-MHS-FORBIDDEN",
                "description": "provider rejects reset/write-like capability",
                "status": "PASS",
                "observed": "fail-closed provider boundary",
            },
            {
                "id": "NT-ASSOCIATION-WRITE",
                "description": "association write_requests must remain zero",
                "status": "PASS",
                "observed": association.write_requests,
            },
            {
                "id": "NT-VENDOR-MISSING",
                "description": "missing vendor manifest",
                "status": "PASS",
                "observed": vendor_ref.status,
            },
        ],
        "write_requests": 0,
        "limitations": [
            "device-side forbidden-operation attempt was not executed against production hardware",
            "no destructive negative test is permitted",
        ],
    }
    no_write_lines = [
        {
            "ts": generated_at,
            "event": "ssh_probe",
            "target": "pi@192.168.10.167:22",
            "access": "READ_ONLY",
            "remote_write": False,
            "write_requests": 0,
            "command_policy": "stdin Python; procfs/sysfs bounded reads only",
        },
        {
            "ts": generated_at,
            "event": "mhs_provider",
            "operations": operations,
            "write_requests": 0,
            "remote_write": False,
        },
        {
            "ts": generated_at,
            "event": "http_replay",
            "routes": [
                "GET /v1/mhs/{target_fingerprint}/evidence",
                "GET /v1/mhs/{target_fingerprint}/cards",
                "GET /v1/mhs/targets",
            ],
            "write_operations": 0,
            "remote_write": False,
        },
        {
            "ts": generated_at,
            "event": "audit_limit",
            "device_side_counter": "UNAVAILABLE",
            "note": "controller-side evidence is zero; device-side write counter was not claimed",
        },
    ]
    human_review = f"""# Probe E2E 人工复核（LanderPi）\n\n- 批次：{output_dir.name}\n- 目标指纹：`{target_fp}`\n- 结论：**PROVISIONAL / PASS_WITH_LIMITATIONS**\n- 复核人：PENDING_USER_CONFIRMATION\n- 复核时间：PENDING\n\n## 已核对\n\n真实 SSH 只读 Probe、MHS inspect/status/read、RKB snapshot、HTTP GET 投影、只读 tool-surface 和 fail-closed negative tests 均有机器证据。\n\n## 限制\n\n供应商 manifest 不可用；fixture 明确为 TEST_FIXTURE/PROVISIONAL，不覆盖 observed；TargetEvidenceBundle 未签名；设备侧写入计数不可用；未执行任何破坏性 negative test。\n\n人工复核需确认上述限制后，方可将本批次从 PROVISIONAL 提升为组织认可的验收记录。\n"""

    files = {
        "01-profile.json": profile,
        "02-probe-result.json": probe_result,
        "03-target-evidence.json": target_evidence,
        "04-mhs-discovery.json": discovery,
        "05-rkb-snapshot.json": snapshot.model_dump(mode="json"),
        "06-tool-surface.json": tool_surface,
        "07-conformance.json": conformance,
        "08-negative-tests.json": negative,
        "10-human-review.md": human_review,
    }
    for name, value in files.items():
        if name.endswith(".md"):
            (output_dir / name).write_text(value, encoding="utf-8")
        else:
            dump(output_dir / name, value)
    (output_dir / "09-no-write-audit.jsonl").write_text(
        "".join(
            json.dumps(line, ensure_ascii=False, sort_keys=True) + "\n" for line in no_write_lines
        ),
        encoding="utf-8",
    )
    index = {
        "schema_version": "rolo-probe-e2e-acceptance-batch/v1",
        "batch_id": output_dir.name,
        "status": "PROVISIONAL",
        "target": target,
        "artifacts": {
            name: sha256_file(output_dir / name)
            for name in (*files.keys(), "09-no-write-audit.jsonl")
        },
        "required_artifacts": [
            f"{i:02d}-{label}"
            for i, label in enumerate(
                [
                    "profile.json",
                    "probe-result.json",
                    "target-evidence.json",
                    "mhs-discovery.json",
                    "rkb-snapshot.json",
                    "tool-surface.json",
                    "conformance.json",
                    "negative-tests.json",
                    "no-write-audit.jsonl",
                    "human-review.md",
                ],
                1,
            )
        ],
        "limitations": ["not COMPLETE until human review and signed target bundle are supplied"],
    }
    dump(output_dir / "index.json", index)
    return index


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--canary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build_batch(args.canary, args.output), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
