"""Controller-side typed orchestration for one SSH journey session."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping

from rolo.core.artifacts import ArtifactStore
from rolo.targets.executor import SshTargetExecutor

from .protocol import (
    ExecutionBundleManifest,
    ExecutionRequestLike,
    FrameKind,
    JourneySession,
    ProtocolFrame,
    TargetdAuthorityActivationRequest,
    TargetdMappingCancelRequest,
    TargetdVerifiedReleaseProvisionRequest,
)
from .transport import JourneySessionClient, SshStdioChannel


def _artifact_segment(value: str) -> str:
    """Map a protocol identifier to a portable artifact filename segment."""

    safe = re.sub(r"[^A-Za-z0-9._-]", "_", value)
    if safe == value:
        return safe
    # Preserve readability while preventing two distinct keys from silently
    # sharing one Windows filename after punctuation normalization.
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"{safe[:96]}-{digest}"


class TargetdJourneyController:
    """Own one targetd channel from bootstrap through tool calls."""

    def __init__(
        self,
        executor: SshTargetExecutor,
        session: JourneySession,
        *,
        remote_root: str,
        state_root: str,
        signing_key: str,
        signing_key_file: str | None = None,
        execute_calls: bool = True,
        admission_store: str | None = None,
        execution_authority_root: str | None = None,
        release_catalog_root: str | None = None,
        provider: str = "none",
        ros2_snapshot: str | None = None,
        execute_readonly: bool = False,
        process_readonly_worker: bool = False,
        container: str = "MentorPi",
        autonomous_source_confirmed: bool = False,
        artifact_root=None,
    ) -> None:
        if not remote_root.startswith("/") or not state_root.startswith("/"):
            raise ValueError("targetd roots must be absolute")
        if execute_calls and (admission_store is None or execution_authority_root is None):
            raise ValueError("targetd execution requires explicit admission and authority roots")
        if admission_store is not None and not admission_store.startswith("/"):
            raise ValueError("targetd admission store must be absolute")
        if execution_authority_root is not None and not execution_authority_root.startswith("/"):
            raise ValueError("targetd execution authority root must be absolute")
        if release_catalog_root is not None and not release_catalog_root.startswith("/"):
            raise ValueError("targetd Release Catalog root must be absolute")
        if signing_key_file is not None and not signing_key_file.startswith("/"):
            raise ValueError("targetd signing key file must be absolute")
        if ros2_snapshot is not None and not ros2_snapshot.startswith("/"):
            raise ValueError("targetd ROS2 snapshot path must be absolute")
        if execute_readonly and ros2_snapshot is None:
            raise ValueError("targetd read-only execution requires a ROS2 snapshot")
        if provider == "ros2-readonly" and (not execute_calls or not execute_readonly or ros2_snapshot is None):
            raise ValueError("targetd ros2-readonly provider requires execution, read-only mode, and a ROS2 snapshot")
        if process_readonly_worker and provider != "ros2-readonly":
            raise ValueError("targetd process worker requires ros2-readonly provider")
        self.executor = executor
        self.session = session
        self._signing_key = signing_key
        self._release_catalog_configured = release_catalog_root is not None
        self.artifacts = ArtifactStore(artifact_root) if artifact_root is not None else None
        self.last_receipt_ref: str | None = None
        self.remote = [
            "env",
            f"PYTHONPATH={remote_root}",
            "python3",
            "-m",
            "rolo.targetd.daemon",
            "--target-id",
            session.target_id,
            "--state-root",
            state_root,
        ]
        if signing_key_file is not None:
            self.remote.extend(["--signing-key-file", signing_key_file])
        else:
            self.remote.extend(["--signing-key", signing_key])
        if execute_calls:
            self.remote.append("--execute-calls")
            self.remote.extend(["--admission-store", str(admission_store)])
            self.remote.extend(["--execution-authority-root", str(execution_authority_root)])
        if release_catalog_root is not None:
            self.remote.extend(["--release-catalog-root", release_catalog_root])
        if ros2_snapshot is not None:
            self.remote.extend(["--ros2-snapshot", ros2_snapshot])
        if execute_readonly:
            self.remote.append("--execute-readonly")
        if process_readonly_worker:
            self.remote.append("--process-readonly-worker")
        if provider != "none":
            self.remote.extend(["--provider", provider])
        if autonomous_source_confirmed:
            self.remote.append("--autonomous-source-confirmed")
        self.remote.extend(["--container", container])
        self.channel: SshStdioChannel | None = None
        self.client: JourneySessionClient | None = None

    def open(self) -> ProtocolFrame:
        if self.channel is not None:
            raise ValueError("targetd journey is already open")
        self.channel = self.executor.open_targetd_channel(self.remote)
        self.client = JourneySessionClient(self.channel, self.session)
        return self.client.exchange(
            FrameKind.OPEN_JOURNEY,
            {
                "target_id": self.session.target_id,
                "profile_id": self.session.profile_id,
                "resume_token": self.session.resume_token,
                **({"surface_digest": self.session.surface_digest} if self.session.surface_digest is not None else {}),
            },
        )

    def bootstrap(self) -> tuple[ProtocolFrame, ProtocolFrame]:
        client = self._client()
        return (
            client.exchange(FrameKind.BOOTSTRAP, {"session_id": self.session.session_id}),
            client.handoff(),
        )

    def change_phase(self, phase: str) -> ProtocolFrame:
        """Move the journey to a validated Probe/Trace/Certify phase."""
        if phase not in {"PROBE", "TRACE", "CERTIFY"}:
            raise ValueError(f"unsupported journey phase: {phase}")
        return self._client().exchange(FrameKind.PHASE_CHANGE, {"phase": phase})

    def call(
        self,
        manifest: ExecutionBundleManifest,
        source: bytes,
        request: ExecutionRequestLike,
    ) -> ProtocolFrame:
        client = self._client()
        client.put_bundle(manifest, source)
        response = client.call_remote(request)
        if self.artifacts is not None:
            # Keep the immutable bundle and the returned receipt in the same
            # local artifact graph.  The targetd receipt remains authoritative;
            # these refs make the controller-side evidence queryable without
            # requiring a second remote call.
            from rolo.core.signed_artifacts import SignedArtifact, SignedArtifactStore

            bundle_artifact = SignedArtifact.build(
                artifact_id=f"targetd-bundle-{manifest.tool_id}",
                version=manifest.bundle_digest,
                payload={
                    "bundle_digest": manifest.bundle_digest,
                    "binding_digest": manifest.binding_digest,
                    "tool_id": manifest.tool_id,
                    "manifest": manifest.model_dump(mode="json"),
                },
                signer_key_id=manifest.signer_key_id,
                key=self._signing_key.encode("utf-8"),
            )
            signed_store = SignedArtifactStore(self.artifacts.root, {manifest.signer_key_id: self._signing_key.encode("utf-8")})
            bundle_ref = signed_store.publish(bundle_artifact)
            relative = f"targetd/{self.session.target_id}/sessions/{self.session.session_id}/calls/{_artifact_segment(request.idempotency_key)}.json"
            payload = dict(response.payload)
            receipt = dict(payload.get("receipt") or {})
            refs = list(receipt.get("artifact_refs") or [])
            result_ref = f"artifact://{relative}"
            refs.append(result_ref)
            if bundle_ref:
                refs.append(bundle_ref)
            receipt["artifact_refs"] = sorted(set(refs))
            payload["receipt"] = receipt
            self.artifacts.write_json(relative, payload)
            for event in client.last_events:
                self.artifacts.append_jsonl(
                    f"targetd/{self.session.target_id}/sessions/{self.session.session_id}/events.jsonl",
                    {
                        "idempotency_key": request.idempotency_key,
                        **event.payload,
                    },
                )
            self.artifacts.append_jsonl(
                "targetd/index.jsonl",
                {
                    "target_id": self.session.target_id,
                    "session_id": self.session.session_id,
                    "idempotency_key": request.idempotency_key,
                    "artifact_ref": result_ref,
                    "bundle_artifact_ref": bundle_ref,
                    "status": receipt.get("status"),
                },
            )
            self.last_receipt_ref = result_ref
            response = ProtocolFrame.create(
                kind=response.kind,
                sequence=response.sequence,
                session_id=response.session_id,
                run_id=response.run_id,
                payload=payload,
            )
        return response

    def prepare_physical_call(
        self,
        manifest: ExecutionBundleManifest,
        source: bytes,
        request: ExecutionRequestLike,
    ) -> ProtocolFrame:
        """Upload and pre-arm one physical call without releasing motion."""

        client = self._client()
        client.put_bundle(manifest, source)
        return client.prepare_physical_call_remote(request)

    def accept_debug_zero_motion(
        self,
        *,
        call_id: str,
        request_digest: str,
        armed_zero_receipt_digest: str,
        debug_admission: Mapping[str, object] | object,
    ) -> ProtocolFrame:
        """Run and persist one target-owned debug zero-motion rehearsal."""

        return self._client().accept_debug_zero_motion_remote(
            call_id=call_id,
            request_digest=request_digest,
            armed_zero_receipt_digest=armed_zero_receipt_digest,
            debug_admission=debug_admission,
        )

    def start_prepared_physical_call(
        self,
        *,
        call_id: str,
        request_digest: str,
        armed_zero_receipt_digest: str,
        provider_gate: Mapping[str, object] | object,
    ) -> ProtocolFrame:
        """Consume the target gate and release the exact prepared child."""

        return self._client().start_prepared_physical_call_remote(
            call_id=call_id,
            request_digest=request_digest,
            armed_zero_receipt_digest=armed_zero_receipt_digest,
            provider_gate=provider_gate,
        )

    def close(self) -> None:
        if self.client is not None:
            self.client.exchange(FrameKind.CLOSE_SESSION, {"session_id": self.session.session_id})
        if self.channel is not None:
            self.channel.close()
        self.client = None
        self.channel = None

    def disconnect(self) -> None:
        """Drop only the physical SSH channel and keep the logical session lease."""
        if self.channel is not None:
            self.channel.close()
        self.client = None
        self.channel = None

    def resume(self, resume_token: str) -> ProtocolFrame:
        """Reconnect the SSH channel and resume the existing targetd session."""
        if self.channel is not None:
            raise ValueError("targetd journey must be disconnected before resume")
        self.channel = self.executor.open_targetd_channel(self.remote)
        self.client = JourneySessionClient(self.channel, self.session)
        return self.client.resume(resume_token)

    def query_call(self, idempotency_key: str) -> ProtocolFrame:
        """Query a pending call after reconnect without replaying it."""
        response = self._client().query_call(idempotency_key)
        if self.artifacts is not None:
            relative = f"targetd/{self.session.target_id}/sessions/{self.session.session_id}/calls/{_artifact_segment(idempotency_key)}-query.json"
            self.artifacts.write_json(relative, response.payload)
        return response

    def query_physical_provider_gate(
        self,
        idempotency_key: str,
        request_digest: str,
        *,
        gate_uri: str | None = None,
        gate_digest_uri: str | None = None,
    ) -> ProtocolFrame:
        """Authenticate and read back an immutable physical gate sidecar."""

        response = self._client().query_physical_gate_remote(
            idempotency_key,
            request_digest,
            gate_uri=gate_uri,
            gate_digest_uri=gate_digest_uri,
        )
        if self.artifacts is not None:
            relative = f"targetd/{self.session.target_id}/sessions/{self.session.session_id}/calls/{_artifact_segment(idempotency_key)}-physical-gate-query.json"
            self.artifacts.write_json(relative, response.payload)
        return response

    def interrupt_process_call(
        self,
        idempotency_key: str,
        request_digest: str,
        *,
        intent: str,
    ) -> ProtocolFrame:
        """Send an authenticated exact-call CANCEL/STOP to the worker."""

        return self._client().interrupt_process_remote(
            idempotency_key,
            request_digest,
            intent=intent,
        )

    def activate_authority(
        self,
        request: TargetdAuthorityActivationRequest,
    ) -> ProtocolFrame:
        """Activate a target-resident verified Release on this same channel."""

        if not self._release_catalog_configured:
            raise ValueError("targetd authority activation requires a Release Catalog")
        return self._client().activate_authority(request)

    def provision_verified_release(
        self,
        request: TargetdVerifiedReleaseProvisionRequest,
    ) -> ProtocolFrame:
        """CAS a cache-verified Release on this same targetd channel."""

        if not self._release_catalog_configured:
            raise ValueError("targetd Release provision requires a Catalog")
        return self._client().provision_verified_release(request)

    def cancel_mapping(
        self,
        request: TargetdMappingCancelRequest,
    ) -> ProtocolFrame:
        """Append a target-authored Mapping cancellation on this channel."""

        return self._client().cancel_mapping(request)

    def _client(self) -> JourneySessionClient:
        if self.client is None:
            raise ValueError("targetd journey is not open")
        return self.client
