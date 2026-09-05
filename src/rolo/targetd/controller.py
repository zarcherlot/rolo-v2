"""Controller-side typed orchestration for one SSH journey session."""

from __future__ import annotations

from rolo.core.artifacts import ArtifactStore
from rolo.targets.executor import SshTargetExecutor

from .protocol import ExecutionBundleManifest, ExecutionRequest, FrameKind, JourneySession, ProtocolFrame
from .transport import JourneySessionClient, SshStdioChannel


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
        execute_calls: bool = True,
        provider: str = "none",
        container: str = "MentorPi",
        artifact_root=None,
    ) -> None:
        if not remote_root.startswith("/") or not state_root.startswith("/"):
            raise ValueError("targetd roots must be absolute")
        self.executor = executor
        self.session = session
        self._signing_key = signing_key
        self.artifacts = ArtifactStore(artifact_root) if artifact_root is not None else None
        self.last_receipt_ref: str | None = None
        self.remote = [
            "env", f"PYTHONPATH={remote_root}", "python3", "-m", "rolo.targetd.daemon",
            "--target-id", session.target_id, "--state-root", state_root,
            "--signing-key", signing_key,
        ]
        if execute_calls:
            self.remote.append("--execute-calls")
        if provider != "none":
            self.remote.extend(["--provider", provider])
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

    def call(self, manifest: ExecutionBundleManifest, source: bytes, request: ExecutionRequest) -> ProtocolFrame:
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
            signed_store = SignedArtifactStore(
                self.artifacts.root, {manifest.signer_key_id: self._signing_key.encode("utf-8")}
            )
            bundle_ref = signed_store.publish(bundle_artifact)
            relative = (
                f"targetd/{self.session.target_id}/sessions/{self.session.session_id}/"
                f"calls/{request.idempotency_key}.json"
            )
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
            relative = (
                f"targetd/{self.session.target_id}/sessions/{self.session.session_id}/"
                f"calls/{idempotency_key}-query.json"
            )
            self.artifacts.write_json(relative, response.payload)
        return response

    def _client(self) -> JourneySessionClient:
        if self.client is None:
            raise ValueError("targetd journey is not open")
        return self.client
