"""Build one Agent-native session from an enrolled target profile."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from rolo.agent_tools.native_tools import (
    AgentNativeRunner,
    AgentNativeToolDescriptor,
    RemoteAgentNativeRunner,
    reduced_agent_native_catalog,
)
from rolo.agent_tools.session import (
    NativeToolSession,
    NativeToolSessionBudget,
    NativeToolSessionDescriptor,
    native_catalog_sha256,
)
from rolo.core.artifacts import ArtifactStore
from rolo.targets.executor import SshTargetExecutor, create_profile_target_executor


def create_profile_native_tool_session(
    profile_id: str,
    *,
    config_root: Path,
    artifact_root: Path,
    timeout_s: float = 15.0,
    ttl_s: int = 900,
    max_calls: int = 32,
    max_elapsed_s: float = 900.0,
    max_result_bytes: int = 4_000_000,
    session_id: str | None = None,
    runner: object | None = None,
    session_nonce: str | None = None,
    native_executor: object | None = None,
    target_host_fingerprint: str | None = None,
) -> NativeToolSession:
    """Create the smallest trusted Tool Surface for one enrolled profile.

    Profile loading, host-key/identity pin checks and SSH connector selection are
    delegated to the target layer.  The returned session is still the authority
    for allowlist, expiry, budget, plan digest and per-call evidence.
    """
    if ttl_s < 1 or ttl_s > 86_400:
        raise ValueError("native tool session TTL must be between 1 second and 24 hours")
    catalog = reduced_agent_native_catalog()
    target_executor = create_profile_target_executor(
        profile_id,
        config_root=config_root,
        timeout_s=timeout_s,
        runner=runner if _is_command_runner(runner) else None,
    )
    if isinstance(target_executor, SshTargetExecutor):
        native_runner = RemoteAgentNativeRunner(
            catalog,
            executor=lambda argv, *, timeout_s, environment: target_executor.run_readonly(
                argv,
                environment=environment,
            ),
        )
    else:
        native_runner = AgentNativeRunner(
            catalog,
            executor=native_executor if callable(native_executor) else None,
        )
    now = datetime.now(timezone.utc).replace(microsecond=0)
    descriptor = NativeToolSessionDescriptor(
        session_id=session_id or f"native-{uuid4().hex}",
        nonce=session_nonce or uuid4().hex,
        robot_id=profile_id,
        target_host_fingerprint=target_host_fingerprint,
        stage="probe",
        native_catalog_sha256=_catalog_digest(catalog),
        allowed_tools=[item.tool_id for item in catalog],
        policy_version="rolo-v2-probe-readonly-v1",
        budget=NativeToolSessionBudget(
            max_calls=max_calls,
            max_elapsed_s=max_elapsed_s,
            max_result_bytes=max_result_bytes,
        ),
        created_at=now,
        expires_at=now + timedelta(seconds=ttl_s),
    )
    return NativeToolSession(
        descriptor=descriptor,
        runner=native_runner,
        artifacts=ArtifactStore(artifact_root),
    )


def _catalog_digest(catalog: list[AgentNativeToolDescriptor]) -> str:
    return native_catalog_sha256(catalog)


def _is_command_runner(value: object | None) -> bool:
    """Accept test doubles without making the factory depend on executor internals."""
    return value is not None and callable(getattr(value, "run", None))


__all__ = ["create_profile_native_tool_session"]
