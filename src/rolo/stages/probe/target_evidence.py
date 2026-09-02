"""Target-bound evidence collection for local and remote deployments.

The remote collector is deliberately a narrow stdin/stdout protocol.  SSH owns
transport authentication and host-key pinning; the bundle adds target identity,
freshness and an integrity signature that remains verifiable after transport.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import signal
import stat
import subprocess
import tempfile
import time

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib  # type: ignore[no-redef]
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from rolo.core.hashing import sha256_file
from rolo.core.models import DiscoveryStatus, ProbeResult
from rolo.stages.probe.active_discovery import (
    HelpProbeResult,
    HelpProbeStatus,
    _extract_help_summary,
    run_bounded_help,
)
from rolo.stages.probe.application_cli_mapping import ApplicationCliRouteProvider
from rolo.stages.probe.discovery import HardwareProbe, LinuxProbe, RosProbe
from rolo.stages.probe.ros_environment import (
    RosSetupFileRecord,
    resolve_pinned_ros_environment,
    verify_pinned_setup_files,
)
from rolo.stages.probe.routes import persist_route_evidence, probe_routes
from rolo.targets.executor import quote_remote_argv

MAX_BUNDLE_BYTES = 8_000_000
MAX_CLOCK_SKEW = timedelta(minutes=2)
MAX_REQUEST_LIFETIME = timedelta(minutes=5)
# Keep target-side help inspection bounded, but large enough to cover a real
# application workspace. Active discovery applies its own process budget.
MAX_HELP_EXECUTABLES = 20
MAX_HELP_EXECUTABLE_BYTES = 250_000_000
MAX_HELP_DISCOVERY_CANDIDATES = 64
MAX_SSH_STDERR_BYTES = 1_000_000
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SSH_TARGET_PATTERN = re.compile(r"^(?:[A-Za-z0-9_.-]+@)?[A-Za-z0-9_.-]+$")
_REMOTE_PATH_PATTERN = re.compile(r"^[/A-Za-z0-9_.-]+$")
_SOURCE_ROOT_PATTERN = re.compile(r"^(?:[/A-Za-z0-9_.-]+|[A-Za-z]:[/A-Za-z0-9_.-]+)$")
_SSH_PUBLIC_KEY_TYPE_PATTERN = re.compile(
    r"^(?:ssh-(?:ed25519|rsa)|ecdsa-sha2-nistp(?:256|384|521)|"
    r"sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$"
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def restricted_collector_authorized_key(
    public_key: str,
    *,
    collector_executable: str,
    collector_config: str,
) -> str:
    """Build one injection-safe authorized_keys entry restricted to the Collector protocol."""
    if not _REMOTE_PATH_PATTERN.fullmatch(collector_executable):
        raise ValueError("collector_executable contains unsupported characters")
    if not _REMOTE_PATH_PATTERN.fullmatch(collector_config):
        raise ValueError("collector_config contains unsupported characters")
    parts = public_key.strip().split()
    if len(parts) < 2 or not _SSH_PUBLIC_KEY_TYPE_PATTERN.fullmatch(parts[0]):
        raise ValueError("unsupported or invalid SSH public key")
    try:
        decoded = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("SSH public key payload is invalid") from exc
    if len(decoded) < 32:
        raise ValueError("SSH public key payload is invalid")
    forced_command = (
        f"{collector_executable} target-evidence collector-run --config {collector_config}"
    )
    restrictions = (
        "restrict,no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding"
    )
    return f'{restrictions},command="{forced_command}" {parts[0]} {parts[1]}'


class EvidenceDeploymentMode(str, Enum):
    LOCAL = "local"
    REMOTE = "remote"


class SSHTransportError(ValueError):
    """Stable, redacted failure classification for the SSH evidence transport."""

    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        self.code = code
        self.retryable = retryable
        super().__init__(f"{code}: {message}")


class CollectorHelpExecutable(BaseModel):
    model_config = ConfigDict(extra="forbid")

    executable_id: str = Field(pattern=r"^target-exe-[0-9a-f]{24}$")
    path: str = Field(min_length=1, max_length=4096)
    sha256: str = Field(pattern=_SHA256_PATTERN)


class CollectorDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[
        "robot-target-evidence-collector/v1",
        "robot-target-evidence-collector/v2",
        "robot-target-evidence-collector/v3",
    ] = "robot-target-evidence-collector/v3"
    robot_id: str = Field(min_length=1, max_length=128)
    collector_id: str = Field(min_length=1, max_length=128)
    target_host_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    # Target-side workspace used by the collector for ROS overlay/source
    # context.  This is descriptive evidence, not a controller-local path.
    source_root: str | None = Field(default=None, max_length=4096)
    help_executables: list[CollectorHelpExecutable] = Field(
        default_factory=list,
        max_length=MAX_HELP_EXECUTABLES,
    )
    ros_setup_files: list[RosSetupFileRecord] = Field(default_factory=list, max_length=8)
    created_at: datetime = Field(default_factory=_utc_now)

    @model_validator(mode="after")
    def require_canonical_help_allowlist(self) -> CollectorDescriptor:
        if self.source_root is not None and not _SOURCE_ROOT_PATTERN.fullmatch(self.source_root):
            raise ValueError("collector source_root contains unsupported characters")
        identities = [item.executable_id for item in self.help_executables]
        paths = [item.path for item in self.help_executables]
        if identities != sorted(set(identities)) or len(paths) != len(set(paths)):
            raise ValueError("collector help executable allowlist must be unique and sorted")
        setup_paths = [item.path for item in self.ros_setup_files]
        if len(setup_paths) != len(setup_paths):
            raise ValueError("collector ROS setup file pins must be unique")
        return self


class CollectorState(CollectorDescriptor):
    secret_path: str = Field(min_length=1, max_length=4096)


class EvidenceDeploymentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[
        "robot-target-evidence-deployment/v1",
        "robot-target-evidence-deployment/v2",
        "robot-target-evidence-deployment/v3",
    ] = "robot-target-evidence-deployment/v3"
    robot_id: str = Field(min_length=1, max_length=128)
    mode: EvidenceDeploymentMode
    collector: CollectorDescriptor
    verification_secret_path: str = Field(min_length=1, max_length=4096)
    verification_secret_sha256: str = Field(pattern=_SHA256_PATTERN)
    local_collector_state_path: str | None = None
    collector_config: str = ".rolo/config/target-evidence-collector.json"
    collector_executable: str = "robotctl"
    ssh_target: str | None = None
    known_hosts_path: str | None = None
    known_hosts_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    ssh_identity_file: str | None = None
    ssh_identity_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    transition_id: str | None = Field(default=None, pattern=r"^transition-[0-9a-f]{32}$")
    configured_at: datetime = Field(default_factory=_utc_now)

    @model_validator(mode="after")
    def require_mode_specific_transport(self) -> EvidenceDeploymentConfig:
        if self.collector.robot_id != self.robot_id:
            raise ValueError("collector descriptor robot identity mismatch")
        if self.mode == EvidenceDeploymentMode.REMOTE:
            if not self.ssh_target or not self.known_hosts_path:
                raise ValueError("remote mode requires ssh_target and known_hosts_path")
            if self.schema_version == "robot-target-evidence-deployment/v3":
                if not self.known_hosts_sha256 or self.ssh_port is None:
                    raise ValueError("remote mode requires pinned known_hosts content and SSH port")
            if not _SSH_TARGET_PATTERN.fullmatch(self.ssh_target):
                raise ValueError("ssh_target contains unsupported characters")
            if not _REMOTE_PATH_PATTERN.fullmatch(self.collector_config):
                raise ValueError("collector_config contains unsupported characters")
            if not _REMOTE_PATH_PATTERN.fullmatch(self.collector_executable):
                raise ValueError("collector_executable contains unsupported characters")
            if bool(self.ssh_identity_file) != bool(self.ssh_identity_sha256):
                raise ValueError("SSH identity path and digest must be configured together")
        elif (
            self.ssh_target
            or self.known_hosts_path
            or self.known_hosts_sha256
            or self.ssh_port is not None
            or self.ssh_identity_file
            or self.ssh_identity_sha256
            or self.collector_executable != "robotctl"
        ):
            raise ValueError("local mode cannot configure a remote transport")
        if self.mode == EvidenceDeploymentMode.LOCAL and not self.local_collector_state_path:
            raise ValueError("local mode requires local_collector_state_path")
        if self.mode == EvidenceDeploymentMode.REMOTE and self.local_collector_state_path:
            raise ValueError("remote mode cannot configure local collector state")
        return self


class EvidenceDeploymentTransition(BaseModel):
    """Auditable authorization for one explicit collector re-enrollment."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[
        "robot-target-evidence-transition/v1", "robot-target-evidence-transition/v2"
    ] = "robot-target-evidence-transition/v2"
    transition_id: str = Field(pattern=r"^transition-[0-9a-f]{32}$")
    robot_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=8, max_length=500)
    previous_collector_id: str
    new_collector_id: str
    previous_target_host_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    new_target_host_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    previous_verification_secret_sha256: str = Field(pattern=_SHA256_PATTERN)
    new_verification_secret_sha256: str = Field(pattern=_SHA256_PATTERN)
    previous_mode: EvidenceDeploymentMode
    new_mode: EvidenceDeploymentMode
    previous_collector_executable: str
    new_collector_executable: str
    previous_collector_config: str | None = None
    new_collector_config: str | None = None
    previous_ssh_target: str | None = None
    new_ssh_target: str | None = None
    previous_ssh_port: int | None = None
    new_ssh_port: int | None = None
    previous_known_hosts_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    new_known_hosts_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    previous_ssh_identity_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    new_ssh_identity_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    authorized_at: datetime = Field(default_factory=_utc_now)


class TargetEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[
        "robot-target-evidence-request/v1", "robot-target-evidence-request/v2"
    ] = "robot-target-evidence-request/v2"
    robot_id: str = Field(min_length=1, max_length=128)
    mode: Literal["READ_ONLY"] = "READ_ONLY"
    nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    requested_layers: list[Literal["hw", "linux", "ros"]] = Field(
        default_factory=lambda: ["hw", "linux", "ros"], min_length=1, max_length=3
    )
    requested_executable_help_ids: list[str] = Field(
        default_factory=list,
        max_length=MAX_HELP_EXECUTABLES,
    )
    issued_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def validate_window_and_layers(self) -> TargetEvidenceRequest:
        if len(set(self.requested_layers)) != len(self.requested_layers):
            raise ValueError("requested_layers must be unique")
        if self.requested_executable_help_ids != sorted(set(self.requested_executable_help_ids)):
            raise ValueError("requested executable help IDs must be unique and sorted")
        if any(
            re.fullmatch(r"target-exe-[0-9a-f]{24}", executable_id) is None
            for executable_id in self.requested_executable_help_ids
        ):
            raise ValueError("requested executable help ID is invalid")
        if self.expires_at <= self.issued_at:
            raise ValueError("request expiry must follow issuance")
        if self.expires_at - self.issued_at > MAX_REQUEST_LIFETIME:
            raise ValueError("request lifetime exceeds five minutes")
        return self


class TargetExecutableHelpEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    executable_id: str = Field(pattern=r"^target-exe-[0-9a-f]{24}$")
    path: str = Field(min_length=1, max_length=4096)
    executable_sha256: str = Field(pattern=_SHA256_PATTERN)
    help_probe: HelpProbeResult
    output_text: str = Field(max_length=250_000)
    output_sha256: str = Field(pattern=_SHA256_PATTERN)
    usage: list[str] = Field(default_factory=list, max_length=20)
    parameters: list[str] = Field(default_factory=list, max_length=500)
    subcommands: list[str] = Field(default_factory=list, max_length=200)


class TargetEvidenceBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[
        "robot-target-evidence-bundle/v2", "robot-target-evidence-bundle/v3"
    ] = "robot-target-evidence-bundle/v2"
    robot_id: str
    collector_id: str
    target_host_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    request_nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    requested_layers: list[Literal["hw", "linux", "ros"]] = Field(min_length=1, max_length=3)
    access: Literal["READ_ONLY"] = "READ_ONLY"
    collected_at: datetime
    probes: dict[str, ProbeResult]
    executable_help: list[TargetExecutableHelpEvidence] = Field(
        default_factory=list,
        max_length=MAX_HELP_EXECUTABLES,
    )
    # Optional signed source snapshot emitted by newer target collectors.  It
    # is intentionally opaque to the Probe controller: the collector's
    # signature and bundle size limits provide integrity and resource bounds,
    # while later products may add a dedicated source-evidence schema.
    source_snapshot: dict[str, Any] | None = None
    payload_sha256: str = Field(pattern=_SHA256_PATTERN)
    signature_hmac_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def require_canonical_executable_help(self) -> TargetEvidenceBundle:
        identities = [item.executable_id for item in self.executable_help]
        if identities != sorted(set(identities)):
            raise ValueError("bundle executable help IDs must be unique and sorted")
        return self


def target_host_fingerprint() -> str:
    """Return a non-reversible stable identity for the host running the collector."""
    stable_id = ""
    for candidate in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
        try:
            stable_id = candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if stable_id:
            break
    if not stable_id and os.name == "nt":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"
            ) as key:
                stable_id = str(winreg.QueryValueEx(key, "MachineGuid")[0]).strip()
        except OSError:
            stable_id = ""
    if not stable_id:
        raise ValueError("stable target machine identity is unavailable")
    payload = {
        "machine_id": stable_id,
        "node": platform.node(),
        "machine": platform.machine(),
        "system": platform.system(),
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _write_private_secret(path: Path, secret: bytes) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise ValueError(f"collector secret already exists: {path}")
    path.write_bytes(secret)
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:
        path.unlink(missing_ok=True)
        raise ValueError(f"cannot restrict collector secret permissions: {exc}") from exc


def _load_secret(path: Path) -> bytes:
    path = path.expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"collector secret is unavailable: {path}")
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError("collector secret permissions must not allow group or other access")
    secret = path.read_bytes()
    if len(secret) != 32:
        raise ValueError("collector secret must contain exactly 32 bytes")
    return secret


def initialize_collector(
    *,
    robot_id: str,
    state_path: Path,
    secret_path: Path,
    help_executables: Sequence[Path] = (),
    ros_setup_files: Sequence[RosSetupFileRecord] = (),
) -> CollectorDescriptor:
    fingerprint = target_host_fingerprint()
    state_path = state_path.expanduser().resolve()
    if state_path.exists():
        raise ValueError(f"collector state already exists: {state_path}")
    allowlist = _build_help_allowlist(help_executables)
    verify_pinned_setup_files(ros_setup_files)
    _write_private_secret(secret_path, secrets.token_bytes(32))
    descriptor = CollectorDescriptor(
        robot_id=robot_id,
        collector_id=f"collector-{uuid4().hex}",
        target_host_fingerprint=fingerprint,
        help_executables=allowlist,
        ros_setup_files=list(ros_setup_files),
    )
    state = CollectorState(
        **descriptor.model_dump(),
        secret_path=str(secret_path.expanduser().resolve()),
    )
    try:
        _atomic_write_text(state_path, state.model_dump_json(indent=2) + "\n")
    except OSError:
        secret_path.expanduser().resolve().unlink(missing_ok=True)
        raise
    return descriptor


def discover_help_executables(project_root: Path) -> list[Path]:
    """Discover installed application entrypoints without executing them.

    Enrollment inspects only project metadata and conventional virtualenv or
    install ``bin`` directories. Paths are still pinned and hashed by
    :func:`initialize_collector` before any later bounded ``--help`` probe.
    """

    root = project_root.expanduser().resolve()
    if not root.is_dir():
        return []
    declared: set[str] = set()
    pyproject = root / "pyproject.toml"
    try:
        with pyproject.open("rb") as handle:
            document = tomllib.load(handle)
        scripts = document.get("project", {}).get("scripts", {})
        if isinstance(scripts, Mapping):
            declared.update(str(name) for name in scripts if str(name).strip())
    except (OSError, tomllib.TOMLDecodeError, AttributeError):
        pass

    bin_roots: list[Path] = []
    for relative in (
        ".venv/bin",
        ".venv/Scripts",
        "venv/bin",
        "venv/Scripts",
        "bin",
        "install",
        "build",
    ):
        candidate = root / relative
        if candidate.is_dir():
            bin_roots.append(candidate)
    for parent in (root / "install", root / "build"):
        if parent.is_dir():
            try:
                bin_roots.extend(
                    child / "bin"
                    for child in sorted(parent.iterdir(), key=lambda item: item.name.casefold())
                    if child.is_dir() and (child / "bin").is_dir()
                )
            except OSError:
                continue

    semantic_tokens = (
        "robot",
        "camera",
        "cam",
        "sensor",
        "lidar",
        "imu",
        "teleop",
        "control",
        "arm",
        "motor",
        "actuator",
        "gripper",
    )
    candidates: dict[str, Path] = {}
    for directory in bin_roots:
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name.casefold())
        except OSError:
            continue
        for path in entries:
            if not path.is_file() or path.is_symlink():
                continue
            name = path.name
            stem = path.stem
            normalized_name = re.sub(r"[^a-z0-9]+", "_", name.casefold())
            name_tokens = {token for token in normalized_name.split("_") if token}
            semantic_match = bool(name_tokens.intersection(semantic_tokens))
            if name in declared or stem in declared or semantic_match:
                candidates[str(path)] = path
                if len(candidates) >= MAX_HELP_DISCOVERY_CANDIDATES:
                    break
        if len(candidates) >= MAX_HELP_DISCOVERY_CANDIDATES:
            break
    return sorted(candidates.values(), key=lambda item: str(item).casefold())[:MAX_HELP_EXECUTABLES]


def _build_help_allowlist(paths: Sequence[Path]) -> list[CollectorHelpExecutable]:
    if len(paths) > MAX_HELP_EXECUTABLES:
        raise ValueError(f"collector allows at most {MAX_HELP_EXECUTABLES} help executables")
    allowed: list[CollectorHelpExecutable] = []
    seen: set[Path] = set()
    for requested in paths:
        path = requested.expanduser().resolve()
        if path in seen:
            raise ValueError("collector help executable paths must be unique")
        seen.add(path)
        if not path.is_file():
            raise ValueError(f"collector help executable is not a regular file: {path}")
        if path.stat().st_size > MAX_HELP_EXECUTABLE_BYTES:
            raise ValueError(f"collector help executable exceeds size limit: {path}")
        digest = sha256_file(path)
        identity_digest = hashlib.sha256(
            _canonical_json({"path": str(path), "sha256": digest})
        ).hexdigest()
        allowed.append(
            CollectorHelpExecutable(
                executable_id=f"target-exe-{identity_digest[:24]}",
                path=str(path),
                sha256=digest,
            )
        )
    return sorted(allowed, key=lambda item: item.executable_id)


def stage_collector_rotation(
    *,
    previous_state_path: Path,
    expected_collector_id: str,
    new_state_path: Path,
    new_secret_path: Path,
    help_executables: Sequence[Path] = (),
    ros_setup_files: Sequence[RosSetupFileRecord] = (),
) -> CollectorDescriptor:
    """Stage parallel collector credentials while preserving the active collector."""
    previous = load_collector_state(previous_state_path)
    if previous.collector_id != expected_collector_id:
        raise ValueError("active collector identity differs from the expected rotation pin")
    descriptor = initialize_collector(
        robot_id=previous.robot_id,
        state_path=new_state_path,
        secret_path=new_secret_path,
        help_executables=help_executables,
        ros_setup_files=ros_setup_files,
    )
    if descriptor.target_host_fingerprint != previous.target_host_fingerprint:
        raise ValueError("staged collector rotation changed target host identity")
    return descriptor


def load_collector_state(path: Path) -> CollectorState:
    try:
        state = CollectorState.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"invalid collector state: {exc}") from exc
    if target_host_fingerprint() != state.target_host_fingerprint:
        raise ValueError("collector state belongs to a different target host")
    _load_secret(Path(state.secret_path))
    verify_pinned_setup_files(state.ros_setup_files)
    return state


def configure_deployment(
    *,
    robot_id: str,
    mode: EvidenceDeploymentMode,
    descriptor: CollectorDescriptor,
    verification_secret_path: Path,
    output_path: Path,
    ssh_target: str | None = None,
    known_hosts_path: Path | None = None,
    ssh_port: int | None = None,
    ssh_identity_file: Path | None = None,
    collector_config: str = ".rolo/config/target-evidence-collector.json",
    collector_executable: str = "robotctl",
    local_collector_state_path: Path | None = None,
) -> EvidenceDeploymentConfig:
    config = _build_deployment_config(
        robot_id=robot_id,
        mode=mode,
        descriptor=descriptor,
        verification_secret_path=verification_secret_path,
        ssh_target=ssh_target,
        known_hosts_path=known_hosts_path,
        ssh_port=ssh_port,
        ssh_identity_file=ssh_identity_file,
        collector_config=collector_config,
        collector_executable=collector_executable,
        local_collector_state_path=local_collector_state_path,
    )
    if output_path.exists():
        existing = load_deployment(output_path)
        stable_fields = {
            "robot_id",
            "mode",
            "collector",
            "verification_secret_path",
            "verification_secret_sha256",
            "local_collector_state_path",
            "collector_config",
            "collector_executable",
            "ssh_target",
            "known_hosts_path",
            "known_hosts_sha256",
            "ssh_port",
            "ssh_identity_file",
            "ssh_identity_sha256",
        }
        existing_stable = existing.model_dump(mode="json", include=stable_fields)
        proposed_stable = config.model_dump(mode="json", include=stable_fields)
        if existing_stable != proposed_stable:
            raise ValueError(
                "target evidence deployment is already pinned; collector identity or transport "
                "changes require an explicit re-enroll/rotate workflow"
            )
        return existing
    _atomic_write_text(output_path, config.model_dump_json(indent=2) + "\n")
    return config


def ensure_local_deployment(
    *,
    robot_id: str,
    config_root: Path,
    project_root: Path | None = None,
    help_executables: Sequence[Path] = (),
    ros_setup_files: Sequence[RosSetupFileRecord] = (),
) -> tuple[EvidenceDeploymentConfig, Path]:
    """Idempotently establish the target-local collector used by product journeys."""
    if not help_executables and project_root is not None:
        help_executables = discover_help_executables(project_root)
    deployment_root = config_root.expanduser().resolve() / "target-evidence"
    deployment_path = deployment_root / f"{robot_id}.json"
    default_state_path = deployment_root / f"{robot_id}-collector.json"
    default_secret_path = deployment_root / f"{robot_id}-collector.key"
    if deployment_path.exists():
        deployment = load_deployment(deployment_path)
        if deployment.mode != EvidenceDeploymentMode.LOCAL:
            raise ValueError("existing target evidence deployment is not local")
        state_path = Path(deployment.local_collector_state_path or "")
        state = load_collector_state(state_path)
        descriptor = CollectorDescriptor.model_validate(state.model_dump(exclude={"secret_path"}))
        if help_executables:
            requested_allowlist = _build_help_allowlist(help_executables)
            if requested_allowlist != descriptor.help_executables:
                raise ValueError(
                    "local executable help allowlist changed; use collector rotation and "
                    "explicit re-enrollment"
                )
        if list(ros_setup_files) != descriptor.ros_setup_files:
            raise ValueError(
                "local ROS setup file pins changed; use collector rotation and explicit "
                "re-enrollment"
            )
        configured = configure_deployment(
            robot_id=robot_id,
            mode=EvidenceDeploymentMode.LOCAL,
            descriptor=descriptor,
            verification_secret_path=Path(deployment.verification_secret_path),
            output_path=deployment_path,
            local_collector_state_path=state_path,
        )
        return configured, state_path
    if default_state_path.exists() or default_secret_path.exists():
        raise ValueError(
            "local target evidence enrollment is incomplete; explicit recovery is required"
        )
    descriptor = initialize_collector(
        robot_id=robot_id,
        state_path=default_state_path,
        secret_path=default_secret_path,
        help_executables=help_executables,
        ros_setup_files=ros_setup_files,
    )
    deployment = configure_deployment(
        robot_id=robot_id,
        mode=EvidenceDeploymentMode.LOCAL,
        descriptor=descriptor,
        verification_secret_path=default_secret_path,
        output_path=deployment_path,
        local_collector_state_path=default_state_path,
    )
    return deployment, default_state_path


def refresh_local_deployment(
    *,
    robot_id: str,
    config_root: Path,
    project_root: Path,
    expected_collector_id: str,
    help_executables: Sequence[Path] = (),
    ros_setup_files: Sequence[RosSetupFileRecord] = (),
    reason: str = "refresh target executable help allowlist",
) -> tuple[EvidenceDeploymentConfig, EvidenceDeploymentTransition, Path, Path]:
    """Expand a local collector's pinned help allowlist through explicit rotation.

    Existing deployments remain immutable during normal Probe starts. This
    helper stages a new collector and secret, re-enrolls the deployment only
    after the expected collector pin matches, and preserves an immutable
    transition record.
    """

    deployment_root = config_root.expanduser().resolve() / "target-evidence"
    deployment_path = deployment_root / f"{robot_id}.json"
    if not deployment_path.is_file():
        raise ValueError("target evidence deployment must exist before collector refresh")
    previous = load_deployment(deployment_path)
    if previous.mode != EvidenceDeploymentMode.LOCAL:
        raise ValueError("collector refresh requires a local target evidence deployment")
    if previous.collector.collector_id != expected_collector_id:
        raise ValueError("pinned collector identity differs from the expected refresh pin")
    discovered_help = (
        list(help_executables) if help_executables else discover_help_executables(project_root)
    )
    if not discovered_help:
        raise ValueError(
            "collector refresh discovered no safe project entrypoints; "
            "provide --allow-executable explicitly"
        )

    # Refresh is additive: operator input may add entries, but cannot silently
    # drop an already pinned executable from the replacement collector.
    pinned_paths = [Path(item.path) for item in previous.collector.help_executables]
    merged_help: list[Path] = []
    seen_help: set[Path] = set()
    for requested in [*pinned_paths, *discovered_help]:
        resolved = requested.expanduser().resolve()
        if resolved not in seen_help:
            seen_help.add(resolved)
            merged_help.append(resolved)
    if not ros_setup_files:
        ros_setup_files = list(previous.collector.ros_setup_files)

    refresh_id = uuid4().hex
    new_state_path = deployment_root / f"{robot_id}-collector-refresh-{refresh_id}.json"
    new_secret_path = deployment_root / f"{robot_id}-collector-refresh-{refresh_id}.key"
    try:
        descriptor = initialize_collector(
            robot_id=robot_id,
            state_path=new_state_path,
            secret_path=new_secret_path,
            help_executables=merged_help,
            ros_setup_files=ros_setup_files,
        )
        deployment, transition, transition_path = reenroll_deployment(
            output_path=deployment_path,
            expected_collector_id=expected_collector_id,
            reason=reason,
            descriptor=descriptor,
            verification_secret_path=new_secret_path,
            mode=EvidenceDeploymentMode.LOCAL,
            collector_config=previous.collector_config,
            local_collector_state_path=new_state_path,
        )
    except Exception:
        # These exact staged files are not active if re-enrollment fails; leave
        # the previous pinned deployment untouched.
        new_state_path.unlink(missing_ok=True)
        new_secret_path.unlink(missing_ok=True)
        raise
    return deployment, transition, transition_path, new_state_path


def _build_deployment_config(
    *,
    robot_id: str,
    mode: EvidenceDeploymentMode,
    descriptor: CollectorDescriptor,
    verification_secret_path: Path,
    ssh_target: str | None,
    known_hosts_path: Path | None,
    ssh_port: int | None,
    ssh_identity_file: Path | None,
    collector_config: str,
    collector_executable: str,
    local_collector_state_path: Path | None,
    transition_id: str | None = None,
) -> EvidenceDeploymentConfig:
    verification_secret_path = verification_secret_path.expanduser().resolve()
    verification_secret_sha256 = hashlib.sha256(_load_secret(verification_secret_path)).hexdigest()
    resolved_local_state = (
        local_collector_state_path.expanduser().resolve()
        if local_collector_state_path is not None
        else None
    )
    if mode == EvidenceDeploymentMode.LOCAL and resolved_local_state is not None:
        local_state = load_collector_state(resolved_local_state)
        if (
            local_state.robot_id != descriptor.robot_id
            or local_state.collector_id != descriptor.collector_id
            or local_state.target_host_fingerprint != descriptor.target_host_fingerprint
        ):
            raise ValueError("local collector state differs from its descriptor")
        if hashlib.sha256(_load_secret(Path(local_state.secret_path))).hexdigest() != (
            verification_secret_sha256
        ):
            raise ValueError("local collector signing and verification secrets differ")
    known_hosts = None
    known_hosts_sha256 = None
    if known_hosts_path is not None:
        known_hosts_path = known_hosts_path.expanduser().resolve()
        if not known_hosts_path.is_file():
            raise ValueError("known_hosts_path must be an existing regular file")
        known_hosts = str(known_hosts_path)
        known_hosts_sha256 = sha256_file(known_hosts_path)
    identity_file = None
    identity_sha256 = None
    if ssh_identity_file is not None:
        ssh_identity_file = ssh_identity_file.expanduser().resolve()
        if not ssh_identity_file.is_file():
            raise ValueError("ssh_identity_file must be an existing regular file")
        if os.name != "nt" and stat.S_IMODE(ssh_identity_file.stat().st_mode) & 0o077:
            raise ValueError("SSH identity permissions must not allow group or other access")
        identity_file = str(ssh_identity_file)
        identity_sha256 = sha256_file(ssh_identity_file)
    config = EvidenceDeploymentConfig(
        robot_id=robot_id,
        mode=mode,
        collector=descriptor,
        verification_secret_path=str(verification_secret_path),
        verification_secret_sha256=verification_secret_sha256,
        ssh_target=ssh_target,
        known_hosts_path=known_hosts,
        known_hosts_sha256=known_hosts_sha256,
        ssh_port=(ssh_port if ssh_port is not None else 22)
        if mode == EvidenceDeploymentMode.REMOTE
        else None,
        ssh_identity_file=identity_file,
        ssh_identity_sha256=identity_sha256,
        collector_config=collector_config,
        collector_executable=collector_executable,
        local_collector_state_path=(
            str(resolved_local_state) if resolved_local_state is not None else None
        ),
        transition_id=transition_id,
    )
    return config


def _atomic_write_text(path: Path, text: str) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def reenroll_deployment(
    *,
    output_path: Path,
    expected_collector_id: str,
    reason: str,
    descriptor: CollectorDescriptor,
    verification_secret_path: Path,
    mode: EvidenceDeploymentMode | None = None,
    ssh_target: str | None = None,
    known_hosts_path: Path | None = None,
    ssh_port: int | None = None,
    ssh_identity_file: Path | None = None,
    collector_config: str | None = None,
    collector_executable: str | None = None,
    local_collector_state_path: Path | None = None,
    transition_dir: Path | None = None,
) -> tuple[EvidenceDeploymentConfig, EvidenceDeploymentTransition, Path]:
    """Explicitly replace a pinned deployment and preserve an immutable transition record."""
    if not output_path.is_file():
        raise ValueError("target evidence deployment must exist before re-enrollment")
    previous = load_deployment(output_path)
    if previous.collector.collector_id != expected_collector_id:
        raise ValueError("pinned collector identity differs from the expected re-enrollment pin")
    transition_id = f"transition-{uuid4().hex}"
    selected_mode = mode or previous.mode
    selected_collector_config = collector_config or previous.collector_config
    selected_collector_executable = collector_executable or previous.collector_executable
    selected_ssh_target = ssh_target if selected_mode == EvidenceDeploymentMode.REMOTE else None
    selected_known_hosts = (
        known_hosts_path if selected_mode == EvidenceDeploymentMode.REMOTE else None
    )
    selected_ssh_port = ssh_port if selected_mode == EvidenceDeploymentMode.REMOTE else None
    selected_ssh_identity = (
        ssh_identity_file if selected_mode == EvidenceDeploymentMode.REMOTE else None
    )
    if selected_mode == EvidenceDeploymentMode.REMOTE:
        selected_ssh_target = selected_ssh_target or previous.ssh_target
        selected_known_hosts = selected_known_hosts or (
            Path(previous.known_hosts_path) if previous.known_hosts_path else None
        )
        if selected_ssh_port is None:
            selected_ssh_port = previous.ssh_port or 22
        selected_ssh_identity = selected_ssh_identity or (
            Path(previous.ssh_identity_file) if previous.ssh_identity_file else None
        )
    elif local_collector_state_path is None and previous.local_collector_state_path:
        local_collector_state_path = Path(previous.local_collector_state_path)
    proposed = _build_deployment_config(
        robot_id=previous.robot_id,
        mode=selected_mode,
        descriptor=descriptor,
        verification_secret_path=verification_secret_path,
        ssh_target=selected_ssh_target,
        known_hosts_path=selected_known_hosts,
        ssh_port=selected_ssh_port,
        ssh_identity_file=selected_ssh_identity,
        collector_config=selected_collector_config,
        collector_executable=selected_collector_executable,
        local_collector_state_path=local_collector_state_path,
        transition_id=transition_id,
    )
    if (
        proposed.collector == previous.collector
        and proposed.verification_secret_sha256 == previous.verification_secret_sha256
        and proposed.mode == previous.mode
        and proposed.collector_config == previous.collector_config
        and proposed.collector_executable == previous.collector_executable
        and proposed.ssh_target == previous.ssh_target
        and proposed.known_hosts_path == previous.known_hosts_path
        and proposed.known_hosts_sha256 == previous.known_hosts_sha256
        and proposed.ssh_port == previous.ssh_port
        and proposed.ssh_identity_file == previous.ssh_identity_file
        and proposed.ssh_identity_sha256 == previous.ssh_identity_sha256
        and proposed.local_collector_state_path == previous.local_collector_state_path
    ):
        raise ValueError(
            "re-enrollment must change collector identity, credentials, mode, or transport"
        )
    transition = EvidenceDeploymentTransition(
        transition_id=transition_id,
        robot_id=previous.robot_id,
        reason=reason.strip(),
        previous_collector_id=previous.collector.collector_id,
        new_collector_id=proposed.collector.collector_id,
        previous_target_host_fingerprint=(previous.collector.target_host_fingerprint),
        new_target_host_fingerprint=proposed.collector.target_host_fingerprint,
        previous_verification_secret_sha256=(previous.verification_secret_sha256),
        new_verification_secret_sha256=proposed.verification_secret_sha256,
        previous_mode=previous.mode,
        new_mode=proposed.mode,
        previous_collector_executable=previous.collector_executable,
        new_collector_executable=proposed.collector_executable,
        previous_collector_config=previous.collector_config,
        new_collector_config=proposed.collector_config,
        previous_ssh_target=previous.ssh_target,
        new_ssh_target=proposed.ssh_target,
        previous_ssh_port=previous.ssh_port,
        new_ssh_port=proposed.ssh_port,
        previous_known_hosts_sha256=previous.known_hosts_sha256,
        new_known_hosts_sha256=proposed.known_hosts_sha256,
        previous_ssh_identity_sha256=previous.ssh_identity_sha256,
        new_ssh_identity_sha256=proposed.ssh_identity_sha256,
    )
    transitions = (
        transition_dir.expanduser().resolve()
        if transition_dir is not None
        else output_path.expanduser().resolve().parent / "transitions"
    )
    transition_path = transitions / f"{transition.transition_id}.json"
    if transition_path.exists():
        raise ValueError("target evidence transition record already exists")
    _atomic_write_text(
        transition_path,
        transition.model_dump_json(indent=2) + "\n",
    )
    _atomic_write_text(output_path, proposed.model_dump_json(indent=2) + "\n")
    return proposed, transition, transition_path


def load_deployment(path: Path) -> EvidenceDeploymentConfig:
    try:
        deployment = EvidenceDeploymentConfig.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"invalid target evidence deployment: {exc}") from exc
    if (
        deployment.mode == EvidenceDeploymentMode.REMOTE
        and deployment.schema_version != "robot-target-evidence-deployment/v3"
    ):
        known_hosts = Path(deployment.known_hosts_path or "").expanduser().resolve()
        if not known_hosts.is_file():
            raise ValueError(
                "legacy remote deployment cannot migrate because known_hosts is unavailable"
            )
        identity = (
            Path(deployment.ssh_identity_file).expanduser().resolve()
            if deployment.ssh_identity_file
            else None
        )
        if identity is not None and not identity.is_file():
            raise ValueError(
                "legacy remote deployment cannot migrate because its SSH identity is unavailable"
            )
        deployment = deployment.model_copy(
            update={
                "schema_version": "robot-target-evidence-deployment/v3",
                "known_hosts_sha256": sha256_file(known_hosts),
                "ssh_port": deployment.ssh_port or 22,
                "ssh_identity_sha256": sha256_file(identity) if identity is not None else None,
            }
        )
        deployment = EvidenceDeploymentConfig.model_validate(deployment.model_dump(mode="json"))
        _atomic_write_text(path, deployment.model_dump_json(indent=2) + "\n")
    return deployment


def verify_ssh_transport_pins(deployment: EvidenceDeploymentConfig) -> None:
    """Fail before SSH when persisted transport files differ from their enrollment pins."""
    if deployment.mode != EvidenceDeploymentMode.REMOTE:
        raise ValueError("SSH transport pin verification requires remote deployment mode")
    known_hosts = Path(deployment.known_hosts_path or "").expanduser().resolve()
    if not known_hosts.is_file():
        raise SSHTransportError("SSH_KNOWN_HOSTS_UNAVAILABLE", "pinned known_hosts is unavailable")
    if sha256_file(known_hosts) != deployment.known_hosts_sha256:
        raise SSHTransportError(
            "SSH_HOST_KEY_PIN_CHANGED",
            "known_hosts content differs from its enrollment pin; use explicit re-enrollment",
        )
    if deployment.ssh_identity_file:
        identity = Path(deployment.ssh_identity_file).expanduser().resolve()
        if not identity.is_file():
            raise SSHTransportError(
                "SSH_IDENTITY_UNAVAILABLE", "pinned SSH identity file is unavailable"
            )
        if os.name != "nt" and stat.S_IMODE(identity.stat().st_mode) & 0o077:
            raise SSHTransportError(
                "SSH_IDENTITY_PERMISSIONS",
                "SSH identity permissions allow group or other access",
            )
        if sha256_file(identity) != deployment.ssh_identity_sha256:
            raise SSHTransportError(
                "SSH_IDENTITY_PIN_CHANGED",
                "SSH identity content differs from its enrollment pin; use explicit re-enrollment",
            )


def new_request(
    robot_id: str,
    *,
    now: datetime | None = None,
    executable_help_ids: Sequence[str] = (),
) -> TargetEvidenceRequest:
    issued_at = now or _utc_now()
    return TargetEvidenceRequest(
        robot_id=robot_id,
        nonce=secrets.token_hex(16),
        requested_executable_help_ids=sorted(set(executable_help_ids)),
        issued_at=issued_at,
        expires_at=issued_at + MAX_REQUEST_LIFETIME,
    )


def _validate_request(
    request: TargetEvidenceRequest, state: CollectorState, *, now: datetime
) -> None:
    if request.robot_id != state.robot_id:
        raise ValueError("evidence request robot identity mismatch")
    if request.issued_at - MAX_CLOCK_SKEW > now:
        raise ValueError("evidence request was issued in the future")
    if request.expires_at < now:
        raise ValueError("evidence request expired")


def collect_target_evidence(
    request: TargetEvidenceRequest,
    state: CollectorState,
    *,
    now: datetime | None = None,
    environment: Mapping[str, str] | None = None,
) -> TargetEvidenceBundle:
    collected_at = now or _utc_now()
    _validate_request(request, state, now=collected_at)
    ros_environment = resolve_pinned_ros_environment(
        state.ros_setup_files,
        environment=environment,
    )
    collectors = {
        "hw": lambda: HardwareProbe().run(robot_id=state.robot_id),
        "linux": lambda: LinuxProbe().run(),
        # Target evidence is the source of truth used by the controller's
        # runtime discovery path.  Collect the same bounded, enriched ROS
        # snapshot as the on-target probe dispatcher so route bindings carry
        # provider/schema evidence and unstable graph snapshots are rejected
        # conservatively.
        "ros": lambda: RosProbe(enrich_routes=True, stabilize=True).run(),
    }
    with _temporary_environment(ros_environment.environment):
        probes = {
            layer: persist_route_evidence(collectors[layer]()) for layer in request.requested_layers
        }
        help_evidence = _collect_executable_help(request, state)
    if ros_probe := probes.get("ros"):
        ros_probe.data["environment_bootstrap"] = ros_environment.model_dump(
            mode="json",
            exclude={"environment"},
        )
        ros_probe.warnings.extend(ros_environment.warnings)
    base = {
        "schema_version": "robot-target-evidence-bundle/v2",
        "robot_id": state.robot_id,
        "collector_id": state.collector_id,
        "target_host_fingerprint": state.target_host_fingerprint,
        "request_nonce": request.nonce,
        "requested_layers": request.requested_layers,
        "access": "READ_ONLY",
        "collected_at": collected_at.isoformat().replace("+00:00", "Z"),
        "probes": {key: value.model_dump(mode="json") for key, value in probes.items()},
        "executable_help": [item.model_dump(mode="json") for item in help_evidence],
    }
    # Hash the same Pydantic-normalized representation that the controller
    # verifies after transport.  Hashing the pre-validation ``base`` dict can
    # diverge for nested datetime/number values and would make a valid bundle
    # unverifiable across Python/Pydantic versions.
    normalized = TargetEvidenceBundle(
        **base,
        payload_sha256="0" * 64,
        signature_hmac_sha256="0" * 64,
    ).model_dump(
        mode="json",
        exclude={"payload_sha256", "signature_hmac_sha256"},
        exclude_none=True,
    )
    payload_sha256 = hashlib.sha256(_canonical_json(normalized)).hexdigest()
    signature = hmac.new(
        _load_secret(Path(state.secret_path)), payload_sha256.encode("ascii"), hashlib.sha256
    ).hexdigest()
    return TargetEvidenceBundle(
        **base,
        payload_sha256=payload_sha256,
        signature_hmac_sha256=signature,
    )


@contextmanager
def _temporary_environment(environment: Mapping[str, str]):
    previous = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(environment)
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


def _collect_executable_help(
    request: TargetEvidenceRequest,
    state: CollectorState,
) -> list[TargetExecutableHelpEvidence]:
    allowed = {item.executable_id: item for item in state.help_executables}
    unknown = sorted(set(request.requested_executable_help_ids) - set(allowed))
    if unknown:
        raise ValueError(f"requested executable help IDs are not allowlisted: {unknown}")
    evidence: list[TargetExecutableHelpEvidence] = []
    for executable_id in request.requested_executable_help_ids:
        descriptor = allowed[executable_id]
        path = Path(descriptor.path)
        if not path.is_file() or path.stat().st_size > MAX_HELP_EXECUTABLE_BYTES:
            # A single stale or removed executable must not suppress evidence
            # for every other pinned CLI. Preserve the failure as signed
            # evidence so route binding can ignore this item while using
            # successfully inspected siblings.
            result = HelpProbeResult(
                status=HelpProbeStatus.FAILED,
                error=f"allowlisted executable is unavailable or oversized: {path}",
            )
            output_text = ""
            usage, parameters, subcommands = [], [], []
        else:
            if sha256_file(path) != descriptor.sha256:
                raise ValueError(f"allowlisted executable digest changed: {executable_id}")
            with tempfile.TemporaryDirectory(prefix="rolo-target-help-") as temporary:
                output_path = Path(temporary) / "help.txt"
                try:
                    result = run_bounded_help(path, output_path)
                except OSError as exc:
                    result = HelpProbeResult(status=HelpProbeStatus.FAILED, error=str(exc))
                output = output_path.read_bytes() if output_path.is_file() else b""
            output_text = output.decode("utf-8", errors="replace")
            usage, parameters, subcommands = _extract_help_summary(output_text)
        canonical_output = output_text.encode("utf-8")
        evidence.append(
            TargetExecutableHelpEvidence(
                executable_id=executable_id,
                path=str(path),
                executable_sha256=descriptor.sha256,
                help_probe=result,
                output_text=output_text,
                output_sha256=hashlib.sha256(canonical_output).hexdigest(),
                usage=usage,
                parameters=parameters,
                subcommands=subcommands,
            )
        )
    return evidence


def bind_target_executable_routes(
    probe: ProbeResult,
    records: Sequence[TargetExecutableHelpEvidence],
    *,
    bundle_payload_sha256: str,
    observed_at: datetime,
) -> ProbeResult:
    """Derive application CLI routes from already verified target help evidence.

    The derivation happens on the controller after bundle signature validation.
    It therefore does not trust a collector-supplied route assertion and remains
    compatible with older v2 bundles that contain help evidence but no CLI route.
    """
    existing = {route.resource_id: route for route in probe_routes(probe)}
    for route in ApplicationCliRouteProvider().observed_routes(
        records,
        bundle_payload_sha256=bundle_payload_sha256,
        observed_at=observed_at,
    ):
        existing[route.resource_id] = route
    data = dict(probe.data)
    data["route_evidence"] = [
        route.model_dump(mode="json")
        for route in sorted(existing.values(), key=lambda item: item.resource_id)
    ]
    status = probe.status
    if (
        records
        and any(item.help_probe.status == HelpProbeStatus.SUCCEEDED for item in records)
        and status not in {DiscoveryStatus.SUCCEEDED, DiscoveryStatus.PARTIAL}
    ):
        status = DiscoveryStatus.PARTIAL
    return probe.model_copy(update={"status": status, "data": data})


def verify_evidence_bundle(
    bundle: TargetEvidenceBundle,
    *,
    deployment: EvidenceDeploymentConfig,
    request: TargetEvidenceRequest | None = None,
    secret_path: Path | None = None,
    now: datetime | None = None,
) -> dict[str, ProbeResult]:
    observed_at = now or _utc_now()
    descriptor = deployment.collector
    if bundle.robot_id != deployment.robot_id:
        raise ValueError("evidence bundle robot identity mismatch")
    if bundle.collector_id != descriptor.collector_id:
        raise ValueError("evidence bundle collector identity mismatch")
    if bundle.target_host_fingerprint != descriptor.target_host_fingerprint:
        raise ValueError("evidence bundle target host fingerprint mismatch")
    if request is not None:
        if request.robot_id != bundle.robot_id or request.nonce != bundle.request_nonce:
            raise ValueError("evidence bundle does not answer the issued request")
        if bundle.requested_layers != request.requested_layers:
            raise ValueError("evidence bundle layer set differs from the issued request")
        if [item.executable_id for item in bundle.executable_help] != (
            request.requested_executable_help_ids
        ):
            raise ValueError("evidence bundle executable help differs from the issued request")
        if bundle.collected_at < request.issued_at - MAX_CLOCK_SKEW:
            raise ValueError("evidence bundle predates the issued request")
        if bundle.collected_at > request.expires_at + MAX_CLOCK_SKEW:
            raise ValueError("evidence bundle was collected after request expiry")
    if bundle.collected_at > observed_at + MAX_CLOCK_SKEW:
        raise ValueError("evidence bundle timestamp is in the future")
    if observed_at - bundle.collected_at > MAX_REQUEST_LIFETIME + MAX_CLOCK_SKEW:
        raise ValueError("evidence bundle is stale")
    if set(bundle.probes) != set(bundle.requested_layers):
        raise ValueError("evidence bundle probe keys do not match its declared layers")
    allowed_help = {item.executable_id: item for item in descriptor.help_executables}
    for item in bundle.executable_help:
        allowed = allowed_help.get(item.executable_id)
        if allowed is None or item.path != allowed.path or item.executable_sha256 != allowed.sha256:
            raise ValueError("evidence bundle executable help is outside the pinned allowlist")
        if hashlib.sha256(item.output_text.encode("utf-8")).hexdigest() != (item.output_sha256):
            raise ValueError("evidence bundle executable help output hash mismatch")
    base = bundle.model_dump(
        mode="json",
        exclude={"payload_sha256", "signature_hmac_sha256"},
        exclude_none=True,
    )
    actual_payload_sha256 = hashlib.sha256(_canonical_json(base)).hexdigest()
    if not hmac.compare_digest(actual_payload_sha256, bundle.payload_sha256):
        raise ValueError("evidence bundle payload hash mismatch")
    verification_secret = _load_secret(secret_path or Path(deployment.verification_secret_path))
    if hashlib.sha256(verification_secret).hexdigest() != (deployment.verification_secret_sha256):
        raise ValueError("collector verification secret differs from its pinned digest")
    expected_signature = hmac.new(
        verification_secret,
        bundle.payload_sha256.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, bundle.signature_hmac_sha256):
        raise ValueError("evidence bundle signature mismatch")
    bound: dict[str, ProbeResult] = {}
    for layer, probe in bundle.probes.items():
        data = dict(probe.data)
        target_binding = {
            "schema_version": "robot-target-evidence-binding/v2",
            "robot_id": bundle.robot_id,
            "collector_id": bundle.collector_id,
            "target_host_fingerprint": bundle.target_host_fingerprint,
            "bundle_payload_sha256": bundle.payload_sha256,
            "access": bundle.access,
            "deployment_mode": deployment.mode.value,
            "collected_at": bundle.collected_at.isoformat(),
        }
        if layer == "linux":
            target_binding["executable_help"] = [
                item.model_dump(mode="json") for item in bundle.executable_help
            ]
        data["target_evidence"] = target_binding
        verified_probe = probe.model_copy(update={"data": data})
        if layer == "linux":
            verified_probe = bind_target_executable_routes(
                verified_probe,
                bundle.executable_help,
                bundle_payload_sha256=bundle.payload_sha256,
                observed_at=bundle.collected_at,
            )
        bound[layer] = verified_probe
    return bound


def build_rkb_envelope(
    bundle: TargetEvidenceBundle,
    *,
    deployment: EvidenceDeploymentConfig,
    request: TargetEvidenceRequest | None = None,
    secret_path: Path | None = None,
    now: datetime | None = None,
) -> Any:
    """Verify a target bundle, then project it into the canonical RKB envelope.

    Callers cannot accidentally publish an unverified bundle through this helper:
    the existing identity, replay, payload and signature checks run first, and
    the bound probe data—not the free-form input payload—is placed in each fact.
    """

    verified = verify_evidence_bundle(
        bundle,
        deployment=deployment,
        request=request,
        secret_path=secret_path,
        now=now,
    )
    from rolo.rkb import snapshot_from_target_bundle

    verified_bundle = bundle.model_copy(update={"probes": verified})
    return snapshot_from_target_bundle(
        verified_bundle,
        deployment_mode=deployment.mode.value,
        source_ref=f"artifact://target-evidence/{bundle.payload_sha256}",
    )


def _ssh_transport_command(
    deployment: EvidenceDeploymentConfig,
    *,
    connect_timeout_s: float,
) -> list[str]:
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={Path(deployment.known_hosts_path or '').expanduser().resolve()}",
        "-o",
        f"ConnectTimeout={max(1, min(15, int(connect_timeout_s)))}",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=2",
        "-o",
        "RequestTTY=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "LogLevel=ERROR",
        "-p",
        str(deployment.ssh_port or 22),
    ]
    if deployment.ssh_identity_file:
        command.extend(
            [
                "-o",
                "IdentitiesOnly=yes",
                "-i",
                str(Path(deployment.ssh_identity_file).expanduser().resolve()),
            ]
        )
    remote_argv = [
        deployment.collector_executable,
        "target-evidence",
        "collector-run",
        "--config",
        deployment.collector_config,
    ]
    command.extend([deployment.ssh_target or "", *quote_remote_argv(remote_argv)])
    return command


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (OSError, ProcessLookupError):
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _classify_ssh_failure(returncode: int, stderr: str) -> SSHTransportError:
    message = stderr.strip()[:1000] or f"SSH exited with status {returncode}"
    lowered = message.lower()
    if (
        "host key verification failed" in lowered
        or "remote host identification has changed" in lowered
    ):
        return SSHTransportError("SSH_HOST_KEY_MISMATCH", message)
    if "permission denied" in lowered or "no supported authentication methods" in lowered:
        return SSHTransportError("SSH_AUTH_FAILED", message)
    if "could not resolve hostname" in lowered or "name or service not known" in lowered:
        return SSHTransportError("SSH_DNS_FAILED", message, retryable=True)
    if "connection refused" in lowered:
        return SSHTransportError("SSH_CONNECTION_REFUSED", message, retryable=True)
    if "connection timed out" in lowered or "operation timed out" in lowered:
        return SSHTransportError("SSH_TIMEOUT", message, retryable=True)
    if any(
        phrase in lowered
        for phrase in ("connection reset", "connection closed", "broken pipe", "connection aborted")
    ):
        return SSHTransportError("SSH_CONNECTION_LOST", message, retryable=True)
    if returncode == 255:
        return SSHTransportError("SSH_TRANSPORT_FAILED", message)
    return SSHTransportError("COLLECTOR_REJECTED", message)


def _run_ssh_transport(command: Sequence[str], request: bytes, *, timeout_s: float) -> bytes:
    with (
        tempfile.TemporaryFile() as request_stream,
        tempfile.TemporaryFile() as stdout_stream,
        tempfile.TemporaryFile() as stderr_stream,
    ):
        request_stream.write(request)
        request_stream.seek(0)
        popen_options: dict[str, object] = {
            "stdin": request_stream,
            "stdout": stdout_stream,
            "stderr": stderr_stream,
        }
        if os.name == "nt":
            popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_options["start_new_session"] = True
        try:
            process = subprocess.Popen(list(command), **popen_options)
        except OSError as exc:
            raise SSHTransportError("SSH_CLIENT_UNAVAILABLE", str(exc)) from exc
        deadline = time.monotonic() + timeout_s
        while process.poll() is None:
            if os.fstat(stdout_stream.fileno()).st_size > MAX_BUNDLE_BYTES:
                _stop_process(process)
                raise SSHTransportError(
                    "SSH_OUTPUT_LIMIT", "remote target evidence bundle exceeded its size limit"
                )
            if os.fstat(stderr_stream.fileno()).st_size > MAX_SSH_STDERR_BYTES:
                _stop_process(process)
                raise SSHTransportError(
                    "SSH_ERROR_OUTPUT_LIMIT", "SSH error output exceeded its size limit"
                )
            if time.monotonic() >= deadline:
                _stop_process(process)
                raise SSHTransportError(
                    "SSH_TIMEOUT", "remote target evidence transport timed out", retryable=True
                )
            time.sleep(0.02)
        stdout_size = os.fstat(stdout_stream.fileno()).st_size
        if stdout_size > MAX_BUNDLE_BYTES:
            raise SSHTransportError(
                "SSH_OUTPUT_LIMIT", "remote target evidence bundle exceeded its size limit"
            )
        if os.fstat(stderr_stream.fileno()).st_size > MAX_SSH_STDERR_BYTES:
            raise SSHTransportError(
                "SSH_ERROR_OUTPUT_LIMIT", "SSH error output exceeded its size limit"
            )
        stderr_stream.seek(0)
        stderr = stderr_stream.read(MAX_SSH_STDERR_BYTES).decode("utf-8", errors="replace")
        if process.returncode != 0:
            raise _classify_ssh_failure(process.returncode or 1, stderr)
        stdout_stream.seek(0)
        return stdout_stream.read(MAX_BUNDLE_BYTES + 1)


def collect_over_ssh(
    deployment: EvidenceDeploymentConfig,
    request: TargetEvidenceRequest,
    *,
    timeout_s: float = 45.0,
    max_attempts: int = 2,
) -> TargetEvidenceBundle:
    if deployment.mode != EvidenceDeploymentMode.REMOTE:
        raise ValueError("SSH collection requires remote deployment mode")
    if not 1 <= max_attempts <= 3:
        raise ValueError("SSH collection attempts must be between 1 and 3")
    verify_ssh_transport_pins(deployment)
    deadline = time.monotonic() + timeout_s
    response: bytes | None = None
    for attempt in range(max_attempts):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SSHTransportError("SSH_TIMEOUT", "remote target evidence transport timed out")
        command = _ssh_transport_command(deployment, connect_timeout_s=remaining)
        try:
            response = _run_ssh_transport(
                command,
                request.model_dump_json().encode("utf-8"),
                timeout_s=remaining,
            )
            break
        except SSHTransportError as exc:
            if not exc.retryable or attempt + 1 >= max_attempts:
                raise
            delay = min(0.25 * (2**attempt), max(0.0, deadline - time.monotonic()))
            if delay:
                time.sleep(delay)
    if response is None:
        raise SSHTransportError("SSH_TRANSPORT_FAILED", "SSH transport returned no response")
    try:
        return TargetEvidenceBundle.model_validate_json(response)
    except ValueError as exc:
        raise SSHTransportError(
            "COLLECTOR_INVALID_BUNDLE", f"remote collector returned invalid JSON: {exc}"
        ) from exc
