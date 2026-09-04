"""Read-only Local/SSH target executors and typed bootstrap planning."""

from __future__ import annotations

import os
import platform
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from rolo.target_ref import LocalTargetRef, SshTargetRef, TargetRef
from rolo.targets.models import (
    BootstrapAction,
    BootstrapPlanStatus,
    CompanionStatus,
    TargetBootstrapPlan,
    TargetBootstrapStep,
    TargetConnectionAssessment,
    TargetConnectionState,
    TargetRisk,
)

MAX_DIAGNOSTIC_CHARS = 1000


def quote_remote_arg(value: str) -> str:
    """Quote one argument for the remote POSIX shell used by OpenSSH."""
    if "\x00" in value:
        raise ValueError("remote command arguments must not contain NUL bytes")
    return shlex.quote(value)


def quote_remote_argv(remote_argv: list[str]) -> list[str]:
    """Encode an argv vector before OpenSSH joins it for the remote shell."""
    return [quote_remote_arg(value) for value in remote_argv]


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandRunner(Protocol):
    def run(self, argv: list[str], *, timeout_s: float) -> CommandResult: ...


class SubprocessCommandRunner:
    """Run fixed executor argv without a shell or interactive input."""

    def run(self, argv: list[str], *, timeout_s: float) -> CommandResult:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
        )
        return CommandResult(
            argv=tuple(argv),
            returncode=completed.returncode,
            stdout=completed.stdout[:MAX_DIAGNOSTIC_CHARS],
            stderr=completed.stderr[:MAX_DIAGNOSTIC_CHARS],
        )


class TargetExecutor(Protocol):
    target: TargetRef

    def inspect(self) -> TargetConnectionAssessment: ...

    def plan_bootstrap(
        self, assessment: TargetConnectionAssessment | None = None
    ) -> TargetBootstrapPlan: ...

    def run_bound(
        self, remote_argv: list[str], *, timeout_s: float | None = None,
        ros_setup_files: tuple[str, ...] = (),
    ) -> CommandResult: ...


def _blocked_plan(
    assessment: TargetConnectionAssessment,
) -> TargetBootstrapPlan:
    return TargetBootstrapPlan(
        target=assessment.target,
        assessment_state=assessment.state,
        status=BootstrapPlanStatus.BLOCKED,
        blockers=assessment.blockers,
    )


class LocalTargetExecutor:
    def __init__(self, target: LocalTargetRef) -> None:
        self.target = target

    def inspect(self) -> TargetConnectionAssessment:
        workspace_accessible = self.target.workspace.is_dir() and os.access(
            self.target.workspace, os.R_OK
        )
        state = (
            TargetConnectionState.READY
            if workspace_accessible
            else TargetConnectionState.WORKSPACE_MISSING
        )
        blockers = [] if workspace_accessible else ["local workspace is unavailable or unreadable"]
        return TargetConnectionAssessment(
            target=self.target,
            state=state,
            reachable=True,
            platform=platform.system(),
            architecture=platform.machine(),
            workspace_accessible=workspace_accessible,
            companion=CompanionStatus.NOT_REQUIRED,
            blockers=blockers,
        )

    def plan_bootstrap(
        self, assessment: TargetConnectionAssessment | None = None
    ) -> TargetBootstrapPlan:
        assessment = assessment or self.inspect()
        if assessment.state != TargetConnectionState.READY:
            return _blocked_plan(assessment)
        return TargetBootstrapPlan(
            target=self.target,
            assessment_state=assessment.state,
            status=BootstrapPlanStatus.READY,
            steps=[
                TargetBootstrapStep(
                    action=BootstrapAction.VERIFY_WORKSPACE,
                    risk=TargetRisk.READ_ONLY,
                    description="Use the existing local Rolo runtime and verified workspace.",
                )
            ],
        )

    def run_bound(
        self, remote_argv: list[str], *, timeout_s: float | None = None,
        ros_setup_files: tuple[str, ...] = (),
    ) -> CommandResult:
        raise ValueError("local bound execution is not available through this target executor")


class SshTargetExecutor:
    def __init__(
        self,
        target: SshTargetRef,
        *,
        known_hosts: Path | None,
        identity_file: Path | None = None,
        ros_setup_files: tuple[str, ...] = (),
        remote_command_prefix: tuple[str, ...] = (),
        timeout_s: float = 10.0,
        runner: CommandRunner | None = None,
    ) -> None:
        if not 1.0 <= timeout_s <= 300.0:
            raise ValueError("SSH target timeout must be between 1 and 300 seconds")
        self.target = target
        self.known_hosts = known_hosts.expanduser().resolve() if known_hosts else None
        self.identity_file = identity_file.expanduser().resolve() if identity_file else None
        self.ros_setup_files = tuple(ros_setup_files)
        if any(
            not item
            or "\x00" in item
            or any(character in item for character in "'\";$`\\")
            for item in remote_command_prefix
        ):
            raise ValueError("remote command prefix must contain shell-free, NUL-free tokens")
        self.remote_command_prefix = tuple(remote_command_prefix)
        self.timeout_s = timeout_s
        self.runner = runner or SubprocessCommandRunner()

    def _ssh_argv(self, remote_argv: list[str]) -> list[str]:
        if self.known_hosts is None:
            raise ValueError("SSH inspection requires a pinned known_hosts file")
        destination = (
            f"{self.target.user}@{self.target.host}"
            if self.target.user
            else self.target.host
        )
        argv = [
            "ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "GlobalKnownHostsFile=none",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            f"ConnectTimeout={max(1, min(int(self.timeout_s), 300))}",
        ]
        if self.identity_file is not None:
            if not self.identity_file.is_file():
                raise ValueError("pinned SSH identity file is unavailable")
            argv.extend(["-o", "IdentitiesOnly=yes", "-i", str(self.identity_file)])
        if self.target.port is not None:
            argv.extend(["-p", str(self.target.port)])
        return [
            *argv,
            "--",
            destination,
            *quote_remote_argv([*self.remote_command_prefix, *remote_argv]),
        ]

    def _run(self, remote_argv: list[str]) -> CommandResult:
        return self.runner.run(self._ssh_argv(remote_argv), timeout_s=self.timeout_s)

    def run_readonly(
        self,
        remote_argv: list[str],
        *,
        environment: dict[str, str] | None = None,
        ros_setup_files: tuple[str, ...] = (),
    ) -> CommandResult:
        """Run one fixed read-only argv on the pinned remote target.

        Native tools are descriptors, never shell text.  The only shell syntax
        assembled here is the bounded ROS bootstrap needed to source pinned setup
        files before invoking a static argv.  Every component is shell-quoted and
        SSH still enforces the pinned host key, identity and forwarding policy.
        """
        if not remote_argv or any(not value or "\x00" in value for value in remote_argv):
            raise ValueError("remote native argv must be non-empty and NUL-free")
        setup_files = tuple(ros_setup_files or self.ros_setup_files)
        if setup_files:
            if any(
                not path
                or "\x00" in path
                or not path.startswith("/")
                or any(character in path for character in "'\";$`\\")
                for path in setup_files
            ):
                raise ValueError("ROS setup paths must be absolute and shell-safe")
            command = "; ".join(
                [
                    "set -eo pipefail",
                    *[f". {quote_remote_arg(path)}" for path in setup_files],
                    f"exec {' '.join(quote_remote_argv(remote_argv))}",
                ]
            )
            return self._run(["bash", "--noprofile", "--norc", "-c", command])
        if environment:
            if any(
                not key
                or "=" in key
                or "\x00" in key
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
                or "\x00" in value
                for key, value in environment.items()
            ):
                raise ValueError("remote native environment contains an unsafe key or value")
            assignments = [f"{key}={value}" for key, value in sorted(environment.items())]
            remote_argv = ["env", *assignments, *remote_argv]
        return self._run(remote_argv)

    def run_bound(
        self,
        remote_argv: list[str],
        *,
        timeout_s: float | None = None,
        ros_setup_files: tuple[str, ...] = (),
    ) -> CommandResult:
        """Run one provider-generated, fixed argv on the pinned target.

        Only a trusted typed provider may call this method.  Harness input is
        never passed here; providers construct and validate the complete argv
        from an evidence-bound execution binding before dispatch.
        """
        if not remote_argv or any(not value or "\x00" in value for value in remote_argv):
            raise ValueError("bound execution argv must be non-empty and NUL-free")
        setup_files = tuple(ros_setup_files or self.ros_setup_files)
        if setup_files:
            if any(
                not path
                or "\x00" in path
                or not path.startswith("/")
                or any(character in path for character in "'\";$`\\")
                for path in setup_files
            ):
                raise ValueError("ROS setup paths must be absolute and shell-safe")
            command = "; ".join(
                [
                    "set -eo pipefail",
                    *[f". {quote_remote_arg(path)}" for path in setup_files],
                    f"exec {' '.join(quote_remote_argv(remote_argv))}",
                ]
            )
            return self._run(["bash", "--noprofile", "--norc", "-c", command])
        return self._run(remote_argv)

    @staticmethod
    def _failure_detail(result: CommandResult) -> str:
        return result.stderr.strip() or result.stdout.strip() or f"SSH exited {result.returncode}"

    def inspect(self) -> TargetConnectionAssessment:
        if self.known_hosts is None:
            return TargetConnectionAssessment(
                target=self.target,
                state=TargetConnectionState.HOST_KEY_REQUIRED,
                reachable=False,
                host_key_pinned=False,
                blockers=["SSH host key must be pinned before connection inspection"],
            )
        try:
            known_hosts_available = (
                self.known_hosts.is_file() and self.known_hosts.stat().st_size > 0
            )
        except OSError:
            known_hosts_available = False
        if not known_hosts_available:
            return TargetConnectionAssessment(
                target=self.target,
                state=TargetConnectionState.HOST_KEY_REQUIRED,
                reachable=False,
                host_key_pinned=False,
                blockers=["pinned SSH known_hosts file is unavailable or empty"],
            )
        try:
            system = self._run(["uname", "-s"])
            if system.returncode != 0:
                return TargetConnectionAssessment(
                    target=self.target,
                    state=TargetConnectionState.UNREACHABLE,
                    reachable=False,
                    host_key_pinned=True,
                    blockers=["SSH target connection inspection failed"],
                    diagnostics=[self._failure_detail(system)],
                )
            platform_name = system.stdout.strip()
            architecture = self._run(["uname", "-m"])
            if architecture.returncode != 0:
                return TargetConnectionAssessment(
                    target=self.target,
                    state=TargetConnectionState.UNREACHABLE,
                    reachable=True,
                    host_key_pinned=True,
                    platform=platform_name,
                    blockers=["SSH target architecture inspection failed"],
                    diagnostics=[self._failure_detail(architecture)],
                )
            if not platform_name.strip():
                return TargetConnectionAssessment(
                    target=self.target,
                    state=TargetConnectionState.UNSUPPORTED,
                    reachable=True,
                    host_key_pinned=True,
                    platform=platform_name,
                    architecture=architecture.stdout.strip(),
                    blockers=["target OS identity could not be determined by the current provider"],
                )
            workspace = self._run(["test", "-d", str(self.target.workspace)])
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            return TargetConnectionAssessment(
                target=self.target,
                state=TargetConnectionState.UNREACHABLE,
                reachable=False,
                host_key_pinned=True,
                blockers=["SSH target connection inspection could not complete"],
                diagnostics=[str(exc)[:MAX_DIAGNOSTIC_CHARS]],
            )
        workspace_accessible = workspace.returncode == 0
        state = (
            TargetConnectionState.READY
            if workspace_accessible
            else TargetConnectionState.WORKSPACE_MISSING
        )
        return TargetConnectionAssessment(
            target=self.target,
            state=state,
            reachable=True,
            host_key_pinned=True,
            platform=platform_name,
            architecture=architecture.stdout.strip(),
            workspace_accessible=workspace_accessible,
            companion=CompanionStatus.NOT_REQUIRED,
            blockers=([] if workspace_accessible else ["remote workspace is unavailable"]),
        )

    def plan_bootstrap(
        self, assessment: TargetConnectionAssessment | None = None
    ) -> TargetBootstrapPlan:
        assessment = assessment or self.inspect()
        if assessment.state != TargetConnectionState.READY:
            return _blocked_plan(assessment)
        steps = [
            TargetBootstrapStep(
                action=BootstrapAction.VERIFY_PLATFORM,
                risk=TargetRisk.READ_ONLY,
                description="Verify the pinned target OS platform and architecture.",
            ),
            TargetBootstrapStep(
                action=BootstrapAction.VERIFY_WORKSPACE,
                risk=TargetRisk.READ_ONLY,
                description="Verify that the remote workspace is readable.",
            ),
        ]
        return TargetBootstrapPlan(
            target=self.target,
            assessment_state=assessment.state,
            status=BootstrapPlanStatus.READY,
            steps=steps,
        )


def create_target_executor(
    target: TargetRef,
    *,
    known_hosts: Path | None = None,
    identity_file: Path | None = None,
    ros_setup_files: tuple[str, ...] = (),
    remote_command_prefix: tuple[str, ...] = (),
    timeout_s: float = 10.0,
    runner: CommandRunner | None = None,
) -> TargetExecutor:
    if isinstance(target, LocalTargetRef):
        if known_hosts is not None or identity_file is not None:
            raise ValueError("local target inspection does not accept SSH transport options")
        return LocalTargetExecutor(target)
    return SshTargetExecutor(
        target,
        known_hosts=known_hosts,
        identity_file=identity_file,
        ros_setup_files=ros_setup_files,
        remote_command_prefix=remote_command_prefix,
        timeout_s=timeout_s,
        runner=runner,
    )


def create_profile_target_executor(
    profile_id: str,
    *,
    config_root: Path,
    timeout_s: float = 10.0,
    runner: CommandRunner | None = None,
) -> TargetExecutor:
    """Build a connector from one persisted profile without exposing secrets.

    The profile owns target identity and host-key approval. The evidence
    deployment owns pinned transport files. Credential resolution is performed
    once here, so callers only provide a profile id and never choose an SSH
    identity ad hoc.
    """

    from rolo.stages.probe.target_evidence import load_deployment, verify_ssh_transport_pins
    from rolo.targets.credentials import PinnedCredentialBroker
    from rolo.targets.profiles import TargetProfileStore

    profile = TargetProfileStore(config_root).load(profile_id)
    if isinstance(profile.target, LocalTargetRef):
        return create_target_executor(profile.target, timeout_s=timeout_s, runner=runner)

    if profile.host_key is None or profile.host_key.status != "APPROVED":
        raise ValueError("SSH target profile requires an approved host key")
    deployment_path = config_root.expanduser().resolve() / "target-evidence" / f"{profile_id}.json"
    deployment = load_deployment(deployment_path)
    if deployment.mode.value != "remote":
        raise ValueError("SSH target profile requires a remote evidence deployment")
    expected_target = (
        f"{profile.target.user}@{profile.target.host}"
        if profile.target.user
        else profile.target.host
    )
    if deployment.ssh_target != expected_target or (
        deployment.ssh_port or 22
    ) != (profile.target.port or 22):
        raise ValueError("target profile and evidence deployment transport do not match")
    verify_ssh_transport_pins(deployment)
    credential = PinnedCredentialBroker().resolve(
        profile.credential,
        identity_file=Path(deployment.ssh_identity_file) if deployment.ssh_identity_file else None,
    )
    return create_target_executor(
        profile.target,
        known_hosts=Path(deployment.known_hosts_path or ""),
        identity_file=credential.identity_file,
        ros_setup_files=tuple(item.path for item in deployment.collector.ros_setup_files),
        remote_command_prefix=tuple(profile.remote_command_prefix),
        timeout_s=timeout_s,
        runner=runner,
    )
