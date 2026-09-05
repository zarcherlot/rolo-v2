from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from rolo.runtime_context import AdapterRuntimeContext, admitted_runtime_environment


class NativeToolStatus(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    UNAVAILABLE = "UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    FAILED = "FAILED"
    REJECTED = "REJECTED"


_SAFE_TOOL_ID = re.compile(r"^[a-z][a-z0-9_.-]{1,127}$")
_SECRET = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|credential|cookie|authorization)"
    r"(\s*[=:]\s*|\s+)([^\s,;]+)"
)
_SAFE_ENV_KEYS = {
    field.alias
    for field in AdapterRuntimeContext.model_fields.values()
    if field.alias and field.alias != "PATH"
}
_PROCESS_ENV_KEYS = {"COMSPEC", "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR"}
_PUBLIC_FAMILY_BY_PROVIDER = {"hw": "hardware", "linux": "OS", "ros": "Middleware"}
_PUBLIC_TOOL_PREFIX_BY_PROVIDER = {
    "native.hw.": "native.hardware.",
    "native.linux.": "native.os.",
    "native.ros.": "native.middleware.",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _redact(value: str) -> str:
    return _SECRET.sub(lambda match: f"{match.group(1)}{match.group(2)}<redacted>", value)


class AgentNativeToolDescriptor(BaseModel):
    """Allowlisted command metadata; this is not a Canonical Operation contract."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-agent-native-tool/v1"
    tool_id: str = Field(pattern=_SAFE_TOOL_ID.pattern)
    family: str = Field(min_length=1, max_length=32)
    execution_path: str = Field(pattern=r"^(DIRECT_RUNNER|MIDDLEWARE_CLI)$")
    executable: str = Field(min_length=1, max_length=256)
    argv_template: list[str] = Field(min_length=1, max_length=16)
    access: str = Field(pattern=r"^(read|experimental_write)$")
    risk: str = Field(pattern=r"^(R0|R1|R2|R3)$")
    max_duration_s: float = Field(gt=0, le=120)
    max_output_bytes: int = Field(gt=0, le=1_000_000)
    evidence_kind: str = Field(min_length=1, max_length=64)
    sensitive: bool = False
    allowed_env_keys: list[str] = Field(default_factory=list, max_length=16)
    parameters: list[NativeToolParameter] = Field(default_factory=list, max_length=32)
    variants: dict[str, NativeToolInvocation] = Field(default_factory=dict, max_length=32)

    @field_validator("parameters")
    @classmethod
    def require_unique_parameters(
        cls, value: list[NativeToolParameter]
    ) -> list[NativeToolParameter]:
        names = [item.name for item in value]
        if len(names) != len(set(names)):
            raise ValueError("native tool parameters must be unique")
        return value

    @field_validator("variants")
    @classmethod
    def validate_variants(
        cls, value: dict[str, NativeToolInvocation]
    ) -> dict[str, NativeToolInvocation]:
        if any(not key or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,31}", key) for key in value):
            raise ValueError("native tool variant names must be safe identifiers")
        return value

    @property
    def parameter_by_name(self) -> dict[str, NativeToolParameter]:
        return {item.name: item for item in self.parameters}

    @field_validator("argv_template")
    @classmethod
    def require_fixed_argv(cls, value: list[str]) -> list[str]:
        if not value or not value[0] or any("\x00" in item for item in value):
            raise ValueError("argv_template must contain non-empty, NUL-free arguments")
        if any("{" in item or "}" in item for item in value):
            raise ValueError("argv_template does not accept interpolation")
        return value

    @field_validator("allowed_env_keys")
    @classmethod
    def restrict_environment(cls, value: list[str]) -> list[str]:
        if any(item not in _SAFE_ENV_KEYS for item in value):
            raise ValueError("agent-native tools may only forward approved environment keys")
        if len(value) != len(set(value)):
            raise ValueError("allowed_env_keys must be unique")
        return value

    @model_validator(mode="after")
    def validate_family_variants(self) -> AgentNativeToolDescriptor:
        parameters = self.parameter_by_name
        for mode, invocation in self.variants.items():
            if invocation.argv_template[0] != invocation.executable:
                raise ValueError(f"native variant {mode} executable must be argv[0]")
            unknown = sorted(set(invocation.required_parameters) - set(parameters))
            if unknown:
                raise ValueError(f"native variant {mode} has unknown parameters: {unknown}")
            placeholders = {
                match.group(1)
                for item in invocation.argv_template
                if (match := re.fullmatch(r"\{([a-z][a-z0-9_]{0,31})\}", item))
            }
            if placeholders != set(invocation.required_parameters):
                raise ValueError(
                    f"native variant {mode} placeholders do not match required parameters"
                )
        return self


class NativeToolParameter(BaseModel):
    """A bounded argument accepted by a family-level native tool."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    kind: Literal["token", "enum", "integer", "path"] = "token"
    required: bool = True
    choices: list[str] = Field(default_factory=list, max_length=64)
    pattern: str | None = Field(default=None, max_length=256)
    max_length: int = Field(default=128, ge=1, le=1024)

    @field_validator("choices")
    @classmethod
    def validate_choices(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("native parameter choices must be unique")
        if any(not item or "\x00" in item or len(item) > 256 for item in value):
            raise ValueError("native parameter choices must be bounded and NUL-free")
        return value

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError("native parameter pattern must be valid regex") from exc
        return value

    @model_validator(mode="after")
    def validate_semantics(self) -> NativeToolParameter:
        if self.kind == "enum" and not self.choices:
            raise ValueError("enum native parameters require choices")
        if self.kind != "enum" and self.choices:
            raise ValueError("only enum native parameters may define choices")
        return self


class NativeToolInvocation(BaseModel):
    """One static argv shape in a family-level descriptor."""

    model_config = ConfigDict(extra="forbid")

    executable: str = Field(min_length=1, max_length=256)
    argv_template: list[str] = Field(min_length=1, max_length=32)
    required_parameters: list[str] = Field(default_factory=list, max_length=32)
    unavailable_return_codes: list[int] = Field(default_factory=list, max_length=8)
    environment_dependency: Literal["NONE", "NETWORK"] = "NONE"

    def __init__(
        self,
        executable: str | None = None,
        argv_template: list[str] | None = None,
        required_parameters: list[str] | None = None,
        unavailable_return_codes: list[int] | None = None,
        **data: Any,
    ) -> None:
        if executable is not None:
            data["executable"] = executable
        if argv_template is not None:
            data["argv_template"] = argv_template
        if required_parameters is not None:
            data["required_parameters"] = required_parameters
        if unavailable_return_codes is not None:
            data["unavailable_return_codes"] = unavailable_return_codes
        super().__init__(**data)

    @field_validator("argv_template")
    @classmethod
    def validate_argv(cls, value: list[str]) -> list[str]:
        if any(not item or "\x00" in item for item in value):
            raise ValueError("native invocation argv must be non-empty and NUL-free")
        for item in value:
            if "{" in item or "}" in item:
                if not re.fullmatch(r"\{[a-z][a-z0-9_]{0,31}\}", item):
                    raise ValueError("native invocation placeholders must occupy one argv item")
        return value

    @field_validator("required_parameters")
    @classmethod
    def unique_required_parameters(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("native invocation parameters must be unique")
        return value

    @field_validator("unavailable_return_codes")
    @classmethod
    def validate_unavailable_return_codes(cls, value: list[int]) -> list[int]:
        if len(value) != len(set(value)) or any(item < 0 or item > 255 for item in value):
            raise ValueError("native unavailable return codes must be unique bytes")
        return value


AgentNativeToolDescriptor.model_rebuild()


class AgentNativeToolResult(BaseModel):
    """Bounded, auditable result returned to the Agent."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-agent-native-tool-result/v1"
    tool_id: str
    status: NativeToolStatus
    argv: list[str]
    observed_at: datetime
    duration_ms: float = Field(ge=0)
    stdout: str = ""
    stderr: str = ""
    stdout_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stderr_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    truncated: bool = False
    environment_limited: bool = False
    evidence_kind: str
    sensitive: bool
    limitations: list[str] = Field(default_factory=list, max_length=32)
    evidence_refs: list[str] = Field(default_factory=list, max_length=64)
    arguments: dict[str, str] = Field(default_factory=dict, max_length=32)


CommandExecutor = Callable[..., subprocess.CompletedProcess[str]]
RemoteCommandExecutor = Callable[..., object]


class AgentNativeRunner:
    """Execute only registered, static-argv read tools with bounded output."""

    def __init__(
        self,
        descriptors: Sequence[AgentNativeToolDescriptor],
        *,
        executor: CommandExecutor | None = None,
    ) -> None:
        by_id = {item.tool_id: item for item in descriptors}
        if len(by_id) != len(descriptors):
            raise ValueError("agent-native tool IDs must be unique")
        self._descriptors = by_id
        self._executor = executor or subprocess.run

    def list_tools(self) -> list[AgentNativeToolDescriptor]:
        return [self._descriptors[key] for key in sorted(self._descriptors)]

    def run(
        self,
        tool_id: str,
        arguments: Mapping[str, str] | None = None,
        *,
        environment: Mapping[str, str] | None = None,
    ) -> AgentNativeToolResult:
        descriptor = self._descriptors.get(tool_id)
        if descriptor is None:
            raise ValueError(f"unknown agent-native tool: {tool_id}")
        supplied = {str(key): str(value) for key, value in (arguments or {}).items()}
        requested_arguments = dict(supplied)
        invocation, argv = self._resolve_invocation(descriptor, supplied)
        source_environment = dict(os.environ if environment is None else environment)
        resolved = shutil.which(invocation.executable, path=source_environment.get("PATH"))
        if resolved is None:
            return self._result(
                descriptor,
                argv,
                NativeToolStatus.UNAVAILABLE,
                "",
                "executable not found",
                0,
                ["executable not found"],
                arguments=requested_arguments,
            )
        env = {
            key: source_environment[key]
            for key in _PROCESS_ENV_KEYS
            if key in source_environment
        }
        env.update(
            admitted_runtime_environment(
                {
                    key: source_environment[key]
                    for key in descriptor.allowed_env_keys
                    if key in source_environment
                }
            )
        )
        ros_log_dir = (
            tempfile.TemporaryDirectory(prefix="rolo-native-ros-log-")
            if invocation.executable == "ros2"
            else None
        )
        if ros_log_dir is not None:
            env["ROS_LOG_DIR"] = ros_log_dir.name
        started = time.monotonic()
        try:
            completed = self._executor(
                [resolved, *argv[1:]],
                capture_output=True,
                check=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=descriptor.max_duration_s,
                env=env,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            return self._result(
                descriptor,
                argv,
                NativeToolStatus.TIMEOUT,
                stdout,
                stderr,
                (time.monotonic() - started) * 1000,
                [
                    "tool execution timed out",
                    *(
                        [
                            "network-dependent check may be unavailable in the current environment"
                        ]
                        if invocation.environment_dependency == "NETWORK"
                        else []
                    ),
                ],
                arguments=requested_arguments,
                environment_limited=invocation.environment_dependency != "NONE",
            )
        except OSError as exc:
            return self._result(
                descriptor,
                argv,
                NativeToolStatus.FAILED,
                "",
                str(exc),
                (time.monotonic() - started) * 1000,
                ["tool execution failed"],
                arguments=requested_arguments,
            )
        finally:
            if ros_log_dir is not None:
                ros_log_dir.cleanup()
        no_output = not (completed.stdout or "").strip() and not (completed.stderr or "").strip()
        unavailable = completed.returncode in invocation.unavailable_return_codes and no_output
        status = (
            NativeToolStatus.SUCCEEDED
            if completed.returncode == 0
            else NativeToolStatus.UNAVAILABLE
            if unavailable
            else NativeToolStatus.FAILED
        )
        limitations = (
            []
            if status == NativeToolStatus.SUCCEEDED
            else [
                (
                    f"command exited with return code {completed.returncode}; "
                    "environment resource is unavailable"
                    if status == NativeToolStatus.UNAVAILABLE
                    else f"command exited with return code {completed.returncode}"
                )
            ]
        )
        return self._result(
            descriptor,
            argv,
            status,
            completed.stdout or "",
            completed.stderr or "",
            (time.monotonic() - started) * 1000,
            limitations,
            arguments=requested_arguments,
            environment_limited=(
                invocation.environment_dependency != "NONE"
                and status != NativeToolStatus.SUCCEEDED
            ),
        )

    @staticmethod
    def _resolve_invocation(
        descriptor: AgentNativeToolDescriptor,
        arguments: dict[str, str],
    ) -> tuple[NativeToolInvocation, list[str]]:
        mode = arguments.pop("mode", None)
        if descriptor.variants:
            selected_mode = mode or next(iter(sorted(descriptor.variants)))
            try:
                invocation = descriptor.variants[selected_mode]
            except KeyError as exc:
                raise ValueError(
                    f"unknown native tool mode {selected_mode!r}; "
                    f"choose one of {sorted(descriptor.variants)}"
                ) from exc
        else:
            if mode is not None:
                raise ValueError("native tool does not support mode selection")
            invocation = NativeToolInvocation(
                executable=descriptor.executable,
                argv_template=descriptor.argv_template,
            )
        parameters = descriptor.parameter_by_name
        unknown = sorted(set(arguments) - set(parameters))
        if unknown:
            raise ValueError(f"unknown native tool parameters: {unknown}")
        required = set(invocation.required_parameters)
        missing = sorted(required - set(arguments))
        if missing:
            raise ValueError(f"missing native tool parameters: {missing}")
        for name, value in arguments.items():
            parameter = parameters.get(name)
            if parameter is None:
                raise ValueError(f"unknown native tool parameter: {name}")
            if not value or "\x00" in value or len(value) > parameter.max_length:
                raise ValueError(f"native tool parameter {name} is out of bounds")
            if parameter.kind == "integer" and not re.fullmatch(r"[0-9]{1,9}", value):
                raise ValueError(f"native tool parameter {name} must be a positive integer")
            if parameter.kind == "path":
                normalized = value.replace("\\", "/")
                if (
                    normalized.startswith("/")
                    or re.match(r"^[A-Za-z]:/", normalized)
                    or ".." in normalized.split("/")
                    or re.fullmatch(r"[A-Za-z0-9._/@+-]+", normalized) is None
                ):
                    raise ValueError(
                        f"native tool parameter {name} must be a bounded relative path"
                    )
            if parameter.choices and value not in parameter.choices:
                raise ValueError(f"native tool parameter {name} must be one of {parameter.choices}")
            if parameter.pattern and re.fullmatch(parameter.pattern, value) is None:
                raise ValueError(f"native tool parameter {name} does not match its pattern")
        rendered: list[str] = []
        for item in invocation.argv_template:
            match = re.fullmatch(r"\{([a-z][a-z0-9_]{0,31})\}", item)
            rendered.append(arguments[match.group(1)] if match else item)
        if not rendered or rendered[0] != invocation.executable:
            raise ValueError("native invocation executable must be argv[0]")
        return invocation, rendered

    @staticmethod
    def _result(
        descriptor: AgentNativeToolDescriptor,
        argv: list[str],
        status: NativeToolStatus,
        stdout: str,
        stderr: str,
        duration_ms: float,
        limitations: list[str],
        arguments: dict[str, str] | None = None,
        environment_limited: bool = False,
    ) -> AgentNativeToolResult:
        stdout = _redact(stdout)
        stderr = _redact(stderr)
        output_bytes = len(stdout.encode("utf-8")) + len(stderr.encode("utf-8"))
        truncated = output_bytes > descriptor.max_output_bytes
        if truncated:
            stdout_budget = descriptor.max_output_bytes // 2
            stderr_budget = descriptor.max_output_bytes - stdout_budget
            stdout = stdout.encode("utf-8")[:stdout_budget].decode("utf-8", errors="ignore")
            stderr = stderr.encode("utf-8")[:stderr_budget].decode("utf-8", errors="ignore")
            limitations = [*limitations, "tool output exceeded the configured byte limit"]
        return AgentNativeToolResult(
            tool_id=descriptor.tool_id,
            status=status,
            argv=argv,
            observed_at=_utc_now(),
            duration_ms=round(max(duration_ms, 0), 3),
            stdout=stdout,
            stderr=stderr,
            stdout_sha256=hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
            stderr_sha256=hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
            truncated=truncated,
            environment_limited=environment_limited,
            evidence_kind=descriptor.evidence_kind,
            sensitive=descriptor.sensitive,
            limitations=limitations,
            arguments=arguments or {},
        )


class RemoteAgentNativeRunner(AgentNativeRunner):
    """Run the same bounded descriptor catalog through a pinned remote executor.

    The controller never resolves or executes the target executable locally.  The
    supplied executor owns SSH host-key, identity and command quoting; this class
    only performs descriptor/mode/argument validation and result normalization.
    """

    def __init__(
        self,
        descriptors: Sequence[AgentNativeToolDescriptor],
        *,
        executor: RemoteCommandExecutor,
    ) -> None:
        super().__init__(descriptors)
        self._remote_executor = executor

    def run(
        self,
        tool_id: str,
        arguments: Mapping[str, str] | None = None,
        *,
        environment: Mapping[str, str] | None = None,
    ) -> AgentNativeToolResult:
        descriptor = self._descriptors.get(tool_id)
        if descriptor is None:
            raise ValueError(f"unknown agent-native tool: {tool_id}")
        supplied = {str(key): str(value) for key, value in (arguments or {}).items()}
        requested_arguments = dict(supplied)
        invocation, argv = self._resolve_invocation(descriptor, supplied)
        started = time.monotonic()
        try:
            completed = self._remote_executor(
                argv,
                timeout_s=descriptor.max_duration_s,
                environment=dict(environment or {}),
            )
            returncode = int(completed.returncode)
            stdout = str(getattr(completed, "stdout", "") or "")
            stderr = str(getattr(completed, "stderr", "") or "")
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            return self._result(
                descriptor,
                argv,
                NativeToolStatus.TIMEOUT,
                stdout,
                stderr,
                (time.monotonic() - started) * 1000,
                [
                    "tool execution timed out",
                    *(
                        [
                            "network-dependent check may be unavailable in the current environment"
                        ]
                        if invocation.environment_dependency != "NONE"
                        else []
                    ),
                ],
                arguments=requested_arguments,
                environment_limited=invocation.environment_dependency != "NONE",
            )
        except OSError as exc:
            return self._result(
                descriptor,
                argv,
                NativeToolStatus.FAILED,
                "",
                str(exc),
                (time.monotonic() - started) * 1000,
                ["remote tool execution failed"],
                arguments=requested_arguments,
            )
        no_output = not stdout.strip() and not stderr.strip()
        unavailable = returncode in invocation.unavailable_return_codes and no_output
        status = (
            NativeToolStatus.SUCCEEDED
            if returncode == 0
            else NativeToolStatus.UNAVAILABLE
            if unavailable
            else NativeToolStatus.FAILED
        )
        limitations = (
            []
            if status == NativeToolStatus.SUCCEEDED
            else [
                (
                    f"remote command exited with return code {returncode}; "
                    "environment resource is unavailable"
                    if status == NativeToolStatus.UNAVAILABLE
                    else f"remote command exited with return code {returncode}"
                )
            ]
        )
        return self._result(
            descriptor,
            argv,
            status,
            stdout,
            stderr,
            (time.monotonic() - started) * 1000,
            limitations,
            arguments=requested_arguments,
            environment_limited=(
                invocation.environment_dependency != "NONE"
                and status != NativeToolStatus.SUCCEEDED
            ),
        )


def _family_tool(
    tool_id: str,
    family: str,
    evidence_kind: str,
    variants: dict[str, NativeToolInvocation],
    *,
    parameters: list[NativeToolParameter] | None = None,
    risk: str = "R0",
    max_duration_s: float = 8,
    max_output_bytes: int = 200_000,
    sensitive: bool = False,
    allowed_env_keys: list[str] | None = None,
) -> AgentNativeToolDescriptor:
    first = variants[sorted(variants)[0]]
    public_family = _PUBLIC_FAMILY_BY_PROVIDER.get(family, family)
    for private_prefix, public_prefix in _PUBLIC_TOOL_PREFIX_BY_PROVIDER.items():
        if tool_id.startswith(private_prefix):
            tool_id = public_prefix + tool_id[len(private_prefix) :]
            break
    return AgentNativeToolDescriptor(
        tool_id=tool_id,
        family=public_family,
        execution_path="MIDDLEWARE_CLI" if family == "ros" else "DIRECT_RUNNER",
        executable=first.executable,
        # The legacy fixed-argv fields remain populated for schema compatibility;
        # family invocations are selected from the validated variants map.
        argv_template=[first.executable],
        access="read",
        risk=risk,
        max_duration_s=max_duration_s,
        max_output_bytes=max_output_bytes,
        evidence_kind=evidence_kind,
        sensitive=sensitive,
        allowed_env_keys=allowed_env_keys or [],
        parameters=parameters or [],
        variants=variants,
    )


def reduced_agent_native_catalog() -> list[AgentNativeToolDescriptor]:
    """Return the curated family catalog used by v2 Probe sessions.

    The catalog deliberately exposes a small number of parameterized semantic families
    rather than one descriptor for every provider command.  Every mode remains a static
    argv shape and is validated before it reaches the host runner.  The concrete provider
    names used below are implementation details; the returned surface is platform-neutral.
    """

    token = NativeToolParameter(name="name", kind="token", pattern=r"[A-Za-z0-9_./:@+-]{1,128}")
    pid = NativeToolParameter(name="pid", kind="integer", max_length=9)
    path = NativeToolParameter(name="path", kind="path", max_length=512)
    topic = NativeToolParameter(
        name="topic", kind="token", pattern=r"/[A-Za-z0-9_./~-]{1,255}", max_length=256
    )
    ros_env = sorted(_SAFE_ENV_KEYS)
    tools = [
        _family_tool(
            "native.linux.host.inspect",
            "linux",
            "HOST_STATUS",
            {
                "inventory": NativeToolInvocation("uname", ["uname", "-a"]),
                "status": NativeToolInvocation("uname", ["uname", "-a"]),
                "time": NativeToolInvocation("date", ["date", "-Is"]),
                "uptime": NativeToolInvocation("uptime", ["uptime"]),
            },
        ),
        _family_tool(
            "native.linux.resource.snapshot",
            "linux",
            "RESOURCE_SNAPSHOT",
            {
                "cpu": NativeToolInvocation("nproc", ["nproc"]),
                "disk": NativeToolInvocation("df", ["df", "-P", "-h"]),
                "memory": NativeToolInvocation("free", ["free", "-h"]),
                "gpu": NativeToolInvocation("nvidia-smi", ["nvidia-smi"]),
            },
            max_output_bytes=300_000,
        ),
        _family_tool(
            "native.linux.process.inspect",
            "linux",
            "PROCESS_STATUS",
            {
                "inspect": NativeToolInvocation(
                    "ps", ["ps", "-p", "{pid}", "-o", "pid,ppid,stat,comm,args"], ["pid"]
                ),
                "list": NativeToolInvocation("ps", ["ps", "-eo", "pid,comm,args"]),
                "resources": NativeToolInvocation(
                    "ps", ["ps", "-p", "{pid}", "-o", "pid,%cpu,%mem,etime,comm"], ["pid"]
                ),
            },
            parameters=[pid],
        ),
        _family_tool(
            "native.linux.process.logs",
            "linux",
            "PROCESS_LOG",
            {"tail": NativeToolInvocation("journalctl", ["journalctl", "-n", "100", "--no-pager"])},
            risk="R1",
            max_output_bytes=500_000,
            sensitive=True,
        ),
        _family_tool(
            "native.linux.service.inspect",
            "linux",
            "SERVICE_STATUS",
            {
                "inspect": NativeToolInvocation(
                    "systemctl", ["systemctl", "status", "{name}", "--no-pager"], ["name"]
                ),
                "list": NativeToolInvocation(
                    "systemctl", ["systemctl", "list-units", "--type=service", "--no-pager"]
                ),
            },
            parameters=[token],
        ),
        _family_tool(
            "native.linux.service.logs",
            "linux",
            "SERVICE_LOG",
            {
                "tail": NativeToolInvocation(
                    "journalctl",
                    ["journalctl", "-u", "{name}", "-n", "100", "--no-pager"],
                    ["name"],
                )
            },
            parameters=[token],
            risk="R1",
            max_output_bytes=500_000,
            sensitive=True,
        ),
        _family_tool(
            "native.linux.container.inspect",
            "linux",
            "CONTAINER_STATUS",
            {
                "inspect": NativeToolInvocation(
                    "docker", ["docker", "inspect", "{name}"], ["name"]
                ),
                "list": NativeToolInvocation("docker", ["docker", "ps", "--no-trunc"]),
                "stats": NativeToolInvocation(
                    "docker", ["docker", "stats", "--no-stream", "{name}"], ["name"]
                ),
            },
            parameters=[token],
        ),
        _family_tool(
            "native.linux.container.logs",
            "linux",
            "CONTAINER_LOG",
            {
                "tail": NativeToolInvocation(
                    "docker", ["docker", "logs", "--tail", "100", "{name}"], ["name"]
                )
            },
            parameters=[token],
            risk="R1",
            max_output_bytes=500_000,
            sensitive=True,
        ),
        _family_tool(
            "native.linux.schedule.inspect",
            "linux",
            "SCHEDULE_STATUS",
            {
                "inspect": NativeToolInvocation(
                    "systemctl", ["systemctl", "status", "{name}", "--no-pager"], ["name"]
                ),
                "list": NativeToolInvocation(
                    "systemctl", ["systemctl", "list-timers", "--all", "--no-pager"]
                ),
            },
            parameters=[token],
        ),
        _family_tool(
            "native.linux.binary.inspect",
            "linux",
            "BINARY_STATUS",
            {
                "describe": NativeToolInvocation("file", ["file", "--brief", "{path}"], ["path"]),
                "verify": NativeToolInvocation("sha256sum", ["sha256sum", "{path}"], ["path"]),
            },
            parameters=[path],
        ),
        _family_tool(
            "native.linux.package.inspect",
            "linux",
            "PACKAGE_STATUS",
            {
                "inspect": NativeToolInvocation(
                    "dpkg-query", ["dpkg-query", "-W", "{name}"], ["name"]
                ),
                "verify": NativeToolInvocation("dpkg", ["dpkg", "-V", "{name}"], ["name"]),
            },
            parameters=[token],
        ),
        _family_tool(
            "native.linux.config.inspect",
            "linux",
            "CONFIG_STATUS",
            {
                "diff": NativeToolInvocation("stat", ["stat", "{path}"], ["path"]),
                "inspect": NativeToolInvocation("sed", ["sed", "-n", "1,200p", "{path}"], ["path"]),
                "locate": NativeToolInvocation("readlink", ["readlink", "-f", "{path}"], ["path"]),
                "validate": NativeToolInvocation("stat", ["stat", "{path}"], ["path"]),
            },
            parameters=[path],
            sensitive=True,
        ),
        _family_tool(
            "native.linux.file.inspect",
            "linux",
            "FILE_STATUS",
            {
                "hash": NativeToolInvocation("sha256sum", ["sha256sum", "{path}"], ["path"]),
                "list": NativeToolInvocation("ls", ["ls", "-la", "{path}"], ["path"]),
                "read": NativeToolInvocation("sed", ["sed", "-n", "1,200p", "{path}"], ["path"]),
                "stat": NativeToolInvocation("stat", ["stat", "{path}"], ["path"]),
            },
            parameters=[path],
            risk="R1",
            max_output_bytes=500_000,
            sensitive=True,
        ),
        _family_tool(
            "native.linux.network.snapshot",
            "linux",
            "NETWORK_SNAPSHOT",
            {
                "connections": NativeToolInvocation("ss", ["ss", "-tunap"]),
                "dns": NativeToolInvocation("resolvectl", ["resolvectl", "status"]),
                "interfaces": NativeToolInvocation("ip", ["ip", "-details", "address"]),
                "listeners": NativeToolInvocation("ss", ["ss", "-ltnp"]),
                "routes": NativeToolInvocation("ip", ["ip", "route"]),
                "statistics": NativeToolInvocation("ip", ["ip", "-s", "link"]),
            },
            max_output_bytes=400_000,
            sensitive=True,
        ),
        _family_tool(
            "native.linux.log.query",
            "linux",
            "SYSTEM_LOG",
            {
                "follow": NativeToolInvocation(
                    "journalctl", ["journalctl", "-n", "200", "--no-pager"]
                ),
                "query": NativeToolInvocation(
                    "journalctl", ["journalctl", "-n", "200", "--no-pager"]
                )
            },
            risk="R1",
            max_output_bytes=600_000,
            sensitive=True,
        ),
        _family_tool(
            "native.ros.graph.inspect",
            "ros",
            "ROS_GRAPH",
            {
                "actions": NativeToolInvocation("ros2", ["ros2", "action", "list"]),
                "action_describe": NativeToolInvocation(
                    "ros2", ["ros2", "action", "info", "{name}"], ["name"]
                ),
                "action_status": NativeToolInvocation(
                    "ros2", ["ros2", "action", "info", "{name}"], ["name"]
                ),
                "clock": NativeToolInvocation(
                    "ros2", ["ros2", "topic", "echo", "--once", "/clock"]
                ),
                "diagnostics": NativeToolInvocation(
                    "ros2", ["ros2", "topic", "echo", "--once", "/diagnostics"]
                ),
                "graph": NativeToolInvocation("ros2", ["ros2", "node", "list"]),
                "nodes": NativeToolInvocation("ros2", ["ros2", "node", "list"]),
                "node_lifecycle": NativeToolInvocation(
                    "ros2", ["ros2", "lifecycle", "get", "{name}"], ["name"]
                ),
                "node_status": NativeToolInvocation(
                    "ros2", ["ros2", "node", "info", "{name}"], ["name"]
                ),
                "parameters": NativeToolInvocation(
                    "ros2", ["ros2", "param", "list", "{name}"], ["name"]
                ),
                "parameter_describe": NativeToolInvocation(
                    "ros2",
                    ["ros2", "param", "describe", "{name}", "{parameter}"],
                    ["name", "parameter"],
                ),
                "parameter_dump": NativeToolInvocation(
                    "ros2", ["ros2", "param", "dump", "{name}"], ["name"]
                ),
                "parameter_get": NativeToolInvocation(
                    "ros2", ["ros2", "param", "get", "{name}", "{parameter}"],
                    ["name", "parameter"],
                ),
                "services": NativeToolInvocation("ros2", ["ros2", "service", "list"]),
                "service_describe": NativeToolInvocation(
                    "ros2", ["ros2", "service", "type", "{name}"], ["name"]
                ),
                "topics": NativeToolInvocation("ros2", ["ros2", "topic", "list"]),
                "topic_describe": NativeToolInvocation(
                    "ros2", ["ros2", "topic", "info", "{topic}"], ["topic"]
                ),
                "node_describe": NativeToolInvocation(
                    "ros2", ["ros2", "node", "info", "{name}"], ["name"]
                ),
            },
            parameters=[token, topic, NativeToolParameter(name="parameter")],
            allowed_env_keys=ros_env,
            max_output_bytes=400_000,
        ),
        _family_tool(
            "native.ros.observe",
            "ros",
            "ROS_OBSERVATION",
            {
                "bandwidth": NativeToolInvocation(
                    "ros2", ["ros2", "topic", "bw", "{topic}"], ["topic"]
                ),
                "rate": NativeToolInvocation("ros2", ["ros2", "topic", "hz", "{topic}"], ["topic"]),
                "sample": NativeToolInvocation(
                    "ros2", ["ros2", "topic", "echo", "--once", "{topic}"], ["topic"]
                ),
                "watch": NativeToolInvocation(
                    "ros2", ["ros2", "topic", "echo", "--once", "/diagnostics"]
                ),
            },
            parameters=[topic],
            risk="R1",
            max_duration_s=30,
            max_output_bytes=500_000,
            allowed_env_keys=ros_env,
        ),
        _family_tool(
            "native.ros.tf.inspect",
            "ros",
            "ROS_TF",
            {
                "lookup": NativeToolInvocation(
                    "ros2",
                    ["ros2", "run", "tf2_ros", "tf2_echo", "{target}", "{source}"],
                    ["target", "source"],
                ),
                "monitor": NativeToolInvocation(
                    "ros2", ["ros2", "topic", "echo", "--once", "/tf"]
                ),
                "snapshot": NativeToolInvocation(
                    "ros2", ["ros2", "topic", "echo", "--once", "/tf"]
                ),
                "tree": NativeToolInvocation("ros2", ["ros2", "topic", "echo", "--once", "/tf"]),
            },
            parameters=[
                NativeToolParameter(name="target", kind="token", pattern=r"[A-Za-z0-9_/~-]{1,128}"),
                NativeToolParameter(name="source", kind="token", pattern=r"[A-Za-z0-9_/~-]{1,128}"),
            ],
            risk="R1",
            max_duration_s=30,
            allowed_env_keys=ros_env,
        ),
        _family_tool(
            "native.ros.bag.inspect",
            "ros",
            "ROS_BAG",
            {"info": NativeToolInvocation("ros2", ["ros2", "bag", "info", "{path}"], ["path"])},
            parameters=[path],
            max_output_bytes=400_000,
            allowed_env_keys=ros_env,
        ),
        _family_tool(
            "native.middleware.snapshot",
            "ros",
            "MIDDLEWARE_STATUS",
            {
                "status": NativeToolInvocation(
                    "ros2",
                    ["ros2", "doctor", "--report"],
                    environment_dependency="NETWORK",
                )
            },
            allowed_env_keys=ros_env,
            max_output_bytes=500_000,
        ),
        _family_tool(
            "native.hw.inventory",
            "hw",
            "HARDWARE_INVENTORY",
            {
                "usb": NativeToolInvocation(
                    "lsusb", ["lsusb"], unavailable_return_codes=[1]
                ),
                "pci": NativeToolInvocation("lspci", ["lspci"]),
            },
            max_output_bytes=200_000,
        ),
        _family_tool(
            "native.hw.status",
            "hw",
            "HARDWARE_STATUS",
            {"udev": NativeToolInvocation("udevadm", ["udevadm", "info", "--export-db"])},
            risk="R1",
            max_output_bytes=500_000,
            sensitive=True,
        ),
    ]
    return sorted(tools, key=lambda item: item.tool_id)
