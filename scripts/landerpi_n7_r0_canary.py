"""Strict, read-only N7-R0 LanderPi canary orchestration.

The live adapter is intentionally fail-closed until targetd exposes every
control surface required by this transcript.  The reusable harness is tested
against an in-memory channel backed by the real targetd daemon/service CALL
path; that test mode is reported as ``SIMULATED_PASS`` and can never be
mistaken for target evidence.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import queue
import re
import subprocess
import tarfile
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Protocol

from rolo.dsl.target_conformance import TargetConformanceReport
from rolo.mvp.artifacts import ArtifactIndex, build_artifact_index
from rolo.mvp.certify import preflight_new_artifact_paths, write_new_artifact
from rolo.mvp.contracts import CertificationCase, CertificationSuite
from rolo.releases import ReleaseBoundCertify, ToolRelease
from rolo.targetd import (
    ExecutionBundleManifest,
    ExecutionRequest,
    FrameKind,
    ProtocolFrame,
    Ros2RuntimeSnapshot,
    TargetdAuthorityActivationRequest,
    TargetdExecutionAuthority,
    TargetdMappingCancelRequest,
    TargetdV2CertifyAdapter,
    TargetdV2CertifyResponse,
    TargetdVerifiedReleaseProvisionRequest,
    decode_frame,
    encode_frame,
)

SCHEMA_VERSION = "rolo-landerpi-n7-r0-canary/v1"
TARGET_ID = "mentorpi"
CONTAINER = "MentorPi"
TOPIC = "/odom"
TOOL_ID = "app.navigation.odom.observe"
OPERATION_KIND = "OBSERVE"
PROVIDER_ID = "ros2-readonly"
PROVIDER_OPERATION = "odom.sample"
ACCESS = "read"
RISK = "R0"
MAX_PACKAGE_BYTES = 32 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_RESULT_BYTES = 64 * 1024
MAX_ADMISSION_LEDGER_BYTES = 1024 * 1024
CERTIFY_CASES = 10
EXPECTED_PROVIDER_CALLS = 1 + 1 + CERTIFY_CASES  # T3 + Trace + Certify
EXPECTED_TARGETD_CALL_PROVIDER_INVOCATIONS = 1 + CERTIFY_CASES

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_REMOTE_ERROR = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")


class CanaryBlocked(RuntimeError):
    """Stable fail-closed diagnostic from the canary boundary."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class PinnedCanaryChannel(Protocol):
    """One physical SSH stdio channel used for the complete transcript."""

    channel_id: str

    def stage_package(
        self,
        *,
        container: str,
        stage_root: str,
        archive: bytes,
        expanded_bytes: int,
        bind_snapshot: Callable[[Mapping[str, Any]], N7R0SnapshotBinding],
    ) -> Mapping[str, Any]: ...

    def exchange(
        self,
        kind: str,
        payload: Mapping[str, Any],
        *,
        run_id: str | None = None,
    ) -> Mapping[str, Any]: ...

    def call_certification(
        self,
        request: ExecutionRequest,
    ) -> TargetdV2CertifyResponse: ...

    def cleanup_stage(
        self,
        *,
        container: str,
        stage_root: str,
    ) -> Mapping[str, Any]: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class VerifiedExecutionPlan:
    """Verified Release plus the v2 CALL identities derived from it."""

    release: ToolRelease
    release_digest: str
    target_conformance_digest: str
    manifest: ExecutionBundleManifest
    source: bytes
    bridge_proof: Mapping[str, Any]
    publisher: Any


ReleaseBuilder = Callable[
    [Mapping[str, Any], TargetConformanceReport, str],
    VerifiedExecutionPlan,
]


@dataclass(frozen=True)
class N7R0SnapshotBinding:
    """Host artifacts derived only after target-owned snapshot capture."""

    admission_ledger: bytes
    dsl_put_payload: Mapping[str, Any]
    compile_payload: Mapping[str, Any]
    release_builder: ReleaseBuilder


@dataclass(frozen=True)
class N7R0Inputs:
    session_id: str
    certify_run_id: str
    target_id: str
    surface_digest: str
    archive: bytes
    bind_snapshot: Callable[[Mapping[str, Any]], N7R0SnapshotBinding]


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256(encoded)


def stage_root_for(session_id: str) -> str:
    if _ID.fullmatch(session_id) is None:
        raise CanaryBlocked("N7_R0_SESSION_INVALID", "session id is not protocol-safe")
    suffix = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:20]
    return f"/dev/shm/rolo-n7-r0-{suffix}"


def inspect_package(archive: bytes) -> int:
    """Validate the bounded tar without extracting it and return expanded bytes."""

    if not archive or len(archive) > MAX_PACKAGE_BYTES:
        raise CanaryBlocked(
            "N7_R0_PACKAGE_LIMIT",
            f"package must be between 1 and {MAX_PACKAGE_BYTES} bytes",
        )
    expanded = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as package:
            members = package.getmembers()
            if not members:
                raise CanaryBlocked("N7_R0_PACKAGE_INVALID", "package is empty")
            for member in members:
                path = PurePosixPath(member.name)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or not path.parts
                    or path.parts[0] != "rolo"
                    or "\\" in member.name
                    or any(":" in part for part in path.parts)
                    or member.issym()
                    or member.islnk()
                    or member.isdev()
                ):
                    raise CanaryBlocked(
                        "N7_R0_PACKAGE_INVALID",
                        "package contains an unsafe or out-of-root member",
                    )
                if member.isfile():
                    expanded += member.size
                    if expanded > MAX_EXPANDED_BYTES:
                        raise CanaryBlocked(
                            "N7_R0_EXPANDED_LIMIT",
                            f"expanded package exceeds {MAX_EXPANDED_BYTES} bytes",
                        )
    except (tarfile.TarError, OSError) as exc:
        raise CanaryBlocked("N7_R0_PACKAGE_INVALID", "package is not a valid tar archive") from exc
    return expanded


_REMOTE_BOOTSTRAP_SOURCE = r"""
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import threading

MAX_RECORD = 8 * 1024 * 1024
MAX_PACKAGE = 32 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024
MAX_LEDGER = 1024 * 1024
MAX_SIGNING_KEY = 4096
ROS2_PATH = "/opt/ros/humble/bin/ros2"
ROS2_SETUP = "/opt/ros/humble/setup.bash"
MAX_CONTROL = 64 * 1024
MAX_ROS_OUTPUT = 32 * 1024
TOTAL_DEADLINE_SECONDS = 600

def deadline_expired(_signum, _frame):
    raise TimeoutError("BOOTSTRAP_TOTAL_DEADLINE")

def safe_error_code(error):
    text = str(error)
    if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", text):
        return text
    return type(error).__name__

if hasattr(signal, "SIGALRM"):
    signal.signal(signal.SIGALRM, deadline_expired)
    signal.alarm(TOTAL_DEADLINE_SECONDS)

def read_exact(stream, size):
    chunks = []
    while size:
        chunk = stream.read(size)
        if not chunk:
            break
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)

def read_record(stream):
    header = read_exact(stream, 4)
    if len(header) != 4:
        raise EOFError("record header")
    size = int.from_bytes(header, "big")
    if size < 2 or size > MAX_RECORD:
        raise ValueError("record size")
    payload = read_exact(stream, size)
    if len(payload) != size:
        raise EOFError("record payload")
    return payload

def write_record(stream, payload):
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_CONTROL:
        raise ValueError("control record size")
    stream.write(len(encoded).to_bytes(4, "big") + encoded)
    stream.flush()

def parse_args(values):
    test_parent = None
    test_ros_script = None
    index = 0
    while index < len(values) and values[index] != "--":
        if values[index] == "--test-stage-parent" and index + 1 < len(values):
            test_parent = values[index + 1]
            index += 2
        elif values[index] == "--test-ros2-python-script" and index + 1 < len(values):
            test_ros_script = values[index + 1]
            index += 2
        else:
            raise ValueError("bootstrap argv")
    if index >= len(values) or values[index] != "--" or index + 1 >= len(values):
        raise ValueError("bootstrap child argv")
    return test_parent, test_ros_script, values[index + 1:]

def ros_command(test_script, *arguments):
    if test_script:
        argv = [sys.executable, test_script, *arguments]
    else:
        argv = [
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            "set -e; . /opt/ros/humble/setup.bash; exec /opt/ros/humble/bin/ros2 \"$@\"",
            "rolo-n7-r0-ros2",
            *arguments,
        ]
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    outputs = [bytearray(), bytearray()]
    overflow = threading.Event()
    def drain(stream, output):
        while True:
            chunk = stream.read(4096)
            if not chunk:
                return
            if len(output) + len(chunk) > MAX_ROS_OUTPUT:
                overflow.set()
                process.kill()
                return
            output.extend(chunk)
    readers = [
        threading.Thread(target=drain, args=(process.stdout, outputs[0]), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, outputs[1]), daemon=True),
    ]
    for reader in readers:
        reader.start()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)
    for reader in readers:
        reader.join(timeout=2)
    if process.returncode != 0 or overflow.is_set():
        raise RuntimeError("ROS2_SNAPSHOT_COMMAND_FAILED")
    return bytes(outputs[0]).decode("utf-8", errors="strict").splitlines()

def capture_snapshot(root, test_script):
    if test_script is None:
        import pwd
        if pwd.getpwuid(os.geteuid()).pw_name != "ubuntu":
            raise RuntimeError("ROS2_SNAPSHOT_USER_MISMATCH")
        if not pathlib.Path(ROS2_SETUP).is_file() or not os.access(ROS2_PATH, os.X_OK):
            raise RuntimeError("ROS2_HUMBLE_RUNTIME_MISSING")
    topic_lines = ros_command(
        test_script,
        "topic",
        "list",
        "-t",
        "--no-daemon",
        "--spin-time",
        "5",
    )
    odom = False
    for line in topic_lines:
        if line.strip() == "/odom [nav_msgs/msg/Odometry]":
            odom = True
            break
    if not odom:
        raise RuntimeError("ROS2_ODOM_NOT_OBSERVED")
    node_lines = ros_command(
        test_script,
        "node",
        "list",
        "--no-daemon",
        "--spin-time",
        "5",
    )
    nodes = sorted({line.strip() for line in node_lines if line.strip().startswith("/")})
    if (
        len(nodes) > 128
        or any(
            len(node) > 256
            or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_/~" for character in node)
            for node in nodes
        )
    ):
        raise RuntimeError("ROS2_NODE_LIST_INVALID")
    identity = {
        "distro": "humble",
        "ros2_path": ROS2_PATH,
        "topics": [{"name": "/odom", "interface_type": "nav_msgs/msg/Odometry"}],
        "nodes": nodes,
        "packages": [],
        "executor_user": "ubuntu",
    }
    digest = "sha256:" + hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    snapshot = {
        "schema_version": "rolo-ros2-runtime-snapshot/v1",
        **identity,
        "runtime_digest": digest,
    }
    runtime_dir = root / "runtime"
    runtime_dir.mkdir(mode=0o700)
    snapshot_path = runtime_dir / "ros2-snapshot.json"
    snapshot_path.write_text(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    os.chmod(snapshot_path, 0o600)
    return digest, snapshot

def extract_package(root, archive_path, expected_expanded):
    expanded = 0
    with tarfile.open(archive_path, mode="r:*") as package:
        members = package.getmembers()
        if not members or len(members) > 8192:
            raise ValueError("package members")
        for member in members:
            path = pathlib.PurePosixPath(member.name)
            if (
                path.is_absolute()
                or not path.parts
                or path.parts[0] != "rolo"
                or ".." in path.parts
                or "\\" in member.name
                or any(":" in part for part in path.parts)
                or member.issym()
                or member.islnk()
                or member.isdev()
                or not (member.isdir() or member.isfile())
            ):
                raise ValueError("package member")
            target = root.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            expanded += member.size
            if expanded > MAX_EXPANDED:
                raise ValueError("expanded limit")
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = package.extractfile(member)
            if source is None:
                raise ValueError("package file")
            with source, target.open("xb") as output:
                remaining = member.size
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise EOFError("package file")
                    output.write(chunk)
                    remaining -= len(chunk)
                if source.read(1):
                    raise ValueError("package file overflow")
            os.chmod(target, 0o600)
    if expanded != expected_expanded:
        raise ValueError("expanded size")

def stop_child(child):
    if child is None:
        return
    if child.stdin is not None:
        try:
            child.stdin.close()
        except OSError:
            pass
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        child.terminate()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=2)

test_parent, test_ros_script, child_argv = parse_args(sys.argv[1:])
logical_root = None
physical_root = None
root_created = False
stage_sent = False
child = None
try:
    metadata = json.loads(read_record(sys.stdin.buffer).decode("utf-8"))
    logical_root = metadata.get("stage_root")
    stage_nonce = metadata.get("stage_nonce")
    if (
        metadata.get("schema_version") != "rolo-n7-r0-stage-request/v1"
        or metadata.get("container") != "MentorPi"
        or not isinstance(logical_root, str)
        or len(logical_root) != len("/dev/shm/rolo-n7-r0-") + 20
        or not logical_root.startswith("/dev/shm/rolo-n7-r0-")
        or any(character not in "0123456789abcdef" for character in logical_root[-20:])
        or not isinstance(stage_nonce, str)
        or len(stage_nonce) != 64
        or any(character not in "0123456789abcdef" for character in stage_nonce)
    ):
        raise ValueError("stage identity")
    archive_bytes = metadata.get("archive_bytes")
    expanded_bytes = metadata.get("expanded_bytes")
    if (
        not isinstance(archive_bytes, int)
        or not 0 < archive_bytes <= MAX_PACKAGE
        or not isinstance(expanded_bytes, int)
        or not 0 <= expanded_bytes <= MAX_EXPANDED
    ):
        raise ValueError("stage bounds")
    archive = read_exact(sys.stdin.buffer, archive_bytes)
    if (
        len(archive) != archive_bytes
        or "sha256:" + hashlib.sha256(archive).hexdigest() != metadata.get("package_sha256")
    ):
        raise ValueError("stage digest")
    if test_parent is None:
        physical_root = pathlib.Path(logical_root)
    else:
        parent = pathlib.Path(test_parent).resolve(strict=True)
        physical_root = parent / pathlib.PurePosixPath(logical_root).name
    free_bytes = shutil.disk_usage(physical_root.parent).free
    if free_bytes < archive_bytes + expanded_bytes + MAX_LEDGER + 64 * 1024:
        raise RuntimeError("TMPFS_CAPACITY_INSUFFICIENT")
    physical_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    root_created = True
    owner_path = physical_root / ".rolo-stage-owner"
    owner_path.write_text(stage_nonce + "\n", encoding="ascii")
    os.chmod(owner_path, 0o600)
    archive_path = physical_root / ".package.tar"
    archive_path.write_bytes(archive)
    os.chmod(archive_path, 0o600)
    extract_package(physical_root, archive_path, expanded_bytes)
    archive_path.unlink()
    snapshot_digest, snapshot = capture_snapshot(physical_root, test_ros_script)
    write_record(
        sys.stdout.buffer,
        {
            "schema_version": "rolo-n7-r0-snapshot-challenge/v1",
            "ok": True,
            "container": "MentorPi",
            "stage_root": logical_root,
            "package_sha256": metadata["package_sha256"],
            "archive_bytes": archive_bytes,
            "expanded_bytes": expanded_bytes,
            "tmpfs_free_bytes": free_bytes,
            "ros2_snapshot_digest": snapshot_digest,
            "snapshot": snapshot,
        },
    )
    commit = json.loads(read_record(sys.stdin.buffer).decode("utf-8"))
    ledger_bytes = commit.get("admission_ledger_bytes")
    signing_key_bytes = commit.get("signing_key_bytes", 0)
    if (
        commit.get("schema_version") != "rolo-n7-r0-ledger-commit/v1"
        or commit.get("container") != "MentorPi"
        or commit.get("stage_root") != logical_root
        or not isinstance(ledger_bytes, int)
        or not 0 < ledger_bytes <= MAX_LEDGER
        or not isinstance(signing_key_bytes, int)
        or not 0 <= signing_key_bytes <= MAX_SIGNING_KEY
    ):
        raise ValueError("ledger commit")
    ledger = read_exact(sys.stdin.buffer, ledger_bytes)
    signing_key = read_exact(sys.stdin.buffer, signing_key_bytes)
    if (
        len(ledger) != ledger_bytes
        or "sha256:" + hashlib.sha256(ledger).hexdigest()
        != commit.get("admission_ledger_sha256")
        or len(signing_key) != signing_key_bytes
        or (
            signing_key_bytes
            and "sha256:" + hashlib.sha256(signing_key).hexdigest()
            != commit.get("signing_key_sha256")
        )
    ):
        raise ValueError("ledger digest")
    authority_dir = physical_root / "authority"
    authority_dir.mkdir(mode=0o700)
    ledger_path = authority_dir / "mapping-confirmations.jsonl"
    ledger_path.write_bytes(ledger)
    os.chmod(ledger_path, 0o600)
    if signing_key:
        secret_dir = physical_root / "secrets"
        secret_dir.mkdir(mode=0o700)
        signing_key_path = secret_dir / "signing-key"
        signing_key_path.write_bytes(signing_key)
        os.chmod(signing_key_path, 0o600)
    write_record(
        sys.stdout.buffer,
        {
            "schema_version": "rolo-n7-r0-stage-receipt/v1",
            "ok": True,
            "container": "MentorPi",
            "stage_root": logical_root,
            "package_sha256": metadata["package_sha256"],
            "admission_ledger_sha256": commit["admission_ledger_sha256"],
            "archive_bytes": archive_bytes,
            "expanded_bytes": expanded_bytes,
            "tmpfs_free_bytes": free_bytes,
            "ros2_snapshot_digest": snapshot_digest,
            "ros2_path": ROS2_PATH,
            "executor_user": "ubuntu",
            "odom_observed": True,
        },
    )
    stage_sent = True
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(physical_root)
    child = subprocess.Popen(
        child_argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,
        cwd=physical_root,
        env=environment,
    )
    while True:
        header = read_exact(sys.stdin.buffer, 4)
        if not header:
            break
        size = int.from_bytes(header, "big")
        if size < 2 or size > MAX_RECORD:
            raise ValueError("targetd request size")
        request_payload = read_exact(sys.stdin.buffer, size)
        if len(request_payload) != size:
            raise EOFError("targetd request")
        request = json.loads(request_payload.decode("utf-8"))
        child.stdin.write(header + request_payload)
        child.stdin.flush()
        while True:
            response_payload = read_record(child.stdout)
            sys.stdout.buffer.write(len(response_payload).to_bytes(4, "big") + response_payload)
            sys.stdout.buffer.flush()
            response = json.loads(response_payload.decode("utf-8"))
            if response.get("kind") != "EVENT":
                break
        if request.get("kind") == "CLOSE_SESSION":
            break
    stop_child(child)
    child = None
    shutil.rmtree(physical_root)
    root_created = False
    residual = int(physical_root.exists() or physical_root.is_symlink())
    write_record(
        sys.stdout.buffer,
        {
            "schema_version": "rolo-n7-r0-cleanup-receipt/v1",
            "ok": residual == 0,
            "container": "MentorPi",
            "stage_root": logical_root,
            "residual_count": residual,
        },
    )
    if hasattr(signal, "SIGALRM"):
        signal.alarm(0)
except Exception as error:
    stop_child(child)
    residual = 0
    if physical_root is not None:
        if root_created:
            try:
                shutil.rmtree(physical_root)
            except FileNotFoundError:
                pass
            except Exception:
                residual = 1
        residual = max(residual, int(physical_root.exists() or physical_root.is_symlink()))
    schema = (
        "rolo-n7-r0-cleanup-receipt/v1"
        if stage_sent
        else "rolo-n7-r0-stage-receipt/v1"
    )
    write_record(
        sys.stdout.buffer,
        {
            "schema_version": schema,
            "ok": False,
            "container": "MentorPi",
            "stage_root": logical_root,
            "residual_count": residual,
            "error": safe_error_code(error),
        },
    )
    if hasattr(signal, "SIGALRM"):
        signal.alarm(0)
    raise SystemExit(2)
"""


_REMOTE_DAEMON_LAUNCHER_SOURCE = r"""
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
key_path = root / "secrets" / "signing-key"
key = key_path.read_text(encoding="utf-8")
key_path.unlink()
sys.argv = [
    "rolo.targetd.daemon",
    "--target-id", "mentorpi",
    "--state-root", str(root / "state"),
    "--signing-key", key,
    "--execute-calls",
    "--admission-store", str(root / "authority"),
    "--execution-authority-root", str(root / "execution-authority"),
    "--release-catalog-root", str(root / "catalog"),
    "--dsl-cache-dir", str(root / "dsl-cache"),
    "--ros2-snapshot", str(root / "runtime" / "ros2-snapshot.json"),
    "--execute-readonly",
    "--provider", "ros2-readonly",
    "--container", "MentorPi",
]
from rolo.targetd.daemon import main
main()
"""


_REMOTE_FALLBACK_CLEANUP_SOURCE = r"""
import json
import pathlib
import re
import shutil
import sys

root_text, nonce = sys.argv[1:]
valid = (
    re.fullmatch(r"/dev/shm/rolo-n7-r0-[0-9a-f]{20}", root_text) is not None
    and re.fullmatch(r"[0-9a-f]{64}", nonce) is not None
)
root = pathlib.Path(root_text)
owned = False
if valid and root.exists() and not root.is_symlink() and root.is_dir():
    marker = root / ".rolo-stage-owner"
    try:
        owned = marker.is_file() and not marker.is_symlink() and marker.read_text(
            encoding="ascii"
        ) == nonce + "\n"
    except OSError:
        owned = False
    if owned:
        shutil.rmtree(root)
residual = int(root.exists() or root.is_symlink())
print(json.dumps({
    "schema_version": "rolo-n7-r0-cleanup-fallback/v1",
    "ok": valid and residual == 0,
    "stage_root": root_text,
    "residual_count": residual,
    "owned_by_run": owned,
}, sort_keys=True, separators=(",", ":")))
raise SystemExit(0 if valid and residual == 0 else 2)
"""


def _read_exact(stream: Any, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _encode_control_record(payload: Mapping[str, Any]) -> bytes:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > MAX_RESULT_BYTES:
        raise CanaryBlocked("N7_R0_BOOTSTRAP_RECORD_LIMIT", "bootstrap record exceeds 64 KiB")
    return len(encoded).to_bytes(4, "big") + encoded


def _read_control_record(stream: Any) -> dict[str, Any]:
    header = _read_exact(stream, 4)
    if len(header) != 4:
        raise CanaryBlocked("N7_R0_BOOTSTRAP_TRUNCATED", "bootstrap record header is missing")
    size = int.from_bytes(header, "big")
    if not 2 <= size <= MAX_RESULT_BYTES:
        raise CanaryBlocked("N7_R0_BOOTSTRAP_RECORD_LIMIT", "bootstrap record size is invalid")
    encoded = _read_exact(stream, size)
    if len(encoded) != size:
        raise CanaryBlocked("N7_R0_BOOTSTRAP_TRUNCATED", "bootstrap record payload is missing")
    try:
        value = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise CanaryBlocked("N7_R0_BOOTSTRAP_INVALID", "bootstrap record is invalid") from exc
    if not isinstance(value, dict):
        raise CanaryBlocked("N7_R0_BOOTSTRAP_INVALID", "bootstrap record is not an object")
    return value


class PinnedSshCanaryChannel:
    """Stage and run targetd through one pinned SSH stdio process."""

    def __init__(
        self,
        process_argv: list[str],
        *,
        session_id: str,
        popen_factory: Callable[..., subprocess.Popen[bytes]] | None = None,
        io_timeout_s: float = 30.0,
        signing_key: bytes | None = None,
        fallback_executor: Any | None = None,
    ) -> None:
        if (
            not process_argv
            or any(not token or "\x00" in token for token in process_argv)
            or _ID.fullmatch(session_id) is None
            or not 0 < io_timeout_s <= 300
            or (
                signing_key is not None
                and (
                    not 16 <= len(signing_key) <= 4096
                    or any(character in signing_key for character in (0, 10, 13))
                )
            )
        ):
            raise ValueError("pinned canary process identity is invalid")
        self.process_argv = tuple(process_argv)
        self.session_id = session_id
        redacted_argv = list(process_argv)
        for index, token in enumerate(redacted_argv[:-1]):
            if token == "--signing-key":
                redacted_argv[index + 1] = "<redacted>"
        self.channel_id = "ssh-stdio:" + hashlib.sha256(
            json.dumps(redacted_argv, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self._popen_factory = popen_factory or subprocess.Popen
        self._process: subprocess.Popen[bytes] | None = None
        self._sequence = 0
        self._response_sequence = 0
        self._protocol_poisoned = False
        self._stage_root: str | None = None
        self._daemon_closed = False
        self._stage_complete = False
        self._cleanup_receipt: dict[str, Any] | None = None
        self._stderr = bytearray()
        self._stderr_thread: threading.Thread | None = None
        self._stdout_records: queue.Queue[bytes | BaseException] = queue.Queue(maxsize=32)
        self._stdout_thread: threading.Thread | None = None
        self._stdout_terminal_error: BaseException | None = None
        self._writer_thread: threading.Thread | None = None
        self._io_timeout_s = io_timeout_s
        self._signing_key = signing_key
        self._fallback_executor = fallback_executor
        self._stage_nonce = os.urandom(32).hex()

    @classmethod
    def from_ssh_executor(
        cls,
        executor: Any,
        *,
        session_id: str,
        signing_key: str,
    ) -> PinnedSshCanaryChannel:
        """Build the fixed live argv; opening remains lazy until staging."""

        root = stage_root_for(session_id)
        daemon_argv = [
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            'set -e; . /opt/ros/humble/setup.bash; exec "$@"',
            "rolo-n7-r0-targetd",
            "python3",
            "-c",
            _REMOTE_DAEMON_LAUNCHER_SOURCE,
            root,
        ]
        remote_argv = [
            "docker",
            "exec",
            "-i",
            "-u",
            "ubuntu",
            CONTAINER,
            "python3",
            "-c",
            _REMOTE_BOOTSTRAP_SOURCE,
            "--",
            *daemon_argv,
        ]
        return cls(
            executor.stdio_argv(remote_argv),
            session_id=session_id,
            signing_key=signing_key.encode("utf-8"),
            fallback_executor=executor,
        )

    def stage_package(
        self,
        *,
        container: str,
        stage_root: str,
        archive: bytes,
        expanded_bytes: int,
        bind_snapshot: Callable[[Mapping[str, Any]], N7R0SnapshotBinding],
    ) -> Mapping[str, Any]:
        if self._process is not None:
            raise CanaryBlocked("N7_R0_CHANNEL_REUSED", "pinned SSH process is already open")
        if container != CONTAINER or stage_root != stage_root_for(self.session_id):
            raise CanaryBlocked("N7_R0_STAGE_IDENTITY_INVALID", "stage target is not fixed")
        if inspect_package(archive) != expanded_bytes:
            raise CanaryBlocked("N7_R0_STAGE_SIZE_INVALID", "expanded package size differs")
        self._stage_root = stage_root
        self._process = self._popen_factory(
            list(self.process_argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        self._start_stdout_drain()
        self._start_stderr_drain()
        metadata = {
            "schema_version": "rolo-n7-r0-stage-request/v1",
            "container": CONTAINER,
            "stage_root": stage_root,
            "stage_nonce": self._stage_nonce,
            "package_sha256": _sha256(archive),
            "archive_bytes": len(archive),
            "expanded_bytes": expanded_bytes,
        }
        self._write_bytes(_encode_control_record(metadata) + archive)
        challenge = self._read_control_record()
        if challenge.get("ok") is not True:
            self._remember_failed_stage(challenge, stage_root=stage_root)
            raise CanaryBlocked(
                "N7_R0_STAGE_BLOCKED",
                str(challenge.get("error", "target bootstrap rejected stage"))[:512],
            )
        if (
            challenge.get("schema_version") != "rolo-n7-r0-snapshot-challenge/v1"
            or challenge.get("container") != CONTAINER
            or challenge.get("stage_root") != stage_root
            or challenge.get("package_sha256") != _sha256(archive)
            or challenge.get("archive_bytes") != len(archive)
            or challenge.get("expanded_bytes") != expanded_bytes
            or not isinstance(challenge.get("snapshot"), Mapping)
        ):
            raise CanaryBlocked(
                "N7_R0_SNAPSHOT_CHALLENGE_INVALID",
                "target snapshot challenge differs from the pinned stage",
            )
        material = bind_snapshot(challenge["snapshot"])
        if not isinstance(material, N7R0SnapshotBinding):
            raise CanaryBlocked(
                "N7_R0_SNAPSHOT_BINDING_INVALID",
                "snapshot binder returned an invalid contract",
            )
        admission_ledger = material.admission_ledger
        if not admission_ledger or len(admission_ledger) > MAX_ADMISSION_LEDGER_BYTES:
            raise CanaryBlocked("N7_R0_ADMISSION_LEDGER_INVALID", "admission ledger is not bounded")
        commit = {
                    "schema_version": "rolo-n7-r0-ledger-commit/v1",
                    "container": CONTAINER,
                    "stage_root": stage_root,
                    "admission_ledger_sha256": _sha256(admission_ledger),
                    "admission_ledger_bytes": len(admission_ledger),
        }
        signing_key = self._signing_key or b""
        if signing_key:
            commit.update(
                {
                    "signing_key_sha256": _sha256(signing_key),
                    "signing_key_bytes": len(signing_key),
                }
            )
        self._write_bytes(
            _encode_control_record(commit) + admission_ledger + signing_key
        )
        receipt = self._read_control_record()
        if receipt.get("ok") is not True:
            self._remember_failed_stage(receipt, stage_root=stage_root)
            raise CanaryBlocked(
                "N7_R0_STAGE_BLOCKED",
                str(receipt.get("error", "target bootstrap rejected bound ledger"))[:512],
            )
        self._stage_complete = True
        return receipt

    def exchange(
        self,
        kind: str,
        payload: Mapping[str, Any],
        *,
        run_id: str | None = None,
    ) -> Mapping[str, Any]:
        return self.exchange_frame(kind, payload, run_id=run_id).payload

    def exchange_frame(
        self,
        kind: str,
        payload: Mapping[str, Any],
        *,
        run_id: str | None = None,
    ) -> ProtocolFrame:
        """Exchange one frame and return the sequence-verified RESULT.

        This method owns the expected response counter.  In particular, a
        certification callback cannot manufacture its own
        ``sequence_correlated`` assertion after receiving only a payload.
        """

        if self._protocol_poisoned:
            raise CanaryBlocked(
                "N7_R0_CHANNEL_POISONED",
                "pinned protocol channel is terminal after an earlier frame failure",
            )
        try:
            return self._exchange_frame_once(kind, payload, run_id=run_id)
        except Exception:
            self._protocol_poisoned = True
            raise

    def _exchange_frame_once(
        self,
        kind: str,
        payload: Mapping[str, Any],
        *,
        run_id: str | None = None,
    ) -> ProtocolFrame:

        try:
            frame_kind = FrameKind(kind)
        except ValueError as exc:
            raise CanaryBlocked("N7_R0_FRAME_UNSUPPORTED", f"unsupported frame: {kind}") from exc
        frame = ProtocolFrame.create(
            kind=frame_kind,
            sequence=self._sequence,
            session_id=self.session_id,
            run_id=run_id,
            payload=dict(payload),
        )
        self._sequence += 1
        self._write_bytes(encode_frame(frame))
        deadline = time.monotonic() + self._io_timeout_s
        event_count = 0
        while True:
            response = self._receive_protocol_frame(deadline=deadline)
            if response.session_id != self.session_id or response.run_id != run_id:
                raise CanaryBlocked(
                    "N7_R0_PROTOCOL_IDENTITY_MISMATCH",
                    "targetd response session/run identity differs",
                )
            if response.kind == FrameKind.EVENT:
                event_count += 1
                if (
                    frame_kind != FrameKind.CALL
                    or response.payload.get("call_id") != payload.get("idempotency_key")
                    or event_count > 4
                ):
                    raise CanaryBlocked(
                        "N7_R0_PROTOCOL_EVENT_MISMATCH",
                        "targetd EVENT does not belong to the current CALL",
                    )
            else:
                break
        if (
            response.kind != FrameKind.RESULT
            or response.payload.get("request_kind") != frame_kind.value
        ):
            raise CanaryBlocked("N7_R0_PROTOCOL_INVALID", "targetd response identity differs")
        if frame_kind == FrameKind.CLOSE_SESSION:
            self._daemon_closed = True
        return response

    def call_certification(
        self,
        request: ExecutionRequest,
    ) -> TargetdV2CertifyResponse:
        """Return CALL metadata only after this channel proves sequencing."""

        if request.session_id != self.session_id:
            raise CanaryBlocked(
                "N7_R0_CERTIFY_SESSION_MISMATCH",
                "formal Certify request does not belong to the pinned session",
            )
        frame = self.exchange_frame(
            FrameKind.CALL.value,
            request.model_dump(mode="json"),
            run_id=request.run_id,
        )
        return TargetdV2CertifyResponse(
            frame=frame,
            sequence_correlated=True,
        )

    def cleanup_stage(
        self,
        *,
        container: str,
        stage_root: str,
    ) -> Mapping[str, Any]:
        if container != CONTAINER or stage_root != self._stage_root:
            raise CanaryBlocked("N7_R0_CLEANUP_IDENTITY_INVALID", "cleanup target differs")
        if self._cleanup_receipt is not None:
            if self._cleanup_receipt["residual_count"] == 0:
                return self._cleanup_receipt
            return self._fallback_cleanup(stage_root)
        if not self._daemon_closed:
            try:
                self._stream("stdin").close()
            except OSError:
                pass
        try:
            receipt = self._read_control_record()
        except CanaryBlocked:
            return self._fallback_cleanup(stage_root)
        if not self._stage_complete:
            self._remember_failed_stage(receipt, stage_root=stage_root)
            if self._cleanup_receipt is not None and self._cleanup_receipt["residual_count"] == 0:
                return self._cleanup_receipt
            raise CanaryBlocked(
                "N7_R0_CLEANUP_INCOMPLETE",
                "partial stage cleanup did not prove zero residuals",
            )
        self._wait_process()
        residual = receipt.get("residual_count") if isinstance(receipt, dict) else None
        if (
            receipt.get("schema_version") != "rolo-n7-r0-cleanup-receipt/v1"
            or receipt.get("container") != CONTAINER
            or receipt.get("stage_root") != stage_root
            or receipt.get("ok") is not True
            or not isinstance(residual, int)
            or isinstance(residual, bool)
            or residual != 0
        ):
            return self._fallback_cleanup(stage_root)
        self._cleanup_receipt = receipt
        return receipt

    def _fallback_cleanup(self, stage_root: str) -> Mapping[str, Any]:
        self._abort_process()
        executor = self._fallback_executor
        if executor is None:
            raise CanaryBlocked(
                "N7_R0_CLEANUP_INCOMPLETE",
                "target cleanup was not proven on the pinned channel",
            )
        result = executor.run_bound(
            [
                "docker",
                "exec",
                "-i",
                "-u",
                "ubuntu",
                CONTAINER,
                "python3",
                "-c",
                _REMOTE_FALLBACK_CLEANUP_SOURCE,
                stage_root,
                self._stage_nonce,
            ],
            timeout_s=max(5.0, min(self._io_timeout_s, 30.0)),
        )
        try:
            receipt = json.loads(result.stdout)
        except (TypeError, ValueError) as exc:
            raise CanaryBlocked(
                "N7_R0_CLEANUP_FALLBACK_INVALID",
                "fallback cleanup did not return a valid receipt",
            ) from exc
        residual = receipt.get("residual_count") if isinstance(receipt, dict) else None
        if (
            result.returncode != 0
            or not isinstance(receipt, dict)
            or receipt.get("schema_version") != "rolo-n7-r0-cleanup-fallback/v1"
            or receipt.get("ok") is not True
            or receipt.get("stage_root") != stage_root
            or not isinstance(residual, int)
            or isinstance(residual, bool)
            or residual != 0
        ):
            raise CanaryBlocked(
                "N7_R0_CLEANUP_FALLBACK_INCOMPLETE",
                "fallback cleanup did not prove the exact stage root absent",
            )
        self._cleanup_receipt = {
            **receipt,
            "container": CONTAINER,
            "cleanup_fallback_connection": True,
        }
        return self._cleanup_receipt

    def close(self) -> None:
        process = self._process
        if process is None:
            return
        if process.poll() is None:
            try:
                self._stream("stdin").close()
            except OSError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
        self._join_stderr()

    def _receive_protocol_frame(self, *, deadline: float) -> ProtocolFrame:
        encoded = self._next_stdout_record(deadline=deadline)
        try:
            response = decode_frame(encoded)
        except ValueError as exc:
            raise CanaryBlocked("N7_R0_PROTOCOL_INVALID", "targetd response frame is invalid") from exc
        if response.sequence != self._response_sequence:
            raise CanaryBlocked(
                "N7_R0_PROTOCOL_SEQUENCE_MISMATCH",
                "targetd response sequence is not monotonic",
            )
        self._response_sequence += 1
        return response

    def _read_control_record(self) -> dict[str, Any]:
        return _read_control_record(io.BytesIO(self._next_stdout_record()))

    def _next_stdout_record(self, *, deadline: float | None = None) -> bytes:
        timeout = self._io_timeout_s
        if deadline is not None:
            timeout = max(0.0, deadline - time.monotonic())
        if self._stdout_terminal_error is not None and self._stdout_records.empty():
            value: bytes | BaseException = self._stdout_terminal_error
        else:
            try:
                value = self._stdout_records.get(timeout=timeout)
            except queue.Empty as exc:
                self._abort_process()
                raise CanaryBlocked(
                    "N7_R0_CHANNEL_TIMEOUT",
                    "pinned SSH channel did not return a bounded record before its deadline",
                ) from exc
        if isinstance(value, BaseException):
            raise CanaryBlocked(
                "N7_R0_CHANNEL_TRUNCATED",
                f"pinned SSH channel ended before a complete record: {type(value).__name__}",
            ) from value
        return value

    def _write_bytes(self, payload: bytes) -> None:
        completed = threading.Event()
        failure: list[BaseException] = []

        def write() -> None:
            try:
                stream = self._stream("stdin")
                stream.write(payload)
                stream.flush()
            except BaseException as exc:  # noqa: BLE001 - returned to channel owner
                failure.append(exc)
            finally:
                completed.set()

        writer = threading.Thread(
            target=write,
            name="n7-r0-ssh-write",
            daemon=True,
        )
        self._writer_thread = writer
        writer.start()
        if not completed.wait(self._io_timeout_s):
            self._abort_process()
            raise CanaryBlocked(
                "N7_R0_CHANNEL_TIMEOUT",
                "pinned SSH channel did not accept a bounded record before its deadline",
            )
        if failure:
            raise CanaryBlocked(
                "N7_R0_CHANNEL_WRITE_FAILED",
                f"pinned SSH channel write failed: {type(failure[0]).__name__}",
            ) from failure[0]
        self._writer_thread = None

    def _remember_failed_stage(
        self,
        receipt: Mapping[str, Any],
        *,
        stage_root: str,
    ) -> None:
        residual = receipt.get("residual_count")
        if (
            receipt.get("schema_version") != "rolo-n7-r0-stage-receipt/v1"
            or receipt.get("container") != CONTAINER
            or receipt.get("stage_root") != stage_root
            or receipt.get("ok") is not False
            or not isinstance(residual, int)
            or isinstance(residual, bool)
            or residual < 0
        ):
            raise CanaryBlocked(
                "N7_R0_STAGE_RECEIPT_INVALID",
                "target stage failure receipt cannot prove its exact cleanup state",
            )
        self._cleanup_receipt = {
            "schema_version": "rolo-n7-r0-stage-receipt/v1",
            "ok": False,
            "container": CONTAINER,
            "stage_root": stage_root,
            "residual_count": residual,
            "error": receipt.get("error"),
        }

    def _stream(self, name: str) -> Any:
        if self._process is None:
            raise CanaryBlocked("N7_R0_CHANNEL_CLOSED", "pinned SSH process is not open")
        stream = getattr(self._process, name)
        if stream is None:
            raise CanaryBlocked("N7_R0_CHANNEL_CLOSED", f"pinned SSH {name} is unavailable")
        return stream

    def _start_stderr_drain(self) -> None:
        def drain() -> None:
            stream = self._stream("stderr")
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    return
                remaining = 8192 - len(self._stderr)
                if remaining > 0:
                    self._stderr.extend(chunk[:remaining])

        self._stderr_thread = threading.Thread(
            target=drain,
            name="n7-r0-ssh-stderr",
            daemon=True,
        )
        self._stderr_thread.start()

    def _start_stdout_drain(self) -> None:
        def drain() -> None:
            try:
                stream = self._stream("stdout")
                while True:
                    header = _read_exact(stream, 4)
                    if not header:
                        raise EOFError("record header")
                    if len(header) != 4:
                        raise EOFError("record header")
                    size = int.from_bytes(header, "big")
                    if not 2 <= size <= 8 * 1024 * 1024:
                        raise ValueError("record size")
                    payload = _read_exact(stream, size)
                    if len(payload) != size:
                        raise EOFError("record payload")
                    self._stdout_records.put(header + payload)
            except BaseException as exc:  # noqa: BLE001 - delivered to channel owner
                self._stdout_terminal_error = exc
                self._stdout_records.put(exc)

        self._stdout_thread = threading.Thread(
            target=drain,
            name="n7-r0-ssh-stdout",
            daemon=True,
        )
        self._stdout_thread.start()

    def _abort_process(self) -> None:
        process = self._process
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
        stream = process.stdin
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass
        if self._writer_thread is not None:
            self._writer_thread.join(timeout=1)

    def _wait_process(self) -> None:
        process = self._process
        if process is None:
            return
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            process.terminate()
            raise CanaryBlocked("N7_R0_BOOTSTRAP_TIMEOUT", "target bootstrap did not exit") from exc
        self._join_stderr()

    def _join_stderr(self) -> None:
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=1)


def live_core_blockers() -> tuple[str, ...]:
    """List missing authorities before any SSH connection is attempted."""

    blockers: list[str] = []
    members = {member.value for member in FrameKind}
    for required in ("ACTIVATE_AUTHORITY", "CANCEL_MAPPING"):
        if required not in members:
            blockers.append(f"TARGETD_{required}_FRAME_TODO")
    if "PROVISION_VERIFIED_RELEASE" not in members:
        blockers.append("TARGETD_BUNDLE_PLAN_EXECUTION_BRIDGE_TODO")
    return tuple(blockers)


class _PinnedChannelCertifyCall:
    """Count formal CALLs while preserving channel-owned sequence evidence."""

    def __init__(
        self,
        channel: PinnedCanaryChannel,
        *,
        initial_provider_count: int,
    ) -> None:
        self.channel = channel
        self.initial_provider_count = initial_provider_count
        self.attempt_count = 0
        self.call_count = 0
        self.provider_count = initial_provider_count
        self.validated_frames: list[dict[str, Any]] = []
        self._blocked: CanaryBlocked | None = None

    def __call__(self, request: ExecutionRequest) -> TargetdV2CertifyResponse:
        # A broken sequence/counter boundary is terminal for this run.  The
        # formal runner may continue classifying its ten cases, but it must
        # never issue another target operation after the first channel fault.
        if self._blocked is not None:
            raise self._blocked
        self.attempt_count += 1
        try:
            response = self.channel.call_certification(request)
            if (
                not isinstance(response, TargetdV2CertifyResponse)
                or response.sequence_correlated is not True
            ):
                raise CanaryBlocked(
                    "N7_R0_CERTIFY_SEQUENCE_UNVERIFIED",
                    "formal Certify response was not correlated by the channel",
                )
            expected = self.initial_provider_count + self.call_count + 1
            count = response.frame.payload.get("provider_invocation_count")
            if not isinstance(count, int) or isinstance(count, bool) or count != expected:
                raise CanaryBlocked(
                    "N7_R0_PROVIDER_COUNTER_INVALID",
                    f"target provider counter must be {expected}",
                )
        except CanaryBlocked as exc:
            self._blocked = exc
            raise
        self.call_count += 1
        self.provider_count = count
        self.validated_frames.append(
            {
                "sequence": response.frame.sequence,
                "frame_digest": response.frame.frame_digest,
                "run_id": response.frame.run_id,
            }
        )
        return response


class N7R0CanaryHarness:
    """Validate and execute the fixed N7-R0 transcript over one channel."""

    def __init__(
        self,
        channel_factory: Callable[[], PinnedCanaryChannel],
        *,
        artifact_path: Path,
        evidence_mode: Literal["LIVE", "FAKE_CHANNEL"] = "LIVE",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.channel_factory = channel_factory
        self.artifact_path = artifact_path
        self.evidence_mode = evidence_mode
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def run(self, inputs: N7R0Inputs) -> dict[str, Any]:
        report: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "status": "BLOCKED",
            "evidence_mode": self.evidence_mode,
            "target_id": inputs.target_id,
            "session_id": inputs.session_id,
            "certify_run_id": inputs.certify_run_id,
            "container": CONTAINER,
            "topic": TOPIC,
            "operation_kind": OPERATION_KIND,
            "access": ACCESS,
            "risk": RISK,
            "operator_auth": "FIXTURE",
            "authority_partial": True,
            "outer_artifact_index_ref": "canary-artifact-index.json",
            "limits": {
                "package_bytes": MAX_PACKAGE_BYTES,
                "expanded_bytes": MAX_EXPANDED_BYTES,
                "result_bytes": MAX_RESULT_BYTES,
            },
        }
        channel: PinnedCanaryChannel | None = None
        journey_open = False
        stage_created = False
        stage_root = ""
        binding: N7R0SnapshotBinding | None = None
        captured_snapshot: Ros2RuntimeSnapshot | None = None
        authority: TargetdExecutionAuthority | None = None
        mapping_cancelled = False
        provider_count = 0
        failure: CanaryBlocked | None = None
        try:
            expanded_bytes = inspect_package(inputs.archive)
            stage_root = stage_root_for(inputs.session_id)
            self._validate_bootstrap_inputs(inputs)
            channel = self.channel_factory()
            if not channel.channel_id:
                raise CanaryBlocked("N7_R0_CHANNEL_ID_REQUIRED", "pinned channel has no identity")
            # Staging can create the target root before returning a receipt.
            # Mark it first so every partial/exceptional upload is covered by
            # the exact-root cleanup in ``finally``.
            stage_created = True

            def bind_snapshot(snapshot: Mapping[str, Any]) -> N7R0SnapshotBinding:
                nonlocal binding, captured_snapshot
                try:
                    captured_snapshot = Ros2RuntimeSnapshot.from_dict(dict(snapshot))
                    self._validate_snapshot(captured_snapshot)
                    candidate = inputs.bind_snapshot(snapshot)
                except CanaryBlocked:
                    raise
                except Exception as exc:
                    raise CanaryBlocked(
                        "N7_R0_SNAPSHOT_BINDING_FAILED",
                        f"{type(exc).__name__}: {exc}",
                    ) from exc
                if not isinstance(candidate, N7R0SnapshotBinding):
                    raise CanaryBlocked(
                        "N7_R0_SNAPSHOT_BINDING_INVALID",
                        "snapshot binder returned an invalid contract",
                    )
                binding = candidate
                return candidate

            stage = dict(
                channel.stage_package(
                    container=CONTAINER,
                    stage_root=stage_root,
                    archive=inputs.archive,
                    expanded_bytes=expanded_bytes,
                    bind_snapshot=bind_snapshot,
                )
            )
            if binding is None or captured_snapshot is None:
                raise CanaryBlocked(
                    "N7_R0_SNAPSHOT_BINDING_MISSING",
                    "target snapshot was not bound before daemon start",
                )
            self._validate_inputs(inputs, binding, captured_snapshot, stage)
            self._validate_stage_receipt(
                stage,
                stage_root=stage_root,
                package_sha256=_sha256(inputs.archive),
                admission_ledger_sha256=_sha256(binding.admission_ledger),
                admission_ledger_bytes=len(binding.admission_ledger),
                archive_bytes=len(inputs.archive),
                expanded_bytes=expanded_bytes,
            )

            self._exchange(
                channel,
                "OPEN_JOURNEY",
                {
                    "target_id": inputs.target_id,
                    "profile_id": "landerpi",
                    "surface_digest": inputs.surface_digest,
                },
            )
            journey_open = True
            self._exchange(channel, "BOOTSTRAP", {"session_id": inputs.session_id})
            self._exchange(channel, "HANDOFF", {"phase": "PROBE"})
            dsl_results: dict[str, Mapping[str, Any]] = {}
            frames = (
                ("PUT", "DSL_PUT", dict(binding.dsl_put_payload)),
                (
                    "CHECK",
                    "DSL_CHECK",
                    {
                        "journey_session_id": inputs.session_id,
                        "dsl_digest": binding.compile_payload["dsl_digest"],
                    },
                ),
                (
                    "PLAN_RESOLVE",
                    "PLAN_RESOLVE",
                    {
                        "journey_session_id": inputs.session_id,
                        "dsl_digest": binding.compile_payload["dsl_digest"],
                    },
                ),
                ("TARGET_COMPILE", "TARGET_COMPILE", dict(binding.compile_payload)),
                (
                    "TARGET_CONFORMANCE",
                    "TARGET_CONFORMANCE",
                    dict(binding.compile_payload),
                ),
            )
            for phase, frame_type, payload in frames:
                outer = self._exchange(
                    channel,
                    "DSL_REQUEST",
                    {
                        "frame": {
                            "schema_version": "rolo-targetd-dsl-frame/v1",
                            "frame_type": frame_type,
                            "request_id": f"{inputs.session_id}:{phase.lower()}",
                            "payload": payload,
                        }
                    },
                )
                nested = outer.get("frame")
                if not isinstance(nested, Mapping) or not isinstance(nested.get("payload"), Mapping):
                    raise CanaryBlocked("N7_R0_DSL_RESPONSE_INVALID", f"{phase} response is missing")
                result = dict(nested["payload"])
                dsl_results[phase] = result
                if phase == "PUT":
                    if result.get("phase") != "PUT" or result.get("diagnostics"):
                        raise CanaryBlocked("N7_R0_DSL_PUT_BLOCKED", "DSL PUT did not pass")
                elif phase in {"CHECK", "PLAN_RESOLVE", "TARGET_COMPILE"}:
                    if result.get("status") != "PASS":
                        raise CanaryBlocked(f"N7_R0_{phase}_BLOCKED", f"{phase} did not pass")

            conformance_payload = dsl_results["TARGET_CONFORMANCE"]
            if conformance_payload.get("target_conformance") != "PASS":
                raise CanaryBlocked("N7_R0_TARGET_CONFORMANCE_BLOCKED", "T1-T4 did not pass")
            target_report = TargetConformanceReport.model_validate(conformance_payload.get("target_conformance_report"))
            self._validate_target_report(target_report, inputs)

            target_conformance_digest = str(conformance_payload.get("target_conformance_digest", ""))
            plan = binding.release_builder(
                dsl_results["TARGET_COMPILE"],
                target_report,
                target_conformance_digest,
            )
            self._validate_execution_plan(plan, target_report, inputs)
            if plan.release.probe_evidence_digest != captured_snapshot.runtime_digest:
                raise CanaryBlocked(
                    "N7_R0_RELEASE_SNAPSHOT_MISMATCH",
                    "verified Release is not bound to the fresh target snapshot",
                )

            present = self._exchange(
                channel,
                "HAS",
                {"bundle_digest": plan.manifest.bundle_digest},
            )
            if present.get("present") is not True:
                self._exchange(
                    channel,
                    "PUT",
                    {
                        "manifest": plan.manifest.model_dump(mode="json"),
                        "source_b64": base64.b64encode(plan.source).decode("ascii"),
                    },
                )
            self._exchange(channel, "PHASE_CHANGE", {"phase": "TRACE"})
            self._provision_verified_release(channel, plan, target_report)
            activated = self._exchange(
                channel,
                "ACTIVATE_AUTHORITY",
                TargetdAuthorityActivationRequest(
                    schema_version="rolo-targetd-authority-activation/v1",
                    tool_id=TOOL_ID,
                    release_digest=plan.release_digest,
                    bundle_digest=plan.manifest.bundle_digest,
                    expected_current_authority_head_digest=None,
                ).model_dump(mode="json"),
            )
            try:
                authority = TargetdExecutionAuthority.model_validate(activated.get("authority"))
            except ValueError as exc:
                raise CanaryBlocked(
                    "N7_R0_AUTHORITY_ACTIVATION_BLOCKED",
                    "target authority response is invalid",
                ) from exc
            self._validate_activated_authority(authority, plan, inputs)
            self._provider_count(activated, expected=provider_count)

            trace_request = self._request(plan, authority, inputs, "trace-01")
            trace, provider_count = self._successful_call(
                channel,
                trace_request,
                expected_provider_count=provider_count + 1,
            )

            self._exchange(channel, "PHASE_CHANGE", {"phase": "CERTIFY"})
            formal_state: dict[str, Any] = {
                "status": "BLOCKED",
                "session_id": inputs.session_id,
                "run_id": inputs.certify_run_id,
                "suite_id": "landerpi-odom-formal-r0-10",
                "target_call_count": 0,
                "raw_persisted": False,
            }
            report["formal_certify"] = formal_state
            formal_call = _PinnedChannelCertifyCall(
                channel,
                initial_provider_count=provider_count,
            )
            suite = CertificationSuite(
                schema_version="rolo-mvp-certification-suite/v1",
                suite_id="landerpi-odom-formal-r0-10",
                target_id=inputs.target_id,
                cases=[
                    CertificationCase(
                        case_id=f"case-{index:02d}",
                        description="Observe one fresh bounded /odom sample through targetd CALL v2",
                        tool_id=TOOL_ID,
                        arguments={},
                        expected={"status": "SUCCEEDED"},
                        timeout_s=60,
                        risk="R0",
                        stop_condition=(
                            "abort this run on any non-SUCCEEDED receipt; no ROS publish, "
                            "service, action, or motion"
                        ),
                    )
                    for index in range(1, CERTIFY_CASES + 1)
                ],
            ).with_digest()
            formal_state["suite_digest"] = suite.digest
            adapter = TargetdV2CertifyAdapter(
                authority,
                call=formal_call,
                clock=self.clock,
            )
            formal_output = self.artifact_path.parent / "certification-report.json"
            try:
                formal_report, formal_paths = ReleaseBoundCertify(
                    plan.publisher,
                    release_digests={TOOL_ID: plan.release_digest},
                    target_fingerprint=authority.target_fingerprint,
                    evidence_digest=captured_snapshot.runtime_digest,
                    compile_context_digest=authority.context_digest,
                    invoker=adapter,
                ).run(
                    suite,
                    snapshot_digest=captured_snapshot.runtime_digest.removeprefix("sha256:"),
                    output=formal_output,
                    session_id=inputs.session_id,
                    run_id=inputs.certify_run_id,
                )
            except Exception as exc:
                formal_state["target_call_count"] = formal_call.call_count
                formal_state["target_call_attempt_count"] = formal_call.attempt_count
                formal_state["targetd_call_provider_invocation_count"] = (
                    formal_call.provider_count
                )
                provider_count = formal_call.provider_count
                reservation = formal_output.parent / ".certify-publication.reservation"
                formal_state["publication_reservation_retained"] = (
                    reservation.is_file() and not reservation.is_symlink()
                )
                if isinstance(exc, CanaryBlocked):
                    raise
                candidate = str(exc)
                safe = (
                    candidate
                    if _SAFE_REMOTE_ERROR.fullmatch(candidate)
                    else type(exc).__name__
                )
                raise CanaryBlocked(
                    "N7_R0_FORMAL_CERTIFY_BLOCKED",
                    f"formal Certify failed closed: {safe}",
                ) from exc
            provider_count = formal_call.provider_count
            formal_state.update(
                self._formal_certify_evidence(
                    formal_report,
                    formal_paths=formal_paths,
                    expected_output=formal_output,
                    formal_call=formal_call,
                    channel_id=channel.channel_id,
                )
            )
            if (
                formal_report.conclusion != "PASS"
                or len(formal_report.results) != CERTIFY_CASES
                or formal_call.call_count != CERTIFY_CASES
            ):
                raise CanaryBlocked(
                    "N7_R0_FORMAL_CERTIFY_BLOCKED",
                    "formal Certify did not produce ten receipt-backed PASS cases",
                )

            cancelled = self._exchange(
                channel,
                "CANCEL_MAPPING",
                TargetdMappingCancelRequest(
                    schema_version="rolo-targetd-mapping-cancel/v1",
                    tool_id=TOOL_ID,
                    authority_head_digest=authority.authority_head_digest,
                    mapping_confirmation_receipt_digest=(authority.mapping_confirmation_receipt_digest),
                    idempotency_key=f"{inputs.session_id}:mapping-cancel",
                ).model_dump(mode="json"),
            )
            self._validate_cancellation(cancelled, authority)
            mapping_cancelled = True
            self._provider_count(cancelled, expected=provider_count)
            blocked_request = self._request(
                plan,
                authority,
                inputs,
                "post-cancel-new-key",
            )
            blocked = self._exchange(
                channel,
                "CALL",
                blocked_request.model_dump(mode="json"),
                run_id=blocked_request.run_id,
                require_ok=False,
            )
            self._validate_post_cancel(blocked, expected_provider_count=provider_count)

            if provider_count != EXPECTED_TARGETD_CALL_PROVIDER_INVOCATIONS:
                raise CanaryBlocked(
                    "N7_R0_PROVIDER_COUNT_INVALID",
                    "targetd CALL provider counter differs from Trace + Certify",
                )
            report.update(
                {
                    "status": "PASS" if self.evidence_mode == "LIVE" else "SIMULATED_PASS",
                    "channel_id": channel.channel_id,
                    "stage": {
                        "root": stage_root,
                        "package_sha256": _sha256(inputs.archive),
                        "admission_ledger_sha256": _sha256(binding.admission_ledger),
                        "package_bytes": len(inputs.archive),
                        "expanded_bytes": expanded_bytes,
                        "ros2_snapshot_digest": stage["ros2_snapshot_digest"],
                        "ros2_path": stage["ros2_path"],
                        "executor_user": stage["executor_user"],
                    },
                    "target_conformance_digest": target_conformance_digest,
                    "release_digest": plan.release_digest,
                    "authority_head_digest": authority.authority_head_digest,
                    "trace": trace,
                    "certify_case_count": len(formal_report.results),
                    "executor_invocation_evidence": {
                        "observed_total": provider_count + 1,
                        "target_conformance_t3": {
                            "count": 1,
                            "basis": "single-fresh-cache-target-conformance-frame",
                            "conformance_idempotency_key": (
                                target_report.conformance_idempotency_key
                            ),
                            "runtime_result_digest": target_report.runtime_result_digest,
                        },
                        "targetd_call_provider": {
                            "count": provider_count,
                            "basis": "targetd-process-monotonic-counter",
                        },
                    },
                    "post_cancel": {
                        "status": "BLOCKED",
                        "idempotency_key": blocked_request.idempotency_key,
                        "targetd_call_provider_invocation_count": provider_count,
                    },
                    "raw_persisted": False,
                }
            )
        except CanaryBlocked as exc:
            failure = exc
        except Exception as exc:  # noqa: BLE001 - stable fail-closed canary boundary
            failure = CanaryBlocked(
                "N7_R0_UNEXPECTED_FAILURE",
                f"unexpected fail-closed boundary: {type(exc).__name__}",
            )
        finally:
            if channel is not None:
                if authority is not None and not mapping_cancelled and journey_open:
                    try:
                        cancelled = self._exchange(
                            channel,
                            "CANCEL_MAPPING",
                            TargetdMappingCancelRequest(
                                schema_version="rolo-targetd-mapping-cancel/v1",
                                tool_id=TOOL_ID,
                                authority_head_digest=authority.authority_head_digest,
                                mapping_confirmation_receipt_digest=(
                                    authority.mapping_confirmation_receipt_digest
                                ),
                                idempotency_key=f"{inputs.session_id}:mapping-cancel",
                            ).model_dump(mode="json"),
                        )
                        self._validate_cancellation(cancelled, authority)
                        self._provider_count(cancelled, expected=provider_count)
                        mapping_cancelled = True
                        report["mapping_cancel_cleanup"] = {
                            "status": "CANCELLED",
                            "targetd_call_provider_invocation_count": provider_count,
                        }
                    except Exception:
                        report.setdefault("limitations", []).append(
                            "MAPPING_CANCEL_CLEANUP_FAILED"
                        )
                        if failure is None:
                            failure = CanaryBlocked(
                                "N7_R0_MAPPING_CANCEL_CLEANUP_FAILED",
                                "target Mapping could not be cancelled during cleanup",
                            )
                if journey_open:
                    try:
                        self._exchange(
                            channel,
                            "CLOSE_SESSION",
                            {"session_id": inputs.session_id},
                        )
                        journey_open = False
                    except CanaryBlocked as exc:
                        failure = exc
                    except Exception as exc:  # noqa: BLE001 - still attempt cleanup
                        failure = CanaryBlocked(
                            "N7_R0_SESSION_CLOSE_FAILED",
                            f"{type(exc).__name__}: {exc}",
                        )
                try:
                    if stage_created:
                        cleanup = dict(
                            channel.cleanup_stage(
                                container=CONTAINER,
                                stage_root=stage_root,
                            )
                        )
                        cleanup_fallback_connection = cleanup.get(
                            "cleanup_fallback_connection", False
                        )
                        cleanup_residual = cleanup.get("residual_count")
                        cleanup_schema = cleanup.get("schema_version")
                        cleanup_ok = cleanup.get("ok")
                        cleanup_kind_valid = (
                            cleanup_fallback_connection is True
                            and cleanup_schema == "rolo-n7-r0-cleanup-fallback/v1"
                            and cleanup_ok is True
                        ) or (
                            cleanup_fallback_connection is False
                            and (
                                (
                                    cleanup_schema == "rolo-n7-r0-cleanup-receipt/v1"
                                    and cleanup_ok is True
                                )
                                or (
                                    cleanup_schema == "rolo-n7-r0-stage-receipt/v1"
                                    and cleanup_ok is False
                                )
                            )
                        )
                        if (
                            not cleanup_kind_valid
                            or cleanup.get("container") != CONTAINER
                            or cleanup.get("stage_root") != stage_root
                            or not isinstance(cleanup_residual, int)
                            or isinstance(cleanup_residual, bool)
                            or cleanup_residual != 0
                        ):
                            raise CanaryBlocked(
                                "N7_R0_CLEANUP_INCOMPLETE",
                                "exact stage cleanup receipt is not bound or zero-residual",
                            )
                        report["cleanup"] = {
                            "stage_root": stage_root,
                            "residual_count": 0,
                            "cleanup_fallback_connection": cleanup_fallback_connection,
                        }
                        if cleanup_fallback_connection and failure is None:
                            failure = CanaryBlocked(
                                "N7_R0_CLEANUP_FALLBACK_USED",
                                "exact cleanup required a recovery connection; "
                                "pinned-channel evidence is invalid",
                            )
                except CanaryBlocked as exc:
                    failure = exc
                except Exception as exc:  # noqa: BLE001 - cleanup must dominate PASS
                    failure = CanaryBlocked(
                        "N7_R0_CLEANUP_FAILED",
                        f"{type(exc).__name__}: {exc}",
                    )
                finally:
                    channel.close()
            if failure is not None:
                report.update(
                    {
                        "status": "BLOCKED",
                        "code": failure.code,
                        "message": "canary failed closed; inspect the stable code and evidence counters",
                    }
                )
            self._persist(report)
        return report

    @staticmethod
    def _validate_bootstrap_inputs(inputs: N7R0Inputs) -> None:
        if inputs.target_id != TARGET_ID:
            raise CanaryBlocked("N7_R0_TARGET_INVALID", f"target must be {TARGET_ID}")
        if re.fullmatch(r"[0-9a-f]{64}", inputs.surface_digest) is None:
            raise CanaryBlocked("N7_R0_SURFACE_INVALID", "surface digest must be unprefixed SHA-256")
        if not callable(inputs.bind_snapshot):
            raise CanaryBlocked("N7_R0_SNAPSHOT_BINDER_INVALID", "snapshot binder is required")

    @staticmethod
    def _validate_snapshot(snapshot: Ros2RuntimeSnapshot) -> None:
        if (
            snapshot.distro != "humble"
            or snapshot.ros2_path != "/opt/ros/humble/bin/ros2"
            or snapshot.executor_user != "ubuntu"
            or snapshot.publisher_user is not None
            or not any(
                topic.name == TOPIC
                and topic.interface_type == "nav_msgs/msg/Odometry"
                for topic in snapshot.topics
            )
        ):
            raise CanaryBlocked(
                "N7_R0_ROS2_SNAPSHOT_INVALID",
                "target snapshot is not the fixed ubuntu ROS2 /odom executor route",
            )

    @staticmethod
    def _validate_inputs(
        inputs: N7R0Inputs,
        snapshot_binding: N7R0SnapshotBinding,
        snapshot: Ros2RuntimeSnapshot,
        stage: Mapping[str, Any],
    ) -> None:
        put = snapshot_binding.dsl_put_payload
        dsl = put.get("dsl")
        context = put.get("context")
        if not isinstance(dsl, Mapping) or not isinstance(context, Mapping):
            raise CanaryBlocked("N7_R0_DSL_INVALID", "DSL and Context are required")
        dsl_binding = dsl.get("binding")
        if (
            dsl.get("tool_id") != TOOL_ID
            or dsl.get("kind") != OPERATION_KIND
            or not isinstance(dsl_binding, Mapping)
            or dsl_binding.get("resource_id") != TOPIC
            or context.get("robot_id") != TARGET_ID
        ):
            raise CanaryBlocked(
                "N7_R0_SCOPE_INVALID",
                "canary is fixed to OBSERVE/read/R0 on /odom",
            )
        if (
            dsl.get("target", {}).get("evidence_digest") != snapshot.runtime_digest
            or context.get("evidence_digest") != snapshot.runtime_digest
            or stage.get("ros2_snapshot_digest") != snapshot.runtime_digest
        ):
            raise CanaryBlocked(
                "N7_R0_SNAPSHOT_BINDING_MISMATCH",
                "DSL, Context, and stage receipt must bind the captured target snapshot",
            )
        compile_payload = snapshot_binding.compile_payload
        if not snapshot_binding.admission_ledger or len(snapshot_binding.admission_ledger) > MAX_ADMISSION_LEDGER_BYTES:
            raise CanaryBlocked(
                "N7_R0_ADMISSION_LEDGER_INVALID",
                "fixture admission ledger must be non-empty and at most 1 MiB",
            )
        expected = {
            "schema_version": "rolo-targetd-dsl-compile/v2",
            "journey_session_id": inputs.session_id,
            "backend_hint": "ros2_observe",
            "runtime_backend_hint": "ros2_runtime",
        }
        if any(compile_payload.get(key) != value for key, value in expected.items()):
            raise CanaryBlocked("N7_R0_COMPILE_IDENTITY_INVALID", "compile backend/session is not fixed")
        if set(compile_payload.get("required_capabilities", ())) != {"operation:OBSERVE"}:
            raise CanaryBlocked("N7_R0_COMPILE_CAPABILITY_INVALID", "compiler must negotiate OBSERVE")
        if set(compile_payload.get("required_runtime_capabilities", ())) != {
            "read_only_topic",
            "ros2",
        }:
            raise CanaryBlocked("N7_R0_RUNTIME_CAPABILITY_INVALID", "runtime must be ROS2 read-only")

    @staticmethod
    def _validate_stage_receipt(
        receipt: Mapping[str, Any],
        *,
        stage_root: str,
        package_sha256: str,
        admission_ledger_sha256: str,
        admission_ledger_bytes: int,
        archive_bytes: int,
        expanded_bytes: int,
    ) -> None:
        expected = {
            "container": CONTAINER,
            "stage_root": stage_root,
            "package_sha256": package_sha256,
            "admission_ledger_sha256": admission_ledger_sha256,
            "archive_bytes": archive_bytes,
            "expanded_bytes": expanded_bytes,
        }
        if (
            receipt.get("schema_version") != "rolo-n7-r0-stage-receipt/v1"
            or receipt.get("ok") is not True
            or any(receipt.get(key) != value for key, value in expected.items())
        ):
            raise CanaryBlocked("N7_R0_STAGE_RECEIPT_INVALID", "target stage receipt differs")
        free_bytes = receipt.get("tmpfs_free_bytes")
        if not isinstance(free_bytes, int) or free_bytes < archive_bytes + expanded_bytes + admission_ledger_bytes + MAX_RESULT_BYTES:
            raise CanaryBlocked(
                "N7_R0_TMPFS_CAPACITY_INVALID",
                "target did not prove enough tmpfs capacity for bounded staging",
            )
        if (
            receipt.get("ros2_path") != "/opt/ros/humble/bin/ros2"
            or receipt.get("executor_user") != "ubuntu"
            or receipt.get("odom_observed") is not True
            or _DIGEST.fullmatch(str(receipt.get("ros2_snapshot_digest", ""))) is None
        ):
            raise CanaryBlocked(
                "N7_R0_ROS2_SNAPSHOT_INVALID",
                "target bootstrap did not freshly observe the fixed /odom route",
            )

    @staticmethod
    def _validate_target_report(report: TargetConformanceReport, inputs: N7R0Inputs) -> None:
        if (
            not report.passed
            or report.tool_id != TOOL_ID
            or report.operation_kind.value != OPERATION_KIND
            or report.target_id != inputs.target_id
            or report.runtime_backend_id != "ros2_runtime"
            or set(report.required_runtime_capabilities) != {"read_only_topic", "ros2"}
            or len(report.proofs) != 4
        ):
            raise CanaryBlocked("N7_R0_TARGET_REPORT_INVALID", "target report is not fixed read-only T1-T4")

    def _provision_verified_release(
        self,
        channel: PinnedCanaryChannel,
        plan: VerifiedExecutionPlan,
        target_report: TargetConformanceReport,
    ) -> None:
        """Reserve the target-owned Catalog transition without a host bypass."""

        if "PROVISION_VERIFIED_RELEASE" not in {member.value for member in FrameKind}:
            if self.evidence_mode == "LIVE":
                raise CanaryBlocked(
                    "N7_R0_RELEASE_PROVISION_UNAVAILABLE",
                    "targetd cannot provision the verified Release on this channel",
                )
            return
        self._exchange(
            channel,
            "PROVISION_VERIFIED_RELEASE",
            TargetdVerifiedReleaseProvisionRequest(
                schema_version="rolo-targetd-verified-release-provision/v1",
                release_digest=plan.release_digest,
                candidate_release=plan.release,
                conformance_cache_key=(target_report.conformance_idempotency_key.removeprefix("sha256:")),
                execution_bundle_digest=plan.manifest.bundle_digest,
                expected_catalog_head_digest=None,
            ).model_dump(mode="json"),
        )

    @staticmethod
    def _validate_execution_plan(
        plan: VerifiedExecutionPlan,
        target_report: TargetConformanceReport,
        inputs: N7R0Inputs,
    ) -> None:
        release = plan.release
        manifest = plan.manifest
        contract = manifest.observation_contract
        expected_bridge = {
            "schema_version": "rolo-n7-r0-bundle-bridge/v1",
            "bundle_plan_digest": target_report.bundle_digest,
            "execution_bundle_digest": manifest.bundle_digest,
            "release_digest": plan.release_digest,
            "target_conformance_digest": plan.target_conformance_digest,
        }
        try:
            current = plan.publisher.current(TOOL_ID)
            confirmation_store = plan.publisher.confirmation_store
        except (AttributeError, OSError, ValueError) as exc:
            raise CanaryBlocked(
                "N7_R0_RELEASE_PUBLISHER_INVALID",
                "formal Certify publisher cannot resolve the current Release",
            ) from exc
        if any(plan.bridge_proof.get(key) != value for key, value in expected_bridge.items()):
            raise CanaryBlocked("N7_R0_BUNDLE_BRIDGE_INVALID", "BundlePlan-to-v2-CALL bridge differs")
        if (
            release.status != "PUBLISHED"
            or release.agent_callable is not True
            or release.tool_id != TOOL_ID
            or release.operation_kind != OPERATION_KIND
            or release.target_id != inputs.target_id
            or release.target_conformance_digest != plan.target_conformance_digest
            or release.generated_bundle_digest != target_report.bundle_digest
            or manifest.release_version != plan.release_digest
            or contract.get("provider") != PROVIDER_ID
            or contract.get("operation") != PROVIDER_OPERATION
            or contract.get("mode") != "READ_ONLY"
            or contract.get("generated_bundle_digest") != release.generated_bundle_digest
            or contract.get("topic") != TOPIC
            or contract.get("operation_kind") != OPERATION_KIND
            or contract.get("access") != ACCESS
            or contract.get("risk") != RISK
            or int(manifest.limits.get("max_output_bytes", 0)) > MAX_RESULT_BYTES
            or hashlib.sha256(plan.source).hexdigest() != manifest.source_digest
            or current is None
            or current[0] != plan.release_digest
            or current[1] != release
            or confirmation_store is None
        ):
            raise CanaryBlocked("N7_R0_RELEASE_EXECUTION_IDENTITY_INVALID", "verified Release/CALL identity differs")

    @staticmethod
    def _validate_activated_authority(
        authority: TargetdExecutionAuthority,
        plan: VerifiedExecutionPlan,
        inputs: N7R0Inputs,
    ) -> None:
        if (
            authority.tool_id != TOOL_ID
            or authority.target_id != inputs.target_id
            or authority.bundle_digest != plan.manifest.bundle_digest
            or authority.binding_digest != plan.manifest.binding_digest
            or authority.release_digest != plan.release_digest
            or authority.provider_id != PROVIDER_ID
            or authority.provider_operation != PROVIDER_OPERATION
            or authority.mode != "READ_ONLY"
            or authority.surface_digest != inputs.surface_digest
            or authority.mapping_admission.scope.access != ACCESS
            or authority.mapping_admission.scope.risk != RISK
            or authority.mapping_admission.scope.operation_kind.value != OPERATION_KIND
        ):
            raise CanaryBlocked(
                "N7_R0_AUTHORITY_ACTIVATION_BLOCKED",
                "target-derived authority identity differs",
            )

    @staticmethod
    def _validate_cancellation(
        response: Mapping[str, Any],
        authority: TargetdExecutionAuthority,
    ) -> None:
        receipt = response.get("receipt")
        if not isinstance(receipt, Mapping) or receipt.get("decision") != "CANCELLED" or receipt.get("supersedes_receipt_digest") != authority.mapping_confirmation_receipt_digest:
            raise CanaryBlocked(
                "N7_R0_MAPPING_CANCEL_INVALID",
                "target did not return the expected Mapping tombstone",
            )

    def _request(
        self,
        plan: VerifiedExecutionPlan,
        authority: TargetdExecutionAuthority,
        inputs: N7R0Inputs,
        suffix: str,
    ) -> ExecutionRequest:
        return ExecutionRequest(
            schema_version="rolo-execution-request/v2",
            run_id=f"{inputs.session_id}:{suffix}",
            session_id=inputs.session_id,
            target_id=inputs.target_id,
            idempotency_key=f"{inputs.session_id}:{suffix}",
            bundle_digest=plan.manifest.bundle_digest,
            binding_digest=plan.manifest.binding_digest,
            surface_digest=inputs.surface_digest,
            release_digest=plan.release_digest,
            context_digest=authority.context_digest,
            mapping_confirmation_receipt_digest=(authority.mapping_confirmation_receipt_digest),
            authority_head_digest=authority.authority_head_digest,
            fence_epoch=authority.fence_epoch,
            provider_id=PROVIDER_ID,
            provider_operation=PROVIDER_OPERATION,
            authority=authority,
            arguments={},
            mode="READ_ONLY",
            deadline=self.clock() + timedelta(seconds=60),
        )

    def _successful_call(
        self,
        channel: PinnedCanaryChannel,
        request: ExecutionRequest,
        *,
        expected_provider_count: int,
    ) -> tuple[dict[str, Any], int]:
        response = self._exchange(
            channel,
            "CALL",
            request.model_dump(mode="json"),
            run_id=request.run_id,
        )
        receipt = response.get("receipt")
        if not isinstance(receipt, Mapping) or receipt.get("status") != "SUCCEEDED":
            status = receipt.get("status") if isinstance(receipt, Mapping) else None
            result = receipt.get("result") if isinstance(receipt, Mapping) else None
            error = result.get("error") if isinstance(result, Mapping) else None
            safe_error = error if isinstance(error, str) and _SAFE_REMOTE_ERROR.fullmatch(error) else "UNAVAILABLE"
            safe_status = status if isinstance(status, str) and _SAFE_REMOTE_ERROR.fullmatch(status) else "INVALID"
            raise CanaryBlocked(
                "N7_R0_CALL_FAILED",
                f"read-only CALL did not succeed: status={safe_status}; error={safe_error}",
            )
        result = receipt.get("result")
        summary = self._result_summary(result, request.idempotency_key)
        return summary, self._provider_count(response, expected=expected_provider_count)

    def _formal_certify_evidence(
        self,
        report: Any,
        *,
        formal_paths: tuple[Path, Path],
        expected_output: Path,
        formal_call: _PinnedChannelCertifyCall,
        channel_id: str,
    ) -> dict[str, Any]:
        """Re-verify the immutable formal graph before the outer PASS."""

        json_path, md_path = formal_paths
        root = expected_output.parent.resolve()
        expected_json = expected_output.resolve(strict=False)
        index_path = expected_output.parent / "artifact-index.json"
        if (expected_output.parent / ".certify-publication.reservation").exists():
            raise CanaryBlocked(
                "N7_R0_FORMAL_RESERVATION_RETAINED",
                "formal publication reservation remained after index commit",
            )
        if json_path.resolve(strict=False) != expected_json:
            raise CanaryBlocked(
                "N7_R0_FORMAL_ARTIFACT_IDENTITY_INVALID",
                "formal report path changed during publication",
            )
        try:
            index = ArtifactIndex.model_validate_json(index_path.read_text(encoding="utf-8"))
            index.verify()
        except (OSError, ValueError) as exc:
            raise CanaryBlocked(
                "N7_R0_FORMAL_INDEX_INVALID",
                "formal artifact index is absent or invalid",
            ) from exc
        if (
            index.run_id != report.run_id
            or index.target_id != report.target_id
            or report.run_id != report.run_id.strip()
        ):
            raise CanaryBlocked(
                "N7_R0_FORMAL_INDEX_IDENTITY_MISMATCH",
                "formal artifact index identity differs from its report",
            )

        indexed: dict[str, str] = {}
        parsed_payloads: list[Any] = []
        for entry in index.artifacts:
            relative = entry.get("path")
            digest = entry.get("sha256")
            if (
                not isinstance(relative, str)
                or relative in indexed
                or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise CanaryBlocked(
                    "N7_R0_FORMAL_INDEX_INVALID",
                    "formal artifact index contains an invalid entry",
                )
            candidate = expected_output.parent / relative
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(root)
                payload = resolved.read_bytes()
            except (OSError, ValueError) as exc:
                raise CanaryBlocked(
                    "N7_R0_FORMAL_ARTIFACT_INVALID",
                    "formal indexed artifact is absent or outside its root",
                ) from exc
            if (
                _is_linklike(candidate)
                or not resolved.is_file()
                or hashlib.sha256(payload).hexdigest() != digest
            ):
                raise CanaryBlocked(
                    "N7_R0_FORMAL_ARTIFACT_DIGEST_MISMATCH",
                    "formal indexed artifact differs from its immutable digest",
                )
            indexed[relative] = digest
            if relative.endswith(".json"):
                try:
                    parsed_payloads.append(json.loads(payload))
                except (UnicodeDecodeError, ValueError) as exc:
                    raise CanaryBlocked(
                        "N7_R0_FORMAL_ARTIFACT_INVALID",
                        "formal JSON artifact is invalid",
                    ) from exc
            elif relative.endswith(".jsonl"):
                try:
                    parsed_payloads.extend(
                        json.loads(line)
                        for line in payload.decode("utf-8").splitlines()
                        if line
                    )
                except (UnicodeDecodeError, ValueError) as exc:
                    raise CanaryBlocked(
                        "N7_R0_FORMAL_ARTIFACT_INVALID",
                        "formal JSONL artifact is invalid",
                    ) from exc
        if any(_contains_sensitive_evidence_key(item) for item in parsed_payloads):
            raise CanaryBlocked(
                "N7_R0_FORMAL_SENSITIVE_EVIDENCE",
                "formal artifact graph contains a sensitive evidence field",
            )

        receipt_entries = sorted(
            (
                (path, digest)
                for path, digest in indexed.items()
                if path.endswith(".targetd-call-receipt.json")
            ),
            key=lambda item: item[0],
        )
        if (
            report.conclusion != "PASS"
            or report.run_id != report.run_id.strip()
            or len(report.results) != CERTIFY_CASES
            or len(receipt_entries) != CERTIFY_CASES
            or formal_call.attempt_count != CERTIFY_CASES
            or formal_call.call_count != CERTIFY_CASES
            or formal_call.provider_count
            != formal_call.initial_provider_count + CERTIFY_CASES
            or len(formal_call.validated_frames) != CERTIFY_CASES
        ):
            raise CanaryBlocked(
                "N7_R0_FORMAL_CERTIFY_COUNT_INVALID",
                "formal Certify evidence is not exactly ten sequence-verified calls",
            )

        receipt_refs: list[dict[str, Any]] = []
        by_case = {item.case_id: item for item in report.results}
        if set(by_case) != {f"case-{index:02d}" for index in range(1, 11)}:
            raise CanaryBlocked(
                "N7_R0_FORMAL_CASE_IDENTITY_INVALID",
                "formal Certify case identities differ",
            )
        for path, digest in receipt_entries:
            try:
                sidecar = json.loads((expected_output.parent / path).read_text(encoding="utf-8"))
                case_id = sidecar["case_id"]
                result = by_case[case_id]
                actual = result.actual
            except (KeyError, OSError, TypeError, ValueError) as exc:
                raise CanaryBlocked(
                    "N7_R0_FORMAL_RECEIPT_INVALID",
                    "formal receipt sidecar cannot be correlated to a case",
                ) from exc
            if (
                not isinstance(actual, Mapping)
                or set(actual) != {"status", "sha256", "byte_count"}
                or actual.get("status") != "SUCCEEDED"
                or _DIGEST.fullmatch(str(actual.get("sha256", ""))) is None
                or isinstance(actual.get("byte_count"), bool)
                or not isinstance(actual.get("byte_count"), int)
                or not 0 < actual["byte_count"] <= MAX_RESULT_BYTES
                or result.status.value != "PASS"
                or result.idempotency_key != sidecar.get("idempotency_key")
                or result.operation_ids != [sidecar.get("operation_id")]
                or digest not in result.artifact_digests
            ):
                raise CanaryBlocked(
                    "N7_R0_FORMAL_RECEIPT_IDENTITY_MISMATCH",
                    "formal receipt/result/case identity differs",
                )
            receipt_refs.append(
                {
                    "case_id": case_id,
                    "path": path,
                    "sha256": digest,
                    "idempotency_key": result.idempotency_key,
                }
            )

        required_paths = {
            json_path.name,
            md_path.name,
            expected_output.with_suffix(".html").name,
            "release-binding.json",
            "certify-test-suite.json",
            f"{expected_output.stem}.events.jsonl",
        }
        if not required_paths <= set(indexed):
            raise CanaryBlocked(
                "N7_R0_FORMAL_ARTIFACT_GRAPH_INCOMPLETE",
                "formal report, events, binding, or suite is absent from the index",
            )

        def ref(path: Path) -> dict[str, str]:
            relative = path.resolve().relative_to(root).as_posix()
            return {"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

        return {
            "status": "PASS",
            "conclusion": report.conclusion,
            "case_count": len(report.results),
            "receipt_count": len(receipt_refs),
            "target_call_attempt_count": formal_call.attempt_count,
            "target_call_count": formal_call.call_count,
            "targetd_call_provider_invocation_count": formal_call.provider_count,
            "report": ref(json_path),
            "artifact_index": {
                **ref(index_path),
                "manifest_sha256": index.manifest_sha256,
                "artifact_count": len(index.artifacts),
            },
            "sequence_attestation": {
                "channel_id": channel_id,
                "verified_result_count": len(formal_call.validated_frames),
                "results": list(formal_call.validated_frames),
            },
            "raw_persisted": False,
        }

    @staticmethod
    def _result_summary(result: object, idempotency_key: str) -> dict[str, Any]:
        if not isinstance(result, Mapping):
            raise CanaryBlocked("N7_R0_RESULT_INVALID", "provider result is not an object")
        encoded = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_RESULT_BYTES:
            raise CanaryBlocked("N7_R0_RESULT_LIMIT", "provider result exceeds 64 KiB")
        if "raw" in result:
            raise CanaryBlocked("N7_R0_RAW_RESULT_EXPOSED", "target persisted raw ROS2 output")
        raw_sha256 = result.get("sha256")
        raw_byte_count = result.get("byte_count")
        if (
            result.get("status") != "SUCCEEDED"
            or set(result) != {"status", "sha256", "byte_count"}
            or not isinstance(raw_sha256, str)
            or _DIGEST.fullmatch(raw_sha256) is None
            or not isinstance(raw_byte_count, int)
            or not 0 < raw_byte_count <= MAX_RESULT_BYTES
        ):
            raise CanaryBlocked("N7_R0_RESULT_IDENTITY_INVALID", "read-only result evidence differs")
        return {
            "idempotency_key": idempotency_key,
            "status": "SUCCEEDED",
            "topic": TOPIC,
            "sha256": raw_sha256,
            "byte_count": raw_byte_count,
        }

    @staticmethod
    def _validate_post_cancel(
        response: Mapping[str, Any],
        *,
        expected_provider_count: int,
    ) -> None:
        count = response.get("provider_invocation_count")
        receipt = response.get("receipt")
        blocked = response.get("ok") is False
        if isinstance(receipt, Mapping):
            blocked = blocked or receipt.get("status") in {"NOT_ACCEPTED", "BLOCKED"}
            if receipt.get("provider_started_at") is not None:
                raise CanaryBlocked("N7_R0_CANCEL_FENCE_FAILED", "provider started after Mapping cancel")
        if not blocked or count != expected_provider_count:
            raise CanaryBlocked("N7_R0_CANCEL_FENCE_FAILED", "new key was not blocked before provider")

    @staticmethod
    def _provider_count(response: Mapping[str, Any], *, expected: int) -> int:
        count = response.get("provider_invocation_count")
        if not isinstance(count, int) or count != expected:
            raise CanaryBlocked(
                "N7_R0_PROVIDER_COUNTER_INVALID",
                f"target provider counter must be {expected}",
            )
        return count

    @staticmethod
    def _exchange(
        channel: PinnedCanaryChannel,
        kind: str,
        payload: Mapping[str, Any],
        *,
        run_id: str | None = None,
        require_ok: bool = True,
    ) -> Mapping[str, Any]:
        response = channel.exchange(kind, payload, run_id=run_id)
        if not isinstance(response, Mapping):
            raise CanaryBlocked("N7_R0_PROTOCOL_INVALID", f"{kind} response is not an object")
        if require_ok and response.get("ok") is not True:
            candidate = response.get("error")
            safe_error = (
                candidate
                if isinstance(candidate, str)
                and _SAFE_REMOTE_ERROR.fullmatch(candidate)
                else "TARGET_REJECTED"
            )
            raise CanaryBlocked(
                f"N7_R0_{kind}_BLOCKED",
                f"{kind} failed closed: {safe_error}",
            )
        return response

    def _persist(self, report: Mapping[str, Any]) -> None:
        if _contains_raw_key(report):
            raise CanaryBlocked("N7_R0_RAW_PERSISTENCE_BLOCKED", "report contains raw provider output")
        encoded = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        try:
            write_new_artifact(self.artifact_path, encoded)
            indexed_files = [self.artifact_path]
            formal = report.get("formal_certify")
            if isinstance(formal, Mapping):
                formal_index = formal.get("artifact_index")
                if isinstance(formal_index, Mapping) and isinstance(
                    formal_index.get("path"), str
                ):
                    indexed_files.append(
                        self.artifact_path.parent / formal_index["path"]
                    )
            outer_index = build_artifact_index(
                run_id=str(report.get("certify_run_id") or report.get("session_id")),
                target_id=str(report.get("target_id", TARGET_ID)),
                files=indexed_files,
                root=self.artifact_path.parent,
            )
            write_new_artifact(
                self.artifact_path.parent / "canary-artifact-index.json",
                outer_index.model_dump_json(indent=2) + "\n",
            )
        except (OSError, ValueError) as exc:
            raise CanaryBlocked(
                "N7_R0_ARTIFACT_PUBLICATION_BLOCKED",
                "immutable outer canary evidence could not be published",
            ) from exc


def _contains_raw_key(value: object) -> bool:
    return _contains_sensitive_evidence_key(value)


def _contains_sensitive_evidence_key(value: object) -> bool:
    """Reject persisted provider detail/secret fields, but allow the boolean claim."""

    sensitive = {"raw", "detail", "secret", "password", "token", "credential"}
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if isinstance(key, str) and key != "raw_persisted":
                segments = {segment.lower() for segment in re.split(r"[_-]+", key)}
                if segments & sensitive:
                    return True
            if _contains_sensitive_evidence_key(nested):
                return True
        return False
    if isinstance(value, (list, tuple)):
        return any(_contains_sensitive_evidence_key(item) for item in value)
    return False


def _is_linklike(path: Path) -> bool:
    """Reject symlinks and Windows junctions at the deployment boundary."""

    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction()) if callable(is_junction) else False


def _regular_pinned_file(path: Path, *, label: str, max_bytes: int) -> tuple[Path, bytes]:
    candidate = path.expanduser()
    if _is_linklike(candidate):
        raise CanaryBlocked(
            f"N7_R0_{label}_UNTRUSTED",
            f"{label.lower()} must not be a symlink or junction",
        )
    try:
        resolved = candidate.resolve(strict=True)
        size = resolved.stat().st_size
        if not resolved.is_file() or not 0 < size <= max_bytes:
            raise OSError("file is missing, empty, or outside its size bound")
        payload = resolved.read_bytes()
    except OSError as exc:
        raise CanaryBlocked(
            f"N7_R0_{label}_UNAVAILABLE",
            f"{label.lower()} is not a bounded regular file",
        ) from exc
    if len(payload) != size:
        raise CanaryBlocked(
            f"N7_R0_{label}_CHANGED",
            f"{label.lower()} changed while it was read",
        )
    return resolved, payload


def _package_rolo_source(package_root: Path) -> bytes:
    """Create a deterministic, link-free archive rooted exactly at ``rolo``."""

    candidate = package_root.expanduser()
    if _is_linklike(candidate):
        raise CanaryBlocked(
            "N7_R0_PACKAGE_ROOT_UNTRUSTED",
            "package root must not be a symlink or junction",
        )
    try:
        root = candidate.resolve(strict=True)
    except OSError as exc:
        raise CanaryBlocked(
            "N7_R0_PACKAGE_ROOT_UNAVAILABLE",
            "package root does not exist",
        ) from exc
    source = root / "src" / "rolo"
    if _is_linklike(source) or not source.is_dir():
        raise CanaryBlocked(
            "N7_R0_PACKAGE_SOURCE_INVALID",
            "package root must contain a regular src/rolo directory",
        )

    entries: list[Path] = []
    expanded_bytes = 0
    try:
        for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()):
            if _is_linklike(path):
                raise CanaryBlocked(
                    "N7_R0_PACKAGE_SOURCE_UNTRUSTED",
                    "src/rolo contains a symlink or junction",
                )
            relative = path.relative_to(source)
            if "__pycache__" in relative.parts or path.suffix in {".pyc", ".pyo"}:
                continue
            if path.is_dir():
                entries.append(path)
                continue
            if not path.is_file():
                raise CanaryBlocked(
                    "N7_R0_PACKAGE_SOURCE_UNTRUSTED",
                    "src/rolo contains a non-regular filesystem entry",
                )
            expanded_bytes += path.stat().st_size
            if expanded_bytes > MAX_EXPANDED_BYTES:
                raise CanaryBlocked(
                    "N7_R0_EXPANDED_LIMIT",
                    f"expanded package exceeds {MAX_EXPANDED_BYTES} bytes",
                )
            entries.append(path)
    except OSError as exc:
        raise CanaryBlocked(
            "N7_R0_PACKAGE_SOURCE_CHANGED",
            "src/rolo changed while it was enumerated",
        ) from exc
    if not entries or len(entries) + 1 > 8192:
        raise CanaryBlocked(
            "N7_R0_PACKAGE_MEMBER_LIMIT",
            "src/rolo is empty or exceeds 8192 archive members",
        )

    output = io.BytesIO()
    try:
        with tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as archive:
            root_info = tarfile.TarInfo("rolo")
            root_info.type = tarfile.DIRTYPE
            root_info.mode = 0o755
            root_info.mtime = root_info.uid = root_info.gid = 0
            root_info.uname = root_info.gname = ""
            archive.addfile(root_info)
            for path in entries:
                name = PurePosixPath("rolo", *path.relative_to(source).parts).as_posix()
                info = tarfile.TarInfo(name)
                info.mtime = info.uid = info.gid = 0
                info.uname = info.gname = ""
                if path.is_dir():
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    archive.addfile(info)
                    continue
                payload = path.read_bytes()
                info.mode = 0o644
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
    except OSError as exc:
        raise CanaryBlocked(
            "N7_R0_PACKAGE_SOURCE_CHANGED",
            "src/rolo changed while it was archived",
        ) from exc
    payload = output.getvalue()
    if inspect_package(payload) != expanded_bytes:
        raise CanaryBlocked(
            "N7_R0_PACKAGE_SIZE_INVALID",
            "local package accounting differs from archive contents",
        )
    return payload


@dataclass(frozen=True)
class _LiveCliPreflight:
    """Values proven locally before the lazy SSH channel may be opened."""

    session_id: str
    certify_run_id: str
    executor: Any
    archive: bytes
    signing_key: str
    known_hosts_digest: str
    artifact_path: Path


def _signing_key_from_environment(variable_name: str) -> str:
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", variable_name) is None:
        raise CanaryBlocked(
            "N7_R0_SIGNING_KEY_ENV_INVALID",
            "signing-key environment variable name is invalid",
        )
    value = os.environ.get(variable_name)
    if (
        value is None
        or not 16 <= len(value) <= 4096
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise CanaryBlocked(
            "N7_R0_SIGNING_KEY_UNAVAILABLE",
            f"{variable_name} must contain a 16..4096 character single-line signing key",
        )
    return value


def _live_cli_preflight(args: argparse.Namespace) -> _LiveCliPreflight:
    """Validate every local live prerequisite without opening a socket."""

    import secrets
    import shutil

    from rolo.target_ref import SshTargetRef, parse_target_ref
    from rolo.targets.executor import SshTargetExecutor

    blockers = live_core_blockers()
    if blockers:
        raise CanaryBlocked(
            "N7_R0_CORE_ADAPTER_TODO",
            ",".join(blockers),
        )
    if shutil.which("ssh") is None or shutil.which("ssh-keygen") is None:
        raise CanaryBlocked(
            "N7_R0_OPENSSH_UNAVAILABLE",
            "ssh and ssh-keygen are required for pinned live transport",
        )
    try:
        target = parse_target_ref(args.target)
    except ValueError as exc:
        raise CanaryBlocked(
            "N7_R0_TARGET_REF_INVALID",
            "target must be a credential-free SSH URI with an absolute workspace",
        ) from exc
    if not isinstance(target, SshTargetRef) or target.user != "pi":
        raise CanaryBlocked(
            "N7_R0_TARGET_REF_INVALID",
            "target must be an ssh://pi@... URI",
        )

    known_hosts, known_hosts_payload = _regular_pinned_file(
        args.known_hosts,
        label="KNOWN_HOSTS",
        max_bytes=1024 * 1024,
    )
    identity_file, identity_payload = _regular_pinned_file(
        args.identity_file,
        label="IDENTITY_FILE",
        max_bytes=1024 * 1024,
    )
    del identity_payload
    lookup = f"[{target.host}]:{target.port}" if target.port is not None else target.host
    try:
        host_pin = subprocess.run(
            ["ssh-keygen", "-F", lookup, "-f", str(known_hosts)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CanaryBlocked(
            "N7_R0_KNOWN_HOSTS_CHECK_FAILED",
            "the pinned host entry could not be checked locally",
        ) from exc
    if host_pin.returncode != 0 or not host_pin.stdout.strip():
        raise CanaryBlocked(
            "N7_R0_HOST_PIN_MISSING",
            "known_hosts has no pin for the requested SSH host and port",
        )

    session_id = args.session_id
    if session_id is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        session_id = f"n7-r0-{timestamp}-{secrets.token_hex(4)}"
    if _ID.fullmatch(session_id) is None:
        raise CanaryBlocked(
            "N7_R0_SESSION_INVALID",
            "session id is not protocol-safe",
        )
    certify_run_id = args.certify_run_id
    if certify_run_id is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        certify_run_id = f"n6-formal-r0-{timestamp}-{secrets.token_hex(4)}"
    if _ID.fullmatch(certify_run_id) is None or certify_run_id == session_id:
        raise CanaryBlocked(
            "N7_R0_CERTIFY_RUN_INVALID",
            "formal Certify run id must be protocol-safe and independent from the session",
        )
    signing_key = _signing_key_from_environment(args.signing_key_env)
    archive = _package_rolo_source(args.package_root)

    artifact = args.artifact.expanduser()
    if _is_linklike(artifact) or (artifact.exists() and not artifact.is_file()):
        raise CanaryBlocked(
            "N7_R0_ARTIFACT_UNTRUSTED",
            "artifact must be a regular file path, not a symlink, junction, or directory",
        )
    artifact_path = artifact.resolve(strict=False)
    if artifact_path.exists():
        raise CanaryBlocked(
            "N7_R0_ARTIFACT_OCCUPIED",
            "live canary evidence is immutable and the requested artifact already exists",
        )
    formal_output = artifact_path.parent / "certification-report.json"
    try:
        preflight_new_artifact_paths(
            [
                artifact_path,
                artifact_path.parent / "canary-artifact-index.json",
                formal_output,
                formal_output.with_suffix(".md"),
                formal_output.with_suffix(".html"),
                artifact_path.parent / "release-binding.json",
                artifact_path.parent / "certify-test-suite.json",
                artifact_path.parent / "certification-report.events.jsonl",
                *[
                    artifact_path.parent
                    / f"certification-report.case-{index:02d}.targetd-call-receipt.json"
                    for index in range(1, CERTIFY_CASES + 1)
                ],
                artifact_path.parent / "artifact-index.json",
                artifact_path.parent / ".certify-publication.reservation",
            ]
        )
    except (OSError, ValueError) as exc:
        raise CanaryBlocked(
            "N7_R0_ARTIFACT_PREFLIGHT_BLOCKED",
            "formal canary artifact plan is occupied, unsafe, or not writable",
        ) from exc
    executor = SshTargetExecutor(
        target,
        known_hosts=known_hosts,
        identity_file=identity_file,
        timeout_s=args.ssh_timeout_s,
    )
    return _LiveCliPreflight(
        session_id=session_id,
        certify_run_id=certify_run_id,
        executor=executor,
        archive=archive,
        signing_key=signing_key,
        known_hosts_digest=_sha256(known_hosts_payload),
        artifact_path=artifact_path,
    )


def _persist_standalone_report(path: Path, report: Mapping[str, Any]) -> None:
    """Use the same atomic/no-raw guarantee for failures before Harness.run."""

    if _contains_raw_key(report):
        raise CanaryBlocked(
            "N7_R0_RAW_PERSISTENCE_BLOCKED",
            "report contains raw provider output",
        )
    encoded = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    try:
        write_new_artifact(path, encoded)
        index = build_artifact_index(
            run_id=str(report.get("certify_run_id") or report.get("session_id") or "preflight-blocked"),
            target_id=str(report.get("target_id", TARGET_ID)),
            files=[path],
            root=path.parent,
        )
        write_new_artifact(
            path.parent / "canary-artifact-index.json",
            index.model_dump_json(indent=2) + "\n",
        )
    except (OSError, ValueError) as exc:
        raise CanaryBlocked(
            "N7_R0_ARTIFACT_PUBLICATION_BLOCKED",
            "immutable preflight evidence could not be published",
        ) from exc


def _snapshot_binding(
    snapshot_payload: Mapping[str, Any],
    *,
    session_id: str,
    known_hosts_digest: str,
    signing_key: str,
    fixture_actor_id: str,
    confirmation_ttl_s: int,
    work_root: Path,
) -> N7R0SnapshotBinding:
    """Build all authority inputs from this channel's fresh target snapshot."""

    from rolo.dsl.admission import (
        MappingAdmissionIdentity,
        MappingAdmissionScope,
        MappingConfirmationStore,
        mapping_digest,
    )
    from rolo.dsl.canonical import context_digest, dsl_digest
    from rolo.dsl.compiler import compile_document
    from rolo.dsl.context import ProbeContext
    from rolo.dsl.models import DslDocument
    from rolo.dsl.runner import ConformanceRunner
    from rolo.releases import ReleasePublisher, tool_release_digest
    from rolo.targetd.ros2_runtime import Ros2RuntimeSnapshot

    expected_snapshot_fields = {
        "schema_version",
        "distro",
        "ros2_path",
        "topics",
        "nodes",
        "packages",
        "executor_user",
        "runtime_digest",
    }
    if set(snapshot_payload) != expected_snapshot_fields:
        raise CanaryBlocked(
            "N7_R0_ROS2_SNAPSHOT_INVALID",
            "target-owned ROS2 snapshot fields differ from the fixed challenge",
        )
    try:
        snapshot = Ros2RuntimeSnapshot.from_dict(dict(snapshot_payload))
    except (TypeError, ValueError) as exc:
        raise CanaryBlocked(
            "N7_R0_ROS2_SNAPSHOT_INVALID",
            "target-owned ROS2 snapshot is not canonical or digest-valid",
        ) from exc
    runtime_digest = snapshot.runtime_digest
    odom_topics = [
        topic
        for topic in snapshot.topics
        if topic.name == TOPIC and topic.interface_type == "nav_msgs/msg/Odometry"
    ]
    if (
        snapshot_payload.get("runtime_digest") != runtime_digest
        or snapshot.distro != "humble"
        or snapshot.ros2_path != "/opt/ros/humble/bin/ros2"
        or snapshot.executor_user != "ubuntu"
        or snapshot.publisher_user is not None
        or len(odom_topics) != 1
        or len(snapshot.topics) != 1
    ):
        raise CanaryBlocked(
            "N7_R0_ROS2_SNAPSHOT_SCOPE_INVALID",
            "fresh target snapshot does not prove the fixed ubuntu/Humble /odom executor surface",
        )

    target_fingerprint = _canonical_digest(
        {
            "schema_version": "rolo-n7-r0-target-fingerprint/v1",
            "target_id": TARGET_ID,
            "container": CONTAINER,
            "known_hosts_digest": known_hosts_digest,
            "runtime_digest": runtime_digest,
        }
    ).removeprefix("sha256:")
    context = ProbeContext(
        robot_id=TARGET_ID,
        target_fingerprint=target_fingerprint,
        runtime_revision=runtime_digest,
        evidence_digest=runtime_digest,
        evidence_refs=(TOPIC,),
        routes=(
            {
                "candidate_id": "n7-r0-odom-observe",
                "operation": TOOL_ID,
                "resource_id": TOPIC,
                "protocol": "ros2",
                "interface_type": "nav_msgs/msg/Odometry",
                "confidence": 1.0,
                "evidence_ref": TOPIC,
            },
        ),
        message_schemas=(
            {
                "schema_id": "nav_msgs/msg/Odometry",
                "source": "targetd:fresh-ros2-snapshot",
            },
        ),
        freshness={
            "status": "fresh",
            "runtime_digest": runtime_digest,
        },
        limitations=("fixture_confirmation_authority_partial",),
    )
    document = DslDocument(
        tool_id=TOOL_ID,
        kind=OPERATION_KIND,
        target={
            "robot_id": TARGET_ID,
            "evidence_digest": runtime_digest,
        },
        binding={
            "resource_id": TOPIC,
            "interface_type": "nav_msgs/msg/Odometry",
        },
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "required": ["status", "sha256", "byte_count"],
            "properties": {
                "status": {"const": "SUCCEEDED"},
                "sha256": {"type": "string"},
                "byte_count": {"type": "integer", "minimum": 1},
            },
            "additionalProperties": False,
        },
        evidence_refs=(TOPIC,),
    )
    document_digest = dsl_digest(document)
    probe_context_digest = context_digest(context)
    scope = MappingAdmissionScope(
        tool_id=TOOL_ID,
        operation_kind=OPERATION_KIND,
        operations=(PROVIDER_OPERATION,),
        access=ACCESS,
        risk=RISK,
    )
    identity_seed = {
        "schema_version": "rolo-n7-r0-fixture-admission/v1",
        "journey_session_id": session_id,
        "target_id": TARGET_ID,
        "target_fingerprint": target_fingerprint,
        "runtime_digest": runtime_digest,
        "dsl_digest": document_digest,
        "context_digest": probe_context_digest,
        "scope": scope.model_dump(mode="json"),
        "authority_partial": True,
    }
    identity = MappingAdmissionIdentity.build(
        journey_session_id=session_id,
        target_id=TARGET_ID,
        target_fingerprint=target_fingerprint,
        candidate_index_digest=mapping_digest({**identity_seed, "kind": "candidate-index"}),
        candidate_digest=mapping_digest({**identity_seed, "kind": "candidate"}),
        proposal_digest=mapping_digest({**identity_seed, "kind": "proposal"}),
        dsl_digest=document_digest,
        context_digest=probe_context_digest,
        evidence_digest=runtime_digest,
        available_tool_catalog_digest=mapping_digest(
            {
                "schema_version": "rolo-tool-catalog/v1",
                "tools": {},
                "authority_partial": True,
            }
        ),
        scope=scope,
    )
    confirmation_store = MappingConfirmationStore(work_root / "admission")
    receipt = confirmation_store.confirm(
        identity,
        decision_id=f"{session_id}:fixture-confirm",
        actor_id=fixture_actor_id,
        ttl_s=confirmation_ttl_s,
    )
    compiler_version = "rolo-compiler/0.1"
    compile_payload = {
        "schema_version": "rolo-targetd-dsl-compile/v2",
        "journey_session_id": session_id,
        "confirmation_receipt_digest": receipt.receipt_digest,
        "dsl_digest": document_digest,
        "context_digest": probe_context_digest,
        "target_fingerprint": target_fingerprint,
        "backend_hint": "ros2_observe",
        "runtime_backend_hint": "ros2_runtime",
        "required_capabilities": ["operation:OBSERVE"],
        "required_runtime_capabilities": ["read_only_topic", "ros2"],
    }
    put_payload = {
        "schema_version": "rolo-targetd-dsl-put/v1",
        "journey_session_id": session_id,
        "dsl": document.model_dump(mode="json", exclude_none=True),
        "context": context.model_dump(mode="json"),
        "compiler_version": compiler_version,
        "dsl_digest": document_digest,
        "context_digest": probe_context_digest,
        "target_fingerprint": target_fingerprint,
        "dsl_schema_version": document.schema_version,
        "context_schema_version": context.schema_version,
    }
    publisher = ReleasePublisher(
        work_root / "catalog",
        confirmation_store=confirmation_store,
    )

    def release_builder(
        remote_compile: Mapping[str, Any],
        target_report: TargetConformanceReport,
        target_conformance_digest: str,
    ) -> VerifiedExecutionPlan:
        canonical_target_digest = _canonical_digest(
            target_report.model_dump(mode="json")
        )
        if (
            target_conformance_digest != canonical_target_digest
            or _DIGEST.fullmatch(target_conformance_digest) is None
        ):
            raise CanaryBlocked(
                "N7_R0_TARGET_REPORT_DIGEST_INVALID",
                "target conformance report digest differs from its canonical payload",
            )
        admission = {
            "confirmation_store": confirmation_store,
            "confirmation_receipt_digest": receipt.receipt_digest,
            "journey_session_id": session_id,
        }
        compiled = compile_document(
            document,
            work_root / "local-compile",
            context=context,
            backend_id="ros2_observe",
            required_capabilities=("operation:OBSERVE",),
            compiler_version=compiler_version,
            **admission,
        )
        conformance = ConformanceRunner(work_root / "local-conformance").run(
            document,
            context,
            **admission,
        )
        release = publisher.publish_verified(
            compiled,
            conformance,
            target_report,
            target_fingerprint=target_fingerprint,
            compiler_version=compiler_version,
            target_compile_artifact_digest=str(
                remote_compile.get("compile_artifact_digest", "")
            ),
            compile_context_digest=probe_context_digest,
            journey_session_id=session_id,
            confirmation_receipt_digest=receipt.receipt_digest,
        )
        release_digest = tool_release_digest(release)
        source = (
            b"def execute(arguments):\n"
            b"    raise RuntimeError('ros2-readonly provider required')\n"
        )
        observation_contract = {
            "provider": PROVIDER_ID,
            "operation": PROVIDER_OPERATION,
            "topic": TOPIC,
            "interface_type": "nav_msgs/msg/Odometry",
            "operation_kind": OPERATION_KIND,
            "access": ACCESS,
            "risk": RISK,
            "mode": "READ_ONLY",
            "generated_bundle_digest": release.generated_bundle_digest,
        }
        binding_digest = hashlib.sha256(
            json.dumps(
                observation_contract,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        manifest = ExecutionBundleManifest.build(
            tool_id=TOOL_ID,
            source=source,
            binding_digest=binding_digest,
            signer_key_id="n7-r0-canary",
            signing_key=signing_key.encode("utf-8"),
            observation_contract=observation_contract,
            limits={
                "max_duration_s": 15,
                "max_output_bytes": MAX_RESULT_BYTES,
            },
            release_version=release_digest,
        )
        return VerifiedExecutionPlan(
            release=release,
            release_digest=release_digest,
            target_conformance_digest=target_conformance_digest,
            manifest=manifest,
            source=source,
            bridge_proof={
                "schema_version": "rolo-n7-r0-bundle-bridge/v1",
                "bundle_plan_digest": target_report.bundle_digest,
                "execution_bundle_digest": manifest.bundle_digest,
                "release_digest": release_digest,
                "target_conformance_digest": target_conformance_digest,
                "evidence_mode": "LIVE",
            },
            publisher=publisher,
        )

    return N7R0SnapshotBinding(
        admission_ledger=confirmation_store.path.read_bytes(),
        dsl_put_payload=put_payload,
        compile_payload=compile_payload,
        release_builder=release_builder,
    )


def _live_inputs(
    preflight: _LiveCliPreflight,
    *,
    fixture_actor_id: str,
    confirmation_ttl_s: int,
    work_root: Path,
) -> N7R0Inputs:
    if (
        not fixture_actor_id
        or fixture_actor_id != fixture_actor_id.strip()
        or len(fixture_actor_id) > 256
        or any(ord(character) < 32 for character in fixture_actor_id)
    ):
        raise CanaryBlocked(
            "N7_R0_FIXTURE_ACTOR_INVALID",
            "fixture actor id must be a normalized printable value",
        )
    if not 60 <= confirmation_ttl_s <= 3600:
        raise CanaryBlocked(
            "N7_R0_CONFIRMATION_TTL_INVALID",
            "fixture confirmation TTL must be between 60 and 3600 seconds",
        )
    bound_digest: str | None = None
    bound: N7R0SnapshotBinding | None = None

    def bind_snapshot(snapshot: Mapping[str, Any]) -> N7R0SnapshotBinding:
        nonlocal bound_digest, bound
        candidate_digest = snapshot.get("runtime_digest")
        if not isinstance(candidate_digest, str):
            raise CanaryBlocked(
                "N7_R0_ROS2_SNAPSHOT_INVALID",
                "target snapshot has no runtime digest",
            )
        if bound is not None:
            if candidate_digest != bound_digest:
                raise CanaryBlocked(
                    "N7_R0_ROS2_SNAPSHOT_REBOUND",
                    "one live session cannot bind two runtime snapshots",
                )
            return bound
        bound = _snapshot_binding(
            snapshot,
            session_id=preflight.session_id,
            known_hosts_digest=preflight.known_hosts_digest,
            signing_key=preflight.signing_key,
            fixture_actor_id=fixture_actor_id,
            confirmation_ttl_s=confirmation_ttl_s,
            work_root=work_root,
        )
        bound_digest = candidate_digest
        return bound

    surface_digest = _canonical_digest(
        {
            "schema_version": "rolo-n7-r0-readonly-surface/v1",
            "target_id": TARGET_ID,
            "container": CONTAINER,
            "tool_id": TOOL_ID,
            "topic": TOPIC,
            "interface_type": "nav_msgs/msg/Odometry",
            "operation_kind": OPERATION_KIND,
            "provider": PROVIDER_ID,
            "provider_operation": PROVIDER_OPERATION,
            "mode": "READ_ONLY",
            "access": ACCESS,
            "risk": RISK,
        }
    ).removeprefix("sha256:")
    return N7R0Inputs(
        session_id=preflight.session_id,
        certify_run_id=preflight.certify_run_id,
        target_id=TARGET_ID,
        surface_digest=surface_digest,
        archive=preflight.archive,
        bind_snapshot=bind_snapshot,
    )


def _blocked_live_report(
    blockers: tuple[str, ...],
    *,
    code: str = "N7_R0_CORE_ADAPTER_TODO",
    message: str = "live canary cannot prove every target-owned boundary",
    session_id: str | None = None,
    certify_run_id: str | None = None,
) -> dict[str, Any]:
    report = {
        "schema_version": SCHEMA_VERSION,
        "status": "BLOCKED",
        "code": code,
        "message": message,
        "blockers": list(blockers),
        "target_id": TARGET_ID,
        "container": CONTAINER,
        "topic": TOPIC,
        "operation_kind": OPERATION_KIND,
        "access": ACCESS,
        "risk": RISK,
        "operator_auth": "FIXTURE",
        "authority_partial": True,
        "ssh_opened": False,
        "outer_artifact_index_ref": "canary-artifact-index.json",
    }
    if session_id is not None:
        report["session_id"] = session_id
    if certify_run_id is not None:
        report["certify_run_id"] = certify_run_id
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the strict LanderPi N7-R0 /odom canary")
    parser.add_argument("--target", required=True, help="pinned ssh:// target")
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--identity-file", type=Path, required=True)
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--session-id")
    parser.add_argument("--certify-run-id")
    parser.add_argument(
        "--signing-key-env",
        default="ROLO_N7_R0_SIGNING_KEY",
        help="name of the environment variable containing the ephemeral bundle key",
    )
    parser.add_argument(
        "--fixture-actor-id",
        default="n7-r0-fixture-operator",
        help="actor recorded on the explicitly partial fixture confirmation",
    )
    parser.add_argument("--confirmation-ttl-s", type=int, default=1800)
    parser.add_argument("--ssh-timeout-s", type=float, default=10.0)
    args = parser.parse_args()

    preflight: _LiveCliPreflight | None = None
    try:
        preflight = _live_cli_preflight(args)
        with tempfile.TemporaryDirectory(prefix="rolo-n7-r0-host-") as temporary:
            inputs = _live_inputs(
                preflight,
                fixture_actor_id=args.fixture_actor_id,
                confirmation_ttl_s=args.confirmation_ttl_s,
                work_root=Path(temporary),
            )
            report = N7R0CanaryHarness(
                lambda: PinnedSshCanaryChannel.from_ssh_executor(
                    preflight.executor,
                    session_id=preflight.session_id,
                    signing_key=preflight.signing_key,
                ),
                artifact_path=preflight.artifact_path,
                evidence_mode="LIVE",
            ).run(inputs)
    except CanaryBlocked as exc:
        report = _blocked_live_report(
            (exc.code,),
            code=exc.code,
            message="live canary failed closed during preflight or immutable publication",
            session_id=preflight.session_id if preflight is not None else args.session_id,
            certify_run_id=(
                preflight.certify_run_id
                if preflight is not None
                else args.certify_run_id
            ),
        )
        artifact = preflight.artifact_path if preflight is not None else args.artifact.expanduser().resolve(strict=False)
        if not _is_linklike(artifact) and not artifact.exists():
            _persist_standalone_report(artifact, report)
    except (OSError, TypeError, ValueError) as exc:
        report = _blocked_live_report(
            ("N7_R0_LIVE_PREFLIGHT_FAILED",),
            code="N7_R0_LIVE_PREFLIGHT_FAILED",
            message=f"live canary failed closed: {type(exc).__name__}",
            session_id=preflight.session_id if preflight is not None else args.session_id,
            certify_run_id=(
                preflight.certify_run_id
                if preflight is not None
                else args.certify_run_id
            ),
        )
        artifact = preflight.artifact_path if preflight is not None else args.artifact.expanduser().resolve(strict=False)
        if not _is_linklike(artifact) and not artifact.exists():
            _persist_standalone_report(artifact, report)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0 if report.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
