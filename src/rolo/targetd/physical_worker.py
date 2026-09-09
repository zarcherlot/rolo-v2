"""Two-phase, fail-closed LanderPi rotation process adapter.

The daemon does not enable this module by default.  A physical worker profile
must explicitly select :class:`LanderPiRotateProcessWorker` and use the
following order:

1. ``prepare(control)`` starts the reviewed target-local ``bounded_twist``
   runtime.  It creates exactly one ``/rolo_bounded_twist`` publisher, emits
   repeated zero commands, and returns an authenticated ``ARMED_ZERO`` receipt.
2. The parent validates and durably consumes its live target gate while that
   exact ROS endpoint and container process remain present.
3. Only the process runtime's authenticated START calls
   ``prepared.execute(control)``.  Until then the inner process cannot publish
   a non-zero command.

The retained host ``docker exec`` handle is not treated as proof that the
container process stopped.  Every arm receipt binds the inner PID, Linux start
ticks and complete cmdline digest.  Normal completion, STOP, cancellation and
recovery all verify that exact identity is gone; the recovery command signals
only an exact identity match.  Missing final-zero evidence or any uncertain
boundary raises :class:`PhysicalWorkerAmbiguity`, which the leased process
runtime persists as ``UNKNOWN`` and must never replay.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import queue
import re
import secrets
import subprocess
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar, Literal

from rolo.core.rotation_evidence import has_verified_rotation_evidence
from rolo.dsl.parser import loads_unique_json
from rolo.mvp.bounded_twist import (
    DEFAULT_INDEPENDENT_IMU_ENDPOINTS,
    LANDERPI_CONTROLLED_COMMAND_ENDPOINT,
    MAX_ROTATION_ANGLE_RAD,
    MAX_ROTATION_SPEED_RAD_S,
    MIN_INDEPENDENT_ROTATION_RAD,
    motion_observation_duration_s,
)

from .lifecycle import WorkerCallKey, WorkerCompletion
from .lifecycle_integration import LeasedProviderOutcome
from .motion_acceptance import (
    ArmedZeroProviderBinding,
    compute_armed_zero_provider_identity_digest,
)
from .process_worker import ProcessWorkerControl
from .protocol import (
    ExecutionBundleManifest,
    ExecutionRequestLike,
    ExecutionRequestV3,
    validate_execution_request,
)
from .worker import RosContainerProvider

_TOOL_ID = "app.base.rotate"
_PROVIDER_ID = "ros-container"
_PROVIDER_OPERATION = "base.rotate"
_MODE = "SUPERVISED_FIELD_DEBUG"
_COMMAND_INTERFACE = "geometry_msgs/msg/Twist"
_STOP_STRATEGY = "zero_velocity"
_FEEDBACK_ENDPOINTS = ("/odom_raw", "/odom")
_INDEPENDENT_ENDPOINTS = tuple(DEFAULT_INDEPENDENT_IMU_ENDPOINTS)
_CONTRACT_KEYS = frozenset(
    {
        "provider",
        "operation",
        "command_endpoint",
        "feedback_endpoints",
        "independent_feedback_endpoints",
        "interface_type",
        "stop_strategy",
        "provider_runtime_sha256",
    }
)
_ARGUMENT_KEYS = frozenset({"angle_degrees", "max_speed_rad_s"})
_TARGET_STATUSES = frozenset(
    {
        "SUCCEEDED",
        "BLOCKED",
        "UNKNOWN",
        "CANCELLED",
        "STOPPED",
        "FAILED",
        "NOT_ACCEPTED",
    }
)

_CONTROL_SCHEMA = "rolo-targetd-physical-worker-control/v1"
_ARM_SCHEMA = "rolo-targetd-physical-worker-armed-zero/v1"
_PREPARE_ERROR_SCHEMA = "rolo-targetd-physical-worker-prepare-error/v1"
_RESULT_SCHEMA = "rolo-targetd-physical-worker-result/v1"
_INNER_IDENTITY_SCHEMA = "rolo-targetd-inner-process-identity/v1"
_ARM_RECEIPT_SCHEMA = "rolo-targetd-physical-worker-arm-receipt/v1"
_REGISTRY_SCHEMA = "rolo-targetd-physical-worker-registry/v1"
_REGISTRY_BINDING_SCHEMA = "rolo-targetd-physical-worker-registry-binding/v1"
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PREFIXED_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_GID = re.compile(r"^[0-9a-f]{16,128}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_PREPARE_ERROR_CODE = re.compile(r"^PHYSICAL_WORKER_[A-Z0-9_]{1,111}$")

_MAX_STDOUT_BYTES = 65_536
_MAX_STDERR_BYTES = 8_192
_MAX_LINE_BYTES = 65_536
_MAX_RUNTIME_SOURCE_BYTES = 128 * 1024
_MAX_PROGRAM_ARG_BYTES = 192 * 1024
_MAX_WALL_TIMEOUT_S = 75.0
_ARM_TIMEOUT_S = 8.0
_INTERRUPT_GRACE_S = 3.0
_POLL_INTERVAL_S = 0.02
_MAX_ARMED_ZERO_GATE_S = 60.0
_MAX_ZERO_HEARTBEAT_AGE_S = 0.25
_REGISTRY_REFRESH_INTERVAL_S = 0.1
_STATIONARY_WINDOW_S = 0.2
_STATIONARY_LAST_SAMPLE_MAX_AGE_S = 0.1
_STATIONARY_MAX_ABS_RAD_S = 0.03
_PRESTART_TRANSIENT_GRACE_S = 1.5
_REGISTRY_DIR = "/home/ubuntu/.local/state/rolo-targetd/physical-workers"

# This small pure library is embedded into the target-local worker so its
# pre-START decisions can be tested without ROS.  A discovered unexpected
# command endpoint is hazardous and fails immediately.  Missing discovery or
# evidence for an otherwise exact endpoint is transient: the caller may keep
# publishing zero for a bounded continuous grace interval.
_PRESTART_GUARD_LIBRARY = r"""
def classify_prestart_guard_observation(
    controlled_names, controlled_gids, expected_controlled_gids,
    competing_count, direct_names, subscription_count,
    stationary_sources, expected_stationary_sources, fresh_zero,
):
    if competing_count != 0:
        return 'DANGER', 'UNEXPECTED_COMPETING_COMMAND_PUBLISHER'
    if len(direct_names) == 0:
        return 'TRANSIENT', 'DIRECT_MOTOR_PUBLISHER_UNDISCOVERED'
    if direct_names != ['/odom_publisher']:
        return 'DANGER', 'UNEXPECTED_DIRECT_MOTOR_TOPOLOGY'
    if len(controlled_names) == 0:
        return 'TRANSIENT', 'OWN_PUBLISHER_UNDISCOVERED'
    if len(controlled_names) != 1 or controlled_names != ['/rolo_bounded_twist']:
        return 'DANGER', 'UNEXPECTED_CONTROL_PUBLISHER_TOPOLOGY'
    if len(controlled_gids) != 1 or controlled_gids[0] is None:
        return 'TRANSIENT', 'OWN_PUBLISHER_GID_UNDISCOVERED'
    if expected_controlled_gids is not None and controlled_gids != expected_controlled_gids:
        return 'DANGER', 'OWN_PUBLISHER_GID_CHANGED'
    if subscription_count <= 0:
        return 'TRANSIENT', 'OWN_SUBSCRIBER_UNDISCOVERED'
    if stationary_sources is None:
        return 'TRANSIENT', 'IMU_STATIONARY_EVIDENCE_UNAVAILABLE'
    if not set(expected_stationary_sources or ()).issubset(set(stationary_sources)):
        return 'TRANSIENT', 'ARMED_IMU_SOURCE_UNAVAILABLE'
    if not fresh_zero:
        return 'TRANSIENT', 'ZERO_FEEDBACK_UNAVAILABLE'
    return 'HEALTHY', None

def update_prestart_transient_guard(unhealthy_since, reason, now, grace_s):
    if reason is None:
        return None, None, False
    since = now if unhealthy_since is None else unhealthy_since
    return since, reason, now - since >= grace_s
"""

# This library runs only inside the fixed ROS container. It owns the HMAC key
# and registry files; neither is passed through argv or the host protocol.
_TARGET_REGISTRY_LIBRARY = r"""
import hashlib as _rh, hmac as _rhm, json as _rj, os as _ro, secrets as _rs, stat as _rst, time as _rt
_RDIR = '/home/ubuntu/.local/state/rolo-targetd/physical-workers'
_RSCHEMA = 'rolo-targetd-physical-worker-registry/v1'
_RMAX = 32768

def _rcanonical(value):
    return _rj.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')

def _rwrite_all(fd, value):
    view = memoryview(value)
    while view:
        count = _ro.write(fd, view)
        if count <= 0: raise RuntimeError('REGISTRY_SHORT_WRITE')
        view = view[count:]

def _rread_all(fd, limit):
    chunks = []; total = 0
    while True:
        chunk = _ro.read(fd, min(4096, limit + 1 - total))
        if not chunk: return b''.join(chunks)
        chunks.append(chunk); total += len(chunk)
        if total > limit: raise RuntimeError('REGISTRY_READ_TOO_LARGE')

def _rsecure_dir(create):
    parts = _RDIR.strip('/').split('/')
    flags = _ro.O_RDONLY | _ro.O_DIRECTORY | getattr(_ro, 'O_NOFOLLOW', 0)
    fd = _ro.open('/', flags)
    try:
        for index, part in enumerate(parts):
            try: child = _ro.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create: raise
                _ro.mkdir(part, 0o700, dir_fd=fd)
                child = _ro.open(part, flags, dir_fd=fd)
            st = _ro.fstat(child)
            if (not _rst.S_ISDIR(st.st_mode)
                or (index >= 1 and st.st_uid != _ro.geteuid())
                or _rst.S_IMODE(st.st_mode) & 0o022
                or (index >= len(parts) - 2 and _rst.S_IMODE(st.st_mode) != 0o700)):
                _ro.close(child); raise RuntimeError('REGISTRY_DIRECTORY_UNSAFE')
            _ro.close(fd); fd = child
        result = fd; fd = None; return result
    finally:
        if fd is not None: _ro.close(fd)

def _rkey(dirfd, create):
    flags = _ro.O_RDONLY | getattr(_ro, 'O_NOFOLLOW', 0)
    try:
        fd = _ro.open('.registry.key', flags, dir_fd=dirfd)
    except FileNotFoundError:
        if not create: raise
        try: _ro.stat('.registry.key.retiring', dir_fd=dirfd, follow_symlinks=False)
        except FileNotFoundError: pass
        else: raise RuntimeError('REGISTRY_KEY_RETIRING')
        value = _rs.token_hex(32).encode('ascii')
        fd = _ro.open('.registry.key', _ro.O_WRONLY | _ro.O_CREAT | _ro.O_EXCL | getattr(_ro, 'O_NOFOLLOW', 0), 0o600, dir_fd=dirfd)
        try:
            _rwrite_all(fd, value); _ro.fsync(fd)
        finally: _ro.close(fd)
        _ro.fsync(dirfd)
        fd = _ro.open('.registry.key', flags, dir_fd=dirfd)
    try:
        st = _ro.fstat(fd)
        if not _rst.S_ISREG(st.st_mode) or st.st_uid != _ro.geteuid() or _rst.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1 or st.st_size != 64:
            raise RuntimeError('REGISTRY_KEY_UNSAFE')
        value = _rread_all(fd, 64)
    finally: _ro.close(fd)
    if len(value) != 64 or any(ch not in b'0123456789abcdef' for ch in value):
        raise RuntimeError('REGISTRY_KEY_INVALID')
    return value

def _rsign(unsigned, key):
    return 'hmac-sha256:' + _rhm.new(key, _rcanonical(unsigned), _rh.sha256).hexdigest()

def _rread_file(dirfd, name, key):
    fd = _ro.open(name, _ro.O_RDONLY | getattr(_ro, 'O_NOFOLLOW', 0), dir_fd=dirfd)
    try:
        st = _ro.fstat(fd)
        if not _rst.S_ISREG(st.st_mode) or st.st_uid != _ro.geteuid() or _rst.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1 or st.st_size > _RMAX:
            raise RuntimeError('REGISTRY_RECORD_UNSAFE')
        raw = _rread_all(fd, _RMAX)
    finally: _ro.close(fd)
    value = _rj.loads(raw.decode('ascii'))
    if not isinstance(value, dict) or set(value) != {'schema_version','state','arm_receipt','updated_at_epoch_s','zero_refresh_count','last_zero_at_epoch_s','terminal_reason','registry_auth_tag'}:
        raise RuntimeError('REGISTRY_RECORD_INVALID')
    tag = value.pop('registry_auth_tag')
    if value.get('schema_version') != _RSCHEMA or not isinstance(tag, str) or not _rhm.compare_digest(tag, _rsign(value, key)):
        raise RuntimeError('REGISTRY_AUTH_INVALID')
    return {**value, 'registry_auth_tag': tag}

def _rwrite_file(dirfd, name, unsigned, key, exclusive_target):
    if exclusive_target:
        try: _ro.stat(name, dir_fd=dirfd, follow_symlinks=False)
        except FileNotFoundError: pass
        else: raise RuntimeError('REGISTRY_ACTIVE_EXISTS')
    value = {**unsigned, 'registry_auth_tag': _rsign(unsigned, key)}
    raw = _rcanonical(value)
    if len(raw) > _RMAX: raise RuntimeError('REGISTRY_RECORD_TOO_LARGE')
    temp = '.registry-%d-%s.tmp' % (_ro.getpid(), _rs.token_hex(8))
    fd = _ro.open(temp, _ro.O_WRONLY | _ro.O_CREAT | _ro.O_EXCL | getattr(_ro, 'O_NOFOLLOW', 0), 0o600, dir_fd=dirfd)
    try:
        _rwrite_all(fd, raw); _ro.fsync(fd)
    finally: _ro.close(fd)
    try:
        if exclusive_target:
            _ro.link(temp, name, src_dir_fd=dirfd, dst_dir_fd=dirfd, follow_symlinks=False)
            _ro.unlink(temp, dir_fd=dirfd)
        else:
            _ro.replace(temp, name, src_dir_fd=dirfd, dst_dir_fd=dirfd)
    except Exception:
        try: _ro.unlink(temp, dir_fd=dirfd)
        except Exception: pass
        raise
    _ro.fsync(dirfd)
    return value

def registry_write_active(arm_receipt):
    dirfd = _rsecure_dir(True)
    try:
        key = _rkey(dirfd, True)
        now = _rt.time()
        unsigned = {'schema_version':_RSCHEMA,'state':'ACTIVE','arm_receipt':arm_receipt,'updated_at_epoch_s':now,'zero_refresh_count':0,'last_zero_at_epoch_s':now,'terminal_reason':None}
        return _rwrite_file(dirfd, 'active.json', unsigned, key, True)
    finally: _ro.close(dirfd)

def registry_read_active():
    dirfd = _rsecure_dir(False)
    try: return _rread_file(dirfd, 'active.json', _rkey(dirfd, False))
    finally: _ro.close(dirfd)

def registry_read_terminal(arm_digest):
    if (not isinstance(arm_digest, str) or len(arm_digest) != 64
        or any(ch not in '0123456789abcdef' for ch in arm_digest)):
        raise RuntimeError('REGISTRY_ARM_DIGEST_INVALID')
    dirfd = _rsecure_dir(False)
    try:
        return _rread_file(
            dirfd, 'terminal-%s.json' % arm_digest, _rkey(dirfd, False))
    finally: _ro.close(dirfd)

def registry_refresh_active(arm_digest, pid, start_ticks, cmdline_sha256):
    dirfd = _rsecure_dir(False)
    try:
        key = _rkey(dirfd, False); current = _rread_file(dirfd, 'active.json', key)
        arm = current['arm_receipt']; identity = arm.get('inner_process_identity', {})
        if (current['state'] != 'ACTIVE'
            or arm.get('arm_receipt_digest') != arm_digest
            or identity.get('pid') != pid
            or identity.get('start_ticks') != start_ticks
            or identity.get('cmdline_sha256') != cmdline_sha256):
            raise RuntimeError('REGISTRY_IDENTITY_MISMATCH')
        now = _rt.time()
        unsigned = {**{k:v for k,v in current.items() if k != 'registry_auth_tag'},
            'updated_at_epoch_s':now,
            'zero_refresh_count':current['zero_refresh_count'] + 1,
            'last_zero_at_epoch_s':now}
        return _rwrite_file(dirfd, 'active.json', unsigned, key, False)
    finally: _ro.close(dirfd)

def registry_terminalize(arm_digest, pid, start_ticks, cmdline_sha256, reason):
    dirfd = _rsecure_dir(False)
    try:
        key = _rkey(dirfd, False); terminal = 'terminal-%s.json' % arm_digest
        try: existing = _rread_file(dirfd, terminal, key)
        except FileNotFoundError: existing = None
        if existing is not None:
            arm = existing['arm_receipt']; identity = arm.get('inner_process_identity', {})
            if (existing['state'] != 'TERMINAL'
                or arm.get('arm_receipt_digest') != arm_digest
                or identity.get('pid') != pid
                or identity.get('start_ticks') != start_ticks
                or identity.get('cmdline_sha256') != cmdline_sha256):
                raise RuntimeError('REGISTRY_IDENTITY_MISMATCH')
            try: active = _rread_file(dirfd, 'active.json', key)
            except FileNotFoundError: return True
            if active.get('arm_receipt') != arm:
                raise RuntimeError('REGISTRY_ACTIVE_CONFLICT')
            _ro.unlink('active.json', dir_fd=dirfd); _ro.fsync(dirfd)
            return True
        current = _rread_file(dirfd, 'active.json', key)
        arm = current['arm_receipt']; identity = arm.get('inner_process_identity', {})
        if (current['state'] != 'ACTIVE'
            or arm.get('arm_receipt_digest') != arm_digest
            or identity.get('pid') != pid
            or identity.get('start_ticks') != start_ticks
            or identity.get('cmdline_sha256') != cmdline_sha256):
            raise RuntimeError('REGISTRY_IDENTITY_MISMATCH')
        unsigned = {**{k:v for k,v in current.items() if k not in {'registry_auth_tag','state','updated_at_epoch_s','terminal_reason'}},
            'schema_version':_RSCHEMA,'state':'TERMINAL','updated_at_epoch_s':_rt.time(),'terminal_reason':reason}
        # Publish the terminal record before removing ACTIVE.  A crash between
        # these operations is repaired by the idempotent existing-terminal
        # branch above; ACTIVE is never overwritten with an unrecoverable
        # terminal-shaped value.
        _rwrite_file(dirfd, terminal, unsigned, key, True)
        _ro.unlink('active.json', dir_fd=dirfd); _ro.fsync(dirfd)
        return True
    finally: _ro.close(dirfd)

def registry_cleanup_terminal(call_key_digest, arm_digest, pid, start_ticks, cmdline_sha256):
    dirfd = _rsecure_dir(False); remove_dir = False
    try:
        key = _rkey(dirfd, False); terminal = 'terminal-%s.json' % arm_digest
        current = _rread_file(dirfd, terminal, key)
        arm = current['arm_receipt']; identity = arm.get('inner_process_identity', {})
        if (current['state'] != 'TERMINAL'
            or arm.get('call_key_digest') != call_key_digest
            or arm.get('arm_receipt_digest') != arm_digest
            or identity.get('pid') != pid
            or identity.get('start_ticks') != start_ticks
            or identity.get('cmdline_sha256') != cmdline_sha256):
            raise RuntimeError('REGISTRY_IDENTITY_MISMATCH')
        try:
            stat_fields = open('/proc/%d/stat' % pid, 'rb').read().split()
            cmdline = open('/proc/%d/cmdline' % pid, 'rb').read()
            live = int(stat_fields[21]) == start_ticks and _rh.sha256(cmdline).hexdigest() == cmdline_sha256
        except (FileNotFoundError, ProcessLookupError): live = False
        if live: raise RuntimeError('REGISTRY_INNER_STILL_LIVE')
        _ro.unlink(terminal, dir_fd=dirfd); _ro.fsync(dirfd)
        if set(_ro.listdir(dirfd)) == {'.registry.key'}:
            _ro.replace('.registry.key', '.registry.key.retiring', src_dir_fd=dirfd, dst_dir_fd=dirfd)
            _ro.fsync(dirfd)
            if set(_ro.listdir(dirfd)) == {'.registry.key.retiring'}:
                _ro.unlink('.registry.key.retiring', dir_fd=dirfd); _ro.fsync(dirfd); remove_dir = True
            else:
                _ro.replace('.registry.key.retiring', '.registry.key', src_dir_fd=dirfd, dst_dir_fd=dirfd)
                _ro.fsync(dirfd)
    finally: _ro.close(dirfd)
    if remove_dir:
        try: _ro.rmdir(_RDIR)
        except OSError: pass
        try: _ro.rmdir(_ro.path.dirname(_RDIR))
        except OSError: pass
    return True

def registry_quarantine(call_key_digest, target_id, call_id, session_id, request_digest,
                        execution_subject_digest, runtime_sha256, pid, start_ticks,
                        cmdline_sha256):
    try: current = registry_read_active()
    except FileNotFoundError: return True
    arm = current['arm_receipt']
    identity = arm.get('inner_process_identity', {})
    if (current['state'] != 'ACTIVE'
        or arm.get('call_key_digest') != call_key_digest
        or arm.get('target_id') != target_id
        or arm.get('call_id') != call_id
        or arm.get('session_id') != session_id
        or arm.get('request_digest') != request_digest
        or arm.get('execution_subject_digest') != execution_subject_digest
        or arm.get('runtime_sha256') != runtime_sha256
        or identity.get('pid') != pid
        or identity.get('start_ticks') != start_ticks
        or identity.get('cmdline_sha256') != cmdline_sha256):
        raise RuntimeError('REGISTRY_QUARANTINE_IDENTITY_MISMATCH')
    return registry_terminalize(
        arm['arm_receipt_digest'], pid, start_ticks, cmdline_sha256,
        'AMBIGUOUS_REAP')
""".strip()

_REGISTRY_CONTROL = f"""
import json, sys
exec({repr(_TARGET_REGISTRY_LIBRARY)}, globals())
mode = sys.argv[1]
if mode == 'read':
    try: value = registry_read_active()
    except FileNotFoundError: print('ABSENT', flush=True); raise SystemExit(0)
elif mode == 'terminal':
    value = registry_terminalize(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5], sys.argv[6])
elif mode == 'cleanup':
    value = registry_cleanup_terminal(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), sys.argv[6])
elif mode == 'quarantine':
    value = registry_quarantine(
        sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6],
        sys.argv[7], sys.argv[8], int(sys.argv[9]), int(sys.argv[10]), sys.argv[11])
else:
    raise RuntimeError('REGISTRY_MODE_INVALID')
print(json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(',', ':')), flush=True)
""".strip()

_REGISTRY_READER = f"""
import json
exec({repr(_TARGET_REGISTRY_LIBRARY)}, globals())
try: value = registry_read_active()
except FileNotFoundError: print('ABSENT', flush=True); raise SystemExit(0)
print(json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(',', ':')), flush=True)
""".strip()

_REGISTRY_TERMINAL_READER = f"""
import json, sys
exec({repr(_TARGET_REGISTRY_LIBRARY)}, globals())
try: value = registry_read_terminal(sys.argv[1])
except FileNotFoundError: print('ABSENT', flush=True); raise SystemExit(0)
print(json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(',', ':')), flush=True)
""".strip()

# The program itself is fixed.  Dynamic timeout/program arguments are quoted
# positional argv, never interpolated into this shell fragment.
_CONTAINER_BOOTSTRAP = (
    "set -e; export HOME=/home/ubuntu; "
    ". /opt/ros/humble/setup.bash; "
    ". /home/ubuntu/ros2_ws/install/setup.bash; "
    ". /home/ubuntu/ros2_ws/.robotrc >/dev/null; "
    'exec timeout --foreground --kill-after=2s "$1" python3 -c "$2"'
)

# A second, shell-free docker exec verifies/reaps the *inner* process.  It
# never signals a PID unless both its Linux start ticks and full cmdline digest
# match the authenticated arm receipt.  REPLACED means the original identity
# is already gone and the reused PID is deliberately left untouched.
_INNER_REAPER = r"""
import hashlib, os, signal, sys, time
mode, raw_pid, raw_start, expected = sys.argv[1:5]
pid = int(raw_pid); start = int(raw_start)
def identity_matches():
    try:
        stat = open('/proc/%d/stat' % pid, 'rb').read().split()
        cmd = open('/proc/%d/cmdline' % pid, 'rb').read()
    except (FileNotFoundError, ProcessLookupError):
        return False
    return int(stat[21]) == start and hashlib.sha256(cmd).hexdigest() == expected
if not identity_matches():
    print('GONE', flush=True); raise SystemExit(0)
if mode == 'probe':
    print('LIVE', flush=True); raise SystemExit(4)
if mode != 'reap':
    print('INVALID', flush=True); raise SystemExit(5)
try:
    os.kill(pid, signal.SIGTERM)
except ProcessLookupError:
    print('GONE', flush=True); raise SystemExit(0)
deadline = time.monotonic() + 2.0
while time.monotonic() < deadline and identity_matches(): time.sleep(0.02)
if identity_matches():
    os.kill(pid, signal.SIGKILL)
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline and identity_matches(): time.sleep(0.02)
if identity_matches():
    print('LIVE', flush=True); raise SystemExit(6)
print('REAPED', flush=True)
""".strip()


class PhysicalWorkerConfigurationError(ValueError):
    """Stable rejection before a non-zero provider boundary is possible."""


class PhysicalWorkerAmbiguity(RuntimeError):
    """An attempted provider boundary cannot be proven terminal and safe."""


@dataclass(frozen=True)
class InnerProcessIdentity:
    """Call-scoped Linux identity for the process inside the ROS container."""

    pid: int
    start_ticks: int
    cmdline_sha256: str

    @classmethod
    def parse(cls, value: object) -> InnerProcessIdentity:
        if not isinstance(value, Mapping) or set(value) != {
            "schema_version",
            "pid",
            "start_ticks",
            "cmdline_sha256",
        }:
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_ARM_IDENTITY_INVALID")
        pid = value.get("pid")
        start_ticks = value.get("start_ticks")
        digest = value.get("cmdline_sha256")
        if (
            value.get("schema_version") != _INNER_IDENTITY_SCHEMA
            or isinstance(pid, bool)
            or not isinstance(pid, int)
            or pid <= 1
            or isinstance(start_ticks, bool)
            or not isinstance(start_ticks, int)
            or start_ticks <= 0
            or not isinstance(digest, str)
            or _HEX_SHA256.fullmatch(digest) is None
        ):
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_ARM_IDENTITY_INVALID")
        return cls(pid=pid, start_ticks=start_ticks, cmdline_sha256=digest)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": _INNER_IDENTITY_SCHEMA,
            "pid": self.pid,
            "start_ticks": self.start_ticks,
            "cmdline_sha256": self.cmdline_sha256,
        }


@dataclass(frozen=True)
class PhysicalWorkerArmedZero:
    """Authenticated zero-motion receipt returned before target gate consume."""

    call_key_digest: str
    target_id: str
    call_id: str
    session_id: str
    request_digest: str
    execution_subject_digest: str
    runtime_sha256: str
    command_endpoint: str
    publisher_identity: str
    publisher_endpoint_gids: tuple[str, ...]
    competing_publisher_count: int
    direct_motor_publisher_identities: tuple[str, ...]
    zeros_published: int
    independent_stationary_sources: tuple[str, ...]
    independent_stationary_sample_counts: tuple[tuple[str, int], ...]
    independent_stationary_last_sample_age_s: tuple[tuple[str, float], ...]
    independent_stationary_max_abs_rad_s: tuple[tuple[str, float], ...]
    independent_stationary_window_s: float
    inner_process_identity: InnerProcessIdentity
    target_monotonic_s: float
    provider_runtime_sha256: str
    provider_cmdline_sha256: str
    provider_runtime_identity_digest: str
    registry_issued_at_epoch_s: float
    registry_expires_at_epoch_s: float
    registry_binding_digest: str
    arm_receipt_digest: str

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": _ARM_RECEIPT_SCHEMA,
            "call_key_digest": self.call_key_digest,
            "target_id": self.target_id,
            "call_id": self.call_id,
            "session_id": self.session_id,
            "request_digest": self.request_digest,
            "execution_subject_digest": self.execution_subject_digest,
            "runtime_sha256": self.runtime_sha256,
            "command_endpoint": self.command_endpoint,
            "publisher_identity": self.publisher_identity,
            "publisher_endpoint_gids": list(self.publisher_endpoint_gids),
            "publisher_endpoint_count": len(self.publisher_endpoint_gids),
            "competing_publisher_count": self.competing_publisher_count,
            "direct_motor_publisher_identities": list(self.direct_motor_publisher_identities),
            "zeros_published": self.zeros_published,
            "independent_stationary_sources": list(self.independent_stationary_sources),
            "independent_stationary_sample_counts": dict(self.independent_stationary_sample_counts),
            "independent_stationary_last_sample_age_s": dict(self.independent_stationary_last_sample_age_s),
            "independent_stationary_max_abs_rad_s": dict(self.independent_stationary_max_abs_rad_s),
            "independent_stationary_window_s": self.independent_stationary_window_s,
            "motion_command_emitted": False,
            "motion_enabled": False,
            "inner_process_identity": self.inner_process_identity.as_dict(),
            "target_monotonic_s": self.target_monotonic_s,
            "provider_runtime_sha256": self.provider_runtime_sha256,
            "provider_cmdline_sha256": self.provider_cmdline_sha256,
            "provider_runtime_identity_digest": self.provider_runtime_identity_digest,
            "registry_issued_at_epoch_s": self.registry_issued_at_epoch_s,
            "registry_expires_at_epoch_s": self.registry_expires_at_epoch_s,
            "registry_binding_digest": self.registry_binding_digest,
            "arm_receipt_digest": self.arm_receipt_digest,
        }

    def provider_binding(self) -> ArmedZeroProviderBinding:
        """Project the receipt into the gate's exact shared binding model."""

        return ArmedZeroProviderBinding(
            call_id=self.call_id,
            session_id=self.session_id,
            execution_subject_digest=self.execution_subject_digest,
            publisher_identity=self.publisher_identity,
            publisher_gid=self.publisher_endpoint_gids[0],
            provider_pid=self.inner_process_identity.pid,
            provider_start_time_ticks=self.inner_process_identity.start_ticks,
            provider_runtime_sha256=self.provider_runtime_sha256,
            provider_cmdline_sha256=self.provider_cmdline_sha256,
            provider_runtime_identity_digest=self.provider_runtime_identity_digest,
        )


def _parse_independent_stationary_evidence(
    value: Mapping[str, Any],
) -> tuple[
    tuple[str, ...],
    tuple[tuple[str, int], ...],
    tuple[tuple[str, float], ...],
    tuple[tuple[str, float], ...],
    float,
]:
    sources = value.get("independent_stationary_sources")
    counts = value.get("independent_stationary_sample_counts")
    ages = value.get("independent_stationary_last_sample_age_s")
    maxima = value.get("independent_stationary_max_abs_rad_s")
    window = _optional_finite_number(value.get("independent_stationary_window_s"))
    if (
        not isinstance(sources, list)
        or not sources
        or sources != sorted(sources)
        or len(set(sources)) != len(sources)
        or any(source not in _INDEPENDENT_ENDPOINTS for source in sources)
        or not isinstance(counts, Mapping)
        or not isinstance(ages, Mapping)
        or not isinstance(maxima, Mapping)
        or set(counts) != set(sources)
        or set(ages) != set(sources)
        or set(maxima) != set(sources)
        or window is None
        or not math.isclose(window, _STATIONARY_WINDOW_S, abs_tol=1e-12)
    ):
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_STATIONARY_EVIDENCE_INVALID")
    parsed_counts: list[tuple[str, int]] = []
    parsed_ages: list[tuple[str, float]] = []
    parsed_maxima: list[tuple[str, float]] = []
    for source in sources:
        count = counts.get(source)
        age = _optional_finite_number(ages.get(source))
        maximum = _optional_finite_number(maxima.get(source))
        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or count < 2
            or age is None
            or not 0 <= age <= _STATIONARY_LAST_SAMPLE_MAX_AGE_S
            or maximum is None
            or not 0 <= maximum <= _STATIONARY_MAX_ABS_RAD_S
        ):
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_STATIONARY_EVIDENCE_INVALID")
        parsed_counts.append((source, count))
        parsed_ages.append((source, age))
        parsed_maxima.append((source, maximum))
    return (
        tuple(sources),
        tuple(parsed_counts),
        tuple(parsed_ages),
        tuple(parsed_maxima),
        window,
    )


def parse_physical_worker_armed_zero(
    value: object,
    *,
    expected_call_key_digest: str,
    expected_request_digest: str,
    expected_execution_subject_digest: str,
    expected_runtime_sha256: str,
    expected_target_id: str | None = None,
    expected_call_id: str | None = None,
    expected_session_id: str | None = None,
) -> PhysicalWorkerArmedZero:
    """Strictly restore and bind a serialized ARMED_ZERO receipt.

    The process runtime uses this at the parent boundary after authenticating
    the child frame. Exact keys and a recomputed receipt digest prevent a
    permissive mapping from being mistaken for the typed, call-bound proof.
    """

    raw_expected_digests = (
        expected_call_key_digest,
        expected_request_digest,
        expected_runtime_sha256,
    )
    if (
        any(not isinstance(item, str) or _HEX_SHA256.fullmatch(item) is None for item in raw_expected_digests)
        or not isinstance(expected_execution_subject_digest, str)
        or _PREFIXED_SHA256.fullmatch(expected_execution_subject_digest) is None
    ):
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_ARM_EXPECTATION_INVALID")
    expected_keys = {
        "schema_version",
        "call_key_digest",
        "target_id",
        "call_id",
        "session_id",
        "request_digest",
        "execution_subject_digest",
        "runtime_sha256",
        "command_endpoint",
        "publisher_identity",
        "publisher_endpoint_gids",
        "publisher_endpoint_count",
        "competing_publisher_count",
        "direct_motor_publisher_identities",
        "zeros_published",
        "independent_stationary_sources",
        "independent_stationary_sample_counts",
        "independent_stationary_last_sample_age_s",
        "independent_stationary_max_abs_rad_s",
        "independent_stationary_window_s",
        "motion_command_emitted",
        "motion_enabled",
        "inner_process_identity",
        "target_monotonic_s",
        "provider_runtime_sha256",
        "provider_cmdline_sha256",
        "provider_runtime_identity_digest",
        "registry_issued_at_epoch_s",
        "registry_expires_at_epoch_s",
        "registry_binding_digest",
        "arm_receipt_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected_keys:
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_ARM_RECEIPT_INVALID")
    receipt = dict(value)
    gids = receipt.get("publisher_endpoint_gids")
    direct = receipt.get("direct_motor_publisher_identities")
    zeros = receipt.get("zeros_published")
    target_id = receipt.get("target_id")
    call_id = receipt.get("call_id")
    session_id = receipt.get("session_id")
    target_time = _optional_finite_number(receipt.get("target_monotonic_s"))
    observed_digest = receipt.get("arm_receipt_digest")
    provider_runtime_sha256 = receipt.get("provider_runtime_sha256")
    provider_cmdline_sha256 = receipt.get("provider_cmdline_sha256")
    provider_runtime_identity_digest = receipt.get("provider_runtime_identity_digest")
    registry_issued_at = _optional_finite_number(receipt.get("registry_issued_at_epoch_s"))
    registry_expires_at = _optional_finite_number(receipt.get("registry_expires_at_epoch_s"))
    registry_binding_digest = receipt.get("registry_binding_digest")
    stationary = _parse_independent_stationary_evidence(receipt)
    if (
        receipt.get("schema_version") != _ARM_RECEIPT_SCHEMA
        or receipt.get("call_key_digest") != expected_call_key_digest
        or not isinstance(target_id, str)
        or _IDENTIFIER.fullmatch(target_id) is None
        or (expected_target_id is not None and target_id != expected_target_id)
        or not isinstance(call_id, str)
        or _IDENTIFIER.fullmatch(call_id) is None
        or (expected_call_id is not None and call_id != expected_call_id)
        or not isinstance(session_id, str)
        or _IDENTIFIER.fullmatch(session_id) is None
        or (expected_session_id is not None and session_id != expected_session_id)
        or receipt.get("request_digest") != expected_request_digest
        or receipt.get("execution_subject_digest") != expected_execution_subject_digest
        or receipt.get("runtime_sha256") != expected_runtime_sha256
        or receipt.get("command_endpoint") != LANDERPI_CONTROLLED_COMMAND_ENDPOINT
        or receipt.get("publisher_identity") != "/rolo_bounded_twist"
        or not isinstance(gids, list)
        or len(gids) != 1
        or not isinstance(gids[0], str)
        or _GID.fullmatch(gids[0]) is None
        or isinstance(receipt.get("publisher_endpoint_count"), bool)
        or receipt.get("publisher_endpoint_count") != 1
        or isinstance(receipt.get("competing_publisher_count"), bool)
        or receipt.get("competing_publisher_count") != 0
        or direct != ["/odom_publisher"]
        or isinstance(zeros, bool)
        or not isinstance(zeros, int)
        or zeros < 5
        or receipt.get("motion_command_emitted") is not False
        or receipt.get("motion_enabled") is not False
        or target_time is None
        or target_time <= 0
        or provider_runtime_sha256 != f"sha256:{expected_runtime_sha256}"
        or not isinstance(provider_cmdline_sha256, str)
        or _PREFIXED_SHA256.fullmatch(provider_cmdline_sha256) is None
        or not isinstance(provider_runtime_identity_digest, str)
        or _PREFIXED_SHA256.fullmatch(provider_runtime_identity_digest) is None
        or registry_issued_at is None
        or registry_issued_at <= 0
        or registry_expires_at is None
        or registry_expires_at <= registry_issued_at
        or registry_expires_at - registry_issued_at > _MAX_ARMED_ZERO_GATE_S
        or not isinstance(registry_binding_digest, str)
        or _PREFIXED_SHA256.fullmatch(registry_binding_digest) is None
        or not isinstance(observed_digest, str)
        or _HEX_SHA256.fullmatch(observed_digest) is None
    ):
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_ARM_RECEIPT_INVALID")
    identity = InnerProcessIdentity.parse(receipt.get("inner_process_identity"))
    if provider_cmdline_sha256 != f"sha256:{identity.cmdline_sha256}":
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_ARM_RECEIPT_INVALID")
    expected_provider_identity_digest = compute_armed_zero_provider_identity_digest(
        call_id=call_id,
        session_id=session_id,
        execution_subject_digest=expected_execution_subject_digest,
        publisher_identity="/rolo_bounded_twist",
        publisher_gid=gids[0],
        provider_pid=identity.pid,
        provider_start_time_ticks=identity.start_ticks,
        provider_runtime_sha256=provider_runtime_sha256,
        provider_cmdline_sha256=provider_cmdline_sha256,
    )
    if not hmac.compare_digest(
        provider_runtime_identity_digest,
        expected_provider_identity_digest,
    ):
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_PROVIDER_IDENTITY_DIGEST_MISMATCH")
    expected_registry_binding_digest = _registry_binding_digest(
        target_id=target_id,
        call_key_digest=expected_call_key_digest,
        call_id=call_id,
        session_id=session_id,
        execution_subject_digest=expected_execution_subject_digest,
        publisher_identity="/rolo_bounded_twist",
        publisher_gid=gids[0],
        provider_pid=identity.pid,
        provider_start_time_ticks=identity.start_ticks,
        provider_runtime_sha256=provider_runtime_sha256,
        provider_cmdline_sha256=provider_cmdline_sha256,
        issued_at_epoch_s=registry_issued_at,
        expires_at_epoch_s=registry_expires_at,
    )
    if not hmac.compare_digest(
        registry_binding_digest,
        expected_registry_binding_digest,
    ):
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_REGISTRY_BINDING_DIGEST_MISMATCH")
    unsigned = dict(receipt)
    del unsigned["arm_receipt_digest"]
    try:
        expected_digest = hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()
    except PhysicalWorkerConfigurationError as exc:
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_ARM_RECEIPT_INVALID") from exc
    if not hmac.compare_digest(observed_digest, expected_digest):
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_ARM_RECEIPT_DIGEST_MISMATCH")
    return PhysicalWorkerArmedZero(
        call_key_digest=expected_call_key_digest,
        target_id=target_id,
        call_id=call_id,
        session_id=session_id,
        request_digest=expected_request_digest,
        execution_subject_digest=expected_execution_subject_digest,
        runtime_sha256=expected_runtime_sha256,
        command_endpoint=LANDERPI_CONTROLLED_COMMAND_ENDPOINT,
        publisher_identity="/rolo_bounded_twist",
        publisher_endpoint_gids=(gids[0],),
        competing_publisher_count=0,
        direct_motor_publisher_identities=("/odom_publisher",),
        zeros_published=zeros,
        independent_stationary_sources=stationary[0],
        independent_stationary_sample_counts=stationary[1],
        independent_stationary_last_sample_age_s=stationary[2],
        independent_stationary_max_abs_rad_s=stationary[3],
        independent_stationary_window_s=stationary[4],
        inner_process_identity=identity,
        target_monotonic_s=target_time,
        provider_runtime_sha256=provider_runtime_sha256,
        provider_cmdline_sha256=provider_cmdline_sha256,
        provider_runtime_identity_digest=provider_runtime_identity_digest,
        registry_issued_at_epoch_s=registry_issued_at,
        registry_expires_at_epoch_s=registry_expires_at,
        registry_binding_digest=registry_binding_digest,
        arm_receipt_digest=observed_digest,
    )


@dataclass(frozen=True)
class PhysicalWorkerRegistryRecord:
    """Target-verified durable state for one exact physical worker identity."""

    state: Literal["ACTIVE", "TERMINAL"]
    armed_zero: PhysicalWorkerArmedZero
    updated_at_epoch_s: float
    zero_refresh_count: int
    last_zero_at_epoch_s: float
    terminal_reason: str | None
    registry_auth_tag: str


@dataclass(frozen=True, init=False)
class LanderPiRotateProcessWorker:
    """Spawn-safe, two-stage worker bound to one exact physical v3 CALL."""

    provider_id: ClassVar[str] = _PROVIDER_ID
    provider_operation: ClassVar[str] = _PROVIDER_OPERATION
    mode: ClassVar[str] = _MODE
    physical_capable: ClassVar[bool] = True
    requires_armed_zero: ClassVar[bool] = True
    sealed_profile: ClassVar[str] = "landerpi-bounded-rotate-v1"

    angle_degrees: float
    max_speed_rad_s: float
    duration_s: float
    container: str
    container_user: str
    timeout_s: float
    max_output_bytes: int
    request_digest: str
    target_id: str
    call_id: str
    session_id: str
    execution_subject_digest: str
    expected_call_key_digest: str
    request_deadline: datetime
    bundle_digest: str
    runtime_sha256: str

    def __init__(
        self,
        request: ExecutionRequestLike,
        manifest: ExecutionBundleManifest,
        *,
        container: str = "MentorPi",
        container_user: str = "ubuntu",
        timeout_s: float = _MAX_WALL_TIMEOUT_S,
    ) -> None:
        request, manifest = validate_landerpi_rotate_process_call(request, manifest)
        if container != "MentorPi" or container_user != "ubuntu":
            raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_CONTAINER_IDENTITY_INVALID")
        angle, speed, duration = _rotation_values(request.arguments)
        timeout = _finite_number(timeout_s, "PHYSICAL_WORKER_TIMEOUT_INVALID")
        if not 1.0 <= timeout <= _MAX_WALL_TIMEOUT_S:
            raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_TIMEOUT_INVALID")
        if duration > 60.0 or timeout < duration + 1.0:
            raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_DEADLINE_TOO_SHORT")
        try:
            RosContainerProvider(
                container,
                container_user=container_user,
                timeout_s=timeout,
                autonomous_source_confirmed=False,
            )
        except (TypeError, ValueError) as exc:
            raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_CONTAINER_IDENTITY_INVALID") from exc

        raw_output_limit = manifest.limits.get("max_output_bytes", _MAX_STDOUT_BYTES)
        if (
            isinstance(raw_output_limit, bool)
            or not isinstance(raw_output_limit, (int, float))
            or not math.isfinite(float(raw_output_limit))
            or int(raw_output_limit) != float(raw_output_limit)
            or not 1 <= int(raw_output_limit) <= _MAX_STDOUT_BYTES
        ):
            raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_OUTPUT_LIMIT_INVALID")
        manifest_duration = manifest.limits.get("max_duration_s")
        if manifest_duration is not None:
            limit = _finite_number(manifest_duration, "PHYSICAL_WORKER_DURATION_LIMIT_INVALID")
            if limit <= 0 or duration > limit:
                raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_DURATION_LIMIT_INVALID")

        runtime_source = _read_bounded_twist_source()
        actual_runtime_sha256 = hashlib.sha256(runtime_source.encode("utf-8")).hexdigest()
        if manifest.observation_contract.get("provider_runtime_sha256") != actual_runtime_sha256:
            raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_RUNTIME_DIGEST_MISMATCH")
        values: dict[str, object] = {
            "angle_degrees": angle,
            "max_speed_rad_s": speed,
            "duration_s": duration,
            "container": container,
            "container_user": container_user,
            "timeout_s": timeout,
            "max_output_bytes": int(raw_output_limit),
            "request_digest": request.request_digest(),
            "target_id": request.target_id,
            "call_id": request.idempotency_key,
            "session_id": request.session_id,
            "execution_subject_digest": request.execution_subject_digest,
            "expected_call_key_digest": WorkerCallKey.from_request(request).digest(),
            "request_deadline": request.deadline,
            "bundle_digest": manifest.bundle_digest,
            "runtime_sha256": actual_runtime_sha256,
        }
        for name, value in values.items():
            object.__setattr__(self, name, value)

    def __call__(self, _control: ProcessWorkerControl) -> LeasedProviderOutcome:
        """Prevent generic one-stage runtimes from bypassing ARMED_ZERO."""

        raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_TWO_PHASE_RUNTIME_REQUIRED")

    def prepare(self, control: ProcessWorkerControl) -> PreparedLanderPiRotation:
        """Create the ROS endpoint at zero and wait for authenticated ARM ack."""

        lease = self._validate_control(control)
        try:
            if control.aborted() or control.interrupt_intent() is not None:
                raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_PREPARE_NOT_LIVE")
        except PhysicalWorkerConfigurationError:
            raise
        except Exception as exc:
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_CONTROL_UNAVAILABLE") from exc

        remaining_s = self._remaining_seconds(lease)
        if remaining_s <= _ARM_TIMEOUT_S:
            raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_PREPARE_DEADLINE_TOO_SHORT")
        runtime_source = _read_bounded_twist_source()
        if hashlib.sha256(runtime_source.encode("utf-8")).hexdigest() != self.runtime_sha256:
            raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_RUNTIME_CHANGED")
        control_key = secrets.token_hex(32)
        program = self._instrumented_program(runtime_source)
        if len(program.encode("utf-8")) > _MAX_PROGRAM_ARG_BYTES:
            raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_RUNTIME_TOO_LARGE")
        wall_timeout_s = min(self.timeout_s, remaining_s)
        argv = self.container_command(max(0.1, wall_timeout_s - 0.25), program)
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
        except OSError as exc:
            raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_PROCESS_START_FAILED") from exc

        transport = _ProviderTransport(
            process,
            stdout_limit=self.max_output_bytes,
            stderr_limit=_MAX_STDERR_BYTES,
        )
        bootstrap = {
            "schema_version": _CONTROL_SCHEMA,
            "kind": "BOOTSTRAP",
            "sequence": 0,
            "call_key_digest": self.expected_call_key_digest,
            "target_id": self.target_id,
            "call_id": self.call_id,
            "session_id": self.session_id,
            "request_digest": self.request_digest,
            "execution_subject_digest": self.execution_subject_digest,
            "runtime_sha256": self.runtime_sha256,
            "request_deadline_epoch_s": self.request_deadline.timestamp(),
            "control_key": control_key,
        }
        try:
            transport.send(bootstrap)
            envelope = transport.receive(timeout_s=min(_ARM_TIMEOUT_S, max(0.1, remaining_s - 0.25)))
            self._raise_prepare_error(envelope, control_key)
            armed = self._parse_armed_zero(envelope, control_key)
        except Exception as exc:
            transport.close_stdin()
            _recover_inner_or_outer(
                self,
                transport,
                identity=_recoverable_prepare_identity(
                    self,
                    locals().get("envelope"),
                    control_key,
                ),
            )
            if isinstance(exc, (PhysicalWorkerAmbiguity, PhysicalWorkerConfigurationError)):
                raise
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_ARM_AMBIGUOUS") from exc
        prepared = PreparedLanderPiRotation(
            worker=self,
            control_key=control_key,
            transport=transport,
            armed_zero=armed,
            execute_deadline_monotonic=time.monotonic() + wall_timeout_s,
        )
        try:
            self._validate_control(control)
            if control.aborted():
                raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_CONTROL_ABORTED")
        except Exception as exc:
            prepared._recover()
            if isinstance(exc, PhysicalWorkerAmbiguity):
                raise
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_POST_ARM_CONTROL_AMBIGUOUS") from exc
        return prepared

    def _raise_prepare_error(self, envelope: dict[str, Any], control_key: str) -> None:
        if envelope.get("kind") != "PREPARE_ERROR":
            return
        _verify_authenticated_envelope(
            envelope,
            control_key,
            schema=_PREPARE_ERROR_SCHEMA,
            kind="PREPARE_ERROR",
        )
        code = envelope.get("error")
        if (
            set(envelope)
            != {
                "schema_version",
                "kind",
                "call_key_digest",
                "target_id",
                "call_id",
                "session_id",
                "request_digest",
                "error",
                "auth_tag",
            }
            or envelope.get("call_key_digest") != self.expected_call_key_digest
            or envelope.get("target_id") != self.target_id
            or envelope.get("call_id") != self.call_id
            or envelope.get("session_id") != self.session_id
            or envelope.get("request_digest") != self.request_digest
            or not isinstance(code, str)
            or _PREPARE_ERROR_CODE.fullmatch(code) is None
        ):
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_PREPARE_ERROR_INVALID")
        raise PhysicalWorkerConfigurationError(code)

    def container_command(self, reaper_timeout_s: float, program: str) -> list[str]:
        """Return fixed docker argv; caller values never enter shell source."""

        timeout = _finite_number(reaper_timeout_s, "PHYSICAL_WORKER_REAPER_TIMEOUT_INVALID")
        if not 0.1 <= timeout <= _MAX_WALL_TIMEOUT_S:
            raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_REAPER_TIMEOUT_INVALID")
        if not isinstance(program, str) or not program:
            raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_RUNTIME_INVALID")
        return [
            "docker",
            "exec",
            "-i",
            "-u",
            self.container_user,
            self.container,
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            _CONTAINER_BOOTSTRAP,
            "rolo-physical-worker",
            f"{timeout:.3f}s",
            program,
        ]

    def _validate_control(self, control: ProcessWorkerControl) -> object:
        try:
            if control.call_key.digest() != self.expected_call_key_digest:
                raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_CALL_IDENTITY_MISMATCH")
            lease = control.heartbeat()
        except PhysicalWorkerConfigurationError:
            raise
        except Exception as exc:
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_CONTROL_UNAVAILABLE") from exc
        if getattr(lease, "call_key_digest", None) != self.expected_call_key_digest or getattr(lease, "deadline_at", None) != self.request_deadline:
            raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_LEASE_IDENTITY_MISMATCH")
        return lease

    def _remaining_seconds(self, lease: object) -> float:
        deadline = getattr(lease, "deadline_at", None)
        if not isinstance(deadline, datetime) or deadline.tzinfo is None:
            raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_LEASE_DEADLINE_INVALID")
        return (deadline.astimezone(timezone.utc) - datetime.now(timezone.utc)).total_seconds()

    def _instrumented_program(self, runtime_source: str) -> str:
        # Compile the reviewed source byte-for-byte and call its public
        # ``run_ros_entrypoint(..., start_gate=...)`` seam.  The wrapper uses
        # a bounded sink for the legacy result print, then emits the returned
        # object in one authenticated envelope.  Motion code is never
        # rewritten or monkey-patched.
        request = {
            "command_endpoint": LANDERPI_CONTROLLED_COMMAND_ENDPOINT,
            "feedback_endpoints": list(_FEEDBACK_ENDPOINTS),
            "independent_feedback_endpoints": list(_INDEPENDENT_ENDPOINTS),
            "autonomous_source_confirmed": False,
            "angular_speed_rad_s": math.copysign(self.max_speed_rad_s, self.angle_degrees),
            "duration_s": self.duration_s,
            "goal_yaw_rad": math.radians(self.angle_degrees),
            "runtime_sha256": self.runtime_sha256,
        }
        return _inner_program(
            runtime_source=runtime_source,
            request_json=json.dumps(
                request,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            ),
        )

    def _parse_armed_zero(self, envelope: dict[str, Any], control_key: str) -> PhysicalWorkerArmedZero:
        _verify_authenticated_envelope(
            envelope,
            control_key,
            schema=_ARM_SCHEMA,
            kind="ARMED_ZERO",
        )
        expected_keys = {
            "schema_version",
            "kind",
            "call_key_digest",
            "target_id",
            "call_id",
            "session_id",
            "request_digest",
            "execution_subject_digest",
            "runtime_sha256",
            "command_endpoint",
            "publisher_identity",
            "publisher_endpoint_gids",
            "competing_publisher_count",
            "direct_motor_publisher_identities",
            "zeros_published",
            "independent_stationary_sources",
            "independent_stationary_sample_counts",
            "independent_stationary_last_sample_age_s",
            "independent_stationary_max_abs_rad_s",
            "independent_stationary_window_s",
            "motion_command_emitted",
            "motion_enabled",
            "inner_process_identity",
            "target_monotonic_s",
            "provider_runtime_sha256",
            "provider_cmdline_sha256",
            "provider_runtime_identity_digest",
            "registry_issued_at_epoch_s",
            "registry_expires_at_epoch_s",
            "registry_binding_digest",
            "arm_receipt_digest",
            "auth_tag",
        }
        gids = envelope.get("publisher_endpoint_gids")
        direct = envelope.get("direct_motor_publisher_identities")
        target_time = _optional_finite_number(envelope.get("target_monotonic_s"))
        registry_issued_at = _optional_finite_number(envelope.get("registry_issued_at_epoch_s"))
        registry_expires_at = _optional_finite_number(envelope.get("registry_expires_at_epoch_s"))
        if (
            set(envelope) != expected_keys
            or envelope.get("call_key_digest") != self.expected_call_key_digest
            or envelope.get("target_id") != self.target_id
            or envelope.get("call_id") != self.call_id
            or envelope.get("session_id") != self.session_id
            or envelope.get("request_digest") != self.request_digest
            or envelope.get("execution_subject_digest") != self.execution_subject_digest
            or envelope.get("runtime_sha256") != self.runtime_sha256
            or envelope.get("command_endpoint") != LANDERPI_CONTROLLED_COMMAND_ENDPOINT
            or envelope.get("publisher_identity") != "/rolo_bounded_twist"
            or not isinstance(gids, list)
            or len(gids) != 1
            or not isinstance(gids[0], str)
            or _GID.fullmatch(gids[0]) is None
            or envelope.get("competing_publisher_count") != 0
            or direct != ["/odom_publisher"]
            or isinstance(envelope.get("zeros_published"), bool)
            or not isinstance(envelope.get("zeros_published"), int)
            or envelope.get("zeros_published", 0) < 5
            or envelope.get("motion_command_emitted") is not False
            or envelope.get("motion_enabled") is not False
            or target_time is None
            or target_time <= 0
            or registry_issued_at is None
            or registry_issued_at <= 0
            or registry_expires_at is None
            or registry_expires_at <= registry_issued_at
            or registry_expires_at - registry_issued_at > _MAX_ARMED_ZERO_GATE_S
            or registry_expires_at > self.request_deadline.timestamp()
        ):
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_ARM_PROOF_INVALID")
        identity = InnerProcessIdentity.parse(envelope.get("inner_process_identity"))
        provider_runtime_sha256 = f"sha256:{self.runtime_sha256}"
        provider_cmdline_sha256 = f"sha256:{identity.cmdline_sha256}"
        provider_runtime_identity_digest = compute_armed_zero_provider_identity_digest(
            call_id=self.call_id,
            session_id=self.session_id,
            execution_subject_digest=self.execution_subject_digest,
            publisher_identity="/rolo_bounded_twist",
            publisher_gid=gids[0],
            provider_pid=identity.pid,
            provider_start_time_ticks=identity.start_ticks,
            provider_runtime_sha256=provider_runtime_sha256,
            provider_cmdline_sha256=provider_cmdline_sha256,
        )
        registry_binding_digest = _registry_binding_digest(
            target_id=self.target_id,
            call_key_digest=self.expected_call_key_digest,
            call_id=self.call_id,
            session_id=self.session_id,
            execution_subject_digest=self.execution_subject_digest,
            publisher_identity="/rolo_bounded_twist",
            publisher_gid=gids[0],
            provider_pid=identity.pid,
            provider_start_time_ticks=identity.start_ticks,
            provider_runtime_sha256=provider_runtime_sha256,
            provider_cmdline_sha256=provider_cmdline_sha256,
            issued_at_epoch_s=registry_issued_at,
            expires_at_epoch_s=registry_expires_at,
        )
        if (
            envelope.get("provider_runtime_sha256") != provider_runtime_sha256
            or envelope.get("provider_cmdline_sha256") != provider_cmdline_sha256
            or envelope.get("provider_runtime_identity_digest") != provider_runtime_identity_digest
            or envelope.get("registry_binding_digest") != registry_binding_digest
        ):
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_ARM_PROOF_INVALID")
        receipt_payload: dict[str, object] = {
            "schema_version": _ARM_RECEIPT_SCHEMA,
            "call_key_digest": self.expected_call_key_digest,
            "target_id": self.target_id,
            "call_id": self.call_id,
            "session_id": self.session_id,
            "request_digest": self.request_digest,
            "execution_subject_digest": self.execution_subject_digest,
            "runtime_sha256": self.runtime_sha256,
            "command_endpoint": LANDERPI_CONTROLLED_COMMAND_ENDPOINT,
            "publisher_identity": "/rolo_bounded_twist",
            "publisher_endpoint_gids": [gids[0]],
            "publisher_endpoint_count": 1,
            "competing_publisher_count": 0,
            "direct_motor_publisher_identities": ["/odom_publisher"],
            "zeros_published": int(envelope["zeros_published"]),
            "independent_stationary_sources": envelope.get("independent_stationary_sources"),
            "independent_stationary_sample_counts": envelope.get("independent_stationary_sample_counts"),
            "independent_stationary_last_sample_age_s": envelope.get("independent_stationary_last_sample_age_s"),
            "independent_stationary_max_abs_rad_s": envelope.get("independent_stationary_max_abs_rad_s"),
            "independent_stationary_window_s": envelope.get("independent_stationary_window_s"),
            "motion_command_emitted": False,
            "motion_enabled": False,
            "inner_process_identity": identity.as_dict(),
            "target_monotonic_s": target_time,
            "provider_runtime_sha256": provider_runtime_sha256,
            "provider_cmdline_sha256": provider_cmdline_sha256,
            "provider_runtime_identity_digest": provider_runtime_identity_digest,
            "registry_issued_at_epoch_s": registry_issued_at,
            "registry_expires_at_epoch_s": registry_expires_at,
            "registry_binding_digest": registry_binding_digest,
        }
        arm_receipt_digest = hashlib.sha256(_canonical_bytes(receipt_payload)).hexdigest()
        if envelope.get("arm_receipt_digest") != arm_receipt_digest:
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_ARM_PROOF_INVALID")
        receipt_payload["arm_receipt_digest"] = arm_receipt_digest
        return parse_physical_worker_armed_zero(
            receipt_payload,
            expected_call_key_digest=self.expected_call_key_digest,
            expected_request_digest=self.request_digest,
            expected_execution_subject_digest=self.execution_subject_digest,
            expected_runtime_sha256=self.runtime_sha256,
            expected_target_id=self.target_id,
            expected_call_id=self.call_id,
            expected_session_id=self.session_id,
        )


class PreparedLanderPiRotation:
    """Live ARMED_ZERO process; only a two-phase runtime may START it."""

    def __init__(
        self,
        *,
        worker: LanderPiRotateProcessWorker,
        control_key: str,
        transport: _ProviderTransport,
        armed_zero: PhysicalWorkerArmedZero,
        execute_deadline_monotonic: float,
    ) -> None:
        self.worker = worker
        self.control_key = control_key
        self.transport = transport
        self.armed_zero = armed_zero
        self.execute_deadline_monotonic = execute_deadline_monotonic
        self._sequence = 1
        self._terminal = False
        self._lock = threading.RLock()

    def arm_receipt(self) -> dict[str, object]:
        return self.armed_zero.as_dict()

    def __call__(self, control: ProcessWorkerControl) -> LeasedProviderOutcome:
        return self.execute(control)

    def execute(self, control: ProcessWorkerControl) -> LeasedProviderOutcome:
        """Send authenticated START, monitor interrupt, then prove inner exit."""

        with self._lock:
            if self._terminal or self._sequence != 1:
                raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_REPLAY_FORBIDDEN")
        try:
            self.worker._validate_control(control)
            if control.aborted():
                self._recover()
                raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_CONTROL_ABORTED")
            pending_intent = control.interrupt_intent()
            if pending_intent is not None:
                return self.stop(control, intent=pending_intent)
        except Exception as exc:
            self._recover()
            if isinstance(exc, PhysicalWorkerAmbiguity):
                raise
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_POST_ARM_CONTROL_AMBIGUOUS") from exc
        with self._lock:
            if self._terminal or self._sequence != 1:
                self._recover()
                raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_REPLAY_FORBIDDEN")
            self._sequence = 2
        try:
            self.transport.send(
                _control_message(
                    control_key=self.control_key,
                    call_key_digest=self.worker.expected_call_key_digest,
                    sequence=1,
                    intent="START",
                )
            )
            return self._wait_terminal(control)
        except Exception as exc:
            self._recover()
            if isinstance(exc, PhysicalWorkerAmbiguity):
                raise
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_START_AMBIGUOUS") from exc

    def stop(
        self,
        control: ProcessWorkerControl,
        *,
        intent: Literal["STOP", "CANCEL"] = "STOP",
    ) -> LeasedProviderOutcome:
        """Stop an armed/running process; acknowledgement requires final zero."""

        if intent not in {"STOP", "CANCEL"}:
            raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_INTERRUPT_INVALID")
        with self._lock:
            if self._terminal:
                raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_REPLAY_FORBIDDEN")
            sequence = self._sequence
            self._sequence += 1
        try:
            self.worker._validate_control(control)
            self.transport.send(
                _control_message(
                    control_key=self.control_key,
                    call_key_digest=self.worker.expected_call_key_digest,
                    sequence=sequence,
                    intent=intent,
                )
            )
            envelope = self.transport.receive(
                timeout_s=min(
                    _INTERRUPT_GRACE_S,
                    max(0.1, self.execute_deadline_monotonic - time.monotonic()),
                )
            )
            result = self._finish_envelope(
                envelope,
                provider_invocation_count=0 if sequence == 1 else 1,
            )
        except Exception as exc:
            self._recover()
            if isinstance(exc, PhysicalWorkerAmbiguity):
                raise
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_INTERRUPT_AMBIGUOUS") from exc
        return self._interrupt_outcome(intent, result)

    def _wait_terminal(self, control: ProcessWorkerControl) -> LeasedProviderOutcome:
        interrupt: Literal["STOP", "CANCEL"] | None = None
        while True:
            if self.transport.overflowed_or_failed():
                self._recover()
                raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_OUTPUT_AMBIGUOUS")
            try:
                if control.aborted():
                    self._recover()
                    raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_CONTROL_ABORTED")
                observed = control.interrupt_intent()
            except PhysicalWorkerAmbiguity:
                raise
            except Exception as exc:
                self._recover()
                raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_CONTROL_UNAVAILABLE") from exc
            if observed is not None:
                interrupt = observed
                return self.stop(control, intent=observed)
            remaining = self.execute_deadline_monotonic - time.monotonic()
            if remaining <= 0:
                self._recover()
                raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_DEADLINE_AMBIGUOUS")
            try:
                envelope = self.transport.receive(timeout_s=min(0.05, remaining))
            except TimeoutError:
                if self.transport.process.poll() is None:
                    continue
                self._recover()
                raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_RESPONSE_LOST") from None
            except PhysicalWorkerAmbiguity:
                self._recover()
                raise
            result = self._finish_envelope(envelope, provider_invocation_count=1)
            if interrupt is not None:
                return self._interrupt_outcome(interrupt, result)
            return self._ordinary_outcome(result)

    def _finish_envelope(
        self,
        envelope: dict[str, Any],
        *,
        provider_invocation_count: Literal[0, 1],
    ) -> dict[str, Any]:
        try:
            _verify_authenticated_envelope(
                envelope,
                self.control_key,
                schema=_RESULT_SCHEMA,
                kind="RESULT",
            )
        except PhysicalWorkerAmbiguity:
            self._recover()
            raise
        if set(envelope) != {
            "schema_version",
            "kind",
            "call_key_digest",
            "inner_process_identity",
            "result",
            "auth_tag",
        }:
            self._recover()
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_RESULT_AMBIGUOUS")
        if envelope.get("call_key_digest") != self.worker.expected_call_key_digest:
            self._recover()
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_RESULT_IDENTITY_MISMATCH")
        try:
            identity = InnerProcessIdentity.parse(envelope.get("inner_process_identity"))
        except PhysicalWorkerAmbiguity:
            self._recover()
            raise
        if identity != self.armed_zero.inner_process_identity:
            self._recover()
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_RESULT_IDENTITY_MISMATCH")
        raw_result = envelope.get("result")
        if not isinstance(raw_result, dict):
            self._recover()
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_RESULT_AMBIGUOUS")
        self.transport.close_stdin()
        if not self.transport.wait_outer(timeout_s=1.0):
            self._recover()
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_OUTER_EXIT_AMBIGUOUS")
        if self.transport.process.returncode != 0:
            self._recover()
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_EXIT_AMBIGUOUS")
        if not _prove_inner_gone(self.worker, identity):
            self._recover()
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_INNER_EXIT_AMBIGUOUS")
        with self._lock:
            self._terminal = True
        return self._bind_result(
            raw_result,
            identity,
            provider_invocation_count=provider_invocation_count,
        )

    def _bind_result(
        self,
        raw: dict[str, Any],
        identity: InnerProcessIdentity,
        *,
        provider_invocation_count: Literal[0, 1],
    ) -> dict[str, Any]:
        status = raw.get("status")
        if not isinstance(status, str) or status.upper() not in _TARGET_STATUSES:
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_RESULT_AMBIGUOUS")
        if provider_invocation_count == 0 and (raw.get("motion_started") is not False or raw.get("motion_command_emitted") is not False):
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_PRESTART_RESULT_CONTRADICTORY")
        result = dict(raw)
        result.update(
            target_status=status.upper(),
            status=status.upper(),
            call_id=self.worker.call_id,
            session_id=self.worker.session_id,
            runtime_sha256=self.worker.runtime_sha256,
            provider_runtime_sha256=self.armed_zero.provider_runtime_sha256,
            provider_cmdline_sha256=self.armed_zero.provider_cmdline_sha256,
            provider_runtime_identity_digest=(self.armed_zero.provider_runtime_identity_digest),
            registry_binding_digest=self.armed_zero.registry_binding_digest,
            registry_issued_at_epoch_s=self.armed_zero.registry_issued_at_epoch_s,
            registry_expires_at_epoch_s=self.armed_zero.registry_expires_at_epoch_s,
            target_registry_terminalized=True,
            request_digest=self.worker.request_digest,
            execution_subject_digest=self.worker.execution_subject_digest,
            worker_call_key_digest=self.worker.expected_call_key_digest,
            provider_invocation_count=provider_invocation_count,
            provider_process_identity=identity.as_dict(),
            armed_zero_receipt_digest=self.armed_zero.arm_receipt_digest,
        )
        return result

    def _ordinary_outcome(self, result: dict[str, Any]) -> LeasedProviderOutcome:
        target_status = result["target_status"]
        if target_status == "SUCCEEDED":
            if not self._verified_success(result):
                raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_ROTATION_PROOF_AMBIGUOUS")
            result.update(
                status="SUCCEEDED",
                final_zero_verified=True,
                stop_acknowledged=True,
                stop_acknowledgement={
                    "kind": "TARGET_FINAL_ZERO",
                    "call_key_digest": self.worker.expected_call_key_digest,
                    "inner_process_gone": True,
                    "verified": True,
                },
            )
            return LeasedProviderOutcome(WorkerCompletion("SUCCEEDED", "ROTATE_SUCCEEDED"), result)
        if target_status in {"BLOCKED", "FAILED", "NOT_ACCEPTED"} and result.get("motion_started") is False:
            if result.get("motion_command_emitted") is not False or not self._verified_safe_stop(result):
                raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_PREMOTION_STOP_UNPROVED")
            result.update(
                status="FAILED",
                final_zero_verified=True,
                stop_acknowledged=True,
                provider_motion_started=False,
                stop_acknowledgement={
                    "kind": "PREMOTION_BLOCK_FINAL_ZERO",
                    "call_key_digest": self.worker.expected_call_key_digest,
                    "inner_process_gone": True,
                    "verified": True,
                },
            )
            return LeasedProviderOutcome(WorkerCompletion("FAILED", "ROTATE_BLOCKED_BEFORE_MOTION"), result)
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_RESULT_AMBIGUOUS")

    def _interrupt_outcome(
        self,
        intent: Literal["STOP", "CANCEL"],
        result: dict[str, Any],
    ) -> LeasedProviderOutcome:
        if not self._verified_safe_stop(result):
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_INTERRUPT_STOP_UNPROVED")
        status: Literal["STOPPED", "CANCELLED"] = "STOPPED" if intent == "STOP" else "CANCELLED"
        code = "ROTATE_STOP_CONFIRMED" if intent == "STOP" else "ROTATE_CANCEL_CONFIRMED"
        result.update(
            status=status,
            interrupt_intent=intent,
            final_zero_verified=True,
            stop_acknowledged=True,
            stop_acknowledgement={
                "kind": "AUTHENTICATED_INTERRUPT_FINAL_ZERO",
                "intent": intent,
                "call_key_digest": self.worker.expected_call_key_digest,
                "inner_process_gone": True,
                "verified": True,
            },
        )
        return LeasedProviderOutcome(WorkerCompletion(status, code), result)

    @staticmethod
    def _verified_safe_stop(result: Mapping[str, Any]) -> bool:
        evidence = result.get("independent_motion_evidence")
        return (
            result.get("stop_published") is True
            and result.get("physical_stop_verified") is True
            and result.get("stopped_observed") is True
            and result.get("control_graph_isolated") is True
            and isinstance(evidence, Mapping)
            and evidence.get("independent_of_odom") is True
            and evidence.get("settled") is True
        )

    def _verified_success(self, result: Mapping[str, Any]) -> bool:
        if result.get("motion_started") is not True or not self._verified_safe_stop(result) or not has_verified_rotation_evidence(result):
            return False
        evidence = result.get("independent_motion_evidence")
        assert isinstance(evidence, Mapping)
        gyro = _optional_finite_number(evidence.get("gyro_delta_rad"))
        error = _optional_finite_number(evidence.get("target_angle_error_rad"))
        tolerance = _optional_finite_number(evidence.get("target_angle_tolerance_rad"))
        if gyro is None or error is None or tolerance is None or math.copysign(1.0, gyro) != math.copysign(1.0, self.worker.angle_degrees):
            return False
        goal = abs(math.radians(self.worker.angle_degrees))
        expected_error = abs(abs(gyro) - goal)
        expected_tolerance = max(goal * 0.25, MIN_INDEPENDENT_ROTATION_RAD)
        return math.isclose(error, expected_error, abs_tol=1e-9) and math.isclose(tolerance, expected_tolerance, abs_tol=1e-9) and error <= expected_tolerance

    def _recover(self) -> None:
        with self._lock:
            self._terminal = True
        self.transport.close_stdin()
        _recover_inner_or_outer(
            self.worker,
            self.transport,
            identity=self.armed_zero.inner_process_identity,
        )


class _ProviderTransport:
    """Bounded line transport for the exact retained docker-exec handle."""

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        *,
        stdout_limit: int,
        stderr_limit: int,
    ) -> None:
        self.process = process
        self.stdout_limit = stdout_limit
        self.stderr_limit = stderr_limit
        self.lines: queue.Queue[bytes | None] = queue.Queue(maxsize=64)
        self.overflow = threading.Event()
        self.failed = threading.Event()
        self._stdin_lock = threading.Lock()
        self._stdin_closed = False
        self._stdout = bytearray()
        self._stderr = bytearray()
        self._readers = (
            threading.Thread(
                target=self._pump_stdout,
                name="rolo-physical-worker-stdout",
                daemon=True,
            ),
            threading.Thread(
                target=self._pump_stderr,
                name="rolo-physical-worker-stderr",
                daemon=True,
            ),
        )
        for reader in self._readers:
            reader.start()

    def _pump_stdout(self) -> None:
        stream = self.process.stdout
        if stream is None:
            self.failed.set()
            self._put_eof()
            return
        try:
            while True:
                line = stream.readline(_MAX_LINE_BYTES + 1)
                if not line:
                    break
                if isinstance(line, str):
                    line = line.encode("utf-8")
                if len(line) > _MAX_LINE_BYTES:
                    self.overflow.set()
                remaining = max(0, self.stdout_limit - len(self._stdout))
                self._stdout.extend(line[:remaining])
                if len(line) > remaining:
                    self.overflow.set()
                try:
                    self.lines.put(line[:_MAX_LINE_BYTES], timeout=0.1)
                except queue.Full:
                    self.overflow.set()
        except (OSError, TypeError, ValueError):
            self.failed.set()
        finally:
            self._put_eof()

    def _pump_stderr(self) -> None:
        stream = self.process.stderr
        if stream is None:
            self.failed.set()
            return
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    return
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8")
                remaining = max(0, self.stderr_limit - len(self._stderr))
                self._stderr.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self.overflow.set()
        except (OSError, TypeError, ValueError):
            self.failed.set()

    def _put_eof(self) -> None:
        try:
            self.lines.put_nowait(None)
        except queue.Full:
            self.overflow.set()

    def send(self, value: Mapping[str, Any]) -> None:
        encoded = _canonical_bytes(dict(value)) + b"\n"
        if len(encoded) > _MAX_LINE_BYTES:
            raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_CONTROL_MESSAGE_TOO_LARGE")
        with self._stdin_lock:
            if self._stdin_closed or self.process.stdin is None:
                raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_CONTROL_CHANNEL_CLOSED")
            view = memoryview(encoded)
            try:
                while view:
                    written = self.process.stdin.write(view)
                    if written is None or written <= 0:
                        raise OSError("short write")
                    view = view[written:]
                self.process.stdin.flush()
            except (OSError, TypeError, ValueError) as exc:
                raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_CONTROL_CHANNEL_FAILED") from exc

    def receive(self, *, timeout_s: float) -> dict[str, Any]:
        timeout = _finite_number(timeout_s, "PHYSICAL_WORKER_RECEIVE_TIMEOUT_INVALID")
        if timeout <= 0:
            raise TimeoutError
        try:
            line = self.lines.get(timeout=timeout)
        except queue.Empty as exc:
            raise TimeoutError from exc
        if line is None:
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_RESPONSE_LOST")
        try:
            value = loads_unique_json(line.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_RESPONSE_INVALID") from exc
        if not isinstance(value, dict):
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_RESPONSE_INVALID")
        return value

    def close_stdin(self) -> None:
        with self._stdin_lock:
            if self._stdin_closed:
                return
            self._stdin_closed = True
            try:
                if self.process.stdin is not None:
                    self.process.stdin.close()
            except (OSError, ValueError):
                pass

    def overflowed_or_failed(self) -> bool:
        return self.overflow.is_set() or self.failed.is_set()

    def wait_outer(self, *, timeout_s: float) -> bool:
        try:
            self.process.wait(timeout=timeout_s)
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return False
        for reader in self._readers:
            reader.join(0.5)
        return not any(reader.is_alive() for reader in self._readers)


def validate_landerpi_rotate_process_call(
    request: ExecutionRequestLike,
    manifest: ExecutionBundleManifest,
) -> tuple[ExecutionRequestV3, ExecutionBundleManifest]:
    """Validate the sole request shape admitted by the physical profile."""

    raw_version = getattr(request, "schema_version", None)
    if raw_version != "rolo-execution-request/v3":
        raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_REQUEST_V3_REQUIRED")
    try:
        parsed = validate_execution_request(request)
        checked_manifest = ExecutionBundleManifest.model_validate(manifest.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_CALL_INVALID") from exc
    if not isinstance(parsed, ExecutionRequestV3):
        raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_REQUEST_V3_REQUIRED")
    if parsed.authority.tool_id != _TOOL_ID or checked_manifest.tool_id != _TOOL_ID or parsed.provider_id != _PROVIDER_ID or parsed.provider_operation != _PROVIDER_OPERATION or parsed.mode != _MODE:
        raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_ROUTE_NOT_SEALED")
    if parsed.bundle_digest != checked_manifest.bundle_digest or parsed.binding_digest != checked_manifest.binding_digest:
        raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_BUNDLE_IDENTITY_MISMATCH")
    contract = checked_manifest.observation_contract
    if set(contract) != _CONTRACT_KEYS or (
        contract.get("provider") != _PROVIDER_ID
        or contract.get("operation") != _PROVIDER_OPERATION
        or contract.get("command_endpoint") != LANDERPI_CONTROLLED_COMMAND_ENDPOINT
        or tuple(contract.get("feedback_endpoints", ())) != _FEEDBACK_ENDPOINTS
        or tuple(contract.get("independent_feedback_endpoints", ())) != _INDEPENDENT_ENDPOINTS
        or contract.get("interface_type") != _COMMAND_INTERFACE
        or contract.get("stop_strategy") != _STOP_STRATEGY
        or not isinstance(contract.get("provider_runtime_sha256"), str)
        or _HEX_SHA256.fullmatch(contract["provider_runtime_sha256"]) is None
    ):
        raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_OBSERVATION_CONTRACT_NOT_SEALED")
    return parsed, checked_manifest


def _rotation_values(arguments: Mapping[str, Any]) -> tuple[float, float, float]:
    if not isinstance(arguments, Mapping) or set(arguments) != _ARGUMENT_KEYS:
        raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_ARGUMENTS_NOT_SEALED")
    angle = _finite_number(arguments.get("angle_degrees"), "PHYSICAL_WORKER_ANGLE_INVALID")
    speed = _finite_number(arguments.get("max_speed_rad_s"), "PHYSICAL_WORKER_SPEED_INVALID")
    if not 0 < abs(math.radians(angle)) <= MAX_ROTATION_ANGLE_RAD:
        raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_ANGLE_INVALID")
    if not 0 < speed <= MAX_ROTATION_SPEED_RAD_S:
        raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_SPEED_INVALID")
    goal = math.radians(angle)
    duration = max(
        abs(goal) / speed * 3.0,
        0.4,
        motion_observation_duration_s(goal, speed),
    )
    return angle, speed, duration


def _finite_number(value: object, code: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PhysicalWorkerConfigurationError(code)
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise PhysicalWorkerConfigurationError(code) from exc
    if not math.isfinite(result):
        raise PhysicalWorkerConfigurationError(code)
    return result


def _optional_finite_number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return result if math.isfinite(result) else None


def _runtime_path() -> Path:
    return Path(__file__).resolve().parents[1] / "mvp" / "bounded_twist.py"


def _read_bounded_twist_source() -> str:
    try:
        source = _runtime_path().read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_RUNTIME_UNAVAILABLE") from exc
    if not source or len(source.encode("utf-8")) > _MAX_RUNTIME_SOURCE_BYTES:
        raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_RUNTIME_UNAVAILABLE")
    return source


def landerpi_bounded_twist_runtime_sha256() -> str:
    """Digest the exact reviewed runtime required by the signed manifest."""

    return hashlib.sha256(_read_bounded_twist_source().encode("utf-8")).hexdigest()


def landerpi_physical_registry_reader_program() -> str:
    """Return the fixed target-side HMAC verifier used by read-only RPCs."""

    return _REGISTRY_READER


def recover_persisted_armed_zero(
    value: object,
    *,
    expected_call_key_digest: str,
    expected_target_id: str,
    expected_call_id: str,
    expected_session_id: str,
    expected_request_digest: str,
    expected_execution_subject_digest: str,
    expected_runtime_sha256: str,
    container: str = "MentorPi",
    container_user: str = "ubuntu",
) -> bool:
    """Reap one exact persisted inner identity after supervisor restart.

    The caller must load ``value`` from its trusted durable lease store. A
    malformed or digest-inconsistent receipt never reaches Docker and returns
    ``False``. ``True`` means the exact PID/starttime/cmdline identity was
    already gone or was reaped; it does not turn an interrupted CALL into a
    retryable outcome.
    """

    if not isinstance(value, Mapping):
        return False
    try:
        parsed = parse_physical_worker_armed_zero(
            value,
            expected_call_key_digest=expected_call_key_digest,
            expected_target_id=expected_target_id,
            expected_call_id=expected_call_id,
            expected_session_id=expected_session_id,
            expected_request_digest=expected_request_digest,
            expected_execution_subject_digest=expected_execution_subject_digest,
            expected_runtime_sha256=expected_runtime_sha256,
        )
        RosContainerProvider(
            container,
            container_user=container_user,
            timeout_s=4.0,
            autonomous_source_confirmed=False,
        )
    except (PhysicalWorkerAmbiguity, TypeError, ValueError):
        return False
    try:
        registry = read_target_physical_worker_registry(
            expected_call_key_digest=expected_call_key_digest,
            expected_target_id=expected_target_id,
            expected_call_id=expected_call_id,
            expected_session_id=expected_session_id,
            expected_request_digest=expected_request_digest,
            expected_execution_subject_digest=expected_execution_subject_digest,
            expected_runtime_sha256=expected_runtime_sha256,
            container=container,
            container_user=container_user,
            require_live=False,
        )
    except (PhysicalWorkerAmbiguity, PhysicalWorkerConfigurationError):
        return False
    if registry is not None:
        if registry.state != "ACTIVE" or registry.armed_zero != parsed:
            return False
        return recover_armed_zero_process(
            parsed,
            expected_call_key_digest=expected_call_key_digest,
            expected_arm_receipt_digest=parsed.arm_receipt_digest,
            container=container,
            container_user=container_user,
        )

    # The inner runtime durably terminalizes before it sends RESULT.  A crash
    # in that intentional ordering leaves no ACTIVE record and no supervisor
    # result.  Recover only through the exact target-HMAC-verified terminal
    # record; an unqualified ABSENT response is never sufficient proof.
    try:
        terminal = read_target_physical_worker_terminal_registry(
            expected_call_key_digest=expected_call_key_digest,
            expected_target_id=expected_target_id,
            expected_call_id=expected_call_id,
            expected_session_id=expected_session_id,
            expected_request_digest=expected_request_digest,
            expected_execution_subject_digest=expected_execution_subject_digest,
            expected_runtime_sha256=expected_runtime_sha256,
            expected_arm_receipt_digest=parsed.arm_receipt_digest,
            container=container,
            container_user=container_user,
        )
    except (PhysicalWorkerAmbiguity, PhysicalWorkerConfigurationError):
        return False
    if terminal is None or terminal.armed_zero != parsed:
        return False
    return _run_inner_control_identity(
        container=container,
        container_user=container_user,
        identity=parsed.inner_process_identity,
        mode="reap",
    )


def recover_armed_zero_process(
    armed_zero: PhysicalWorkerArmedZero,
    *,
    expected_call_key_digest: str,
    expected_arm_receipt_digest: str,
    container: str = "MentorPi",
    container_user: str = "ubuntu",
) -> bool:
    """Exact-reap and terminalize an already authenticated typed ARM receipt."""

    if not isinstance(armed_zero, PhysicalWorkerArmedZero) or armed_zero.call_key_digest != expected_call_key_digest or armed_zero.arm_receipt_digest != expected_arm_receipt_digest:
        return False
    try:
        _validate_registry_container(container, container_user)
    except PhysicalWorkerConfigurationError:
        return False
    reaped = _run_inner_control_identity(
        container=container,
        container_user=container_user,
        identity=armed_zero.inner_process_identity,
        mode="reap",
    )
    return reaped and _terminalize_target_registry(
        armed_zero,
        container=container,
        container_user=container_user,
        reason="RECOVERED_UNKNOWN",
    )


def read_target_physical_worker_registry(
    *,
    expected_call_key_digest: str,
    expected_target_id: str,
    expected_call_id: str,
    expected_session_id: str,
    expected_request_digest: str,
    expected_execution_subject_digest: str,
    expected_runtime_sha256: str,
    container: str = "MentorPi",
    container_user: str = "ubuntu",
    require_live: bool = True,
) -> PhysicalWorkerRegistryRecord | None:
    """Read one target-authenticated active registry record without a shell."""

    raw = _read_target_registry_value(
        container=container,
        container_user=container_user,
    )
    if raw is None:
        return None
    record = _parse_physical_worker_registry_record(
        raw,
        expected_call_key_digest=expected_call_key_digest,
        expected_target_id=expected_target_id,
        expected_call_id=expected_call_id,
        expected_session_id=expected_session_id,
        expected_request_digest=expected_request_digest,
        expected_execution_subject_digest=expected_execution_subject_digest,
        expected_runtime_sha256=expected_runtime_sha256,
    )
    if require_live:
        point = time.time()
        if (
            record.state != "ACTIVE"
            or point < record.armed_zero.registry_issued_at_epoch_s
            or point >= record.armed_zero.registry_expires_at_epoch_s
            or point < record.last_zero_at_epoch_s
            or point - record.last_zero_at_epoch_s > _MAX_ZERO_HEARTBEAT_AGE_S
            or point - record.updated_at_epoch_s > _MAX_ZERO_HEARTBEAT_AGE_S
        ):
            raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_REGISTRY_STALE")
    return record


def read_target_physical_worker_terminal_registry(
    *,
    expected_call_key_digest: str,
    expected_target_id: str,
    expected_call_id: str,
    expected_session_id: str,
    expected_request_digest: str,
    expected_execution_subject_digest: str,
    expected_runtime_sha256: str,
    expected_arm_receipt_digest: str,
    container: str = "MentorPi",
    container_user: str = "ubuntu",
) -> PhysicalWorkerRegistryRecord | None:
    """Read one exact target-HMAC-verified TERMINAL record by arm digest."""

    raw = _read_target_terminal_registry_value(
        container=container,
        container_user=container_user,
        arm_receipt_digest=expected_arm_receipt_digest,
    )
    if raw is None:
        return None
    record = _parse_physical_worker_registry_record(
        raw,
        expected_call_key_digest=expected_call_key_digest,
        expected_target_id=expected_target_id,
        expected_call_id=expected_call_id,
        expected_session_id=expected_session_id,
        expected_request_digest=expected_request_digest,
        expected_execution_subject_digest=expected_execution_subject_digest,
        expected_runtime_sha256=expected_runtime_sha256,
    )
    if record.state != "TERMINAL" or record.armed_zero.arm_receipt_digest != expected_arm_receipt_digest:
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_TERMINAL_REGISTRY_MISMATCH")
    return record


def cleanup_terminal_registry(
    armed_zero: PhysicalWorkerArmedZero,
    *,
    expected_call_key_digest: str,
    expected_arm_receipt_digest: str,
    container: str = "MentorPi",
    container_user: str = "ubuntu",
) -> bool:
    """Delete only a matching TERMINAL record whose exact inner identity is gone."""

    if not isinstance(armed_zero, PhysicalWorkerArmedZero) or armed_zero.call_key_digest != expected_call_key_digest or armed_zero.arm_receipt_digest != expected_arm_receipt_digest:
        return False
    return _cleanup_target_registry(
        armed_zero,
        container=container,
        container_user=container_user,
    )


def _parse_physical_worker_registry_record(
    value: object,
    *,
    expected_call_key_digest: str,
    expected_target_id: str,
    expected_call_id: str,
    expected_session_id: str,
    expected_request_digest: str,
    expected_execution_subject_digest: str,
    expected_runtime_sha256: str,
) -> PhysicalWorkerRegistryRecord:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "state",
        "arm_receipt",
        "updated_at_epoch_s",
        "zero_refresh_count",
        "last_zero_at_epoch_s",
        "terminal_reason",
        "registry_auth_tag",
    }:
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_REGISTRY_INVALID")
    state = value.get("state")
    updated_at = _optional_finite_number(value.get("updated_at_epoch_s"))
    refresh_count = value.get("zero_refresh_count")
    last_zero_at = _optional_finite_number(value.get("last_zero_at_epoch_s"))
    reason = value.get("terminal_reason")
    tag = value.get("registry_auth_tag")
    if (
        value.get("schema_version") != _REGISTRY_SCHEMA
        or state not in {"ACTIVE", "TERMINAL"}
        or updated_at is None
        or updated_at <= 0
        or isinstance(refresh_count, bool)
        or not isinstance(refresh_count, int)
        or refresh_count < 0
        or last_zero_at is None
        or last_zero_at <= 0
        or last_zero_at > updated_at
        or not isinstance(tag, str)
        or re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", tag) is None
        or (state == "ACTIVE" and reason is not None)
        or (state == "TERMINAL" and (not isinstance(reason, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", reason) is None))
    ):
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_REGISTRY_INVALID")
    armed = parse_physical_worker_armed_zero(
        value.get("arm_receipt"),
        expected_call_key_digest=expected_call_key_digest,
        expected_target_id=expected_target_id,
        expected_call_id=expected_call_id,
        expected_session_id=expected_session_id,
        expected_request_digest=expected_request_digest,
        expected_execution_subject_digest=expected_execution_subject_digest,
        expected_runtime_sha256=expected_runtime_sha256,
    )
    if updated_at < armed.registry_issued_at_epoch_s:
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_REGISTRY_INVALID")
    return PhysicalWorkerRegistryRecord(
        state=state,
        armed_zero=armed,
        updated_at_epoch_s=updated_at,
        zero_refresh_count=refresh_count,
        last_zero_at_epoch_s=last_zero_at,
        terminal_reason=reason,
        registry_auth_tag=tag,
    )


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_CANONICAL_JSON_INVALID") from exc


def _registry_binding_digest(
    *,
    target_id: str,
    call_key_digest: str,
    call_id: str,
    session_id: str,
    execution_subject_digest: str,
    publisher_identity: str,
    publisher_gid: str,
    provider_pid: int,
    provider_start_time_ticks: int,
    provider_runtime_sha256: str,
    provider_cmdline_sha256: str,
    issued_at_epoch_s: float,
    expires_at_epoch_s: float,
) -> str:
    payload = {
        "schema_version": _REGISTRY_BINDING_SCHEMA,
        "target_id": target_id,
        "call_key_digest": call_key_digest,
        "call_id": call_id,
        "session_id": session_id,
        "execution_subject_digest": execution_subject_digest,
        "publisher_identity": publisher_identity,
        "publisher_gid": publisher_gid,
        "provider_pid": provider_pid,
        "provider_start_time_ticks": provider_start_time_ticks,
        "provider_runtime_sha256": provider_runtime_sha256,
        "provider_cmdline_sha256": provider_cmdline_sha256,
        "issued_at_epoch_s": issued_at_epoch_s,
        "expires_at_epoch_s": expires_at_epoch_s,
    }
    return "sha256:" + hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _auth_tag(value: Mapping[str, Any], control_key: str) -> str:
    return hmac.new(
        control_key.encode("ascii"),
        _canonical_bytes(dict(value)),
        hashlib.sha256,
    ).hexdigest()


def _control_message(
    *,
    control_key: str,
    call_key_digest: str,
    sequence: int,
    intent: Literal["START", "STOP", "CANCEL"],
) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "schema_version": _CONTROL_SCHEMA,
        "kind": "CONTROL",
        "sequence": sequence,
        "call_key_digest": call_key_digest,
        "intent": intent,
    }
    return {**unsigned, "auth_tag": _auth_tag(unsigned, control_key)}


def _verify_authenticated_envelope(
    value: Mapping[str, Any],
    control_key: str,
    *,
    schema: str,
    kind: str,
) -> None:
    tag = value.get("auth_tag")
    unsigned = {key: item for key, item in value.items() if key != "auth_tag"}
    if (
        value.get("schema_version") != schema
        or value.get("kind") != kind
        or not isinstance(tag, str)
        or _HEX_SHA256.fullmatch(tag) is None
        or not hmac.compare_digest(tag, _auth_tag(unsigned, control_key))
    ):
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_MESSAGE_AUTHENTICATION_FAILED")


def _inner_program(*, runtime_source: str, request_json: str) -> str:
    """Build trusted inner orchestration around bounded_twist's public hook."""

    # Values below are repository-controlled constants or canonical validated
    # request data.  They are Python literals, not shell fragments.
    return f"""
import hashlib, hmac, json, math, os, queue, sys, threading, time
CONTROL_SCHEMA = {json.dumps(_CONTROL_SCHEMA)}
ARM_SCHEMA = {json.dumps(_ARM_SCHEMA)}
PREPARE_ERROR_SCHEMA = {json.dumps(_PREPARE_ERROR_SCHEMA)}
RESULT_SCHEMA = {json.dumps(_RESULT_SCHEMA)}
IDENTITY_SCHEMA = {json.dumps(_INNER_IDENTITY_SCHEMA)}
ARM_RECEIPT_SCHEMA = {json.dumps(_ARM_RECEIPT_SCHEMA)}
REGISTRY_BINDING_SCHEMA = {json.dumps(_REGISTRY_BINDING_SCHEMA)}
CALL_KEY = None
CONTROL_KEY = None
INNER_IDENTITY = None
ARM_RECEIPT = None
ARM_IO = None
ARM_REQUEST = None
ARM_ZERO_COUNT = 0
CONTROL_FAILED = False
PRESTART_FAILURE_REASON = None
exec({json.dumps(_TARGET_REGISTRY_LIBRARY)}, globals())
exec({json.dumps(_PRESTART_GUARD_LIBRARY)}, globals())

def canonical(value):
    return json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')

def tag(value):
    return hmac.new(CONTROL_KEY.encode('ascii'), canonical(value), hashlib.sha256).hexdigest()

def emit(unsigned):
    value = dict(unsigned); value['auth_tag'] = tag(unsigned)
    sys.stdout.write(json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\\n')
    sys.stdout.flush()

def read_value():
    line = sys.stdin.buffer.readline({_MAX_LINE_BYTES + 1})
    if not line or len(line) > {_MAX_LINE_BYTES}:
        raise RuntimeError('CONTROL_LINE_INVALID')
    value = json.loads(line.decode('ascii'))
    if not isinstance(value, dict): raise RuntimeError('CONTROL_OBJECT_INVALID')
    return value

bootstrap = read_value()
if set(bootstrap) != {{
    'schema_version','kind','sequence','call_key_digest','target_id','call_id',
    'session_id','request_digest','execution_subject_digest','runtime_sha256',
    'request_deadline_epoch_s','control_key'
}}:
    raise RuntimeError('BOOTSTRAP_SHAPE_INVALID')
if bootstrap.get('schema_version') != CONTROL_SCHEMA or bootstrap.get('kind') != 'BOOTSTRAP' or bootstrap.get('sequence') != 0:
    raise RuntimeError('BOOTSTRAP_INVALID')
CALL_KEY = bootstrap['call_key_digest']; CONTROL_KEY = bootstrap['control_key']
if not isinstance(CONTROL_KEY, str) or len(CONTROL_KEY) != 64:
    raise RuntimeError('BOOTSTRAP_KEY_INVALID')

def identity():
    pid = os.getpid()
    stat = open('/proc/%d/stat' % pid, 'rb').read().split()
    cmdline = open('/proc/%d/cmdline' % pid, 'rb').read()
    return {{'schema_version': IDENTITY_SCHEMA, 'pid': pid, 'start_ticks': int(stat[21]), 'cmdline_sha256': hashlib.sha256(cmdline).hexdigest()}}

INNER_IDENTITY = identity()

def full_name(info):
    namespace = str(getattr(info, 'node_namespace', '') or '/').strip('/')
    name = str(getattr(info, 'node_name', '') or '').strip('/')
    if not name: return None
    return '/' + ('%s/' % namespace if namespace else '') + name

def gid(info):
    raw = getattr(info, 'endpoint_gid', None)
    try: value = bytes(raw).hex()
    except Exception: return None
    return value if len(value) >= 16 else None

def verify_control(value, sequence, intents):
    if set(value) != {{'schema_version','kind','sequence','call_key_digest','intent','auth_tag'}}:
        raise RuntimeError('CONTROL_SHAPE_INVALID')
    unsigned = {{k:v for k,v in value.items() if k != 'auth_tag'}}
    observed = value.get('auth_tag')
    if (
        value.get('schema_version') != CONTROL_SCHEMA
        or value.get('kind') != 'CONTROL'
        or value.get('sequence') != sequence
        or value.get('call_key_digest') != CALL_KEY
        or value.get('intent') not in intents
        or not isinstance(observed, str)
        or not hmac.compare_digest(observed, tag(unsigned))
    ):
        raise RuntimeError('CONTROL_AUTH_INVALID')
    return value['intent']

def stop_result(io, request, zeros):
    started = io.now()
    for _ in range(5): io.publish(0.0); io.spin(0.05)
    settle_end = io.now() + 0.35
    while io.now() < settle_end: io.spin(0.02)
    state = io.latest(); fresh = state is not None and io.now() - state['at'] <= 0.5
    stopped = bool(fresh and abs(state['angular_speed']) <= 0.03)
    try: evidence = io.independent_motion_evidence(request['goal_yaw_rad'], started, started, io.now())
    except Exception: evidence = {{'status':'NOT_VERIFIED','independent_of_odom':True,'settled':False}}
    result = {{
        'status':'STOPPED',
        'motion_started':False,
        'motion_command_emitted':False,
        'stop_published':True,
        'command_stopped':stopped,
        'stopped_observed':stopped,
        'physical_stop_verified':bool(
            isinstance(evidence,dict) and evidence.get('settled') is True
        ),
        'angle_accuracy_verified':False,
        'control_graph_isolated':bool(io.control_graph_isolated()),
        'independent_motion_evidence':evidence,
        'zero_publish_count':zeros + 5,
    }}
    if PRESTART_FAILURE_REASON is not None:
        result['prestart_failure_reason'] = PRESTART_FAILURE_REASON
    return result

def independent_stationary_evidence(io):
    now = io.now()
    counts = {{}}; ages = {{}}; maxima = {{}}
    for topic in sorted(io.imu_samples):
        samples = io.imu_samples[topic]
        tail = [(at, abs(value)) for at, value in samples if now - {_STATIONARY_WINDOW_S!r} <= at <= now]
        if not tail: continue
        age = now - tail[-1][0]; maximum = max(value for _at, value in tail)
        if len(tail) >= 2 and age <= {_STATIONARY_LAST_SAMPLE_MAX_AGE_S!r} and maximum <= {_STATIONARY_MAX_ABS_RAD_S!r}:
            counts[topic] = len(tail); ages[topic] = age; maxima[topic] = maximum
    sources = sorted(counts)
    if not sources: return None
    return {{
        'independent_stationary_sources':sources,
        'independent_stationary_sample_counts':counts,
        'independent_stationary_last_sample_age_s':ages,
        'independent_stationary_max_abs_rad_s':maxima,
        'independent_stationary_window_s':{_STATIONARY_WINDOW_S!r},
    }}

def _rolo_prearm(io, node, publisher, request):
    global ARM_RECEIPT, ARM_IO, ARM_REQUEST, ARM_ZERO_COUNT, CONTROL_FAILED, PRESTART_FAILURE_REASON
    ARM_IO = io; ARM_REQUEST = request
    zeros = 5
    ARM_ZERO_COUNT = zeros
    deadline = time.monotonic() + 5.0
    controlled = competing = direct = stationary = None
    guard_reason = 'TOPOLOGY_UNAVAILABLE'
    while time.monotonic() < deadline:
        controlled = node.get_publishers_info_by_topic('/cmd_vel')
        competing = node.get_publishers_info_by_topic('/controller/cmd_vel')
        direct = node.get_publishers_info_by_topic('/ros_robot_controller/set_motor')
        controlled_names = [full_name(item) for item in controlled]
        controlled_gids = [gid(item) for item in controlled]
        direct_names = [full_name(item) for item in direct]
        state = io.latest()
        stationary = independent_stationary_evidence(io)
        fresh_zero = state is not None and io.now() - state['at'] <= 0.5 and abs(state['angular_speed']) <= 0.03
        guard_state, guard_reason = classify_prestart_guard_observation(
            controlled_names, controlled_gids, None, len(competing), direct_names,
            publisher.get_subscription_count(),
            None if stationary is None else stationary['independent_stationary_sources'],
            (), fresh_zero,
        )
        if guard_state == 'DANGER':
            raise RuntimeError('ARMED_ZERO_' + guard_reason)
        if guard_state == 'HEALTHY':
            break
        io.publish(0.0); zeros += 1; ARM_ZERO_COUNT = zeros; io.spin(0.02)
    else:
        raise RuntimeError('ARMED_ZERO_' + guard_reason)
    target_monotonic = time.monotonic(); issued_at = time.time()
    expires_at = min(float(bootstrap['request_deadline_epoch_s']), issued_at + {_MAX_ARMED_ZERO_GATE_S!r})
    if not math.isfinite(expires_at) or expires_at <= issued_at:
        raise RuntimeError('REGISTRY_EXPIRY_INVALID')
    provider_runtime = 'sha256:' + bootstrap['runtime_sha256']
    provider_cmdline = 'sha256:' + INNER_IDENTITY['cmdline_sha256']
    provider_identity_payload = {{
        'schema_version':'rolo-landerpi-armed-zero-provider-identity/v1',
        'call_id':bootstrap['call_id'],'session_id':bootstrap['session_id'],
        'execution_subject_digest':bootstrap['execution_subject_digest'],
        'publisher_identity':'/rolo_bounded_twist','publisher_gid':controlled_gids[0],
        'provider_pid':INNER_IDENTITY['pid'],'provider_start_time_ticks':INNER_IDENTITY['start_ticks'],
        'provider_runtime_sha256':provider_runtime,'provider_cmdline_sha256':provider_cmdline,
    }}
    provider_identity_digest = 'sha256:' + hashlib.sha256(canonical(provider_identity_payload)).hexdigest()
    registry_binding_payload = {{
        'schema_version':REGISTRY_BINDING_SCHEMA,'target_id':bootstrap['target_id'],
        'call_key_digest':CALL_KEY,'call_id':bootstrap['call_id'],'session_id':bootstrap['session_id'],
        'execution_subject_digest':bootstrap['execution_subject_digest'],
        'publisher_identity':'/rolo_bounded_twist','publisher_gid':controlled_gids[0],
        'provider_pid':INNER_IDENTITY['pid'],'provider_start_time_ticks':INNER_IDENTITY['start_ticks'],
        'provider_runtime_sha256':provider_runtime,'provider_cmdline_sha256':provider_cmdline,
        'issued_at_epoch_s':issued_at,'expires_at_epoch_s':expires_at,
    }}
    registry_binding_digest = 'sha256:' + hashlib.sha256(canonical(registry_binding_payload)).hexdigest()
    receipt = {{
        'schema_version':ARM_RECEIPT_SCHEMA,'call_key_digest':CALL_KEY,
        'target_id':bootstrap['target_id'],'call_id':bootstrap['call_id'],'session_id':bootstrap['session_id'],
        'request_digest':bootstrap['request_digest'],'execution_subject_digest':bootstrap['execution_subject_digest'],
        'runtime_sha256':bootstrap['runtime_sha256'],'command_endpoint':'/cmd_vel',
        'publisher_identity':'/rolo_bounded_twist','publisher_endpoint_gids':controlled_gids,
        'publisher_endpoint_count':1,'competing_publisher_count':0,
        'direct_motor_publisher_identities':['/odom_publisher'],'zeros_published':zeros,
        **stationary,
        'motion_command_emitted':False,'motion_enabled':False,
        'inner_process_identity':INNER_IDENTITY,'target_monotonic_s':target_monotonic,
        'provider_runtime_sha256':provider_runtime,'provider_cmdline_sha256':provider_cmdline,
        'provider_runtime_identity_digest':provider_identity_digest,
        'registry_issued_at_epoch_s':issued_at,'registry_expires_at_epoch_s':expires_at,
        'registry_binding_digest':registry_binding_digest,
    }}
    receipt['arm_receipt_digest'] = hashlib.sha256(canonical(receipt)).hexdigest()
    registry_write_active(receipt)
    ARM_RECEIPT = receipt
    arm_fields = {{k:v for k,v in receipt.items() if k not in {{'schema_version','publisher_endpoint_count'}}}}
    emit({{'schema_version':ARM_SCHEMA,'kind':'ARMED_ZERO',**arm_fields}})
    controls = queue.Queue(maxsize=1)
    def await_initial_control():
        global CONTROL_FAILED
        try: controls.put(('CONTROL', verify_control(read_value(), 1, {{'START','STOP','CANCEL'}})))
        except Exception: CONTROL_FAILED = True; controls.put(('ERROR', None))
    threading.Thread(target=await_initial_control, name='rolo-inner-arm-control', daemon=True).start()
    next_refresh = time.monotonic()
    transient_since = None
    transient_reason = None
    pending_intent = None
    intent = None
    while intent is None:
        if time.time() >= expires_at:
            PRESTART_FAILURE_REASON = 'PRESTART_ARM_LEASE_EXPIRED'
            CONTROL_FAILED = True; return stop_result(io, request, zeros)
        io.publish(0.0); zeros += 1; ARM_ZERO_COUNT = zeros; io.spin(0.02)
        if io.cancelled:
            PRESTART_FAILURE_REASON = 'PRESTART_IO_CANCELLED'
            CONTROL_FAILED = True; return stop_result(io, request, zeros)
        controlled_now = node.get_publishers_info_by_topic('/cmd_vel')
        competing_now = node.get_publishers_info_by_topic('/controller/cmd_vel')
        direct_now = node.get_publishers_info_by_topic('/ros_robot_controller/set_motor')
        state = io.latest()
        stationary_now = independent_stationary_evidence(io)
        fresh_zero = state is not None and io.now() - state['at'] <= 0.5 and abs(state['angular_speed']) <= 0.03
        guard_state, guard_reason = classify_prestart_guard_observation(
            [full_name(item) for item in controlled_now],
            [gid(item) for item in controlled_now],
            controlled_gids,
            len(competing_now),
            [full_name(item) for item in direct_now],
            publisher.get_subscription_count(),
            None if stationary_now is None else stationary_now['independent_stationary_sources'],
            receipt['independent_stationary_sources'],
            fresh_zero,
        )
        if guard_state == 'DANGER':
            PRESTART_FAILURE_REASON = 'PRESTART_' + guard_reason
            CONTROL_FAILED = True; return stop_result(io, request, zeros)
        transient_since, transient_reason, grace_expired = update_prestart_transient_guard(
            transient_since,
            None if guard_state == 'HEALTHY' else guard_reason,
            time.monotonic(),
            {_PRESTART_TRANSIENT_GRACE_S!r},
        )
        if grace_expired:
            PRESTART_FAILURE_REASON = 'PRESTART_' + transient_reason + '_GRACE_EXPIRED'
            CONTROL_FAILED = True; return stop_result(io, request, zeros)
        if time.monotonic() >= next_refresh:
            registry_refresh_active(
                receipt['arm_receipt_digest'], INNER_IDENTITY['pid'],
                INNER_IDENTITY['start_ticks'], INNER_IDENTITY['cmdline_sha256'],
            )
            next_refresh = time.monotonic() + {_REGISTRY_REFRESH_INTERVAL_S!r}
        if pending_intent is None:
            try: kind, observed = controls.get_nowait()
            except queue.Empty: continue
            if kind != 'CONTROL':
                PRESTART_FAILURE_REASON = 'PRESTART_CONTROL_MESSAGE_INVALID'
                return stop_result(io, request, zeros)
            pending_intent = observed
        if pending_intent != 'START' or guard_state == 'HEALTHY':
            intent = pending_intent
    ARM_ZERO_COUNT = zeros
    if intent != 'START':
        return stop_result(io, request, zeros)
    def listen():
        global CONTROL_FAILED
        try:
            observed = verify_control(read_value(), 2, {{'STOP','CANCEL'}})
            if observed in {{'STOP','CANCEL'}}: io.cancelled = True
        except Exception:
            CONTROL_FAILED = True; io.cancelled = True
    threading.Thread(target=listen, name='rolo-inner-control', daemon=True).start()
    return None

def _rolo_emit_result(result):
    global ARM_ZERO_COUNT
    if not isinstance(result, dict): raise RuntimeError('RESULT_INVALID')
    if result.get('motion_started') is False:
        original_status = result.get('status', 'UNKNOWN')
        original_error = result.get('error')
        safe = stop_result(ARM_IO, ARM_REQUEST, ARM_ZERO_COUNT)
        result = {{**result, **safe, 'status':original_status,
            'motion_started':False, 'motion_command_emitted':False}}
        if original_error is not None: result['error'] = original_error
        ARM_ZERO_COUNT = int(result.get('zero_publish_count', ARM_ZERO_COUNT))
    if CONTROL_FAILED: result = dict(result); result['control_channel_failed'] = True; result['status'] = 'UNKNOWN'
    if ARM_RECEIPT is None: raise RuntimeError('REGISTRY_ARM_MISSING')
    registry_terminalize(
        ARM_RECEIPT['arm_receipt_digest'], INNER_IDENTITY['pid'],
        INNER_IDENTITY['start_ticks'], INNER_IDENTITY['cmdline_sha256'],
        'RESULT_' + str(result.get('status', 'UNKNOWN')).upper()[:32],
    )
    emit({{'schema_version':RESULT_SCHEMA,'kind':'RESULT','call_key_digest':CALL_KEY,'inner_process_identity':INNER_IDENTITY,'result':result}})

try:
    runtime_source = {json.dumps(runtime_source)}
    namespace = {{'__name__':'rolo_bounded_twist_embedded'}}
    exec(compile(runtime_source, '<rolo-bounded-twist>', 'exec'), namespace, namespace)
    request = json.loads({json.dumps(request_json)})
    namespace['run_ros_entrypoint'](
        request,
        start_gate=lambda io, node, publisher: _rolo_prearm(
            io,
            node,
            publisher,
            request,
        ),
        result_sink=_rolo_emit_result,
    )
except BaseException as exc:
    if ARM_RECEIPT is None:
        error = str(exc)
        code_shaped = (
            bool(error)
            and len(error) <= 111
            and all(character in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_' for character in error)
        )
        if code_shaped and not error.startswith('PHYSICAL_WORKER_'):
            error = 'PHYSICAL_WORKER_' + error
        elif isinstance(exc, ModuleNotFoundError):
            error = 'PHYSICAL_WORKER_RUNTIME_IMPORT_FAILED'
        elif isinstance(exc, PermissionError):
            error = 'PHYSICAL_WORKER_RUNTIME_PERMISSION_FAILED'
        elif isinstance(exc, FileNotFoundError):
            error = 'PHYSICAL_WORKER_RUNTIME_FILE_MISSING'
        elif isinstance(exc, SyntaxError):
            error = 'PHYSICAL_WORKER_RUNTIME_SYNTAX_INVALID'
        elif not code_shaped:
            error = 'PHYSICAL_WORKER_INNER_PREPARE_FAILED'
        emit({{
            'schema_version':PREPARE_ERROR_SCHEMA,
            'kind':'PREPARE_ERROR',
            'call_key_digest':CALL_KEY,
            'target_id':bootstrap['target_id'],
            'call_id':bootstrap['call_id'],
            'session_id':bootstrap['session_id'],
            'request_digest':bootstrap['request_digest'],
            'error':error,
        }})
    raise
""".strip()


def _inner_control_command(
    worker: LanderPiRotateProcessWorker,
    identity: InnerProcessIdentity,
    *,
    mode: Literal["probe", "reap"],
) -> list[str]:
    return _inner_control_command_identity(
        container=worker.container,
        container_user=worker.container_user,
        identity=identity,
        mode=mode,
    )


def _inner_control_command_identity(
    *,
    container: str,
    container_user: str,
    identity: InnerProcessIdentity,
    mode: Literal["probe", "reap"],
) -> list[str]:
    return [
        "docker",
        "exec",
        "-i",
        "-u",
        container_user,
        container,
        "python3",
        "-c",
        _INNER_REAPER,
        mode,
        str(identity.pid),
        str(identity.start_ticks),
        identity.cmdline_sha256,
    ]


def _run_inner_control(
    worker: LanderPiRotateProcessWorker,
    identity: InnerProcessIdentity,
    *,
    mode: Literal["probe", "reap"],
) -> bool:
    return _run_inner_control_identity(
        container=worker.container,
        container_user=worker.container_user,
        identity=identity,
        mode=mode,
    )


def _run_inner_control_identity(
    *,
    container: str,
    container_user: str,
    identity: InnerProcessIdentity,
    mode: Literal["probe", "reap"],
) -> bool:
    try:
        completed = subprocess.run(
            _inner_control_command_identity(
                container=container,
                container_user=container_user,
                identity=identity,
                mode=mode,
            ),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            shell=False,
            timeout=4.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    stdout = bytes(completed.stdout or b"")
    stderr = bytes(completed.stderr or b"")
    if len(stdout) > 128 or len(stderr) > 512:
        return False
    return completed.returncode == 0 and stdout.strip() in {b"GONE", b"REAPED"}


def _registry_control_command(
    *,
    container: str,
    container_user: str,
    mode: Literal["read", "terminal", "cleanup"],
    armed_zero: PhysicalWorkerArmedZero | None = None,
    reason: str | None = None,
) -> list[str]:
    program = _REGISTRY_READER if mode == "read" else _REGISTRY_CONTROL
    argv = [
        "docker",
        "exec",
        "-i",
        "-u",
        container_user,
        container,
        "python3",
        "-c",
        program,
    ]
    if mode == "read":
        if armed_zero is not None or reason is not None:
            raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_REGISTRY_COMMAND_INVALID")
        return argv
    argv.append(mode)
    if not isinstance(armed_zero, PhysicalWorkerArmedZero):
        raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_REGISTRY_COMMAND_INVALID")
    identity = armed_zero.inner_process_identity
    if mode == "terminal":
        if reason not in {"AMBIGUOUS_REAP", "RECOVERED_UNKNOWN"}:
            raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_REGISTRY_COMMAND_INVALID")
        return [
            *argv,
            armed_zero.arm_receipt_digest,
            str(identity.pid),
            str(identity.start_ticks),
            identity.cmdline_sha256,
            reason,
        ]
    if reason is not None:
        raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_REGISTRY_COMMAND_INVALID")
    return [
        *argv,
        armed_zero.call_key_digest,
        armed_zero.arm_receipt_digest,
        str(identity.pid),
        str(identity.start_ticks),
        identity.cmdline_sha256,
    ]


def _validate_registry_container(container: str, container_user: str) -> None:
    if container != "MentorPi" or container_user != "ubuntu":
        raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_CONTAINER_IDENTITY_INVALID")
    try:
        RosContainerProvider(
            container,
            container_user=container_user,
            timeout_s=4.0,
            autonomous_source_confirmed=False,
        )
    except (TypeError, ValueError) as exc:
        raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_CONTAINER_IDENTITY_INVALID") from exc


def _run_registry_command(argv: list[str]) -> bytes | None:
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            shell=False,
            timeout=4.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    stdout = bytes(completed.stdout or b"")
    stderr = bytes(completed.stderr or b"")
    if completed.returncode != 0 or len(stdout) > 32_768 or len(stderr) > 512:
        return None
    return stdout.strip()


def _read_target_registry_value(
    *,
    container: str,
    container_user: str,
) -> dict[str, Any] | None:
    _validate_registry_container(container, container_user)
    output = _run_registry_command(
        _registry_control_command(
            container=container,
            container_user=container_user,
            mode="read",
        )
    )
    if output == b"ABSENT":
        return None
    if output is None or not output:
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_REGISTRY_READ_FAILED")
    try:
        value = loads_unique_json(output.decode("ascii"))
    except (UnicodeError, ValueError) as exc:
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_REGISTRY_READ_FAILED") from exc
    if not isinstance(value, dict):
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_REGISTRY_READ_FAILED")
    return value


def _read_target_terminal_registry_value(
    *,
    container: str,
    container_user: str,
    arm_receipt_digest: str,
) -> dict[str, Any] | None:
    _validate_registry_container(container, container_user)
    if _HEX_SHA256.fullmatch(arm_receipt_digest) is None:
        raise PhysicalWorkerConfigurationError("PHYSICAL_WORKER_ARM_DIGEST_INVALID")
    output = _run_registry_command(
        [
            "docker",
            "exec",
            "-i",
            "-u",
            container_user,
            container,
            "python3",
            "-c",
            _REGISTRY_TERMINAL_READER,
            arm_receipt_digest,
        ]
    )
    if output == b"ABSENT":
        return None
    if output is None or not output:
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_REGISTRY_READ_FAILED")
    try:
        value = loads_unique_json(output.decode("ascii"))
    except (UnicodeError, ValueError) as exc:
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_REGISTRY_READ_FAILED") from exc
    if not isinstance(value, dict):
        raise PhysicalWorkerAmbiguity("PHYSICAL_WORKER_REGISTRY_READ_FAILED")
    return value


def _terminalize_target_registry(
    armed_zero: PhysicalWorkerArmedZero,
    *,
    container: str,
    container_user: str,
    reason: Literal["AMBIGUOUS_REAP", "RECOVERED_UNKNOWN"],
) -> bool:
    try:
        _validate_registry_container(container, container_user)
        output = _run_registry_command(
            _registry_control_command(
                container=container,
                container_user=container_user,
                mode="terminal",
                armed_zero=armed_zero,
                reason=reason,
            )
        )
    except PhysicalWorkerConfigurationError:
        return False
    return output == b"true"


def _cleanup_target_registry(
    armed_zero: PhysicalWorkerArmedZero,
    *,
    container: str,
    container_user: str,
) -> bool:
    try:
        _validate_registry_container(container, container_user)
        output = _run_registry_command(
            _registry_control_command(
                container=container,
                container_user=container_user,
                mode="cleanup",
                armed_zero=armed_zero,
            )
        )
    except PhysicalWorkerConfigurationError:
        return False
    return output == b"true"


def _quarantine_target_registry(
    worker: LanderPiRotateProcessWorker,
    identity: InnerProcessIdentity,
) -> bool:
    """Terminalize only the HMAC-authenticated ACTIVE record for this call.

    This narrower recovery path is used when the child ARMED_ZERO frame was
    authenticated but failed a later strict receipt check, so there is no
    trusted ``PhysicalWorkerArmedZero`` available on the host.  All receipt
    identity fields are instead compared inside the target against its signed
    registry before ACTIVE can be moved to TERMINAL.
    """

    try:
        _validate_registry_container(worker.container, worker.container_user)
        output = _run_registry_command(
            [
                "docker",
                "exec",
                "-i",
                "-u",
                worker.container_user,
                worker.container,
                "python3",
                "-c",
                _REGISTRY_CONTROL,
                "quarantine",
                worker.expected_call_key_digest,
                worker.target_id,
                worker.call_id,
                worker.session_id,
                worker.request_digest,
                worker.execution_subject_digest,
                worker.runtime_sha256,
                str(identity.pid),
                str(identity.start_ticks),
                identity.cmdline_sha256,
            ]
        )
    except PhysicalWorkerConfigurationError:
        return False
    return output == b"true"


def _prove_inner_gone(worker: LanderPiRotateProcessWorker, identity: InnerProcessIdentity) -> bool:
    return _run_inner_control(worker, identity, mode="probe")


def _recover_inner_or_outer(
    worker: LanderPiRotateProcessWorker,
    transport: _ProviderTransport,
    *,
    identity: InnerProcessIdentity | None,
) -> bool:
    reaped = _run_inner_control(worker, identity, mode="reap") if identity is not None else False
    registry_terminal = _quarantine_target_registry(worker, identity) if reaped and identity is not None else False
    _terminate_outer(transport.process)
    transport.wait_outer(timeout_s=1.0)
    return reaped and registry_terminal


def _terminate_outer(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        process.terminate()
    except (OSError, ValueError):
        pass
    deadline = time.monotonic() + 0.5
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(_POLL_INTERVAL_S)
    if process.poll() is None:
        try:
            process.kill()
        except (OSError, ValueError):
            pass


def _authenticated_identity(envelope: object, control_key: str) -> InnerProcessIdentity | None:
    if not isinstance(envelope, dict):
        return None
    try:
        _verify_authenticated_envelope(
            envelope,
            control_key,
            schema=_ARM_SCHEMA,
            kind="ARMED_ZERO",
        )
        return InnerProcessIdentity.parse(envelope.get("inner_process_identity"))
    except PhysicalWorkerAmbiguity:
        return None


def _recoverable_prepare_identity(
    worker: LanderPiRotateProcessWorker,
    envelope: object,
    control_key: str,
) -> InnerProcessIdentity | None:
    identity = _authenticated_identity(envelope, control_key)
    if identity is not None:
        return identity
    # If the host frame was damaged before it could be authenticated, the
    # target-HMAC registry is an independent trust boundary.  It may supply an
    # exact identity only after every trusted call/release expectation parses.
    try:
        record = read_target_physical_worker_registry(
            expected_call_key_digest=worker.expected_call_key_digest,
            expected_target_id=worker.target_id,
            expected_call_id=worker.call_id,
            expected_session_id=worker.session_id,
            expected_request_digest=worker.request_digest,
            expected_execution_subject_digest=worker.execution_subject_digest,
            expected_runtime_sha256=worker.runtime_sha256,
            container=worker.container,
            container_user=worker.container_user,
            require_live=False,
        )
    except (PhysicalWorkerAmbiguity, PhysicalWorkerConfigurationError):
        return None
    if record is None or record.state != "ACTIVE":
        return None
    return record.armed_zero.inner_process_identity


__all__ = [
    "InnerProcessIdentity",
    "LanderPiRotateProcessWorker",
    "PhysicalWorkerAmbiguity",
    "PhysicalWorkerArmedZero",
    "PhysicalWorkerConfigurationError",
    "PhysicalWorkerRegistryRecord",
    "PreparedLanderPiRotation",
    "cleanup_terminal_registry",
    "landerpi_bounded_twist_runtime_sha256",
    "landerpi_physical_registry_reader_program",
    "parse_physical_worker_armed_zero",
    "read_target_physical_worker_registry",
    "read_target_physical_worker_terminal_registry",
    "recover_armed_zero_process",
    "recover_persisted_armed_zero",
    "validate_landerpi_rotate_process_call",
]
