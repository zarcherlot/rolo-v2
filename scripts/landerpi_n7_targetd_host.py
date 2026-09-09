"""Spawn-safe Pi-host targetd composition for one N7 debug motion call.

Direct execution is inert unless ``--serve-stdio`` and a validated,
owner-bound bootstrap record are both supplied.  The first stdin/stdout
records use the same four-byte big-endian length prefix as targetd frames;
after the READY record the stream is handed to :class:`TargetdDaemon`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, BinaryIO

from rolo.dsl.parser import loads_unique_json
from rolo.targetd.lifecycle import WorkerCallKey
from rolo.targetd.protocol import (
    ExecutionRequestV3,
    FrameKind,
    decode_frame,
)

BOOTSTRAP_SCHEMA = "rolo-n7-targetd-host-bootstrap/v1"
READY_SCHEMA = "rolo-n7-targetd-host-ready/v1"
STAGE_OWNER_SCHEMA = "rolo-n7-targetd-host-stage/v1"
MAX_BOOTSTRAP_BYTES = 512 * 1024
MAX_TARGETD_FRAME_BYTES = 4 * 1024 * 1024
STAGE_ROOT_PATTERN = re.compile(r"^/dev/shm/rolo-n7-targetd-[0-9a-f]{20}$")
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
RAW_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
OWNER_MARKER = ".rolo-n7-targetd-owner"

_BOOTSTRAP_KEYS = {
    "schema_version",
    "run_id",
    "stage_root",
    "stage_nonce",
    "payload_sha256",
    "target_id",
    "target_identity",
    "expected_call",
    "execution_request",
    "motion_intent",
    "policy",
    "authority",
    "mapping_confirmation_receipt",
    "manifest",
    "bundle_source_base64",
    "keys",
    "peer_bootstrap_receipt",
    "provider_runtime_sha256",
    "expected_peer",
}
_EXPECTED_CALL_KEYS = {
    "id",
    "session",
    "execution_subject_digest",
    "motion_fence_epoch",
    "request_digest",
    "call_key_digest",
}
_KEY_MATERIAL_KEYS = {
    "targetd_signing_base64",
    "bundle_verification_base64",
    "graph_signing_base64",
    "target_signing_base64",
    "peer_bootstrap_verification_base64",
}
_EXPECTED_PEER_KEYS = {
    "bootstrap_authority_id",
    "ssh_host",
    "ssh_port",
    "ssh_username",
    "pinned_host_key_sha256",
    "client_public_key_sha256",
    "known_hosts_sha256",
    "channel_binding_sha256",
}


class HostBootstrapError(RuntimeError):
    """Stable fail-closed error emitted before targetd owns the stream."""


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def bootstrap_payload_sha256(payload: Mapping[str, object]) -> str:
    unsigned = dict(payload)
    unsigned.pop("payload_sha256", None)
    return "sha256:" + hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()


def encode_record(value: Mapping[str, object]) -> bytes:
    payload = canonical_json_bytes(dict(value))
    if not 2 <= len(payload) <= MAX_BOOTSTRAP_BYTES:
        raise HostBootstrapError("N7_TARGETD_HOST_RECORD_LIMIT")
    return len(payload).to_bytes(4, "big") + payload


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(bytes(chunk))
        remaining -= len(chunk)
    return b"".join(chunks)


def read_record(stream: BinaryIO, *, limit: int = MAX_BOOTSTRAP_BYTES) -> dict[str, Any]:
    header = _read_exact(stream, 4)
    if len(header) != 4:
        raise HostBootstrapError("N7_TARGETD_HOST_RECORD_TRUNCATED")
    size = int.from_bytes(header, "big")
    if not 2 <= size <= limit:
        raise HostBootstrapError("N7_TARGETD_HOST_RECORD_LIMIT")
    body = _read_exact(stream, size)
    if len(body) != size:
        raise HostBootstrapError("N7_TARGETD_HOST_RECORD_TRUNCATED")
    try:
        value = loads_unique_json(body.decode("ascii"))
    except (UnicodeError, TypeError, ValueError) as exc:
        raise HostBootstrapError("N7_TARGETD_HOST_RECORD_INVALID") from exc
    if not isinstance(value, dict):
        raise HostBootstrapError("N7_TARGETD_HOST_RECORD_INVALID")
    return value


def _require_regular(path: Path, *, mode: int | None = None) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise HostBootstrapError("N7_TARGETD_HOST_STAGE_INVALID") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise HostBootstrapError("N7_TARGETD_HOST_STAGE_INVALID")
    if os.name != "nt" and mode is not None and stat.S_IMODE(metadata.st_mode) != mode:
        raise HostBootstrapError("N7_TARGETD_HOST_STAGE_MODE_INVALID")


def validate_stage_owner(stage_root: str) -> dict[str, Any]:
    if not isinstance(stage_root, str) or STAGE_ROOT_PATTERN.fullmatch(stage_root) is None:
        raise HostBootstrapError("N7_TARGETD_HOST_STAGE_ROOT_INVALID")
    root = Path(stage_root)
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise HostBootstrapError("N7_TARGETD_HOST_STAGE_INVALID") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or root.resolve() != root
        or (os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o700)
    ):
        raise HostBootstrapError("N7_TARGETD_HOST_STAGE_INVALID")
    marker = root / OWNER_MARKER
    _require_regular(marker, mode=0o600)
    try:
        value = loads_unique_json(marker.read_text(encoding="ascii"))
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        raise HostBootstrapError("N7_TARGETD_HOST_STAGE_OWNER_INVALID") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "stage_root", "run_id", "nonce_sha256"}
        or value.get("schema_version") != STAGE_OWNER_SCHEMA
        or value.get("stage_root") != stage_root
        or not isinstance(value.get("run_id"), str)
        or IDENTIFIER_PATTERN.fullmatch(str(value.get("run_id"))) is None
        or not isinstance(value.get("nonce_sha256"), str)
        or SHA256_PATTERN.fullmatch(str(value.get("nonce_sha256"))) is None
    ):
        raise HostBootstrapError("N7_TARGETD_HOST_STAGE_OWNER_INVALID")
    return value


def validate_bootstrap(
    payload: Mapping[str, object],
    *,
    stage_root: str,
    owner: Mapping[str, object],
) -> dict[str, Any]:
    value = dict(payload)
    expected_call = value.get("expected_call")
    keys = value.get("keys")
    expected_peer = value.get("expected_peer")
    nonce = value.get("stage_nonce")
    if (
        set(value) != _BOOTSTRAP_KEYS
        or value.get("schema_version") != BOOTSTRAP_SCHEMA
        or value.get("stage_root") != stage_root
        or value.get("run_id") != owner.get("run_id")
        or not isinstance(nonce, str)
        or RAW_SHA256_PATTERN.fullmatch(nonce) is None
        or owner.get("nonce_sha256")
        != "sha256:" + hashlib.sha256(nonce.encode("ascii")).hexdigest()
        or value.get("payload_sha256") != bootstrap_payload_sha256(value)
        or not isinstance(value.get("target_id"), str)
        or IDENTIFIER_PATTERN.fullmatch(str(value.get("target_id"))) is None
        or not isinstance(value.get("target_identity"), str)
        or len(str(value.get("target_identity"))) > 256
        or not isinstance(expected_call, dict)
        or set(expected_call) != _EXPECTED_CALL_KEYS
        or not isinstance(keys, dict)
        or set(keys) != _KEY_MATERIAL_KEYS
        or not isinstance(expected_peer, dict)
        or set(expected_peer) != _EXPECTED_PEER_KEYS
    ):
        raise HostBootstrapError("N7_TARGETD_HOST_BOOTSTRAP_INVALID")
    if (
        not all(
            isinstance(expected_call.get(name), str)
            and (
                IDENTIFIER_PATTERN.fullmatch(str(expected_call[name])) is not None
                if name in {"id", "session"}
                else (
                    SHA256_PATTERN.fullmatch(str(expected_call[name])) is not None
                    if name == "execution_subject_digest"
                    else RAW_SHA256_PATTERN.fullmatch(str(expected_call[name])) is not None
                )
            )
            for name in {
                "id",
                "session",
                "execution_subject_digest",
                "request_digest",
                "call_key_digest",
            }
        )
        or isinstance(expected_call.get("motion_fence_epoch"), bool)
        or not isinstance(expected_call.get("motion_fence_epoch"), int)
        or int(expected_call["motion_fence_epoch"]) < 1
        or expected_peer.get("ssh_username") != "pi"
        or isinstance(expected_peer.get("ssh_port"), bool)
        or not isinstance(expected_peer.get("ssh_port"), int)
        or not 1 <= int(expected_peer["ssh_port"]) <= 65535
        or any(
            not isinstance(expected_peer.get(name), str)
            or SHA256_PATTERN.fullmatch(str(expected_peer[name])) is None
            for name in {
                "pinned_host_key_sha256",
                "client_public_key_sha256",
                "known_hosts_sha256",
                "channel_binding_sha256",
            }
        )
        or not isinstance(value.get("provider_runtime_sha256"), str)
        or RAW_SHA256_PATTERN.fullmatch(str(value["provider_runtime_sha256"])) is None
    ):
        raise HostBootstrapError("N7_TARGETD_HOST_BOOTSTRAP_INVALID")
    try:
        request = ExecutionRequestV3.model_validate(value.get("execution_request"))
    except (TypeError, ValueError) as exc:
        raise HostBootstrapError("N7_TARGETD_HOST_EXECUTION_REQUEST_INVALID") from exc
    request_digest = request.request_digest()
    call_key_digest = WorkerCallKey.from_request(request).digest()
    intent = request.motion_safety_admission.intent
    if (
        request.target_id != value["target_id"]
        or request.authority.mapping_admission.target_identity_digest
        != value["target_identity"]
        or request.idempotency_key != expected_call["id"]
        or request.session_id != expected_call["session"]
        or request.execution_subject_digest
        != expected_call["execution_subject_digest"]
        or request_digest != expected_call["request_digest"]
        or call_key_digest != expected_call["call_key_digest"]
        or request.authority.fence_epoch != expected_call["motion_fence_epoch"]
        or intent.model_dump(mode="json") != value.get("motion_intent")
    ):
        raise HostBootstrapError("N7_TARGETD_HOST_EXECUTION_REQUEST_MISMATCH")

    # Secrets are accepted only in this in-memory bootstrap record.  Decode
    # validation is delegated to the composition, which immediately unlinks
    # any temporary key material after constructing typed key objects.
    for material in keys.values():
        if not isinstance(material, str) or not 40 <= len(material) <= 8192:
            raise HostBootstrapError("N7_TARGETD_HOST_BOOTSTRAP_KEY_INVALID")
    return value


class _CloseAwareInput:
    """Make daemon.serve return immediately after consuming CLOSE_SESSION."""

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        self.close_seen = False
        self._pending_size: int | None = None

    def read(self, size: int = -1) -> bytes:
        if self.close_seen and self._pending_size is None:
            return b""
        value = _read_exact(self.stream, size)
        if size == 4:
            if len(value) == 4:
                self._pending_size = int.from_bytes(value, "big")
            return value
        if self._pending_size is not None and size == self._pending_size:
            encoded = self._pending_size.to_bytes(4, "big") + value
            self._pending_size = None
            try:
                frame = decode_frame(encoded)
            except Exception:
                return value
            if frame.kind == FrameKind.CLOSE_SESSION:
                self.close_seen = True
        return value


def _emit_error(stdout: BinaryIO, code: str) -> None:
    safe = code if re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", code) else "N7_TARGETD_HOST_BLOCKED"
    try:
        stdout.write(
            encode_record(
                {
                    "schema_version": "rolo-n7-targetd-host-error/v1",
                    "ok": False,
                    "error": safe,
                }
            )
        )
        stdout.flush()
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="N7 Pi-host targetd boundary")
    parser.add_argument("--serve-stdio", action="store_true")
    parser.add_argument("--stage-root")
    args = parser.parse_args(argv)
    if not args.serve_stdio:
        print('{"motion_enabled":false,"status":"DESCRIBE_ONLY"}')
        return 0
    if not args.stage_root:
        parser.error("--serve-stdio requires --stage-root")
    return serve_stdio(args.stage_root, sys.stdin.buffer, sys.stdout.buffer)


def serve_stdio(stage_root: str, stdin, stdout) -> int:
    """Validate the sealed bootstrap, then serve one targetd session."""

    runtime = None
    close_aware: _CloseAwareInput | None = None
    try:
        owner = validate_stage_owner(stage_root)
        bootstrap = validate_bootstrap(
            read_record(stdin),
            stage_root=stage_root,
            owner=owner,
        )
        from rolo.targetd.n7_host_composition import compose_n7_host_targetd

        runtime = compose_n7_host_targetd(bootstrap, stage_root=Path(stage_root))
        ready = runtime.ready_payload()
        stdout.write(encode_record(ready))
        stdout.flush()
        close_aware = _CloseAwareInput(stdin)
        runtime.daemon.serve(close_aware, stdout)
        if not close_aware.close_seen:
            raise HostBootstrapError("N7_TARGETD_HOST_CLOSE_REQUIRED")
        finalize = read_record(stdin)
        receipt = runtime.finalize(finalize)
        stdout.write(encode_record(receipt))
        stdout.flush()
        runtime.mark_finalize_delivered()
        return 0
    except HostBootstrapError as exc:
        _emit_error(stdout, str(exc))
        return 2
    except Exception as exc:
        # Composition failures intentionally expose only stable all-caps
        # reason codes.  This keeps the remote diagnostic actionable without
        # serializing exception text, paths, key material, or target output.
        code = str(exc)
        if re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", code) is None:
            code = "N7_TARGETD_HOST_COMPOSITION_BLOCKED"
        _emit_error(stdout, code)
        return 2
    finally:
        if runtime is not None:
            finalized = bool(
                close_aware is not None
                and close_aware.close_seen
                and runtime.finalize_delivered
            )
            try:
                runtime.close(finalized=finalized)
            except Exception:
                # A post-receipt cleanup failure must make the pinned host
                # process exit non-zero.  The controller therefore cannot
                # mistake an authenticated cleanup authorization for actual
                # stage removal.  Unfinalized recovery remains best-effort
                # and deliberately preserves the stage for reconciliation.
                if finalized:
                    return 3


if __name__ == "__main__":
    raise SystemExit(main())
