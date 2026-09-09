from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4


@contextmanager
def interprocess_lock(
    target: Path,
    *,
    timeout_s: float = 10.0,
    stale_after_s: float | None = 120.0,
) -> Iterator[None]:
    """Serialize writers with a bounded sibling lock file.

    ``stale_after_s=None`` is the fail-closed mode for critical sections that
    may call a slow external authority.  In that mode an operator must recover
    a crashed owner's lock; no waiter can guess liveness from file mtime and
    enter concurrently with a still-running owner.
    """
    target = target.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_id = hashlib.sha256(target.name.encode("utf-8")).hexdigest()[:8]
    lock_path = target.with_name(f".l{lock_id}")
    deadline = time.monotonic() + timeout_s
    descriptor: int | None = None
    owner_token = uuid4().hex
    owner_metadata: os.stat_result | None = None
    while descriptor is None:
        try:
            descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(
                descriptor,
                json.dumps(
                    {
                        "pid": os.getpid(),
                        "created_at": time.time(),
                        "owner_token": owner_token,
                    }
                ).encode("ascii"),
            )
            os.fsync(descriptor)
            owner_metadata = os.fstat(descriptor)
        except (FileExistsError, PermissionError) as exc:
            # Windows may report a sharing violation as PermissionError while another process
            # owns the lock file. The owner may remove it before exists()/stat(), so a missing
            # path is also retried within the same bounded deadline instead of being mistaken
            # for a permanent ACL failure.
            if isinstance(exc, PermissionError) and not lock_path.exists():
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"timed out waiting for artifact lock: {target}"
                    ) from None
                time.sleep(0.02)
                continue
            try:
                stale = (
                    stale_after_s is not None
                    and time.time() - lock_path.stat().st_mtime > stale_after_s
                )
            except FileNotFoundError:
                continue
            if stale:
                try:
                    lock_path.unlink()
                except FileNotFoundError:
                    pass
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"timed out waiting for artifact lock: {target}"
                ) from None
            time.sleep(0.02)
    try:
        yield
    finally:
        os.close(descriptor)
        try:
            path_metadata = os.stat(lock_path)
            payload = json.loads(lock_path.read_text(encoding="ascii"))
            if (
                owner_metadata is not None
                and (path_metadata.st_dev, path_metadata.st_ino)
                == (owner_metadata.st_dev, owner_metadata.st_ino)
                and payload.get("owner_token") == owner_token
            ):
                lock_path.unlink()
        except (FileNotFoundError, OSError, ValueError, TypeError, json.JSONDecodeError):
            pass


def atomic_write_text(
    path: Path,
    value: str,
    *,
    acquire_lock: bool = True,
    require_absent: bool = False,
) -> None:
    """Durably replace one file through a unique same-directory temporary."""
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    def write() -> None:
        if require_absent and path.exists():
            raise FileExistsError(path)
        # Keep the sibling name short enough for Windows MAX_PATH while retaining 48 bits of
        # per-write uniqueness. The exclusive create still detects the improbable collision.
        temporary = path.with_name(f".t{uuid4().hex[:12]}")
        try:
            with temporary.open("x", encoding="utf-8", newline="") as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            if os.name != "nt":
                directory = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)

    if acquire_lock:
        with interprocess_lock(path):
            write()
    else:
        write()


def append_text_record(path: Path, record: str) -> None:
    """Append exactly one durable record without cross-process interleaving."""
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with interprocess_lock(path):
        with path.open("a", encoding="utf-8", newline="") as stream:
            stream.write(record)
            stream.flush()
            os.fsync(stream.fileno())
