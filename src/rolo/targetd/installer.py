"""Ordinary SSH installer for the targetd Python package."""

from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path
from typing import Literal

from pydantic import Field

from rolo.dsl.models import StrictModel
from rolo.targets.executor import SshTargetExecutor

MAPPING_RUNTIME_SOURCE = "landerpi_autonomous_mapping_runtime.py"


class TargetdInstallManifest(StrictModel):
    """Digest and version record embedded in every targetd installation."""

    schema_version: Literal["rolo-targetd-install-manifest/v1"] = "rolo-targetd-install-manifest/v1"
    package_version: str = Field(min_length=1, max_length=64)
    archive_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    files: tuple[str, ...] = Field(min_length=1, max_length=4096)


class TargetdInstaller:
    def __init__(self, executor: SshTargetExecutor, *, package_root: Path, package_version: str = "rolo-targetd/v1") -> None:
        self.executor = executor
        self.package_root = package_root.resolve()
        if not package_version or any(character in package_version for character in "\x00\r\n"):
            raise ValueError("targetd package version must be non-empty and single-line")
        self.package_version = package_version

    def build_archive(self) -> bytes:
        """Build a deterministic source archive containing the complete rolo package."""
        entries = self._archive_entries()
        source_digest = self._source_digest(entries)
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            for path, arcname in entries:
                info = archive.gettarinfo(str(path), arcname=arcname)
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                with path.open("rb") as source:
                    archive.addfile(info, source)
            manifest = TargetdInstallManifest(
                package_version=self.package_version,
                archive_sha256=source_digest,
                files=tuple(arcname for _, arcname in entries),
            )
            encoded = manifest.model_dump_json().encode("utf-8")
            info = tarfile.TarInfo("rolo/INSTALL-MANIFEST.json")
            info.size = len(encoded)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(encoded))
        return output.getvalue()

    def manifest(self) -> TargetdInstallManifest:
        """Return the local source manifest without contacting a target."""
        entries = self._archive_entries()
        return TargetdInstallManifest(
            package_version=self.package_version,
            archive_sha256=self._source_digest(entries),
            files=tuple(arcname for _, arcname in entries),
        )

    @staticmethod
    def _source_digest(entries: list[tuple[Path, str]]) -> str:
        digest = hashlib.sha256()
        for path, arcname in entries:
            relative = arcname.replace("\\", "/").encode("utf-8")
            content = path.read_bytes()
            digest.update(len(relative).to_bytes(4, "big"))
            digest.update(relative)
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
        return digest.hexdigest()

    def _archive_entries(self) -> list[tuple[Path, str]]:
        """Return deterministic package files plus the reviewed mapping runtime.

        ``targetd`` is installed as a source tree rather than a wheel.  The
        mapping provider source intentionally lives in ``scripts/`` because it
        is a target-only debug runtime, so it would otherwise be omitted from
        the archive and unavailable after an SSH install.  Put it next to the
        worker under the package namespace on the target.  Small fixture trees
        used by installer tests (and downstream callers) do not have a
        ``scripts/`` sibling, in which case the ordinary package-only archive
        remains unchanged.
        """
        source_root = self.package_root / "rolo"
        if not source_root.is_dir():
            raise ValueError(f"Rolo source package is missing: {source_root}")

        entries = [
            (
                path,
                str(Path("rolo") / path.relative_to(source_root)).replace("\\", "/"),
            )
            for path in sorted(source_root.rglob("*.py"))
        ]
        arcname = f"rolo/targetd/{MAPPING_RUNTIME_SOURCE}"
        runtime = self.package_root.parent / "scripts" / MAPPING_RUNTIME_SOURCE
        if runtime.is_file() and all(existing_arcname != arcname for _, existing_arcname in entries):
            entries.append((runtime, arcname))
        entries.sort(key=lambda item: item[1])
        return entries

    @staticmethod
    def _validate_remote_root(remote_root: str) -> None:
        if not remote_root.startswith("/") or remote_root == "/" or any(c in remote_root for c in "\x00\r\n"):
            raise ValueError("targetd install root must be an absolute non-root safe path")

    def install(self, remote_root: str) -> str:
        self._validate_remote_root(remote_root)
        archive = self.build_archive()
        result = self.executor.stream_stdin(
            ["mkdir", "-p", remote_root], b""
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr or "targetd install directory creation failed")
        result = self.executor.stream_stdin(
            ["tar", "-xf", "-", "-C", remote_root], archive
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr or "targetd package installation failed")
        return remote_root

    def upgrade(self, remote_root: str) -> str:
        """Install the exact local archive again; extraction is idempotent by file."""
        return self.install(remote_root)

    def uninstall(self, remote_root: str, *, confirm: bool = False) -> str:
        """Remove a dedicated targetd root only when the caller explicitly confirms."""
        self._validate_remote_root(remote_root)
        if not confirm:
            raise ValueError("targetd uninstall requires explicit confirmation")
        result = self.executor.stream_stdin(["rm", "-rf", "--", remote_root], b"")
        if result.returncode != 0:
            raise RuntimeError(result.stderr or "targetd package uninstall failed")
        return remote_root


__all__ = ["TargetdInstallManifest", "TargetdInstaller"]
