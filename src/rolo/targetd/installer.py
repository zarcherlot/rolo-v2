"""Ordinary SSH installer for the targetd Python package."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

from rolo.targets.executor import SshTargetExecutor


class TargetdInstaller:
    def __init__(self, executor: SshTargetExecutor, *, package_root: Path) -> None:
        self.executor = executor
        self.package_root = package_root.resolve()

    def build_archive(self) -> bytes:
        """Build a deterministic source archive containing the complete rolo package."""
        source_root = self.package_root / "rolo"
        if not source_root.is_dir():
            raise ValueError(f"Rolo source package is missing: {source_root}")
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            for path in sorted(source_root.rglob("*.py")):
                archive.add(path, arcname=str(Path("rolo") / path.relative_to(source_root)))
        return output.getvalue()

    def install(self, remote_root: str) -> str:
        if not remote_root.startswith("/") or any(c in remote_root for c in "\x00\r\n"):
            raise ValueError("targetd install root must be an absolute safe path")
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
