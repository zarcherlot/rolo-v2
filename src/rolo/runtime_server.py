"""Robot-local single-listener runtime for API and optional Workbench assets."""

from __future__ import annotations

import os
from pathlib import Path


def serve(
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    workbench_dir: Path | None = None,
    rkb_root: Path | None = None,
    artifact_root: Path | None = None,
) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("v2 runtime serve only permits loopback bind addresses")
    for name, value in (
        ("ROLO_WORKBENCH_DIR", workbench_dir),
        ("ROLO_RKB_ROOT", rkb_root),
        ("ROLO_ARTIFACT_ROOT", artifact_root),
    ):
        if value is None:
            continue
        if value.is_symlink() or not value.is_dir():
            raise ValueError(f"{name} path must be a real directory")
        os.environ[name] = str(value.resolve())
    import uvicorn

    from .api import app, configure_workbench_mount

    configure_workbench_mount(workbench_dir)
    uvicorn.run(app, host=host, port=port, access_log=False, log_level="info")
