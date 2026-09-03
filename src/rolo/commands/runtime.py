"""Robot-local runtime commands.

``serve`` is the single HTTP listener used by the Workbench and API.  The
command imports the ASGI app directly; it does not create an HTTP self-proxy.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from rolo.api import health
from rolo.commands.common import emit

runtime_app = typer.Typer(help="Serve and inspect the robot-local rolo runtime.")


@runtime_app.command("health")
def runtime_health() -> None:
    """Print the current read-model health without starting a listener."""
    emit(health())


@runtime_app.command("serve")
def runtime_serve(
    host: Annotated[
        str, typer.Option("--host", help="Bind address; loopback is the default.")
    ] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", min=1, max=65535)] = 8765,
    log_level: Annotated[str, typer.Option("--log-level")] = "info",
    workbench_dir: Annotated[Path | None, typer.Option("--workbench-dir")] = None,
    rkb_root: Annotated[Path | None, typer.Option("--rkb-root")] = None,
    artifact_root: Annotated[Path | None, typer.Option("--artifact-root")] = None,
) -> None:
    """Run the one in-process rolo API listener."""
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise typer.BadParameter("runtime serve only supports loopback binding")
    del log_level
    from rolo.runtime_server import serve

    try:
        serve(
            host=host,
            port=port,
            workbench_dir=workbench_dir,
            rkb_root=rkb_root,
            artifact_root=artifact_root,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


__all__ = ["runtime_app", "runtime_health", "runtime_serve"]
