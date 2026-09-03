"""Robot-local runtime commands.

``serve`` is the single HTTP listener used by the Workbench and API.  The
command imports the ASGI app directly; it does not create an HTTP self-proxy.
"""

from __future__ import annotations

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
) -> None:
    """Run the one in-process rolo API listener."""
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise typer.BadParameter("runtime serve only supports loopback binding")
    import uvicorn

    uvicorn.run("rolo.api:app", host=host, port=port, log_level=log_level)


__all__ = ["runtime_app", "runtime_health", "runtime_serve"]
