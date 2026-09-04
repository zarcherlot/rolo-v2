"""Rolo's production HTTP server entrypoint.

The server intentionally embeds the same validated, GET-only MHS router used
by the standalone adapter.  Keeping one route definition prevents the
read-only contract from drifting between development and the service entry
point.
"""

from __future__ import annotations

import uvicorn
from fastapi import FastAPI

from .rkb.mhs_api import MhsEvidenceReadApi
from .rkb.mhs_http import create_mhs_router


def create_app(api: MhsEvidenceReadApi | None = None) -> FastAPI:
    """Build the Rolo HTTP application with the MHS read-only surface."""

    app = FastAPI(title="Rolo HTTP server", version="1")
    app.include_router(create_mhs_router(api))
    return app


app = create_app()


def run() -> None:
    """Run the service with a conservative local-only default bind."""

    uvicorn.run("rolo.http_server:app", host="127.0.0.1", port=8000, log_level="info")


__all__ = ["app", "create_app", "run"]
