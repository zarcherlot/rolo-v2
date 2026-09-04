"""HTTP adapter exposing the MHS evidence facade as read-only endpoints."""

from __future__ import annotations

from fastapi import APIRouter, FastAPI, HTTPException

from .mhs_api import MhsEvidenceReadApi
from .mhs_vis import render_probe_evidence_cards


def create_mhs_router(api: MhsEvidenceReadApi | None = None) -> APIRouter:
    """Create the GET-only MHS routes for embedding in an HTTP server."""

    store = api or MhsEvidenceReadApi()
    router = APIRouter()

    @router.get("/v1/mhs/{target_fingerprint}/evidence")
    def get_evidence(target_fingerprint: str) -> dict:
        view = store.get(target_fingerprint)
        if view is None:
            raise HTTPException(status_code=404, detail="MHS evidence not found")
        return view.model_dump(mode="json")

    @router.get("/v1/mhs/{target_fingerprint}/cards")
    def get_cards(target_fingerprint: str) -> dict:
        view = store.get(target_fingerprint)
        if view is None:
            raise HTTPException(status_code=404, detail="MHS evidence not found")
        return render_probe_evidence_cards(view)

    @router.get("/v1/mhs/targets")
    def list_targets() -> dict:
        return {"targets": store.list_targets(), "access": "READ_ONLY", "write_operations": 0}

    return router


def create_mhs_app(api: MhsEvidenceReadApi | None = None) -> FastAPI:
    """Create a minimal app with GET-only target evidence routes."""

    app = FastAPI(title="Rolo MHS read-only API", version="1")
    app.include_router(create_mhs_router(api))
    return app


__all__ = ["create_mhs_app", "create_mhs_router"]
