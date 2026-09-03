"""HTTP adapter exposing the MHS evidence facade as read-only endpoints."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException

from .mhs_api import MhsEvidenceReadApi


def create_mhs_app(api: MhsEvidenceReadApi | None = None) -> FastAPI:
    """Create a minimal app with GET-only target evidence routes."""

    store = api or MhsEvidenceReadApi()
    app = FastAPI(title="Rolo MHS read-only API", version="1")

    @app.get("/v1/mhs/{target_fingerprint}/evidence")
    def get_evidence(target_fingerprint: str) -> dict:
        view = store.get(target_fingerprint)
        if view is None:
            raise HTTPException(status_code=404, detail="MHS evidence not found")
        return view.model_dump(mode="json")

    @app.get("/v1/mhs/targets")
    def list_targets() -> dict:
        return {"targets": store.list_targets(), "access": "READ_ONLY", "write_operations": 0}

    return app


__all__ = ["create_mhs_app"]
