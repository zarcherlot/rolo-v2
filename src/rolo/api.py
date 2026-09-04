"""Compatibility ASGI module for the Rolo HTTP service.

Deployment scripts historically refer to ``rolo.api:app``.  Keep that stable
while the implementation lives in :mod:`rolo.http_server`.
"""

from .http_server import app, create_app

__all__ = ["app", "create_app"]
