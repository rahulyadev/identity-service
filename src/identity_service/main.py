"""ASGI module loaded by the single-process server."""

from identity_service.app import create_app

app = create_app()
