"""FastAPI application factory and database-engine lifecycle."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response

from identity_service.api.middleware import OperationalMiddleware, get_request_id
from identity_service.api.problems import status_problem
from identity_service.api.routes import router
from identity_service.config import Settings
from identity_service.db import build_engine, build_session_factory
from identity_service.observability import Metrics, configure_logging


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or Settings()
    configure_logging(resolved)
    metrics = Metrics()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = build_engine(resolved)
        app.state.engine = engine
        app.state.session_factory = build_session_factory(engine)
        try:
            yield
        finally:
            engine.dispose(close=True)

    docs_url = "/docs" if resolved.enable_interactive_docs else None
    redoc_url = "/redoc" if resolved.enable_interactive_docs else None
    app = FastAPI(
        title="identity-service",
        summary="Operational foundation for internal identity data",
        description=(
            "The service currently exposes operational endpoints only. It does not provide "
            "authentication or profile HTTP endpoints."
        ),
        version=resolved.service_version,
        docs_url=docs_url,
        redoc_url=redoc_url,
        swagger_ui_oauth2_redirect_url=None,
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    app.state.settings = resolved
    app.state.metrics = metrics
    app.add_middleware(OperationalMiddleware, settings=resolved, metrics=metrics)
    app.include_router(router if resolved.metrics_enabled else _router_without_metrics())

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, error: StarletteHTTPException) -> Response:
        return status_problem(
            error.status_code,
            get_request_id(request.scope),
            headers=error.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, error: RequestValidationError
    ) -> Response:
        del error
        return status_problem(422, get_request_id(request.scope))

    @app.exception_handler(Exception)
    async def unexpected_exception_handler(request: Request, error: Exception) -> Response:
        logging.getLogger("identity_service.http").error(
            "unexpected_application_error",
            extra={
                "service": "identity-service",
                "service_version": resolved.service_version,
                "environment": resolved.app_env.value,
                "request_id": get_request_id(request.scope),
                "outcome": "error",
                "error_code": "internal_error",
                "error_type": type(error).__name__,
            },
        )
        return status_problem(500, get_request_id(request.scope))

    return app


def _router_without_metrics() -> APIRouter:
    filtered = APIRouter()
    for route in router.routes:
        if getattr(route, "path", None) != "/metrics":
            filtered.routes.append(route)
    return filtered
