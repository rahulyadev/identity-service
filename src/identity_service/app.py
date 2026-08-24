"""FastAPI application factory and database-engine lifecycle."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

import httpx2
from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response

from identity_service.api.middleware import OperationalMiddleware, get_request_id
from identity_service.api.problems import (
    PublicProblemError,
    public_problem_response,
    status_problem,
)
from identity_service.api.profile import router as profile_router
from identity_service.api.routes import router
from identity_service.config import Settings
from identity_service.db import build_engine, build_session_factory
from identity_service.observability import Metrics, configure_logging
from identity_service.security import (
    AccessTokenVerifier,
    CognitoUserInfoClient,
    JwksCache,
    UpstreamHttpClient,
)
from identity_service.services import IdentityProfileService


def create_app(
    settings: Settings | None = None,
    *,
    upstream_transport: httpx2.BaseTransport | None = None,
    jwks_monotonic_clock: Callable[[], float] | None = None,
) -> FastAPI:
    resolved = settings or Settings()
    configure_logging(resolved)
    metrics = Metrics()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = build_engine(resolved)
        upstream_client = UpstreamHttpClient(resolved, transport=upstream_transport)
        jwks_options = (
            {"monotonic": jwks_monotonic_clock} if jwks_monotonic_clock is not None else {}
        )
        jwks_cache = JwksCache(resolved, upstream_client, metrics=metrics, **jwks_options)
        app.state.engine = engine
        app.state.session_factory = build_session_factory(engine)
        app.state.identity_profile_service = IdentityProfileService(
            app.state.session_factory, metrics=metrics
        )
        app.state.upstream_http_client = upstream_client
        app.state.jwks_cache = jwks_cache
        app.state.access_token_verifier = AccessTokenVerifier(resolved, jwks_cache, metrics=metrics)
        app.state.userinfo_client = CognitoUserInfoClient(
            resolved, upstream_client, metrics=metrics
        )
        try:
            yield
        finally:
            jwks_cache.close()
            try:
                upstream_client.close()
            finally:
                engine.dispose(close=True)

    docs_url = "/docs" if resolved.enable_interactive_docs else None
    redoc_url = "/redoc" if resolved.enable_interactive_docs else None
    app = FastAPI(
        title="identity-service",
        summary="Authenticated identity profile service",
        description=(
            "The service exposes operational endpoints and an authenticated v1 profile API. "
            "Browser login, sessions, and direct browser integration remain outside this service."
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
    app.include_router(profile_router)

    @app.exception_handler(PublicProblemError)
    async def public_problem_handler(request: Request, error: PublicProblemError) -> Response:
        return public_problem_response(error, get_request_id(request.scope))

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
