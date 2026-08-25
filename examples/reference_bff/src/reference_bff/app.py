"""Application factory for the reference BFF transaction foundation."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from urllib.parse import urlencode

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, RedirectResponse, Response

from reference_bff.config import Settings
from reference_bff.logging import configure_logging
from reference_bff.middleware import SecurityBoundaryMiddleware, get_request_id
from reference_bff.problems import PublicProblemError, problem_response
from reference_bff.return_targets import InvalidReturnTargetError, return_target_from_query
from reference_bff.store import (
    RedisTransactionStore,
    TransactionStore,
    TransactionStoreUnavailableError,
)


def create_app(
    settings: Settings | None = None, *, transaction_store: TransactionStore | None = None
) -> FastAPI:
    resolved = settings or Settings()
    configure_logging(resolved)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        store = transaction_store or RedisTransactionStore.from_settings(resolved)
        app.state.transaction_store = store
        try:
            yield
        finally:
            await store.close()

    docs_url = "/docs" if resolved.enable_interactive_docs else None
    app = FastAPI(
        title="reference-bff",
        version=resolved.service_version,
        docs_url=docs_url,
        redoc_url=None,
        openapi_url="/openapi.json" if resolved.enable_interactive_docs else None,
        swagger_ui_oauth2_redirect_url=None,
        lifespan=lifespan,
    )
    app.state.settings = resolved
    app.add_middleware(SecurityBoundaryMiddleware, allowed_hosts=resolved.allowed_hosts)

    @app.get("/health/live", include_in_schema=False)
    async def liveness() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/health/ready", include_in_schema=False)
    async def readiness(request: Request) -> Response:
        store: TransactionStore = request.app.state.transaction_store
        if not await store.ready():
            return problem_response(
                503, "transaction_store_unavailable", get_request_id(request.scope)
            )
        return JSONResponse({"status": "ready"})

    @app.get("/auth/login", include_in_schema=False)
    async def login(request: Request) -> Response:
        try:
            return_to = return_target_from_query(
                request.scope.get("query_string", b""), max_bytes=resolved.max_return_to_bytes
            )
        except InvalidReturnTargetError:
            raise PublicProblemError(400, "invalid_return_target") from None
        store: TransactionStore = request.app.state.transaction_store
        try:
            transaction = await store.create(return_to)
        except TransactionStoreUnavailableError:
            logging.getLogger("reference_bff.http").warning("transaction_store_unavailable")
            raise PublicProblemError(503, "transaction_store_unavailable") from None
        query = urlencode(
            (
                ("response_type", "code"),
                ("client_id", resolved.client_id),
                ("redirect_uri", resolved.callback_uri),
                ("scope", " ".join(resolved.requested_scopes)),
                ("state", transaction.state),
                ("nonce", transaction.nonce),
                ("code_challenge", transaction.code_challenge),
                ("code_challenge_method", "S256"),
            )
        )
        logging.getLogger("reference_bff.http").info("authorization_transaction_created")
        return RedirectResponse(f"{resolved.authorization_endpoint}?{query}", status_code=307)

    @app.exception_handler(PublicProblemError)
    async def public_problem_handler(request: Request, error: PublicProblemError) -> Response:
        return problem_response(error.status, error.code, get_request_id(request.scope))

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, error: StarletteHTTPException) -> Response:
        status = error.status_code if error.status_code in {400, 404, 405} else 500
        code = {400: "bad_request", 404: "not_found", 405: "method_not_allowed"}.get(
            status, "internal_error"
        )
        return problem_response(status, code, get_request_id(request.scope))

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, error: RequestValidationError) -> Response:
        del error
        return problem_response(400, "bad_request", get_request_id(request.scope))

    @app.exception_handler(Exception)
    async def unexpected_handler(request: Request, error: Exception) -> Response:
        logging.getLogger("reference_bff.http").error(
            "unexpected_application_error:%s", type(error).__name__
        )
        return problem_response(500, "internal_error", get_request_id(request.scope))

    return app
