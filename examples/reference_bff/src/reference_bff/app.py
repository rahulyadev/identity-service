"""Application factory for the reference BFF callback/session slice."""

from __future__ import annotations

import logging
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from urllib.parse import urlencode

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, RedirectResponse, Response

from reference_bff.callback import (
    OAUTH_BINDING_COOKIE_NAME,
    CallbackDenied,
    InvalidCallbackQueryError,
    InvalidOAuthBrowserBindingError,
    parse_callback_query,
    parse_oauth_browser_binding,
)
from reference_bff.config import Settings
from reference_bff.exchange import AuthorizationCodeClient
from reference_bff.flow import CallbackCompleter, CallbackFlow, CallbackFlowError
from reference_bff.http import AsyncUpstreamClient
from reference_bff.identity import IdentityBootstrapClient, IdentityProfileClient
from reference_bff.jwks import AsyncJwksCache
from reference_bff.logging import configure_logging
from reference_bff.middleware import SecurityBoundaryMiddleware, get_request_id
from reference_bff.problems import PublicProblemError, problem_response
from reference_bff.return_targets import InvalidReturnTargetError, return_target_from_query
from reference_bff.session_flow import (
    SessionFlow,
    SessionReader,
    SessionReadError,
    SessionReadResult,
)
from reference_bff.sessions import (
    SESSION_COOKIE_NAME,
    InvalidSessionCookieError,
    parse_session_cookie,
)
from reference_bff.store import (
    RedisTransactionStore,
    TransactionStore,
    TransactionStoreUnavailableError,
)
from reference_bff.tokens import CognitoTokenVerifier
from reference_bff.transactions import ExpiredTransactionError, MalformedTransactionError


def _set_oauth_binding_cookie(response: Response, transaction_id: str, *, max_age: int) -> None:
    response.set_cookie(
        OAUTH_BINDING_COOKIE_NAME,
        transaction_id,
        max_age=max_age,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )


def _clear_oauth_binding_cookie(response: Response) -> None:
    response.delete_cookie(
        OAUTH_BINDING_COOKIE_NAME,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )


def _set_session_cookie(response: Response, session_id: str, *, max_age: int) -> None:
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_id,
        max_age=max_age,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )


class _InjectedCallbackSessionReader:
    """Keep legacy injected callback tests isolated from a real upstream session stack."""

    async def read(self, session_id: str) -> SessionReadResult:
        del session_id
        raise SessionReadError(503, "session_unavailable", False)

    async def ready(self) -> bool:
        return True

    async def close(self) -> None:
        return


async def _require_empty_safe_read(request: Request) -> None:
    headers = list(request.scope.get("headers", []))
    if request.scope.get("query_string", b"") or any(
        name.lower() in {b"authorization", b"transfer-encoding"} for name, _ in headers
    ):
        raise PublicProblemError(400, "bad_request")
    content_lengths = [value for name, value in headers if name.lower() == b"content-length"]
    if len(content_lengths) > 1 or (content_lengths and content_lengths[0] != b"0"):
        raise PublicProblemError(400, "bad_request")
    async for chunk in request.stream():
        if chunk:
            raise PublicProblemError(400, "bad_request")


def create_app(
    settings: Settings | None = None,
    *,
    transaction_store: TransactionStore | None = None,
    callback_service: CallbackCompleter | None = None,
    session_reader: SessionReader | None = None,
) -> FastAPI:
    resolved = settings or Settings()
    configure_logging(resolved)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        store = transaction_store or RedisTransactionStore.from_settings(resolved)
        if callback_service is None:
            upstream = AsyncUpstreamClient(resolved)
            jwks = AsyncJwksCache(resolved, upstream)
            service: CallbackCompleter = CallbackFlow(
                settings=resolved,
                upstream=upstream,
                jwks=jwks,
                exchange=AuthorizationCodeClient(resolved, upstream),
                verifier=CognitoTokenVerifier(resolved, jwks),
                identity=IdentityBootstrapClient(resolved, upstream),
                store=store,
            )
        else:
            service = callback_service
        if session_reader is not None:
            profile_reader = session_reader
        elif callback_service is not None:
            profile_reader = _InjectedCallbackSessionReader()
        else:
            session_upstream = AsyncUpstreamClient(resolved)
            session_jwks = AsyncJwksCache(resolved, session_upstream)
            session_verifier = CognitoTokenVerifier(resolved, session_jwks)
            profile_reader = SessionFlow(
                settings=resolved,
                upstream=session_upstream,
                jwks=session_jwks,
                refresh=AuthorizationCodeClient(resolved, session_upstream),
                verifier=session_verifier,
                identity=IdentityProfileClient(resolved, session_upstream),
                store=store,
            )
        app.state.transaction_store = store
        app.state.callback_service = service
        app.state.session_reader = profile_reader
        try:
            yield
        finally:
            try:
                await profile_reader.close()
            finally:
                try:
                    await service.close()
                finally:
                    await store.close()

    docs_url = "/docs" if resolved.enable_interactive_docs else None
    app = FastAPI(
        title="reference-bff",
        version=resolved.service_version,
        redirect_slashes=False,
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
        service: CallbackCompleter = request.app.state.callback_service
        profile_reader: SessionReader = request.app.state.session_reader
        if not await store.ready() or not await service.ready() or not await profile_reader.ready():
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
                ("resource", resolved.oauth_resource),
                ("state", transaction.state),
                ("nonce", transaction.nonce),
                ("code_challenge", transaction.code_challenge),
                ("code_challenge_method", "S256"),
            )
        )
        logging.getLogger("reference_bff.http").info("authorization_transaction_created")
        response = RedirectResponse(f"{resolved.authorization_endpoint}?{query}", status_code=307)
        _set_oauth_binding_cookie(
            response,
            transaction.transaction_id,
            max_age=resolved.oauth_transaction_ttl_seconds,
        )
        return response

    @app.get("/auth/callback", include_in_schema=False)
    async def callback(request: Request) -> Response:
        try:
            callback_query = parse_callback_query(
                request.scope.get("query_string", b""),
                max_query_bytes=resolved.max_callback_query_bytes,
                max_code_bytes=resolved.max_oauth_code_bytes,
                max_error_bytes=resolved.max_provider_error_bytes,
            )
        except InvalidCallbackQueryError:
            raise PublicProblemError(400, "invalid_callback") from None
        store: TransactionStore = request.app.state.transaction_store
        try:
            transaction = await store.consume(callback_query.state)
        except TransactionStoreUnavailableError:
            raise PublicProblemError(503, "transaction_store_unavailable") from None
        except MalformedTransactionError, ExpiredTransactionError:
            raise PublicProblemError(400, "invalid_oauth_transaction") from None
        if transaction is None:
            raise PublicProblemError(400, "invalid_oauth_transaction")
        try:
            browser_binding = parse_oauth_browser_binding(request.scope.get("headers", []))
        except InvalidOAuthBrowserBindingError:
            raise PublicProblemError(400, "invalid_oauth_transaction") from None
        if not secrets.compare_digest(browser_binding.transaction_id, transaction.transaction_id):
            raise PublicProblemError(400, "invalid_oauth_transaction")
        if isinstance(callback_query, CallbackDenied):
            logging.getLogger("reference_bff.http").info("authorization_denied")
            denial_response = problem_response(
                400, "authorization_denied", get_request_id(request.scope)
            )
            _clear_oauth_binding_cookie(denial_response)
            return denial_response
        service: CallbackCompleter = request.app.state.callback_service
        try:
            session = await service.complete(callback_query.code, transaction)
        except CallbackFlowError as error:
            failure_response = problem_response(
                error.status, error.code, get_request_id(request.scope)
            )
            _clear_oauth_binding_cookie(failure_response)
            return failure_response
        redirect_response = RedirectResponse(transaction.return_to, status_code=303)
        _clear_oauth_binding_cookie(redirect_response)
        redirect_response.set_cookie(
            "__Host-session",
            session.session_id,
            max_age=session.max_age,
            path="/",
            secure=True,
            httponly=True,
            samesite="lax",
        )
        logging.getLogger("reference_bff.http").info("browser_session_created")
        return redirect_response

    @app.get("/api/me", include_in_schema=False)
    async def profile(request: Request) -> Response:
        await _require_empty_safe_read(request)
        try:
            session_id = parse_session_cookie(list(request.scope.get("headers", [])))
        except InvalidSessionCookieError:
            missing_response = problem_response(
                401, "session_required", get_request_id(request.scope)
            )
            _clear_session_cookie(missing_response)
            return missing_response
        profile_reader: SessionReader = request.app.state.session_reader
        try:
            result = await profile_reader.read(session_id)
        except SessionReadError as error:
            failure = problem_response(error.status, error.code, get_request_id(request.scope))
            if error.clear_cookie:
                _clear_session_cookie(failure)
            return failure
        response = JSONResponse(result.profile, headers={"ETag": result.etag})
        _set_session_cookie(response, session_id, max_age=result.max_age)
        return response

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
