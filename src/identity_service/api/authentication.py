"""Strict HTTP bearer authentication dependencies for profile routes."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from identity_service.api.problems import PublicProblemError
from identity_service.security import (
    InsufficientScopeError,
    InvalidBearerSyntaxError,
    InvalidTokenError,
    TokenVerificationUnavailableError,
    VerifiedAccessToken,
    parse_bearer_authorization,
)

AUTHENTICATION_FAILURE_CHALLENGE = 'Bearer realm="identity", error="invalid_token"'
INSUFFICIENT_SCOPE_CHALLENGE = 'Bearer realm="identity", error="insufficient_scope"'
BEARER_SCHEME = HTTPBearer(
    auto_error=False,
    bearerFormat="JWT",
    scheme_name="BearerAuth",
    description="Cognito access token for the identity-service resource server.",
)


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticatedAccess:
    raw_access_token: str
    verified: VerifiedAccessToken

    def __repr__(self) -> str:
        return "AuthenticatedAccess(<redacted>)"

    def __str__(self) -> str:
        return "AuthenticatedAccess(<redacted>)"


def _authorization_values(request: Request) -> list[str]:
    return [
        value.decode("latin-1")
        for name, value in request.scope.get("headers", [])
        if name.lower() == b"authorization"
    ]


def require_access_token(
    *scope_setting_names: str,
    additional_scopes: tuple[str, ...] = (),
) -> Callable[..., AuthenticatedAccess]:
    """Build a dependency that documents bearer auth and enforces configured scopes."""

    def authenticate(
        request: Request,
        documented_credential: Annotated[
            HTTPAuthorizationCredentials | None, Security(BEARER_SCHEME)
        ],
    ) -> AuthenticatedAccess:
        del documented_credential
        settings = request.app.state.settings
        try:
            raw_token = parse_bearer_authorization(
                _authorization_values(request),
                max_token_bytes=settings.jwt_max_token_bytes,
            )
            required_scopes = [getattr(settings, name) for name in scope_setting_names]
            required_scopes.extend(additional_scopes)
            verified = request.app.state.access_token_verifier.verify_access_token(
                raw_token, required_scopes
            )
        except InvalidBearerSyntaxError, InvalidTokenError:
            raise PublicProblemError(
                "invalid_token",
                headers={"WWW-Authenticate": AUTHENTICATION_FAILURE_CHALLENGE},
            ) from None
        except InsufficientScopeError:
            raise PublicProblemError(
                "insufficient_scope",
                headers={"WWW-Authenticate": INSUFFICIENT_SCOPE_CHALLENGE},
            ) from None
        except TokenVerificationUnavailableError:
            raise PublicProblemError("authentication_unavailable") from None
        return AuthenticatedAccess(raw_token, verified)

    return authenticate
