"""Internal Cognito access-token and UserInfo security core."""

from identity_service.security.bearer import parse_bearer_authorization
from identity_service.security.contracts import VerifiedAccessToken
from identity_service.security.errors import (
    InsufficientScopeError,
    InvalidBearerSyntaxError,
    InvalidTokenError,
    TokenVerificationUnavailableError,
    UserInfoResponseError,
    UserInfoTokenRejectedError,
    UserInfoUnavailableError,
)
from identity_service.security.http import UpstreamHttpClient
from identity_service.security.jwks import JwksCache
from identity_service.security.tokens import AccessTokenVerifier
from identity_service.security.userinfo import CognitoUserInfoClient

__all__ = [
    "AccessTokenVerifier",
    "CognitoUserInfoClient",
    "InsufficientScopeError",
    "InvalidBearerSyntaxError",
    "InvalidTokenError",
    "JwksCache",
    "TokenVerificationUnavailableError",
    "UpstreamHttpClient",
    "UserInfoResponseError",
    "UserInfoTokenRejectedError",
    "UserInfoUnavailableError",
    "VerifiedAccessToken",
    "parse_bearer_authorization",
]
