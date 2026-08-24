"""Typed, redaction-safe security-domain failures."""

from __future__ import annotations


class SecurityCoreError(Exception):
    """Base class whose messages never contain token or provider input."""


class InvalidBearerSyntaxError(SecurityCoreError):
    """The future Authorization header does not contain one strict bearer token."""


class InvalidTokenError(SecurityCoreError):
    """A token is malformed or fails a cryptographic or claim requirement."""

    def __init__(self, outcome: str = "malformed") -> None:
        super().__init__("access token is invalid")
        self.outcome = outcome


class InsufficientScopeError(SecurityCoreError):
    """A valid access token lacks a caller-required scope."""


class TokenVerificationUnavailableError(SecurityCoreError):
    """Token verification cannot safely complete because key material is unavailable."""


class UserInfoTokenRejectedError(SecurityCoreError):
    """Cognito UserInfo rejected the supplied access token."""


class UserInfoUnavailableError(SecurityCoreError):
    """Cognito UserInfo is temporarily unavailable."""

    def __init__(self, *, retry_after_seconds: int | None = None) -> None:
        super().__init__("UserInfo dependency is unavailable")
        self.retry_after_seconds = retry_after_seconds


class UserInfoResponseError(SecurityCoreError):
    """Cognito UserInfo returned an unsafe or inconsistent provider response."""


class JwksResponseError(SecurityCoreError):
    """The JWKS endpoint returned an unusable response."""


class UpstreamTimeoutError(SecurityCoreError):
    """A bounded upstream request timed out."""


class UpstreamNetworkError(SecurityCoreError):
    """A bounded upstream request failed at the transport layer."""


class UpstreamResponseTooLargeError(SecurityCoreError):
    """An upstream response crossed the streaming byte limit."""
