"""Authenticated v1 profile HTTP adapter."""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime
from typing import Annotated, Any, Never, cast

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import SQLAlchemyError

from identity_service.api.authentication import (
    AUTHENTICATION_FAILURE_CHALLENGE,
    INSUFFICIENT_SCOPE_CHALLENGE,
    AuthenticatedAccess,
    require_access_token,
)
from identity_service.api.problems import PROBLEM_MEDIA_TYPE, ProblemResponse, PublicProblemError
from identity_service.security import (
    InsufficientScopeError,
    UserInfoResponseError,
    UserInfoTokenRejectedError,
    UserInfoUnavailableError,
)
from identity_service.services import (
    IdentityNotFoundError,
    ProfileView,
    ProviderIdentityInput,
    ProviderProfileInput,
    UserUnavailableError,
    VersionConflictError,
)
from identity_service.services.validation import normalize_display_name_override

router = APIRouter(prefix="/v1", tags=["profile"])
IF_MATCH_PATTERN = re.compile(r'"v([1-9][0-9]*)"')
MAX_SIGNED_64_BIT = (1 << 63) - 1
CACHE_CONTROL_HEADER = {
    "description": "Always present with the fixed value `no-store` for profile responses.",
    "schema": {"type": "string", "const": "no-store", "example": "no-store"},
}
INVALID_TOKEN_CHALLENGE_HEADER = {
    "description": "Always present with the fixed bearer challenge for invalid tokens.",
    "schema": {
        "type": "string",
        "const": AUTHENTICATION_FAILURE_CHALLENGE,
        "example": AUTHENTICATION_FAILURE_CHALLENGE,
    },
}
INSUFFICIENT_SCOPE_CHALLENGE_HEADER = {
    "description": (
        "Present with the fixed insufficient-scope bearer challenge for scope failures; "
        "absent for `account_unavailable`."
    ),
    "schema": {
        "type": "string",
        "const": INSUFFICIENT_SCOPE_CHALLENGE,
        "example": INSUFFICIENT_SCOPE_CHALLENGE,
    },
}
RETRY_AFTER_HEADER = {
    "description": (
        "Optional. Present only when a validated UserInfo rate-limit response supplies a delay "
        "from 0 through 300 seconds; absent for every other 503 response."
    ),
    "schema": {
        "type": "string",
        "pattern": r"^(?:0|[1-9][0-9]?|[12][0-9]{2}|300)$",
        "example": "30",
    },
}
PROFILE_RESPONSE_HEADERS = {
    "ETag": {
        "description": 'Strong profile version validator in the form `"vN"`.',
        "schema": {"type": "string"},
    },
    "Cache-Control": CACHE_CONTROL_HEADER,
}


class ProfileResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    user_id: uuid.UUID
    email: str | None
    email_verified: bool
    display_name: str | None
    avatar_url: str | None
    version: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_view(cls, profile: ProfileView) -> ProfileResponse:
        return cls(
            user_id=profile.user_id,
            email=profile.provider_email,
            email_verified=profile.provider_email_verified,
            display_name=profile.effective_display_name,
            avatar_url=profile.provider_avatar_url,
            version=profile.version,
            created_at=profile.created_at,
            updated_at=profile.updated_at,
        )


def _problem_response(
    description: str, *, headers: dict[str, dict[str, Any]] | None = None
) -> dict[str, Any]:
    return {
        "description": description,
        "headers": {"Cache-Control": CACHE_CONTROL_HEADER, **(headers or {})},
        "content": {PROBLEM_MEDIA_TYPE: {"schema": ProblemResponse.model_json_schema()}},
    }


COMMON_AUTH_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: _problem_response(
        "Invalid access token",
        headers={"WWW-Authenticate": INVALID_TOKEN_CHALLENGE_HEADER},
    ),
    403: _problem_response(
        "Insufficient scope or unavailable local account",
        headers={"WWW-Authenticate": INSUFFICIENT_SCOPE_CHALLENGE_HEADER},
    ),
    503: _problem_response(
        "Authentication or profile dependency unavailable",
        headers={"Retry-After": RETRY_AFTER_HEADER},
    ),
}


def _header_values(request: Request, name: bytes) -> list[str]:
    return [
        value.decode("latin-1")
        for key, value in request.scope.get("headers", [])
        if key.lower() == name
    ]


def _buffered_body(request: Request) -> bytes:
    body = request.scope.get("identity_service.body")
    if not isinstance(body, bytes):
        raise RuntimeError("bounded request body is unavailable")
    return body


def _set_profile_headers(response: Response, profile: ProfileView) -> None:
    response.headers["ETag"] = f'"v{profile.version}"'
    response.headers["Cache-Control"] = "no-store"


def _raise_service_failure(error: Exception) -> Never:
    if isinstance(error, IdentityNotFoundError):
        raise PublicProblemError("identity_not_initialized") from None
    if isinstance(error, UserUnavailableError):
        raise PublicProblemError("account_unavailable") from None
    if isinstance(error, VersionConflictError):
        raise PublicProblemError("profile_version_conflict") from None
    if isinstance(error, SQLAlchemyError):
        raise PublicProblemError("database_unavailable") from None
    raise error


def _fetch_provider_profile(request: Request, access: AuthenticatedAccess) -> ProviderProfileInput:
    try:
        return cast(
            ProviderProfileInput,
            request.app.state.userinfo_client.fetch_userinfo(
                access.raw_access_token, access.verified
            ),
        )
    except UserInfoTokenRejectedError:
        raise PublicProblemError(
            "invalid_token",
            headers={"WWW-Authenticate": AUTHENTICATION_FAILURE_CHALLENGE},
        ) from None
    except InsufficientScopeError:
        raise PublicProblemError(
            "insufficient_scope",
            headers={"WWW-Authenticate": INSUFFICIENT_SCOPE_CHALLENGE},
        ) from None
    except UserInfoUnavailableError as error:
        headers = (
            {"Retry-After": str(error.retry_after_seconds)}
            if error.retry_after_seconds is not None
            else None
        )
        raise PublicProblemError("provider_unavailable", headers=headers) from None
    except UserInfoResponseError:
        raise PublicProblemError("provider_unavailable") from None


def _parse_if_match(request: Request) -> int:
    values = _header_values(request, b"if-match")
    if not values:
        raise PublicProblemError("precondition_required")
    if len(values) != 1:
        raise PublicProblemError("invalid_precondition")
    if len(values[0]) > 22:
        raise PublicProblemError("invalid_precondition")
    match = IF_MATCH_PATTERN.fullmatch(values[0])
    if match is None:
        raise PublicProblemError("invalid_precondition")
    version = int(match.group(1))
    if version > MAX_SIGNED_64_BIT:
        raise PublicProblemError("invalid_precondition")
    return version


def _validate_patch_media_type(request: Request) -> None:
    values = _header_values(request, b"content-type")
    if len(values) != 1:
        raise PublicProblemError("unsupported_media_type")
    media_type = values[0].partition(";")[0].strip().casefold()
    if media_type != "application/merge-patch+json":
        raise PublicProblemError("unsupported_media_type")


class _JsonObject(list[tuple[str, object]]):
    pass


def _reject_nonfinite_json(_value: str) -> None:
    raise ValueError("non-finite JSON is invalid")


def _parse_display_name_patch(request: Request) -> str | None:
    try:
        encoded = _buffered_body(request)
        document = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_JsonObject,
            parse_constant=_reject_nonfinite_json,
        )
    except UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError:
        raise PublicProblemError("validation_failed") from None
    if (
        not isinstance(document, _JsonObject)
        or len(document) != 1
        or document[0][0] != "display_name"
    ):
        raise PublicProblemError("validation_failed")
    value = document[0][1]
    if value is not None and not isinstance(value, str):
        raise PublicProblemError("validation_failed")
    try:
        if value is not None:
            value.encode("utf-8")
        return normalize_display_name_override(value)
    except UnicodeEncodeError, ValueError:
        raise PublicProblemError("validation_failed") from None


@router.put(
    "/me",
    operation_id="put_current_profile",
    response_model=ProfileResponse,
    responses={
        200: {"description": "Existing identity synchronized", "headers": PROFILE_RESPONSE_HEADERS},
        201: {
            "description": "Identity initialized",
            "model": ProfileResponse,
            "headers": PROFILE_RESPONSE_HEADERS,
        },
        400: _problem_response("A request body is not allowed"),
        **COMMON_AUTH_RESPONSES,
    },
    summary="Initialize or synchronize the authenticated profile",
)
def put_current_profile(
    request: Request,
    response: Response,
    access: Annotated[
        AuthenticatedAccess,
        Depends(
            require_access_token(
                "oauth_profile_write_scope",
                additional_scopes=("openid",),
            )
        ),
    ],
) -> ProfileResponse:
    if _buffered_body(request):
        raise PublicProblemError("request_body_not_allowed")
    provider_profile = _fetch_provider_profile(request, access)
    try:
        result = request.app.state.identity_profile_service.bootstrap_identity_result(
            ProviderIdentityInput(
                issuer=access.verified.issuer,
                subject=access.verified.subject,
                auth_time=access.verified.auth_time,
            ),
            provider_profile,
        )
    except (IdentityNotFoundError, UserUnavailableError, SQLAlchemyError) as error:
        _raise_service_failure(error)
    response.status_code = 201 if result.created else 200
    _set_profile_headers(response, result.profile)
    return ProfileResponse.from_view(result.profile)


@router.get(
    "/me",
    operation_id="get_current_profile",
    response_model=ProfileResponse,
    responses={
        200: {"description": "Current local profile", "headers": PROFILE_RESPONSE_HEADERS},
        404: _problem_response("The identity has not been initialized"),
        **COMMON_AUTH_RESPONSES,
    },
    summary="Read the authenticated local profile",
)
def get_current_profile(
    request: Request,
    response: Response,
    access: Annotated[
        AuthenticatedAccess,
        Depends(require_access_token("oauth_profile_read_scope")),
    ],
) -> ProfileResponse:
    try:
        profile = request.app.state.identity_profile_service.get_profile_for_identity(
            access.verified.issuer, access.verified.subject
        )
    except (IdentityNotFoundError, UserUnavailableError, SQLAlchemyError) as error:
        _raise_service_failure(error)
    _set_profile_headers(response, profile)
    return ProfileResponse.from_view(profile)


@router.patch(
    "/me",
    operation_id="patch_current_profile",
    response_model=ProfileResponse,
    responses={
        200: {"description": "Profile override updated", "headers": PROFILE_RESPONSE_HEADERS},
        400: _problem_response("The profile precondition is invalid"),
        404: _problem_response("The identity has not been initialized"),
        412: _problem_response("The profile version has changed"),
        415: _problem_response("The media type is unsupported"),
        422: _problem_response("The merge patch is invalid"),
        428: _problem_response("A profile version precondition is required"),
        **COMMON_AUTH_RESPONSES,
    },
    summary="Conditionally update the display-name override",
    openapi_extra={
        "parameters": [
            {
                "name": "If-Match",
                "in": "header",
                "required": True,
                "description": (
                    'One strong profile validator in the exact form `"vN"`, where `N` is a '
                    "positive signed-64-bit integer without leading zeros. Duplicate headers, "
                    "weak validators, wildcards, lists, padding, zero, negative, and oversized "
                    "values are rejected."
                ),
                "schema": {
                    "type": "string",
                    "pattern": '^"v[1-9][0-9]*"$',
                    "example": '"v1"',
                },
            }
        ],
        "requestBody": {
            "required": True,
            "content": {
                "application/merge-patch+json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "display_name": {
                                "anyOf": [
                                    {"type": "string", "maxLength": 100},
                                    {"type": "null"},
                                ]
                            }
                        },
                        "required": ["display_name"],
                        "additionalProperties": False,
                        "minProperties": 1,
                        "maxProperties": 1,
                    }
                }
            },
        },
    },
)
def patch_current_profile(
    request: Request,
    response: Response,
    access: Annotated[
        AuthenticatedAccess,
        Depends(require_access_token("oauth_profile_write_scope")),
    ],
) -> ProfileResponse:
    _validate_patch_media_type(request)
    expected_version = _parse_if_match(request)
    display_name = _parse_display_name_patch(request)
    service = request.app.state.identity_profile_service
    try:
        current = service.get_profile_for_identity(access.verified.issuer, access.verified.subject)
        profile = service.update_display_name(current.user_id, expected_version, display_name)
    except (
        IdentityNotFoundError,
        UserUnavailableError,
        VersionConflictError,
        SQLAlchemyError,
    ) as error:
        _raise_service_failure(error)
    _set_profile_headers(response, profile)
    return ProfileResponse.from_view(profile)
