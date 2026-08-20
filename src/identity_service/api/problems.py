"""Safe RFC 9457-style problem responses."""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict
from starlette.responses import JSONResponse

PROBLEM_MEDIA_TYPE = "application/problem+json"
SAFE_EXCEPTION_HEADERS = frozenset({"allow", "retry-after", "www-authenticate"})


class ProblemResponse(BaseModel):
    """Public schema for the service's bounded RFC 9457-style response body."""

    model_config = ConfigDict(frozen=True)

    type: str
    title: str
    status: int
    detail: str
    request_id: str
    code: str


def problem_response(
    *,
    status: int,
    title: str,
    detail: str,
    request_id: str,
    code: str,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    safe_headers = {
        name: value
        for name, value in (headers or {}).items()
        if name.lower() in SAFE_EXCEPTION_HEADERS
    }
    return JSONResponse(
        status_code=status,
        media_type=PROBLEM_MEDIA_TYPE,
        headers=safe_headers,
        content={
            "type": "about:blank",
            "title": title,
            "status": status,
            "detail": detail,
            "request_id": request_id,
            "code": code,
        },
    )


def status_problem(
    status: int,
    request_id: str,
    *,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    descriptions = {
        400: ("Bad Request", "The request could not be processed.", "bad_request"),
        401: ("Unauthorized", "Authentication is required.", "unauthorized"),
        404: ("Not Found", "The requested resource does not exist.", "not_found"),
        405: ("Method Not Allowed", "The HTTP method is not supported.", "method_not_allowed"),
        413: (
            "Content Too Large",
            "The request body exceeds the configured limit.",
            "body_too_large",
        ),
        422: ("Unprocessable Content", "Request validation failed.", "validation_failed"),
        429: ("Too Many Requests", "The request rate is too high.", "rate_limited"),
        500: ("Internal Server Error", "An unexpected error occurred.", "internal_error"),
        503: ("Service Unavailable", "The service is not ready.", "not_ready"),
    }
    title, detail, code = descriptions.get(
        status, ("Request Failed", "The request could not be completed.", "request_failed")
    )
    return problem_response(
        status=status,
        title=title,
        detail=detail,
        request_id=request_id,
        code=code,
        headers=headers,
    )
