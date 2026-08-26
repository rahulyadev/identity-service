"""Fixed, non-reflective HTTP problem responses."""

from __future__ import annotations

from dataclasses import dataclass

from starlette.responses import JSONResponse

PROBLEM_TITLES = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    412: "Precondition Failed",
    415: "Unsupported Media Type",
    422: "Unprocessable Content",
    428: "Precondition Required",
    500: "Internal Server Error",
    503: "Service Unavailable",
}


@dataclass(frozen=True, slots=True)
class PublicProblemError(Exception):
    status: int
    code: str


def problem_response(status: int, code: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        {
            "type": f"https://reference-bff.invalid/problems/{code}",
            "title": PROBLEM_TITLES.get(status, "Request Failed"),
            "status": status,
            "code": code,
            "request_id": request_id,
        },
        status_code=status,
        media_type="application/problem+json",
    )
