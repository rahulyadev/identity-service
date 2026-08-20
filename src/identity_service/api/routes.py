"""Operational route definitions."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST
from pydantic import BaseModel, ConfigDict

from identity_service.api.middleware import get_request_id
from identity_service.api.problems import PROBLEM_MEDIA_TYPE, ProblemResponse, status_problem
from identity_service.db.readiness import check_database_readiness

router = APIRouter()


class LiveResponse(BaseModel):
    model_config = ConfigDict(frozen=True)
    status: Literal["alive"]


class ReadyResponse(BaseModel):
    model_config = ConfigDict(frozen=True)
    status: Literal["ready"]


@router.get(
    "/health/live",
    response_model=LiveResponse,
    operation_id="health_live",
    tags=["operations"],
)
async def live() -> LiveResponse:
    return LiveResponse(status="alive")


@router.get(
    "/health/ready",
    response_model=ReadyResponse,
    operation_id="health_ready",
    responses={
        503: {
            "description": "PostgreSQL or migration revision is not ready",
            "content": {
                PROBLEM_MEDIA_TYPE: {
                    "schema": ProblemResponse.model_json_schema(),
                }
            },
        }
    },
    tags=["operations"],
)
def ready(request: Request) -> ReadyResponse | Response:
    if not check_database_readiness(request.app.state.engine, request.app.state.metrics):
        return status_problem(503, get_request_id(request.scope))
    return ReadyResponse(status="ready")


@router.get(
    "/metrics",
    operation_id="metrics",
    include_in_schema=True,
    tags=["operations"],
    response_class=Response,
    responses={
        200: {
            "description": "Prometheus metrics",
            "content": {
                CONTENT_TYPE_LATEST: {
                    "schema": {"type": "string"},
                }
            },
        }
    },
)
async def metrics(request: Request) -> Response:
    return Response(
        content=request.app.state.metrics.render(request.app.state.engine),
        headers={"Content-Type": CONTENT_TYPE_LATEST},
    )
