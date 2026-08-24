from __future__ import annotations

import asyncio
import json
import logging
import threading
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx2
import pytest
from fastapi import HTTPException, Request
from prometheus_client import CONTENT_TYPE_LATEST
from starlette.types import Message, Scope

from identity_service.api.problems import PROBLEM_MEDIA_TYPE, status_problem
from identity_service.app import create_app
from identity_service.config import AppEnvironment, Settings
from tests.fixtures.fake_cognito import FakeCognito
from tests.http_client import ASGIClient


def test_liveness_is_dependency_free_and_minimal(
    settings_factory: Callable[..., Settings], monkeypatch: object
) -> None:
    del monkeypatch
    app = create_app(settings_factory())
    with ASGIClient(app) as client:
        response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "alive"}
    assert set(response.json()) == {"status"}


def test_application_lifespan_disposes_database_engine(
    settings_factory: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    class EngineProbe:
        def __init__(self) -> None:
            self.dispose_calls: list[bool] = []

        def dispose(self, *, close: bool) -> None:
            self.dispose_calls.append(close)

    engine = EngineProbe()
    monkeypatch.setattr("identity_service.app.build_engine", lambda _settings: engine)
    monkeypatch.setattr("identity_service.app.build_session_factory", lambda _engine: object())
    app = create_app(settings_factory())
    with ASGIClient(app) as client:
        assert client.get("/health/live").status_code == 200
    assert engine.dispose_calls == [True]


def test_readiness_has_safe_success_and_failure_contract(
    settings_factory: Callable[..., Settings], monkeypatch: object
) -> None:
    from pytest import MonkeyPatch

    assert isinstance(monkeypatch, MonkeyPatch)
    app = create_app(settings_factory())
    monkeypatch.setattr("identity_service.api.routes.check_database_readiness", lambda *_: True)
    monkeypatch.setattr("identity_service.security.jwks.JwksCache.ready", lambda _: True)
    with ASGIClient(app) as client:
        ready = client.get("/health/ready")
    assert ready.status_code == 200
    assert ready.json() == {"status": "ready"}

    monkeypatch.setattr("identity_service.api.routes.check_database_readiness", lambda *_: False)
    with ASGIClient(app) as client:
        unavailable = client.get("/health/ready")
    assert unavailable.status_code == 503
    assert unavailable.headers["content-type"] == "application/problem+json"
    assert unavailable.json()["code"] == "not_ready"
    rendered = unavailable.text.lower()
    assert "postgresql" not in rendered
    assert "alembic" not in rendered
    assert "select" not in rendered


@pytest.mark.parametrize(
    ("status", "expected_code"),
    [
        (400, "bad_request"),
        (401, "unauthorized"),
        (404, "not_found"),
        (405, "method_not_allowed"),
        (413, "body_too_large"),
        (422, "validation_failed"),
        (429, "rate_limited"),
        (500, "internal_error"),
        (503, "not_ready"),
        (418, "request_failed"),
    ],
)
def test_every_public_problem_body_uses_only_the_code_field(
    status: int, expected_code: str
) -> None:
    response = status_problem(status, str(uuid.uuid4()))
    body = json.loads(response.body)
    assert set(body) == {"type", "title", "status", "detail", "request_id", "code"}
    assert body["code"] == expected_code
    assert "error_code" not in body


def test_blocked_jwks_fetch_does_not_block_liveness_on_same_asgi_event_loop(
    settings_factory: Callable[..., Settings],
    monkeypatch: pytest.MonkeyPatch,
    fake_cognito: FakeCognito,
) -> None:
    blocked = threading.Event()
    release = threading.Event()
    live_completed = threading.Event()
    liveness_completed_before_release: list[bool] = []
    event_loop: asyncio.AbstractEventLoop | None = None
    blocked_on_loop: asyncio.Event | None = None

    def blocking_jwks_fetch(request: httpx2.Request) -> httpx2.Response:
        blocked.set()
        assert event_loop is not None
        assert blocked_on_loop is not None
        event_loop.call_soon_threadsafe(blocked_on_loop.set)
        if not release.wait(timeout=2):
            raise RuntimeError("readiness test synchronization timed out")
        return fake_cognito.handle(request)

    def release_after_observation() -> None:
        if not blocked.wait(timeout=2):
            liveness_completed_before_release.append(False)
        else:
            liveness_completed_before_release.append(live_completed.wait(timeout=0.5))
        release.set()

    fake_cognito.jwks_status = 500
    monkeypatch.setattr("identity_service.api.routes.check_database_readiness", lambda *_: True)
    app = create_app(
        settings_factory(**fake_cognito.settings_overrides()),
        upstream_transport=httpx2.MockTransport(blocking_jwks_fetch),
    )
    observer = threading.Thread(target=release_after_observation)
    observer.start()

    async def exercise() -> tuple[tuple[int, dict[str, object]], tuple[int, dict[str, object]]]:
        nonlocal event_loop, blocked_on_loop
        event_loop = asyncio.get_running_loop()
        blocked_on_loop = asyncio.Event()

        async def invoke(path: str) -> tuple[int, dict[str, object]]:
            incoming = iter(
                [
                    {"type": "http.request", "body": b"", "more_body": False},
                    {"type": "http.disconnect"},
                ]
            )
            sent: list[Message] = []

            async def receive() -> Message:
                return next(incoming)  # type: ignore[return-value]

            async def send(message: Message) -> None:
                sent.append(message)

            scope: Scope = {
                "type": "http",
                "asgi": {"version": "3.0", "spec_version": "2.4"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "http",
                "path": path,
                "raw_path": path.encode(),
                "query_string": b"",
                "root_path": "",
                "headers": [(b"host", b"testserver")],
                "client": ("testclient", 50000),
                "server": ("testserver", 80),
            }
            await app(scope, receive, send)
            status = next(
                message["status"] for message in sent if message["type"] == "http.response.start"
            )
            body = b"".join(
                message.get("body", b"")
                for message in sent
                if message["type"] == "http.response.body"
            )
            return status, json.loads(body)

        async with app.router.lifespan_context(app):
            ready_task = asyncio.create_task(invoke("/health/ready"))
            assert blocked_on_loop is not None
            await asyncio.wait_for(blocked_on_loop.wait(), timeout=1)
            live_response = await invoke("/health/live")
            live_completed.set()
            ready_response = await ready_task
            return ready_response, live_response

    try:
        ready_response, live_response = asyncio.run(exercise())
    finally:
        release.set()
        observer.join(timeout=2)

    assert liveness_completed_before_release == [True]
    assert live_response == (200, {"status": "alive"})
    assert ready_response[0] == 503
    assert ready_response[1]["code"] == "not_ready"


def test_request_ids_are_generated_validated_and_propagated(
    settings_factory: Callable[..., Settings],
) -> None:
    app = create_app(settings_factory())
    supplied = str(uuid.uuid4())
    with ASGIClient(app) as client:
        generated = client.get("/health/live")
        invalid_replaced = client.get("/health/live", headers={"X-Request-ID": "invalid"})
        propagated = client.get("/health/live", headers={"X-Request-ID": supplied})

    assert uuid.UUID(generated.headers["x-request-id"]).version == 4
    assert invalid_replaced.headers["x-request-id"] != "invalid"
    assert uuid.UUID(invalid_replaced.headers["x-request-id"]).version == 4
    assert propagated.headers["x-request-id"] == supplied


def test_security_headers_and_no_cors(
    settings_factory: Callable[..., Settings],
) -> None:
    app = create_app(settings_factory())
    with ASGIClient(app) as client:
        response = client.get("/health/live", headers={"Origin": "https://browser.invalid"})
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert "access-control-allow-origin" not in response.headers
    assert "strict-transport-security" not in response.headers


@pytest.mark.parametrize(
    "environment",
    [AppEnvironment.DEVELOPMENT, AppEnvironment.STAGING, AppEnvironment.PRODUCTION],
)
def test_deployed_hsts_and_interactive_docs_are_disabled(
    settings_factory: Callable[..., Settings], environment: AppEnvironment
) -> None:
    settings = settings_factory(
        app_env=environment,
        identity_origin="https://identity.invalid",
        allowed_hosts=["identity.invalid"],
        enable_interactive_docs=False,
        log_format="json",
        database_url=(
            "postgresql+psycopg://app:local@db/identity?sslmode=verify-full&sslrootcert=system"  # pragma: allowlist secret (synthetic test credential)  # noqa: E501
        ),
    )
    app = create_app(settings)
    with ASGIClient(app, base_url="https://identity.invalid") as client:
        live = client.get("/health/live")
        docs = client.get("/docs")
        redoc = client.get("/redoc")
    assert live.headers["strict-transport-security"].startswith("max-age=31536000")
    assert docs.status_code == 404
    assert redoc.status_code == 404


def test_local_documentation_is_usable_without_weakening_api_csp(
    settings_factory: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("identity_service.api.routes.check_database_readiness", lambda *_: False)
    monkeypatch.setattr("identity_service.security.jwks.JwksCache.ready", lambda _: False)
    app = create_app(settings_factory(enable_interactive_docs=True))
    with ASGIClient(app) as client:
        docs = client.get("/docs")
        redoc = client.get("/redoc")
        protected = [
            client.get("/health/live"),
            client.get("/health/ready"),
            client.get("/metrics"),
            client.get("/openapi.json"),
            client.get("/future/api/path"),
        ]

    assert docs.status_code == 200
    assert redoc.status_code == 200
    assert "cdn.jsdelivr.net" in docs.text
    assert "cdn.jsdelivr.net" in redoc.text
    assert "content-security-policy" not in docs.headers
    assert "content-security-policy" not in redoc.headers
    for response in protected:
        assert "default-src 'none'" in response.headers["content-security-policy"]


def test_invalid_host_and_oversized_body_use_problem_responses(
    settings_factory: Callable[..., Settings],
) -> None:
    app = create_app(settings_factory(max_request_body_bytes=16))
    with ASGIClient(app) as client:
        bad_host = client.get("/health/live", headers={"Host": "attacker.invalid"})
        oversized = client.post("/health/live", content=b"x" * 17)
    assert bad_host.status_code == 400
    assert bad_host.headers["content-type"] == "application/problem+json"
    assert oversized.status_code == 413
    assert oversized.json()["code"] == "body_too_large"
    assert "x-request-id" in oversized.headers


@pytest.mark.parametrize(
    "host",
    [
        "allowed-host#fragment",
        "allowed-host?query",
        "allowed-host\\path",
        "allowed-host:",
        "allowed-host:0",
        "allowed-host:65536",
        "user@allowed-host",
        "allowed-host,other-host",
    ],
)
def test_malformed_host_values_are_rejected(
    settings_factory: Callable[..., Settings], host: str
) -> None:
    app = create_app(settings_factory(allowed_hosts=["localhost", "testserver", "allowed-host"]))
    with ASGIClient(app) as client:
        response = client.get("/health/live", headers={"Host": host})
    assert response.status_code == 400


def test_host_matching_supports_exact_case_port_and_subdomain_only_wildcards(
    settings_factory: Callable[..., Settings],
) -> None:
    app = create_app(
        settings_factory(
            identity_origin="http://api.example.invalid",
            allowed_hosts=["exact.invalid", "*.example.invalid"],
        )
    )
    with ASGIClient(app, base_url="http://api.example.invalid") as client:
        exact = client.get("/health/live", headers={"Host": "EXACT.INVALID:8080"})
        wildcard = client.get("/health/live", headers={"Host": "child.example.invalid"})
        parent = client.get("/health/live", headers={"Host": "example.invalid"})
        duplicate = client.get(
            "/health/live",
            headers=[("Host", "exact.invalid"), ("Host", "exact.invalid")],
        )
    assert exact.status_code == 200
    assert wildcard.status_code == 200
    assert parent.status_code == 400
    assert duplicate.status_code == 400


def test_handled_http_exception_headers_are_safely_preserved(
    settings_factory: Callable[..., Settings],
) -> None:
    app = create_app(settings_factory())

    @app.get("/_test/auth", include_in_schema=False)
    async def authentication_probe() -> None:
        raise HTTPException(
            status_code=401,
            headers={
                "WWW-Authenticate": 'Bearer realm="identity"',
                "X-Request-ID": "attacker-controlled",
                "X-Frame-Options": "SAMEORIGIN",
                "Content-Security-Policy": "default-src *",
            },
        )

    @app.get("/_test/rate", include_in_schema=False)
    async def rate_limit_probe() -> None:
        raise HTTPException(status_code=429, headers={"Retry-After": "30"})

    with ASGIClient(app) as client:
        method_not_allowed = client.post("/health/live")
        unauthorized = client.get("/_test/auth")
        rate_limited = client.get("/_test/rate")

    assert method_not_allowed.status_code == 405
    assert method_not_allowed.headers["content-type"] == "application/problem+json"
    assert method_not_allowed.headers["allow"] == "GET"
    assert method_not_allowed.json()["code"] == "method_not_allowed"
    assert "error_code" not in method_not_allowed.json()
    assert unauthorized.status_code == 401
    assert unauthorized.headers["www-authenticate"] == 'Bearer realm="identity"'
    assert unauthorized.json()["code"] == "unauthorized"
    assert "error_code" not in unauthorized.json()
    assert unauthorized.headers["x-request-id"] != "attacker-controlled"
    assert unauthorized.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in unauthorized.headers["content-security-policy"]
    assert rate_limited.status_code == 429
    assert rate_limited.headers["retry-after"] == "30"
    assert rate_limited.json()["code"] == "rate_limited"
    assert "error_code" not in rate_limited.json()


def test_untrusted_forwarded_headers_do_not_change_request_scope(
    settings_factory: Callable[..., Settings],
) -> None:
    app = create_app(settings_factory(trusted_proxy_cidrs=[]))

    @app.get("/_test/scope", include_in_schema=False)
    async def scope_probe(request: Request) -> dict[str, object]:
        return {
            "scheme": request.scope["scheme"],
            "host": request.headers["host"],
            "client": request.client.host if request.client else None,
        }

    with ASGIClient(app) as client:
        response = client.get(
            "/_test/scope",
            headers={
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "attacker.invalid",
                "X-Forwarded-For": "203.0.113.8",
            },
        )
    assert response.status_code == 200
    assert response.json() == {"scheme": "http", "host": "testserver", "client": "testclient"}


def test_unexpected_errors_do_not_leak_internal_values(
    settings_factory: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    app = create_app(settings_factory())
    sentinel = "unexpected-error-redaction-sentinel"
    logged: list[tuple[str, dict[str, object]]] = []

    def capture_error(message: str, *, extra: dict[str, object]) -> None:
        logged.append((message, extra))

    monkeypatch.setattr(logging.getLogger("identity_service.http"), "error", capture_error)

    @app.get("/_test/explode", include_in_schema=False)
    async def explode() -> None:
        raise RuntimeError(f"postgresql://user:{sentinel}@internal-db/name /home/private/file")

    with ASGIClient(app, raise_app_exceptions=False) as client:
        response = client.get("/_test/explode")
    assert response.status_code == 500
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["code"] == "internal_error"
    assert "error_code" not in response.json()
    assert sentinel not in response.text
    assert "internal-db" not in response.text
    assert "/home/" not in response.text
    assert "x-request-id" in response.headers
    assert sentinel not in json.dumps(logged, sort_keys=True)
    assert logged[0][1]["error_type"] == "RuntimeError"


def test_metrics_use_only_bounded_route_labels_and_no_pii(
    settings_factory: Callable[..., Settings],
) -> None:
    app = create_app(settings_factory())
    request_id = str(uuid.uuid4())
    with ASGIClient(app) as client:
        client.get(
            "/health/live?email=person@example.invalid&subject=private-subject",
            headers={"X-Request-ID": request_id},
        )
        response = client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain; version=")
    assert 'route="/health/live"' in response.text
    assert "person@example.invalid" not in response.text
    assert "private-subject" not in response.text
    assert request_id not in response.text
    assert "issuer=" not in response.text
    assert "user_id=" not in response.text


def test_metrics_route_can_be_disabled(settings_factory: Callable[..., Settings]) -> None:
    app = create_app(settings_factory(metrics_enabled=False))
    with ASGIClient(app) as client:
        response = client.get("/metrics")
    assert response.status_code == 404
    assert "/metrics" not in app.openapi()["paths"]


def test_only_implemented_operational_and_profile_routes_are_documented(
    settings_factory: Callable[..., Settings],
) -> None:
    app = create_app(settings_factory())
    document = app.openapi()
    assert set(document["paths"]) == {
        "/health/live",
        "/health/ready",
        "/metrics",
        "/v1/me",
    }
    operation_ids = {
        operation["operationId"]
        for path in document["paths"].values()
        for operation in path.values()
        if isinstance(operation, dict) and "operationId" in operation
    }
    assert operation_ids == {
        "health_live",
        "health_ready",
        "metrics",
        "put_current_profile",
        "get_current_profile",
        "patch_current_profile",
    }

    with ASGIClient(app) as client:
        profile = client.get("/v1/me")
        assert profile.status_code == 401
        assert profile.json()["code"] == "invalid_token"
        for path in (
            "/v1/login",
            "/v1/callback",
            "/v1/session",
            "/v1/logout",
        ):
            response = client.get(path)
            assert response.status_code == 404
            assert response.headers["content-type"] == "application/problem+json"


def test_openapi_json_documents_one_strict_http_bearer_contract(
    settings_factory: Callable[..., Settings],
) -> None:
    document = create_app(settings_factory()).openapi()
    rendered = json.dumps(document, sort_keys=True)
    scheme = document["components"]["securitySchemes"]["BearerAuth"]
    assert scheme["type"] == "http"
    assert scheme["scheme"] == "bearer"
    assert scheme["bearerFormat"] == "JWT"
    for method in ("put", "get", "patch"):
        assert document["paths"]["/v1/me"][method]["security"] == [{"BearerAuth": []}]
    for prohibited in ("authorizationUrl", "tokenUrl", "clientSecret"):
        assert prohibited not in rendered


def test_profile_openapi_matches_representation_media_status_and_header_contract(
    settings_factory: Callable[..., Settings],
) -> None:
    document = create_app(settings_factory()).openapi()
    operations = document["paths"]["/v1/me"]
    assert set(operations) == {"put", "get", "patch"}
    profile_schema = document["components"]["schemas"]["ProfileResponse"]
    assert set(profile_schema["properties"]) == {
        "user_id",
        "email",
        "email_verified",
        "display_name",
        "avatar_url",
        "version",
        "created_at",
        "updated_at",
    }
    assert set(profile_schema["required"]) == set(profile_schema["properties"])
    assert profile_schema["properties"]["user_id"]["format"] == "uuid"
    assert profile_schema["properties"]["version"]["minimum"] == 1
    assert "requestBody" not in operations["put"]
    assert set(operations["patch"]["requestBody"]["content"]) == {"application/merge-patch+json"}
    assert set(operations["put"]["responses"]) == {"200", "201", "400", "401", "403", "503"}
    assert set(operations["get"]["responses"]) == {"200", "401", "403", "404", "503"}
    assert set(operations["patch"]["responses"]) == {
        "200",
        "400",
        "401",
        "403",
        "404",
        "412",
        "415",
        "422",
        "428",
        "503",
    }
    for method in ("put", "get", "patch"):
        success = operations[method]["responses"]["200"]
        assert set(success["headers"]) == {"ETag", "Cache-Control"}
    assert set(operations["put"]["responses"]["201"]["headers"]) == {
        "ETag",
        "Cache-Control",
    }


def _resolve_schema(document: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    reference = schema.get("$ref")
    if reference is None:
        return schema
    resolved: Any = document
    for segment in reference.removeprefix("#/").split("/"):
        resolved = resolved[segment]
    assert isinstance(resolved, dict)
    return resolved


def _assert_body_matches_object_schema(
    document: dict[str, Any], schema: dict[str, Any], body: dict[str, Any]
) -> None:
    resolved = _resolve_schema(document, schema)
    assert resolved["type"] == "object"
    assert set(resolved.get("required", [])) <= set(body)
    properties = resolved["properties"]
    for name, value in body.items():
        property_schema = properties[name]
        if "const" in property_schema:
            assert value == property_schema["const"]
        expected_type = property_schema.get("type")
        if expected_type == "string":
            assert isinstance(value, str)
        elif expected_type == "integer":
            assert isinstance(value, int) and not isinstance(value, bool)


def test_openapi_response_schemas_match_live_responses(
    settings_factory: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    app = create_app(settings_factory())
    document = app.openapi()
    monkeypatch.setattr("identity_service.api.routes.check_database_readiness", lambda *_: True)
    monkeypatch.setattr("identity_service.security.jwks.JwksCache.ready", lambda _: True)
    with ASGIClient(app) as client:
        live = client.get("/health/live")
        ready = client.get("/health/ready")
        metrics = client.get("/metrics")
        monkeypatch.setattr(
            "identity_service.api.routes.check_database_readiness", lambda *_: False
        )
        unavailable = client.get("/health/ready")

    live_schema = document["paths"]["/health/live"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]
    ready_responses = document["paths"]["/health/ready"]["get"]["responses"]
    ready_schema = ready_responses["200"]["content"]["application/json"]["schema"]
    problem_content = ready_responses["503"]["content"]
    metrics_content = document["paths"]["/metrics"]["get"]["responses"]["200"]["content"]

    _assert_body_matches_object_schema(document, live_schema, live.json())
    _assert_body_matches_object_schema(document, ready_schema, ready.json())
    assert set(problem_content) == {PROBLEM_MEDIA_TYPE}
    _assert_body_matches_object_schema(
        document, problem_content[PROBLEM_MEDIA_TYPE]["schema"], unavailable.json()
    )
    assert unavailable.headers["content-type"] == PROBLEM_MEDIA_TYPE
    assert set(metrics_content) == {CONTENT_TYPE_LATEST}
    assert metrics_content[CONTENT_TYPE_LATEST]["schema"] == {"type": "string"}
    assert metrics.headers["content-type"] == CONTENT_TYPE_LATEST

    schemas = document["components"]["schemas"]
    assert schemas["LiveResponse"]["required"] == ["status"]
    assert schemas["ReadyResponse"]["required"] == ["status"]
    problem_schema = _resolve_schema(document, problem_content[PROBLEM_MEDIA_TYPE]["schema"])
    assert "code" in problem_schema["required"]
    assert "code" in problem_schema["properties"]
    assert "error_code" not in problem_schema["required"]
    assert "error_code" not in problem_schema["properties"]
    assert unavailable.json()["code"] == "not_ready"
    assert "error_code" not in unavailable.json()
    rendered = json.dumps(document, sort_keys=True).lower()
    for absent in ("provider_email", "provider_display_name", "subject", "client_id"):
        assert absent not in rendered


def test_public_problem_source_and_generated_contract_do_not_declare_error_code() -> None:
    repository = Path(__file__).resolve().parents[2]
    for relative_path in (
        "src/identity_service/api/problems.py",
        "src/identity_service/api/routes.py",
        "openapi/openapi.json",
    ):
        content = (repository / relative_path).read_text(encoding="utf-8")
        assert '"error_code"' not in content
