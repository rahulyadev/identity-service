from __future__ import annotations

import asyncio
import importlib
import io
import json
import logging
import sys
from collections.abc import Callable
from typing import Any

import pytest
from reference_bff import server
from reference_bff.config import Settings
from reference_bff.logging import configure_logging
from reference_bff.middleware import (
    SecurityBoundaryMiddleware,
    _parse_host,
    _request_id,
    get_request_id,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (b"localhost:8081", "localhost"),
        (b"127.0.0.1", "127.0.0.1"),
        (b"LOCALHOST.", "localhost"),
        (b"", None),
        (b" localhost", None),
        (b"user@localhost", None),
        (b"localhost:0", None),
        (b"localhost:not-a-port", None),
        (b"bad..host", None),
        (b"\xff", None),
    ],
)
def test_strict_host_parser(value: bytes, expected: str | None) -> None:
    assert _parse_host(value) == expected


def test_request_id_and_scope_fallbacks_are_bounded() -> None:
    assert _request_id([(b"x-request-id", b"safe-id")]) == "safe-id"
    assert _request_id([(b"x-request-id", b"\xff")]) != ""
    assert _request_id([(b"x-request-id", b"first"), (b"x-request-id", b"second")]) not in {
        "first",
        "second",
    }
    assert get_request_id({"state": {"request_id": "safe-id"}}) == "safe-id"  # type: ignore[typeddict-item]
    assert get_request_id({"state": {"request_id": "unsafe id"}}) == "unavailable"  # type: ignore[typeddict-item]
    assert get_request_id({}) == "unavailable"


def test_middleware_passes_non_http_scopes_without_http_mutation() -> None:
    calls: list[str] = []

    async def downstream(scope: Any, receive: Any, send: Any) -> None:
        del receive, send
        calls.append(scope["type"])

    async def receive() -> dict[str, str]:
        return {"type": "lifespan.startup"}

    async def send(message: object) -> None:
        del message

    middleware = SecurityBoundaryMiddleware(downstream, allowed_hosts=["localhost"])
    asyncio.run(middleware({"type": "lifespan"}, receive, send))  # type: ignore[arg-type]
    assert calls == ["lifespan"]


def test_json_logging_and_server_entrypoint_use_safe_fixed_runtime_options(
    bff_settings_factory: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = bff_settings_factory(log_format="json")
    stream = io.StringIO()
    configure_logging(settings, stream=stream)
    logging.getLogger("reference_bff.test").warning("safe_event")
    payload = json.loads(stream.getvalue())
    assert payload["event"] == "safe_event"
    assert payload["service"] == "reference-bff"

    observed: dict[str, Any] = {}
    monkeypatch.setattr(server, "Settings", lambda: settings)
    monkeypatch.setattr(
        server, "configure_logging", lambda resolved: observed.update(config=resolved)
    )
    monkeypatch.setattr(
        server.uvicorn, "run", lambda *args, **kwargs: observed.update(args=args, kwargs=kwargs)
    )
    server.main()
    assert observed["config"] is settings
    assert observed["args"] == ("reference_bff.main:app",)
    assert observed["kwargs"] == {
        "host": "0.0.0.0",
        "port": 8081,
        "workers": 1,
        "proxy_headers": False,
        "access_log": False,
        "log_config": None,
        "log_level": None,
        "timeout_graceful_shutdown": 15,
    }


def test_environment_backed_main_module_constructs_only_the_bff_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {
        "APP_ENV": "test",
        "BFF_ORIGIN": "http://localhost:8081",
        "ALLOWED_HOSTS": '["localhost"]',
        "AUTHORIZATION_ENDPOINT": "http://127.0.0.1:9000/oauth2/authorize",
        "TOKEN_ENDPOINT": "http://127.0.0.1:9000/oauth2/token",
        "COGNITO_ISSUER": "http://127.0.0.1:9000/test-pool",
        "COGNITO_JWKS_URL": "http://127.0.0.1:9000/test-pool/.well-known/jwks.json",
        "IDENTITY_API_ORIGIN": "http://127.0.0.1:9001",
        "BFF_CLIENT_ID": "synthetic-reference-client",
        "BFF_CLIENT_SECRET": "synthetic-reference-secret",  # pragma: allowlist secret
        "REDIS_URL": "redis://127.0.0.1:56379/15",
        "REDIS_KEY_NAMESPACE": "reference-bff:test:module",
        "ENABLE_INTERACTIVE_DOCS": "false",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    sys.modules.pop("reference_bff.main", None)
    module = importlib.import_module("reference_bff.main")
    assert module.app.title == "reference-bff"
