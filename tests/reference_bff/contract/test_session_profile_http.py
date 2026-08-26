from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi import FastAPI
from reference_bff.app import create_app
from reference_bff.config import Settings
from reference_bff.session_flow import SessionReadError
from reference_bff.sessions import opaque_session_id

from tests.http_client import ASGIClient
from tests.reference_bff.fakes import FakeCallbackService, FakeSessionReader, FakeTransactionStore


def app_stack(
    settings: Settings,
) -> tuple[FastAPI, FakeSessionReader]:
    reader = FakeSessionReader()
    app = create_app(
        settings,
        transaction_store=FakeTransactionStore(settings),
        callback_service=FakeCallbackService(),
        session_reader=reader,
    )
    return app, reader


def assert_session_cookie(cookie: str, *, session_id: str | None, max_age: int) -> None:
    expected = f"__Host-session={session_id}" if session_id is not None else '__Host-session=""'
    assert cookie.startswith(expected)
    assert "Path=/" in cookie
    assert f"Max-Age={max_age}" in cookie
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=lax" in cookie
    assert "Domain=" not in cookie


def test_profile_read_returns_exact_validated_body_etag_and_renews_stable_cookie(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    app, reader = app_stack(settings)
    session_id = opaque_session_id()
    with ASGIClient(app) as client:
        response = client.get(
            "/api/me",
            headers={"cookie": f"other=value; __Host-session={session_id}"},
        )

    assert response.status_code == 200
    assert response.json() == reader.result.profile
    assert response.headers["etag"] == '"v1"'
    assert response.headers["cache-control"] == "no-store"
    assert "access-control-allow-origin" not in response.headers
    assert "www-authenticate" not in response.headers
    cookies = response.headers.get_list("set-cookie")
    assert len(cookies) == 1
    assert_session_cookie(cookies[0], session_id=session_id, max_age=43_200)
    assert reader.calls == [session_id]
    assert session_id not in response.text


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"cookie": "other=value"},
        {"cookie": "__Host-session=short"},
        {"cookie": "__Host-session=" + "A" * 42 + "B"},
        {"cookie": "__Host-session=" + "A" * 43 + "; __Host-session=" + "Q" * 43},
        {"cookie": 'other="quoted"; __Host-session=' + "A" * 43},
    ],
)
def test_missing_ambiguous_and_malformed_session_cookie_is_fixed_401_and_cleared(
    bff_settings_factory: Callable[..., Settings], headers: dict[str, str]
) -> None:
    app, reader = app_stack(bff_settings_factory())
    with ASGIClient(app) as client:
        response = client.get("/api/me", headers=headers)

    assert response.status_code == 401
    assert response.json()["code"] == "session_required"
    assert "www-authenticate" not in response.headers
    assert "access-control-allow-origin" not in response.headers
    assert len(response.headers.get_list("set-cookie")) == 1
    assert_session_cookie(
        response.headers["set-cookie"],
        session_id=None,
        max_age=0,
    )
    assert reader.calls == []


@pytest.mark.parametrize(
    ("failure", "clear"),
    [
        (SessionReadError(401, "session_required", True), True),
        (SessionReadError(503, "session_unavailable", False), False),
        (SessionReadError(503, "identity_unavailable", False), False),
    ],
)
def test_profile_fixed_failures_clear_only_invalid_sessions(
    bff_settings_factory: Callable[..., Settings], failure: SessionReadError, clear: bool
) -> None:
    app, reader = app_stack(bff_settings_factory())
    reader.failure = failure
    session_id = opaque_session_id()
    with ASGIClient(app) as client:
        response = client.get(
            "/api/me",
            headers={"cookie": f"__Host-session={session_id}"},
        )

    assert response.status_code == failure.status
    assert response.json()["code"] == failure.code
    assert ("set-cookie" in response.headers) is clear
    if clear:
        assert_session_cookie(response.headers["set-cookie"], session_id=None, max_age=0)
    assert session_id not in response.text


@pytest.mark.parametrize(
    ("method", "target", "kwargs", "status"),
    [
        ("GET", "/api/me?x=1", {}, 400),
        ("GET", "/api/me", {"content": b"x"}, 400),
        ("GET", "/api/me", {"headers": {"authorization": "Bearer browser-token"}}, 400),
        ("PUT", "/api/me", {}, 405),
        ("PATCH", "/api/me", {}, 405),
        ("POST", "/api/me", {}, 405),
        ("DELETE", "/api/me", {}, 405),
        ("GET", "/api/me/", {}, 404),
        ("POST", "/auth/logout", {}, 404),
        ("GET", "/auth/signed-out", {}, 404),
        ("POST", "/auth/refresh", {}, 404),
        ("GET", "/api/session", {}, 404),
    ],
)
def test_profile_request_shape_and_deferred_surfaces_remain_closed(
    bff_settings_factory: Callable[..., Settings],
    method: str,
    target: str,
    kwargs: dict[str, object],
    status: int,
) -> None:
    app, reader = app_stack(bff_settings_factory())
    with ASGIClient(app) as client:
        response = client.request(method, target, **kwargs)

    assert response.status_code == status
    assert reader.calls == []
    assert "access-control-allow-origin" not in response.headers
    assert "www-authenticate" not in response.headers
