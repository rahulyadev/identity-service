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
    assert response.headers["x-csrf-token"] == reader.result.csrf_token
    assert response.headers["cache-control"] == "no-store"
    assert "access-control-allow-origin" not in response.headers
    assert "www-authenticate" not in response.headers
    cookies = response.headers.get_list("set-cookie")
    assert len(cookies) == 1
    assert_session_cookie(cookies[0], session_id=session_id, max_age=43_200)
    assert reader.calls == [session_id]
    assert session_id not in response.text
    assert reader.result.csrf_token not in response.text


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
        ("POST", "/api/me", {}, 405),
        ("DELETE", "/api/me", {}, 405),
        ("GET", "/api/me/", {}, 404),
        ("POST", "/auth/refresh", {}, 404),
        ("GET", "/api/session", {}, 404),
    ],
)
def test_profile_request_shape_and_remaining_deferred_surfaces_remain_closed(
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


def test_profile_patch_route_passes_raw_request_and_returns_header_only_csrf_etag_and_cookie(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    app, reader = app_stack(settings)
    session_id = opaque_session_id()
    body = b'{"display_name":"Updated"}'
    with ASGIClient(app) as client:
        response = client.request(
            "PATCH",
            "/api/me",
            headers={
                "cookie": f"__Host-session={session_id}",
                "origin": settings.bff_origin,
                "x-csrf-token": reader.result.csrf_token,
                "sec-fetch-site": "same-origin",
                "if-match": '"v1"',
                "content-type": "application/merge-patch+json",
            },
            content=body,
        )

    assert response.status_code == 200
    assert response.json() == reader.result.profile
    assert response.headers["etag"] == reader.result.etag
    assert response.headers["x-csrf-token"] == reader.result.csrf_token
    assert reader.result.csrf_token not in response.text
    assert "access-control-allow-origin" not in response.headers
    assert len(response.headers.get_list("x-csrf-token")) == 1
    assert len(response.headers.get_list("set-cookie")) == 1
    assert_session_cookie(response.headers["set-cookie"], session_id=session_id, max_age=43_200)
    assert len(reader.patch_calls) == 1
    assert reader.patch_calls[0][0] == session_id
    raw = reader.patch_calls[0][1]
    assert raw.body == body
    assert raw.query_string == b""


@pytest.mark.parametrize(
    ("failure", "clear"),
    [
        (SessionReadError(403, "csrf_failed", False), False),
        (SessionReadError(412, "profile_conflict", False), False),
        (SessionReadError(503, "identity_unavailable", False), False),
        (SessionReadError(401, "session_required", True), True),
    ],
)
def test_profile_patch_failures_never_expose_csrf_or_renew_valid_cookie(
    bff_settings_factory: Callable[..., Settings],
    failure: SessionReadError,
    clear: bool,
) -> None:
    settings = bff_settings_factory()
    app, reader = app_stack(settings)
    reader.failure = failure
    session_id = opaque_session_id()
    with ASGIClient(app) as client:
        response = client.request(
            "PATCH",
            "/api/me",
            headers={
                "cookie": f"__Host-session={session_id}",
                "origin": settings.bff_origin,
                "x-csrf-token": reader.result.csrf_token,
                "if-match": '"v1"',
                "content-type": "application/merge-patch+json",
            },
            content=b'{"display_name":null}',
        )

    assert response.status_code == failure.status
    assert response.json()["code"] == failure.code
    assert "x-csrf-token" not in response.headers
    assert reader.result.csrf_token not in response.text
    assert ("set-cookie" in response.headers) is clear


def test_profile_patch_unsafe_unicode_422_exposes_nothing_and_does_not_renew_cookie(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    app, reader = app_stack(settings)
    reader.failure = SessionReadError(422, "validation_failed", False)
    session_id = opaque_session_id()
    unsafe_body = rb'{"display_name":"\ud800"}'
    with ASGIClient(app) as client:
        response = client.request(
            "PATCH",
            "/api/me",
            headers={
                "cookie": f"__Host-session={session_id}",
                "origin": settings.bff_origin,
                "x-csrf-token": reader.result.csrf_token,
                "if-match": '"v1"',
                "content-type": "application/merge-patch+json",
            },
            content=unsafe_body,
        )

    assert response.status_code == 422
    assert response.json()["code"] == "validation_failed"
    assert "x-csrf-token" not in response.headers
    assert "set-cookie" not in response.headers
    assert "access-control-allow-origin" not in response.headers
    assert reader.result.csrf_token not in response.text
    assert session_id not in response.text
    assert "\\ud800" not in response.text
    assert len(reader.patch_calls) == 1
    assert reader.patch_calls[0][0] == session_id
    assert reader.patch_calls[0][1].body == unsafe_body
