from __future__ import annotations

from collections.abc import Callable
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import FastAPI
from reference_bff.app import create_app
from reference_bff.config import Settings
from reference_bff.session_flow import SessionReadError
from reference_bff.sessions import opaque_session_id

from tests.http_client import ASGIClient
from tests.reference_bff.fakes import FakeCallbackService, FakeSessionReader, FakeTransactionStore


def app_stack(settings: Settings) -> tuple[FastAPI, FakeSessionReader]:
    reader = FakeSessionReader()
    app = create_app(
        settings,
        transaction_store=FakeTransactionStore(settings),
        callback_service=FakeCallbackService(),
        session_reader=reader,
    )
    return app, reader


def logout_headers(settings: Settings, csrf_token: str, session_id: str) -> dict[str, str]:
    return {
        "cookie": f"__Host-session={session_id}",
        "origin": settings.bff_origin,
        "x-csrf-token": csrf_token,
        "sec-fetch-site": "same-origin",
    }


def assert_both_cookies_cleared(cookies: list[str]) -> None:
    assert len(cookies) == 2
    for name in ("__Host-oauth", "__Host-session"):
        cookie = next(value for value in cookies if value.startswith(f'{name}="";'))
        assert "Path=/" in cookie
        assert "Max-Age=0" in cookie
        assert "HttpOnly" in cookie
        assert "Secure" in cookie
        assert "SameSite=lax" in cookie
        assert "Domain=" not in cookie


def test_logout_success_clears_both_cookies_and_uses_exact_cognito_navigation(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    app, reader = app_stack(settings)
    session_id = opaque_session_id()
    with ASGIClient(app) as client:
        response = client.post(
            "/auth/logout",
            headers=logout_headers(settings, reader.result.csrf_token, session_id),
        )

    assert response.status_code == 303
    assert response.content == b""
    assert response.headers["location"] == settings.logout_redirect_uri
    target = urlsplit(response.headers["location"])
    assert f"{target.scheme}://{target.netloc}{target.path}" == settings.logout_endpoint
    assert parse_qs(target.query, strict_parsing=True) == {
        "client_id": [settings.client_id],
        "logout_uri": [settings.signed_out_uri],
    }
    assert set(parse_qs(target.query, strict_parsing=True)) == {"client_id", "logout_uri"}
    assert "access-control-allow-origin" not in response.headers
    assert "x-csrf-token" not in response.headers
    assert reader.result.csrf_token not in response.text
    assert session_id not in response.text
    assert_both_cookies_cleared(response.headers.get_list("set-cookie"))
    assert len(reader.logout_calls) == 1
    assert reader.logout_calls[0][0] == session_id
    raw = reader.logout_calls[0][1]
    assert raw.query_string == b""
    assert raw.body_present is False
    assert raw.body_complete is True


@pytest.mark.parametrize(
    "cookie",
    [
        None,
        "other=value",
        "__Host-session=short",
        "__Host-session=" + "A" * 43 + "; __Host-session=" + "Q" * 43,
        '__Host-session="quoted"',
    ],
)
def test_logout_missing_or_ambiguous_session_is_fixed_401_and_clears_both(
    bff_settings_factory: Callable[..., Settings], cookie: str | None
) -> None:
    settings = bff_settings_factory()
    app, reader = app_stack(settings)
    headers = {
        "origin": settings.bff_origin,
        "x-csrf-token": reader.result.csrf_token,
    }
    if cookie is not None:
        headers["cookie"] = cookie
    with ASGIClient(app) as client:
        response = client.post("/auth/logout", headers=headers)

    assert response.status_code == 401
    assert response.json()["code"] == "session_required"
    assert "location" not in response.headers
    assert "x-csrf-token" not in response.headers
    assert_both_cookies_cleared(response.headers.get_list("set-cookie"))
    assert reader.logout_calls == []


@pytest.mark.parametrize(
    ("failure", "clear"),
    [
        (SessionReadError(400, "bad_request", False), False),
        (SessionReadError(403, "csrf_failed", False), False),
        (SessionReadError(401, "session_required", True), True),
        (SessionReadError(503, "session_unavailable", True), True),
    ],
)
def test_logout_fixed_failures_never_redirect_renew_or_expose_csrf(
    bff_settings_factory: Callable[..., Settings],
    failure: SessionReadError,
    clear: bool,
) -> None:
    settings = bff_settings_factory()
    app, reader = app_stack(settings)
    reader.failure = failure
    session_id = opaque_session_id()
    with ASGIClient(app) as client:
        response = client.post(
            "/auth/logout",
            headers=logout_headers(settings, reader.result.csrf_token, session_id),
        )

    assert response.status_code == failure.status
    assert response.json()["code"] == failure.code
    assert "location" not in response.headers
    assert "x-csrf-token" not in response.headers
    assert "access-control-allow-origin" not in response.headers
    assert reader.result.csrf_token not in response.text
    assert session_id not in response.text
    cookies = response.headers.get_list("set-cookie")
    if clear:
        assert_both_cookies_cleared(cookies)
    else:
        assert cookies == []


@pytest.mark.parametrize(
    ("target", "headers", "content"),
    [
        ("/auth/logout?unsafe=value", {}, b""),
        ("/auth/logout", {"authorization": "Bearer unsafe-value"}, b""),
        ("/auth/logout", {"content-type": "application/json"}, b""),
        ("/auth/logout", {}, b"unsafe-value"),
    ],
)
def test_logout_forwards_raw_unsafe_shape_without_reflecting_it(
    bff_settings_factory: Callable[..., Settings],
    target: str,
    headers: dict[str, str],
    content: bytes,
) -> None:
    settings = bff_settings_factory()
    app, reader = app_stack(settings)
    reader.failure = SessionReadError(400, "bad_request", False)
    session_id = opaque_session_id()
    with ASGIClient(app) as client:
        response = client.post(
            target,
            headers={
                **logout_headers(settings, reader.result.csrf_token, session_id),
                **headers,
            },
            content=content,
        )

    assert response.status_code == 400
    assert response.json()["code"] == "bad_request"
    assert "unsafe" not in response.text
    assert "set-cookie" not in response.headers
    assert "location" not in response.headers
    assert len(reader.logout_calls) == 1


def test_signed_out_is_strict_clears_both_and_has_no_session_or_provider_operation(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    app, reader = app_stack(settings)
    with ASGIClient(app) as client:
        response = client.get(
            "/auth/signed-out",
            headers={"cookie": "__Host-oauth=opaque; __Host-session=opaque"},
        )
        bad_query = client.get("/auth/signed-out?unsafe=value")
        bad_body = client.request("GET", "/auth/signed-out", content=b"unsafe-value")
        bad_auth = client.get("/auth/signed-out", headers={"authorization": "Bearer unsafe-value"})

    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert response.content == b""
    assert_both_cookies_cleared(response.headers.get_list("set-cookie"))
    for failure in (bad_query, bad_body, bad_auth):
        assert failure.status_code == 400
        assert failure.json()["code"] == "bad_request"
        assert "set-cookie" not in failure.headers
        assert "location" not in failure.headers
        assert "unsafe" not in failure.text
    assert reader.calls == []
    assert reader.patch_calls == []
    assert reader.logout_calls == []
