from __future__ import annotations

import asyncio
from collections.abc import Callable
from urllib.parse import parse_qs, quote, urlsplit

import httpx2
from fastapi import FastAPI
from reference_bff.app import create_app
from reference_bff.config import Settings
from reference_bff.flow import CallbackFlowError

from tests.http_client import ASGIClient
from tests.reference_bff.fakes import FakeCallbackService, FakeTransactionStore

SECURITY_HEADERS = {
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "permissions-policy": "camera=(), geolocation=(), microphone=()",
}


def callback_app(settings: Settings, store: FakeTransactionStore) -> FastAPI:
    return create_app(
        settings,
        transaction_store=store,
        callback_service=FakeCallbackService(),
    )


def test_login_persists_before_exact_temporary_redirect(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    store = FakeTransactionStore(settings)
    app = callback_app(settings, store)
    return_to = "/profile?tab=security"
    with ASGIClient(app) as client:
        response = client.get(f"/auth/login?return_to={quote(return_to, safe='')}")

    assert response.status_code == 307
    assert len(store.transactions) == 1
    transaction = store.transactions[0]
    assert transaction.return_to == return_to
    parsed = urlsplit(response.headers["location"])
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == settings.authorization_endpoint
    query = parse_qs(parsed.query, strict_parsing=True)
    assert set(query) == {
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "resource",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    }
    assert query == {
        "response_type": ["code"],
        "client_id": [settings.client_id],
        "redirect_uri": [settings.callback_uri],
        "scope": [" ".join(settings.requested_scopes)],
        "resource": [settings.oauth_resource],
        "state": [transaction.state],
        "nonce": [transaction.nonce],
        "code_challenge": [transaction.code_challenge],
        "code_challenge_method": ["S256"],
    }
    forbidden = (
        settings.client_secret.get_secret_value(),
        transaction.pkce_verifier,
        transaction.transaction_id,
        settings.redis_key_namespace,
        "redis://",
        "access_token",
    )
    assert all(value not in response.headers["location"] for value in forbidden)
    assert "set-cookie" not in response.headers


def test_fifty_logins_have_independent_unique_browser_and_server_values(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    store = FakeTransactionStore(settings)
    with ASGIClient(callback_app(settings, store)) as client:
        responses = [client.get("/auth/login") for _ in range(50)]

    assert all(response.status_code == 307 for response in responses)
    queries = [parse_qs(urlsplit(response.headers["location"]).query) for response in responses]
    assert len({query["state"][0] for query in queries}) == 50
    assert len({query["nonce"][0] for query in queries}) == 50
    assert len({query["code_challenge"][0] for query in queries}) == 50
    assert len({transaction.transaction_id for transaction in store.transactions}) == 50
    assert len({transaction.pkce_verifier for transaction in store.transactions}) == 50


def test_callback_consumes_once_then_sets_one_exact_opaque_host_cookie(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    store = FakeTransactionStore(settings)
    service = FakeCallbackService()
    app = create_app(settings, transaction_store=store, callback_service=service)
    with ASGIClient(app) as client:
        login = client.get("/auth/login?return_to=%2Fprofile")
        state = parse_qs(urlsplit(login.headers["location"]).query)["state"][0]
        code = quote("synthetic/code=value", safe="-._~")
        callback = client.get(f"/auth/callback?code={code}&state={state}")
        replay = client.get(f"/auth/callback?code={code}&state={state}")

    assert callback.status_code == 303
    assert callback.headers["location"] == "/profile"
    cookies = callback.headers.get_list("set-cookie")
    assert len(cookies) == 1
    cookie = cookies[0]
    assert cookie.startswith(f"__Host-session={service.handle.session_id};")
    assert "Path=/" in cookie
    assert "Max-Age=43200" in cookie
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=lax" in cookie
    assert "Domain=" not in cookie
    assert "access_token" not in cookie
    assert len(service.calls) == 1
    assert service.calls[0][0] == "synthetic/code=value"
    assert replay.status_code == 400
    assert replay.json()["code"] == "invalid_oauth_transaction"
    assert "set-cookie" not in replay.headers


def test_provider_denial_consumes_without_exchange_session_cookie_or_reflection(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    store = FakeTransactionStore(settings)
    service = FakeCallbackService()
    app = create_app(settings, transaction_store=store, callback_service=service)
    with ASGIClient(app) as client:
        login = client.get("/auth/login")
        state = parse_qs(urlsplit(login.headers["location"]).query)["state"][0]
        denied = client.get(f"/auth/callback?error=access_denied&state={state}")
        replay = client.get(f"/auth/callback?error=access_denied&state={state}")

    assert denied.status_code == 400
    assert denied.json()["code"] == "authorization_denied"
    assert "access_denied" not in denied.text
    assert "set-cookie" not in denied.headers
    assert service.calls == []
    assert replay.json()["code"] == "invalid_oauth_transaction"


def test_callback_failure_never_sets_cookie_or_redirects(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    store = FakeTransactionStore(settings)
    service = FakeCallbackService()
    service.failure = CallbackFlowError(503, "authentication_unavailable")
    app = create_app(settings, transaction_store=store, callback_service=service)
    with ASGIClient(app) as client:
        login = client.get("/auth/login")
        state = parse_qs(urlsplit(login.headers["location"]).query)["state"][0]
        response = client.get(f"/auth/callback?code=synthetic-code&state={state}")

    assert response.status_code == 503
    assert response.json()["code"] == "authentication_unavailable"
    assert "set-cookie" not in response.headers
    assert "location" not in response.headers


def test_twenty_concurrent_duplicate_callbacks_have_exactly_one_completion(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    store = FakeTransactionStore(settings)
    service = FakeCallbackService()
    app = create_app(settings, transaction_store=store, callback_service=service)

    async def scenario() -> list[httpx2.Response]:
        async with (
            app.router.lifespan_context(app),
            httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app),
                base_url="http://testserver",
            ) as client,
        ):
            login = await client.get("/auth/login")
            state = parse_qs(urlsplit(login.headers["location"]).query)["state"][0]
            return await asyncio.gather(
                *(
                    client.get(f"/auth/callback?code=synthetic-code&state={state}")
                    for _ in range(20)
                )
            )

    responses = asyncio.run(scenario())
    assert sum(response.status_code == 303 for response in responses) == 1
    assert sum(response.status_code == 400 for response in responses) == 19
    assert sum("set-cookie" in response.headers for response in responses) == 1
    assert len(service.calls) == 1


def test_no_redirect_occurs_when_redis_persistence_fails(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    store = FakeTransactionStore(settings)
    store.available = False
    with ASGIClient(callback_app(settings, store)) as client:
        response = client.get("/auth/login")
    assert response.status_code == 503
    assert "location" not in response.headers
    assert response.json()["code"] == "transaction_store_unavailable"
    assert store.transactions == []


def test_liveness_is_dependency_free_and_readiness_tracks_store_recovery(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    store = FakeTransactionStore(settings)
    store.available = False
    with ASGIClient(callback_app(settings, store)) as client:
        live = client.get("/health/live")
        unavailable = client.get("/health/ready")
        store.available = True
        ready = client.get("/health/ready")
    assert live.status_code == 200
    assert live.json() == {"status": "alive"}
    assert unavailable.status_code == 503
    assert unavailable.json()["code"] == "transaction_store_unavailable"
    assert ready.status_code == 200
    assert ready.json() == {"status": "ready"}
    assert store.closed


def test_readiness_tracks_usable_jwks_without_weakening_liveness(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    store = FakeTransactionStore(settings)
    service = FakeCallbackService()
    service.available = False
    app = create_app(settings, transaction_store=store, callback_service=service)
    with ASGIClient(app) as client:
        live = client.get("/health/live")
        unavailable = client.get("/health/ready")
        service.available = True
        ready = client.get("/health/ready")
    assert live.status_code == 200
    assert unavailable.status_code == 503
    assert ready.status_code == 200
    assert service.closed


def test_all_response_classes_receive_restrictive_headers_without_cors(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    store = FakeTransactionStore(settings)
    with ASGIClient(callback_app(settings, store)) as client:
        responses = [
            client.get("/health/live"),
            client.get("/missing"),
            client.get("/auth/login?return_to=%2F%2Fevil.invalid"),
            client.post("/auth/login"),
        ]
    for response in responses:
        assert all(response.headers[name] == value for name, value in SECURITY_HEADERS.items())
        assert not any(name.lower().startswith("access-control-") for name in response.headers)
        assert len(response.headers["x-request-id"]) <= 64
        assert "set-cookie" not in response.headers


def test_only_callback_is_added_while_deferred_surfaces_remain_absent(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    store = FakeTransactionStore(settings)
    with ASGIClient(callback_app(settings, store)) as client:
        callback = client.get("/auth/callback")
        assert callback.status_code == 400
        assert callback.json()["code"] == "invalid_callback"
        for path in (
            "/auth/logout",
            "/auth/signed-out",
            "/session",
            "/sessions",
            "/v1/me",
        ):
            response = client.get(path)
            assert response.status_code == 404
            assert response.json()["code"] == "not_found"


def test_host_and_request_id_validation_are_bounded_and_nonreflective(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    store = FakeTransactionStore(settings)
    app = callback_app(settings, store)
    with ASGIClient(app) as client:
        accepted = client.get("/health/live", headers={"x-request-id": "safe-request-123"})
        invalid_request_id = client.get("/health/live", headers={"x-request-id": "x" * 65})
    with ASGIClient(app, base_url="http://evil.invalid") as client:
        invalid_host = client.get("/health/live")
    assert accepted.headers["x-request-id"] == "safe-request-123"
    assert invalid_request_id.headers["x-request-id"] != "x" * 65
    assert invalid_host.status_code == 400
    assert invalid_host.json()["code"] == "invalid_host"
    assert "evil.invalid" not in invalid_host.text
