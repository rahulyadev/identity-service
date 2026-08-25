from __future__ import annotations

from collections.abc import Callable
from urllib.parse import parse_qs, quote, urlsplit

from reference_bff.app import create_app
from reference_bff.config import Settings

from tests.http_client import ASGIClient
from tests.reference_bff.fakes import FakeTransactionStore

SECURITY_HEADERS = {
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "permissions-policy": "camera=(), geolocation=(), microphone=()",
}


def test_login_persists_before_exact_temporary_redirect(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    store = FakeTransactionStore(settings)
    app = create_app(settings, transaction_store=store)
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
    with ASGIClient(create_app(settings, transaction_store=store)) as client:
        responses = [client.get("/auth/login") for _ in range(50)]

    assert all(response.status_code == 307 for response in responses)
    queries = [parse_qs(urlsplit(response.headers["location"]).query) for response in responses]
    assert len({query["state"][0] for query in queries}) == 50
    assert len({query["nonce"][0] for query in queries}) == 50
    assert len({query["code_challenge"][0] for query in queries}) == 50
    assert len({transaction.transaction_id for transaction in store.transactions}) == 50
    assert len({transaction.pkce_verifier for transaction in store.transactions}) == 50


def test_no_redirect_occurs_when_redis_persistence_fails(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    store = FakeTransactionStore(settings)
    store.available = False
    with ASGIClient(create_app(settings, transaction_store=store)) as client:
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
    with ASGIClient(create_app(settings, transaction_store=store)) as client:
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


def test_all_response_classes_receive_restrictive_headers_without_cors(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    store = FakeTransactionStore(settings)
    with ASGIClient(create_app(settings, transaction_store=store)) as client:
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


def test_callback_session_and_logout_routes_are_absent(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    store = FakeTransactionStore(settings)
    with ASGIClient(create_app(settings, transaction_store=store)) as client:
        for path in (
            "/auth/callback",
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
    app = create_app(settings, transaction_store=store)
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
