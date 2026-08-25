from __future__ import annotations

from collections.abc import Callable
from typing import cast
from urllib.parse import parse_qs, urlsplit

import httpx2
from reference_bff.app import create_app
from reference_bff.config import Settings
from reference_bff.exchange import AuthorizationCodeClient
from reference_bff.flow import CallbackFlow
from reference_bff.http import AsyncUpstreamClient
from reference_bff.identity import IdentityBootstrapClient
from reference_bff.jwks import AsyncJwksCache
from reference_bff.tokens import CognitoTokenVerifier

from tests.http_client import ASGIClient
from tests.reference_bff.fakes import FakeTransactionStore
from tests.reference_bff.provider import SyntheticProvider


def test_actual_callback_vertical_slice_issues_cookie_only_after_bootstrap_and_session(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    store = FakeTransactionStore(settings)
    provider = SyntheticProvider(settings)
    transport = cast(httpx2.AsyncBaseTransport, httpx2.MockTransport(provider.handle))
    upstream = AsyncUpstreamClient(settings, transport=transport)
    jwks = AsyncJwksCache(settings, upstream)
    flow = CallbackFlow(
        settings=settings,
        upstream=upstream,
        jwks=jwks,
        exchange=AuthorizationCodeClient(settings, upstream),
        verifier=CognitoTokenVerifier(settings, jwks),
        identity=IdentityBootstrapClient(settings, upstream),
        store=store,
    )
    app = create_app(settings, transaction_store=store, callback_service=flow)

    with ASGIClient(app) as client:
        login = client.get("/auth/login?return_to=%2Fprofile")
        transaction = store.transactions[0]
        provider.configure(transaction)
        state = parse_qs(urlsplit(login.headers["location"]).query)["state"][0]
        copied = client.get(f"/auth/callback?code={provider.code}&state={state}")
        second_login = client.get("/auth/login?return_to=%2Fprofile")
        transaction = store.transactions[0]
        provider.configure(transaction)
        state = parse_qs(urlsplit(second_login.headers["location"]).query)["state"][0]
        callback = client.get(
            f"/auth/callback?code={provider.code}&state={state}",
            headers={"cookie": f"__Host-oauth={transaction.transaction_id}"},
        )

    assert copied.status_code == 400
    assert copied.json()["code"] == "invalid_oauth_transaction"
    assert provider.events == ["token", "jwks", "identity"]
    assert callback.status_code == 303
    assert callback.headers["location"] == "/profile"
    assert len(callback.headers.get_list("set-cookie")) == 2
    assert len(store.session_records) == 1
    assert store.session_records[0].user_id == "1526af3c-c76a-4e01-a507-347205fb3c93"
    browser_surface = callback.text + callback.headers["location"] + callback.headers["set-cookie"]
    assert provider.access_token not in browser_surface
    assert provider.id_token not in browser_surface
    assert provider.refresh_token not in browser_surface
    assert provider.subject not in browser_surface
