from __future__ import annotations

import asyncio
import io
import json
import uuid
from collections.abc import Callable
from typing import cast
from urllib.parse import parse_qs, urlsplit

import httpx2
import pytest
from reference_bff.app import create_app
from reference_bff.config import Settings
from reference_bff.exchange import AuthorizationCodeClient
from reference_bff.flow import CallbackFlow
from reference_bff.http import AsyncUpstreamClient
from reference_bff.identity import IdentityBootstrapClient
from reference_bff.jwks import AsyncJwksCache
from reference_bff.logging import configure_logging
from reference_bff.middleware import SECURITY_HEADERS
from reference_bff.tokens import CognitoTokenVerifier

from tests.http_client import ASGIClient
from tests.reference_bff.fakes import FakeTransactionStore
from tests.reference_bff.provider import SyntheticProvider
from tests.reference_bff.unit.test_auth_diagnostics import (
    PAIR_CASES,
    REJECTION_CASES,
    independent_provider,
    mutate,
)


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


def diagnostic_app(settings, store, provider, *, transport=None):
    upstream = AsyncUpstreamClient(
        settings, transport=transport or httpx2.MockTransport(provider.handle)
    )
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
    return create_app(settings, transaction_store=store, callback_service=flow)


def diagnostic_records(output: str, mode: str) -> list[dict[str, str]]:
    records = [
        json.loads(line) if mode == "json" else dict(field.split("=", 1) for field in line.split())
        for line in output.splitlines()
        if "callback_token_rejected" in line
    ]
    for record in records:
        assert set(record) == {
            "timestamp",
            "level",
            "logger",
            "event",
            "service",
            "service_version",
            "environment",
            "category",
            "request_id",
        }
    return records


class CountingStore(FakeTransactionStore):
    consumes = 0

    def __init__(self, settings):
        super().__init__(settings)
        self.consumes = 0

    async def consume(self, state):
        self.consumes += 1
        return await super().consume(state)


def assert_rejection(response, output, mode, expected):
    assert response.status_code == 400
    request_id = response.headers["x-request-id"]
    assert uuid.UUID(hex=request_id).version == 4
    assert response.json() == {
        "type": "https://reference-bff.invalid/problems/authentication_failed",
        "title": "Bad Request",
        "status": 400,
        "code": "authentication_failed",
        "request_id": request_id,
    }
    assert response.headers["content-type"] == "application/problem+json"
    for name, value in SECURITY_HEADERS:
        assert response.headers[name.decode()] == value.decode()
    assert not any(name.startswith("access-control-") for name in response.headers)
    cookies = response.headers.get_list("set-cookie")
    assert len(cookies) == 1
    assert cookies[0].startswith('__Host-oauth="";')
    assert "Max-Age=0" in cookies[0]
    assert "HttpOnly" in cookies[0] and "Secure" in cookies[0] and "SameSite=lax" in cookies[0]
    assert "Domain=" not in cookies[0] and "Path=/" in cookies[0]
    records = diagnostic_records(output, mode)
    assert len(records) == 1
    assert records[0]["event"] == "callback_token_rejected"
    assert records[0]["category"] == expected.value
    assert records[0]["request_id"] == request_id
    assert records[0]["service"] == "reference-bff"


@pytest.mark.parametrize("mode", ["json", "console"])
@pytest.mark.parametrize(("side", "case", "expected"), REJECTION_CASES)
def test_real_http_rejection_has_one_private_category_and_server_correlation(
    bff_settings_factory, mode, side, case, expected
):
    settings = bff_settings_factory(log_format=mode)
    store = CountingStore(settings)
    provider = independent_provider(settings)
    app = diagnostic_app(settings, store, provider)
    stream = io.StringIO()
    configure_logging(settings, stream=stream)
    with ASGIClient(app) as client:
        login = client.get(
            "/auth/login?return_to=%2Fprofile", headers={"X-Request-ID": "other-route-id"}
        )
        assert login.headers["x-request-id"] == "other-route-id"
        transaction = store.transactions[0]
        provider.configure(transaction)
        mutate(provider, side, case)
        callback = client.get(
            f"/auth/callback?code={provider.code}&state={transaction.state}",
            headers={
                "cookie": f"__Host-oauth={transaction.transaction_id}",
                "X-Request-ID": "synthetic.person.example.invalid",
            },
        )
        assert store.consumes == 1
        events = list(provider.events)
        replay = client.get(
            f"/auth/callback?code={provider.code}&state={transaction.state}",
            headers={"cookie": f"__Host-oauth={transaction.transaction_id}"},
        )
        assert replay.json()["code"] == "invalid_oauth_transaction"
        assert provider.events == events
    output = stream.getvalue()
    assert_rejection(callback, output, mode, expected)
    assert provider.events.count("token") == 1
    assert "identity" not in provider.events
    assert store.session_records == [] and store.session_handles == []
    combined = output + callback.text + str(callback.headers)
    for forbidden in (
        provider.id_token,
        provider.access_token,
        provider.refresh_token,
        provider.subject,
        provider.token_family_id,
        provider.code,
        transaction.state,
        transaction.nonce,
        transaction.pkce_verifier,
        transaction.transaction_id,
        "synthetic.person.example.invalid",
    ):
        assert forbidden not in combined


@pytest.mark.parametrize("mode", ["json", "console"])
@pytest.mark.parametrize("failure", [None, "jwks", "unknown-key-outage", "exchange"])
def test_success_and_dependency_failures_emit_no_token_rejection(
    bff_settings_factory, mode, failure
):
    settings = bff_settings_factory(log_format=mode)
    provider = independent_provider(settings)
    store = CountingStore(settings)
    app = diagnostic_app(settings, store, provider)
    stream = io.StringIO()
    configure_logging(settings, stream=stream)
    with ASGIClient(app) as client:
        client.get("/auth/login")
        transaction = store.transactions[0]
        provider.configure(transaction)
        if failure in {"jwks", "unknown-key-outage"}:
            provider.jwks_status = 503
            if failure == "unknown-key-outage":
                mutate(provider, "id", "unknown-key")
        elif failure == "exchange":
            provider.token_status = 503
        response = client.get(
            f"/auth/callback?code={provider.code}&state={transaction.state}",
            headers={"cookie": f"__Host-oauth={transaction.transaction_id}"},
        )
    assert response.status_code == (303 if failure is None else 503)
    assert len(store.session_records) == (1 if failure is None else 0)
    assert provider.events.count("token") == 1
    assert store.consumes == 1
    if failure is not None:
        assert response.json()["code"] == "authentication_unavailable"
        assert "identity" not in provider.events
        assert len(response.headers.get_list("set-cookie")) == 1
    assert diagnostic_records(stream.getvalue(), mode) == []


@pytest.mark.parametrize("mode", ["json", "console"])
def test_concurrent_real_callbacks_keep_categories_and_correlation_local(
    bff_settings_factory, mode
):
    settings = bff_settings_factory(log_format=mode)
    store = CountingStore(settings)
    primary = independent_provider(settings)
    providers = {}
    arrivals = 0
    release = asyncio.Event()

    async def handle(request):
        nonlocal arrivals
        if request.method == "POST":
            code = parse_qs(request.content.decode())["code"][0]
            arrivals += 1
            if arrivals == 16:
                release.set()
            await release.wait()
            return providers[code].handle(request)
        return primary.handle(request)

    app = diagnostic_app(settings, store, primary, transport=httpx2.MockTransport(handle))
    stream = io.StringIO()
    configure_logging(settings, stream=stream)

    async def scenario():
        async with (
            app.router.lifespan_context(app),
            httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app), base_url="http://testserver"
            ) as client,
        ):
            pending = []
            categories = []
            for index in range(16):
                await client.get("/auth/login")
                transaction = store.transactions[-1]
                provider = SyntheticProvider(
                    settings,
                    private_key=primary.private_key,
                    access_private_key=primary.access_private_key,
                    code=f"synthetic-code-{index}",
                )
                provider.configure(transaction)
                side, case, expected = PAIR_CASES[index % len(PAIR_CASES)]
                mutate(provider, side, case)
                providers[provider.code] = provider
                categories.append(expected.value)
                pending.append(
                    client.get(
                        f"/auth/callback?code={provider.code}&state={transaction.state}",
                        headers={
                            "cookie": f"__Host-oauth={transaction.transaction_id}",
                            "X-Request-ID": "same.injected.id.for.all",
                        },
                    )
                )
            responses = await asyncio.gather(*pending)
            records = diagnostic_records(stream.getvalue(), mode)
            assert len(records) == 16
            by_id = {record["request_id"]: record["category"] for record in records}
            assert len(by_id) == 16
            for response, expected in zip(responses, categories, strict=True):
                assert response.status_code == 400
                request_id = response.json()["request_id"]
                assert response.headers["x-request-id"] == request_id
                assert by_id[request_id] == expected
            assert store.consumes == 16
            assert store.session_records == []
            assert all(provider.events == ["token"] for provider in providers.values())

    asyncio.run(scenario())
    assert "same.injected.id.for.all" not in stream.getvalue()
